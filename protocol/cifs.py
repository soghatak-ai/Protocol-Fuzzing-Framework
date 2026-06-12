"""
CIFS (SMB1 / NT LM 0.12) protocol mutation strategies for IDS/IPS evasion fuzzing.

Grounded in:
  - [MS-CIFS]  (Microsoft Open Specification, NT LM 0.12 dialect)
  - [MS-SMB]   (Extensions to CIFS)
  - RFC 1001 / RFC 1002  (NetBIOS over TCP/IP)
  - CVE-2017-0144  (EternalBlue — MS17-010, SMBv1 RCE)
  - CVE-2017-0143  (MS17-010 variant — Transaction buffer overflow)
  - CVE-2008-4835  (SMB header parsing RCE, MS09-001)
  - CVE-2010-0020  (SMB NTLM auth bypass, MS10-012)
  - CVE-2017-0145  (EternalRomance, Transaction2 bug)
  - Snort 3 dce_smb inspector  (GID 133, SMBv1 rules)
  - "Implementing CIFS" by Christopher Hertel

Transport: TCP port 445 (direct host SMB) or TCP port 139 (NetBIOS session).
SMB1 binary protocol: 32-byte header (\xffSMB magic), parameter block
(WordCount + Words[]), data block (ByteCount + Bytes[]).
All multi-byte fields are little-endian.

SMB1 header (32 bytes):
  Protocol        (4 bytes) : \xff S M B
  Command         (1 byte)
  Status          (4 bytes) : NT_STATUS or DOS error
  Flags           (1 byte)
  Flags2          (2 bytes)
  PIDHigh         (2 bytes)
  Signature       (8 bytes) : MAC for signing
  Reserved        (2 bytes)
  TID             (2 bytes) : Tree ID
  PID             (2 bytes) : Process ID
  UID             (2 bytes) : User ID
  MID             (2 bytes) : Multiplex ID
"""

import struct
import random
import os

# ── SMB1 Constants ──────────────────────────────────────────────────────────

SMB1_MAGIC = b'\xffSMB'

# Command codes
SMB_COM_NEGOTIATE        = 0x72
SMB_COM_SESSION_SETUP    = 0x73
SMB_COM_LOGOFF           = 0x74
SMB_COM_TREE_CONNECT     = 0x75
SMB_COM_TREE_CONNECT_ANDX = 0x75
SMB_COM_TREE_DISCONNECT  = 0x71
SMB_COM_NT_CREATE_ANDX   = 0xA2
SMB_COM_OPEN_ANDX        = 0x2D
SMB_COM_READ_ANDX        = 0x2E
SMB_COM_WRITE_ANDX       = 0x2F
SMB_COM_CLOSE            = 0x04
SMB_COM_TRANSACTION      = 0x25
SMB_COM_TRANSACTION2     = 0x32
SMB_COM_NT_TRANSACT      = 0xA0
SMB_COM_TRANSACTION2_SEC = 0x33
SMB_COM_NT_TRANSACT_SEC  = 0xA1
SMB_COM_ECHO             = 0x2B
SMB_COM_LOCKING_ANDX     = 0x24
SMB_COM_NT_CANCEL        = 0xA4

# Flags
FLAGS_REPLY              = 0x80
FLAGS_OPLOCK             = 0x20
FLAGS_BATCH_OPLOCK       = 0x40
FLAGS_CANONICAL          = 0x10
FLAGS_CASELESS           = 0x08

# Flags2
FLAGS2_UNICODE           = 0xC001
FLAGS2_NT_STATUS         = 0xC003
FLAGS2_EXT_SEC           = 0x0800
FLAGS2_LONG_NAMES        = 0x0001
FLAGS2_SMB_SECURITY_SIG  = 0x0004
FLAGS2_DFS               = 0x1000
FLAGS2_EAS               = 0x0002

# NetBIOS session types
NBT_SESSION_MESSAGE      = 0x00
NBT_SESSION_REQUEST      = 0x81
NBT_POSITIVE_RESPONSE    = 0x82
NBT_NEGATIVE_RESPONSE    = 0x83
NBT_RETARGET             = 0x84
NBT_KEEPALIVE            = 0x85

# AndX chain terminator
ANDX_NONE                = 0xFF

# Transaction sub-commands
TRANS2_OPEN2             = 0x0000
TRANS2_FIND_FIRST2       = 0x0001
TRANS2_FIND_NEXT2        = 0x0002
TRANS2_QUERY_FS_INFO     = 0x0003
TRANS2_QUERY_PATH_INFO   = 0x0005
TRANS2_SET_PATH_INFO     = 0x0006
TRANS2_QUERY_FILE_INFO   = 0x0007
TRANS2_SET_FILE_INFO     = 0x0008

_CIFS_PORT_445 = 445
_CIFS_PORT_139 = 139
_MAX_PKT = 65535

# ── Strategy metadata ────────────────────────────────────────────────────────

CIFS_STRATEGIES = [
    "dialect_negotiation",
    "header_manipulation",
    "wordcount_bytecount_desync",
    "andx_chain_abuse",
    "transaction_fragmentation",
    "named_pipe_mailslot",
    "authentication_attack",
    "oplock_state_confusion",
    "dfs_referral_attack",
    "signing_bypass",
    "nbt_session_layer",
    "file_attribute_ea_overflow",
    "deprecated_command_abuse",
    "tcp_segmentation_evasion",
]

CIFS_WEIGHTS = [10, 10, 12, 12, 14, 8, 8, 5, 6, 6, 8, 6, 5, 5]

CIFS_STRATEGY_LABELS = {
    "dialect_negotiation":          "Dialect Negotiation Attack",
    "header_manipulation":          "SMB1 Header Manipulation",
    "wordcount_bytecount_desync":   "WordCount/ByteCount Desync",
    "andx_chain_abuse":             "AndX Chain Abuse",
    "transaction_fragmentation":    "Transaction Fragmentation",
    "named_pipe_mailslot":          "Named Pipe / Mailslot Injection",
    "authentication_attack":        "Authentication Attack",
    "oplock_state_confusion":       "OpLock State Confusion",
    "dfs_referral_attack":          "DFS Referral Attack",
    "signing_bypass":               "SMB Signing Bypass",
    "nbt_session_layer":            "NetBIOS Session Layer Attack",
    "file_attribute_ea_overflow":   "File Attribute / EA Overflow",
    "deprecated_command_abuse":     "Deprecated Command Abuse",
    "tcp_segmentation_evasion":     "TCP Segmentation Evasion",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _nb(payload_len):
    """4-byte NetBIOS session message header (type 0x00 + 3 bytes length)."""
    return bytes([NBT_SESSION_MESSAGE]) + struct.pack("!I", payload_len)[1:]


def _wrap(body):
    """NetBIOS-wrap an SMB message body."""
    return _nb(len(body)) + body


def _smb1_header(command, flags=0x18, flags2=0xC803, tid=0, pid=None,
                 uid=0, mid=None, status=0):
    """Build a 32-byte SMB1 header."""
    if pid is None:
        pid = random.randint(1, 0xFFFF)
    if mid is None:
        mid = random.randint(1, 0xFFFF)
    hdr = SMB1_MAGIC
    hdr += struct.pack("<B", command)
    hdr += struct.pack("<I", status)           # NT_STATUS
    hdr += struct.pack("<B", flags)
    hdr += struct.pack("<H", flags2)
    hdr += struct.pack("<H", 0)                # PIDHigh
    hdr += b'\x00' * 8                         # Signature
    hdr += struct.pack("<H", 0)                # Reserved
    hdr += struct.pack("<H", tid)
    hdr += struct.pack("<H", pid)
    hdr += struct.pack("<H", uid)
    hdr += struct.pack("<H", mid)
    return hdr


def _negotiate_msg(dialects=None):
    """Build an SMB_COM_NEGOTIATE message with dialect strings."""
    if dialects is None:
        dialects = [b"NT LM 0.12"]
    hdr = _smb1_header(SMB_COM_NEGOTIATE, mid=0)
    data = b""
    for d in dialects:
        data += b'\x02' + d + b'\x00'
    # WordCount=0, ByteCount=len(data)
    body = struct.pack("<B", 0) + struct.pack("<H", len(data)) + data
    return _wrap(hdr + body)


def _andx_header(command, andx_cmd=ANDX_NONE, andx_offset=0):
    """Build the AndX chain fields: AndXCommand, Reserved, AndXOffset."""
    return struct.pack("<BBH", andx_cmd, 0, andx_offset)


def _session_setup_andx(uid=0, ntlm_response=None, lm_response=None,
                         account=b"admin", domain=b"WORKGROUP",
                         native_os=b"Windows", native_lanman=b"CIFS"):
    """Build SESSION_SETUP_ANDX for NT LM 0.12 (non-extended security)."""
    if ntlm_response is None:
        ntlm_response = os.urandom(24)
    if lm_response is None:
        lm_response = os.urandom(24)

    hdr = _smb1_header(SMB_COM_SESSION_SETUP, uid=uid)
    # WordCount=13 for non-extended security
    words = _andx_header(ANDX_NONE)
    words += struct.pack("<H", 4096)       # MaxBufferSize
    words += struct.pack("<H", 50)         # MaxMpxCount
    words += struct.pack("<H", 0)          # VCNumber
    words += struct.pack("<I", 0)          # SessionKey
    words += struct.pack("<H", len(lm_response))     # OEMPasswordLen
    words += struct.pack("<H", len(ntlm_response))   # UnicodePasswordLen
    words += struct.pack("<I", 0)          # Reserved
    words += struct.pack("<I", 0)          # Capabilities

    data = lm_response + ntlm_response
    data += account + b'\x00'
    data += domain + b'\x00'
    data += native_os + b'\x00'
    data += native_lanman + b'\x00'

    body = struct.pack("<B", 13) + words + struct.pack("<H", len(data)) + data
    return _wrap(hdr + body)


def _tree_connect_andx(path=b"\\\\server\\IPC$", tid=0, uid=1):
    """Build TREE_CONNECT_ANDX."""
    hdr = _smb1_header(SMB_COM_TREE_CONNECT_ANDX, tid=tid, uid=uid)
    words = _andx_header(ANDX_NONE)
    words += struct.pack("<H", 0)  # Flags
    words += struct.pack("<H", 1)  # PasswordLength
    password = b'\x00'             # null password

    data = password + path + b'\x00' + b"?????\x00"  # service
    body = struct.pack("<B", 4) + words + struct.pack("<H", len(data)) + data
    return _wrap(hdr + body)


def _clamp(data):
    """Clamp packet to sane TCP payload size."""
    return data[:_MAX_PKT] if len(data) > _MAX_PKT else data


# ── Strategy Builders ────────────────────────────────────────────────────────

def _build_dialect_negotiation():
    """Strategy 1: Dialect negotiation attacks.

    Variants:
    - oversized_list: 500+ dialect strings to overflow parser buffers
    - empty_dialects: empty dialect strings / null bytes
    - invalid_strings: garbage / control chars in dialect names
    - multi_negotiate: multiple NEGOTIATE messages (state confusion)
    - mixed_versions: SMB1 dialects mixed with SMB2 wild dialect
    - duplicate_dialects: same dialect string repeated many times
    """
    variant = random.choice([
        "oversized_list", "empty_dialects", "invalid_strings",
        "multi_negotiate", "mixed_versions", "duplicate_dialects",
    ])

    if variant == "oversized_list":
        dialects = [f"DIALECT_{i}".encode() for i in range(500)]
        dialects.insert(0, b"NT LM 0.12")
        return _negotiate_msg(dialects), _CIFS_PORT_445
    elif variant == "empty_dialects":
        dialects = [b"", b"\x00", b"NT LM 0.12", b"", b"\x00\x00"]
        return _negotiate_msg(dialects), _CIFS_PORT_445
    elif variant == "invalid_strings":
        dialects = [
            b"\xff\xfe\xfd" * 50,
            b"NT LM 0.12",
            b"\x00" * 200,
            os.urandom(300),
            b"A" * 1000,
        ]
        return _negotiate_msg(dialects), _CIFS_PORT_445
    elif variant == "multi_negotiate":
        msg1 = _negotiate_msg([b"PC NETWORK PROGRAM 1.0", b"NT LM 0.12"])
        msg2 = _negotiate_msg([b"NT LM 0.12"])
        msg3 = _negotiate_msg([b"LANMAN1.0", b"NT LM 0.12", b"SMB 2.002"])
        return msg1 + msg2 + msg3, _CIFS_PORT_445
    elif variant == "mixed_versions":
        dialects = [
            b"PC NETWORK PROGRAM 1.0",
            b"LANMAN1.0",
            b"NT LM 0.12",
            b"SMB 2.002",
            b"SMB 2.???",
        ]
        return _negotiate_msg(dialects), _CIFS_PORT_445
    else:  # duplicate_dialects
        dialects = [b"NT LM 0.12"] * 200
        return _negotiate_msg(dialects), _CIFS_PORT_445


def _build_header_manipulation():
    """Strategy 2: Mutate the 32-byte SMB1 header.

    Variants:
    - bad_magic: corrupted \xffSMB magic bytes
    - bad_command: invalid/reserved command codes
    - flags_confusion: conflicting FLAGS/FLAGS2 bits
    - pid_tid_uid_mid_boundary: boundary values for ID fields
    - status_injection: inject error status in request
    - all_zeros: zero-fill the entire header
    """
    variant = random.choice([
        "bad_magic", "bad_command", "flags_confusion",
        "pid_tid_uid_mid_boundary", "status_injection", "all_zeros",
    ])

    if variant == "bad_magic":
        bad = random.choice([b'\xffSMX', b'\x00SMB', b'\xfeSMB',
                             b'\xffsmb', b'\xff\x00\x00\x00', b'JUNK'])
        hdr = bad + b'\x00' * 28  # pad to 32 bytes
        return _wrap(hdr), _CIFS_PORT_445
    elif variant == "bad_command":
        cmd = random.choice([0x00, 0x01, 0xFE, 0xFF, 0xBB, 0xCC])
        hdr = _smb1_header(cmd)
        body = struct.pack("<B", 0) + struct.pack("<H", 0)
        return _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "flags_confusion":
        # Set contradictory flag combinations
        flags = random.choice([0xFF, FLAGS_REPLY, 0x00])
        flags2 = random.choice([0xFFFF, 0x0000, FLAGS2_UNICODE | FLAGS2_EXT_SEC | FLAGS2_DFS])
        hdr = _smb1_header(SMB_COM_NEGOTIATE, flags=flags, flags2=flags2)
        data = b'\x02NT LM 0.12\x00'
        body = struct.pack("<B", 0) + struct.pack("<H", len(data)) + data
        return _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "pid_tid_uid_mid_boundary":
        tid = random.choice([0, 0xFFFF, 1])
        uid = random.choice([0, 0xFFFF, 1])
        mid = random.choice([0, 0xFFFF, 0x8000])
        pid = random.choice([0, 0xFFFF])
        hdr = _smb1_header(SMB_COM_ECHO, tid=tid, uid=uid, mid=mid, pid=pid)
        body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4)
        body += b"ECHO"
        return _negotiate_msg() + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "status_injection":
        # Client sends a "request" with an error status set
        hdr = _smb1_header(SMB_COM_NEGOTIATE, status=0xC0000022)  # ACCESS_DENIED
        data = b'\x02NT LM 0.12\x00'
        body = struct.pack("<B", 0) + struct.pack("<H", len(data)) + data
        return _wrap(hdr + body), _CIFS_PORT_445
    else:  # all_zeros
        hdr = SMB1_MAGIC + b'\x00' * 28
        return _wrap(hdr), _CIFS_PORT_445


def _build_wordcount_bytecount_desync():
    """Strategy 3: WordCount says N words but body has different amount.

    Targets Snort 133:5 (bad word count) and 133:6 (bad byte count).

    Variants:
    - wc_too_large: WordCount claims more words than present
    - wc_too_small: WordCount claims fewer words than present
    - wc_zero_with_data: WordCount=0 but data follows
    - bc_too_large: ByteCount exceeds actual data
    - bc_too_small: ByteCount less than actual data
    - bc_zero_with_data: ByteCount=0 but bytes follow
    """
    variant = random.choice([
        "wc_too_large", "wc_too_small", "wc_zero_with_data",
        "bc_too_large", "bc_too_small", "bc_zero_with_data",
    ])

    pre = _negotiate_msg()
    hdr = _smb1_header(SMB_COM_SESSION_SETUP, mid=1)

    if variant == "wc_too_large":
        # Claim 50 words (100 bytes) but provide only 4 bytes of words
        real_words = os.urandom(4)
        body = struct.pack("<B", 50) + real_words + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "wc_too_small":
        # Claim 1 word but provide 100 bytes
        real_words = os.urandom(100)
        body = struct.pack("<B", 1) + real_words + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "wc_zero_with_data":
        body = struct.pack("<B", 0) + os.urandom(64) + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "bc_too_large":
        real_data = b"AAAA"
        body = struct.pack("<B", 0) + struct.pack("<H", 50000) + real_data
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "bc_too_small":
        real_data = os.urandom(500)
        body = struct.pack("<B", 0) + struct.pack("<H", 2) + real_data
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    else:  # bc_zero_with_data
        real_data = os.urandom(200)
        body = struct.pack("<B", 0) + struct.pack("<H", 0) + real_data
        return pre + _wrap(hdr + body), _CIFS_PORT_445


def _build_andx_chain_abuse():
    """Strategy 4: AndX chaining abuse.

    Targets Snort 133:20 (excessive chaining) and 133:21 (multiple chained login).

    Variants:
    - excessive_chain: chain >3 commands (Snort smb_max_chain=3)
    - circular_chain: AndXOffset points back to earlier command
    - invalid_offset: AndXOffset beyond message boundary
    - chained_login_logoff: SESSION_SETUP chained with LOGOFF
    - nested_tree_connect: deeply nested TREE_CONNECT chains
    - andx_to_non_andx: chain to a non-AndX command
    """
    variant = random.choice([
        "excessive_chain", "circular_chain", "invalid_offset",
        "chained_login_logoff", "nested_tree_connect", "andx_to_non_andx",
    ])

    pre = _negotiate_msg()

    if variant == "excessive_chain":
        # Chain 20+ READ_ANDX commands
        hdr = _smb1_header(SMB_COM_READ_ANDX, tid=1, uid=1, mid=1)
        chain = b""
        offset = 32  # after header
        for i in range(20):
            is_last = (i == 19)
            andx_cmd = ANDX_NONE if is_last else SMB_COM_READ_ANDX
            # WordCount=12 for READ_ANDX
            words = struct.pack("<BBH", andx_cmd, 0, 0)  # placeholder offset
            words += struct.pack("<H", 0xFFFF)  # FID
            words += struct.pack("<I", i * 4096)  # Offset
            words += struct.pack("<H", 4096)  # MaxCount
            words += struct.pack("<H", 0)     # MinCount
            words += struct.pack("<I", 0)     # Timeout
            words += struct.pack("<H", 0)     # Remaining
            words += struct.pack("<I", 0)     # OffsetHigh
            wc_body = struct.pack("<B", 12) + words + struct.pack("<H", 0)
            # Fix AndXOffset to point to next command
            if not is_last:
                next_off = offset + len(wc_body)
                wc_body = wc_body[:2] + struct.pack("<H", next_off) + wc_body[4:]
            chain += wc_body
            offset += len(wc_body)
        return pre + _wrap(hdr + chain), _CIFS_PORT_445
    elif variant == "circular_chain":
        hdr = _smb1_header(SMB_COM_READ_ANDX, tid=1, uid=1, mid=1)
        # Point AndXOffset back to byte 0 (the header start)
        words = struct.pack("<BBH", SMB_COM_READ_ANDX, 0, 0)  # offset = 0 (circular)
        words += struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<HHI", 4096, 0, 0)
        words += struct.pack("<H", 0) + struct.pack("<I", 0)
        body = struct.pack("<B", 12) + words + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "invalid_offset":
        hdr = _smb1_header(SMB_COM_READ_ANDX, tid=1, uid=1, mid=1)
        # AndXOffset points way past end
        words = struct.pack("<BBH", SMB_COM_READ_ANDX, 0, 0xFFFF)
        words += struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<HHI", 4096, 0, 0)
        words += struct.pack("<H", 0) + struct.pack("<I", 0)
        body = struct.pack("<B", 12) + words + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "chained_login_logoff":
        hdr = _smb1_header(SMB_COM_SESSION_SETUP, mid=1)
        # SESSION_SETUP chained to LOGOFF_ANDX
        setup_words = _andx_header(SMB_COM_LOGOFF, 0)
        setup_words += struct.pack("<H", 4096)  # MaxBufferSize
        setup_words += struct.pack("<H", 50)    # MaxMpxCount
        setup_words += struct.pack("<H", 0)     # VCNumber
        setup_words += struct.pack("<I", 0)     # SessionKey
        setup_words += struct.pack("<H", 0)     # OEMPasswordLen
        setup_words += struct.pack("<H", 0)     # UnicodePasswordLen
        setup_words += struct.pack("<I", 0)     # Reserved
        setup_words += struct.pack("<I", 0)     # Capabilities
        setup_body = struct.pack("<B", 13) + setup_words + struct.pack("<H", 4)
        setup_body += b'\x00' * 4  # empty passwords/strings

        # Fix AndXOffset
        logoff_off = 32 + len(setup_body)
        setup_body = setup_body[:2] + struct.pack("<H", logoff_off) + setup_body[4:]

        logoff_words = _andx_header(ANDX_NONE)
        logoff_body = struct.pack("<B", 2) + logoff_words + struct.pack("<H", 0)

        return pre + _wrap(hdr + setup_body + logoff_body), _CIFS_PORT_445
    elif variant == "nested_tree_connect":
        hdr = _smb1_header(SMB_COM_TREE_CONNECT_ANDX, uid=1, mid=1)
        chain = b""
        offset = 32
        for i in range(10):
            is_last = (i == 9)
            path = f"\\\\server\\share{i}".encode() + b'\x00'
            andx_cmd = ANDX_NONE if is_last else SMB_COM_TREE_CONNECT_ANDX
            words = struct.pack("<BBH", andx_cmd, 0, 0)
            words += struct.pack("<H", 0)    # Flags
            words += struct.pack("<H", 1)    # PasswordLength
            data = b'\x00' + path + b"A:\x00"
            wc_body = struct.pack("<B", 4) + words + struct.pack("<H", len(data)) + data
            if not is_last:
                next_off = offset + len(wc_body)
                wc_body = wc_body[:2] + struct.pack("<H", next_off) + wc_body[4:]
            chain += wc_body
            offset += len(wc_body)
        return pre + _wrap(hdr + chain), _CIFS_PORT_445
    else:  # andx_to_non_andx
        hdr = _smb1_header(SMB_COM_READ_ANDX, tid=1, uid=1, mid=1)
        # Chain to SMB_COM_ECHO (not an AndX command)
        words = struct.pack("<BBH", SMB_COM_ECHO, 0, 100)
        words += struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<HHI", 4096, 0, 0)
        words += struct.pack("<H", 0) + struct.pack("<I", 0)
        body = struct.pack("<B", 12) + words + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445


def _build_transaction_fragmentation():
    """Strategy 5: Transaction sub-protocol fragmentation attacks.

    Targets EternalBlue-class bugs (CVE-2017-0144, CVE-2017-0145).

    Variants:
    - oversized_total: TotalDataCount > actual data
    - mismatched_fragments: primary + secondary with wrong sizes
    - nttrans_32bit_overflow: NTtrans with 32-bit length overflow
    - zero_setup_count: Transaction with SetupCount=0 but setup data present
    - secondary_without_primary: send TRANSACTION2_SECONDARY without primary
    - overlapping_fragments: overlapping data offsets in fragments
    """
    variant = random.choice([
        "oversized_total", "mismatched_fragments", "nttrans_32bit_overflow",
        "zero_setup_count", "secondary_without_primary", "overlapping_fragments",
    ])

    pre = _negotiate_msg()

    if variant == "oversized_total":
        hdr = _smb1_header(SMB_COM_TRANSACTION, tid=1, uid=1, mid=1)
        # WordCount=14 for TRANSACTION
        name = b"\\PIPE\\LANMAN\x00"
        # Claim 0xFFFF total but send only 10 bytes
        param_data = b"\x00" * 10
        setup = struct.pack("<H", 0x0068)  # TransactNmPipe setup word
        words = struct.pack("<H", 0xFFFF)   # TotalParamCount (oversized)
        words += struct.pack("<H", 0xFFFF)  # TotalDataCount (oversized)
        words += struct.pack("<H", 0xFFFF)  # MaxParamCount
        words += struct.pack("<H", 0xFFFF)  # MaxDataCount
        words += struct.pack("<B", 0)       # MaxSetupCount
        words += b'\x00'                    # Reserved
        words += struct.pack("<H", 0)       # Flags
        words += struct.pack("<I", 0)       # Timeout
        words += struct.pack("<H", 0)       # Reserved2
        words += struct.pack("<H", len(param_data))  # ParamCount
        words += struct.pack("<H", 100)     # ParamOffset (placeholder)
        words += struct.pack("<H", len(param_data))  # DataCount
        words += struct.pack("<H", 120)     # DataOffset (placeholder)
        words += struct.pack("<B", 1)       # SetupCount
        words += b'\x00'                    # Reserved3
        words += setup
        data_block = name + param_data + param_data
        body = struct.pack("<B", 14 + 1) + words + struct.pack("<H", len(data_block)) + data_block
        return pre + _wrap(hdr + body), _CIFS_PORT_445

    elif variant == "mismatched_fragments":
        # Primary Transaction claims total > sent, then secondary with wrong offsets
        hdr1 = _smb1_header(SMB_COM_TRANSACTION2, tid=1, uid=1, mid=1)
        name = b"\\PIPE\\\x00"
        setup = struct.pack("<H", TRANS2_QUERY_PATH_INFO)
        frag1 = os.urandom(100)
        words = struct.pack("<H", 500)     # TotalParamCount
        words += struct.pack("<H", 500)    # TotalDataCount
        words += struct.pack("<H", 0xFFFF)
        words += struct.pack("<H", 0xFFFF)
        words += struct.pack("<B", 0) + b'\x00'
        words += struct.pack("<H", 0)
        words += struct.pack("<I", 0)
        words += struct.pack("<H", 0)
        words += struct.pack("<H", len(frag1))
        words += struct.pack("<H", 100)
        words += struct.pack("<H", len(frag1))
        words += struct.pack("<H", 130)
        words += struct.pack("<B", 1) + b'\x00'
        words += setup
        data_block = name + frag1 + frag1
        body1 = struct.pack("<B", 15) + words + struct.pack("<H", len(data_block)) + data_block

        # Secondary with different offsets
        hdr2 = _smb1_header(SMB_COM_TRANSACTION2_SEC, tid=1, uid=1, mid=1)
        frag2 = os.urandom(200)
        sec_words = struct.pack("<H", 500)     # TotalParamCount
        sec_words += struct.pack("<H", 500)    # TotalDataCount
        sec_words += struct.pack("<H", len(frag2))  # ParamCount
        sec_words += struct.pack("<H", 50)     # ParamOffset (overlapping)
        sec_words += struct.pack("<H", 0)      # ParamDisplacement
        sec_words += struct.pack("<H", len(frag2))
        sec_words += struct.pack("<H", 80)
        sec_words += struct.pack("<H", 0)      # DataDisplacement
        sec_words += struct.pack("<H", 0)      # FID
        body2 = struct.pack("<B", 9) + sec_words + struct.pack("<H", len(frag2)) + frag2

        return pre + _wrap(hdr1 + body1) + _wrap(hdr2 + body2), _CIFS_PORT_445

    elif variant == "nttrans_32bit_overflow":
        hdr = _smb1_header(SMB_COM_NT_TRANSACT, tid=1, uid=1, mid=1)
        # Use 32-bit fields that overflow
        words = struct.pack("<B", 0)        # MaxSetupCount
        words += struct.pack("<H", 0)       # Reserved
        words += struct.pack("<I", 0xFFFFFFFF)  # TotalParamCount (overflow)
        words += struct.pack("<I", 0xFFFFFFFF)  # TotalDataCount (overflow)
        words += struct.pack("<I", 0xFFFF)  # MaxParamCount
        words += struct.pack("<I", 0xFFFF)  # MaxDataCount
        words += struct.pack("<I", 100)     # ParamCount
        words += struct.pack("<I", 100)     # ParamOffset
        words += struct.pack("<I", 100)     # DataCount
        words += struct.pack("<I", 200)     # DataOffset
        words += struct.pack("<B", 0)       # SetupCount
        words += struct.pack("<H", 0x0002)  # Function (NT_CREATE)
        real_data = os.urandom(200)
        body = struct.pack("<B", 19) + words + struct.pack("<H", len(real_data)) + real_data
        return pre + _wrap(hdr + body), _CIFS_PORT_445

    elif variant == "zero_setup_count":
        hdr = _smb1_header(SMB_COM_TRANSACTION, tid=1, uid=1, mid=1)
        name = b"\\PIPE\\BROWSER\x00"
        # SetupCount=0 but include setup words anyway
        fake_setup = struct.pack("<HH", 0x0068, 0x1234)
        words = struct.pack("<H", 100) + struct.pack("<H", 100)
        words += struct.pack("<H", 0xFFFF) + struct.pack("<H", 0xFFFF)
        words += struct.pack("<B", 0) + b'\x00' + struct.pack("<H", 0)
        words += struct.pack("<I", 0) + struct.pack("<H", 0)
        words += struct.pack("<H", 0) + struct.pack("<H", 100)
        words += struct.pack("<H", 0) + struct.pack("<H", 120)
        words += struct.pack("<B", 0) + b'\x00'  # SetupCount=0, Reserved
        data_block = name + fake_setup + os.urandom(50)
        body = struct.pack("<B", 14) + words + struct.pack("<H", len(data_block)) + data_block
        return pre + _wrap(hdr + body), _CIFS_PORT_445

    elif variant == "secondary_without_primary":
        # Send TRANSACTION2_SECONDARY without ever sending the primary
        hdr = _smb1_header(SMB_COM_TRANSACTION2_SEC, tid=1, uid=1, mid=1)
        frag = os.urandom(300)
        words = struct.pack("<H", 500) + struct.pack("<H", 500)
        words += struct.pack("<H", len(frag)) + struct.pack("<H", 80)
        words += struct.pack("<H", 0)
        words += struct.pack("<H", len(frag)) + struct.pack("<H", 100)
        words += struct.pack("<H", 0)
        words += struct.pack("<H", 0)
        body = struct.pack("<B", 9) + words + struct.pack("<H", len(frag)) + frag
        return _wrap(hdr + body), _CIFS_PORT_445

    else:  # overlapping_fragments
        hdr1 = _smb1_header(SMB_COM_TRANSACTION, tid=1, uid=1, mid=1)
        name = b"\\PIPE\\LANMAN\x00"
        frag = os.urandom(100)
        setup = struct.pack("<H", 0x0068)
        words = struct.pack("<H", 200) + struct.pack("<H", 200)
        words += struct.pack("<H", 0xFFFF) + struct.pack("<H", 0xFFFF)
        words += struct.pack("<B", 0) + b'\x00' + struct.pack("<H", 0)
        words += struct.pack("<I", 0) + struct.pack("<H", 0)
        words += struct.pack("<H", len(frag)) + struct.pack("<H", 100)
        words += struct.pack("<H", len(frag)) + struct.pack("<H", 130)
        words += struct.pack("<B", 1) + b'\x00' + setup
        data_block = name + frag + frag
        body1 = struct.pack("<B", 15) + words + struct.pack("<H", len(data_block)) + data_block

        # Secondary with displacement=0 (overlapping first fragment)
        hdr2 = _smb1_header(SMB_COM_TRANSACTION2_SEC, tid=1, uid=1, mid=1)
        frag2 = os.urandom(100)
        sec_words = struct.pack("<H", 200) + struct.pack("<H", 200)
        sec_words += struct.pack("<H", len(frag2)) + struct.pack("<H", 80)
        sec_words += struct.pack("<H", 0)  # ParamDisplacement=0 (overlap!)
        sec_words += struct.pack("<H", len(frag2)) + struct.pack("<H", 100)
        sec_words += struct.pack("<H", 0)  # DataDisplacement=0 (overlap!)
        sec_words += struct.pack("<H", 0)
        body2 = struct.pack("<B", 9) + sec_words + struct.pack("<H", len(frag2)) + frag2

        return pre + _wrap(hdr1 + body1) + _wrap(hdr2 + body2), _CIFS_PORT_445


def _build_named_pipe_mailslot():
    """Strategy 6: Named pipe / mailslot injection.

    Variants:
    - pipe_name_overflow: oversized pipe names
    - lanman_pipe_abuse: malformed \\PIPE\\LANMAN requests
    - mailslot_via_trans: mailslot write via TRANSACTION
    - null_pipe_name: null/empty pipe names
    - deep_pipe_path: deeply nested pipe paths
    - special_pipe_names: reserved/special pipe names
    """
    variant = random.choice([
        "pipe_name_overflow", "lanman_pipe_abuse", "mailslot_via_trans",
        "null_pipe_name", "deep_pipe_path", "special_pipe_names",
    ])

    pre = _negotiate_msg()
    hdr = _smb1_header(SMB_COM_TRANSACTION, tid=1, uid=1, mid=1)

    if variant == "pipe_name_overflow":
        name = b"\\PIPE\\" + b"A" * 5000 + b"\x00"
    elif variant == "lanman_pipe_abuse":
        name = b"\\PIPE\\LANMAN\x00"
    elif variant == "mailslot_via_trans":
        name = b"\\MAILSLOT\\BROWSE\x00"
    elif variant == "null_pipe_name":
        name = b"\x00"
    elif variant == "deep_pipe_path":
        name = b"\\PIPE" + b"\\sub" * 200 + b"\x00"
    else:  # special_pipe_names
        name = random.choice([
            b"\\PIPE\\srvsvc\x00",
            b"\\PIPE\\wkssvc\x00",
            b"\\PIPE\\samr\x00",
            b"\\PIPE\\lsarpc\x00",
            b"\\PIPE\\epmapper\x00",
        ])

    setup = struct.pack("<H", 0x0026)  # TRANS_CALL_NMPIPE
    param_data = os.urandom(random.randint(100, 2000))
    words = struct.pack("<H", len(param_data))  # TotalParamCount
    words += struct.pack("<H", len(param_data))  # TotalDataCount
    words += struct.pack("<H", 0xFFFF)  # MaxParamCount
    words += struct.pack("<H", 0xFFFF)  # MaxDataCount
    words += struct.pack("<B", 0) + b'\x00'
    words += struct.pack("<H", 0)       # Flags
    words += struct.pack("<I", 0)       # Timeout
    words += struct.pack("<H", 0)
    words += struct.pack("<H", len(param_data))
    words += struct.pack("<H", 100)
    words += struct.pack("<H", len(param_data))
    words += struct.pack("<H", 130)
    words += struct.pack("<B", 1) + b'\x00' + setup
    data_block = name + param_data
    body = struct.pack("<B", 15) + words + struct.pack("<H", len(data_block)) + data_block
    return pre + _wrap(hdr + body), _CIFS_PORT_445


def _build_authentication_attack():
    """Strategy 7: Authentication protocol attacks.

    Variants:
    - malformed_lm: garbage LM challenge-response
    - malformed_ntlm: oversized NTLM response
    - spnego_corruption: corrupted SPNEGO token in extended security
    - empty_credentials: anonymous login with empty user+pass
    - oversized_blob: huge security blob in SESSION_SETUP
    - ntlmv2_timestamp_abuse: NTLMv2 blob with bad timestamp/target info
    """
    variant = random.choice([
        "malformed_lm", "malformed_ntlm", "spnego_corruption",
        "empty_credentials", "oversized_blob", "ntlmv2_timestamp_abuse",
    ])

    pre = _negotiate_msg()

    if variant == "malformed_lm":
        return pre + _session_setup_andx(
            lm_response=os.urandom(100),  # LM should be 24 bytes
            ntlm_response=os.urandom(24),
        ), _CIFS_PORT_445
    elif variant == "malformed_ntlm":
        return pre + _session_setup_andx(
            lm_response=os.urandom(24),
            ntlm_response=os.urandom(5000),  # huge NTLM response
        ), _CIFS_PORT_445
    elif variant == "spnego_corruption":
        # Build with extended security (Flags2 bit 0x0800)
        hdr = _smb1_header(SMB_COM_SESSION_SETUP, flags2=FLAGS2_NT_STATUS | FLAGS2_EXT_SEC)
        # SPNEGO-like blob but corrupted
        spnego = b'\x60\x82' + struct.pack(">H", 500) + os.urandom(500)
        words = _andx_header(ANDX_NONE)
        words += struct.pack("<H", 4096)  # MaxBufferSize
        words += struct.pack("<H", 50)    # MaxMpxCount
        words += struct.pack("<H", 0)     # VCNumber
        words += struct.pack("<I", 0)     # SessionKey
        words += struct.pack("<H", len(spnego))  # SecurityBlobLength
        words += struct.pack("<I", 0)     # Reserved
        words += struct.pack("<I", 0)     # Capabilities
        data = spnego + b"Windows\x00" + b"CIFS\x00"
        body = struct.pack("<B", 12) + words + struct.pack("<H", len(data)) + data
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "empty_credentials":
        return pre + _session_setup_andx(
            lm_response=b"",
            ntlm_response=b"",
            account=b"",
            domain=b"",
        ), _CIFS_PORT_445
    elif variant == "oversized_blob":
        hdr = _smb1_header(SMB_COM_SESSION_SETUP, flags2=FLAGS2_NT_STATUS | FLAGS2_EXT_SEC)
        blob = os.urandom(30000)
        words = _andx_header(ANDX_NONE)
        words += struct.pack("<H", 4096)
        words += struct.pack("<H", 50)
        words += struct.pack("<H", 0)
        words += struct.pack("<I", 0)
        words += struct.pack("<H", len(blob))
        words += struct.pack("<I", 0)
        words += struct.pack("<I", 0)
        data = blob
        body = struct.pack("<B", 12) + words + struct.pack("<H", len(data)) + data
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    else:  # ntlmv2_timestamp_abuse
        # NTLMv2 blob with bogus timestamp and oversized target info
        client_challenge = os.urandom(8)
        timestamp = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)  # max timestamp
        target_info = b'\x02\x00' + struct.pack("<H", 200) + b'A' * 200  # MsvAvNbDomainName
        target_info += b'\x00\x00\x00\x00'  # MsvAvEOL
        ntlm_blob = b'\x01\x01\x00\x00\x00\x00\x00\x00'
        ntlm_blob += timestamp + client_challenge + b'\x00\x00\x00\x00'
        ntlm_blob += target_info
        ntlm_response = os.urandom(16) + ntlm_blob  # 16-byte NTProofStr + blob
        return pre + _session_setup_andx(
            lm_response=os.urandom(24),
            ntlm_response=ntlm_response,
        ), _CIFS_PORT_445


def _build_oplock_state_confusion():
    """Strategy 8: OpLock state confusion attacks.

    Variants:
    - break_without_oplock: send OpLock break without holding one
    - invalid_oplock_level: request invalid OpLock level
    - concurrent_oplock_flood: rapid OpLock requests on same FID
    - oplock_on_pipe: request OpLock on a named pipe
    - batch_then_exclusive: request conflicting OpLock types
    - break_race_condition: interleave break acks with new opens
    """
    variant = random.choice([
        "break_without_oplock", "invalid_oplock_level",
        "concurrent_oplock_flood", "oplock_on_pipe",
        "batch_then_exclusive", "break_race_condition",
    ])

    pre = _negotiate_msg()

    if variant == "break_without_oplock":
        hdr = _smb1_header(SMB_COM_LOCKING_ANDX, tid=1, uid=1, mid=1)
        words = _andx_header(ANDX_NONE)
        words += struct.pack("<H", 0xFFFF)  # FID
        words += struct.pack("<B", 0x02)    # TypeOfLock: OPLOCK_RELEASE
        words += struct.pack("<B", 0)       # NewOpLockLevel
        words += struct.pack("<I", 0)       # Timeout
        words += struct.pack("<H", 0)       # NumberOfUnlocks
        words += struct.pack("<H", 0)       # NumberOfLocks
        body = struct.pack("<B", 8) + words + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "invalid_oplock_level":
        # Request OPEN_ANDX with invalid OpLock flags
        hdr = _smb1_header(SMB_COM_OPEN_ANDX, tid=1, uid=1,
                           flags=FLAGS_OPLOCK | FLAGS_BATCH_OPLOCK | 0x03, mid=1)
        fname = b"test.txt\x00"
        words = _andx_header(ANDX_NONE)
        words += struct.pack("<H", 0xFF)   # Flags (invalid)
        words += struct.pack("<H", 0x0042) # DesiredAccess (read/write)
        words += struct.pack("<H", 0)      # SearchAttrs
        words += struct.pack("<H", 0)      # FileAttrs
        words += struct.pack("<I", 0)      # CreationTime
        words += struct.pack("<H", 0x01)   # OpenFunction
        words += struct.pack("<I", 0)      # AllocationSize
        words += struct.pack("<I", 0)      # Reserved1
        words += struct.pack("<I", 0)      # Reserved2
        data = fname
        body = struct.pack("<B", 15) + words + struct.pack("<H", len(data)) + data
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "concurrent_oplock_flood":
        msgs = b""
        for i in range(200):
            hdr = _smb1_header(SMB_COM_NT_CREATE_ANDX, tid=1, uid=1,
                               flags=FLAGS_OPLOCK, mid=i + 1)
            fname = b"f\x00l\x00o\x00o\x00d\x00.\x00t\x00x\x00t\x00\x00\x00"
            words = _andx_header(ANDX_NONE)
            words += struct.pack("<B", 0)          # Reserved
            words += struct.pack("<H", len(fname)) # NameLength
            words += struct.pack("<I", 0x16)       # Flags
            words += struct.pack("<I", 0)          # RootFID
            words += struct.pack("<I", 0x02000000) # DesiredAccess
            words += struct.pack("<Q", 0)          # AllocationSize
            words += struct.pack("<I", 0x80)       # ExtFileAttributes
            words += struct.pack("<I", 0x07)       # ShareAccess
            words += struct.pack("<I", 0x01)       # CreateDisposition
            words += struct.pack("<I", 0x40)       # CreateOptions
            words += struct.pack("<I", 0x02)       # ImpersonationLevel
            words += struct.pack("<B", 0)          # SecurityFlags
            data = fname
            body = struct.pack("<B", 24) + words + struct.pack("<H", len(data)) + data
            msgs += _wrap(hdr + body)
        return pre + msgs, _CIFS_PORT_445
    elif variant == "oplock_on_pipe":
        hdr = _smb1_header(SMB_COM_NT_CREATE_ANDX, tid=1, uid=1,
                           flags=FLAGS_OPLOCK | FLAGS_BATCH_OPLOCK, mid=1)
        fname = b"\\\x00P\x00I\x00P\x00E\x00\\\x00s\x00r\x00v\x00s\x00v\x00c\x00\x00\x00"
        words = _andx_header(ANDX_NONE)
        words += struct.pack("<B", 0)
        words += struct.pack("<H", len(fname))
        words += struct.pack("<I", 0x16)
        words += struct.pack("<I", 0)
        words += struct.pack("<I", 0x02000000)
        words += struct.pack("<Q", 0)
        words += struct.pack("<I", 0x80)
        words += struct.pack("<I", 0x07)
        words += struct.pack("<I", 0x01)
        words += struct.pack("<I", 0x40)
        words += struct.pack("<I", 0x02)
        words += struct.pack("<B", 0)
        body = struct.pack("<B", 24) + words + struct.pack("<H", len(fname)) + fname
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "batch_then_exclusive":
        msgs = b""
        for i, flg in enumerate([FLAGS_BATCH_OPLOCK, FLAGS_OPLOCK, 0]):
            hdr = _smb1_header(SMB_COM_NT_CREATE_ANDX, tid=1, uid=1,
                               flags=flg, mid=i + 1)
            fname = b"s\x00a\x00m\x00e\x00.\x00t\x00x\x00t\x00\x00\x00"
            words = _andx_header(ANDX_NONE)
            words += struct.pack("<B", 0) + struct.pack("<H", len(fname))
            words += struct.pack("<I", 0x16) + struct.pack("<I", 0)
            words += struct.pack("<I", 0x02000000) + struct.pack("<Q", 0)
            words += struct.pack("<I", 0x80) + struct.pack("<I", 0x07)
            words += struct.pack("<I", 0x01) + struct.pack("<I", 0x40)
            words += struct.pack("<I", 0x02) + struct.pack("<B", 0)
            body = struct.pack("<B", 24) + words + struct.pack("<H", len(fname)) + fname
            msgs += _wrap(hdr + body)
        return pre + msgs, _CIFS_PORT_445
    else:  # break_race_condition
        msgs = b""
        for i in range(100):
            if i % 2 == 0:
                # Locking_AndX for OpLock break ack
                hdr = _smb1_header(SMB_COM_LOCKING_ANDX, tid=1, uid=1, mid=i + 1)
                words = _andx_header(ANDX_NONE)
                words += struct.pack("<H", i // 2)
                words += struct.pack("<B", 0x02) + struct.pack("<B", 0)
                words += struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
                body = struct.pack("<B", 8) + words + struct.pack("<H", 0)
            else:
                # NT_CREATE_ANDX new open
                hdr = _smb1_header(SMB_COM_NT_CREATE_ANDX, tid=1, uid=1,
                                   flags=FLAGS_OPLOCK, mid=i + 1)
                fname = f"r{i}.tmp".encode("utf-16-le") + b"\x00\x00"
                words = _andx_header(ANDX_NONE) + struct.pack("<B", 0)
                words += struct.pack("<H", len(fname)) + struct.pack("<I", 0x16)
                words += struct.pack("<I", 0) + struct.pack("<I", 0x02000000)
                words += struct.pack("<Q", 0) + struct.pack("<I", 0x80)
                words += struct.pack("<I", 0x07) + struct.pack("<I", 0x01)
                words += struct.pack("<I", 0x40) + struct.pack("<I", 0x02)
                words += struct.pack("<B", 0)
                body = struct.pack("<B", 24) + words + struct.pack("<H", len(fname)) + fname
            msgs += _wrap(hdr + body)
        return pre + msgs, _CIFS_PORT_445


def _build_dfs_referral_attack():
    """Strategy 9: DFS referral attacks.

    Variants:
    - malformed_path: invalid DFS paths
    - recursive_referral: self-referencing DFS paths
    - oversized_referral: huge referral path
    - empty_referral: empty DFS path request
    - multi_level_referral: deeply nested DFS referral chain
    - unicode_dfs_path: Unicode-exploiting DFS paths
    """
    variant = random.choice([
        "malformed_path", "recursive_referral", "oversized_referral",
        "empty_referral", "multi_level_referral", "unicode_dfs_path",
    ])

    pre = _negotiate_msg()
    hdr = _smb1_header(SMB_COM_TRANSACTION2, tid=1, uid=1, mid=1,
                       flags2=FLAGS2_UNICODE | FLAGS2_NT_STATUS | FLAGS2_DFS)

    if variant == "malformed_path":
        path = b"\\\x00\\\x00\x00\x00" + os.urandom(100) + b"\x00\x00"
    elif variant == "recursive_referral":
        path = "\\\\server\\dfs\\server\\dfs\\server\\dfs".encode("utf-16-le") + b"\x00\x00"
    elif variant == "oversized_referral":
        path = ("\\\\" + "A" * 5000 + "\\share").encode("utf-16-le") + b"\x00\x00"
    elif variant == "empty_referral":
        path = b"\x00\x00"
    elif variant == "multi_level_referral":
        path = ("\\\\root" + "\\sub" * 100 + "\\leaf").encode("utf-16-le") + b"\x00\x00"
    else:  # unicode_dfs_path
        path = "\\\\sérvér\\shàré\\pàth".encode("utf-16-le") + b"\x00\x00"

    # TRANS2_GET_DFS_REFERRAL setup
    setup = struct.pack("<H", 0x0010)  # TRANS2_GET_DFS_REFERRAL
    referral_request = struct.pack("<H", 4) + path  # MaxReferralLevel + RequestFileName

    words = struct.pack("<H", len(referral_request))
    words += struct.pack("<H", 0)
    words += struct.pack("<H", 0xFFFF) + struct.pack("<H", 0xFFFF)
    words += struct.pack("<B", 0) + b'\x00' + struct.pack("<H", 0)
    words += struct.pack("<I", 0) + struct.pack("<H", 0)
    words += struct.pack("<H", len(referral_request)) + struct.pack("<H", 100)
    words += struct.pack("<H", 0) + struct.pack("<H", 120)
    words += struct.pack("<B", 1) + b'\x00' + setup
    data_block = b'\x00' + referral_request  # pad byte + data
    body = struct.pack("<B", 15) + words + struct.pack("<H", len(data_block)) + data_block
    return pre + _wrap(hdr + body), _CIFS_PORT_445


def _build_signing_bypass():
    """Strategy 10: SMB message signing bypass.

    Variants:
    - corrupted_signature: valid message with corrupted 8-byte MAC
    - zero_signature: signature field zeroed when signing negotiated
    - signature_on_unsigned: signature present when not negotiated
    - replay_signature: reuse old signature on new message
    - flags2_confusion: set SMB_SECURITY_SIGNATURE but clear SecurityMode
    - partial_signature: truncated signature (only first 4 bytes)
    """
    variant = random.choice([
        "corrupted_signature", "zero_signature", "signature_on_unsigned",
        "replay_signature", "flags2_confusion", "partial_signature",
    ])

    pre = _negotiate_msg()

    # Build a base header with signing flag
    flags2_signed = FLAGS2_NT_STATUS | FLAGS2_SMB_SECURITY_SIG

    if variant == "corrupted_signature":
        hdr = bytearray(_smb1_header(SMB_COM_ECHO, flags2=flags2_signed, mid=1))
        # Put random bytes in signature field (offset 14-21)
        hdr[14:22] = os.urandom(8)
        hdr = bytes(hdr)
        body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4)
        body += b"ECHO"
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "zero_signature":
        hdr = bytearray(_smb1_header(SMB_COM_ECHO, flags2=flags2_signed, mid=1))
        hdr[14:22] = b'\x00' * 8
        hdr = bytes(hdr)
        body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4)
        body += b"ECHO"
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "signature_on_unsigned":
        hdr = bytearray(_smb1_header(SMB_COM_ECHO, flags2=FLAGS2_NT_STATUS, mid=1))
        hdr[14:22] = os.urandom(8)  # signature present but not negotiated
        hdr = bytes(hdr)
        body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4)
        body += b"ECHO"
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "replay_signature":
        # Same signature on two different messages
        sig = os.urandom(8)
        msgs = b""
        for i in range(10):
            hdr = bytearray(_smb1_header(SMB_COM_ECHO, flags2=flags2_signed, mid=i + 1))
            hdr[14:22] = sig
            body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4)
            body += f"EC{i:02d}".encode()
            msgs += _wrap(bytes(hdr) + body)
        return pre + msgs, _CIFS_PORT_445
    elif variant == "flags2_confusion":
        # Toggle signing flag mid-stream
        msg1_hdr = _smb1_header(SMB_COM_ECHO, flags2=flags2_signed, mid=1)
        msg1_body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4) + b"ECH1"
        msg2_hdr = _smb1_header(SMB_COM_ECHO, flags2=FLAGS2_NT_STATUS, mid=2)
        msg2_body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4) + b"ECH2"
        msg3_hdr = _smb1_header(SMB_COM_ECHO, flags2=flags2_signed, mid=3)
        msg3_body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4) + b"ECH3"
        return pre + _wrap(msg1_hdr + msg1_body) + _wrap(msg2_hdr + msg2_body) + _wrap(msg3_hdr + msg3_body), _CIFS_PORT_445
    else:  # partial_signature
        hdr = bytearray(_smb1_header(SMB_COM_ECHO, flags2=flags2_signed, mid=1))
        hdr[14:18] = os.urandom(4)
        hdr[18:22] = b'\x00' * 4  # only half filled
        hdr = bytes(hdr)
        body = struct.pack("<B", 1) + struct.pack("<H", 1) + struct.pack("<H", 4)
        body += b"ECHO"
        return pre + _wrap(hdr + body), _CIFS_PORT_445


def _build_nbt_session_layer():
    """Strategy 11: NetBIOS session layer attacks.

    Targets Snort 133:2 (bad NetBIOS session type).

    Variants:
    - bad_session_type: invalid NBT session type bytes
    - oversized_nbt_length: NetBIOS length > actual data
    - session_request_abuse: NBT session request on port 445
    - retarget_abuse: NBT retarget message injection
    - keepalive_flood: excessive keepalive messages
    - zero_length_message: zero-length NetBIOS session message
    """
    variant = random.choice([
        "bad_session_type", "oversized_nbt_length", "session_request_abuse",
        "retarget_abuse", "keepalive_flood", "zero_length_message",
    ])

    if variant == "bad_session_type":
        smb = _smb1_header(SMB_COM_NEGOTIATE) + struct.pack("<B", 0) + struct.pack("<H", 14)
        smb += b'\x02NT LM 0.12\x00'
        # Use invalid session type
        bad_type = random.choice([0x01, 0x02, 0x7F, 0xFE, 0xFF])
        nbt = bytes([bad_type]) + struct.pack("!I", len(smb))[1:]
        return nbt + smb, _CIFS_PORT_445
    elif variant == "oversized_nbt_length":
        smb = _smb1_header(SMB_COM_ECHO) + struct.pack("<BHH", 1, 1, 4) + b"ECHO"
        return _negotiate_msg() + _nb(0x00FFFFFF) + smb, _CIFS_PORT_445
    elif variant == "session_request_abuse":
        # NetBIOS session request (type 0x81) normally on port 139
        called = b'\x20' + b'EAEBEJEPFHCACACACACACACACACACACA' + b'\x00'
        calling = b'\x20' + b'EIEFEJFEEJCACACACACACACACACACACB' + b'\x00'
        nbt = bytes([NBT_SESSION_REQUEST]) + struct.pack("!I", len(called + calling))[1:]
        return nbt + called + calling, random.choice([_CIFS_PORT_445, _CIFS_PORT_139])
    elif variant == "retarget_abuse":
        # Retarget response (type 0x84) — server-to-client but sent client-to-server
        ip_port = struct.pack("!I", 0xC0A80101) + struct.pack("!H", 445)
        nbt = bytes([NBT_RETARGET]) + struct.pack("!I", len(ip_port))[1:]
        return nbt + ip_port, _CIFS_PORT_445
    elif variant == "keepalive_flood":
        ka = bytes([NBT_KEEPALIVE, 0x00, 0x00, 0x00])
        return ka * 500 + _negotiate_msg() + ka * 500, _CIFS_PORT_445
    else:  # zero_length_message
        return _negotiate_msg() + _nb(0), _CIFS_PORT_445


def _build_file_attribute_ea_overflow():
    """Strategy 12: File attribute / Extended Attribute overflow.

    Variants:
    - oversized_ea: Extended Attributes exceeding buffer limits
    - long_filename: filenames exceeding MAX_PATH
    - ea_list_bomb: huge list of small EAs
    - invalid_attributes: conflicting/invalid file attribute bits
    - unicode_filename_abuse: malformed Unicode filenames
    - stream_name_overflow: oversized NTFS alternate data stream names
    """
    variant = random.choice([
        "oversized_ea", "long_filename", "ea_list_bomb",
        "invalid_attributes", "unicode_filename_abuse", "stream_name_overflow",
    ])

    pre = _negotiate_msg()

    if variant == "oversized_ea":
        hdr = _smb1_header(SMB_COM_TRANSACTION2, tid=1, uid=1, mid=1)
        setup = struct.pack("<H", TRANS2_SET_PATH_INFO)
        # Build oversized EA
        ea_name = b"MYEA"
        ea_value = b"V" * 60000
        ea = struct.pack("<BBHH", 0, 0, len(ea_name), len(ea_value))
        ea += ea_name + b'\x00' + ea_value
        path = b"test.txt\x00"
        param = struct.pack("<H", 0x0002) + struct.pack("<H", 0) + path  # InfoLevel + Reserved + Path
        data_block = b'\x00' + param + ea

        words = struct.pack("<H", len(param)) + struct.pack("<H", len(ea))
        words += struct.pack("<H", 0xFFFF) + struct.pack("<H", 0xFFFF)
        words += struct.pack("<B", 0) + b'\x00' + struct.pack("<H", 0)
        words += struct.pack("<I", 0) + struct.pack("<H", 0)
        words += struct.pack("<H", len(param)) + struct.pack("<H", 100)
        words += struct.pack("<H", len(ea)) + struct.pack("<H", 120)
        words += struct.pack("<B", 1) + b'\x00' + setup
        body = struct.pack("<B", 15) + words + struct.pack("<H", len(data_block)) + data_block
        return pre + _wrap(hdr + body), _CIFS_PORT_445

    elif variant == "long_filename":
        hdr = _smb1_header(SMB_COM_NT_CREATE_ANDX, tid=1, uid=1, mid=1)
        fname = ("A" * 5000 + ".txt").encode("utf-16-le") + b"\x00\x00"
        words = _andx_header(ANDX_NONE) + struct.pack("<B", 0)
        words += struct.pack("<H", len(fname)) + struct.pack("<I", 0x16)
        words += struct.pack("<I", 0) + struct.pack("<I", 0x02000000)
        words += struct.pack("<Q", 0) + struct.pack("<I", 0x80)
        words += struct.pack("<I", 0x07) + struct.pack("<I", 0x01)
        words += struct.pack("<I", 0x40) + struct.pack("<I", 0x02) + struct.pack("<B", 0)
        body = struct.pack("<B", 24) + words + struct.pack("<H", len(fname)) + fname
        return pre + _wrap(hdr + body), _CIFS_PORT_445

    elif variant == "ea_list_bomb":
        hdr = _smb1_header(SMB_COM_TRANSACTION2, tid=1, uid=1, mid=1)
        setup = struct.pack("<H", TRANS2_QUERY_PATH_INFO)
        eas = b""
        for i in range(500):
            n = f"EA{i:04d}".encode()
            v = b"X" * 100
            eas += struct.pack("<BBHH", 0, 0, len(n), len(v)) + n + b'\x00' + v
        path = b"test.txt\x00"
        param = struct.pack("<H", 0x0003) + struct.pack("<H", 0) + path
        data_block = b'\x00' + param + eas
        words = struct.pack("<H", len(param)) + struct.pack("<H", len(eas))
        words += struct.pack("<H", 0xFFFF) + struct.pack("<H", 0xFFFF)
        words += struct.pack("<B", 0) + b'\x00' + struct.pack("<H", 0)
        words += struct.pack("<I", 0) + struct.pack("<H", 0)
        words += struct.pack("<H", len(param)) + struct.pack("<H", 100)
        words += struct.pack("<H", len(eas)) + struct.pack("<H", 120)
        words += struct.pack("<B", 1) + b'\x00' + setup
        body = struct.pack("<B", 15) + words + struct.pack("<H", len(data_block)) + data_block
        return pre + _wrap(hdr + body), _CIFS_PORT_445

    elif variant == "invalid_attributes":
        hdr = _smb1_header(SMB_COM_NT_CREATE_ANDX, tid=1, uid=1, mid=1)
        fname = b"b\x00a\x00d\x00.\x00t\x00x\x00t\x00\x00\x00"
        words = _andx_header(ANDX_NONE) + struct.pack("<B", 0)
        words += struct.pack("<H", len(fname)) + struct.pack("<I", 0x16)
        words += struct.pack("<I", 0) + struct.pack("<I", 0x02000000)
        words += struct.pack("<Q", 0)
        words += struct.pack("<I", 0xFFFFFFFF)  # ALL attribute bits set
        words += struct.pack("<I", 0x07) + struct.pack("<I", 0x01)
        words += struct.pack("<I", 0x40) + struct.pack("<I", 0x02) + struct.pack("<B", 0)
        body = struct.pack("<B", 24) + words + struct.pack("<H", len(fname)) + fname
        return pre + _wrap(hdr + body), _CIFS_PORT_445

    elif variant == "unicode_filename_abuse":
        hdr = _smb1_header(SMB_COM_NT_CREATE_ANDX, tid=1, uid=1, mid=1,
                           flags2=FLAGS2_UNICODE | FLAGS2_NT_STATUS)
        # Malformed Unicode sequences
        fname = b'\xff\xfe' + b'\x00\xd8' * 100 + b'\x00\x00'  # unpaired surrogates
        words = _andx_header(ANDX_NONE) + struct.pack("<B", 0)
        words += struct.pack("<H", len(fname)) + struct.pack("<I", 0x16)
        words += struct.pack("<I", 0) + struct.pack("<I", 0x02000000)
        words += struct.pack("<Q", 0) + struct.pack("<I", 0x80)
        words += struct.pack("<I", 0x07) + struct.pack("<I", 0x01)
        words += struct.pack("<I", 0x40) + struct.pack("<I", 0x02) + struct.pack("<B", 0)
        body = struct.pack("<B", 24) + words + struct.pack("<H", len(fname)) + fname
        return pre + _wrap(hdr + body), _CIFS_PORT_445

    else:  # stream_name_overflow
        hdr = _smb1_header(SMB_COM_NT_CREATE_ANDX, tid=1, uid=1, mid=1,
                           flags2=FLAGS2_UNICODE | FLAGS2_NT_STATUS)
        # NTFS alternate data stream with huge name
        base = "file.txt"
        stream = ":" + "A" * 3000 + ":$DATA"
        fname = (base + stream).encode("utf-16-le") + b"\x00\x00"
        words = _andx_header(ANDX_NONE) + struct.pack("<B", 0)
        words += struct.pack("<H", len(fname)) + struct.pack("<I", 0x16)
        words += struct.pack("<I", 0) + struct.pack("<I", 0x02000000)
        words += struct.pack("<Q", 0) + struct.pack("<I", 0x80)
        words += struct.pack("<I", 0x07) + struct.pack("<I", 0x01)
        words += struct.pack("<I", 0x40) + struct.pack("<I", 0x02) + struct.pack("<B", 0)
        body = struct.pack("<B", 24) + words + struct.pack("<H", len(fname)) + fname
        return pre + _wrap(hdr + body), _CIFS_PORT_445


def _build_deprecated_command_abuse():
    """Strategy 13: Deprecated / obsolete command abuse.

    Targets Snort 133:52 (deprecated dialect) and 133:53 (deprecated command).

    Variants:
    - process_exit: send PROCESS_EXIT (obsolete)
    - old_copy_move: send COPY/MOVE commands
    - old_open: send legacy OPEN (not OPEN_ANDX)
    - old_read_write: send legacy READ/WRITE (not _ANDX variants)
    - old_lock: send LOCK_BYTE_RANGE (not LOCKING_ANDX)
    - old_create: send legacy CREATE / CREATE_NEW
    """
    variant = random.choice([
        "process_exit", "old_copy_move", "old_open",
        "old_read_write", "old_lock", "old_create",
    ])

    pre = _negotiate_msg()

    if variant == "process_exit":
        hdr = _smb1_header(0x11, mid=1)  # SMB_COM_PROCESS_EXIT
        body = struct.pack("<B", 0) + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "old_copy_move":
        cmd = random.choice([0x29, 0x2A])  # COPY=0x29, MOVE=0x2A
        hdr = _smb1_header(cmd, tid=1, uid=1, mid=1)
        body = struct.pack("<B", 0) + struct.pack("<H", 50)
        body += b"\\\\src\\file\x00\\\\dst\\file\x00" + os.urandom(20)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "old_open":
        hdr = _smb1_header(0x02, tid=1, uid=1, mid=1)  # SMB_COM_OPEN
        fname = b"test.txt\x00"
        words = struct.pack("<H", 0x0042) + struct.pack("<H", 0)
        body = struct.pack("<B", 2) + words + struct.pack("<H", len(fname)) + fname
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "old_read_write":
        # Legacy READ (0x0A)
        hdr = _smb1_header(0x0A, tid=1, uid=1, mid=1)
        words = struct.pack("<H", 0xFFFF)   # FID
        words += struct.pack("<H", 1024)    # CountOfBytesToRead
        words += struct.pack("<I", 0)       # Offset
        words += struct.pack("<H", 0)       # Remaining
        body = struct.pack("<B", 5) + words + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    elif variant == "old_lock":
        # LOCK_BYTE_RANGE (0x0C)
        hdr = _smb1_header(0x0C, tid=1, uid=1, mid=1)
        words = struct.pack("<H", 0xFFFF)   # FID
        words += struct.pack("<I", 1000)    # CountOfBytesToLock
        words += struct.pack("<I", 0)       # Offset
        body = struct.pack("<B", 5) + words + struct.pack("<H", 0)
        return pre + _wrap(hdr + body), _CIFS_PORT_445
    else:  # old_create
        cmd = random.choice([0x03, 0x0F])  # CREATE=0x03, CREATE_NEW=0x0F
        hdr = _smb1_header(cmd, tid=1, uid=1, mid=1)
        fname = b"newfile.txt\x00"
        words = struct.pack("<H", 0x80)    # FileAttrs
        words += struct.pack("<I", 0)      # CreationTime
        body = struct.pack("<B", 3) + words + struct.pack("<H", len(fname)) + fname
        return pre + _wrap(hdr + body), _CIFS_PORT_445


def _build_tcp_segmentation_evasion():
    """Strategy 14: TCP-layer attacks against CIFS/SMB parsers.

    Targets Snort dce_smb TCP stream reassembly.

    Variants:
    - split_nbt_header: split 4-byte NetBIOS header across segments
    - split_smb_header: split 32-byte SMB header at various points
    - header_body_split: header in one segment, body in another
    - single_byte_segments: one byte at a time
    - partial_delivery: truncate mid-message
    - interleaved_sessions: mix bytes from different sessions
    """
    variant = random.choice([
        "split_nbt_header", "split_smb_header", "header_body_split",
        "single_byte_segments", "partial_delivery", "interleaved_sessions",
    ])

    hdr = _smb1_header(SMB_COM_NEGOTIATE)
    data = b'\x02NT LM 0.12\x00'
    body = struct.pack("<B", 0) + struct.pack("<H", len(data)) + data
    pkt = _wrap(hdr + body)

    if variant == "split_nbt_header":
        return pkt, _CIFS_PORT_445
    elif variant == "split_smb_header":
        return pkt, _CIFS_PORT_445
    elif variant == "header_body_split":
        return pkt, _CIFS_PORT_445
    elif variant == "single_byte_segments":
        return pkt, _CIFS_PORT_445
    elif variant == "partial_delivery":
        cut = random.randint(1, len(pkt) - 1)
        return pkt[:cut], _CIFS_PORT_445
    else:  # interleaved_sessions
        pkt2 = _negotiate_msg([b"LANMAN1.0", b"NT LM 0.12"])
        # Remove the NetBIOS header from pkt2 for raw interleaving
        result = bytearray()
        for i in range(max(len(pkt), len(pkt2))):
            if i < len(pkt):
                result.append(pkt[i])
            if i < len(pkt2):
                result.append(pkt2[i])
        return bytes(result), _CIFS_PORT_445


# ── Dispatcher ──────────────────────────────────────────────────────────────

_BUILDERS = {
    "dialect_negotiation":          _build_dialect_negotiation,
    "header_manipulation":          _build_header_manipulation,
    "wordcount_bytecount_desync":   _build_wordcount_bytecount_desync,
    "andx_chain_abuse":             _build_andx_chain_abuse,
    "transaction_fragmentation":    _build_transaction_fragmentation,
    "named_pipe_mailslot":          _build_named_pipe_mailslot,
    "authentication_attack":        _build_authentication_attack,
    "oplock_state_confusion":       _build_oplock_state_confusion,
    "dfs_referral_attack":          _build_dfs_referral_attack,
    "signing_bypass":               _build_signing_bypass,
    "nbt_session_layer":            _build_nbt_session_layer,
    "file_attribute_ea_overflow":   _build_file_attribute_ea_overflow,
    "deprecated_command_abuse":     _build_deprecated_command_abuse,
    "tcp_segmentation_evasion":     _build_tcp_segmentation_evasion,
}


def build_cifs_payload(strategy: str):
    """Return (payload_bytes, dst_port) for the given strategy."""
    builder = _BUILDERS.get(strategy)
    if builder is None:
        builder = _build_dialect_negotiation
    payload, dst_port = builder()
    return _clamp(payload), dst_port


# ── Mutator class ──────────────────────────────────────────────────────────

class CifsMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = CIFS_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return CIFS_WEIGHTS

    def mutate(self):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_cifs_payload(strategy)
        return payload, strategy, dst_port
