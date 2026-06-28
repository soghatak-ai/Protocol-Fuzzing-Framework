import struct
import socket
import random
import time


def _ip_checksum(hdr: bytes) -> int:
    s = sum(struct.unpack("!%dH" % (len(hdr) // 2), hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _tcp_checksum(src_ip: int, dst_ip: int, tcp_seg: bytes) -> int:
    orig_len = len(tcp_seg)
    if orig_len % 2:
        tcp_seg = tcp_seg + b"\x00"
    pseudo = struct.pack("!IIBBH", src_ip, dst_ip, 0, 6, orig_len)
    blob = pseudo + tcp_seg
    s = sum(struct.unpack("!%dH" % (len(blob) // 2), blob))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


_MAX_ICMP = 65515  # max ICMP payload: 65535 - 20 (IP header)


class StreamTransport:
    _ETH_C2S = b"\x00\x0c\x29\x00\x00\x02\x00\x0c\x29\x00\x00\x01\x08\x00"
    _ETH_S2C = b"\x00\x0c\x29\x00\x00\x01\x00\x0c\x29\x00\x00\x02\x08\x00"

    def __init__(self, target_port: int = 53):
        self.port = target_port

    def get_global_header(self) -> bytes:
        """Returns the standard PCAP global header required at the start of the stream."""
        return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    def _pcap_record(self, pkt: bytes) -> bytes:
        ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        return struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)) + pkt

    def _ip_hdr(self, proto: int, src: int, dst: int, payload_len: int) -> bytes:
        ip_len = 20 + payload_len
        hdr = bytearray(struct.pack("!BBHHHBBHII",
            0x45, 0, ip_len, random.randint(1, 65535), 0x4000, 64, proto, 0, src, dst))
        hdr[10:12] = struct.pack("!H", _ip_checksum(bytes(hdr)))
        return bytes(hdr)

    def _tcp_pkt(self, src_ip: int, dst_ip: int, sport: int, dport: int,
                 seq: int, ack_seq: int, flags: int, data: bytes = b"") -> bytes:
        tcp = bytearray(struct.pack("!HHIIBBHHH",
            sport, dport, seq, ack_seq, 0x50, flags, 65535, 0, 0))
        seg = bytes(tcp) + data
        tcp[16:18] = struct.pack("!H", _tcp_checksum(src_ip, dst_ip, seg))
        ip = self._ip_hdr(6, src_ip, dst_ip, len(tcp) + len(data))
        return ip + bytes(tcp) + data

    def wrap_payload(self, payload: bytes, src_ip: int = 0x7f000001, src_port: int = 12345) -> bytes:
        """Wraps a raw payload into a full Ethernet/IP/UDP PCAP record (for DNS)."""
        eth = b"\x00\x0c\x29\x00\x00\x01\x00\x0c\x29\x00\x00\x02\x08\x00"
        ip_total_len = 20 + 8 + len(payload)
        ip_hdr = bytearray(struct.pack("!BBHHHBBHII",
            0x45, 0, ip_total_len, 54321, 0, 64, 17, 0, src_ip, 0x7f000001))
        ip_hdr[10:12] = struct.pack("!H", _ip_checksum(bytes(ip_hdr)))
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", src_port, self.port, udp_len, 0)
        pkt = eth + bytes(ip_hdr) + udp + payload
        return self._pcap_record(pkt)

    def wrap_tcp_session(self, payload: bytes, src_ip: int = 0x7f000001,
                         src_port: int = None, dst_ip: int = 0x7f000001) -> bytes:
        """
        Emits four PCAP records forming a complete TCP session:
            SYN → SYN-ACK → ACK → PSH-ACK(payload)
        This satisfies Snort's stream inspector so the FTP application-layer
        inspector actually processes the payload bytes.
        """
        if src_port is None:
            src_port = random.randint(1025, 65534)
        payload = payload[:60000]  # clamp to fit in one IP packet (16-bit length field)
        seq_c = random.randint(100000, 9000000)
        seq_s = random.randint(100000, 9000000)
        dport = self.port

        syn      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c, 0, 0x02)
        syn_ack  = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port, seq_s, seq_c + 1, 0x12)
        ack      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c + 1, seq_s + 1, 0x10)
        psh_ack  = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c + 1, seq_s + 1, 0x18, payload)
        cli_fin  = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport,
                                                  seq_c + 1 + len(payload), seq_s + 1, 0x11)
        srv_fin  = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port,
                                                  seq_s + 1, seq_c + 2 + len(payload), 0x11)
        last_ack = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport,
                                                  seq_c + 2 + len(payload), seq_s + 2, 0x10)

        return (self._pcap_record(syn) + self._pcap_record(syn_ack) +
                self._pcap_record(ack) + self._pcap_record(psh_ack) +
                self._pcap_record(cli_fin) + self._pcap_record(srv_fin) +
                self._pcap_record(last_ack))

    def wrap_tcp_response_session(self, response: bytes, request: bytes = None,
                                  src_ip: int = 0x7f000001, src_port: int = None,
                                  dst_ip: int = 0x7f000001) -> bytes:
        """
        Emits a full TCP session carrying a CLIENT REQUEST (C2S) followed by a
        possibly malformed SERVER RESPONSE (S2C):
            SYN → SYN-ACK → ACK → PSH-ACK(request) → ACK
                → PSH-ACK(response) → FIN-ACK(server) → ACK/FIN(client) → ACK
        The server closes the connection right after the body, which is required
        for HTTP/0.9-style responses that are delimited only by EOF.

        This drives Snort's http_inspect RESPONSE parser (status line, response
        headers, Content-/Transfer-Encoding, decompression, body extraction) —
        the surface targeted by the HTTP Evader semantic-gap evasions.
        """
        if src_port is None:
            src_port = random.randint(1025, 65534)
        if request is None:
            request = b"GET / HTTP/1.1\r\nHost: victim.example.com\r\n\r\n"
        response = response[:60000]
        dport = self.port
        seq_c = random.randint(100000, 9000000)
        seq_s = random.randint(100000, 9000000)

        syn      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c, 0, 0x02)
        syn_ack  = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port, seq_s, seq_c + 1, 0x12)
        ack      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c + 1, seq_s + 1, 0x10)

        # Client request (C2S)
        req      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport,
                                                 seq_c + 1, seq_s + 1, 0x18, request)
        seq_c2 = seq_c + 1 + len(request)
        req_ack  = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port,
                                                 seq_s + 1, seq_c2, 0x10)

        # Server response (S2C)
        resp     = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port,
                                                 seq_s + 1, seq_c2, 0x18, response)
        seq_s2 = seq_s + 1 + len(response)
        srv_fin  = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port,
                                                 seq_s2, seq_c2, 0x11)
        cli_ack  = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport,
                                                 seq_c2, seq_s2 + 1, 0x10)
        cli_fin  = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport,
                                                 seq_c2, seq_s2 + 1, 0x11)
        last_ack = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port,
                                                 seq_s2 + 1, seq_c2 + 1, 0x10)

        return (self._pcap_record(syn) + self._pcap_record(syn_ack) +
                self._pcap_record(ack) + self._pcap_record(req) +
                self._pcap_record(req_ack) + self._pcap_record(resp) +
                self._pcap_record(srv_fin) + self._pcap_record(cli_ack) +
                self._pcap_record(cli_fin) + self._pcap_record(last_ack))

    def _ip_frag_hdr(self, proto: int, src: int, dst: int, payload_len: int,
                     ip_id: int, frag_offset_bytes: int, more_fragments: bool) -> bytes:
        """Build an IP header with fragmentation fields."""
        ip_len = 20 + payload_len
        # flags_frag: bit 13 = MF, bits 12-0 = offset in 8-byte units
        offset_units = frag_offset_bytes // 8
        flags_frag = (offset_units & 0x1FFF) | (0x2000 if more_fragments else 0)
        hdr = bytearray(struct.pack("!BBHHHBBHII",
            0x45, 0, ip_len, ip_id, flags_frag, 64, proto, 0, src, dst))
        hdr[10:12] = struct.pack("!H", _ip_checksum(bytes(hdr)))
        return bytes(hdr)

    def wrap_ip_fragments(self, fragments, src_ip: int = 0x7f000001,
                          dst_ip: int = 0x7f000001) -> bytes:
        """Wrap a list of IP fragment descriptors as PCAP records.
        Each fragment: (payload_bytes, frag_offset_bytes, more_frags, ip_id, proto)"""
        records = b''
        for payload, frag_off, mf, ip_id, proto in fragments:
            ip = self._ip_frag_hdr(proto, src_ip, dst_ip, len(payload),
                                   ip_id, frag_off, mf)
            pkt = self._ETH_C2S + ip + payload
            records += self._pcap_record(pkt)
        return records

    def wrap_udp_to_port(self, payload: bytes, dst_port: int,
                         src_ip: int = 0x7f000001, src_port: int = 12345) -> bytes:
        """Like wrap_payload but allows targeting an arbitrary destination port."""
        payload = payload[:65507]  # max UDP payload in IPv4: 65535 - 20 (IP) - 8 (UDP)
        ip_total_len = 20 + 8 + len(payload)
        ip_hdr = bytearray(struct.pack("!BBHHHBBHII",
            0x45, 0, ip_total_len, random.randint(1, 0xFFFF), 0, 64, 17, 0,
            src_ip, 0x7f000001))
        ip_hdr[10:12] = struct.pack("!H", _ip_checksum(bytes(ip_hdr)))
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        pkt = self._ETH_C2S + bytes(ip_hdr) + udp + payload
        return self._pcap_record(pkt)

    def wrap_tcp_session_to_port(self, payload: bytes, dst_port: int,
                                 src_ip: int = 0x7f000001,
                                 dst_ip: int = 0x7f000001) -> bytes:
        """Full TCP session targeting an arbitrary port with proper teardown."""
        src_port = random.randint(1025, 65534)
        payload = payload[:60000]
        seq_c = random.randint(100000, 9000000)
        seq_s = random.randint(100000, 9000000)
        syn      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dst_port, seq_c, 0, 0x02)
        syn_ack  = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dst_port, src_port, seq_s, seq_c + 1, 0x12)
        ack      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dst_port, seq_c + 1, seq_s + 1, 0x10)
        psh_ack  = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dst_port, seq_c + 1, seq_s + 1, 0x18, payload)
        cli_fin  = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dst_port,
                                                  seq_c + 1 + len(payload), seq_s + 1, 0x11)
        srv_fin  = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dst_port, src_port,
                                                  seq_s + 1, seq_c + 2 + len(payload), 0x11)
        last_ack = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dst_port,
                                                  seq_c + 2 + len(payload), seq_s + 2, 0x10)
        return (self._pcap_record(syn) + self._pcap_record(syn_ack) +
                self._pcap_record(ack) + self._pcap_record(psh_ack) +
                self._pcap_record(cli_fin) + self._pcap_record(srv_fin) +
                self._pcap_record(last_ack))

    def wrap_icmp(self, icmp_payload: bytes, src_ip: int = 0x7f000001,
                  dst_ip: int = 0x7f000001) -> bytes:
        """Wrap raw ICMP bytes in Ethernet/IP(proto=1)/PCAP record."""
        icmp_payload = icmp_payload[:_MAX_ICMP]
        ip = self._ip_hdr(1, src_ip, dst_ip, len(icmp_payload))
        pkt = self._ETH_C2S + ip + icmp_payload
        return self._pcap_record(pkt)

    def wrap_raw_ip_packet(self, ip_packet: bytes) -> bytes:
        """Wrap a pre-built IP packet (header included) in Ethernet + PCAP."""
        pkt = self._ETH_C2S + ip_packet
        return self._pcap_record(pkt)

    # Ethernet headers for IPv6 (EtherType 0x86DD)
    _ETH6_C2S = b"\x00\x0c\x29\x00\x00\x02\x00\x0c\x29\x00\x00\x01\x86\xDD"
    _ETH6_S2C = b"\x00\x0c\x29\x00\x00\x01\x00\x0c\x29\x00\x00\x02\x86\xDD"

    def _ipv6_hdr(self, next_header: int, src: bytes, dst: bytes,
                  payload_len: int, hop_limit: int = 64) -> bytes:
        """Build a bare IPv6 header (40 bytes)."""
        ver_tc_fl = (6 << 28)
        return struct.pack("!IHBB", ver_tc_fl, payload_len, next_header,
                           hop_limit) + src + dst

    def wrap_icmpv6(self, icmpv6_payload: bytes, src_ipv6: bytes,
                    dst_ipv6: bytes) -> bytes:
        """Wrap raw ICMPv6 bytes in Ethernet(IPv6)/IPv6(NH=58)/PCAP record."""
        ipv6 = self._ipv6_hdr(58, src_ipv6, dst_ipv6, len(icmpv6_payload))
        pkt = self._ETH6_C2S + ipv6 + icmpv6_payload
        return self._pcap_record(pkt)

    def wrap_raw_ipv6_packet(self, ipv6_packet: bytes) -> bytes:
        """Wrap a pre-built IPv6 packet in Ethernet + PCAP."""
        pkt = self._ETH6_C2S + ipv6_packet
        return self._pcap_record(pkt)

    def wrap_ipv6_fragments(self, fragment_packets: list) -> bytes:
        """Wrap a list of pre-built IPv6 fragment packets as PCAP records."""
        records = b''
        for frag_pkt in fragment_packets:
            pkt = self._ETH6_C2S + frag_pkt
            records += self._pcap_record(pkt)
        return records

    def wrap_split_tcp_session(self, payload: bytes, split_at: int = 1,
                               src_ip: int = 0x7f000001, src_port: int = None,
                               dst_ip: int = 0x7f000001) -> bytes:
        """
        Delivers payload as TWO separate PSH-ACK segments before FIN-ACK.
        split_at=1  → exercises DNS_RESP_STATE_LENGTH_PART (1 of 2 length bytes)
        split_at=2  → exercises DNS_RESP_STATE_HDR_ID_PART (partial header)
        split_at=13 → partial DNS header (all but last byte)
        This forces Snort's TCP-DNS state machine through every partial-read
        state handler that rarely fires in single-packet testing.
        """
        if src_port is None:
            src_port = random.randint(1025, 65534)
        payload = payload[:60000]
        split_at = max(1, min(split_at, len(payload) - 1))
        part1, part2 = payload[:split_at], payload[split_at:]

        seq_c = random.randint(100000, 9000000)
        seq_s = random.randint(100000, 9000000)
        dport = self.port

        syn      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c, 0, 0x02)
        syn_ack  = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port, seq_s, seq_c + 1, 0x12)
        ack      = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c + 1, seq_s + 1, 0x10)
        psh_ack1 = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport,
                                                  seq_c + 1, seq_s + 1, 0x18, part1)
        psh_ack2 = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport,
                                                  seq_c + 1 + len(part1), seq_s + 1, 0x18, part2)
        fin_ack  = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport,
                                                  seq_c + 1 + len(payload), seq_s + 1, 0x11)

        return (self._pcap_record(syn) + self._pcap_record(syn_ack) + self._pcap_record(ack) +
                self._pcap_record(psh_ack1) + self._pcap_record(psh_ack2) +
                self._pcap_record(fin_ack))



class LiveNetworkTransport:
    """
    Sends real protocol packets over the network to a target server.
    Used in live-network mode: fuzzer → NIC → [FTD/Snort] → server.

    UDP strategies send the raw DNS payload directly (no framing).
    TCP strategies can either use one-shot sockets or persistent sockets with
    TCP_NODELAY so each send() call produces a distinct segment while keeping
    Snort's stream/app inspector state alive across fuzz iterations.
    """

    def __init__(self, server_ip: str, server_port: int = 53,
                 interface: str = None, mem_pressure: bool = False):
        self.server_ip = server_ip
        self.server_port = server_port
        self.interface = interface
        self.mem_pressure = mem_pressure
        self._persistent_tcp_sockets = {}
        self._udp_socket = None
        self._pressure_pool = {}
        self._PRESSURE_POOL_SIZE = 60

    def _bind_iface(self, sock: socket.socket):
        """Bind socket to a specific interface (Linux: SO_BINDTODEVICE)."""
        if not self.interface:
            return
        try:
            import platform as _plat
            if _plat.system() == "Linux":
                sock.setsockopt(socket.SOL_SOCKET, 25, self.interface.encode())
        except Exception:
            pass

    def _get_udp_socket(self) -> socket.socket:
        """Return a reusable UDP socket, creating one if needed."""
        if self._udp_socket is not None:
            return self._udp_socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        self._bind_iface(sock)
        self._udp_socket = sock
        return sock

    def send_udp(self, dns_payload: bytes, port: int = None):
        """Send a raw UDP payload via a reusable socket."""
        try:
            self._get_udp_socket().sendto(
                dns_payload, (self.server_ip, port or self.server_port)
            )
        except OSError:
            try:
                if self._udp_socket is not None:
                    self._udp_socket.close()
            except OSError:
                pass
            self._udp_socket = None
            try:
                self._get_udp_socket().sendto(
                    dns_payload, (self.server_ip, port or self.server_port)
                )
            except OSError:
                pass

    def send_tcp(self, tcp_dns_payload: bytes, port: int = None):
        """
        Send a TCP payload over a real TCP connection with TCP_NODELAY.
        Uses server_port unless overridden.
        Graceful shutdown ensures stream_tcp flushes to the inspector.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(0.05)
                self._bind_iface(s)
                s.connect((self.server_ip, port or self.server_port))
                s.sendall(tcp_dns_payload)
                s.shutdown(socket.SHUT_WR)
                try:
                    s.recv(1)
                except Exception:
                    pass
        except OSError:
            pass

    def _persistent_tcp_socket(self, port: int) -> socket.socket:
        actual_port = port or self.server_port
        sock = self._persistent_tcp_sockets.get(actual_port)
        if sock is not None:
            return sock

        conn_timeout = 0.15 if self.mem_pressure else 0.5
        recv_timeout = 0.05 if self.mem_pressure else 0.5
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack('ii', 1, 0))
        sock.settimeout(conn_timeout)
        self._bind_iface(sock)
        sock.connect((self.server_ip, actual_port))
        sock.settimeout(recv_timeout)
        self._persistent_tcp_sockets[actual_port] = sock
        return sock

    def close_udp(self):
        """Close the reusable UDP socket."""
        sock = self._udp_socket
        self._udp_socket = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def close_persistent_tcp(self, port: int = None):
        """Close one persistent TCP socket, or all of them when port is omitted."""
        if port is None:
            ports = list(self._persistent_tcp_sockets)
        else:
            ports = [port or self.server_port]

        for actual_port in ports:
            sock = self._persistent_tcp_sockets.pop(actual_port, None)
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

        for key in list(self._pressure_pool):
            sock = self._pressure_pool.pop(key, None)
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        if hasattr(self, '_pressure_pending'):
            self._pressure_pending.clear()

    def _pressure_pool_sock(self, port: int, idx: int) -> socket.socket:
        """Get or create one socket in the memory-pressure connection pool."""
        key = (port, idx)
        sock = self._pressure_pool.get(key)
        if sock is not None:
            return sock
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack('ii', 1, 0))
        sock.settimeout(0.1)
        self._bind_iface(sock)
        sock.connect((self.server_ip, port))
        sock.settimeout(0.05)
        self._pressure_pool[key] = sock
        return sock

    def _close_pressure_sock(self, port: int, idx: int):
        key = (port, idx)
        sock = self._pressure_pool.pop(key, None)
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def send_persistent_tcp(self, tcp_payload: bytes, port: int = None,
                            split_at: int = None) -> bool:
        """
        Send over a long-lived TCP connection. If the peer has closed the stream,
        reconnect once and retry the same payload so fuzzing can continue.

        When mem_pressure is enabled, uses a pool of concurrent sockets and
        staggers segment delivery across them to hold Snort reassembly buffers.
        """
        actual_port = port or self.server_port

        if self.mem_pressure and len(tcp_payload) > 4:
            return self._send_pressure(tcp_payload, actual_port, split_at)

        if split_at is not None and len(tcp_payload) > 1:
            split_at = max(1, min(split_at, len(tcp_payload) - 1))
        for _attempt in range(3):
            try:
                sock = self._persistent_tcp_socket(actual_port)
                if split_at is not None and len(tcp_payload) > 1:
                    sock.sendall(tcp_payload[:split_at])
                    sock.sendall(tcp_payload[split_at:])
                else:
                    sock.sendall(tcp_payload)
                return True
            except OSError:
                self.close_persistent_tcp(actual_port)
        return False

    def _send_pressure(self, tcp_payload: bytes, port: int,
                       split_at: int = None) -> bool:
        """Rotate across a large pool of sockets. On each call we:
        1. Pick slot N (round-robin).
        2. If slot N has a pending second segment from a *previous* call,
           deliver it now -- completing that reassembly.
        3. Open (or reuse) a socket on slot N, send only the FIRST segment.
           Store the second segment as pending.
        Because the pool is large (60 slots), the second segment isn't
        delivered until ~60 calls later.  Snort must hold partial reassembly
        state for all ~60 in-flight half-payloads simultaneously."""
        pool_sz = self._PRESSURE_POOL_SIZE
        if not hasattr(self, '_pressure_cursor'):
            self._pressure_cursor = 0
            self._pressure_pending = {}

        idx = self._pressure_cursor % pool_sz
        self._pressure_cursor += 1

        pending = self._pressure_pending.pop(idx, None)
        if pending is not None:
            p_port, p_data = pending
            try:
                sock = self._pressure_pool.get((p_port, idx))
                if sock is not None:
                    sock.sendall(p_data)
            except OSError:
                self._close_pressure_sock(p_port, idx)

        if split_at is None:
            split_at = random.choice([1, 2, 3, max(1, len(tcp_payload) // 3)])
        split_at = max(1, min(split_at, len(tcp_payload) - 1))

        for _attempt in range(2):
            try:
                sock = self._pressure_pool_sock(port, idx)
                sock.sendall(tcp_payload[:split_at])
                self._pressure_pending[idx] = (port, tcp_payload[split_at:])
                return True
            except OSError:
                self._close_pressure_sock(port, idx)
        return False

    def send_icmp(self, icmp_payload: bytes):
        """Send raw ICMP payload via raw socket (requires root/CAP_NET_RAW)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                s.settimeout(0.5)
                self._bind_iface(s)
                s.sendto(icmp_payload, (self.server_ip, 0))
        except OSError:
            pass

    def send_icmpv6(self, icmpv6_payload: bytes, dst_ipv6: str = "::1"):
        """Send raw ICMPv6 payload via raw socket (requires root/CAP_NET_RAW)."""
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58) as s:
                s.settimeout(0.5)
                s.sendto(icmpv6_payload, (dst_ipv6, 0, 0, 0))
        except OSError:
            pass

    def send_split_tcp(self, tcp_dns_payload: bytes, split_at: int = 1):
        """
        Send TCP-DNS in TWO separate send() calls with a 1 ms gap.
        With TCP_NODELAY each send() becomes a distinct TCP segment, forcing
        Snort through DNS_RESP_STATE_LENGTH_PART and other partial-data paths.
        split_at=1  → split after the first byte of the 2-byte length prefix
        split_at=2  → split after the full length prefix (before DNS header)
        split_at=13 → split mid-DNS-header
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # Extremely short timeout
                s.settimeout(0.05)
                self._bind_iface(s)
                s.connect((self.server_ip, self.server_port))
                split_at = max(1, min(split_at, len(tcp_dns_payload) - 1))
                s.send(tcp_dns_payload[:split_at])
                # Minimal sleep to force fragmentation without killing throughput
                time.sleep(0.0001)
                s.send(tcp_dns_payload[split_at:])
                s.shutdown(socket.SHUT_WR)
                try:
                    s.recv(1)
                except Exception:
                    pass
        except OSError:
            pass


class LiveTransport:
    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 53, pool_size: int = 100):
        self.target_host = target_host
        self.target_port = target_port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._pool = self._build_pool(pool_size)
        print(f"[LiveTransport] Socket pool ready: {len(self._pool)} unique source ports bound")

    def _build_pool(self, pool_size: int) -> list:
        pool = []
        port = 30000
        while len(pool) < pool_size and port < 60000:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind(("", port))
                pool.append(s)
            except OSError:
                s.close()
            port += 1
        return pool

    def send(self, payload: bytes):
        self._sock.sendto(payload, (self.target_host, self.target_port))

    def send_spoofed(self, payload: bytes):
        s = random.choice(self._pool)
        s.sendto(payload, (self.target_host, self.target_port))

    def close(self):
        self._sock.close()
        for s in self._pool:
            s.close()