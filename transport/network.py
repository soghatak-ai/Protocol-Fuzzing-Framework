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
    Sends real DNS/FTP packets over the network to a target server.
    Used in live-network mode: fuzzer → NIC → [FTD/Snort] → server.

    UDP strategies send the raw DNS payload directly (no framing).
    TCP strategies send the 2-byte TCP-DNS length-prefixed payload over a
    real TCP connection with TCP_NODELAY so each send() call produces a
    separate TCP segment — exercising Snort's TCP reassembly state machine.
    """

    def __init__(self, server_ip: str, server_port: int = 53,
                 interface: str = None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.interface = interface

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

    def send_udp(self, dns_payload: bytes, port: int = None):
        """Send a raw UDP payload.  Uses server_port unless overridden."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                self._bind_iface(s)
                s.sendto(dns_payload, (self.server_ip, port or self.server_port))
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