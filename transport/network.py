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
    if len(tcp_seg) % 2:
        tcp_seg = tcp_seg + b"\x00"
    pseudo = struct.pack("!IIBBH", src_ip, dst_ip, 0, 6, len(tcp_seg))
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

        syn     = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c, 0, 0x02)
        syn_ack = self._ETH_S2C + self._tcp_pkt(dst_ip, src_ip, dport, src_port, seq_s, seq_c + 1, 0x12)
        ack     = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c + 1, seq_s + 1, 0x10)
        psh_ack = self._ETH_C2S + self._tcp_pkt(src_ip, dst_ip, src_port, dport, seq_c + 1, seq_s + 1, 0x18, payload)

        return (self._pcap_record(syn) + self._pcap_record(syn_ack) +
                self._pcap_record(ack) + self._pcap_record(psh_ack))


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