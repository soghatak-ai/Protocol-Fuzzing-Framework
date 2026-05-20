import struct
import socket
import random
import time

class StreamTransport:
    def __init__(self, target_port: int = 53):
        self.port = target_port

    def get_global_header(self) -> bytes:
        """Returns the standard PCAP global header required at the start of the stream."""
        return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    def wrap_payload(self, payload: bytes, src_ip: int = 0x7f000001, src_port: int = 12345) -> bytes:
        """Wraps a raw DNS payload into a full Ethernet/IP/UDP PCAP record."""
        # Standard Mock MAC addresses
        eth_header = b"\x00\x0c\x29\x00\x00\x01\x00\x0c\x29\x00\x00\x02\x08\x00"
        
        # IPv4 Header
        ip_total_len = 20 + 8 + len(payload)
        ip_header = struct.pack("!BBHHHBBHII", 0x45, 0, ip_total_len, 54321, 0, 64, 17, 0, src_ip, 0x7f000001)
        
        # Calculate Checksum
        checksum = sum(struct.unpack("!%dH" % (len(ip_header)//2), ip_header))
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        ip_header = ip_header[:10] + struct.pack("!H", ~checksum & 0xFFFF) + ip_header[12:]
        
        # UDP Header
        udp_len = 8 + len(payload)
        udp_header = struct.pack("!HHHH", src_port, self.port, udp_len, 0)
        
        full_packet = eth_header + ip_header + udp_header + payload
        
        # PCAP Packet Record Header (Timestamp sec, Timestamp usec, Saved Len, Orig Len)
        ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        packet_header = struct.pack("<IIII", ts_sec, ts_usec, len(full_packet), len(full_packet))
        
        return packet_header + full_packet


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