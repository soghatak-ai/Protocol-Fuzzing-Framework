import struct

class StreamTransport:
    def __init__(self, target_port: int = 53):
        self.port = target_port

    def get_global_header(self) -> bytes:
        """Returns the standard PCAP global header required at the start of the stream."""
        return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    def wrap_payload(self, payload: bytes) -> bytes:
        """Wraps a raw DNS payload into a full Ethernet/IP/UDP PCAP record."""
        # Standard Mock MAC addresses
        eth_header = b"\x00\x0c\x29\x00\x00\x01\x00\x0c\x29\x00\x00\x02\x08\x00"
        
        # IPv4 Header
        ip_total_len = 20 + 8 + len(payload)
        ip_header = struct.pack("!BBHHHBBHII", 0x45, 0, ip_total_len, 54321, 0, 64, 17, 0, 0x7f000001, 0x7f000001)
        
        # Calculate Checksum
        checksum = sum(struct.unpack("!%dH" % (len(ip_header)//2), ip_header))
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        ip_header = ip_header[:10] + struct.pack("!H", ~checksum & 0xFFFF) + ip_header[12:]
        
        # UDP Header
        udp_len = 8 + len(payload)
        udp_header = struct.pack("!HHHH", 12345, self.port, udp_len, 0)
        
        full_packet = eth_header + ip_header + udp_header + payload
        
        # PCAP Packet Record Header (Timestamp sec, Timestamp usec, Saved Len, Orig Len)
        packet_header = struct.pack("<IIII", 0, 0, len(full_packet), len(full_packet))
        
        return packet_header + full_packet