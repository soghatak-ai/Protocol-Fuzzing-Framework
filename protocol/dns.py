# fuzzer_framework/protocol/dns.py
import struct
import random

def encode_domain_name(domain: str) -> bytes:
    encoded = b""
    if domain == "":
        return b"\x00"
    for label in domain.split("."):
        length = len(label)
        encoded += struct.pack("B", length) + label.encode("ascii")
    encoded += b"\x00"
    return encoded

class DNSHeader:
    def __init__(self, transaction_id=None):
        self.transaction_id = transaction_id if transaction_id is not None else random.randint(0, 65535)
        
        # Breakdown of the 16-bit flags field
        self.qr = 0          # Query (0) or Response (1)
        self.opcode = 0      # 0 = Standard Query, 1-15 = Other/Reserved
        self.aa = 0          # Authoritative Answer
        self.tc = 0          # Truncated
        self.rd = 1          # Recursion Desired (Default 1 for standard queries)
        self.ra = 0          # Recursion Available
        self.z = 0           # Reserved (Must be 0)
        self.rcode = 0       # Response Code (0 = No Error, 1-15 = Errors)

        # Section Counts
        self.qdcount = 1
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

    def assemble_flags(self) -> int:
        """Packs the individual bits into a single 16-bit integer."""
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | \
                (self.z << 4) | self.rcode
        return flags

    def to_bytes(self) -> bytes:
        flags_packed = self.assemble_flags()
        return struct.pack(
            "!HHHHHH", self.transaction_id, flags_packed, self.qdcount, 
            self.ancount, self.nscount, self.arcount
        )

class DNSQuestion:
    def __init__(self, qname, qtype=1, qclass=1):
        self.qname = qname       
        self.qtype = qtype       
        self.qclass = qclass     

    def to_bytes(self) -> bytes:
        return encode_domain_name(self.qname) + struct.pack("!HH", self.qtype, self.qclass)

class DNSAnswer:
    def __init__(self, name, rtype=1, rclass=1, ttl=300, rdata=b"\x08\x08\x08\x08"):
        self.name = name       
        self.rtype = rtype       
        self.rclass = rclass     
        self.ttl = ttl           # 32-bit Time to Live
        self.rdata = rdata       # Raw bytes of the answer (e.g., an IP address)
        self.rdlength = len(rdata) # Automatically calculated length

    def to_bytes(self) -> bytes:
        encoded_name = encode_domain_name(self.name)
        # Pack Type (2), Class (2), TTL (4), and Length (2)
        metadata = struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, self.rdlength)
        return encoded_name + metadata + self.rdata

class DNSMessage:
    def __init__(self, header: DNSHeader, questions: list, answers=None):
        self.header = header
        self.questions = questions
        self.answers = answers if answers is not None else []
        
        # Auto-sync counts for valid structure
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)

    def to_bytes(self) -> bytes:
        packet = self.header.to_bytes()
        for q in self.questions:
            packet += q.to_bytes()
        for a in self.answers:
            packet += a.to_bytes()
        return packet