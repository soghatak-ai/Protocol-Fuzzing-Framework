
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
        self.qr = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 1
        self.ra = 0
        self.z = 0
        self.rcode = 0
        self.qdcount = 1
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

    def assemble_flags(self) -> int:
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
        self.ttl = ttl           
        self.rdata = rdata
        self.rdlength = len(rdata) 

    def to_bytes(self) -> bytes:
        encoded_name = encode_domain_name(self.name)
        metadata = struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, self.rdlength)
        return encoded_name + metadata + self.rdata

class DNSMessage:
    def __init__(self, header: DNSHeader, questions: list, answers=None):
        self.header = header
        self.questions = questions
        self.answers = answers if answers is not None else []
        
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)

    def to_bytes(self) -> bytes:
        packet = self.header.to_bytes()
        for q in self.questions:
            packet += q.to_bytes()
        for a in self.answers:
            packet += a.to_bytes()
        return packet