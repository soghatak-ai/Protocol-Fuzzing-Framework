
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


def build_compression_loop_packet(loop_type: str = "self_ref", transaction_id: int = None) -> bytes:
    tid = transaction_id if transaction_id is not None else random.randint(0, 65535)
    flags = 0x0100
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)

    if loop_type == "self_ref":
        qname = b"\xc0\x0c"
        return header + qname + struct.pack("!HH", 1, 1)

    elif loop_type == "mutual":
        qname = b"\xc0\x10"
        qtype = struct.pack("!H", 1)
        qclass_as_ptr = b"\xc0\x0c"
        return header + qname + qtype + qclass_as_ptr

    elif loop_type == "chain":
        qname = b"\xc0\x12"
        qtype_qclass = struct.pack("!HH", 1, 1)
        hop1 = b"\xc0\x18" + b"\x00\x00\x00\x00"
        hop2 = b"\xc0\x1e" + b"\x00\x00\x00\x00"
        hop3 = b"\xc0\x0c" + b"\x00\x00\x00\x00"
        return header + qname + qtype_qclass + hop1 + hop2 + hop3

    return header + b"\xc0\x0c" + struct.pack("!HH", 1, 1)


def build_label_flood_packet(strategy: str = "max_labels", transaction_id: int = None) -> bytes:
    tid = transaction_id if transaction_id is not None else random.randint(0, 65535)
    flags = 0x0100
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)

    if strategy == "max_labels":
        label = b"\x3f" + b"A" * 63
        qname = label * 6 + b"\x00"
    elif strategy == "tiny_labels":
        label = b"\x01" + b"a"
        qname = label * 200 + b"\x00"
    else:
        label = b"\x3f" + b"B" * 63
        qname = label * 6 + b"\x00"

    return header + qname + struct.pack("!HH", 1, 1)


def build_response_packet(anomaly: str = "rdlength_mismatch", transaction_id: int = None) -> bytes:
    tid = transaction_id if transaction_id is not None else random.randint(0, 65535)
    flags = 0x8180
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack("!HH", 1, 1)
    ans_name = b"\xc0\x0c"

    if anomaly == "rdlength_mismatch":
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        rdlength_lie = random.choice([100, 255, 512, 0xFFFF])
        rdata = b"\x08\x08\x08\x08"
        answer = ans_name + struct.pack("!HHIH", 1, 1, 300, rdlength_lie) + rdata
        return header + question + answer

    elif anomaly == "cname_bad_pointer":
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        bad_offset = random.choice([0xFF, 0x1FF, 0x3FF, 0x0D])
        rdata = struct.pack("!BB", 0xC0 | (bad_offset >> 8), bad_offset & 0xFF)
        answer = ans_name + struct.pack("!HHIH", 5, 1, 300, len(rdata)) + rdata
        return header + question + answer

    elif anomaly == "count_mismatch":
        header = struct.pack("!HHHHHH", tid, flags, 1, random.randint(3, 20), 0, 0)
        rdata = b"\x08\x08\x08\x08"
        answer = ans_name + struct.pack("!HHIH", 1, 1, 300, len(rdata)) + rdata
        return header + question + answer

    elif anomaly == "zero_rdlength":
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        rtype = random.choice([1, 2, 5, 6, 15, 16, 28, 33])
        answer = ans_name + struct.pack("!HHIH", rtype, 1, 0, 0)
        return header + question + answer

    elif anomaly == "multi_record_overlap":
        header = struct.pack("!HHHHHH", tid, flags, 1, 3, 0, 0)
        ans1_rdata = b"\x0awww\x06target\x03com\x00"
        ans1 = ans_name + struct.pack("!HHIH", 1, 1, 300, len(ans1_rdata)) + ans1_rdata
        rdata_offset = 12 + len(question) + len(ans_name) + 10
        ans2_rdata = struct.pack("!BB", 0xC0 | (rdata_offset >> 8), rdata_offset & 0xFF)
        ans2 = ans_name + struct.pack("!HHIH", 5, 1, 300, len(ans2_rdata)) + ans2_rdata
        ans3_rdata = b"\x7f\x00\x00\x01"
        ans3 = ans_name + struct.pack("!HHIH", 1, 1, 300, len(ans3_rdata)) + ans3_rdata
        return header + question + ans1 + ans2 + ans3

    elif anomaly == "srv_malformed":
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        rdata = struct.pack("!HHH", 10, 60, 5060) + b"\x04sip\x07"
        answer = ans_name + struct.pack("!HHIH", 33, 1, 300, len(rdata)) + rdata
        return header + question + answer

    elif anomaly == "mx_bad_pointer":
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        rdata = struct.pack("!H", 10) + struct.pack("!BB", 0xC0, random.choice([0, 1, 6, 11]))
        answer = ans_name + struct.pack("!HHIH", 15, 1, 300, len(rdata)) + rdata
        return header + question + answer

    elif anomaly == "txt_overflow":
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        rdata = b"\xff" + b"A" * random.randint(1, 10)
        answer = ans_name + struct.pack("!HHIH", 16, 1, 300, len(rdata)) + rdata
        return header + question + answer

    return build_response_packet("rdlength_mismatch", tid)