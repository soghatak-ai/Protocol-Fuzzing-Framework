# fuzzer_framework/engine/mutator.py
import random
import copy
from protocol.dns import DNSMessage

class FuzzLibrary:
    """Expanded libraries to handle deep protocol bit-fuzzing."""
    
    UINT16 = [0x0000, 0xFFFF, 0x7FFF, 0x8000, 0xFFFE]
    UINT32 = [0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, -1]
    
    # 4-bit fields (Opcodes and RCODEs)
    NIBBLE = [0, 15, 14, 8]
    
    # Booleans for single-bit flags
    BOOLEAN = [0, 1]
    
    # 3-bit Reserved Z flag (normally 0, we test 1-7)
    Z_FLAG = [1, 2, 4, 7]

    DOMAINS = [
        "a" * 63 + ".com", "A" * 255, "%n%s%x", "admin.local\x00.com", ""
    ]

class SmartDNSMutator:
    def __init__(self, seed_message: DNSMessage):
        self.message = copy.deepcopy(seed_message)

    def fuzz_field(self, obj, field_name, fuzz_pool):
        if hasattr(obj, field_name):
            setattr(obj, field_name, random.choice(fuzz_pool))

    def mutate(self) -> DNSMessage:
        # We now have 4 attack vectors, including the new Answers section
        target_section = random.choice(["header_counts", "header_flags", "question", "answer"])

        if target_section == "header_counts":
            # Target all 4 memory allocation boundaries
            target_field = random.choice(["qdcount", "ancount", "nscount", "arcount"])
            self.fuzz_field(self.message.header, target_field, FuzzLibrary.UINT16)

        elif target_section == "header_flags":
            # Granularly attack individual logic bits
            target_field = random.choice(["qr", "opcode", "aa", "tc", "rd", "ra", "z", "rcode"])
            if target_field in ["qr", "aa", "tc", "rd", "ra"]:
                self.fuzz_field(self.message.header, target_field, FuzzLibrary.BOOLEAN)
            elif target_field in ["opcode", "rcode"]:
                self.fuzz_field(self.message.header, target_field, FuzzLibrary.NIBBLE)
            elif target_field == "z":
                self.fuzz_field(self.message.header, target_field, FuzzLibrary.Z_FLAG)

        elif target_section == "question" and self.message.questions:
            target_q = random.choice(self.message.questions)
            if random.choice([True, False]):
                self.fuzz_field(target_q, "qname", FuzzLibrary.DOMAINS)
            else:
                self.fuzz_field(target_q, "qtype", FuzzLibrary.UINT16)

        elif target_section == "answer" and self.message.answers:
            # Target the TTL (Cache logic) or RDLENGTH (Buffer allocation)
            target_a = random.choice(self.message.answers)
            if random.choice([True, False]):
                self.fuzz_field(target_a, "ttl", FuzzLibrary.UINT32)
            else:
                # The ultimate buffer overflow test: length says 65535, but payload is tiny
                self.fuzz_field(target_a, "rdlength", FuzzLibrary.UINT16)

        # POST-MUTATION FIXUP
        if target_section not in ["header_counts", "answer"]:
            self.message.header.qdcount = len(self.message.questions)
            self.message.header.ancount = len(self.message.answers)

        return self.message

class ByteMutator:
    @staticmethod
    def bit_flip(payload: bytes) -> bytes:
        if not payload: return payload
        byte_array = bytearray(payload)
        byte_idx = random.randint(0, len(byte_array) - 1)
        bit_idx = random.randint(0, 7)
        byte_array[byte_idx] ^= (1 << bit_idx)
        return bytes(byte_array)