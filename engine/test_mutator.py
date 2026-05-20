
from protocol.dns import DNSHeader, DNSQuestion, DNSMessage
from engine.mutator import SmartDNSMutator, ByteMutator


question = DNSQuestion(qname="example.com")
header = DNSHeader()
seed = DNSMessage(header=header, questions=[question])


for i in range(3):
    mutator = SmartDNSMutator(seed)
    mutated_msg = mutator.mutate()
    print(f"[Generation {i+1}] Questions: {len(mutated_msg.questions)} | Header qdcount: {mutated_msg.header.qdcount}")


raw_bytes = seed.to_bytes()
print(f"\n[Byte Flip] Original : {raw_bytes.hex()}")
print(f"[Byte Flip] Mutated  : {ByteMutator.bit_flip(raw_bytes).hex()}")