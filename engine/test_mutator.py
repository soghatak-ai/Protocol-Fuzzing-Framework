# fuzzer_framework/engine/test_mutator.py
from protocol.dns import DNSHeader, DNSQuestion, DNSMessage
from engine.mutator import SmartDNSMutator, ByteMutator

# 1. Generate a valid seed message
question = DNSQuestion(qname="example.com")
header = DNSHeader()
seed = DNSMessage(header=header, questions=[question])

# 2. Run the Smart Mutator 3 times to see different dynamic attacks
for i in range(3):
    mutator = SmartDNSMutator(seed)
    mutated_msg = mutator.mutate()
    print(f"[Generation {i+1}] Questions: {len(mutated_msg.questions)} | Header qdcount: {mutated_msg.header.qdcount}")

# 3. Test Byte Mutator
raw_bytes = seed.to_bytes()
print(f"\n[Byte Flip] Original : {raw_bytes.hex()}")
print(f"[Byte Flip] Mutated  : {ByteMutator.bit_flip(raw_bytes).hex()}")