
from protocol.dns import DNSHeader, DNSQuestion, DNSMessage

def generate_basic_query(domain: str) -> bytes:
    """Generates a valid A record query for the given domain."""
    question = DNSQuestion(qname=domain, qtype=1, qclass=1)
    header = DNSHeader(transaction_id=4242)
    message = DNSMessage(header=header, questions=[question])
    
    return message.to_bytes()

if __name__ == "__main__":
    raw_payload = generate_basic_query("example.com")
    print(f"[+] Generated Seed Payload (Hex): {raw_payload.hex()}")
    
    # Optional: Save it to a file so the fuzzer can load it later
    with open("valid_query.seed", "wb") as f:
        f.write(raw_payload)
        print("[+] Saved to valid_query.seed")