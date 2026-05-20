from corpus.seed_generator import generate_basic_query
from transport.network import DNSTransport

if __name__ == "__main__":
    print("[*] Manufacturing standard seed packet...")
    payload = generate_basic_query("google.com")
    
    target_dns = "8.8.8.8"
    sender = DNSTransport(target_host=target_dns, timeout=2.0)
    
    print(f"[*] Sending valid UDP query to {target_dns}...")
    udp_response = sender.send_udp(payload)
    print(f"[+] UDP Response Raw Hex (First 20 bytes): {udp_response[:20].hex()}")
    
    print(f"\n[*] Sending valid TCP query to {target_dns}...")
    tcp_response = sender.send_tcp(payload)
    print(f"[+] TCP Response Raw Hex (First 20 bytes): {tcp_response[:20].hex()}")