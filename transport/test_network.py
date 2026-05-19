# fuzzer_framework/transport/test_network.py
from corpus.seed_generator import generate_basic_query
from transport.network import DNSTransport

if __name__ == "__main__":
    # Let's generate a clean, valid query for google.com
    # (Since we are testing network connectivity, use a live target or local dev setup)
    print("[*] Manufacturing standard seed packet...")
    payload = generate_basic_query("google.com")
    
    # Target Google's public DNS server for a single live loopback test
    target_dns = "8.8.8.8"
    sender = DNSTransport(target_host=target_dns, timeout=2.0)
    
    print(f"[*] Sending valid UDP query to {target_dns}...")
    udp_response = sender.send_udp(payload)
    print(f"[+] UDP Response Raw Hex (First 20 bytes): {udp_response[:20].hex()}")
    
    print(f"\n[*] Sending valid TCP query to {target_dns}...")
    tcp_response = sender.send_tcp(payload)
    print(f"[+] TCP Response Raw Hex (First 20 bytes): {tcp_response[:20].hex()}")