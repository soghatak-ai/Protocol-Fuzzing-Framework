# fuzzer_framework/main.py
import os
import time
import random
from corpus.seed_generator import generate_basic_query
from protocol.dns import DNSMessage, DNSHeader, DNSQuestion
from engine.mutator import SmartDNSMutator, ByteMutator
from transport.network import DNSTransport
from monitor.oracle import ServerOracle

def save_crash(payload: bytes, iteration: int):
    """Saves the packet that crashed the server to disk."""
    timestamp = int(time.time())
    filename = f"crashes/crash_iter_{iteration}_{timestamp}.pcapng" # We'll save raw bytes for now
    
    with open(f"crashes/crash_iter_{iteration}_{timestamp}.bin", "wb") as f:
        f.write(payload)
    print(f"\n[!!!] CRASH DETECTED [!!!]")
    print(f"[+] Saved fatal payload to crashes/crash_iter_{iteration}_{timestamp}.bin")

def run_fuzzer(target_host: str, target_port: int, protocol: str = "UDP"):
    print(f"[*] Starting Protocol Fuzzer against {target_host}:{target_port} ({protocol})")
    
    # 1. Initialize Transport and Oracle
    transport = DNSTransport(target_host, target_port, timeout=3.0)
    oracle = ServerOracle(target_host, target_port, protocol)
    
    # 2. Verify target is alive before we start attacking
    print("[*] Performing initial health check...")
    if not oracle.check_health():
        print("[-] Target is already dead or unreachable. Aborting.")
        return
    print("[+] Target is alive. Commencing attack loop!\n")

    # 3. Create our clean Seed Message
    seed_question = DNSQuestion(qname="example.com")
    seed_message = DNSMessage(header=DNSHeader(), questions=[seed_question])

    # 4. THE INFINITE FUZZING LOOP
    iteration = 0
    try:
        while True:
            iteration += 1
            if iteration % 100 == 0:
                print(f"[*] Fuzzing iteration {iteration}...")

            # --- A. MUTATE ---
            # Apply Smart Structure Mutations
            mutator = SmartDNSMutator(seed_message)
            mutated_msg = mutator.mutate()
            mutated_bytes = mutated_msg.to_bytes()

            # Randomly apply Byte-Level bit flips 20% of the time
            if random.random() < 0.2:
                mutated_bytes = ByteMutator.bit_flip(mutated_bytes)

            # --- B. DELIVER ---
            if protocol == "UDP":
                transport.send_udp(mutated_bytes)
            else:
                transport.send_tcp(mutated_bytes)

            # Give the server a tiny fraction of a second to process (prevents false network floods)
            time.sleep(0.01)

            # --- C. MONITOR ---
            # Ask the Oracle if the server survived the last packet
            if not oracle.check_health():
                # --- D. SAVE CRASH ---
                save_crash(mutated_bytes, iteration)
                break # Stop the fuzzer so we don't overwrite or lose context

    except KeyboardInterrupt:
        print(f"\n[*] Fuzzer stopped manually by user after {iteration} iterations.")

if __name__ == "__main__":
    TARGET_IP = "127.0.0.1"
    TARGET_PORT = 8053
    PROTOCOL = "UDP" 

    run_fuzzer(TARGET_IP, TARGET_PORT, PROTOCOL)