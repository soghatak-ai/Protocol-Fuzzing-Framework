import os
import time
import random
import subprocess
import sys
from protocol.dns import DNSMessage, DNSHeader, DNSQuestion
from engine.mutator import SmartDNSMutator, ByteMutator
from transport.network import DNSTransport
from monitor.oracle import ServerOracle

def save_crash(payload: bytes, iteration: int, stderr_data: bytes):
    timestamp = int(time.time())
    os.makedirs("crashes", exist_ok=True)
    
    # Save the input binary that triggered the failure
    with open(f"crashes/crash_iter_{iteration}_{timestamp}.bin", "wb") as f:
        f.write(payload)
    
    # Save the diagnostic sanitizer track trace
    with open(f"crashes/crash_report_{iteration}_{timestamp}.txt", "w") as f:
        f.write(stderr_data.decode('utf-8', errors='ignore'))
        
    print(f"\n[!!!] CRASH DETECTED [!!!]")
    print(f"[+] Saved reproducing payload and diagnostic report to crashes/")

def run_fuzzer(target_host: str, target_port: int, build_dir: str):
    print(f"[*] Initializing Target Application under supervision...")
    
    # Spawn the process under AddressSanitizer monitoring
    # -q runs quiet mode to prevent output flooding your terminal
    cmd = ["sudo", "./src/snort", "-c", "../lua/snort.lua", "-i", "en0", "-q"]
    
    target_process = subprocess.Popen(
        cmd,
        cwd=build_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Allow the initialization routines and interface bindings to complete
    time.sleep(2)
    
    transport = DNSTransport(target_host, target_port)
    oracle = ServerOracle(target_process)
    
    if not oracle.check_health():
        print("[-] Target failed to initialize. Extracting diagnostic dump...")
        
        # Capture whatever Snort printed right before it closed
        stdout, stderr = target_process.communicate()
        print("\n=== SNORT STDOUT ===")
        print(stdout.decode('utf-8', errors='ignore'))
        print("\n=== SNORT STDERR ===")
        print(stderr.decode('utf-8', errors='ignore'))
        return
    print("[+] Supervision active. Commencing loop!\n")

    seed_question = DNSQuestion(qname="example.com")
    seed_message = DNSMessage(header=DNSHeader(), questions=[seed_question])

    iteration = 0
    try:
        while True:
            iteration += 1
            if iteration % 100 == 0:
                print(f"[*] Fuzzing iteration {iteration}... (Target Status: Operational)")

            mutator = SmartDNSMutator(seed_message)
            mutated_msg = mutator.mutate()
            mutated_bytes = mutated_msg.to_bytes()

            if random.random() < 0.2:
                mutated_bytes = ByteMutator.bit_flip(mutated_bytes)

            transport.send_udp(mutated_bytes)
            time.sleep(0.001)

            # The Oracle now inspects the process block directly
            if not oracle.check_health():
                # Read the crash trace out of stderr
                _, stderr = target_process.communicate()
                save_crash(mutated_bytes, iteration, stderr)
                break

    except KeyboardInterrupt:
        print(f"\n[*] Fuzzer stopped manually. Terminating target safely...")
        target_process.terminate()

if __name__ == "__main__":
    TARGET_IP = "224.0.0.123"
    TARGET_PORT = 53  # Standard service port mapped to the parsing engine
    SNORT_BUILD = "/Users/soghatak/snort3/build"

    run_fuzzer(TARGET_IP, TARGET_PORT, SNORT_BUILD)