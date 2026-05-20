import os
import time
import random
import subprocess
from protocol.dns import DNSMessage, DNSHeader, DNSQuestion
from engine.mutator import SmartDNSMutator, ByteMutator
from transport.network import StreamTransport

def save_crash_log(iteration: int, stderr_data: bytes):
    os.makedirs("crashes", exist_ok=True)
    timestamp = int(time.time())
    report_path = f"crashes/crash_report_{iteration}_{timestamp}.txt"
    
    with open(report_path, "w") as f:
        f.write(stderr_data.decode('utf-8', errors='ignore'))
        
    print(f"\n[!!!] TARGET CRASHED AT ITERATION {iteration} [!!!]")
    print(f"[+] AddressSanitizer trace saved to: {report_path}")

def run_fuzzer(build_dir: str):
    pipe_path = "target.pipe"
    transport = StreamTransport(target_port=53)
    
    seed_question = DNSQuestion(qname="example.com")
    seed_message = DNSMessage(header=DNSHeader(), questions=[seed_question])
    
    # 1. Initialize the Unix Named Pipe Node
    if os.path.exists(pipe_path):
        os.remove(pipe_path)
    os.mkfifo(pipe_path)
    
    # Get the absolute, unshakeable path of the pipe file descriptor
    absolute_pipe_path = os.path.abspath(pipe_path)
    print(f"[*] Named Pipe created at {absolute_pipe_path}. Launching Snort...")

    # 2. Launch Snort instructing it to read directly from the absolute Pipe path
    cmd = [
        "./src/snort", 
        "-c", "../lua/snort.lua", 
        "-r", absolute_pipe_path, 
        "--lua", "perfmonitor = { modules = { { name = \"service_counters\" } } }"
    ]
    target_process = subprocess.Popen(
        cmd, cwd=build_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    iteration = 0
    try:
        # 3. Open the pipe file descriptor. (This blocks until Snort attaches to the other side)
        with open(pipe_path, "wb") as pipe:
            print("[+] Memory Stream synchronized! Injecting payloads...")
            
            # Write the mandatory PCAP global header once to establish the stream format
            pipe.write(transport.get_global_header())
            pipe.flush()

            while True:
                iteration += 1
                # Mutate structural model
                mutator = SmartDNSMutator(seed_message)
                mutated_bytes = mutator.mutate().to_bytes()
                
                # Apply raw byte-level mutations
                if random.random() < 0.2:
                    mutated_bytes = ByteMutator.bit_flip(mutated_bytes)

                # Wrap packet and push straight into RAM stream
                pipe.write(transport.wrap_payload(mutated_bytes))
                
                # Flush buffers every 500 records to keep the processing stream dynamic
                if iteration % 500 == 0:
                    pipe.flush()

                if iteration % 10000 == 0:
                    print(f"[*] Streamed {iteration} mutations into memory... (Target Status: Secure)")

    except BrokenPipeError:
        # If Snort hits an ASan memory violation, the binary crashes instantly.
        # The OS severs the pipe link, causing Python to drop immediately into this block.
        print("\n[-] Pipe severed! Snort process collapsed unexpectedly.")
        
    except KeyboardInterrupt:
        print(f"\n[*] Fuzzer halted manually. Total streamed packets: {iteration}")

    finally:
        # 4. Clean shutdown and crash reporting
        if target_process.poll() is None:
            target_process.terminate()
            
        stdout, stderr = target_process.communicate()
        
        # PRINT SNORT'S INTERNAL COUNTERS TO VERIFY DELIVERY
        print("\n=== SNORT PROTOCOL INSPECTION SUMMARY ===")
        print(stdout.decode('utf-8', errors='ignore'))
        
        # If Snort closed with an anomaly code, dump the AddressSanitizer stderr block
        if target_process.returncode != 0 and target_process.returncode is not None:
            save_crash_log(iteration, stderr)

        # Cleanup file layout
        if os.path.exists(pipe_path):
            os.remove(pipe_path)

if __name__ == "__main__":
    # Point this to your compiled absolute build folder path
    SNORT_BUILD = "/Users/soghatak/snort3/build"
    run_fuzzer(SNORT_BUILD)