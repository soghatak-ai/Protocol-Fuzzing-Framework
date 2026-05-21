import os
import copy
import time
import random
import subprocess
import threading
import psutil
from protocol.dns import DNSMessage, DNSHeader, DNSQuestion
from engine.mutator import SmartDNSMutator, ByteMutator, CompressionLoopMutator, LabelComplexityMutator, ResponseMutator
from transport.network import StreamTransport, LiveTransport

fuzzer_state = {
    "iteration": 0,
    "last_packet_time": time.time(),
    "running": True,
    "anomaly_detected": None,
    "current_strategy": "smart_dns"
}

def save_crash_log(iteration: int, stderr_data: bytes, anomaly_type: str = "CRASH"):
    os.makedirs("crashes", exist_ok=True)
    timestamp = int(time.time())
    report_path = f"crashes/{anomaly_type}_report_{iteration}_{timestamp}.txt"
    
    with open(report_path, "w") as f:
        f.write(f"Triggering Strategy: {fuzzer_state['current_strategy']}\n")
        f.write(f"Iteration: {iteration}\n\n")
        f.write(stderr_data.decode('utf-8', errors='ignore'))
        
    print(f"\n[!!!] {anomaly_type} DETECTED AT ITERATION {iteration} [!!!]")
    print(f"[+] Diagnostic trace saved to: {report_path}")

def watchdog_monitor(pid: int):
    try:
        proc = psutil.Process(pid)
        time.sleep(2.0)
        try:
            baseline_mem = proc.memory_info().rss / (1024 * 1024)
            print(f"[Watchdog] Baseline memory established at: {baseline_mem:.2f} MB")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        while fuzzer_state["running"]:
            time.sleep(0.5) # Poll twice as fast (every 500ms) for tighter precision
            
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                break
                
            # Calculate exact silence threshold
            time_since_last_packet = time.time() - fuzzer_state["last_packet_time"]
            
            if time_since_last_packet > 3.0:
                # DYNAMIC INTELLIGENCE: Classify the bug based on what strategy sent the packet
                current_strat = fuzzer_state.get("current_strategy", "unknown")
                
                if current_strat == "compression_loop":
                    fuzzer_state["anomaly_detected"] = "HANG_INFINITE_LOOP"
                elif current_strat == "label_complexity":
                    fuzzer_state["anomaly_detected"] = "ALGORITHMIC_COMPLEXITY_DoS"
                else:
                    fuzzer_state["anomaly_detected"] = f"GENERIC_TIMEOUT_{current_strat.upper()}"
                
                print(f"\n[Watchdog Trigger] Snort hung for {time_since_last_packet:.1f}s during {current_strat}!")
                proc.kill() 
                break

            # MEMORY TRACKING ENHANCEMENT
            try:
                mem_info = proc.memory_info()
                current_mem_mb = mem_info.rss / (1024 * 1024)
                memory_growth = current_mem_mb - baseline_mem
                
                # If memory jumps by 500MB over stable baseline
                if memory_growth > 500.0:
                    fuzzer_state["anomaly_detected"] = "MEMORY_LEAK_AMPLIFICATION"
                    print(f"\n[Watchdog Trigger] Excessive RAM bloat detected (+{memory_growth:.2f} MB)!")
                    proc.kill()
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

    except psutil.NoSuchProcess:
        pass

    
def run_fuzzer(build_dir: str):
    pipe_path = "target.pipe"
    transport = StreamTransport(target_port=53)
    
    seed_question = DNSQuestion(qname="example.com")
    seed_message = DNSMessage(header=DNSHeader(), questions=[seed_question])
    
    if os.path.exists(pipe_path):
        os.remove(pipe_path)
    os.mkfifo(pipe_path)
    
    absolute_pipe_path = os.path.abspath(pipe_path)
    print(f"[*] Named Pipe created at {absolute_pipe_path}. Launching Snort...")

    cmd = [
        "./src/snort", 
        "-c", "../lua/snort.lua", 
        "-r", absolute_pipe_path, 
        "--lua", "perfmonitor = { modules = { { name = \"service_counters\" } } }"
    ]
    target_process = subprocess.Popen(
        cmd, cwd=build_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    watchdog = threading.Thread(target=watchdog_monitor, args=(target_process.pid,), daemon=True)
    watchdog.start()

    try:
        with open(pipe_path, "wb") as pipe:
            print("[+] Memory Stream synchronized! Injecting payloads...")
            
            pipe.write(transport.get_global_header())
            pipe.flush()

            while True:
                fuzzer_state["iteration"] += 1
                iteration = fuzzer_state["iteration"]
                
                strategy = random.choices(
                    ["smart_dns", "response_fuzz", "compression_loop", "label_complexity", "state_exhaustion"],
                    weights=[0.25, 0.30, 0.10, 0.10, 0.25]
                )[0]
                fuzzer_state["current_strategy"] = strategy
                src_ip, src_port = 0x7f000001, 12345

                if strategy == "smart_dns":
                    mutator = SmartDNSMutator(seed_message)
                    mutated_bytes = mutator.mutate().to_bytes()
                    if random.random() < 0.2:
                        mutated_bytes = ByteMutator.bit_flip(mutated_bytes)

                elif strategy == "response_fuzz":
                    mutated_bytes = ResponseMutator.mutate()
                    if random.random() < 0.3:
                        mutated_bytes = ByteMutator.bit_flip(mutated_bytes)

                elif strategy == "compression_loop":
                    mutated_bytes = CompressionLoopMutator.mutate()

                elif strategy == "label_complexity":
                    mutated_bytes = LabelComplexityMutator.mutate()

                elif strategy == "state_exhaustion":
                    tc_header = DNSHeader()
                    tc_header.tc = 1
                    tc_message = DNSMessage(
                        header=tc_header,
                        questions=[copy.deepcopy(seed_message.questions[0])]
                    )
                    mutated_bytes = tc_message.to_bytes()
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = random.randint(1024, 65535)

                pipe.write(transport.wrap_payload(mutated_bytes, src_ip=src_ip, src_port=src_port))
                
                if iteration % 500 == 0:
                    pipe.flush()
                    fuzzer_state["last_packet_time"] = time.time() 

                if iteration % 10000 == 0:
                    print(f"[*] Streamed {iteration} mutations into memory... (Target Status: Secure)")

    except BrokenPipeError:
        print("\n[-] Pipe severed! Snort process collapsed unexpectedly.")
        
    except KeyboardInterrupt:
        print(f"\n[*] Fuzzer halted manually. Total streamed packets: {fuzzer_state['iteration']}")

    finally:
        fuzzer_state["running"] = False 
        
        if target_process.poll() is None:
            target_process.terminate()
            
        stdout, stderr = target_process.communicate()
        
        if fuzzer_state["anomaly_detected"]:
            save_crash_log(fuzzer_state["iteration"], stderr, anomaly_type=fuzzer_state["anomaly_detected"])
        elif target_process.returncode != 0 and target_process.returncode is not None and target_process.returncode != -15:
            save_crash_log(fuzzer_state["iteration"], stderr, anomaly_type="MEMORY_CORRUPTION")
        else:
            print("\n=== SNORT PROTOCOL INSPECTION SUMMARY ===")
            print(stdout.decode('utf-8', errors='ignore'))

        if os.path.exists(pipe_path):
            os.remove(pipe_path)

def run_fuzzer_live(build_dir: str):
    live = LiveTransport(target_host="127.0.0.1", target_port=53)

    seed_question = DNSQuestion(qname="example.com")
    seed_message = DNSMessage(header=DNSHeader(), questions=[seed_question])

    cmd = [
        "./src/snort",
        "-c", "../lua/snort.lua",
        "-i", "lo0",
    ]
    print("[*] Launching Snort in live IDS mode on lo0 (requires sudo)...")
    target_process = subprocess.Popen(
        cmd, cwd=build_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    time.sleep(3.0)

    stderr_chunks = []
    def drain_stderr(pipe, chunks):
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except (ValueError, OSError):
            pass

    stderr_thread = threading.Thread(target=drain_stderr, args=(target_process.stderr, stderr_chunks), daemon=True)
    stderr_thread.start()

    if target_process.poll() is not None:
        stderr_thread.join(timeout=3.0)
        err_msg = b"".join(stderr_chunks).decode("utf-8", errors="ignore")
        print(f"\n[FATAL] Snort exited immediately (code {target_process.returncode}).")
        print(f"[FATAL] Stderr:\n{err_msg}")
        print("[HINT] Live mode requires root. Run: sudo python3 main.py")
        live.close()
        return

    watchdog = threading.Thread(target=watchdog_monitor, args=(target_process.pid,), daemon=True)
    watchdog.start()
    print(f"[+] Snort is alive (PID {target_process.pid}). Injecting payloads...")

    try:
        while True:
            fuzzer_state["iteration"] += 1
            iteration = fuzzer_state["iteration"]

            if iteration % 1000 == 0 and target_process.poll() is not None:
                print(f"\n[-] Snort died during fuzzing at iteration {iteration}.")
                break

            strategy = random.choices(
                ["smart_dns", "compression_loop", "label_complexity", "state_exhaustion"],
                weights=[0.40, 0.20, 0.20, 0.20]
            )[0]
            fuzzer_state["current_strategy"] = strategy

            try:
                if strategy == "smart_dns":
                    mutator = SmartDNSMutator(seed_message)
                    mutated_bytes = mutator.mutate().to_bytes()
                    if random.random() < 0.2:
                        mutated_bytes = ByteMutator.bit_flip(mutated_bytes)
                    live.send(mutated_bytes)

                elif strategy == "compression_loop":
                    live.send(CompressionLoopMutator.mutate())

                elif strategy == "label_complexity":
                    live.send(LabelComplexityMutator.mutate())

                elif strategy == "state_exhaustion":
                    tc_header = DNSHeader()
                    tc_header.tc = 1
                    tc_message = DNSMessage(
                        header=tc_header,
                        questions=[copy.deepcopy(seed_message.questions[0])]
                    )
                    live.send_spoofed(tc_message.to_bytes())
            except OSError:
                pass

            fuzzer_state["last_packet_time"] = time.time()

            if iteration % 10000 == 0:
                print(f"[*] Injected {iteration} live packets... (Target Status: Secure)")

    except KeyboardInterrupt:
        print(f"\n[*] Fuzzer halted manually. Total live packets: {fuzzer_state['iteration']}")

    finally:
        fuzzer_state["running"] = False
        live.close()

        if target_process.poll() is None:
            target_process.terminate()

        target_process.wait()
        stderr_thread.join(timeout=5.0)
        stderr = b"".join(stderr_chunks)

        if fuzzer_state["anomaly_detected"]:
            save_crash_log(fuzzer_state["iteration"], stderr, anomaly_type=fuzzer_state["anomaly_detected"])
        elif target_process.returncode != 0 and target_process.returncode is not None and target_process.returncode != -15:
            save_crash_log(fuzzer_state["iteration"], stderr, anomaly_type="MEMORY_CORRUPTION")
        else:
            print("\n=== SNORT LIVE SESSION SUMMARY ===")
            print(f"Snort exited cleanly (code {target_process.returncode}). No anomalies detected.")


if __name__ == "__main__":
    SNORT_BUILD = "/Users/soghatak/snort3/build"
    LIVE_MODE = False

    if LIVE_MODE:
        run_fuzzer_live(SNORT_BUILD)
    else:
        run_fuzzer(SNORT_BUILD)