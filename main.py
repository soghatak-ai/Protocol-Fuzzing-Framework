import os
import copy
import time
import random
import subprocess
import threading
import platform
from datetime import datetime
import psutil
from protocol.dns import DNSMessage, DNSHeader, DNSQuestion
from protocol.ftp import FtpMutator, FTP_STRATEGY_LABELS
from engine.mutator import SmartDNSMutator, ByteMutator, CompressionLoopMutator, LabelComplexityMutator, ResponseMutator
from transport.network import StreamTransport, LiveTransport

fuzzer_state = {
    "iteration": 0,
    "last_packet_time": time.time(),
    "running": False,
    "protocol": "dns",
    "anomaly_detected": None,
    "current_strategy": "smart_dns",
    "start_time": None,
    "baseline_mem_mb": None,
    "peak_mem_mb": None,
    "current_mem_mb": None,
    "snort_pid": None,
    "trigger_detail": None,
    "status": "idle",
    "total_crashes": 0,
    "last_crash_time": None,
    "last_crash_type": None,
    "packets_per_sec": 0,
    "strategy_stats": {
        "smart_dns": 0,
        "response_fuzz": 0,
        "compression_loop": 0,
        "label_complexity": 0,
        "state_exhaustion": 0,
    },
}

event_log = []

def log_event(level, message):
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "message": message,
    }
    event_log.append(entry)
    if len(event_log) > 500:
        event_log.pop(0)

def reset_state():
    # Preserve protocol across resets so the fuzzer loop reads the right one
    protocol = fuzzer_state.get("protocol", "dns")
    fuzzer_state.update({
        "iteration": 0,
        "last_packet_time": time.time(),
        "running": False,
        "protocol": protocol,
        "anomaly_detected": None,
        "current_strategy": "",
        "start_time": None,
        "baseline_mem_mb": None,
        "peak_mem_mb": None,
        "current_mem_mb": None,
        "snort_pid": None,
        "trigger_detail": None,
        "status": "idle",
        "last_crash_time": None,
        "last_crash_type": None,
        "packets_per_sec": 0,
        "strategy_stats": {},
    })
    event_log.clear()

def save_crash_log(iteration: int, stderr_data: bytes, anomaly_type: str = "CRASH", return_code: int = None):
    os.makedirs("crashes", exist_ok=True)
    timestamp = int(time.time())
    report_path = f"crashes/{anomaly_type}_report_{iteration}_{timestamp}.txt"

    elapsed = time.time() - fuzzer_state["start_time"] if fuzzer_state["start_time"] else 0
    hours, rem = divmod(int(elapsed), 3600)
    mins, secs = divmod(rem, 60)

    with open(report_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write(f"  SNORT FUZZER CRASH REPORT — {anomaly_type}\n")
        f.write("=" * 70 + "\n\n")

        f.write("[1] ENVIRONMENT\n")
        f.write(f"    Timestamp       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"    Platform        : {platform.system()} {platform.release()} ({platform.machine()})\n")
        f.write(f"    Python          : {platform.python_version()}\n")
        f.write(f"    Snort PID       : {fuzzer_state.get('snort_pid', 'N/A')}\n\n")

        f.write("[2] FUZZER STATE AT CRASH\n")
        f.write(f"    Anomaly Type    : {anomaly_type}\n")
        f.write(f"    Strategy        : {fuzzer_state['current_strategy']}\n")
        f.write(f"    Iteration       : {iteration:,}\n")
        f.write(f"    Runtime         : {hours:02d}:{mins:02d}:{secs:02d}\n")
        f.write(f"    Throughput      : {iteration / max(elapsed, 0.001):,.0f} packets/sec\n\n")

        f.write("[3] MEMORY ANALYSIS\n")
        f.write(f"    Baseline RSS    : {fuzzer_state.get('baseline_mem_mb', 'N/A')} MB\n")
        f.write(f"    Current RSS     : {fuzzer_state.get('current_mem_mb', 'N/A')} MB\n")
        f.write(f"    Peak RSS        : {fuzzer_state.get('peak_mem_mb', 'N/A')} MB\n")
        baseline = fuzzer_state.get('baseline_mem_mb')
        current = fuzzer_state.get('current_mem_mb')
        if baseline and current:
            growth = current - baseline
            f.write(f"    Memory Growth   : +{growth:.2f} MB ({growth/baseline*100:.1f}% over baseline)\n")
        f.write("\n")

        f.write("[4] TRIGGER DETAIL\n")
        f.write(f"    {fuzzer_state.get('trigger_detail', 'No additional detail captured.')}\n\n")

        f.write("[5] PROCESS EXIT\n")
        f.write(f"    Return Code     : {return_code}\n")
        signal_map = {-2: "SIGINT", -6: "SIGABRT", -9: "SIGKILL", -11: "SIGSEGV", -15: "SIGTERM"}
        if return_code and return_code < 0:
            f.write(f"    Signal          : {signal_map.get(return_code, f'Signal {abs(return_code)}')}\n")
        f.write("\n")

        stderr_text = stderr_data.decode('utf-8', errors='ignore').strip()
        f.write("[6] SNORT STDERR OUTPUT\n")
        if stderr_text:
            f.write("    " + "\n    ".join(stderr_text.splitlines()) + "\n")
        else:
            f.write("    (no stderr output captured)\n")
        f.write("\n")

    fuzzer_state["total_crashes"] = fuzzer_state.get("total_crashes", 0) + 1
    fuzzer_state["last_crash_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fuzzer_state["last_crash_type"] = anomaly_type
    log_event("CRITICAL", f"{anomaly_type} detected at iteration {iteration:,}")
    log_event("INFO", f"Crash report saved: {report_path}")
    print(f"\n[!!!] {anomaly_type} DETECTED AT ITERATION {iteration:,} [!!!]")
    print(f"[+] Diagnostic trace saved to: {report_path}")

def watchdog_monitor(pid: int):
    try:
        proc = psutil.Process(pid)
        time.sleep(2.0)
        baseline_mem = None
        print(f"[Watchdog] Starting watchdog for PID: {proc}")
        for attempt in range(10):
            try:
                baseline_mem = proc.memory_info().rss / (1024 * 1024)
                fuzzer_state["baseline_mem_mb"] = round(baseline_mem, 2)
                fuzzer_state["peak_mem_mb"] = round(baseline_mem, 2)
                print(f"[Watchdog] Baseline memory established at: {baseline_mem:.2f} MB")
                log_event("INFO", f"Watchdog baseline: {baseline_mem:.2f} MB")
                break
            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                if not proc.is_running():
                    print("[Watchdog] Snort exited before baseline could be captured.")
                    return
                print(f"[Watchdog] {type(e).__name__} on attempt {attempt+1}/10, retrying...")
                time.sleep(1.0)
        if baseline_mem is None:
            print("[Watchdog] WARNING: Could not read Snort memory after 10 attempts. Watchdog disabled.")
            return

        while fuzzer_state["running"]:
            time.sleep(0.5) # Poll twice as fast (every 500ms) for tighter precision
            
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                break
                
            # Calculate exact silence threshold
            time_since_last_packet = time.time() - fuzzer_state["last_packet_time"]
            
            if time_since_last_packet > 3.0:
                current_strat = fuzzer_state.get("current_strategy", "unknown")
                
                if current_strat == "compression_loop":
                    fuzzer_state["anomaly_detected"] = "HANG_INFINITE_LOOP"
                elif current_strat == "label_complexity":
                    fuzzer_state["anomaly_detected"] = "ALGORITHMIC_COMPLEXITY_DoS"
                else:
                    fuzzer_state["anomaly_detected"] = f"GENERIC_TIMEOUT_{current_strat.upper()}"
                
                fuzzer_state["trigger_detail"] = f"Snort unresponsive for {time_since_last_packet:.1f}s during '{current_strat}' strategy. Pipe write blocked — target stopped consuming packets."
                fuzzer_state["status"] = "crash_detected"
                log_event("CRITICAL", f"Hang detected: {time_since_last_packet:.1f}s during {current_strat}")
                print(f"\n[Watchdog Trigger] Snort hung for {time_since_last_packet:.1f}s during {current_strat}!")
                proc.kill() 
                break

            # MEMORY TRACKING ENHANCEMENT
            try:
                mem_info = proc.memory_info()
                current_mem_mb = mem_info.rss / (1024 * 1024)
                fuzzer_state["current_mem_mb"] = round(current_mem_mb, 2)
                if current_mem_mb > (fuzzer_state.get("peak_mem_mb") or 0):
                    fuzzer_state["peak_mem_mb"] = round(current_mem_mb, 2)
                memory_growth = current_mem_mb - baseline_mem
                
                if memory_growth > 500.0:
                    fuzzer_state["anomaly_detected"] = "MEMORY_LEAK_AMPLIFICATION"
                    fuzzer_state["trigger_detail"] = f"RSS grew from {baseline_mem:.2f} MB to {current_mem_mb:.2f} MB (+{memory_growth:.2f} MB, {memory_growth/baseline_mem*100:.1f}% increase). Threshold: 500 MB."
                    fuzzer_state["status"] = "crash_detected"
                    log_event("CRITICAL", f"Memory bloat: +{memory_growth:.2f} MB (RSS: {current_mem_mb:.2f} MB)")
                    print(f"\n[Watchdog Trigger] Excessive RAM bloat detected (+{memory_growth:.2f} MB)!")
                    proc.kill()
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

    except psutil.NoSuchProcess:
        print("----------------------------------------")
        pass

    
def run_fuzzer(build_dir: str):
    pipe_path = "target.pipe"
    protocol = fuzzer_state.get("protocol", "dns")

    if protocol == "ftp":
        transport = StreamTransport(target_port=21)
        ftp_mutator = FtpMutator()
        seed_message = None
    else:
        transport = StreamTransport(target_port=53)
        ftp_mutator = None
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
    fuzzer_state["snort_pid"] = target_process.pid
    fuzzer_state["start_time"] = time.time()
    fuzzer_state["status"] = "running"
    fuzzer_state["running"] = True
    log_event("INFO", f"Snort launched (PID {target_process.pid})")

    watchdog = threading.Thread(target=watchdog_monitor, args=(target_process.pid,), daemon=True)
    watchdog.start()

    try:
        with open(pipe_path, "wb", buffering=0) as pipe:
            print("[+] Memory Stream synchronized! Injecting payloads...")
            log_event("INFO", "Pipe synchronized. Fuzzing started.")
            
            pipe.write(transport.get_global_header())
            pipe.flush()

            while fuzzer_state["running"] and not fuzzer_state["anomaly_detected"]:
                fuzzer_state["iteration"] += 1
                iteration = fuzzer_state["iteration"]

                if protocol == "ftp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _ftp_payload, _ftp_strategy = ftp_mutator.mutate()
                    payload, strategy = _ftp_payload, _ftp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session(payload, src_port=src_port))
                    fuzzer_state["iteration"] += 3  # 4 PCAP records per TCP session
                else:
                    strategy = random.choices(
                        ["smart_dns", "response_fuzz", "compression_loop", "label_complexity", "state_exhaustion"],
                        weights=[0.25, 0.30, 0.10, 0.10, 0.25]
                    )[0]
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
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

                fuzzer_state["last_packet_time"] = time.time() 

                stat_interval = 500 if protocol == "ftp" else 10000
                if fuzzer_state["iteration"] % stat_interval == 0:
                    elapsed = time.time() - fuzzer_state["start_time"] if fuzzer_state["start_time"] else 1
                    fuzzer_state["packets_per_sec"] = int(fuzzer_state["iteration"] / max(elapsed, 0.001))
                    print(f"[*] Streamed {iteration} mutations into memory... (Target Status: Secure)")

    except BrokenPipeError:
        log_event("ERROR", "Pipe severed — Snort collapsed unexpectedly")
        print("\n[-] Pipe severed! Snort process collapsed unexpectedly.")
        
    except KeyboardInterrupt:
        log_event("WARNING", f"Fuzzer halted manually at iteration {fuzzer_state['iteration']}")
        print(f"\n[*] Fuzzer halted manually. Total streamed packets: {fuzzer_state['iteration']}")

    finally:
        fuzzer_state["running"] = False
        fuzzer_state["status"] = "stopped" if not fuzzer_state["anomaly_detected"] else "crash_detected"
        
        try:
            if target_process.poll() is None:
                target_process.terminate()
                try:
                    stdout, stderr = target_process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    target_process.kill()
                    stdout, stderr = target_process.communicate()
            else:
                stdout, stderr = target_process.communicate()
            
            if fuzzer_state["anomaly_detected"]:
                save_crash_log(fuzzer_state["iteration"], stderr, anomaly_type=fuzzer_state["anomaly_detected"], return_code=target_process.returncode)
            elif target_process.returncode not in (0, None, -2, -9, -15):
                fuzzer_state["trigger_detail"] = f"Snort exited with unexpected return code {target_process.returncode}."
                save_crash_log(fuzzer_state["iteration"], stderr, anomaly_type="MEMORY_CORRUPTION", return_code=target_process.returncode)
            else:
                print("\n=== SNORT PROTOCOL INSPECTION SUMMARY ===")
                print(stdout.decode('utf-8', errors='ignore'))
        except KeyboardInterrupt:
            target_process.kill()
            target_process.wait()
            print("\n[*] Force-killed Snort. Exiting.")

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