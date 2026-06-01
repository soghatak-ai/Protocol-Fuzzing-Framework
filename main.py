import os
import copy
import time
import random
import struct
import subprocess
import threading
import platform
from datetime import datetime
import psutil
from protocol.dns import DNSMessage, DNSHeader, DNSQuestion
from protocol.ftp import FtpMutator, FTP_STRATEGY_LABELS
from protocol.http import (HttpMutator, HTTP_STRATEGY_LABELS,
                           HTTP_STRATEGIES as HTTP_STRATEGY_NAMES,
                           HTTP_WEIGHTS as HTTP_DEFAULT_WEIGHTS,
                           is_http_response_strategy)
from engine.mutator import (SmartDNSMutator, ByteMutator, CompressionLoopMutator,
                            LabelComplexityMutator, ResponseMutator,
                            EDNSExploitMutator, DNSSECRecordMutator, TCPDNSSegmentMutator,
                            TxtRdataBombMutator, TcpTwoMessageMutator,
                            InspectorStressMutator,
                            IPDefragMutator, BackOrificeMutator, DCESmbMutator,
                            DNSDynamicUpdateMutator, MultiQueryStormMutator)
from transport.network import StreamTransport, LiveTransport, LiveNetworkTransport
from engine.bandit import UCB1Bandit

DNS_STRATEGY_NAMES = [
    "smart_dns", "response_fuzz", "compression_loop",
    "label_complexity", "edns_exploit", "tcp_dns_segment",
    "txt_rdata_bomb", "tcp_two_message", "ip_defrag",
    "back_orifice", "dce_smb", "inspector_stress",
    "dnssec_exploit", "dns_dynamic_update", "multi_query_storm",
]

DNS_DEFAULT_WEIGHTS = [0.10, 0.14, 0.07, 0.06, 0.08, 0.04, 0.06, 0.05,
                       0.08, 0.07, 0.06, 0.00, 0.07, 0.06, 0.06]

FTP_STRATEGY_NAMES = [
    "cmd_overflow", "port_bomb", "pipelined_auth", "cwd_depth",
    "epsv_eprt_mix", "stray_commands", "boundary_port", "oversized_site",
    "encoding_attack", "rest_overflow", "data_channel_confusion", "feat_negotiate",
]

FTP_DEFAULT_WEIGHTS = [18, 18, 12, 12, 8, 8, 4, 4, 6, 4, 4, 2]

# HTTP_STRATEGY_NAMES / HTTP_DEFAULT_WEIGHTS are imported from protocol.http
# (single source of truth; includes both request- and response-side strategies).

ai_weights = {
    "source": "default",
    "dns": dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS)),
    "ftp": dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS)),
    "http": dict(zip(HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS)),
    "reasoning": "",
}

# RL bandits — one per protocol, adjusts base weights via multipliers
dns_bandit = UCB1Bandit(DNS_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
ftp_bandit = UCB1Bandit(FTP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
http_bandit = UCB1Bandit(HTTP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)


def _bandit_for(protocol):
    if protocol == "ftp":
        return ftp_bandit
    if protocol == "http":
        return http_bandit
    return dns_bandit

fuzzer_state = {
    "iteration": 0,
    "last_packet_time": time.time(),
    "running": False,
    "protocol": "dns",
    "anomaly_detected": None,
    "current_strategy": "smart_dns",
    "start_time": None,
    "run_id": 0,
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
    "strategy_stats": {},
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
        "run_id": fuzzer_state.get("run_id", 0) + 1,
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

def _build_dns_mutation(strategy: str, seed_message):
    """Build one DNS mutation payload. Returns (mutated_bytes, tcp_payload, split_at).
    Exactly one of mutated_bytes / tcp_payload will be non-None.
    split_at is set only when the TCP payload must be delivered in two segments."""
    mutated_bytes = None
    tcp_payload = None
    split_at = None

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
    elif strategy == "edns_exploit":
        mutated_bytes = EDNSExploitMutator.mutate()
    elif strategy == "tcp_dns_segment":
        tcp_payload = TCPDNSSegmentMutator.mutate()
        split_at = random.choice([1, 2, 3, 13, max(1, len(tcp_payload) // 2)])
    elif strategy == "txt_rdata_bomb":
        tcp_payload = TxtRdataBombMutator.mutate()
    elif strategy == "tcp_two_message":
        tcp_payload = TcpTwoMessageMutator.mutate()
        split_at = random.choice([1, 2, max(1, len(tcp_payload) // 3)])
    elif strategy == "inspector_stress":
        udp_pay, tcp_pay = InspectorStressMutator.mutate()
        if udp_pay is not None:
            mutated_bytes = udp_pay
        else:
            tcp_payload = tcp_pay
    elif strategy == "dnssec_exploit":
        mutated_bytes = DNSSECRecordMutator.mutate()
    elif strategy == "dns_dynamic_update":
        mutated_bytes = DNSDynamicUpdateMutator.mutate()
    elif strategy == "multi_query_storm":
        mutated_bytes = MultiQueryStormMutator.mutate()

    return mutated_bytes, tcp_payload, split_at


def _remote_watchdog(monitor):
    """SSH-based watchdog for Snort running on a remote FTD host.
    Mirrors watchdog_monitor() but polls via SSH instead of psutil."""
    baseline_mem = None
    for _ in range(5):
        mem = monitor.get_memory_mb()
        if mem is not None:
            baseline_mem = mem
            fuzzer_state["baseline_mem_mb"] = round(mem, 2)
            fuzzer_state["peak_mem_mb"] = round(mem, 2)
            log_event("INFO", f"Remote watchdog baseline: {mem:.2f} MB on {monitor.host}")
            break
        time.sleep(1.0)

    if baseline_mem is None:
        log_event("WARNING", "Could not read remote Snort memory — process monitoring limited to liveness.")

    while fuzzer_state["running"]:
        time.sleep(2.0)
        alive = monitor.is_alive()
        if alive is False:
            fuzzer_state["anomaly_detected"] = "REMOTE_SNORT_CRASH"
            fuzzer_state["status"] = "crash_detected"
            fuzzer_state["trigger_detail"] = (
                f"Snort PID {monitor.snort_pid} on {monitor.host} stopped responding. "
                "Process vanished \u2014 likely crashed or killed by the FTD watchdog."
            )
            fuzzer_state["running"] = False
            log_event("CRITICAL", f"Remote Snort crash on {monitor.host} (PID {monitor.snort_pid})")
            break

        mem = monitor.get_memory_mb()
        if mem is not None:
            fuzzer_state["current_mem_mb"] = round(mem, 2)
            if mem > (fuzzer_state.get("peak_mem_mb") or 0):
                fuzzer_state["peak_mem_mb"] = round(mem, 2)
            if baseline_mem and (mem - baseline_mem) > 4096.0:
                fuzzer_state["anomaly_detected"] = "REMOTE_MEMORY_LEAK"
                fuzzer_state["status"] = "crash_detected"
                fuzzer_state["running"] = False
                log_event("CRITICAL", f"Remote memory bloat: +{mem - baseline_mem:.2f} MB")
                break

    monitor.close()


def watchdog_monitor(pid: int, run_id: int = 0):
    try:
        proc = psutil.Process(pid)
        time.sleep(2.0)
        if fuzzer_state.get("run_id", 0) != run_id:
            return  # stale watchdog from a previous run
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
            
            if fuzzer_state.get("run_id", 0) != run_id:
                return  # stale watchdog — new run started
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
                
                if memory_growth > 4096.0:
                    fuzzer_state["anomaly_detected"] = "MEMORY_LEAK_AMPLIFICATION"
                    fuzzer_state["trigger_detail"] = f"RSS grew from {baseline_mem:.2f} MB to {current_mem_mb:.2f} MB (+{memory_growth:.2f} MB, {memory_growth/baseline_mem*100:.1f}% increase). Threshold: 4096 MB."
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
        ftp_mutator = FtpMutator(external_weights=ai_weights.get("ftp"), bandit=ftp_bandit)
        http_mutator = None
        seed_message = None
    elif protocol == "http":
        transport = StreamTransport(target_port=80)
        ftp_mutator = None
        http_mutator = HttpMutator(external_weights=ai_weights.get("http"), bandit=http_bandit)
        seed_message = None
    else:
        transport = StreamTransport(target_port=53)
        ftp_mutator = None
        http_mutator = None
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

    current_run_id = fuzzer_state["run_id"]
    watchdog = threading.Thread(target=watchdog_monitor, args=(target_process.pid, current_run_id), daemon=True)
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
                    fuzzer_state["iteration"] += 4  # 5 PCAP records per TCP session (includes FIN-ACK)
                elif protocol == "http":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _http_payload, _http_strategy = http_mutator.mutate()
                    payload, strategy = _http_payload, _http_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    if is_http_response_strategy(strategy):
                        # server->client: drives the http_inspect RESPONSE parser
                        pipe.write(transport.wrap_tcp_response_session(payload, src_port=src_port))
                    else:
                        pipe.write(transport.wrap_tcp_session(payload, src_port=src_port))
                    fuzzer_state["iteration"] += 4  # full TCP session per HTTP message
                else:
                    dns_w = ai_weights.get("dns", {})
                    strategy = dns_bandit.select_with_weights(dns_w)
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1

                    if strategy == "ip_defrag":
                        frags = IPDefragMutator.mutate()
                        src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                        pipe.write(transport.wrap_ip_fragments(frags, src_ip=src_ip))
                        fuzzer_state["iteration"] += len(frags) - 1
                    elif strategy == "back_orifice":
                        bo_payload = BackOrificeMutator.mutate()
                        src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                        pipe.write(transport.wrap_udp_to_port(bo_payload, 31337, src_ip=src_ip))
                    elif strategy == "dce_smb":
                        smb_payload = DCESmbMutator.mutate()
                        src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                        pipe.write(transport.wrap_tcp_session_to_port(smb_payload, 445, src_ip=src_ip))
                        fuzzer_state["iteration"] += 4
                    else:
                        mutated_bytes, tcp_payload, split_at = _build_dns_mutation(strategy, seed_message)
                        if mutated_bytes is not None:
                            pipe.write(transport.wrap_payload(mutated_bytes, src_ip=0x7f000001, src_port=12345))
                        elif tcp_payload is not None:
                            src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                            if split_at is not None:
                                pipe.write(transport.wrap_split_tcp_session(tcp_payload, split_at=split_at, src_ip=src_ip))
                            else:
                                pipe.write(transport.wrap_tcp_session(tcp_payload, src_ip=src_ip))

                fuzzer_state["last_packet_time"] = time.time()

                # RL bandit: record no-crash outcome for this strategy
                active_bandit = _bandit_for(protocol)
                active_bandit.update(strategy, 0.0)

                stat_interval = 500 if protocol in ("ftp", "http") else 10000
                if fuzzer_state["iteration"] % stat_interval == 0:
                    elapsed = time.time() - fuzzer_state["start_time"] if fuzzer_state["start_time"] else 1
                    fuzzer_state["packets_per_sec"] = int(fuzzer_state["iteration"] / max(elapsed, 0.001))
                    print(f"[*] Streamed {iteration} mutations into memory... (Target Status: Secure)")

    except BrokenPipeError:
        # RL bandit: reward the strategy that caused the crash
        active_bandit = _bandit_for(protocol)
        active_bandit.update(fuzzer_state.get("current_strategy", ""), 1.0)
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
                # RL bandit: reward the crashing strategy
                ab = _bandit_for(protocol)
                ab.update(fuzzer_state.get("current_strategy", ""), 1.0)
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

def run_fuzzer_live(config: dict):
    """
    Live network fuzzing mode.
    Sends real DNS/FTP packets via a network interface to a target server.
    A Cisco FTD (or any inline Snort 3 device) sitting between this machine
    and the server will inspect and process the malformed traffic.

    config keys:
        server_ip      : target DNS/FTP server IP
        server_port    : target port (default 53)
        interface      : NIC name, e.g. eth0 / en0 (optional)
        ftd_ip         : FTD management IP for SSH monitoring (optional)
        ftd_user       : SSH username on FTD (default admin)
        ftd_pass       : SSH password
        ftd_ssh_port   : SSH port on FTD (default 22)
        snort_pid      : Snort process PID on FTD for health tracking
    """
    from monitor.remote_monitor import RemoteSnortMonitor

    server_ip   = config.get("server_ip", "127.0.0.1")
    server_port = int(config.get("server_port", 53))
    interface   = config.get("interface") or None
    ftd_ip      = config.get("ftd_ip") or None
    ftd_user    = config.get("ftd_user", "admin")
    ftd_pass    = config.get("ftd_pass", "")
    ftd_ssh_port = int(config.get("ftd_ssh_port", 22))
    snort_pid   = config.get("snort_pid")

    protocol = fuzzer_state.get("protocol", "dns")
    live_transport = LiveNetworkTransport(server_ip, server_port, interface)

    if protocol == "ftp":
        ftp_mutator_inst = FtpMutator(external_weights=ai_weights.get("ftp"), bandit=ftp_bandit)
        http_mutator_inst = None
        seed_message = None
    elif protocol == "http":
        ftp_mutator_inst = None
        http_mutator_inst = HttpMutator(external_weights=ai_weights.get("http"), bandit=http_bandit)
        seed_message = None
    else:
        ftp_mutator_inst = None
        http_mutator_inst = None
        seed_question = DNSQuestion(qname="example.com")
        seed_message = DNSMessage(header=DNSHeader(), questions=[seed_question])

    fuzzer_state["start_time"] = time.time()
    fuzzer_state["status"] = "running"
    fuzzer_state["running"] = True
    iface_label = interface or "default route"
    log_event("INFO", f"Live fuzzer started → {server_ip}:{server_port} via {iface_label} ({protocol.upper()})")
    print(f"[+] Live network fuzzer → {server_ip}:{server_port} (iface: {iface_label})")

    if ftd_ip and snort_pid:
        snort_pid = int(snort_pid)
        fuzzer_state["snort_pid"] = snort_pid
        monitor = RemoteSnortMonitor(ftd_ip, snort_pid, ftd_user, ftd_pass, ftd_ssh_port)
        if monitor.connect():
            log_event("INFO", f"SSH monitor connected to {ftd_ip} — watching PID {snort_pid}")
            print(f"[+] Remote Snort monitor active: {ftd_ip} PID {snort_pid}")
            wdog = threading.Thread(target=_remote_watchdog, args=(monitor,), daemon=True)
            wdog.start()
        else:
            log_event("WARNING", f"SSH to {ftd_ip} failed — running without remote monitoring")
            monitor = None
    else:
        monitor = None
        log_event("WARNING", "No FTD IP / Snort PID provided — fire-and-forget mode (no health tracking)")

    _ftp_payload, _ftp_strategy = None, None
    _http_payload, _http_strategy = None, None

    try:
        while fuzzer_state["running"] and not fuzzer_state["anomaly_detected"]:
            fuzzer_state["iteration"] += 1
            iteration = fuzzer_state["iteration"]

            if protocol == "ftp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _ftp_payload, _ftp_strategy = ftp_mutator_inst.mutate()
                strategy = _ftp_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_tcp(_ftp_payload)
                fuzzer_state["iteration"] += 1
            elif protocol == "http":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _http_payload, _http_strategy = http_mutator_inst.mutate()
                strategy = _http_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                # NOTE: in live mode the fuzzer is the CLIENT, so it can only send
                # client->server bytes. Request-side strategies test the on-path
                # http_inspect request parser; response-side (resp_*) evasions are
                # best exercised in pipe mode via wrap_tcp_response_session.
                live_transport.send_tcp(_http_payload, port=80)
                fuzzer_state["iteration"] += 1
            else:
                dns_w = ai_weights.get("dns", {})
                strategy = dns_bandit.select_with_weights(dns_w)
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1

                if strategy == "back_orifice":
                    bo_payload = BackOrificeMutator.mutate()
                    live_transport.send_udp(bo_payload, port=31337)
                elif strategy == "dce_smb":
                    smb_payload = DCESmbMutator.mutate()
                    live_transport.send_tcp(smb_payload, port=445)
                    time.sleep(0.001)
                else:
                    mutated_bytes, tcp_payload, split_at = _build_dns_mutation(strategy, seed_message)
                    if mutated_bytes is not None:
                        live_transport.send_udp(mutated_bytes)
                    elif tcp_payload is not None:
                        if split_at is not None:
                            live_transport.send_split_tcp(tcp_payload, split_at)
                        else:
                            live_transport.send_tcp(tcp_payload)
                        time.sleep(0.001)

            fuzzer_state["last_packet_time"] = time.time()

            # RL bandit: record no-crash outcome
            active_bandit = _bandit_for(protocol)
            active_bandit.update(strategy, 0.0)

            stat_interval = 500 if protocol in ("ftp", "http") else 10000
            if fuzzer_state["iteration"] % stat_interval == 0:
                elapsed = time.time() - fuzzer_state["start_time"] if fuzzer_state["start_time"] else 1
                fuzzer_state["packets_per_sec"] = int(fuzzer_state["iteration"] / max(elapsed, 0.001))
                status = "ANOMALY" if fuzzer_state["anomaly_detected"] else "Secure"
                print(f"[*] Sent {iteration} live mutations... (Target Status: {status})")

    except KeyboardInterrupt:
        log_event("WARNING", f"Live fuzzer halted manually at iteration {fuzzer_state['iteration']}")
        print(f"\n[*] Live fuzzer halted. Total packets sent: {fuzzer_state['iteration']}")

    except Exception as e:
        log_event("ERROR", f"Live fuzzer error: {e}")
        print(f"\n[!] Live fuzzer error: {e}")

    finally:
        fuzzer_state["running"] = False
        fuzzer_state["status"] = "stopped" if not fuzzer_state["anomaly_detected"] else "crash_detected"
        if fuzzer_state.get("anomaly_detected"):
            # RL bandit: reward the crashing strategy
            ab = _bandit_for(protocol)
            ab.update(fuzzer_state.get("current_strategy", ""), 1.0)
            save_crash_log(
                fuzzer_state["iteration"],
                b"",
                anomaly_type=fuzzer_state["anomaly_detected"],
                return_code=None,
            )
        log_event("INFO", "Live network fuzzer stopped.")


if __name__ == "__main__":
    SNORT_BUILD = "/Users/soghatak/snort3/build"
    LIVE_MODE = False

    if LIVE_MODE:
        run_fuzzer_live(SNORT_BUILD)
    else:
        run_fuzzer(SNORT_BUILD)