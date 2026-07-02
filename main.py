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
from protocol.ftp import (FtpMutator, FTP_STRATEGY_LABELS,
                          FTP_STRATEGIES as FTP_STRATEGY_NAMES,
                          FTP_WEIGHTS as FTP_DEFAULT_WEIGHTS)
from protocol.http import (HttpMutator, HTTP_STRATEGY_LABELS,
                           HTTP_STRATEGIES as HTTP_STRATEGY_NAMES,
                           HTTP_WEIGHTS as HTTP_DEFAULT_WEIGHTS,
                           is_http_response_strategy)
from protocol.smtp import (SmtpMutator, SMTP_STRATEGY_LABELS,
                           SMTP_STRATEGIES as SMTP_STRATEGY_NAMES,
                           SMTP_WEIGHTS as SMTP_DEFAULT_WEIGHTS)
from protocol.ssh import (SshMutator, SSH_STRATEGY_LABELS,
                          SSH_STRATEGIES as SSH_STRATEGY_NAMES,
                          SSH_WEIGHTS as SSH_DEFAULT_WEIGHTS)
from protocol.smb import (Smb2Mutator, Smb3Mutator,
                          SMB2_STRATEGY_LABELS, SMB3_STRATEGY_LABELS,
                          SMB2_STRATEGIES as SMB2_STRATEGY_NAMES,
                          SMB2_WEIGHTS as SMB2_DEFAULT_WEIGHTS,
                          SMB3_STRATEGIES as SMB3_STRATEGY_NAMES,
                          SMB3_WEIGHTS as SMB3_DEFAULT_WEIGHTS)
from protocol.http2 import (Http2Mutator, HTTP2_STRATEGY_LABELS,
                            HTTP2_STRATEGIES as HTTP2_STRATEGY_NAMES,
                            HTTP2_WEIGHTS as HTTP2_DEFAULT_WEIGHTS)
from protocol.dcerpc import (DcerpcMutator, DCERPC_STRATEGY_LABELS,
                             DCERPC_STRATEGIES as DCERPC_STRATEGY_NAMES,
                             DCERPC_WEIGHTS as DCERPC_DEFAULT_WEIGHTS)
from protocol.dhcp import (DhcpMutator, DHCP_STRATEGY_LABELS,
                           DHCP_STRATEGIES as DHCP_STRATEGY_NAMES,
                           DHCP_WEIGHTS as DHCP_DEFAULT_WEIGHTS)
from protocol.dhcpv6 import (Dhcpv6Mutator, DHCPV6_STRATEGY_LABELS,
                             DHCPV6_STRATEGIES as DHCPV6_STRATEGY_NAMES,
                             DHCPV6_WEIGHTS as DHCPV6_DEFAULT_WEIGHTS)
from protocol.snmp import (SnmpMutator, SNMP_STRATEGY_LABELS,
                           SNMP_STRATEGIES as SNMP_STRATEGY_NAMES,
                           SNMP_WEIGHTS as SNMP_DEFAULT_WEIGHTS)
from protocol.icmp import (IcmpMutator, ICMP_STRATEGY_LABELS,
                           ICMP_STRATEGIES as ICMP_STRATEGY_NAMES,
                           ICMP_WEIGHTS as ICMP_DEFAULT_WEIGHTS)
from protocol.icmpv6 import (Icmpv6Mutator, ICMPV6_STRATEGY_LABELS,
                             ICMPV6_STRATEGIES as ICMPV6_STRATEGY_NAMES,
                             ICMPV6_WEIGHTS as ICMPV6_DEFAULT_WEIGHTS)
from protocol.sip import (SipMutator, SIP_STRATEGY_LABELS,
                          SIP_STRATEGIES as SIP_STRATEGY_NAMES,
                          SIP_WEIGHTS as SIP_DEFAULT_WEIGHTS)
from protocol.mgcp import (MgcpMutator, MGCP_STRATEGY_LABELS,
                           MGCP_STRATEGIES as MGCP_STRATEGY_NAMES,
                           MGCP_WEIGHTS as MGCP_DEFAULT_WEIGHTS)
from protocol.rtsp import (RtspMutator, RTSP_STRATEGY_LABELS,
                           RTSP_STRATEGIES as RTSP_STRATEGY_NAMES,
                           RTSP_WEIGHTS as RTSP_DEFAULT_WEIGHTS)
from protocol.radius import (RadiusMutator, RADIUS_STRATEGY_LABELS,
                              RADIUS_STRATEGIES as RADIUS_STRATEGY_NAMES,
                              RADIUS_WEIGHTS as RADIUS_DEFAULT_WEIGHTS)
from protocol.tacacs import (TacacsMutator, TACACS_STRATEGY_LABELS,
                             TACACS_STRATEGIES as TACACS_STRATEGY_NAMES,
                             TACACS_WEIGHTS as TACACS_DEFAULT_WEIGHTS)
from protocol.ldap import (LdapMutator, LDAP_STRATEGY_LABELS,
                           LDAP_STRATEGIES as LDAP_STRATEGY_NAMES,
                           LDAP_WEIGHTS as LDAP_DEFAULT_WEIGHTS)
from protocol.cifs import (CifsMutator, CIFS_STRATEGY_LABELS,
                           CIFS_STRATEGIES as CIFS_STRATEGY_NAMES,
                           CIFS_WEIGHTS as CIFS_DEFAULT_WEIGHTS)
from protocol.sunrpc import (SunrpcMutator, SUNRPC_STRATEGY_LABELS,
                             SUNRPC_STRATEGIES as SUNRPC_STRATEGY_NAMES,
                             SUNRPC_WEIGHTS as SUNRPC_DEFAULT_WEIGHTS)
from protocol.telnet import (TelnetMutator, TELNET_STRATEGY_LABELS,
                             TELNET_STRATEGIES as TELNET_STRATEGY_NAMES,
                             TELNET_WEIGHTS as TELNET_DEFAULT_WEIGHTS)
from protocol.tftp import (TftpMutator, TFTP_STRATEGY_LABELS,
                           TFTP_STRATEGIES as TFTP_STRATEGY_NAMES,
                           TFTP_WEIGHTS as TFTP_DEFAULT_WEIGHTS)
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

# FTP_STRATEGY_NAMES / FTP_DEFAULT_WEIGHTS are imported from protocol.ftp
# HTTP_STRATEGY_NAMES / HTTP_DEFAULT_WEIGHTS are imported from protocol.http
# (single source of truth; includes both request- and response-side strategies).

ai_weights = {
    "source": "default",
    "dns": dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS)),
    "ftp": dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS)),
    "http": dict(zip(HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS)),
    "smtp": dict(zip(SMTP_STRATEGY_NAMES, SMTP_DEFAULT_WEIGHTS)),
    "ssh": dict(zip(SSH_STRATEGY_NAMES, SSH_DEFAULT_WEIGHTS)),
    "smb2": dict(zip(SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS)),
    "smb3": dict(zip(SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS)),
    "http2": dict(zip(HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS)),
    "dcerpc": dict(zip(DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS)),
    "dhcp": dict(zip(DHCP_STRATEGY_NAMES, DHCP_DEFAULT_WEIGHTS)),
    "dhcpv6": dict(zip(DHCPV6_STRATEGY_NAMES, DHCPV6_DEFAULT_WEIGHTS)),
    "snmp": dict(zip(SNMP_STRATEGY_NAMES, SNMP_DEFAULT_WEIGHTS)),
    "sip": dict(zip(SIP_STRATEGY_NAMES, SIP_DEFAULT_WEIGHTS)),
    "mgcp": dict(zip(MGCP_STRATEGY_NAMES, MGCP_DEFAULT_WEIGHTS)),
    "rtsp": dict(zip(RTSP_STRATEGY_NAMES, RTSP_DEFAULT_WEIGHTS)),
    "radius": dict(zip(RADIUS_STRATEGY_NAMES, RADIUS_DEFAULT_WEIGHTS)),
    "tacacs": dict(zip(TACACS_STRATEGY_NAMES, TACACS_DEFAULT_WEIGHTS)),
    "ldap": dict(zip(LDAP_STRATEGY_NAMES, LDAP_DEFAULT_WEIGHTS)),
    "cifs": dict(zip(CIFS_STRATEGY_NAMES, CIFS_DEFAULT_WEIGHTS)),
    "telnet": dict(zip(TELNET_STRATEGY_NAMES, TELNET_DEFAULT_WEIGHTS)),
    "tftp": dict(zip(TFTP_STRATEGY_NAMES, TFTP_DEFAULT_WEIGHTS)),
    "reasoning": "",
}

# RL bandits — one per protocol, adjusts base weights via multipliers
dns_bandit = UCB1Bandit(DNS_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
ftp_bandit = UCB1Bandit(FTP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
http_bandit = UCB1Bandit(HTTP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
smtp_bandit = UCB1Bandit(SMTP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
ssh_bandit = UCB1Bandit(SSH_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
smb2_bandit = UCB1Bandit(SMB2_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
smb3_bandit = UCB1Bandit(SMB3_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
http2_bandit = UCB1Bandit(HTTP2_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
dcerpc_bandit = UCB1Bandit(DCERPC_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
dhcp_bandit = UCB1Bandit(DHCP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
dhcpv6_bandit = UCB1Bandit(DHCPV6_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
snmp_bandit = UCB1Bandit(SNMP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
icmp_bandit = UCB1Bandit(ICMP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
icmpv6_bandit = UCB1Bandit(ICMPV6_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
sip_bandit = UCB1Bandit(SIP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
mgcp_bandit = UCB1Bandit(MGCP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
rtsp_bandit = UCB1Bandit(RTSP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
radius_bandit = UCB1Bandit(RADIUS_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
tacacs_bandit = UCB1Bandit(TACACS_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
ldap_bandit = UCB1Bandit(LDAP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
cifs_bandit = UCB1Bandit(CIFS_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
sunrpc_bandit = UCB1Bandit(SUNRPC_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
telnet_bandit = UCB1Bandit(TELNET_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)
tftp_bandit = UCB1Bandit(TFTP_STRATEGY_NAMES, crash_boost=0.5, decay_rate=0.1)

import uuid as _uuid
import copy as _copy
import multiprocessing as _mp

_mp_ctx = _mp.get_context("spawn")

_PROTOCOL_STRATEGIES = {
    "dns": DNS_STRATEGY_NAMES,
    "ftp": FTP_STRATEGY_NAMES,
    "http": HTTP_STRATEGY_NAMES,
    "smtp": SMTP_STRATEGY_NAMES,
    "ssh": SSH_STRATEGY_NAMES,
    "smb2": SMB2_STRATEGY_NAMES,
    "smb3": SMB3_STRATEGY_NAMES,
    "http2": HTTP2_STRATEGY_NAMES,
    "dcerpc": DCERPC_STRATEGY_NAMES,
    "dhcp": DHCP_STRATEGY_NAMES,
    "dhcpv6": DHCPV6_STRATEGY_NAMES,
    "snmp": SNMP_STRATEGY_NAMES,
    "icmp": ICMP_STRATEGY_NAMES,
    "icmpv6": ICMPV6_STRATEGY_NAMES,
    "sip": SIP_STRATEGY_NAMES,
    "mgcp": MGCP_STRATEGY_NAMES,
    "rtsp": RTSP_STRATEGY_NAMES,
    "radius": RADIUS_STRATEGY_NAMES,
    "tacacs": TACACS_STRATEGY_NAMES,
    "ldap": LDAP_STRATEGY_NAMES,
    "cifs": CIFS_STRATEGY_NAMES,
    "sunrpc": SUNRPC_STRATEGY_NAMES,
    "telnet": TELNET_STRATEGY_NAMES,
    "tftp": TFTP_STRATEGY_NAMES,
}

_MEM_PRESSURE_STRATEGIES = {
    "dns": ["tcp_dns_segment", "txt_rdata_bomb", "tcp_two_message",
            "dce_smb", "inspector_stress", "compression_loop"],
    "ftp": None,
    "http": None,
    "smtp": None,
    "ssh": None,
    "smb2": None,
    "smb3": None,
    "http2": None,
    "dcerpc": None,
    "ldap": None,
    "telnet": None,
    "rtsp": None,
    "tacacs": None,
    "cifs": None,
}

_mp_manager = None
_mp_manager_lock = threading.Lock()


def _get_manager():
    global _mp_manager
    if _mp_manager is None:
        with _mp_manager_lock:
            if _mp_manager is None:
                _mp_manager = _mp_ctx.Manager()
    return _mp_manager


_instances = {}           # instance_id -> FuzzerInstance
_instances_lock = threading.Lock()


class FuzzerInstance:
    """Encapsulates all per-run state for one fuzzer instance."""

    def __init__(self, instance_id=None, protocol="dns", config=None):
        self.id = instance_id or _uuid.uuid4().hex[:12]
        self.protocol = protocol
        self.config = config or {}

        self.state = {
            "iteration": 0,
            "last_packet_time": time.time(),
            "running": False,
            "protocol": protocol,
            "anomaly_detected": None,
            "current_strategy": "",
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
            "payload_mode": "default",
            "payload_override": None,
        }

        self.event_log = []
        self.weights = _copy.deepcopy(ai_weights)

        strat_names = _PROTOCOL_STRATEGIES.get(protocol, DNS_STRATEGY_NAMES)
        self.bandit = UCB1Bandit(strat_names, crash_boost=0.5, decay_rate=0.1)

        self.thread = None
        self.transport = None
        self.watchdog_thread = None
        # Multiprocessing support (populated by start_as_process)
        self._shared_state = None
        self._stop_event = None
        self.process = None

    def log_event(self, level, message):
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        self.event_log.append(entry)
        if len(self.event_log) > 500:
            self.event_log.pop(0)

    def reset_state(self):
        protocol = self.state.get("protocol", self.protocol)
        payload_mode = self.state.get("payload_mode", "default")
        payload_override = self.state.get("payload_override")
        self.state.update({
            "iteration": 0,
            "last_packet_time": time.time(),
            "running": False,
            "protocol": protocol,
            "anomaly_detected": None,
            "current_strategy": "",
            "start_time": None,
            "run_id": self.state.get("run_id", 0) + 1,
            "baseline_mem_mb": None,
            "peak_mem_mb": None,
            "current_mem_mb": None,
            "payload_mode": payload_mode,
            "payload_override": payload_override,
            "snort_pid": None,
            "trigger_detail": None,
            "status": "idle",
            "last_crash_time": None,
            "last_crash_type": None,
            "packets_per_sec": 0,
            "strategy_stats": {},
        })
        self.event_log.clear()

    def save_crash_log(self, iteration, stderr_data, anomaly_type="CRASH", return_code=None):
        os.makedirs("crashes", exist_ok=True)
        timestamp = int(time.time())
        report_path = f"crashes/{self.id}_{anomaly_type}_report_{iteration}_{timestamp}.txt"

        elapsed = time.time() - self.state["start_time"] if self.state["start_time"] else 0
        hours, rem = divmod(int(elapsed), 3600)
        mins, secs = divmod(rem, 60)

        with open(report_path, "w") as f:
            f.write("=" * 70 + "\n")
            f.write(f"  SNORT FUZZER CRASH REPORT \u2014 {anomaly_type}\n")
            f.write(f"  Instance: {self.id} | Protocol: {self.protocol}\n")
            f.write("=" * 70 + "\n\n")
            f.write("[1] ENVIRONMENT\n")
            f.write(f"    Timestamp       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"    Platform        : {platform.system()} {platform.release()} ({platform.machine()})\n")
            f.write(f"    Python          : {platform.python_version()}\n")
            f.write(f"    Snort PID       : {self.state.get('snort_pid', 'N/A')}\n\n")
            f.write("[2] FUZZER STATE AT CRASH\n")
            f.write(f"    Anomaly Type    : {anomaly_type}\n")
            f.write(f"    Strategy        : {self.state['current_strategy']}\n")
            f.write(f"    Iteration       : {iteration:,}\n")
            f.write(f"    Runtime         : {hours:02d}:{mins:02d}:{secs:02d}\n")
            f.write(f"    Throughput      : {iteration / max(elapsed, 0.001):,.0f} packets/sec\n\n")
            f.write("[3] MEMORY ANALYSIS\n")
            f.write(f"    Baseline RSS    : {self.state.get('baseline_mem_mb', 'N/A')} MB\n")
            f.write(f"    Current RSS     : {self.state.get('current_mem_mb', 'N/A')} MB\n")
            f.write(f"    Peak RSS        : {self.state.get('peak_mem_mb', 'N/A')} MB\n")
            baseline = self.state.get('baseline_mem_mb')
            current = self.state.get('current_mem_mb')
            if baseline and current:
                growth = current - baseline
                f.write(f"    Memory Growth   : +{growth:.2f} MB ({growth/baseline*100:.1f}% over baseline)\n")
            f.write("\n")
            f.write("[4] TRIGGER DETAIL\n")
            f.write(f"    {self.state.get('trigger_detail', 'No additional detail captured.')}\n\n")
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

        self.state["total_crashes"] = self.state.get("total_crashes", 0) + 1
        self.state["last_crash_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.state["last_crash_type"] = anomaly_type
        self.log_event("CRITICAL", f"{anomaly_type} detected at iteration {iteration:,}")
        self.log_event("INFO", f"Crash report saved: {report_path}")
        print(f"\n[!!!] [{self.id}] {anomaly_type} DETECTED AT ITERATION {iteration:,} [!!!]")
        print(f"[+] Diagnostic trace saved to: {report_path}")

    # ── Multiprocessing helpers ───────────────────────────────────────────

    def start_as_process(self):
        """Start this instance as a separate OS process (bypasses GIL)."""
        mgr = _get_manager()
        self._shared_state = mgr.dict(self.state)
        self._stop_event = _mp_ctx.Event()

        self.process = _mp_ctx.Process(
            target=_run_instance_mp,
            args=(self.protocol, self.config, dict(self.weights),
                  self._shared_state, self._stop_event),
            daemon=True,
        )
        self.process.start()

    def request_stop(self):
        """Signal the instance to stop (works for both thread and process)."""
        if self._stop_event:
            self._stop_event.set()
        else:
            self.state["running"] = False

    def get_state(self):
        """Return current state snapshot (reads from Manager proxy in process mode)."""
        if self._shared_state is not None:
            try:
                return dict(self._shared_state)
            except Exception:
                return dict(self.state)
        return dict(self.state)

    def get_events(self):
        """Return recent event log entries."""
        if self._shared_state is not None:
            try:
                return list(self._shared_state.get("_events_snapshot", []))
            except Exception:
                return list(self.event_log[-20:])
        return list(self.event_log[-20:])

    def get_bandit_stats(self):
        """Return bandit statistics (from shared state in process mode)."""
        if self._shared_state is not None:
            try:
                return self._shared_state.get("_bandit_stats", {})
            except Exception:
                return {}
        return self.bandit.get_stats(
            base_weights=self.weights.get(self.protocol, {}))

    def is_alive(self):
        if self.process:
            return self.process.is_alive()
        if self.thread:
            return self.thread.is_alive()
        return False


# ── Instance registry functions ───────────────────────────────────────────

def create_instance(protocol="dns", config=None):
    inst = FuzzerInstance(protocol=protocol, config=config or {})
    with _instances_lock:
        _instances[inst.id] = inst
    return inst

def get_instance(instance_id):
    return _instances.get(instance_id)

def list_instances():
    return list(_instances.values())

def destroy_instance(instance_id):
    with _instances_lock:
        inst = _instances.pop(instance_id, None)
    if inst:
        inst.request_stop()
        if inst.process and inst.process.is_alive():
            inst.process.join(timeout=3)
            if inst.process.is_alive():
                inst.process.terminate()
    return inst is not None


def _bandit_for(protocol):
    if protocol == "ftp":
        return ftp_bandit
    if protocol == "http":
        return http_bandit
    if protocol == "smtp":
        return smtp_bandit
    if protocol == "ssh":
        return ssh_bandit
    if protocol == "smb2":
        return smb2_bandit
    if protocol == "smb3":
        return smb3_bandit
    if protocol == "http2":
        return http2_bandit
    if protocol == "dcerpc":
        return dcerpc_bandit
    if protocol == "dhcp":
        return dhcp_bandit
    if protocol == "dhcpv6":
        return dhcpv6_bandit
    if protocol == "snmp":
        return snmp_bandit
    if protocol == "icmp":
        return icmp_bandit
    if protocol == "icmpv6":
        return icmpv6_bandit
    if protocol == "sip":
        return sip_bandit
    if protocol == "mgcp":
        return mgcp_bandit
    if protocol == "rtsp":
        return rtsp_bandit
    if protocol == "radius":
        return radius_bandit
    if protocol == "tacacs":
        return tacacs_bandit
    if protocol == "ldap":
        return ldap_bandit
    if protocol == "cifs":
        return cifs_bandit
    if protocol == "sunrpc":
        return sunrpc_bandit
    if protocol == "telnet":
        return telnet_bandit
    if protocol == "tftp":
        return tftp_bandit
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
    "payload_mode": "default",
    "payload_override": None,
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
    payload_mode = fuzzer_state.get("payload_mode", "default")
    payload_override = fuzzer_state.get("payload_override")
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
        "payload_mode": payload_mode,
        "payload_override": payload_override,
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

def _build_dns_mutation(strategy: str, seed_message, payload_override=None):
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
        mutated_bytes = ResponseMutator.mutate(payload_override=payload_override)
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
        tcp_payload = TxtRdataBombMutator.mutate(payload_override=payload_override)
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

    consecutive_failures = 0
    max_failures = 3

    while fuzzer_state["running"]:
        time.sleep(2.0)
        alive = monitor.is_alive()

        if alive is True:
            consecutive_failures = 0
        elif alive is None:
            pass
        elif alive is False:
            new_pid = monitor.find_snort_pid()
            if new_pid:
                log_event("INFO",
                    f"Snort PID rotated on {monitor.host}: {monitor.snort_pid} → {new_pid} (normal FTD behavior)")
                monitor.update_pid(new_pid)
                fuzzer_state["snort_pid"] = new_pid
                consecutive_failures = 0
                baseline_mem = None
                mem = monitor.get_memory_mb()
                if mem is not None:
                    baseline_mem = mem
                    fuzzer_state["baseline_mem_mb"] = round(mem, 2)
                continue

            consecutive_failures += 1
            log_event("WARNING",
                f"Snort PID {monitor.snort_pid} not found on {monitor.host} "
                f"({consecutive_failures}/{max_failures} before crash declaration)")
            if consecutive_failures >= max_failures:
                fuzzer_state["anomaly_detected"] = "REMOTE_SNORT_CRASH"
                fuzzer_state["status"] = "crash_detected"
                fuzzer_state["trigger_detail"] = (
                    f"Snort PID {monitor.snort_pid} on {monitor.host} not found after "
                    f"{max_failures} consecutive checks. No snort3 process found \u2014 likely crashed."
                )
                fuzzer_state["running"] = False
                log_event("CRITICAL", f"Remote Snort crash on {monitor.host} (PID {monitor.snort_pid}) — confirmed after {max_failures} checks")
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
        smtp_mutator = None
        smb_mutator = None
        seed_message = None
    elif protocol == "http":
        transport = StreamTransport(target_port=80)
        ftp_mutator = None
        http_mutator = HttpMutator(external_weights=ai_weights.get("http"), bandit=http_bandit)
        smtp_mutator = None
        smb_mutator = None
        seed_message = None
    elif protocol == "smtp":
        transport = StreamTransport(target_port=25)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = SmtpMutator(external_weights=ai_weights.get("smtp"), bandit=smtp_bandit)
        smb_mutator = None
        seed_message = None
    elif protocol == "ssh":
        transport = StreamTransport(target_port=22)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        ssh_mutator = SshMutator(external_weights=ai_weights.get("ssh"), bandit=ssh_bandit)
        smb_mutator = None
        seed_message = None
    elif protocol == "smb2":
        transport = StreamTransport(target_port=445)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = Smb2Mutator(external_weights=ai_weights.get("smb2"), bandit=smb2_bandit)
        seed_message = None
    elif protocol == "smb3":
        transport = StreamTransport(target_port=445)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = Smb3Mutator(external_weights=ai_weights.get("smb3"), bandit=smb3_bandit)
        http2_mutator = None
        seed_message = None
    elif protocol == "http2":
        transport = StreamTransport(target_port=80)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        http2_mutator = Http2Mutator(external_weights=ai_weights.get("http2"), bandit=http2_bandit)
        seed_message = None
    elif protocol == "dcerpc":
        transport = StreamTransport(target_port=135)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        dcerpc_mutator = DcerpcMutator(external_weights=ai_weights.get("dcerpc"), bandit=dcerpc_bandit)
        seed_message = None
    elif protocol == "dhcp":
        transport = StreamTransport(target_port=67)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        dhcp_mutator = DhcpMutator(external_weights=ai_weights.get("dhcp"), bandit=dhcp_bandit)
        seed_message = None
    elif protocol == "dhcpv6":
        transport = StreamTransport(target_port=547)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        dhcpv6_mutator = Dhcpv6Mutator(external_weights=ai_weights.get("dhcpv6"), bandit=dhcpv6_bandit)
        seed_message = None
    elif protocol == "snmp":
        transport = StreamTransport(target_port=161)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        snmp_mutator = SnmpMutator(external_weights=ai_weights.get("snmp"), bandit=snmp_bandit)
        seed_message = None
    elif protocol == "icmp":
        transport = StreamTransport(target_port=0)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        icmp_mutator = IcmpMutator(external_weights=ai_weights.get("icmp"), bandit=icmp_bandit)
        seed_message = None
    elif protocol == "icmpv6":
        transport = StreamTransport(target_port=0)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        icmpv6_mutator = Icmpv6Mutator(external_weights=ai_weights.get("icmpv6"), bandit=icmpv6_bandit)
        seed_message = None
    elif protocol == "sip":
        transport = StreamTransport(target_port=5060)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        sip_mutator = SipMutator(external_weights=ai_weights.get("sip"), bandit=sip_bandit)
        seed_message = None
    elif protocol == "mgcp":
        transport = StreamTransport(target_port=2427)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        mgcp_mutator = MgcpMutator(external_weights=ai_weights.get("mgcp"), bandit=mgcp_bandit)
        seed_message = None
    elif protocol == "rtsp":
        transport = StreamTransport(target_port=554)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        rtsp_mutator = RtspMutator(external_weights=ai_weights.get("rtsp"), bandit=rtsp_bandit)
        seed_message = None
    elif protocol == "radius":
        transport = StreamTransport(target_port=1812)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        radius_mutator = RadiusMutator(external_weights=ai_weights.get("radius"), bandit=radius_bandit)
        seed_message = None
    elif protocol == "tacacs":
        transport = StreamTransport(target_port=49)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        tacacs_mutator = TacacsMutator(external_weights=ai_weights.get("tacacs"), bandit=tacacs_bandit)
        seed_message = None
    elif protocol == "ldap":
        transport = StreamTransport(target_port=389)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        ldap_mutator = LdapMutator(external_weights=ai_weights.get("ldap"), bandit=ldap_bandit)
        seed_message = None
    elif protocol == "cifs":
        transport = StreamTransport(target_port=445)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        cifs_mutator = CifsMutator(external_weights=ai_weights.get("cifs"), bandit=cifs_bandit)
        seed_message = None
    elif protocol == "sunrpc":
        transport = StreamTransport(target_port=111)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        sunrpc_mutator = SunrpcMutator(external_weights=ai_weights.get("sunrpc"), bandit=sunrpc_bandit)
        seed_message = None
    elif protocol == "telnet":
        transport = StreamTransport(target_port=23)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        telnet_mutator = TelnetMutator(external_weights=ai_weights.get("telnet"), bandit=telnet_bandit)
        seed_message = None
    elif protocol == "tftp":
        transport = StreamTransport(target_port=69)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
        tftp_mutator = TftpMutator(external_weights=ai_weights.get("tftp"), bandit=tftp_bandit)
        seed_message = None
    else:
        transport = StreamTransport(target_port=53)
        ftp_mutator = None
        http_mutator = None
        smtp_mutator = None
        smb_mutator = None
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

            # Resolve dynamic payload override (None = default random mode)
            _po = fuzzer_state.get("payload_override") if fuzzer_state.get("payload_mode") == "custom" else None

            while fuzzer_state["running"] and not fuzzer_state["anomaly_detected"]:
                fuzzer_state["iteration"] += 1
                iteration = fuzzer_state["iteration"]

                if protocol == "ftp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _ftp_payload, _ftp_strategy = ftp_mutator.mutate(payload_override=_po)
                    payload, strategy = _ftp_payload, _ftp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session(payload, src_port=src_port))
                    fuzzer_state["iteration"] += 4  # 5 PCAP records per TCP session (includes FIN-ACK)
                elif protocol == "http":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _http_payload, _http_strategy = http_mutator.mutate(payload_override=_po)
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
                elif protocol == "smtp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _smtp_payload, _smtp_strategy = smtp_mutator.mutate(payload_override=_po)
                    payload, strategy = _smtp_payload, _smtp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session(payload, src_port=src_port))
                    fuzzer_state["iteration"] += 4  # full TCP session per SMTP transaction
                elif protocol == "ssh":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _ssh_payload, _ssh_strategy = ssh_mutator.mutate(payload_override=_po)
                    payload, strategy = _ssh_payload, _ssh_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session(payload, src_port=src_port))
                    fuzzer_state["iteration"] += 4  # full TCP session per SSH handshake
                elif protocol in ("smb2", "smb3"):
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _smb_payload, _smb_strategy = smb_mutator.mutate(payload_override=_po)
                    payload, strategy = _smb_payload, _smb_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session(payload, src_port=src_port))
                    fuzzer_state["iteration"] += 4  # full TCP session per SMB transaction
                elif protocol == "http2":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _h2_payload, _h2_strategy = http2_mutator.mutate(payload_override=_po)
                    payload, strategy = _h2_payload, _h2_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session(payload, src_port=src_port))
                    fuzzer_state["iteration"] += 4  # full TCP session per HTTP/2 message
                elif protocol == "dcerpc":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _dcerpc_payload, _dcerpc_strategy = dcerpc_mutator.mutate(payload_override=_po)
                    payload, strategy = _dcerpc_payload, _dcerpc_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session(payload, src_port=src_port))
                    fuzzer_state["iteration"] += 4  # full TCP session per DCE/RPC message
                elif protocol == "dhcp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _dhcp_payload, _dhcp_strategy, _dhcp_dst_port = dhcp_mutator.mutate(payload_override=_po)
                    payload, strategy = _dhcp_payload, _dhcp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = 68 if _dhcp_dst_port == 67 else 67
                    pipe.write(transport.wrap_udp_to_port(payload, _dhcp_dst_port,
                                                          src_ip=src_ip, src_port=src_port))
                elif protocol == "dhcpv6":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _dhcpv6_payload, _dhcpv6_strategy, _dhcpv6_dst_port = dhcpv6_mutator.mutate(payload_override=_po)
                    payload, strategy = _dhcpv6_payload, _dhcpv6_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = 546 if _dhcpv6_dst_port == 547 else 547
                    pipe.write(transport.wrap_udp_to_port(payload, _dhcpv6_dst_port,
                                                          src_ip=src_ip, src_port=src_port))
                elif protocol == "snmp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _snmp_payload, _snmp_strategy, _snmp_dst_port = snmp_mutator.mutate(payload_override=_po)
                    payload, strategy = _snmp_payload, _snmp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_udp_to_port(payload, _snmp_dst_port,
                                                          src_ip=src_ip, src_port=src_port))
                elif protocol == "icmp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _icmp_data, _icmp_strategy, _icmp_pkt_type = icmp_mutator.mutate(payload_override=_po)
                    strategy = _icmp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    if _icmp_pkt_type == "fragments":
                        pipe.write(transport.wrap_ip_fragments(_icmp_data, src_ip=src_ip))
                        fuzzer_state["iteration"] += max(0, len(_icmp_data) - 1)
                    elif _icmp_pkt_type == "raw_ip":
                        pipe.write(transport.wrap_raw_ip_packet(_icmp_data))
                    else:
                        pipe.write(transport.wrap_icmp(_icmp_data, src_ip=src_ip))
                elif protocol == "icmpv6":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _v6_data, _v6_strategy, _v6_pkt_type, _v6_src, _v6_dst = icmpv6_mutator.mutate(payload_override=_po)
                    strategy = _v6_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    if _v6_pkt_type == "fragments":
                        pipe.write(transport.wrap_ipv6_fragments(_v6_data))
                        fuzzer_state["iteration"] += max(0, len(_v6_data) - 1)
                    elif _v6_pkt_type == "raw_ipv6":
                        pipe.write(transport.wrap_raw_ipv6_packet(_v6_data))
                    else:
                        pipe.write(transport.wrap_icmpv6(_v6_data, _v6_src, _v6_dst))
                elif protocol == "sip":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _sip_payload, _sip_strategy, _sip_dst_port = sip_mutator.mutate(payload_override=_po)
                    payload, strategy = _sip_payload, _sip_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_udp_to_port(payload, _sip_dst_port,
                                                          src_ip=src_ip, src_port=src_port))
                elif protocol == "mgcp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _mgcp_payload, _mgcp_strategy, _mgcp_dst_port = mgcp_mutator.mutate(payload_override=_po)
                    payload, strategy = _mgcp_payload, _mgcp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_udp_to_port(payload, _mgcp_dst_port,
                                                          src_ip=src_ip, src_port=src_port))
                elif protocol == "rtsp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _rtsp_payload, _rtsp_strategy, _rtsp_dst_port = rtsp_mutator.mutate(payload_override=_po)
                    payload, strategy = _rtsp_payload, _rtsp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session_to_port(payload, _rtsp_dst_port,
                                                                src_ip=src_ip))
                elif protocol == "radius":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _radius_payload, _radius_strategy, _radius_dst_port = radius_mutator.mutate(payload_override=_po)
                    payload, strategy = _radius_payload, _radius_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_udp_to_port(payload, _radius_dst_port,
                                                          src_ip=src_ip, src_port=src_port))
                elif protocol == "tacacs":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _tacacs_payload, _tacacs_strategy, _tacacs_dst_port = tacacs_mutator.mutate(payload_override=_po)
                    payload, strategy = _tacacs_payload, _tacacs_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_tcp_session_to_port(payload, _tacacs_dst_port,
                                                                src_ip=random.randint(0x01000001, 0xFEFFFFFF)))
                    fuzzer_state["iteration"] += 4
                elif protocol == "ldap":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _ldap_payload, _ldap_strategy, _ldap_dst_port = ldap_mutator.mutate(payload_override=_po)
                    payload, strategy = _ldap_payload, _ldap_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_port = random.randint(1025, 65534)
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    if strategy == "tcp_segment_evasion":
                        split_at = random.choice([1, 2, 3, max(1, len(payload) // 3), max(1, len(payload) // 2)])
                        pipe.write(transport.wrap_split_tcp_session(payload, split_at=split_at, src_ip=src_ip))
                    else:
                        pipe.write(transport.wrap_tcp_session_to_port(payload, _ldap_dst_port, src_ip=src_ip))
                    fuzzer_state["iteration"] += 4
                elif protocol == "cifs":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _cifs_payload, _cifs_strategy, _cifs_dst_port = cifs_mutator.mutate(payload_override=_po)
                    payload, strategy = _cifs_payload, _cifs_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    if strategy == "tcp_segmentation_evasion":
                        split_at = random.choice([1, 2, 3, max(1, len(payload) // 3), max(1, len(payload) // 2)])
                        pipe.write(transport.wrap_split_tcp_session(payload, split_at=split_at, src_ip=src_ip))
                    else:
                        pipe.write(transport.wrap_tcp_session_to_port(payload, _cifs_dst_port, src_ip=src_ip))
                    fuzzer_state["iteration"] += 4
                elif protocol == "sunrpc":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _sunrpc_payload, _sunrpc_strategy, _sunrpc_dst_port = sunrpc_mutator.mutate(payload_override=_po)
                    payload, strategy = _sunrpc_payload, _sunrpc_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = random.randint(1025, 65534)
                    # TCP-oriented strategies (RM framing, segmentation, NFS COMPOUND)
                    _tcp_strategies = ("record_marking_abuse", "tcp_segmentation_evasion",
                                       "nfs_compound_overflow")
                    if strategy in _tcp_strategies:
                        if strategy == "tcp_segmentation_evasion":
                            split_at = random.choice([2, 4, 8, max(1, len(payload) // 3)])
                            pipe.write(transport.wrap_split_tcp_session(payload, split_at=split_at, src_ip=src_ip))
                        else:
                            pipe.write(transport.wrap_tcp_session_to_port(payload, _sunrpc_dst_port, src_ip=src_ip))
                        fuzzer_state["iteration"] += 4
                    else:
                        pipe.write(transport.wrap_udp_to_port(payload, _sunrpc_dst_port,
                                                              src_ip=src_ip, src_port=src_port))
                elif protocol == "telnet":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _telnet_payload, _telnet_strategy, _telnet_dst_port = telnet_mutator.mutate(payload_override=_po)
                    payload, strategy = _telnet_payload, _telnet_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    if strategy == "tcp_segmentation_evasion":
                        split_at = random.choice([1, 2, 3, max(1, len(payload) // 3), max(1, len(payload) // 2)])
                        pipe.write(transport.wrap_split_tcp_session(payload, split_at=split_at, src_ip=src_ip))
                    else:
                        pipe.write(transport.wrap_tcp_session_to_port(payload, _telnet_dst_port, src_ip=src_ip))
                    fuzzer_state["iteration"] += 4
                elif protocol == "tftp":
                    if iteration == 1 or (iteration - 1) % 50 == 0:
                        _tftp_payload, _tftp_strategy, _tftp_dst_port = tftp_mutator.mutate(payload_override=_po)
                    payload, strategy = _tftp_payload, _tftp_strategy
                    fuzzer_state["current_strategy"] = strategy
                    fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                    src_ip = random.randint(0x01000001, 0xFEFFFFFF)
                    src_port = random.randint(1025, 65534)
                    pipe.write(transport.wrap_udp_to_port(payload, _tftp_dst_port,
                                                          src_ip=src_ip, src_port=src_port))
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
                        mutated_bytes, tcp_payload, split_at = _build_dns_mutation(strategy, seed_message, payload_override=_po)
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

                stat_interval = 500 if protocol in ("ftp", "http", "smtp", "ssh", "smb2", "smb3", "http2", "dcerpc", "dhcp", "dhcpv6", "snmp", "icmp", "icmpv6", "sip", "mgcp", "radius", "tacacs", "ldap", "cifs", "sunrpc", "telnet", "tftp") else 10000
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
    mem_pressure = config.get("mem_pressure", False)

    protocol = fuzzer_state.get("protocol", "dns")
    live_transport = LiveNetworkTransport(server_ip, server_port, interface,
                                         mem_pressure=mem_pressure)

    if protocol == "ftp":
        ftp_mutator_inst = FtpMutator(external_weights=ai_weights.get("ftp"), bandit=ftp_bandit)
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        seed_message = None
    elif protocol == "http":
        ftp_mutator_inst = None
        http_mutator_inst = HttpMutator(external_weights=ai_weights.get("http"), bandit=http_bandit)
        smtp_mutator_inst = None
        smb_mutator_inst = None
        seed_message = None
    elif protocol == "smtp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = SmtpMutator(external_weights=ai_weights.get("smtp"), bandit=smtp_bandit)
        smb_mutator_inst = None
        seed_message = None
    elif protocol == "ssh":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        ssh_mutator_inst = SshMutator(external_weights=ai_weights.get("ssh"), bandit=ssh_bandit)
        smb_mutator_inst = None
        seed_message = None
    elif protocol == "smb2":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = Smb2Mutator(external_weights=ai_weights.get("smb2"), bandit=smb2_bandit)
        seed_message = None
    elif protocol == "smb3":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = Smb3Mutator(external_weights=ai_weights.get("smb3"), bandit=smb3_bandit)
        http2_mutator_inst = None
        seed_message = None
    elif protocol == "http2":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        http2_mutator_inst = Http2Mutator(external_weights=ai_weights.get("http2"), bandit=http2_bandit)
        seed_message = None
    elif protocol == "dcerpc":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        dcerpc_mutator_inst = DcerpcMutator(external_weights=ai_weights.get("dcerpc"), bandit=dcerpc_bandit)
        seed_message = None
    elif protocol == "dhcp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        dhcp_mutator_inst = DhcpMutator(external_weights=ai_weights.get("dhcp"), bandit=dhcp_bandit)
        seed_message = None
    elif protocol == "dhcpv6":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        dhcpv6_mutator_inst = Dhcpv6Mutator(external_weights=ai_weights.get("dhcpv6"), bandit=dhcpv6_bandit)
        seed_message = None
    elif protocol == "snmp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        snmp_mutator_inst = SnmpMutator(external_weights=ai_weights.get("snmp"), bandit=snmp_bandit)
        seed_message = None
    elif protocol == "icmp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        icmp_mutator_inst = IcmpMutator(external_weights=ai_weights.get("icmp"), bandit=icmp_bandit)
        seed_message = None
    elif protocol == "icmpv6":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        icmpv6_mutator_inst = Icmpv6Mutator(external_weights=ai_weights.get("icmpv6"), bandit=icmpv6_bandit)
        seed_message = None
    elif protocol == "sip":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        sip_mutator_inst = SipMutator(external_weights=ai_weights.get("sip"), bandit=sip_bandit)
        seed_message = None
    elif protocol == "mgcp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        mgcp_mutator_inst = MgcpMutator(external_weights=ai_weights.get("mgcp"), bandit=mgcp_bandit)
        seed_message = None
    elif protocol == "rtsp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        rtsp_mutator_inst = RtspMutator(external_weights=ai_weights.get("rtsp"), bandit=rtsp_bandit)
        seed_message = None
    elif protocol == "radius":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        radius_mutator_inst = RadiusMutator(external_weights=ai_weights.get("radius"), bandit=radius_bandit)
        seed_message = None
    elif protocol == "tacacs":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        tacacs_mutator_inst = TacacsMutator(external_weights=ai_weights.get("tacacs"), bandit=tacacs_bandit)
        seed_message = None
    elif protocol == "ldap":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        ldap_mutator_inst = LdapMutator(external_weights=ai_weights.get("ldap"), bandit=ldap_bandit)
        seed_message = None
    elif protocol == "cifs":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        cifs_mutator_inst = CifsMutator(external_weights=ai_weights.get("cifs"), bandit=cifs_bandit)
        seed_message = None
    elif protocol == "sunrpc":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        sunrpc_mutator_inst = SunrpcMutator(external_weights=ai_weights.get("sunrpc"), bandit=sunrpc_bandit)
        seed_message = None
    elif protocol == "telnet":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        telnet_mutator_inst = TelnetMutator(external_weights=ai_weights.get("telnet"), bandit=telnet_bandit)
        seed_message = None
    elif protocol == "tftp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        tftp_mutator_inst = TftpMutator(external_weights=ai_weights.get("tftp"), bandit=tftp_bandit)
        seed_message = None
    else:
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        seed_question = DNSQuestion(qname="example.com")
        seed_message = DNSMessage(header=DNSHeader(), questions=[seed_question])

    fuzzer_state["start_time"] = time.time()
    fuzzer_state["status"] = "running"
    fuzzer_state["running"] = True
    iface_label = interface or "default route"
    log_event("INFO", f"Live fuzzer started → {server_ip}:{server_port} via {iface_label} ({protocol.upper()})")
    log_event("INFO", "Live TCP delivery mode: persistent sockets with reconnect-on-close.")
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
    _smtp_payload, _smtp_strategy = None, None
    _ssh_payload, _ssh_strategy = None, None
    _smb_payload, _smb_strategy = None, None
    _h2_payload, _h2_strategy = None, None
    _dcerpc_payload, _dcerpc_strategy = None, None
    _dhcp_payload, _dhcp_strategy, _dhcp_dst_port = None, None, None
    _dhcpv6_payload, _dhcpv6_strategy, _dhcpv6_dst_port = None, None, None
    _snmp_payload, _snmp_strategy, _snmp_dst_port = None, None, None
    _icmp_data, _icmp_strategy, _icmp_pkt_type = None, None, None
    _v6_data, _v6_strategy, _v6_pkt_type, _v6_src, _v6_dst = None, None, None, None, None
    _sip_payload, _sip_strategy, _sip_dst_port = None, None, None
    _rtsp_payload, _rtsp_strategy, _rtsp_dst_port = None, None, None
    _radius_payload, _radius_strategy, _radius_dst_port = None, None, None
    _tacacs_payload, _tacacs_strategy, _tacacs_dst_port = None, None, None
    _ldap_payload, _ldap_strategy, _ldap_dst_port = None, None, None
    _telnet_payload, _telnet_strategy, _telnet_dst_port = None, None, None
    _dns_cached_bytes, _dns_cached_tcp, _dns_cached_split, _dns_cached_strategy = None, None, None, None
    _dns_is_udp = True

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
                live_transport.send_persistent_tcp(_ftp_payload)
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
                live_transport.send_persistent_tcp(_http_payload, port=80)
                fuzzer_state["iteration"] += 1
            elif protocol == "smtp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _smtp_payload, _smtp_strategy = smtp_mutator_inst.mutate()
                strategy = _smtp_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                # Live mode is the CLIENT: client->server SMTP commands/DATA drive
                # the on-path smtp inspector. Default SMTP port is 25.
                live_transport.send_persistent_tcp(_smtp_payload, port=25)
                fuzzer_state["iteration"] += 1
            elif protocol == "ssh":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _ssh_payload, _ssh_strategy = ssh_mutator_inst.mutate()
                strategy = _ssh_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                # Live mode is the CLIENT: client->server SSH handshake bytes drive
                # the on-path ssh inspector. Default SSH port is 22.
                live_transport.send_persistent_tcp(_ssh_payload, port=22)
                fuzzer_state["iteration"] += 1
            elif protocol in ("smb2", "smb3"):
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _smb_payload, _smb_strategy = smb_mutator_inst.mutate()
                strategy = _smb_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_smb_payload, port=445)
                fuzzer_state["iteration"] += 1
            elif protocol == "http2":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _h2_payload, _h2_strategy = http2_mutator_inst.mutate()
                strategy = _h2_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_h2_payload, port=80)
                fuzzer_state["iteration"] += 1
            elif protocol == "dcerpc":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _dcerpc_payload, _dcerpc_strategy = dcerpc_mutator_inst.mutate()
                strategy = _dcerpc_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_dcerpc_payload, port=135)
                fuzzer_state["iteration"] += 1
            elif protocol == "dhcp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _dhcp_payload, _dhcp_strategy, _dhcp_dst_port = dhcp_mutator_inst.mutate()
                strategy = _dhcp_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_dhcp_payload, port=_dhcp_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "dhcpv6":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _dhcpv6_payload, _dhcpv6_strategy, _dhcpv6_dst_port = dhcpv6_mutator_inst.mutate()
                strategy = _dhcpv6_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_dhcpv6_payload, port=_dhcpv6_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "snmp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _snmp_payload, _snmp_strategy, _snmp_dst_port = snmp_mutator_inst.mutate()
                strategy = _snmp_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_snmp_payload, port=_snmp_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "icmp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _icmp_data, _icmp_strategy, _icmp_pkt_type = icmp_mutator_inst.mutate()
                strategy = _icmp_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                if _icmp_pkt_type in ("icmp", "raw_ip"):
                    live_transport.send_icmp(_icmp_data)
                else:
                    for frag_data, frag_off, frag_mf, frag_id, frag_proto in _icmp_data:
                        live_transport.send_icmp(frag_data)
                fuzzer_state["iteration"] += 1
            elif protocol == "icmpv6":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _v6_data, _v6_strategy, _v6_pkt_type, _v6_src, _v6_dst = icmpv6_mutator_inst.mutate()
                strategy = _v6_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                if _v6_pkt_type == "icmpv6":
                    live_transport.send_icmpv6(_v6_data, dst_ipv6=server_ip)
                elif _v6_pkt_type == "fragments":
                    for frag_pkt in _v6_data:
                        live_transport.send_icmpv6(frag_pkt, dst_ipv6=server_ip)
                else:
                    live_transport.send_icmpv6(_v6_data, dst_ipv6=server_ip)
                fuzzer_state["iteration"] += 1
            elif protocol == "sip":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _sip_payload, _sip_strategy, _sip_dst_port = sip_mutator_inst.mutate()
                strategy = _sip_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_sip_payload, port=_sip_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "mgcp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _mgcp_payload, _mgcp_strategy, _mgcp_dst_port = mgcp_mutator_inst.mutate()
                strategy = _mgcp_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_mgcp_payload, port=_mgcp_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "rtsp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _rtsp_payload, _rtsp_strategy, _rtsp_dst_port = rtsp_mutator_inst.mutate()
                strategy = _rtsp_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_rtsp_payload, port=_rtsp_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "radius":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _radius_payload, _radius_strategy, _radius_dst_port = radius_mutator_inst.mutate()
                strategy = _radius_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_radius_payload, port=_radius_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "tacacs":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _tacacs_payload, _tacacs_strategy, _tacacs_dst_port = tacacs_mutator_inst.mutate()
                strategy = _tacacs_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_tacacs_payload, port=_tacacs_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "ldap":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _ldap_payload, _ldap_strategy, _ldap_dst_port = ldap_mutator_inst.mutate()
                strategy = _ldap_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_ldap_payload, port=_ldap_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "cifs":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _cifs_payload, _cifs_strategy, _cifs_dst_port = cifs_mutator_inst.mutate()
                strategy = _cifs_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_cifs_payload, port=_cifs_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "sunrpc":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _sunrpc_payload, _sunrpc_strategy, _sunrpc_dst_port = sunrpc_mutator_inst.mutate()
                strategy = _sunrpc_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                _tcp_strats = ("record_marking_abuse", "tcp_segmentation_evasion",
                               "nfs_compound_overflow")
                if strategy in _tcp_strats:
                    live_transport.send_persistent_tcp(_sunrpc_payload, port=_sunrpc_dst_port)
                else:
                    live_transport.send_udp(_sunrpc_payload, port=_sunrpc_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "telnet":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _telnet_payload, _telnet_strategy, _telnet_dst_port = telnet_mutator_inst.mutate()
                strategy = _telnet_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_telnet_payload, port=_telnet_dst_port)
                fuzzer_state["iteration"] += 1
            elif protocol == "tftp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _tftp_payload, _tftp_strategy, _tftp_dst_port = tftp_mutator_inst.mutate()
                strategy = _tftp_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_tftp_payload, port=_tftp_dst_port)
                fuzzer_state["iteration"] += 1
            else:
                _dns_cache_interval = 200 if mem_pressure else 50
                if iteration == 1 or (iteration - 1) % _dns_cache_interval == 0:
                    dns_w = ai_weights.get("dns", {})
                    if mem_pressure:
                        _dns_cached_strategy = random.choice(_MEM_PRESSURE_STRATEGIES["dns"])
                    else:
                        _dns_cached_strategy = dns_bandit.select_with_weights(dns_w)
                    if _dns_cached_strategy == "back_orifice":
                        _dns_cached_bytes = BackOrificeMutator.mutate()
                        _dns_cached_tcp, _dns_cached_split = None, None
                        _dns_is_udp = True
                    elif _dns_cached_strategy == "dce_smb":
                        _dns_cached_tcp = DCESmbMutator.mutate()
                        _dns_cached_bytes, _dns_cached_split = None, None
                        _dns_is_udp = False
                    else:
                        _dns_cached_bytes, _dns_cached_tcp, _dns_cached_split = _build_dns_mutation(_dns_cached_strategy, seed_message)
                        _dns_is_udp = _dns_cached_bytes is not None

                    if mem_pressure and _dns_is_udp:
                        _dns_cached_bytes, _dns_cached_tcp, _dns_cached_split = None, None, None
                        _dns_cached_strategy = "tcp_dns_segment"
                        _dns_cached_tcp = TCPDNSSegmentMutator.mutate()
                        _dns_cached_split = random.choice([1, 2, 3, 13, max(1, len(_dns_cached_tcp) // 2)])
                        _dns_is_udp = False

                strategy = _dns_cached_strategy
                fuzzer_state["current_strategy"] = strategy
                fuzzer_state["strategy_stats"][strategy] = fuzzer_state["strategy_stats"].get(strategy, 0) + 1

                if _dns_is_udp:
                    live_transport.send_udp(_dns_cached_bytes, port=31337 if strategy == "back_orifice" else None)
                elif _dns_cached_tcp is not None:
                    if _dns_cached_split is not None:
                        live_transport.send_persistent_tcp(_dns_cached_tcp, split_at=_dns_cached_split)
                    else:
                        live_transport.send_persistent_tcp(_dns_cached_tcp)

            fuzzer_state["last_packet_time"] = time.time()

            active_bandit = _bandit_for(protocol)
            active_bandit.update(strategy, 0.0)

            stat_interval = 500 if protocol in ("dns", "ftp", "http", "smtp", "ssh", "smb2", "smb3", "http2", "dcerpc", "dhcp", "dhcpv6", "snmp", "icmp", "icmpv6", "sip", "mgcp", "radius", "tacacs", "ldap", "cifs", "sunrpc", "telnet", "tftp") else 10000
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
        live_transport.close_persistent_tcp()
        live_transport.close_udp()
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


def _instance_remote_watchdog(monitor, instance):
    """SSH-based watchdog for a FuzzerInstance on a remote FTD host.
    Mirrors _remote_watchdog() but operates on instance.state."""
    state = instance.state
    baseline_mem = None
    for _ in range(5):
        mem = monitor.get_memory_mb()
        if mem is not None:
            baseline_mem = mem
            state["baseline_mem_mb"] = round(mem, 2)
            state["peak_mem_mb"] = round(mem, 2)
            instance.log_event("INFO", f"Remote watchdog baseline: {mem:.2f} MB on {monitor.host}")
            break
        time.sleep(1.0)

    if baseline_mem is None:
        instance.log_event("WARNING", "Could not read remote Snort memory \u2014 process monitoring limited to liveness.")

    consecutive_failures = 0
    max_failures = 3

    while state["running"]:
        time.sleep(2.0)
        alive = monitor.is_alive()

        if alive is True:
            consecutive_failures = 0
        elif alive is None:
            pass
        elif alive is False:
            new_pid = monitor.find_snort_pid()
            if new_pid:
                instance.log_event("INFO",
                    f"Snort PID rotated on {monitor.host}: {monitor.snort_pid} \u2192 {new_pid} (normal FTD behavior)")
                monitor.update_pid(new_pid)
                state["snort_pid"] = new_pid
                consecutive_failures = 0
                baseline_mem = None
                mem = monitor.get_memory_mb()
                if mem is not None:
                    baseline_mem = mem
                    state["baseline_mem_mb"] = round(mem, 2)
                continue

            consecutive_failures += 1
            instance.log_event("WARNING",
                f"Snort PID {monitor.snort_pid} not found on {monitor.host} "
                f"({consecutive_failures}/{max_failures} before crash declaration)")
            if consecutive_failures >= max_failures:
                state["anomaly_detected"] = "REMOTE_SNORT_CRASH"
                state["status"] = "crash_detected"
                state["trigger_detail"] = (
                    f"Snort PID {monitor.snort_pid} on {monitor.host} not found after "
                    f"{max_failures} consecutive checks. No snort3 process found \u2014 likely crashed."
                )
                state["running"] = False
                instance.log_event("CRITICAL", f"Remote Snort crash on {monitor.host} (PID {monitor.snort_pid}) \u2014 confirmed after {max_failures} checks")
                break

        mem = monitor.get_memory_mb()
        if mem is not None:
            state["current_mem_mb"] = round(mem, 2)
            if mem > (state.get("peak_mem_mb") or 0):
                state["peak_mem_mb"] = round(mem, 2)
            if baseline_mem and (mem - baseline_mem) > 4096.0:
                state["anomaly_detected"] = "REMOTE_MEMORY_LEAK"
                state["status"] = "crash_detected"
                state["running"] = False
                instance.log_event("CRITICAL", f"Remote memory bloat: +{mem - baseline_mem:.2f} MB")
                break

    monitor.close()


def _run_instance_mp(protocol, config, weights_dict, shared_state, stop_event):
    """multiprocessing.Process target — runs the fuzzer in its own OS process."""
    inst = FuzzerInstance(protocol=protocol, config=config)
    inst.weights = weights_dict

    def _sync(local_state, local_events):
        snap = dict(local_state)
        snap["_bandit_stats"] = inst.bandit.get_stats(
            base_weights=inst.weights.get(protocol, {}))
        snap["_events_snapshot"] = list(local_events[-20:])
        try:
            shared_state.update(snap)
        except Exception:
            pass

    try:
        run_instance_live(inst, _sync_fn=_sync, _stop_check=stop_event.is_set)
    except Exception as exc:
        inst.log_event("ERROR", f"Fuzzer crashed: {exc}")
        inst.state["status"] = "error"
        inst.state["running"] = False
    finally:
        _sync(inst.state, inst.event_log)


def run_instance_live(instance, _sync_fn=None, _stop_check=None):
    """Live-mode fuzzer loop for a FuzzerInstance. Mirrors run_fuzzer_live but
    reads/writes instance.state instead of the global fuzzer_state.
    Optional _sync_fn(state, events) syncs local state to a Manager proxy.
    Optional _stop_check() returns True when an external stop is requested."""
    from monitor.remote_monitor import RemoteSnortMonitor

    config = instance.config
    server_ip = config.get("server_ip", "127.0.0.1")
    server_port = int(config.get("server_port", 53))
    interface = config.get("interface") or None
    ftd_ip = config.get("ftd_ip") or None
    ftd_user = config.get("ftd_user", "admin")
    ftd_pass = config.get("ftd_pass", "")
    ftd_ssh_port = int(config.get("ftd_ssh_port", 22))
    snort_pid = config.get("snort_pid")
    mem_pressure = config.get("mem_pressure", False)

    state = instance.state
    protocol = instance.protocol
    bandit = instance.bandit
    weights = instance.weights
    live_transport = LiveNetworkTransport(server_ip, server_port, interface,
                                         mem_pressure=mem_pressure)
    instance.transport = live_transport

    if protocol == "ftp":
        ftp_mutator_inst = FtpMutator(external_weights=weights.get("ftp"), bandit=bandit)
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        seed_message = None
    elif protocol == "http":
        ftp_mutator_inst = None
        http_mutator_inst = HttpMutator(external_weights=weights.get("http"), bandit=bandit)
        smtp_mutator_inst = None
        smb_mutator_inst = None
        seed_message = None
    elif protocol == "smtp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = SmtpMutator(external_weights=weights.get("smtp"), bandit=bandit)
        smb_mutator_inst = None
        seed_message = None
    elif protocol == "ssh":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        ssh_mutator_inst = SshMutator(external_weights=weights.get("ssh"), bandit=bandit)
        smb_mutator_inst = None
        seed_message = None
    elif protocol == "smb2":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = Smb2Mutator(external_weights=weights.get("smb2"), bandit=bandit)
        seed_message = None
    elif protocol == "smb3":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = Smb3Mutator(external_weights=weights.get("smb3"), bandit=bandit)
        http2_mutator_inst = None
        seed_message = None
    elif protocol == "http2":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        http2_mutator_inst = Http2Mutator(external_weights=weights.get("http2"), bandit=bandit)
        seed_message = None
    elif protocol == "dcerpc":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        dcerpc_mutator_inst = DcerpcMutator(external_weights=weights.get("dcerpc"), bandit=bandit)
        seed_message = None
    elif protocol == "dhcp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        dhcp_mutator_inst = DhcpMutator(external_weights=weights.get("dhcp"), bandit=bandit)
        seed_message = None
    elif protocol == "dhcpv6":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        dhcpv6_mutator_inst = Dhcpv6Mutator(external_weights=weights.get("dhcpv6"), bandit=bandit)
        seed_message = None
    elif protocol == "snmp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        snmp_mutator_inst = SnmpMutator(external_weights=weights.get("snmp"), bandit=bandit)
        seed_message = None
    elif protocol == "icmp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        icmp_mutator_inst = IcmpMutator(external_weights=weights.get("icmp"), bandit=bandit)
        seed_message = None
    elif protocol == "icmpv6":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        icmpv6_mutator_inst = Icmpv6Mutator(external_weights=weights.get("icmpv6"), bandit=bandit)
        seed_message = None
    elif protocol == "sip":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        sip_mutator_inst = SipMutator(external_weights=weights.get("sip"), bandit=bandit)
        seed_message = None
    elif protocol == "mgcp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        mgcp_mutator_inst = MgcpMutator(external_weights=weights.get("mgcp"), bandit=bandit)
        seed_message = None
    elif protocol == "rtsp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        rtsp_mutator_inst = RtspMutator(external_weights=weights.get("rtsp"), bandit=bandit)
        seed_message = None
    elif protocol == "radius":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        radius_mutator_inst = RadiusMutator(external_weights=weights.get("radius"), bandit=bandit)
        seed_message = None
    elif protocol == "tacacs":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        tacacs_mutator_inst = TacacsMutator(external_weights=weights.get("tacacs"), bandit=bandit)
        seed_message = None
    elif protocol == "ldap":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        ldap_mutator_inst = LdapMutator(external_weights=weights.get("ldap"), bandit=bandit)
        seed_message = None
    elif protocol == "cifs":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        cifs_mutator_inst = CifsMutator(external_weights=weights.get("cifs"), bandit=bandit)
        seed_message = None
    elif protocol == "sunrpc":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        sunrpc_mutator_inst = SunrpcMutator(external_weights=weights.get("sunrpc"), bandit=bandit)
        seed_message = None
    elif protocol == "telnet":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        telnet_mutator_inst = TelnetMutator(external_weights=weights.get("telnet"), bandit=bandit)
        seed_message = None
    elif protocol == "tftp":
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        tftp_mutator_inst = TftpMutator(external_weights=weights.get("tftp"), bandit=bandit)
        seed_message = None
    else:
        ftp_mutator_inst = None
        http_mutator_inst = None
        smtp_mutator_inst = None
        smb_mutator_inst = None
        seed_question = DNSQuestion(qname="example.com")
        seed_message = DNSMessage(header=DNSHeader(), questions=[seed_question])

    state["start_time"] = time.time()
    state["status"] = "running"
    state["running"] = True
    iface_label = interface or "default route"
    instance.log_event("INFO", f"Live fuzzer started \u2192 {server_ip}:{server_port} via {iface_label} ({protocol.upper()})")
    instance.log_event("INFO", "Live TCP delivery mode: persistent sockets with reconnect-on-close.")
    print(f"[+] [{instance.id}] Live network fuzzer \u2192 {server_ip}:{server_port} (iface: {iface_label})")

    if ftd_ip and snort_pid:
        snort_pid = int(snort_pid)
        state["snort_pid"] = snort_pid
        monitor = RemoteSnortMonitor(ftd_ip, snort_pid, ftd_user, ftd_pass, ftd_ssh_port)
        if monitor.connect():
            instance.log_event("INFO", f"SSH monitor connected to {ftd_ip} \u2014 watching PID {snort_pid}")
            print(f"[+] [{instance.id}] Remote Snort monitor active: {ftd_ip} PID {snort_pid}")
            wdog = threading.Thread(target=_instance_remote_watchdog, args=(monitor, instance), daemon=True)
            wdog.start()
            instance.watchdog_thread = wdog
        else:
            instance.log_event("WARNING", f"SSH to {ftd_ip} failed \u2014 running without remote monitoring")
            monitor = None
    else:
        monitor = None
        instance.log_event("WARNING", "No FTD IP / Snort PID provided \u2014 fire-and-forget mode (no health tracking)")

    _ftp_payload, _ftp_strategy = None, None
    _http_payload, _http_strategy = None, None
    _smtp_payload, _smtp_strategy = None, None
    _ssh_payload, _ssh_strategy = None, None
    _smb_payload, _smb_strategy = None, None
    _h2_payload, _h2_strategy = None, None
    _dcerpc_payload, _dcerpc_strategy = None, None
    _dhcp_payload, _dhcp_strategy, _dhcp_dst_port = None, None, None
    _dhcpv6_payload, _dhcpv6_strategy, _dhcpv6_dst_port = None, None, None
    _snmp_payload, _snmp_strategy, _snmp_dst_port = None, None, None
    _icmp_data, _icmp_strategy, _icmp_pkt_type = None, None, None
    _v6_data, _v6_strategy, _v6_pkt_type, _v6_src, _v6_dst = None, None, None, None, None
    _sip_payload, _sip_strategy, _sip_dst_port = None, None, None
    _rtsp_payload, _rtsp_strategy, _rtsp_dst_port = None, None, None
    _radius_payload, _radius_strategy, _radius_dst_port = None, None, None
    _tacacs_payload, _tacacs_strategy, _tacacs_dst_port = None, None, None
    _ldap_payload, _ldap_strategy, _ldap_dst_port = None, None, None
    _telnet_payload, _telnet_strategy, _telnet_dst_port = None, None, None
    _dns_cached_bytes, _dns_cached_tcp, _dns_cached_split, _dns_cached_strategy = None, None, None, None
    _dns_is_udp = True

    _mp_last_sync = time.time()

    try:
        while state["running"] and not state["anomaly_detected"]:
            if _stop_check and _stop_check():
                state["running"] = False
                break

            state["iteration"] += 1
            iteration = state["iteration"]

            if protocol == "ftp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _ftp_payload, _ftp_strategy = ftp_mutator_inst.mutate()
                strategy = _ftp_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_ftp_payload)
                state["iteration"] += 1
            elif protocol == "http":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _http_payload, _http_strategy = http_mutator_inst.mutate()
                strategy = _http_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_http_payload, port=80)
                state["iteration"] += 1
            elif protocol == "smtp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _smtp_payload, _smtp_strategy = smtp_mutator_inst.mutate()
                strategy = _smtp_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_smtp_payload, port=25)
                state["iteration"] += 1
            elif protocol == "ssh":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _ssh_payload, _ssh_strategy = ssh_mutator_inst.mutate()
                strategy = _ssh_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_ssh_payload, port=22)
                state["iteration"] += 1
            elif protocol in ("smb2", "smb3"):
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _smb_payload, _smb_strategy = smb_mutator_inst.mutate()
                strategy = _smb_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_smb_payload, port=445)
                state["iteration"] += 1
            elif protocol == "http2":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _h2_payload, _h2_strategy = http2_mutator_inst.mutate()
                strategy = _h2_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_h2_payload, port=80)
                state["iteration"] += 1
            elif protocol == "dcerpc":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _dcerpc_payload, _dcerpc_strategy = dcerpc_mutator_inst.mutate()
                strategy = _dcerpc_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_dcerpc_payload, port=135)
                state["iteration"] += 1
            elif protocol == "dhcp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _dhcp_payload, _dhcp_strategy, _dhcp_dst_port = dhcp_mutator_inst.mutate()
                strategy = _dhcp_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_dhcp_payload, port=_dhcp_dst_port)
                state["iteration"] += 1
            elif protocol == "dhcpv6":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _dhcpv6_payload, _dhcpv6_strategy, _dhcpv6_dst_port = dhcpv6_mutator_inst.mutate()
                strategy = _dhcpv6_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_dhcpv6_payload, port=_dhcpv6_dst_port)
                state["iteration"] += 1
            elif protocol == "snmp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _snmp_payload, _snmp_strategy, _snmp_dst_port = snmp_mutator_inst.mutate()
                strategy = _snmp_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_snmp_payload, port=_snmp_dst_port)
                state["iteration"] += 1
            elif protocol == "icmp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _icmp_data, _icmp_strategy, _icmp_pkt_type = icmp_mutator_inst.mutate()
                strategy = _icmp_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                if _icmp_pkt_type in ("icmp", "raw_ip"):
                    live_transport.send_icmp(_icmp_data)
                else:
                    for frag_data, frag_off, frag_mf, frag_id, frag_proto in _icmp_data:
                        live_transport.send_icmp(frag_data)
                state["iteration"] += 1
            elif protocol == "icmpv6":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _v6_data, _v6_strategy, _v6_pkt_type, _v6_src, _v6_dst = icmpv6_mutator_inst.mutate()
                strategy = _v6_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                if _v6_pkt_type == "icmpv6":
                    live_transport.send_icmpv6(_v6_data, dst_ipv6=server_ip)
                elif _v6_pkt_type == "fragments":
                    for frag_pkt in _v6_data:
                        live_transport.send_icmpv6(frag_pkt, dst_ipv6=server_ip)
                else:
                    live_transport.send_icmpv6(_v6_data, dst_ipv6=server_ip)
                state["iteration"] += 1
            elif protocol == "sip":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _sip_payload, _sip_strategy, _sip_dst_port = sip_mutator_inst.mutate()
                strategy = _sip_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_sip_payload, port=_sip_dst_port)
                state["iteration"] += 1
            elif protocol == "mgcp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _mgcp_payload, _mgcp_strategy, _mgcp_dst_port = mgcp_mutator_inst.mutate()
                strategy = _mgcp_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_mgcp_payload, port=_mgcp_dst_port)
                state["iteration"] += 1
            elif protocol == "rtsp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _rtsp_payload, _rtsp_strategy, _rtsp_dst_port = rtsp_mutator_inst.mutate()
                strategy = _rtsp_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_rtsp_payload, port=_rtsp_dst_port)
                state["iteration"] += 1
            elif protocol == "radius":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _radius_payload, _radius_strategy, _radius_dst_port = radius_mutator_inst.mutate()
                strategy = _radius_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_radius_payload, port=_radius_dst_port)
                state["iteration"] += 1
            elif protocol == "tacacs":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _tacacs_payload, _tacacs_strategy, _tacacs_dst_port = tacacs_mutator_inst.mutate()
                strategy = _tacacs_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_tacacs_payload, port=_tacacs_dst_port)
                state["iteration"] += 1
            elif protocol == "ldap":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _ldap_payload, _ldap_strategy, _ldap_dst_port = ldap_mutator_inst.mutate()
                strategy = _ldap_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_ldap_payload, port=_ldap_dst_port)
                state["iteration"] += 1
            elif protocol == "cifs":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _cifs_payload, _cifs_strategy, _cifs_dst_port = cifs_mutator_inst.mutate()
                strategy = _cifs_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_cifs_payload, port=_cifs_dst_port)
                state["iteration"] += 1
            elif protocol == "sunrpc":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _sunrpc_payload, _sunrpc_strategy, _sunrpc_dst_port = sunrpc_mutator_inst.mutate()
                strategy = _sunrpc_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                _tcp_strats = ("record_marking_abuse", "tcp_segmentation_evasion",
                               "nfs_compound_overflow")
                if strategy in _tcp_strats:
                    live_transport.send_persistent_tcp(_sunrpc_payload, port=_sunrpc_dst_port)
                else:
                    live_transport.send_udp(_sunrpc_payload, port=_sunrpc_dst_port)
                state["iteration"] += 1
            elif protocol == "telnet":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _telnet_payload, _telnet_strategy, _telnet_dst_port = telnet_mutator_inst.mutate()
                strategy = _telnet_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_persistent_tcp(_telnet_payload, port=_telnet_dst_port)
                state["iteration"] += 1
            elif protocol == "tftp":
                if iteration == 1 or (iteration - 1) % 50 == 0:
                    _tftp_payload, _tftp_strategy, _tftp_dst_port = tftp_mutator_inst.mutate()
                strategy = _tftp_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1
                live_transport.send_udp(_tftp_payload, port=_tftp_dst_port)
                state["iteration"] += 1
            else:
                _dns_cache_interval = 200 if mem_pressure else 50
                if iteration == 1 or (iteration - 1) % _dns_cache_interval == 0:
                    dns_w = weights.get("dns", {})
                    if mem_pressure:
                        _dns_cached_strategy = random.choice(_MEM_PRESSURE_STRATEGIES["dns"])
                    else:
                        _dns_cached_strategy = bandit.select_with_weights(dns_w)
                    if _dns_cached_strategy == "back_orifice":
                        _dns_cached_bytes = BackOrificeMutator.mutate()
                        _dns_cached_tcp, _dns_cached_split = None, None
                        _dns_is_udp = True
                    elif _dns_cached_strategy == "dce_smb":
                        _dns_cached_tcp = DCESmbMutator.mutate()
                        _dns_cached_bytes, _dns_cached_split = None, None
                        _dns_is_udp = False
                    else:
                        _dns_cached_bytes, _dns_cached_tcp, _dns_cached_split = _build_dns_mutation(_dns_cached_strategy, seed_message)
                        _dns_is_udp = _dns_cached_bytes is not None

                    if mem_pressure and _dns_is_udp:
                        _dns_cached_bytes, _dns_cached_tcp, _dns_cached_split = None, None, None
                        _dns_cached_strategy = "tcp_dns_segment"
                        _dns_cached_tcp = TCPDNSSegmentMutator.mutate()
                        _dns_cached_split = random.choice([1, 2, 3, 13, max(1, len(_dns_cached_tcp) // 2)])
                        _dns_is_udp = False

                strategy = _dns_cached_strategy
                state["current_strategy"] = strategy
                state["strategy_stats"][strategy] = state["strategy_stats"].get(strategy, 0) + 1

                if _dns_is_udp:
                    live_transport.send_udp(_dns_cached_bytes, port=31337 if strategy == "back_orifice" else None)
                elif _dns_cached_tcp is not None:
                    if _dns_cached_split is not None:
                        live_transport.send_persistent_tcp(_dns_cached_tcp, split_at=_dns_cached_split)
                    else:
                        live_transport.send_persistent_tcp(_dns_cached_tcp)

            state["last_packet_time"] = time.time()

            bandit.update(strategy, 0.0)

            stat_interval = 500 if protocol in ("dns", "ftp", "http", "smtp", "ssh", "smb2", "smb3", "http2", "dcerpc", "dhcp", "dhcpv6", "snmp", "icmp", "icmpv6", "sip", "mgcp", "radius", "tacacs", "ldap", "cifs", "sunrpc", "telnet", "tftp") else 10000

            _now = time.time()
            _iter_sync = state["iteration"] % stat_interval == 0
            _time_sync = _sync_fn and (_now - _mp_last_sync >= 0.5)

            if _iter_sync or _time_sync:
                elapsed = _now - state["start_time"] if state["start_time"] else 1
                state["packets_per_sec"] = int(state["iteration"] / max(elapsed, 0.001))
                state["_frozen_elapsed"] = elapsed
                if _iter_sync:
                    status = "ANOMALY" if state["anomaly_detected"] else "Secure"
                    print(f"[*] [{instance.id}] Sent {iteration} live mutations... (Target Status: {status})")
                if _sync_fn:
                    _sync_fn(state, instance.event_log)
                    _mp_last_sync = _now

    except KeyboardInterrupt:
        instance.log_event("WARNING", f"Live fuzzer halted manually at iteration {state['iteration']}")
        print(f"\n[*] [{instance.id}] Live fuzzer halted. Total packets sent: {state['iteration']}")

    except Exception as e:
        instance.log_event("ERROR", f"Live fuzzer error: {e}")
        print(f"\n[!] [{instance.id}] Live fuzzer error: {e}")

    finally:
        live_transport.close_persistent_tcp()
        live_transport.close_udp()
        state["running"] = False
        state["status"] = "stopped" if not state["anomaly_detected"] else "crash_detected"
        if state.get("anomaly_detected"):
            bandit.update(state.get("current_strategy", ""), 1.0)
            instance.save_crash_log(
                state["iteration"],
                b"",
                anomaly_type=state["anomaly_detected"],
                return_code=None,
            )
        instance.log_event("INFO", "Live network fuzzer stopped.")
        if _sync_fn:
            _sync_fn(state, instance.event_log)


if __name__ == "__main__":
    SNORT_BUILD = "/Users/soghatak/snort3/build"
    LIVE_MODE = False

    if LIVE_MODE:
        run_fuzzer_live(SNORT_BUILD)
    else:
        run_fuzzer(SNORT_BUILD)