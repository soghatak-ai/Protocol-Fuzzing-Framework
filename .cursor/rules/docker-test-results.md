---
description: Docker test environment topology, test results, and Snort behavior notes
globs: "**/*.py,**/*.yml,**/*.html"
alwaysApply: false
---

# Docker Test Environment & Snort Behavior

## Network Topology
- **kali_attacker** (172.20.0.2) → attacker_net (172.20.0.0/24)
- **snort_firewall** (172.20.0.254 / 172.21.0.254) → bridges both networks, Snort3 inline on eth1
- **target_server** (172.21.0.2) → target_net (172.21.0.0/24)
- **vuln_ids_target** (172.20.0.100) → attacker_net (direct, no Snort)

## Snort Configuration
- Snort3 runs on `eth1` (target_net side) with `-A fast -k none -D`
- DCE/SMB inspectors are enabled in `snort.lua`: `dce_smb`, `dce_tcp`, `dce_udp`, `dce_http_proxy`, `dce_http_server`
- Service bindings: `netbios-ssn` → `dce_smb`, `dcerpc` (tcp/udp) → `dce_tcp`/`dce_udp`
- **No detection rules (.rules files) are loaded** — Snort processes traffic through preprocessors but fires zero alerts
- Traffic flows: kali→eth0(fw)→eth1(fw)→target. Snort sees traffic on eth1 (verified via tcpdump on `any`).

## SMB Trigger Packet Test Results (Jun 24, 2026)
- 6 LLM-generated SMB_COM_WRITE / WRITE_ANDX packets targeting `DCE2_BufferAddData` integer overflow
- All packets have correct SMB1 preamble: NetBIOS session header (00 00 xx xx) + `\xffSMB` magic
- All 6 packets successfully sent through Snort to target on port 445 (TCP handshake completes, payload delivered)
- Target needs a TCP listener on port 445 (no native SMB service) — use `python3 socket server` or `nc -l -p 445`
- Snort stayed alive after 5000-packet flood at 154K pps (persistent TCP, zero errors)
- Snort memory grew from 46MB → 62MB RSS during flood — confirms DCE2 reassembly buffer is accumulating data
- No crash, no core dumps, no OOM after 5000 packets
- The real integer overflow (DCE2_BufferAddData) requires pushing the buffer past UINT32_MAX (~4GB of segment data) — needs sustained long-duration flood

## Key Reminders
- Always start a TCP listener on the target before sending TCP-based trigger packets
- Port 445 is not natively open on the target container (plain Ubuntu)
- Snort processes SMB traffic silently with no rules — absence of alerts does NOT mean Snort isn't parsing
- For persistent TCP flood testing, use continuous flood mode with 0ms delay
