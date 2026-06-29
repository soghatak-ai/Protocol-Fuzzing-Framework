# Protocol Fuzzing Framework

An AI-driven, multi-protocol fuzzer with a **5-phase agentic analysis pipeline**, **reinforcement learning (UCB1 bandit)**, **memory depletion attacks**, and **dual deployment** (Docker lab + physical Cisco FTD) designed to uncover memory corruption, logical vulnerabilities, IDS evasion, and inspection bypass in deep packet inspection engines like Snort 3.

**24 protocols | 100+ mutation strategies | 500+ internal variants | AI-tuned weights | Real-time RL adaptation | Live FTD testing**

> **Validated on Cisco FTD (Snort 3):** Full analysis of 2,051 source files → 18,065 AST chunks → 188 explorer tasks → **306 unique vulnerabilities** and **3,295 protocol constants** extracted. **332 evasion tests** yielded a **90.1% evasion rate**. Memory pool exhaustion demonstrated with **168,000+ allocation failures** and a **10-18 KB malware bypass window**.

## Key Features

### Multi-Protocol Fuzzing Engine (24 Protocols)

| Protocol | Port | Transport | Strategies | Description |
|----------|------|-----------|------------|-------------|
| **DNS** | 53 | TCP | 15 | Smart DNS, response fuzz, compression loop, label complexity, EDNS exploit, TCP DNS segment, TXT RDATA bomb, TCP two-message, IP defrag, Back Orifice, DCE/SMB, inspector stress, DNSSEC exploit, dynamic update, multi-query storm |
| **FTP** | 21 | TCP | 12 | CMD overflow, PORT bomb, pipelined auth, CWD depth, EPSV/EPRT mix, stray commands, boundary PORT, oversized SITE, encoding attack, REST overflow, data channel confusion, FEAT negotiate |
| **HTTP** | 80 | TCP | 25 | 14 request-side (method overflow, header bomb, chunked confusion, request smuggling, URI evasion, pipeline flood, etc.) + 11 response-side (HTTP/0.9, deflate ambiguity, chunked tricks, double encoding, gzip quirks, whitespace evasion, NUL injection, etc.) |
| **SMTP** | 25 | TCP | 14 | CMD overflow, header overflow, MIME decode bomb, MIME boundary confusion, DATA desync, state machine violation, pipeline flood, RCPT bomb, XLINK2STATE, BDAT chunk, AUTH overflow, STARTTLS evasion, encoding attack, command fuzz |
| **SSH** | 22 | TCP | — | Protocol version, key exchange, and banner mutation strategies |
| **SMB2** | 445 | TCP | 13 | Negotiate confusion, header manipulation, compound abuse, NetBIOS desync, session state attack, tree path overflow, create fuzz, read/write overflow, DCE pipe attack, IOCTL attack, oplock/lease flood, multi-protocol evasion, query info overflow |
| **SMB3** | 445 | TCP | 5 | Negotiate confusion, signing evasion, transform header attack, compression attack, multi-protocol evasion |
| **HTTP/2** | 80 | TCP | 14 | HPACK state desync, CONTINUATION flood, stream interleave evasion, SETTINGS manipulation, pseudo-header smuggling, unknown frame injection, flow control evasion, GOAWAY desync, priority tree attack, PUSH_PROMISE confusion, DATA padding evasion, RST_STREAM race, preface manipulation, header block fragmentation |
| **DCE/RPC** | 135 | TCP | 14 | BIND flood, fragment reassembly attack, PTYPE confusion, auth verifier overflow, context negotiation abuse, stub data overflow, ALTER_CONTEXT race, CL header manipulation, endian/DREP confusion, opnum dispatch fuzz, cancel/orphan attack, record marking desync, multi-BIND/ACK confusion, UUID manipulation |
| **RTSP** | 554 | TCP | — | RTSP method, header, and session mutation strategies |
| **TACACS+** | 49 | TCP | — | Authentication, authorization, and accounting PDU fuzzing |
| **LDAP** | 389 | TCP | — | LDAP search, bind, and filter mutation strategies |
| **CIFS/SMB1** | 445 | TCP | — | Legacy SMB1 dialect and command fuzzing |
| **Telnet** | 23 | TCP | — | Telnet option negotiation and command mutation |
| **DHCP** | 67 | UDP | — | DHCPv4 discover, offer, request, and option fuzzing |
| **DHCPv6** | 547 | UDP | — | DHCPv6 solicit, advertise, and option mutation |
| **SNMP** | 161 | UDP | — | SNMP v1/v2c/v3 PDU and OID mutation |
| **SIP** | 5060 | UDP | — | SIP INVITE, REGISTER, and header field fuzzing |
| **MGCP** | 2427 | UDP | — | MGCP command and parameter mutation |
| **RADIUS** | 1812 | UDP | — | RADIUS authentication and attribute fuzzing |
| **SUN RPC** | 111 | UDP | — | SUN RPC call and portmap mutation |
| **TFTP** | 69 | UDP | — | TFTP read/write request and option mutation |
| **ICMPv4** | — | ICMP | — | ICMP echo, unreachable, and redirect mutation |
| **ICMPv6** | — | ICMP | — | ICMPv6 echo, neighbor discovery, and router advertisement mutation |

Each strategy contains **3-7 internal variants** randomly selected at runtime, producing diverse payloads across runs.

### Memory Pressure Mode — TCP Reassembly Attack

Forces Snort to hold partial TCP reassembly state across many concurrent streams, exhausting its memory pools:

- **Toggle:** "Force TCP Reassembly" checkbox in live mode
- **60-socket connection pool** per fuzzer instance with staggered segment delivery
- Sends first half of each payload immediately; delays second half by ~60 iterations
- Snort must hold partial reassembly buffers for all ~60 in-flight half-payloads simultaneously
- Each buffer consumes a **2560-byte block** from Snort's finite memory pool (201 slots)
- **Multiple instances** (4-6 DNS) × 60 sockets = 240-360 partial streams → exceeds pool capacity
- `SO_LINGER(0)` on all TCP sockets prevents TIME_WAIT port exhaustion
- `TCP_NODELAY` ensures each `sendall()` becomes a distinct TCP segment

**Demonstrated on Cisco FTD:**
```
show blocks
SIZE    MAX    LOW    CNT  FAILED
2560    201      0      0  168467   ← Pool exhausted, 168K allocations denied
4096    161      0      1    4339
8192    202      0      3     512
```

### Multi-Protocol Attack Engine (Snort Blinder)

Dedicated attack mode that floods all protocol inspectors simultaneously:

- Launches **N parallel processes** across all 24 protocols with configurable intensity (1-5)
- **5 intensity presets** with phased escalation (send delays decrease over time)
- TCP workers use **30-socket persistent pools** with split-segment delivery
- Configurable: duration (up to 3600s), intensity, process count, protocol selection (All/None/UDP/TCP)
- **FTD SSH monitoring:** real-time Snort stats, canary/EICAR detection rate, per-protocol breakdown
- **Staggered process launch** prevents thundering-herd saturation
- Forces Snort to process thousands of concurrent streams across all inspectors simultaneously

### Malware Inspection Bypass (Key Finding)

Demonstrated that Snort memory pool exhaustion creates a **10-18 KB inspection bypass window** on physical Cisco FTD hardware:

| Condition | Behavior |
|-----------|----------|
| **Snort healthy** | Malware download immediately blocked — `Connection reset by peer` (0 bytes) |
| **Snort memory depleted (CNT=0)** | 10-18 KB of malware data transfers uninspected before Snort recovers |
| **Recovery** | Snort recovers in 2-5 seconds, picks up mid-stream inspection, detects malware, sends RST |

The 10-18 KB bypass window is sufficient for real-world initial-stage payloads: reverse shell stagers (1-5 KB), shellcode droppers (2-8 KB), web shells (1-10 KB), and credential harvesters (2-8 KB).

### 5-Phase Agentic AI Analysis Pipeline

Analyzes uploaded IDS/firewall source code using semantic code understanding to intelligently tune fuzzing weights:

| Phase | Component | LLM Calls | Description |
|-------|-----------|-----------|-------------|
| 1 | **Semantic Graph** | 0 (embedding only) | AST parsing via tree-sitter (8 languages), chunking, embedding into ChromaDB vector store |
| 2 | **Orchestrator** | N (chunked) | Splits repo map into ~4K-token chunks, sends each to LLM independently, merges & deduplicates tasks. Handles large codebases (tested: 18K+ symbols) without exceeding context windows |
| 3 | **Explorers** | N (up to 5 concurrent) | Each agent retrieves relevant code chunks via semantic search and produces vulnerability dossiers |
| 4 | **Synthesizer** | 0 | Pure Python — merges dossiers, deduplicates vulns, extracts protocol constants to `dynamic_dictionary.json` |
| 5 | **Weigher** | 0 | Deterministic formula maps vulns to strategy weights with severity multipliers (critical=5x, high=3x, medium=2x, low=1.5x) |

**Resilience features:**
- **Chunked Orchestrator** — Repo map is split into budget-sized chunks (~4K tokens each), sorted by security relevance (highest-scored symbols first). Each chunk generates 3-10 tasks independently, results are merged and deduplicated by search query.
- **Truncated JSON Recovery** — If the LLM hits the completion-token cap (common with reasoning models like GPT-5), the framework recovers complete task/vuln objects from the partial JSON via bracket-balancing and regex extraction.
- **ChromaDB Index Reuse** — Skips re-embedding when the uploaded file set hasn't changed, avoiding unnecessary rate-limit consumption.
- **Rate-Limit Resilience** — Exponential backoff (up to 60s) with 8 retries, 2s courtesy pauses between orchestrator chunks.

Supports both **Azure OpenAI (GPT-5)** and **Google Gemini** as LLM backends.

Legacy 3-pass Gemini pipeline (Hunter → Verifier → Weigher) also available.

### Reinforcement Learning (UCB1 Bandit)

One bandit per protocol, adjusting AI/default weights in real-time based on observed crashes:

```
final_weight = base_weight * rl_multiplier    (normalized to 100%)
```

| Event | Effect on Multiplier |
|-------|---------------------|
| Crash detected | +0.5 per crash (e.g., 1 crash = 1.5x, 3 crashes = 2.5x) |
| No crash, many pulls | Slow fade toward 0.5x minimum |
| Never tried | Stays at 1.0x (no change) |

RL bandits reset automatically when AI weights are applied or reset.

### Evasion Testing Results

332 strategies tested against Snort 3 across 23 protocols:

| Verdict | Count | Percentage |
|---------|-------|------------|
| **EVADED** | 249 | 75.0% |
| **EVADED!** (canary embedded, undetected) | 50 | 15.1% |
| **DETECTED** | 5 | 1.5% |
| **SKIP** | 28 | 8.4% |

**90.1% evasion rate** — Snort failed to detect embedded canary content in 299/304 testable strategies.

### File Send Feature

Send files as properly framed protocol traffic to a target — useful for delivering crafted payloads through Snort for rule testing. Supports all **24 protocols** including:

- **HTTP** — Configurable method (GET/POST/PUT) and path
- **FTP** — User/pass authentication, optional directory
- **SMTP** — Full envelope (FROM/TO/SUBJECT), optional AUTH
- **SMB2/SMB3** — Share path, user/pass
- **HTTP/2** — Binary h2c framing (connection preface + SETTINGS + HEADERS + DATA)
- **DCE/RPC** — Binary CO framing (BIND + REQUEST with file as stub data)
- **DNS, SSH, SIP, SNMP, ICMP, DHCP, RADIUS, TFTP, RTSP, MGCP, TACACS+, LDAP, Telnet, CIFS, SUN RPC, DHCPv6, ICMPv6** — Protocol-appropriate framing

Supports both single-shot (`/api/filesend/send`) and streaming (`/api/filesend/stream`) with real-time TX/RX packet visualization.

### Additional Features

- **Dual Deployment:**
  - **Docker Lab:** Multi-container topology with isolated attacker, firewall (Snort 3 inline via NFQ DAQ), and target networks
  - **Physical FTD:** Live testing against real Cisco Firepower Threat Defense hardware
- **Multi-Layer Crash Detection:**
  - **Local Watchdog** — `psutil`-based PID monitoring with hang detection (packet silence >3s) and memory bloat tracking (>4 GB RSS growth)
  - **Remote Watchdog** — SSH-based process monitoring via `paramiko` for targets on remote hosts
  - **ServerOracle** — Subprocess health check for locally launched targets
- **Real-Time Web Dashboard** — 5 integrated pages with live SSE updates:
  - Dashboard: fuzzer control, protocol selector, stats, strategy distribution
  - AI Analysis: pipeline visualization, vulnerability list, weight management, AI chat
  - Multi-Protocol Attack: protocol grid, live verdict, per-protocol stats
  - File Send: protocol transport config, streaming hex packet viewer
  - Crash Reports: view/download/delete crash reports
- **Multi-Instance Fuzzing** — Run multiple independent fuzzer instances in parallel via `/api/instances` API
- **Custom Payload Mode** — Inject detection strings (e.g., EICAR) into evasion strategies for testing
- **Dynamic Dictionary** — Protocol constants (magic bytes, buffer sizes, commands) extracted from target source code and injected into mutation strategies at runtime
- **Conversation History** — MongoDB-backed analysis history with AI chat for follow-up questions about vulnerabilities
- **Automated Crash Reporting** — Extracts ASan stack traces, logs exact iteration and strategy that triggered the failure
- **Dual Delivery Modes:**
  - **PCAP Pipe Mode:** Synthetic Ethernet/IP/TCP headers streamed via POSIX named pipe
  - **Live Mode:** TCP/UDP datagrams over the network with persistent socket pools
- **Standalone AI Analyzer** — Gemini-powered secondary analyzer (`ai_analyzer.py`) with its own web UI

## Architecture

```
protocol-fuzzer/
├── app.py                      # Flask server — dashboard, SSE stream, AI pipelines, 40+ API endpoints
├── main.py                     # Fuzzer orchestrator — strategy selection, mutation, delivery, watchdog
├── ai_analyzer.py              # Standalone Gemini-powered AI analyzer (port 5001)
├── engine/
│   ├── semantic_search.py      # Phase 1 — AST parsing (tree-sitter), chunking, ChromaDB embedding
│   ├── orchestrator.py         # Phase 2 — Chunked repo map, parallel task generation, dedup
│   ├── explorers.py            # Phases 3 & 4 — Concurrent LLM explorer agents, dossier production
│   ├── synthesizer.py          # Phase 5 — Dossier merging, dedup, dynamic_dictionary.json generation
│   ├── llm_client.py           # Azure OpenAI chat completion wrapper (retry, truncated JSON recovery)
│   ├── code_collector.py       # Source file collection and filtering
│   ├── mutator.py              # DNS mutation engine (15 strategies)
│   └── bandit.py               # UCB1 multi-armed bandit (RL weight adjuster, thread-safe)
├── protocol/
│   ├── dns.py                  # DNS protocol builder and parser
│   ├── ftp.py                  # FTP mutation engine (12 strategies)
│   ├── http.py                 # HTTP mutation engine (25 strategies: 14 request + 11 response)
│   ├── smtp.py                 # SMTP mutation engine (14 strategies)
│   ├── ssh.py                  # SSH protocol mutation engine
│   ├── smb.py                  # SMB2 (13) + SMB3 (5) + CIFS mutation engine
│   ├── http2.py                # HTTP/2 mutation engine (14 strategies, binary frame crafting)
│   ├── dcerpc.py               # DCE/RPC mutation engine (14 strategies, CO/CL PDU crafting)
│   ├── dhcp.py                 # DHCP/DHCPv6 mutation engine
│   ├── snmp.py                 # SNMP mutation engine
│   ├── icmp.py                 # ICMPv4/ICMPv6 mutation engine
│   ├── sip.py                  # SIP mutation engine
│   ├── mgcp.py                 # MGCP mutation engine
│   ├── radius.py               # RADIUS mutation engine
│   ├── rtsp.py                 # RTSP mutation engine
│   ├── tacacs.py               # TACACS+ mutation engine
│   ├── ldap.py                 # LDAP mutation engine
│   ├── telnet.py               # Telnet mutation engine
│   ├── sunrpc.py               # SUN RPC mutation engine
│   ├── tftp.py                 # TFTP mutation engine
│   ├── exploit_packets.py      # Exploit packet builders (Back Orifice, DCE/SMB)
│   └── dynamic_data.py         # Dynamic dictionary loader (runtime constant injection)
├── transport/
│   ├── network.py              # PCAP pipe (StreamTransport) + live TCP/UDP (LiveNetworkTransport)
│   │                           #   Memory pressure mode: 60-socket pool, staggered segments
│   └── file_sender.py          # File-as-packet senders (all 24 protocols)
├── monitor/
│   ├── oracle.py               # ServerOracle — subprocess health check
│   └── remote_monitor.py       # SSH-based remote process monitor (paramiko)
├── Testing/
│   └── snort_blinder.py        # Multi-protocol inspector overload / flood test harness
├── corpus/
│   └── seed_generator.py       # Seed corpus generation
├── docker-compose.yml          # Multi-container lab topology
├── Dockerfile.firewall         # Snort 3 firewall container build (NFQ DAQ, inline mode)
├── crashes/                    # Auto-generated crash reports
├── evasion_results.json        # 332 evasion test results across 23 protocols
├── dynamic_dictionary.json     # Extracted protocol constants from analysis (3,295 constants)
├── requirements.txt            # Python dependencies
└── .env                        # API keys and config (not committed)
```

## Network Topology — Dual Deployment

### Docker Lab (Development)

```
┌──────────────┐     172.20.0.0/24      ┌──────────────────┐     172.21.0.0/24     ┌──────────────┐
│    Kali       │◄──── attacker_net ────►│    Firewall       │◄──── target_net ────►│    Target     │
│  (Attacker)   │     172.20.0.2         │  (Snort 3 IDS)    │     172.21.0.254     │   (Server)    │
│  Port: 5000   │                        │  172.20.0.254     │                      │  Port: 7682   │
└──────────────┘                         │  Port: 7681       │                      └──────────────┘
                                         └──────────────────┘
```

- **kali_attacker** — Ubuntu container running the fuzzer, mounted at `/fuzzer`
- **snort_firewall** — Snort 3 compiled from source, inline (NFQ DAQ, `-Q`) between attacker and target networks with IP forwarding, `checksum_eval = 'none'` for Docker vNIC compatibility
- **target_server** — Ubuntu container running real services (vsftpd, dnsmasq) as the fuzzing endpoint

### Physical FTD (Validation)

```
┌──────────────┐                        ┌──────────────────┐                       ┌──────────────┐
│    Kali       │──────────────────────►│    Cisco FTD       │─────────────────────►│    Target     │
│  (Attacker)   │                        │  Snort 3 Inline   │                      │   (Server)    │
│  192.168.x.x  │                        │  IPS               │                      │ 192.168.42.100│
└──────────────┘                         └──────────────────┘                       └──────────────┘
```

- Real Cisco Firepower Threat Defense appliance with production Snort 3 engine
- Target server running Apache, vsftpd, Samba, dnsmasq — real services on all 24 protocol ports
- All evasion and memory depletion results validated on this physical deployment

## Setup

### Prerequisites

- Python 3.9+
- Docker & Docker Compose (for the lab topology)
- MongoDB Atlas account (for persistent analysis storage)

### Installation

```bash
git clone https://github.com/soghatak-ai/Protocol-Fuzzing-Framework.git
cd Protocol-Fuzzing-Framework
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root:

```env
# LLM Providers
GOOGLE_API_KEY=your-gemini-api-key
AZURE_OPENAI_ENDPOINT=your-azure-endpoint
AZURE_OPENAI_API_KEY=your-azure-key
AZURE_OPENAI_CHAT_DEPLOYMENT=your-chat-deployment
AZURE_OPENAI_EMBEDDING_DEPLOYMENT=your-embedding-deployment

# Embedding (for agentic pipeline)
AZURE_EMBEDDING_ENDPOINT=your-embedding-endpoint
AZURE_EMBEDDING_API_KEY=your-embedding-key

# Database
MONGODB_URI=your-mongodb-atlas-uri
MONGODB_DB=protocol_fuzzer
MONGODB_COLLECTION=analyses
```

All keys are loaded via `python-dotenv` and never hardcoded in source code.

### Start the Docker Lab

```bash
docker-compose up -d
```

This creates the three-container network topology with web terminals accessible at:
- Firewall terminal: `http://localhost:7681`
- Target terminal: `http://localhost:7682`

## Usage

### Start the Dashboard

```bash
python app.py
```

Open `http://localhost:5000` in your browser.

### Workflow

1. **Configure** — Select protocol (24 available), delivery mode (Pipe / Live), target IP and port, enable memory pressure mode
2. **Upload Source Code** — Go to the AI Analysis tab, upload source files from the target IDS
3. **Analyze** — Run the 5-phase agentic pipeline (semantic graph → orchestrator → explorers → synthesizer → weights)
4. **Apply Weights** — Review discovered vulnerabilities, then apply AI-tuned strategy weights
5. **Fuzz** — Start the fuzzer with optimized mutation weights
6. **Monitor** — Watch real-time strategy distribution, RL adjustments, packet counts, crash/hang detection
7. **Multi-Protocol Attack** — Launch the Snort Blinder for concurrent inspector overload testing
8. **File Send** — Use the File Send tab to deliver crafted files as properly framed protocol traffic

### Memory Pressure Attack

To exhaust Snort's memory pools on a live FTD:

1. Start **4-6 DNS instances** with "Force TCP Reassembly" enabled from the dashboard
2. Optionally run a Multi-Protocol Attack for additional pressure
3. Monitor `show blocks` on FTD — watch for CNT dropping to 0 on 2560/4096/8192 byte pools
4. When CNT=0, Snort cannot allocate buffers for new packet inspection

### Crash Detection

The framework supports three monitoring modes depending on deployment:

| Mode | Class | Use Case |
|------|-------|----------|
| **Local** | `watchdog_monitor` (psutil) | Target runs on the same machine as the fuzzer |
| **Remote** | `RemoteSnortMonitor` (SSH) | Target on a remote host in the same private network |
| **Subprocess** | `ServerOracle` (poll) | Target launched as a child process by the fuzzer |

Detectable anomalies:
- **Process crash** — PID vanishes (segfault, abort, kill)
- **Hang** — No packet processing for >3 seconds
- **Memory bloat** — RSS grows >4 GB over baseline

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/start` | POST | Start fuzzer (protocol, mode, live_config) |
| `/api/stop` | POST | Stop fuzzer |
| `/api/stream` | GET | SSE event stream (real-time stats, bandit data) |
| `/api/state` | GET | Current fuzzer state |
| `/api/config` | GET/POST | Get/set live configuration |
| `/api/instances` | GET/POST | List or create fuzzer instances |
| `/api/instances/<id>` | DELETE | Destroy a fuzzer instance |
| `/api/crashes` | GET | List crash reports |
| `/api/crashes/<file>` | GET/DELETE | View or delete a crash report |
| `/api/crashes/<file>/download` | GET | Download crash report |
| `/api/filesend/send` | POST | Send files as protocol traffic (single-shot) |
| `/api/filesend/stream` | POST | Send files with real-time TX/RX streaming |
| `/api/multiattack/start` | POST | Start multi-protocol attack |
| `/api/multiattack/stop` | POST | Stop multi-protocol attack |
| `/api/multiattack/status` | GET | Get attack status and stats |
| `/api/multiattack/protocols` | GET | List available attack protocols |
| `/api/ai/upload` | POST | Upload source files for analysis |
| `/api/ai/upload-directory` | POST | Upload an entire local directory |
| `/api/ai/files` | GET | List uploaded files |
| `/api/ai/analyze` | POST | Run 3-pass Gemini analysis (legacy) |
| `/api/ai/analyze-v2` | POST | Run 5-phase agentic pipeline |
| `/api/ai/results` | GET | Get analysis results + pipeline status |
| `/api/ai/weights` | GET | Get current + default weights (all 24 protocols) |
| `/api/ai/apply_weights` | POST | Apply AI-tuned weights to fuzzer |
| `/api/ai/reset_weights` | POST | Reset to default weights |
| `/api/ai/vulns/<vid>/generate_packets` | POST | LLM-generated trigger packets per vulnerability |
| `/api/ai/history` | GET | List analysis conversations |
| `/api/ai/history/<id>` | GET/DELETE | Get or delete a conversation |
| `/api/ai/chat` | POST | Chat with AI about analysis results |
| `/api/ai/clear` | POST | Clear uploaded files and results |
| `/api/events` | GET | Get recent event log |

### Strategy Weight Columns (Dashboard)

| Column | Meaning | Source |
|--------|---------|--------|
| **Original** | Default hardcoded weights | `main.py` |
| **Applied** | AI-tuned weights (or defaults if no analysis) | AI pipeline |
| **RL** | Applied × RL multiplier (normalized) | `engine/bandit.py` |
| **Actual** | Observed distribution (count / total) | Runtime statistics |

## Key Results

| Metric | Value |
|--------|-------|
| Protocols supported | 24 |
| Mutation strategies | 100+ (500+ internal variants) |
| Evasion tests run | 332 |
| Evasion rate | 90.1% (299/332) |
| EVADED! (canary undetected) | 50 strategies |
| Vulnerabilities discovered | 306 (from AI pipeline) |
| Protocol constants extracted | 3,295 |
| Memory pool failures | 168,000+ (on Cisco FTD) |
| Malware bypass window | 10-18 KB per depletion event |
| Snort recovery time | 2-5 seconds |

## Tech Stack

- **Backend:** Python 3.9+, Flask, SSE, multiprocessing
- **AI/ML:** Azure OpenAI (GPT-5), Google Gemini, tree-sitter (8 languages), ChromaDB, tiktoken
- **Resilience:** Chunked orchestration, truncated JSON recovery, ChromaDB index reuse, exponential backoff
- **RL:** UCB1 multi-armed bandit (thread-safe, per-protocol)
- **Networking:** Raw sockets, PCAP pipe, TCP/UDP persistent pools, `SO_LINGER`, `TCP_NODELAY`, `SO_KEEPALIVE`
- **Protocols:** 24 custom binary PDU constructors (DNS, SMB2/3, HTTP/2, DCE/RPC, SIP, RADIUS, etc.)
- **Monitoring:** psutil (local), paramiko/SSH (remote), subprocess oracle
- **Storage:** MongoDB Atlas (conversations), ChromaDB (embeddings)
- **Infrastructure:** Docker Compose, Snort 3 (NFQ DAQ inline), Cisco FTD (physical)
- **Frontend:** HTML/CSS/JS dashboard with real-time SSE updates, hex packet viewer

## License

MIT
