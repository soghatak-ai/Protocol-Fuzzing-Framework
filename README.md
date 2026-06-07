# Protocol Fuzzing Framework

An AI-driven, multi-protocol fuzzer with a **5-phase agentic analysis pipeline**, **reinforcement learning (UCB1 bandit)**, and **Dockerized network topology** designed to uncover memory corruption, logical vulnerabilities, algorithmic complexity bugs, and IDS evasion in deep packet inspection engines like Snort 3.

**8 protocols | 100+ mutation strategies | 500+ internal variants | AI-tuned weights | Real-time RL adaptation**

> **Validated on Snort 3:** Full analysis of 2,051 source files → 18,065 AST chunks → 188 explorer tasks → **306 unique vulnerabilities** and **3,295 protocol constants** extracted in a single run.

## Key Features

### Multi-Protocol Fuzzing Engine

| Protocol | Port | Strategies | Description |
|----------|------|------------|-------------|
| **DNS** | 53 | 15 | Smart DNS, response fuzz, compression loop, label complexity, EDNS exploit, TCP DNS segment, TXT RDATA bomb, TCP two-message, IP defrag, Back Orifice, DCE/SMB, inspector stress, DNSSEC exploit, dynamic update, multi-query storm |
| **FTP** | 21 | 12 | CMD overflow, PORT bomb, pipelined auth, CWD depth, EPSV/EPRT mix, stray commands, boundary PORT, oversized SITE, encoding attack, REST overflow, data channel confusion, FEAT negotiate |
| **HTTP** | 80 | 25 | 14 request-side (method overflow, header bomb, chunked confusion, request smuggling, URI evasion, pipeline flood, etc.) + 11 response-side (HTTP/0.9, deflate ambiguity, chunked tricks, double encoding, gzip quirks, whitespace evasion, NUL injection, etc.) |
| **SMTP** | 25 | 14 | CMD overflow, header overflow, MIME decode bomb, MIME boundary confusion, DATA desync, state machine violation, pipeline flood, RCPT bomb, XLINK2STATE, BDAT chunk, AUTH overflow, STARTTLS evasion, encoding attack, command fuzz |
| **SMB2** | 445 | 13 | Negotiate confusion, header manipulation, compound abuse, NetBIOS desync, session state attack, tree path overflow, create fuzz, read/write overflow, DCE pipe attack, IOCTL attack, oplock/lease flood, multi-protocol evasion, query info overflow |
| **SMB3** | 445 | 5 | Negotiate confusion, signing evasion, transform header attack, compression attack, multi-protocol evasion |
| **HTTP/2** | 80 | 14 | HPACK state desync, CONTINUATION flood, stream interleave evasion, SETTINGS manipulation, pseudo-header smuggling, unknown frame injection, flow control evasion, GOAWAY desync, priority tree attack, PUSH_PROMISE confusion, DATA padding evasion, RST_STREAM race, preface manipulation, header block fragmentation |
| **DCE/RPC** | 135 | 14 | BIND flood, fragment reassembly attack, PTYPE confusion, auth verifier overflow, context negotiation abuse, stub data overflow, ALTER_CONTEXT race, CL header manipulation, endian/DREP confusion, opnum dispatch fuzz, cancel/orphan attack, record marking desync, multi-BIND/ACK confusion, UUID manipulation |

Each strategy contains **3-7 internal variants** randomly selected at runtime, producing diverse payloads across runs.

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

### File Send Feature

Send files as properly framed protocol traffic to a target — useful for delivering crafted payloads through Snort for rule testing:

- **HTTP** — Configurable method (GET/POST/PUT) and path
- **FTP** — User/pass authentication, optional directory
- **SMTP** — Full envelope (FROM/TO/SUBJECT), optional AUTH
- **SMB2/SMB3** — Share path, user/pass
- **HTTP/2** — Binary h2c framing (connection preface + SETTINGS + HEADERS + DATA)
- **DCE/RPC** — Binary CO framing (BIND + REQUEST with file as stub data)

Supports both single-shot (`/api/filesend/send`) and streaming (`/api/filesend/stream`) with real-time TX/RX packet visualization.

### Additional Features

- **Dockerized Network Topology** — Multi-container lab with isolated attacker, firewall (Snort 3 inline via NFQ DAQ), and target networks
- **Multi-Layer Crash Detection:**
  - **Local Watchdog** — `psutil`-based PID monitoring with hang detection (packet silence >3s) and memory bloat tracking (>4 GB RSS growth)
  - **Remote Watchdog** — SSH-based process monitoring via `paramiko` for targets on remote hosts
  - **ServerOracle** — Subprocess health check for locally launched targets
- **Real-Time Web Dashboard** — Live strategy distribution with Original, Applied, RL, and Actual weight columns; SSE event stream; per-protocol AI weight comparison
- **Dynamic Dictionary** — Protocol constants (magic bytes, buffer sizes, commands) extracted from target source code and injected into mutation strategies at runtime
- **Conversation History** — MongoDB-backed analysis history with AI chat for follow-up questions about vulnerabilities
- **Automated Crash Reporting** — Extracts ASan stack traces, logs exact iteration and strategy that triggered the failure
- **Dual Delivery Modes:**
  - **PCAP Pipe Mode:** Synthetic Ethernet/IP/TCP headers streamed via POSIX named pipe
  - **Live Mode:** TCP/UDP datagrams over the network with a pre-bound socket pool
- **Standalone AI Analyzer** — Gemini-powered secondary analyzer (`ai_analyzer.py`) with its own web UI

## Architecture

```
protocol-fuzzer/
├── app.py                      # Flask server — dashboard, SSE stream, AI pipelines, 30+ API endpoints
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
│   ├── smb.py                  # SMB2 (13 strategies) + SMB3 (5 strategies) mutation engine
│   ├── http2.py                # HTTP/2 mutation engine (14 strategies, binary frame crafting)
│   ├── dcerpc.py               # DCE/RPC mutation engine (14 strategies, CO/CL PDU crafting)
│   ├── exploit_packets.py      # Exploit packet builders (Back Orifice, DCE/SMB)
│   └── dynamic_data.py         # Dynamic dictionary loader (runtime constant injection)
├── transport/
│   ├── network.py              # PCAP pipe (StreamTransport) + live TCP/UDP (LiveNetworkTransport)
│   └── file_sender.py          # File-as-packet senders (HTTP, FTP, SMTP, SMB, HTTP/2, DCE/RPC)
├── monitor/
│   ├── oracle.py               # ServerOracle — subprocess health check
│   └── remote_monitor.py       # SSH-based remote process monitor (paramiko)
├── corpus/
│   └── seed_generator.py       # Seed corpus generation
├── docker-compose.yml          # Multi-container lab topology
├── Dockerfile.firewall         # Snort 3 firewall container build (NFQ DAQ, inline mode)
├── crashes/                    # Auto-generated crash reports
├── dynamic_dictionary.json     # Extracted protocol constants from analysis
├── requirements.txt            # Python dependencies
└── .env                        # API keys and config (not committed)
```

## Docker Network Topology

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

1. **Configure** — Select protocol (DNS / FTP / HTTP / SMTP / SMB2 / SMB3 / HTTP/2 / DCE/RPC), delivery mode (Pipe / Live), target IP and port
2. **Upload Source Code** — Go to the AI Analysis tab, upload source files from the target IDS
3. **Analyze** — Run the 5-phase agentic pipeline (semantic graph → orchestrator → explorers → synthesizer → weights)
4. **Apply Weights** — Review discovered vulnerabilities, then apply AI-tuned strategy weights
5. **Fuzz** — Start the fuzzer with optimized mutation weights
6. **Monitor** — Watch real-time strategy distribution, RL adjustments, packet counts, crash/hang detection
7. **File Send** — Use the File Send tab to deliver crafted files as properly framed protocol traffic

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
| `/api/crashes` | GET | List crash reports |
| `/api/crashes/<file>` | GET/DELETE | View or delete a crash report |
| `/api/crashes/<file>/download` | GET | Download crash report |
| `/api/filesend/send` | POST | Send files as protocol traffic (single-shot) |
| `/api/filesend/stream` | POST | Send files with real-time TX/RX streaming |
| `/api/ai/upload` | POST | Upload source files for analysis |
| `/api/ai/upload-directory` | POST | Upload an entire local directory |
| `/api/ai/files` | GET | List uploaded files |
| `/api/ai/analyze` | POST | Run 3-pass Gemini analysis (legacy) |
| `/api/ai/analyze-v2` | POST | Run 5-phase agentic pipeline |
| `/api/ai/results` | GET | Get analysis results + pipeline status |
| `/api/ai/weights` | GET | Get current + default weights (all 8 protocols) |
| `/api/ai/apply_weights` | POST | Apply AI-tuned weights to fuzzer |
| `/api/ai/reset_weights` | POST | Reset to default weights |
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
| **RL** | Applied * RL multiplier (normalized) | `engine/bandit.py` |
| **Actual** | Observed distribution (count / total) | Runtime statistics |

## Tech Stack

- **Backend:** Python 3.9+, Flask, SSE
- **AI/ML:** Azure OpenAI (GPT-5), Google Gemini, tree-sitter (8 languages), ChromaDB, tiktoken
- **Resilience:** Chunked orchestration, truncated JSON recovery, ChromaDB index reuse, exponential backoff
- **RL:** UCB1 multi-armed bandit (thread-safe, per-protocol)
- **Networking:** Raw sockets, PCAP pipe, custom packet crafting (binary protocol PDU construction)
- **Monitoring:** psutil, paramiko (SSH)
- **Storage:** MongoDB Atlas (conversations), ChromaDB (embeddings)
- **Infrastructure:** Docker, Docker Compose, Snort 3 (NFQ DAQ inline)
- **Frontend:** HTML/CSS/JS dashboard with real-time SSE updates

## License

MIT
