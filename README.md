# Protocol Fuzzing Framework

An AI-driven protocol fuzzer with a **5-phase agentic analysis pipeline**, **reinforcement learning (UCB1 bandit)**, and **Dockerized network topology** designed to uncover memory corruption, logical vulnerabilities, algorithmic complexity bugs, and state exhaustion in deep packet inspection engines like Snort 3.

## Key Features

- **5-Phase Agentic Analysis Pipeline** — Analyzes uploaded IDS/firewall source code using semantic code understanding to intelligently tune fuzzing weights:
  - **Phase 1 (Semantic Graph):** AST parsing via tree-sitter, chunking, and embedding into ChromaDB vector store
  - **Phase 2 (Orchestrator):** LLM builds a repo map and generates targeted investigation tasks for Explorer agents
  - **Phase 3 (Explorers):** Concurrent LLM agents retrieve relevant code chunks via semantic search and produce vulnerability dossiers
  - **Phase 4 (Synthesizer):** Deterministic Python merges dossiers, deduplicates findings, and extracts protocol constants
  - **Phase 5 (Weight Computation):** Maps vulnerabilities to mutation strategies with severity-based multipliers (critical=5x, high=3x, medium=2x, low=1.5x)
- **Multi-Protocol Support:**
  - **12 DNS Mutation Strategies** — Smart DNS, Response Fuzz, Compression Loop, Label Complexity, EDNS Exploit, TCP DNS Segment, TXT RDATA Bomb, TCP Two-Message, IP Defrag, Back Orifice, DCE/SMB, Inspector Stress
  - **8 FTP Mutation Strategies** — CMD Overflow, PORT Bomb, Pipelined Auth, CWD Depth, EPSV/EPRT Mix, Stray Commands, Boundary PORT, Oversized SITE
  - **HTTP & SMTP** protocol mutation engines
- **Reinforcement Learning (UCB1 Bandit)** — Adjusts AI/default weights in real-time based on observed crashes:
  - Crash-producing strategies boosted (+50% per crash, configurable)
  - Non-productive strategies fade slowly (`decay_rate=0.1`)
  - Multipliers clamped 0.5x-3.0x to prevent starvation
  - Formula: `final_weight = base_weight * rl_multiplier` (normalized)
- **Dockerized Network Topology** — Multi-container lab with isolated attacker, firewall (Snort 3), and target networks
- **Multi-Layer Crash Detection:**
  - **Local Watchdog** — `psutil`-based PID monitoring with hang detection (packet silence >3s) and memory bloat tracking (>4 GB RSS growth)
  - **Remote Watchdog** — SSH-based process monitoring via `paramiko` for targets on remote hosts or private networks
  - **ServerOracle** — Subprocess health check for locally launched targets
- **Real-Time Web Dashboard** — Live strategy distribution with Original, Applied, RL, and Actual weight columns; SSE event stream
- **Standalone AI Analyzer** — Gemini-powered secondary analyzer (`ai_analyzer.py`) with its own web UI
- **Automated Crash Reporting** — Extracts ASan stack traces, logs exact iteration and strategy that triggered the failure
- **Dual Delivery Modes:**
  - **PCAP Pipe Mode:** Synthetic Ethernet/IP/UDP headers streamed via POSIX named pipe
  - **Live Mode:** UDP/TCP datagrams over the network with a pre-bound socket pool
- **Persistent Storage** — MongoDB Atlas for analysis results; ChromaDB for local vector embeddings

## Architecture

```
protocol-fuzzer/
├── app.py                      # Flask server — dashboard, SSE stream, AI pipeline, API endpoints
├── main.py                     # Fuzzer orchestrator — strategy selection, mutation, delivery, watchdog
├── ai_analyzer.py              # Standalone Gemini-powered AI analyzer (port 5001)
├── engine/
│   ├── semantic_search.py      # Phase 1 — AST parsing, chunking, ChromaDB embedding
│   ├── orchestrator.py         # Phase 2 — Repo map building, task generation
│   ├── explorers.py            # Phase 3 — Concurrent LLM explorer agents
│   ├── synthesizer.py          # Phase 4 — Dossier merging, deduplication
│   ├── llm_client.py           # Azure OpenAI / Gemini LLM client
│   ├── code_collector.py       # Source file collection and filtering
│   ├── mutator.py              # DNS mutation engine (12 strategies)
│   └── bandit.py               # UCB1 multi-armed bandit (RL weight adjuster)
├── protocol/
│   ├── dns.py                  # DNS protocol builder and parser
│   ├── ftp.py                  # FTP mutation engine (8 strategies)
│   ├── http.py                 # HTTP mutation engine
│   ├── smtp.py                 # SMTP mutation engine
│   ├── exploit_packets.py      # Exploit packet builders (Back Orifice, DCE/SMB)
│   └── dynamic_data.py         # Dynamic dictionary integration
├── transport/
│   ├── network.py              # PCAP pipe + live UDP/TCP transport
│   └── file_sender.py          # File-based packet delivery
├── monitor/
│   ├── oracle.py               # ServerOracle — subprocess health check
│   └── remote_monitor.py       # SSH-based remote process monitor (paramiko)
├── corpus/
│   └── seed_generator.py       # Seed corpus generation
├── templates/
│   ├── dashboard.html          # Main fuzzer dashboard UI
│   └── ai_dashboard.html       # Standalone AI analyzer UI
├── docker-compose.yml          # Multi-container lab topology
├── Dockerfile.firewall         # Snort 3 firewall container build
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
- **snort_firewall** — Snort 3 compiled from source, inline between attacker and target networks with IP forwarding enabled
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
PORT=5001 python app.py
```

Open `http://localhost:5001` in your browser (port 5000 may conflict with Docker/AirPlay on macOS).

### Workflow

1. **Configure** — Select protocol (DNS/FTP/HTTP/SMTP), delivery mode (Pipe/Live), target IP and port
2. **Upload Source Code** — Go to the AI Analysis tab, upload source files from the target IDS
3. **Analyze** — Run the 5-phase agentic pipeline (semantic graph -> orchestrator -> explorers -> synthesizer -> weights)
4. **Apply Weights** — Review discovered vulnerabilities, then apply AI-tuned strategy weights
5. **Fuzz** — Start the fuzzer with optimized mutation weights
6. **Monitor** — Watch real-time strategy distribution, RL adjustments, packet counts, crash/hang detection

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

### Reinforcement Learning (RL) Layer

```
final_weight = base_weight * rl_multiplier    (normalized to 100%)
```

| Event | Effect on Multiplier |
|-------|---------------------|
| Crash detected | +0.5 per crash (e.g., 1 crash = 1.5x, 3 crashes = 2.5x) |
| No crash, many pulls | Slow fade toward 0.5x minimum |
| Never tried | Stays at 1.0x (no change) |

RL bandits reset automatically when AI weights are applied or reset.

### 5-Phase Agentic Pipeline

| Phase | Component | LLM Calls | Description |
|-------|-----------|-----------|-------------|
| 1 | Semantic Graph | 0 (embedding only) | AST parse, chunk, embed into ChromaDB |
| 2 | Orchestrator | 1 | Repo map + LLM generates investigation tasks |
| 3 | Explorers | N (concurrent) | Each task retrieves chunks via vector search, LLM produces dossier |
| 4 | Synthesizer | 0 | Merges dossiers, deduplicates vulns, extracts constants |
| 5 | Weigher | 0 | Deterministic formula maps vulns to strategy weights |

Supports both **Azure OpenAI** and **Google Gemini** as LLM backends.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/start` | POST | Start fuzzer |
| `/api/stop` | POST | Stop fuzzer |
| `/api/stream` | GET | SSE event stream (real-time stats) |
| `/api/ai/upload` | POST | Upload source files for analysis |
| `/api/ai/upload-directory` | POST | Upload entire directory |
| `/api/ai/analyze` | POST | Run 3-pass analysis (legacy) |
| `/api/ai/analyze-v2` | POST | Run 5-phase agentic pipeline |
| `/api/ai/results` | GET | Get analysis results + pipeline status |
| `/api/ai/weights` | GET | Get current + default weights |
| `/api/ai/apply_weights` | POST | Apply AI-tuned weights to fuzzer |
| `/api/ai/reset_weights` | POST | Reset to default weights |
| `/api/crashes` | GET | List crash reports |

### Strategy Weight Columns (Dashboard)

| Column | Meaning | Source |
|--------|---------|--------|
| **Original** | Default hardcoded weights | `main.py` |
| **Applied** | AI-tuned weights (or defaults if no analysis) | AI pipeline |
| **RL** | Applied * RL multiplier (normalized) | `engine/bandit.py` |
| **Actual** | Observed distribution (count / total) | Runtime statistics |

## Tech Stack

- **Backend:** Python, Flask, SSE
- **AI/ML:** Azure OpenAI, Google Gemini, tree-sitter, ChromaDB, tiktoken
- **RL:** UCB1 multi-armed bandit
- **Networking:** Raw sockets, PCAP pipe, custom packet crafting
- **Monitoring:** psutil, paramiko (SSH)
- **Storage:** MongoDB Atlas, ChromaDB (local)
- **Infrastructure:** Docker, Docker Compose
- **Frontend:** HTML/CSS/JS dashboard with real-time SSE updates

## License

MIT
