# Protocol Fuzzing Framework

A high-performance protocol fuzzer with an **AI-driven agentic pipeline** designed to uncover memory corruption, logical vulnerabilities, algorithmic complexity bugs, and state exhaustion in deep packet inspection engines like Snort 3.

## Key Features

- **AI-Powered Agentic Analysis** — A 3-pass pipeline analyzes uploaded IDS source code to intelligently tune fuzzing weights:
  - **Pass 1 (Hunter):** LLM scans source code for all potential vulnerabilities
  - **Pass 2 (Verifier):** LLM reviews each finding, assigns confidence scores, rejects false positives
  - **Pass 3 (Weigher):** Deterministic Python formula computes mutation weights from verified vulnerabilities — no LLM involved, 100% reproducible
- **15 DNS Mutation Strategies** — Smart DNS, Response Fuzz, Compression Loop, Label Complexity, EDNS Exploit, TCP DNS Segment, TXT RDATA Bomb, TCP Two-Message, IP Defrag, Back Orifice, DCE/SMB, Inspector Stress, DNSSEC Exploit, DNS Dynamic Update, Multi-Query Storm
- **12 FTP Mutation Strategies** — CMD Overflow, PORT Bomb, Pipelined Auth, CWD Depth, EPSV/EPRT Mix, Stray Commands, Boundary PORT, Oversized SITE, Encoding Attack, REST Overflow, Data Channel Confusion, FEAT Negotiate
- **Dynamic Weight Adjustment** — AI analysis maps vulnerabilities to mutation strategies and applies severity-based multipliers (critical=5x, high=3x, medium=2x, low=1.5x) scaled by confidence
- **Real-Time Web Dashboard** — Live strategy distribution visualization with original, applied, and actual weight columns; green-to-red gradient bars based on rank
- **Intelligent Watchdog** — Monitors target process RSS memory and processing latency; detects silent hangs and RAM bloat (>4096MB over baseline)
- **Automated Crash Reporting** — Extracts ASan stack traces, dumps diagnostic logs with exact iteration and strategy that caused the failure
- **Dual Delivery Modes:**
  - **PCAP Pipe Mode:** Synthetic Ethernet/IP/UDP headers streamed via POSIX named pipe
  - **Live Mode:** UDP datagrams over loopback with a pre-bound socket pool

## Architecture

```
protocol-fuzzer/
├── app.py                  # Flask server — dashboard, SSE stream, AI pipeline endpoints
├── main.py                 # Fuzzer orchestrator — strategy selection, mutation, delivery
├── ai_analyzer.py          # Standalone AI analyzer (port 5001)
├── engine/
│   ├── mutator.py          # DNS mutation engine (15 strategies)
│   └── seed.py             # Seed generation
├── protocol/
│   ├── ftp.py              # FTP mutation engine (12 strategies)
│   └── exploit_packets.py  # Exploit packet builders
├── transport/
│   └── network.py          # PCAP pipe + live UDP transport
├── monitor/
│   ├── watchdog.py         # Process monitoring + crash detection
│   └── remote_monitor.py   # Remote monitoring
├── templates/
│   ├── dashboard.html      # Main fuzzer dashboard UI
│   └── ai_dashboard.html   # Standalone AI analyzer UI
├── crashes/                # Auto-generated crash reports
├── test_weights.py         # Weight pipeline verification tests
└── .env                    # API keys (not committed)
```

## Setup

### Prerequisites

- Python 3.9+
- Target IDS built with AddressSanitizer (e.g., Snort 3)

### Installation

```bash
git clone https://github.com/soghatak-ai/Protocol-Fuzzing-Framework.git
cd Protocol-Fuzzing-Framework
python -m venv venv
source venv/bin/activate
pip install flask google-generativeai python-dotenv
```

### Configuration

Create a `.env` file in the project root:

```
GOOGLE_API_KEY=your-gemini-api-key-here
```

The API key is loaded via `python-dotenv` and is never hardcoded in source code.

## Usage

### Start the Dashboard

```bash
python app.py
```

Open `http://localhost:5000` in your browser.

### Workflow

1. **Configure** — Select protocol (DNS/FTP), delivery mode (Pipe/Live), target settings
2. **Upload Source Code** — Go to the AI Analysis tab, upload C/C++ source files from the target IDS
3. **Analyze** — Click "Analyze" to run the 3-pass agentic pipeline
4. **Apply Weights** — Review verified vulnerabilities, then apply AI-tuned weights
5. **Fuzz** — Go to Dashboard tab, start the fuzzer with optimized mutation weights
6. **Monitor** — Watch real-time strategy distribution, packet counts, crash detection

### AI Analysis Pipeline

The agentic pipeline uses 2 LLM calls + 1 deterministic Python step:

| Pass | Agent | API Calls | Description |
|------|-------|-----------|-------------|
| 1 | Hunter | 1 | Finds all potential vulnerabilities in source code |
| 2 | Verifier | 1 | Reviews findings, assigns confidence %, rejects false positives |
| 3 | Weigher | 0 | Python formula: `weight × (1 + (severity_mult - 1) × confidence)` |

Temperature is set to `0.0` for deterministic LLM output. Weights are computed in Python, ensuring identical results for the same verified vulnerabilities.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/start` | POST | Start fuzzer |
| `/api/stop` | POST | Stop fuzzer |
| `/api/stream` | GET | SSE event stream (real-time stats) |
| `/api/ai/upload` | POST | Upload source files for analysis |
| `/api/ai/analyze` | POST | Run 3-pass agentic analysis |
| `/api/ai/results` | GET | Get analysis results + pipeline status |
| `/api/ai/weights` | GET | Get current + default weights |
| `/api/ai/apply_weights` | POST | Apply AI-tuned weights to fuzzer |
| `/api/ai/reset_weights` | POST | Reset to default weights |
| `/api/crashes` | GET | List crash reports |

## Testing

```bash
# Start the server first
python app.py

# Run weight pipeline tests
python test_weights.py
```

## License

MIT
