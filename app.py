import os
import json
import time
import traceback
import threading
from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, Response, send_file, request
from openai import AzureOpenAI
from main import (fuzzer_state, event_log, reset_state, run_fuzzer, run_fuzzer_live,
                  log_event, ai_weights, DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS,
                  FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS,
                  dns_bandit, ftp_bandit)
from protocol.ftp import FTP_STRATEGY_LABELS
from engine.code_collector import (collect_to_dict, collect_to_single_text, VALID_EXTENSIONS,
                                    minify_code, hotspot_filter, extract_repo_map,
                                    build_optimized_context, estimate_tokens)

load_dotenv()

DNS_STRATEGY_LABELS = {
    "smart_dns":          "Smart DNS",
    "response_fuzz":      "Response Fuzz",
    "compression_loop":   "Compression Loop",
    "label_complexity":   "Label Complexity",
    "edns_exploit":       "EDNS Exploit",
    "tcp_dns_segment":    "TCP Segment",
    "txt_rdata_bomb":     "TXT RDATA Bomb",
    "tcp_two_message":    "TCP Two-Message",
    "inspector_stress":   "Inspector Stress",
    "ip_defrag":          "IP Defrag Exploit",
    "back_orifice":       "Back Orifice Exploit",
    "dce_smb":            "DCE/RPC SMB Exploit",
    "dnssec_exploit":     "DNSSEC Exploit",
    "dns_dynamic_update": "DNS Dynamic Update",
    "multi_query_storm":  "Multi-Query Storm",
}

app = Flask(__name__)

SNORT_BUILD = "/Users/soghatak/snort3/build"
CRASHES_DIR = os.path.join(os.path.dirname(__file__), "crashes")
fuzzer_thread = None

# ---------------------------------------------------------------------------
# Azure OpenAI configuration
# ---------------------------------------------------------------------------
AZURE_OPENAI_ENDPOINT = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_API_KEY = os.environ.get("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_API_VERSION = os.environ.get("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
AZURE_OPENAI_MODEL = os.environ.get("AZURE_OPENAI_MODEL", "gpt-5")

STRATEGY_DESCRIPTIONS = """
The fuzzer has these MUTATION STRATEGIES available. Each generates a specific type of malformed packet:

DNS STRATEGIES (used when fuzzing DNS/network inspectors):
- smart_dns: Swaps DNS header fields with boundary values (0x0000, 0xFFFF, etc.). Triggers: integer-overflow, null-deref, header-parsing bugs
- response_fuzz: Injects deep anomaly structures in DNS responses (mismatched RDLENGTH, zero-length pointers, OOB CNAME pointers). Triggers: oob-read, heap-overflow, buffer-overread
- compression_loop: Creates cyclic DNS compression pointer loops to cause infinite recursion. Triggers: infinite-loop, stack-overflow, algorithmic-complexity
- label_complexity: Generates massive DNS label floods to exhaust CPU. Triggers: algorithmic-complexity, memory-exhaustion, DoS
- edns_exploit: Crafts malformed EDNS OPT records. Triggers: oob-read, integer-overflow, heap-overflow
- tcp_dns_segment: Splits DNS-over-TCP at adversarial byte offsets to break reassembly. Triggers: oob-read, buffer-overflow, off-by-one
- txt_rdata_bomb: Oversized TXT RDATA payloads to overflow record parsing buffers. Triggers: heap-overflow, buffer-overflow
- tcp_two_message: Sends two DNS messages in one TCP segment to confuse message boundary parsing. Triggers: oob-read, buffer-overflow, state-corruption
- ip_defrag: Creates overlapping/malformed IP fragments targeting the IP defragmentation engine. Triggers: heap-overflow, oob-write, memory-corruption
- back_orifice: Sends crafted Back Orifice UDP packets (port 31337) with XOR-encrypted payloads. Triggers: oob-read, integer-underflow, heap-overflow
- dce_smb: Sends malformed DCE/RPC over SMB (TCP port 445) with crafted NetBIOS+SMB headers. Triggers: oob-read, heap-overflow, pointer-arithmetic bugs
- inspector_stress: Randomizes source IPs/ports to force massive concurrent session tracking. Triggers: memory-leak, state-table-exhaustion, DoS
- dnssec_exploit: Crafts malformed DNSSEC records (RRSIG OOB signer names, NSEC3 hash overflow, DNSKEY flag exploits, NSEC bitmap overflow). Triggers: oob-read, heap-overflow, buffer-overread
- dns_dynamic_update: Sends DNS UPDATE (RFC 2136) packets with malformed zone/prereq/update sections, forged TSIG records. Targets rarely-exercised opcode=5 parser path. Triggers: oob-read, state-corruption, integer-overflow
- multi_query_storm: Multiple questions per packet with conflicting/unusual types (CHAOS class, OPT-in-question, root-label floods). Triggers: type-confusion, oob-read, algorithmic-complexity

FTP STRATEGIES (used when fuzzing FTP inspectors):
- cmd_overflow: Sends oversized FTP commands (USER/PASS/RETR) to overflow command parsing buffers. Triggers: stack-overflow, heap-overflow, buffer-overflow
- port_bomb: Floods with malformed PORT commands with invalid IP/port values. Triggers: memory-leak, integer-overflow, state-exhaustion
- pipelined_auth: Sends rapid pipelined AUTH sequences to confuse state machines. Triggers: state-corruption, use-after-free, race-condition
- cwd_depth: Deeply nested CWD commands to exhaust path traversal logic. Triggers: stack-overflow, algorithmic-complexity, DoS
- epsv_eprt_mix: Mixes EPSV and EPRT commands to confuse extended passive/active mode handling. Triggers: state-corruption, null-deref
- stray_commands: Sends unexpected/invalid FTP commands mid-session. Triggers: state-corruption, null-deref, use-after-free
- boundary_port: PORT commands with boundary values (0, 255, 65535). Triggers: integer-overflow, integer-underflow, oob-write
- oversized_site: Oversized SITE command arguments. Triggers: format-string, heap-overflow, buffer-overflow
- encoding_attack: Null bytes, UTF-8 BOM, overlong UTF-8, backslash confusion, Telnet IAC sequences in FTP stream. Targets command normalization. Triggers: evasion, oob-read, state-corruption
- rest_overflow: REST command with boundary integer values (LLONG_MAX, negative, sequential overflow). Targets file position tracking. Triggers: integer-overflow, integer-underflow, oob-write
- data_channel_confusion: Rapid PASV/PORT mode switching, simultaneous transfers, aborted transfers. Targets data channel state tracking. Triggers: use-after-free, state-corruption, memory-leak
- feat_negotiate: AUTH TLS cleartext evasion, FEAT floods, OPTS overflow, rapid mode switching. Targets feature negotiation state. Triggers: evasion, state-corruption, buffer-overflow
"""

# ---------------------------------------------------------------------------
# PASS 1: HUNTER — finds all potential vulnerabilities (no weights)
# ---------------------------------------------------------------------------
HUNTER_PROMPT = """You are an expert security researcher specializing in memory corruption vulnerabilities in C/C++ network software.

You will be given source code file(s) from a network intrusion detection system (IDS).

YOUR ONLY TASK: Find ALL potential vulnerabilities. Do NOT compute weights — that will be done later.

For each vulnerability found, provide:
  - The exact function name and line range
  - The bug class: heap-overflow | stack-overflow | integer-overflow | integer-underflow | oob-read | oob-write | use-after-free | null-deref | infinite-loop | format-string | race-condition | state-corruption | memory-leak
  - A step-by-step reasoning chain: what input → what code path → what goes wrong
  - A concrete byte-level payload (hex string) that triggers it
  - The severity: critical | high | medium | low
    (critical = RCE/arbitrary write; high = crash/DoS; medium = info leak; low = minor)
  - Protocol and port the payload should be sent on
  - Which mutation strategy from the list below BEST triggers this vulnerability

Be thorough but precise:
- Do NOT report theoretical bugs guarded by runtime checks
- Only report bugs where you can construct a concrete input that reaches the vulnerable code
- Pay attention to the GAP between validation and the dangerous operation
- Consider multi-packet stateful attacks

AVAILABLE MUTATION STRATEGIES:
""" + STRATEGY_DESCRIPTIONS + """

Respond in valid JSON:
{
  "file_summary": "What this code does",
  "vulnerabilities": [
    {
      "id": 1,
      "function": "function_name",
      "line_range": "100-120",
      "bug_class": "heap-overflow",
      "severity": "critical",
      "reasoning": "Step-by-step chain...",
      "payload_hex": "deadbeef...",
      "payload_description": "Human-readable payload description",
      "protocol": "UDP",
      "port": 31337,
      "preconditions": "Setup needed",
      "matched_strategy": "back_orifice",
      "strategy_reasoning": "Why this strategy triggers it"
    }
  ],
  "attack_chains": [
    {
      "description": "Multi-step attack",
      "steps": ["Step 1", "Step 2"]
    }
  ]
}

If no exploitable vulnerabilities are found:
{
  "file_summary": "...",
  "vulnerabilities": [],
  "attack_chains": [],
  "notes": "Why the code appears safe"
}
"""



# ---------------------------------------------------------------------------
# TRIAGE: MAP PROMPT — picks riskiest files from repo map
# ---------------------------------------------------------------------------
MAP_PROMPT = """You are an expert security researcher triaging a large C/C++ codebase for vulnerability analysis.

You will receive a REPO MAP: a list of source files with their function signatures and struct declarations.

Your task: Select the TOP 20 files most likely to contain exploitable vulnerabilities.

Prioritize files that have:
1. Functions handling raw network input (recv, read, packet parsing)
2. Memory operations without obvious bounds checking (memcpy, strcpy, sprintf with pointer params)
3. Buffer manipulation, pointer arithmetic, or manual memory management
4. Protocol parsers, decoders, or inspectors
5. Functions with size/length parameters that could overflow

DO NOT select:
- Test files, build scripts, or configuration files
- Files with only simple getters/setters or logging
- Files that are clearly auto-generated

Respond in valid JSON:
{
  "selected_files": [
    {
      "path": "relative/path/to/file.c",
      "risk_reason": "Brief reason why this file is risky"
    }
  ],
  "summary": "Brief overview of the codebase and its attack surface"
}
"""

# ---------------------------------------------------------------------------
# DETERMINISTIC PYTHON WEIGHER — no LLM involved
# ---------------------------------------------------------------------------
SEVERITY_MULTIPLIERS = {
    "critical": 5.0,
    "high":     3.0,
    "medium":   2.0,
    "low":      1.5,
}

def compute_weights_from_vulns(verified_vulns):
    """Deterministic weight computation from verified vulnerabilities.
    Returns (dns_weights, ftp_weights, reasoning_str)."""

    # Start with default weights
    dns_w = dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS))
    ftp_w = dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS))

    reasoning_lines = ["Weight computation (deterministic formula):"]
    reasoning_lines.append(f"  Starting from default weights. {len(verified_vulns)} verified vulnerabilities.")

    # Apply multipliers
    for v in verified_vulns:
        strat = v.get("matched_strategy", "")
        sev = v.get("severity", "medium").lower()
        mult = SEVERITY_MULTIPLIERS.get(sev, 1.5)
        conf = v.get("confidence", 80) / 100.0  # scale multiplier by confidence

        effective_mult = 1.0 + (mult - 1.0) * conf
        func = v.get("function", "?")

        if strat in dns_w:
            old = dns_w[strat]
            dns_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  DNS/{strat}: {old:.4f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {dns_w[strat]:.4f}")
        elif strat in ftp_w:
            old = ftp_w[strat]
            ftp_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  FTP/{strat}: {old:.1f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {ftp_w[strat]:.1f}")
        else:
            reasoning_lines.append(f"  WARNING: strategy '{strat}' not recognized, skipping")

    # Normalize DNS to sum=1.0
    dns_total = sum(dns_w.values())
    if dns_total > 0:
        dns_w = {s: round(v / dns_total, 4) for s, v in dns_w.items()}
    reasoning_lines.append(f"  DNS normalized (sum was {dns_total:.4f})")

    # Normalize FTP to sum=100
    ftp_total = sum(ftp_w.values())
    if ftp_total > 0:
        ftp_w = {s: round(v / ftp_total * 100, 1) for s, v in ftp_w.items()}
    reasoning_lines.append(f"  FTP normalized (sum was {ftp_total:.1f})")

    return dns_w, ftp_w, "\n".join(reasoning_lines)

# AI analysis state
analysis_state = {
    "files": {},
    "results": None,
    "status": "idle",
    "error": None,
}


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/state")
def api_state():
    elapsed = 0
    if fuzzer_state["start_time"]:
        if fuzzer_state["running"]:
            elapsed = time.time() - fuzzer_state["start_time"]
            fuzzer_state["_frozen_elapsed"] = elapsed
        else:
            elapsed = fuzzer_state.get("_frozen_elapsed", 0)
    hours, rem = divmod(int(elapsed), 3600)
    mins, secs = divmod(rem, 60)

    protocol = fuzzer_state.get("protocol", "dns")
    labels = FTP_STRATEGY_LABELS if protocol == "ftp" else DNS_STRATEGY_LABELS
    data = {
        "iteration": fuzzer_state["iteration"],
        "status": fuzzer_state["status"],
        "running": fuzzer_state["running"],
        "protocol": protocol,
        "anomaly_detected": fuzzer_state["anomaly_detected"],
        "current_strategy": fuzzer_state["current_strategy"],
        "baseline_mem_mb": fuzzer_state["baseline_mem_mb"],
        "peak_mem_mb": fuzzer_state["peak_mem_mb"],
        "current_mem_mb": fuzzer_state["current_mem_mb"],
        "snort_pid": fuzzer_state["snort_pid"],
        "total_crashes": fuzzer_state.get("total_crashes", 0),
        "last_crash_time": fuzzer_state.get("last_crash_time"),
        "last_crash_type": fuzzer_state.get("last_crash_type"),
        "packets_per_sec": fuzzer_state.get("packets_per_sec", 0),
        "strategy_stats": fuzzer_state.get("strategy_stats", {}),
        "strategy_labels": labels,
        "runtime": f"{hours:02d}:{mins:02d}:{secs:02d}",
        "trigger_detail": fuzzer_state.get("trigger_detail"),
        "bandit_stats": (ftp_bandit if protocol == "ftp" else dns_bandit).get_stats(
            base_weights=ai_weights.get("ftp" if protocol == "ftp" else "dns", {})),
    }
    return jsonify(data)


@app.route("/api/events")
def api_events():
    return jsonify(event_log[-100:])


@app.route("/api/stream")
def api_stream():
    def generate():
        last_iter = 0
        while True:
            elapsed = 0
            if fuzzer_state["start_time"]:
                if fuzzer_state["running"]:
                    elapsed = time.time() - fuzzer_state["start_time"]
                    fuzzer_state["_frozen_elapsed"] = elapsed
                else:
                    elapsed = fuzzer_state.get("_frozen_elapsed", 0)
            hours, rem = divmod(int(elapsed), 3600)
            mins, secs = divmod(rem, 60)

            protocol = fuzzer_state.get("protocol", "dns")
            labels = FTP_STRATEGY_LABELS if protocol == "ftp" else DNS_STRATEGY_LABELS
            data = {
                "iteration": fuzzer_state["iteration"],
                "status": fuzzer_state["status"],
                "running": fuzzer_state["running"],
                "protocol": protocol,
                "anomaly_detected": fuzzer_state["anomaly_detected"],
                "current_strategy": fuzzer_state["current_strategy"],
                "baseline_mem_mb": fuzzer_state["baseline_mem_mb"],
                "peak_mem_mb": fuzzer_state["peak_mem_mb"],
                "current_mem_mb": fuzzer_state["current_mem_mb"],
                "snort_pid": fuzzer_state["snort_pid"],
                "total_crashes": fuzzer_state.get("total_crashes", 0),
                "last_crash_time": fuzzer_state.get("last_crash_time"),
                "last_crash_type": fuzzer_state.get("last_crash_type"),
                "packets_per_sec": fuzzer_state.get("packets_per_sec", 0),
                "strategy_stats": fuzzer_state.get("strategy_stats", {}),
                "strategy_labels": labels,
                "runtime": f"{hours:02d}:{mins:02d}:{secs:02d}",
                "trigger_detail": fuzzer_state.get("trigger_detail"),
                "bandit_stats": (ftp_bandit if protocol == "ftp" else dns_bandit).get_stats(
                    base_weights=ai_weights.get("ftp" if protocol == "ftp" else "dns", {})),
                "events": event_log[-20:],
            }
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/config", methods=["GET"])
def api_config_get():
    return jsonify(fuzzer_state.get("live_config", {}))


@app.route("/api/config", methods=["POST"])
def api_config_set():
    body = request.json or {}
    fuzzer_state["live_config"] = body
    return jsonify({"status": "saved"})


@app.route("/api/start", methods=["POST"])
def api_start():
    global fuzzer_thread
    if fuzzer_state["running"]:
        return jsonify({"error": "Fuzzer is already running"}), 400

    body = request.json or {}
    protocol = body.get("protocol", "dns").lower()
    if protocol not in ("dns", "ftp"):
        protocol = "dns"
    mode = body.get("mode", "pipe").lower()
    live_config = body.get("live_config", {})

    fuzzer_state["protocol"] = protocol
    fuzzer_state["mode"] = mode
    if live_config:
        fuzzer_state["live_config"] = live_config
    reset_state()
    fuzzer_state["mode"] = mode
    log_event("INFO", f"Fuzzer started from UI (protocol: {protocol.upper()}, mode: {mode})")

    def _run():
        try:
            if mode == "live":
                cfg = fuzzer_state.get("live_config", {})
                run_fuzzer_live(cfg)
            else:
                run_fuzzer(SNORT_BUILD)
        except Exception as e:
            log_event("ERROR", f"Fuzzer crashed: {e}")
            fuzzer_state["status"] = "error"
            fuzzer_state["running"] = False

    fuzzer_thread = threading.Thread(target=_run, daemon=True)
    fuzzer_thread.start()
    return jsonify({"status": "started", "mode": mode})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    if not fuzzer_state["running"]:
        return jsonify({"error": "Fuzzer is not running"}), 400
    fuzzer_state["running"] = False
    log_event("WARNING", "Stop requested from UI")
    return jsonify({"status": "stopping"})


@app.route("/api/crashes")
def api_crashes():
    os.makedirs(CRASHES_DIR, exist_ok=True)
    reports = []
    
    files_with_mtime = []
    for fname in os.listdir(CRASHES_DIR):
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(CRASHES_DIR, fname)
        files_with_mtime.append((fname, fpath, os.stat(fpath)))
        
    files_with_mtime.sort(key=lambda x: x[2].st_mtime, reverse=True)
    
    for fname, fpath, stat in files_with_mtime:
        parts = fname.replace(".txt", "").split("_report_")
        anomaly_type = parts[0] if parts else fname
        iteration = ""
        timestamp_str = ""
        if len(parts) > 1:
            tail = parts[1].split("_")
            iteration = tail[0] if tail else ""
            timestamp_str = tail[1] if len(tail) > 1 else ""

        reports.append({
            "filename": fname,
            "anomaly_type": anomaly_type,
            "iteration": iteration,
            "size": stat.st_size,
            "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
            "mtime": stat.st_mtime  
        })
    return jsonify(reports)


@app.route("/api/crashes/<filename>")
def api_crash_detail(filename):
    fpath = os.path.join(CRASHES_DIR, filename)
    if not os.path.isfile(fpath):
        return jsonify({"error": "Not found"}), 404
    with open(fpath, "r") as f:
        content = f.read()
    return jsonify({"filename": filename, "content": content})


@app.route("/api/crashes/<filename>/download")
def api_crash_download(filename):
    fpath = os.path.join(CRASHES_DIR, filename)
    if not os.path.isfile(fpath):
        return jsonify({"error": "Not found"}), 404
    return send_file(fpath, as_attachment=True)


@app.route("/api/crashes/<filename>", methods=["DELETE"])
def api_crash_delete(filename):
    fpath = os.path.join(CRASHES_DIR, filename)
    if not os.path.isfile(fpath):
        return jsonify({"error": "Not found"}), 404
    os.remove(fpath)
    log_event("INFO", f"Crash report deleted: {filename}")
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# AI Analysis Routes
# ---------------------------------------------------------------------------
@app.route("/api/ai/upload", methods=["POST"])
def ai_upload():
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400
    uploaded = request.files.getlist("files")
    for f in uploaded:
        if f.filename:
            content = f.read().decode("utf-8", errors="replace")
            analysis_state["files"][f.filename] = content
    return jsonify({
        "status": "ok",
        "files": list(analysis_state["files"].keys()),
        "total_lines": sum(c.count("\n") + 1 for c in analysis_state["files"].values()),
    })


@app.route("/api/ai/upload-directory", methods=["POST"])
def ai_upload_directory():
    """Accept a local directory path, collect all source files, and load them."""
    body = request.json or {}
    dir_path = body.get("path", "").strip()
    if not dir_path:
        return jsonify({"error": "No directory path provided"}), 400
    dir_path = os.path.expanduser(dir_path)
    if not os.path.isdir(dir_path):
        return jsonify({"error": f"Directory not found: {dir_path}"}), 400

    try:
        collected = collect_to_dict(dir_path)
        if not collected:
            return jsonify({"error": "No source files found in directory"}), 400

        analysis_state["files"].update(collected)
        total_lines = sum(c.count("\n") + 1 for c in collected.values())
        total_size_mb = sum(len(c) for c in collected.values()) / (1024 * 1024)
        print(f"[AI] Directory loaded: {len(collected)} files from {dir_path} ({total_size_mb:.2f} MB)")

        return jsonify({
            "status": "ok",
            "new_files": len(collected),
            "total_files": len(analysis_state["files"]),
            "total_lines": total_lines,
            "size_mb": round(total_size_mb, 2),
            "files": list(analysis_state["files"].keys()),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/files", methods=["GET"])
def ai_files():
    files = []
    for name, content in analysis_state["files"].items():
        files.append({"name": name, "lines": content.count("\n") + 1, "size": len(content)})
    return jsonify({"files": files})


@app.route("/api/ai/files/<filename>", methods=["DELETE"])
def ai_delete_file(filename):
    if filename in analysis_state["files"]:
        del analysis_state["files"][filename]
        return jsonify({"status": "removed", "files": list(analysis_state["files"].keys())})
    return jsonify({"error": "File not found"}), 404


def _ai_call(prompt_text, user_text):
    """Call Azure OpenAI. Returns (parsed_json, model_name)."""
    client = AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_API_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
    )
    model_name = AZURE_OPENAI_MODEL
    print(f"[AI] Calling Azure OpenAI model: {model_name}")
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": prompt_text},
                {"role": "user", "content": user_text},
            ],
            max_completion_tokens=65536,
            response_format={"type": "json_object"},
            timeout=600,
        )
        # Log rate limit headers to show quota details
        http_resp = getattr(response, '_response', None)
        if http_resp:
            headers = http_resp.headers
            print(f"[AI] ── Rate Limit Info ──")
            for h in ['x-ratelimit-limit-requests', 'x-ratelimit-remaining-requests',
                       'x-ratelimit-limit-tokens', 'x-ratelimit-remaining-tokens',
                       'x-ratelimit-reset-requests', 'x-ratelimit-reset-tokens']:
                val = headers.get(h)
                if val:
                    print(f"[AI]   {h}: {val}")

        raw_text = response.choices[0].message.content.strip()
        print(f"[AI] Success with model: {model_name}")
        print(f"[AI] Response length: {len(raw_text)} chars")
        print(f"[AI] Tokens used — prompt: {response.usage.prompt_tokens}, completion: {response.usage.completion_tokens}, total: {response.usage.total_tokens}")

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            if "```json" in raw_text:
                json_str = raw_text.split("```json")[1].split("```")[0].strip()
                parsed = json.loads(json_str)
            elif "```" in raw_text:
                json_str = raw_text.split("```")[1].split("```")[0].strip()
                parsed = json.loads(json_str)
            else:
                parsed = {"raw_response": raw_text, "parse_error": True}

        print(f"[AI] Parsed JSON keys: {list(parsed.keys()) if isinstance(parsed, dict) else type(parsed).__name__}")
        return parsed, model_name
    except Exception as err:
        print(f"[AI] {model_name} failed: {err}")
        raise


@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze():
    if not analysis_state["files"]:
        return jsonify({"error": "No files uploaded"}), 400
    if not AZURE_OPENAI_API_KEY:
        return jsonify({"error": "AZURE_OPENAI_API_KEY not set in .env"}), 500

    analysis_state["status"] = "analyzing"
    analysis_state["results"] = None
    analysis_state["error"] = None

    try:
        all_files = dict(analysis_state["files"])
        total_raw = sum(len(v) for v in all_files.values())
        print(f"[AI] ── Input: {len(all_files)} files, {total_raw/1024:.1f} KB, ~{estimate_tokens(total_raw)} tokens (raw)")

        # ── STAGE 1: MINIFY (local, instant) ──────────────────────
        print("[AI] ══ STAGE 1: Minifying code (strip comments/blanks) ══")
        analysis_state["status"] = "analyzing (stage 1/4: minifying)"
        minified_files = {}
        for path, content in all_files.items():
            minified_files[path] = minify_code(content)
        total_minified = sum(len(v) for v in minified_files.values())
        reduction_1 = (1 - total_minified / max(total_raw, 1)) * 100
        print(f"[AI]   Minified: {total_minified/1024:.1f} KB, ~{estimate_tokens(total_minified)} tokens ({reduction_1:.0f}% reduction)")

        # ── STAGE 2: HOTSPOT FILTER (local, instant) ──────────────
        print("[AI] ══ STAGE 2: Hotspot filtering (dangerous patterns) ══")
        analysis_state["status"] = "analyzing (stage 2/4: hotspot filtering)"
        hotspot_files = hotspot_filter(minified_files)
        total_hotspot = sum(len(v) for v in hotspot_files.values())
        print(f"[AI]   Hotspots: {len(hotspot_files)}/{len(minified_files)} files, {total_hotspot/1024:.1f} KB, ~{estimate_tokens(total_hotspot)} tokens")

        # If small enough (<=20 files or <=100K tokens), skip triage and analyze directly
        DIRECT_THRESHOLD_FILES = 20
        DIRECT_THRESHOLD_TOKENS = 100_000
        hotspot_tokens = estimate_tokens(total_hotspot)

        if len(hotspot_files) <= DIRECT_THRESHOLD_FILES or hotspot_tokens <= DIRECT_THRESHOLD_TOKENS:
            print(f"[AI]   Small enough for direct analysis — skipping repo map triage")
            selected_paths = list(hotspot_files.keys())
            map_summary = "Direct analysis (small codebase)"
            triage_details = []
            code_context = build_optimized_context(hotspot_files, selected_paths)
        else:
            # ── STAGE 3: REPO MAP TRIAGE (1 API call) ─────────────
            print("[AI] ══ STAGE 3: Repo map triage (LLM picks top-20 files) ══")
            analysis_state["status"] = "analyzing (stage 3/4: triage)"
            repo_map = extract_repo_map(hotspot_files)
            map_tokens = estimate_tokens(repo_map)
            print(f"[AI]   Repo map: {map_tokens} tokens ({len(hotspot_files)} files)")

            triage_results, _ = _ai_call(MAP_PROMPT, repo_map)

            selected_entries = triage_results.get("selected_files", [])
            map_summary = triage_results.get("summary", "")
            triage_details = selected_entries

            # Extract paths, handling both exact and fuzzy matches
            selected_paths = []
            available = set(hotspot_files.keys())
            for entry in selected_entries:
                p = entry.get("path", "")
                if p in available:
                    selected_paths.append(p)
                else:
                    for avail_path in available:
                        if avail_path.endswith(p) or p.endswith(avail_path):
                            selected_paths.append(avail_path)
                            break

            if not selected_paths:
                print(f"[AI]   WARNING: No path matches — falling back to all hotspot files")
                selected_paths = list(hotspot_files.keys())

            print(f"[AI]   Selected {len(selected_paths)} files for deep analysis")
            code_context = build_optimized_context(hotspot_files, selected_paths)

        context_tokens = estimate_tokens(code_context)
        reduction_total = (1 - len(code_context) / max(total_raw, 1)) * 100
        print(f"[AI]   Final context: {len(code_context)/1024:.1f} KB, ~{context_tokens} tokens ({reduction_total:.0f}% total reduction)")

        # Save consolidated context to disk
        context_path = os.path.join(os.path.expanduser("~"), "ai_context.txt")
        with open(context_path, "w", encoding="utf-8") as ctx_file:
            ctx_file.write(code_context)

        # ── STAGE 4: DEEP ANALYSIS (1 API call) ──────────────────
        print("[AI] ══ STAGE 4: Deep vulnerability analysis ══")
        analysis_state["status"] = "analyzing (stage 4/4: deep analysis)"
        hunter_prompt = f"""Analyze the following source code file(s) for security vulnerabilities.
For each vulnerability, provide a concrete byte-level payload that would trigger it.

{code_context}"""

        hunter_results, model_used = _ai_call(HUNTER_PROMPT, hunter_prompt)
        raw_vulns = hunter_results.get("vulnerabilities", [])

        # Deep search: model sometimes nests vulns under a different key
        if not raw_vulns and isinstance(hunter_results, dict):
            for key, val in hunter_results.items():
                if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                    if any(k in val[0] for k in ["bug_class", "severity", "function", "matched_strategy"]):
                        print(f"[AI] Found vulnerabilities under key '{key}' instead of 'vulnerabilities'")
                        raw_vulns = val
                        break
                elif isinstance(val, dict) and "vulnerabilities" in val:
                    print(f"[AI] Found nested vulnerabilities under '{key}.vulnerabilities'")
                    raw_vulns = val["vulnerabilities"]
                    break

        print(f"[AI] Deep analysis found {len(raw_vulns)} potential vulnerabilities")

        if not raw_vulns:
            debug_path = os.path.join(os.path.expanduser("~"), "ai_hunter_debug.json")
            with open(debug_path, "w") as f:
                json.dump(hunter_results, f, indent=2)
            print(f"[AI] 0 vulns found — raw response saved to {debug_path}")
            hunter_results["model_used"] = model_used
            hunter_results["pipeline"] = {
                "total_files": len(all_files),
                "hotspot_files": len(hotspot_files),
                "analyzed_files": len(selected_paths),
                "raw_tokens": estimate_tokens(total_raw),
                "final_tokens": context_tokens,
                "reduction_pct": round(reduction_total, 1),
                "vulns_found": 0,
            }
            hunter_results["recommended_weights"] = None
            analysis_state["results"] = hunter_results
            analysis_state["status"] = "done"
            return jsonify({"status": "done", "results": hunter_results})

        # ── WEIGHER: DETERMINISTIC PYTHON ─────────────────────────
        print("[AI] ══ Computing weights (Python) ══")
        dns_w, ftp_w, reasoning = compute_weights_from_vulns(raw_vulns)
        print(f"[AI] Weights computed deterministically.")

        # Assemble final results
        results = {
            "file_summary": hunter_results.get("file_summary", ""),
            "map_summary": map_summary,
            "vulnerabilities": raw_vulns,
            "attack_chains": hunter_results.get("attack_chains", []),
            "recommended_weights": {
                "dns": dns_w,
                "ftp": ftp_w,
                "weight_reasoning": reasoning,
            },
            "model_used": model_used,
            "pipeline": {
                "total_files": len(all_files),
                "hotspot_files": len(hotspot_files),
                "analyzed_files": len(selected_paths),
                "raw_tokens": estimate_tokens(total_raw),
                "final_tokens": context_tokens,
                "reduction_pct": round(reduction_total, 1),
                "vulns_found": len(raw_vulns),
            },
        }

        analysis_state["results"] = results
        analysis_state["status"] = "done"
        return jsonify({"status": "done", "results": results})

    except Exception as e:
        analysis_state["status"] = "error"
        analysis_state["error"] = str(e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/results", methods=["GET"])
def ai_results():
    return jsonify({
        "status": analysis_state["status"],
        "results": analysis_state["results"],
        "error": analysis_state["error"],
    })


@app.route("/api/ai/weights", methods=["GET"])
def ai_get_weights():
    """Return current weights (AI or default) plus defaults for comparison."""
    dns_default = dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS))
    ftp_default = dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS))
    return jsonify({
        "source": ai_weights.get("source", "default"),
        "dns": ai_weights.get("dns", dns_default),
        "ftp": ai_weights.get("ftp", ftp_default),
        "reasoning": ai_weights.get("reasoning", ""),
        "dns_default": dns_default,
        "ftp_default": ftp_default,
    })


@app.route("/api/ai/apply_weights", methods=["POST"])
def ai_apply_weights():
    """Apply AI-recommended weights from the latest analysis to the fuzzer."""
    results = analysis_state.get("results")
    if not results:
        return jsonify({"error": "No analysis results available"}), 400

    rec = results.get("recommended_weights")
    if not rec or not isinstance(rec, dict):
        return jsonify({"error": "No weight recommendations in analysis results"}), 400

    dns_raw = rec.get("dns", {})
    ftp_raw = rec.get("ftp", {})

    # Normalize DNS weights
    dns_total = sum(dns_raw.get(s, 0) for s in DNS_STRATEGY_NAMES)
    if dns_total > 0:
        ai_weights["dns"] = {s: round(dns_raw.get(s, 0) / dns_total, 4) for s in DNS_STRATEGY_NAMES}
    
    # Normalize FTP weights
    ftp_total = sum(ftp_raw.get(s, 0) for s in FTP_STRATEGY_NAMES)
    if ftp_total > 0:
        ai_weights["ftp"] = {s: round(ftp_raw.get(s, 0) / ftp_total * 100, 1) for s in FTP_STRATEGY_NAMES}

    ai_weights["source"] = "ai"
    ai_weights["reasoning"] = rec.get("weight_reasoning", "")

    # Reset RL bandits so they start fresh with new AI base weights
    dns_bandit.reset()
    ftp_bandit.reset()

    log_event("INFO", f"AI weights applied — source: {results.get('model_used', 'unknown')}, RL bandits reset")
    print(f"[AI] Weights applied: DNS={ai_weights['dns']}")
    print(f"[AI] Weights applied: FTP={ai_weights['ftp']}")

    return jsonify({"status": "applied", "dns": ai_weights["dns"], "ftp": ai_weights["ftp"]})


@app.route("/api/ai/reset_weights", methods=["POST"])
def ai_reset_weights():
    """Reset weights back to defaults."""
    ai_weights["dns"] = dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS))
    ai_weights["ftp"] = dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS))
    ai_weights["source"] = "default"
    ai_weights["reasoning"] = ""

    # Reset RL bandits
    dns_bandit.reset()
    ftp_bandit.reset()

    log_event("INFO", "Strategy weights reset to defaults, RL bandits reset")
    return jsonify({"status": "reset"})


@app.route("/api/ai/_test_inject", methods=["POST"])
def ai_test_inject():
    """DEBUG: Inject fake analysis results to test weight pipeline without OpenAI."""
    data = request.json
    analysis_state["results"] = data
    analysis_state["status"] = "done" if data else "idle"
    return jsonify({"status": "injected" if data else "cleared"})


@app.route("/api/ai/clear", methods=["POST"])
def ai_clear():
    analysis_state["files"].clear()
    analysis_state["results"] = None
    analysis_state["status"] = "idle"
    analysis_state["error"] = None
    return jsonify({"status": "cleared"})


if __name__ == "__main__":
    if not AZURE_OPENAI_API_KEY:
        print("[!] WARNING: AZURE_OPENAI_API_KEY not set in .env")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)

