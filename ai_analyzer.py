import os
import json
import traceback
from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, request
import google.generativeai as genai

load_dotenv()

app = Flask(__name__, template_folder="templates")

# ---------------------------------------------------------------------------
# Gemini configuration
# ---------------------------------------------------------------------------
GEMINI_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
GEMINI_MODELS = ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-2.5-pro"]

DNS_STRATEGIES = [
    "smart_dns", "response_fuzz", "compression_loop",
    "label_complexity", "edns_exploit", "tcp_dns_segment",
    "txt_rdata_bomb", "tcp_two_message", "ip_defrag",
    "back_orifice", "dce_smb", "inspector_stress",
]

DNS_DEFAULT_WEIGHTS = {
    "smart_dns": 0.12, "response_fuzz": 0.18, "compression_loop": 0.08,
    "label_complexity": 0.08, "edns_exploit": 0.10, "tcp_dns_segment": 0.05,
    "txt_rdata_bomb": 0.08, "tcp_two_message": 0.06, "ip_defrag": 0.10,
    "back_orifice": 0.08, "dce_smb": 0.07, "inspector_stress": 0.00,
}

FTP_STRATEGIES_LIST = [
    "cmd_overflow", "port_bomb", "pipelined_auth", "cwd_depth",
    "epsv_eprt_mix", "stray_commands", "boundary_port", "oversized_site",
    "encoding_attack", "rest_overflow", "data_channel_confusion",
    "feat_negotiate", "rest_data_reuse",
]

FTP_DEFAULT_WEIGHTS = {
    "cmd_overflow": 18, "port_bomb": 18, "pipelined_auth": 12,
    "cwd_depth": 12, "epsv_eprt_mix": 8, "stray_commands": 8,
    "boundary_port": 4, "oversized_site": 4, "encoding_attack": 6,
    "rest_overflow": 4, "data_channel_confusion": 4, "feat_negotiate": 2,
    "rest_data_reuse": 10,
}

STRATEGY_DESCRIPTIONS = """
The fuzzer has these MUTATION STRATEGIES available. Each generates a specific type of malformed packet:

DNS STRATEGIES (used when fuzzing DNS/network inspectors):
- smart_dns: Swaps DNS header fields with boundary values (0x0000, 0xFFFF, etc.)
- response_fuzz: Injects deep anomaly structures in DNS responses (mismatched RDLENGTH, zero-length pointers, OOB CNAME pointers)
- compression_loop: Creates cyclic DNS compression pointer loops to cause infinite recursion
- label_complexity: Generates massive DNS label floods to exhaust CPU
- edns_exploit: Crafts malformed EDNS OPT records
- tcp_dns_segment: Splits DNS-over-TCP at adversarial byte offsets to break reassembly
- txt_rdata_bomb: Oversized TXT RDATA payloads to overflow record parsing buffers
- tcp_two_message: Sends two DNS messages in one TCP segment to confuse message boundary parsing
- ip_defrag: Creates overlapping/malformed IP fragments targeting the IP defragmentation engine
- back_orifice: Sends crafted Back Orifice UDP packets (port 31337) with XOR-encrypted payloads designed to trigger OOB reads in the decrypt loop
- dce_smb: Sends malformed DCE/RPC over SMB (TCP port 445) with crafted NetBIOS+SMB headers targeting pointer arithmetic bugs
- inspector_stress: Randomizes source IPs/ports to force massive concurrent session tracking, causing memory leaks and state table exhaustion

FTP STRATEGIES (used when fuzzing FTP inspectors):
- cmd_overflow: Sends oversized FTP commands (USER/PASS/RETR) to overflow command parsing buffers
- port_bomb: Floods with malformed PORT commands with invalid IP/port values
- pipelined_auth: Sends rapid pipelined AUTH sequences to confuse state machines
- cwd_depth: Deeply nested CWD commands to exhaust path traversal logic
- epsv_eprt_mix: Mixes EPSV and EPRT commands to confuse extended passive/active mode handling
- stray_commands: Sends unexpected/invalid FTP commands mid-session
- boundary_port: PORT commands with boundary values (0, 255, 65535)
- oversized_site: Oversized SITE command arguments
- encoding_attack: Null bytes, UTF-8 BOM, overlong UTF-8, backslash confusion in FTP stream
- rest_overflow: REST command with boundary integer values (LLONG_MAX, negative, sequential overflow)
- data_channel_confusion: Rapid PASV/PORT mode switching, simultaneous transfers, aborted transfers
- feat_negotiate: AUTH TLS cleartext evasion, FEAT floods, OPTS overflow, rapid mode switching
- rest_data_reuse: CSCwu90022 — REST offset reuse after ABOR, multi-channel race, offset accumulation without transfer
"""

SYSTEM_PROMPT = """You are an expert security researcher specializing in memory corruption vulnerabilities in C/C++ network software.

You will be given source code file(s) from a network intrusion detection system (IDS).

Your task:
1. Read the code carefully.
2. Identify ALL potentially vulnerable code patterns:
   - Buffer overflows (stack and heap)
   - Integer overflows / underflows
   - Out-of-bounds reads/writes
   - Use-after-free
   - Null pointer dereferences
   - Infinite loops / algorithmic complexity
   - Format string bugs
   - Race conditions
   - Unchecked return values leading to dangerous operations
3. For EACH vulnerability found, provide:
   - The exact function name and line range
   - The bug class (heap-overflow, stack-overflow, integer-underflow, oob-read, use-after-free, null-deref, infinite-loop, format-string, race-condition)
   - A detailed reasoning chain explaining HOW the bug can be triggered
   - A concrete byte-level payload (as hex string) that would trigger this bug, considering:
     * What input validation / guard checks exist BEFORE the vulnerable code
     * What byte values are needed to PASS those guards
     * What byte values then TRIGGER the bug
   - The severity (critical / high / medium / low)
   - What protocol and port the payload should be sent on (e.g., UDP/31337, TCP/445)
   - Which mutation strategy from the available strategies below is BEST suited to trigger this vulnerability (matched_strategy field)

IMPORTANT:
- Do NOT report theoretical bugs that are fully guarded by runtime checks. Only report bugs where you can construct a concrete input that reaches the vulnerable code.
- Pay special attention to the GAP between validation checks and the actual dangerous operation — this is where real bugs hide.
- Consider multi-packet / stateful attacks where packet 1 corrupts internal state and packet 2 triggers the crash.

AVAILABLE MUTATION STRATEGIES:
""" + STRATEGY_DESCRIPTIONS + """

4. CRITICAL — After listing vulnerabilities, you MUST also return a "recommended_weights" object.
   Use this DETERMINISTIC FORMULA to calculate weights (do NOT guess or estimate):

   STEP A: Start every strategy at its default weight (DNS sums to 1.0, FTP sums to 100).
   STEP B: For each vulnerability found, apply a MULTIPLIER to its matched_strategy:
     - critical severity → multiply that strategy's weight by 5
     - high severity     → multiply by 3
     - medium severity   → multiply by 2
     - low severity      → multiply by 1.5
   STEP C: If a strategy matches MULTIPLE vulnerabilities, multiply cumulatively.
   STEP D: Strategies with ZERO matched vulnerabilities keep their default weight.
   STEP E: Normalize DNS weights to sum to exactly 1.0, FTP weights to sum to exactly 100.
   STEP F: Round DNS weights to 4 decimal places, FTP weights to 1 decimal place.

   Show your multiplication steps in the weight_reasoning field so the result is reproducible.

Respond in valid JSON format with this structure:
{
  "file_summary": "Brief description of what this code does",
  "vulnerabilities": [
    {
      "id": 1,
      "function": "function_name",
      "line_range": "100-120",
      "bug_class": "heap-overflow",
      "severity": "critical",
      "reasoning": "Detailed step-by-step explanation...",
      "payload_hex": "d2d163ce41414141...",
      "payload_description": "Human-readable description of payload structure",
      "protocol": "UDP",
      "port": 31337,
      "preconditions": "Any setup needed before sending this payload",
      "matched_strategy": "back_orifice",
      "strategy_reasoning": "Why this strategy is the best match"
    }
  ],
  "attack_chains": [
    {
      "description": "Multi-step attack description",
      "steps": ["Send packet A to corrupt state", "Send packet B to trigger crash"]
    }
  ],
  "recommended_weights": {
    "dns": {
      "smart_dns": 0.05,
      "response_fuzz": 0.08,
      "compression_loop": 0.04,
      "label_complexity": 0.04,
      "edns_exploit": 0.05,
      "tcp_dns_segment": 0.03,
      "txt_rdata_bomb": 0.04,
      "tcp_two_message": 0.03,
      "ip_defrag": 0.05,
      "back_orifice": 0.40,
      "dce_smb": 0.04,
      "inspector_stress": 0.15
    },
    "ftp": {
      "cmd_overflow": 20,
      "port_bomb": 20,
      "pipelined_auth": 15,
      "cwd_depth": 15,
      "epsv_eprt_mix": 10,
      "stray_commands": 10,
      "boundary_port": 5,
      "oversized_site": 5
    },
    "weight_reasoning": "Explanation of why these weights were chosen based on the vulnerabilities found"
  }
}

If no exploitable vulnerabilities are found, return:
{
  "file_summary": "...",
  "vulnerabilities": [],
  "attack_chains": [],
  "recommended_weights": null,
  "notes": "Explanation of why the code appears safe"
}
"""

# ---------------------------------------------------------------------------
# State — uploaded files and analysis results
# ---------------------------------------------------------------------------
analysis_state = {
    "files": {},        # filename -> content
    "results": None,    # last analysis JSON
    "status": "idle",   # idle | analyzing | done | error
    "error": None,
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("ai_dashboard.html")


@app.route("/api/upload", methods=["POST"])
def upload_files():
    """Accept one or more source code files."""
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


@app.route("/api/files", methods=["GET"])
def list_files():
    """Return list of uploaded files with line counts."""
    files = []
    for name, content in analysis_state["files"].items():
        files.append({
            "name": name,
            "lines": content.count("\n") + 1,
            "size": len(content),
        })
    return jsonify({"files": files})


@app.route("/api/files/<filename>", methods=["DELETE"])
def delete_file(filename):
    """Remove a file from the upload list."""
    if filename in analysis_state["files"]:
        del analysis_state["files"][filename]
        return jsonify({"status": "removed", "files": list(analysis_state["files"].keys())})
    return jsonify({"error": "File not found"}), 404


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Send uploaded files to Gemini for vulnerability analysis."""
    if not analysis_state["files"]:
        return jsonify({"error": "No files uploaded"}), 400

    if not GEMINI_API_KEY:
        return jsonify({"error": "GOOGLE_API_KEY environment variable not set"}), 500

    analysis_state["status"] = "analyzing"
    analysis_state["results"] = None
    analysis_state["error"] = None

    try:
        genai.configure(api_key=GEMINI_API_KEY)

        # Build the code context
        code_blocks = []
        for filename, content in analysis_state["files"].items():
            code_blocks.append(f"=== FILE: {filename} ===\n{content}\n=== END: {filename} ===")
        code_context = "\n\n".join(code_blocks)

        user_prompt = f"""Analyze the following source code file(s) for security vulnerabilities.
For each vulnerability, provide a concrete byte-level payload that would trigger it.

{code_context}"""

        # Try each model in order until one works
        last_error = None
        for model_name in GEMINI_MODELS:
            try:
                print(f"[*] Trying model: {model_name}")
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(
                    [
                        {"role": "user", "parts": [SYSTEM_PROMPT + "\n\n" + user_prompt]}
                    ],
                    generation_config=genai.GenerationConfig(
                        temperature=0.0,
                        response_mime_type="application/json",
                    ),
                )
                raw_text = response.text.strip()
                print(f"[+] Success with model: {model_name}")
                break
            except Exception as model_err:
                last_error = model_err
                print(f"[-] {model_name} failed: {model_err}")
                continue
        else:
            raise last_error or Exception("All models failed")

        # Parse JSON from response
        try:
            results = json.loads(raw_text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            if "```json" in raw_text:
                json_str = raw_text.split("```json")[1].split("```")[0].strip()
                results = json.loads(json_str)
            elif "```" in raw_text:
                json_str = raw_text.split("```")[1].split("```")[0].strip()
                results = json.loads(json_str)
            else:
                results = {"raw_response": raw_text, "parse_error": True}

        results["model_used"] = model_name
        analysis_state["results"] = results
        analysis_state["status"] = "done"
        return jsonify({"status": "done", "results": results})

    except Exception as e:
        analysis_state["status"] = "error"
        analysis_state["error"] = str(e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/results", methods=["GET"])
def get_results():
    """Return the latest analysis results."""
    return jsonify({
        "status": analysis_state["status"],
        "results": analysis_state["results"],
        "error": analysis_state["error"],
    })


@app.route("/api/weights", methods=["GET"])
def get_weights():
    """Return AI-recommended strategy weights (normalized), or defaults if no analysis done."""
    results = analysis_state.get("results")
    rec = results.get("recommended_weights") if results else None

    if rec and isinstance(rec, dict):
        dns_raw = rec.get("dns", DNS_DEFAULT_WEIGHTS)
        ftp_raw = rec.get("ftp", FTP_DEFAULT_WEIGHTS)
        reasoning = rec.get("weight_reasoning", "")

        # Normalize DNS weights to sum to 1.0
        dns_total = sum(dns_raw.get(s, 0) for s in DNS_STRATEGIES)
        if dns_total > 0:
            dns_norm = {s: round(dns_raw.get(s, 0) / dns_total, 4) for s in DNS_STRATEGIES}
        else:
            dns_norm = DNS_DEFAULT_WEIGHTS

        # Normalize FTP weights to sum to 100
        ftp_total = sum(ftp_raw.get(s, 0) for s in FTP_STRATEGIES_LIST)
        if ftp_total > 0:
            ftp_norm = {s: round(ftp_raw.get(s, 0) / ftp_total * 100, 1) for s in FTP_STRATEGIES_LIST}
        else:
            ftp_norm = FTP_DEFAULT_WEIGHTS

        return jsonify({
            "source": "ai",
            "dns": dns_norm,
            "ftp": ftp_norm,
            "reasoning": reasoning,
            "dns_default": DNS_DEFAULT_WEIGHTS,
            "ftp_default": FTP_DEFAULT_WEIGHTS,
        })

    return jsonify({
        "source": "default",
        "dns": DNS_DEFAULT_WEIGHTS,
        "ftp": FTP_DEFAULT_WEIGHTS,
        "reasoning": "No AI analysis performed yet. Using default weights.",
        "dns_default": DNS_DEFAULT_WEIGHTS,
        "ftp_default": FTP_DEFAULT_WEIGHTS,
    })


@app.route("/api/clear", methods=["POST"])
def clear_all():
    """Reset all state."""
    analysis_state["files"].clear()
    analysis_state["results"] = None
    analysis_state["status"] = "idle"
    analysis_state["error"] = None
    return jsonify({"status": "cleared"})


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════════╗")
    print("║       AI Source Code Analyzer — Phase 1          ║")
    print("║  Upload IDS source files → Get exploit payloads  ║")
    print("╚══════════════════════════════════════════════════╝\n")
    if not GEMINI_API_KEY:
        print("[!] WARNING: GOOGLE_API_KEY not set. Set it with:")
        print("    export GOOGLE_API_KEY='your-key-here'\n")
    app.run(debug=True, port=5001)
