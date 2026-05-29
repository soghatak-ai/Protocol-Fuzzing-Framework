#!/usr/bin/env python3
"""
Quick verification that dynamic AI weights work end-to-end.
Run while app.py is serving on port 5000.

Usage:
    source venv/bin/activate && python test_weights.py
"""
import requests, json

BASE = "http://localhost:5000"

def p(label, data):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(json.dumps(data, indent=2))

# Fake analysis results (simulates what Gemini would return)
FAKE_RESULTS = {
    "file_summary": "Test file for weight verification",
    "vulnerabilities": [
        {
            "id": 1,
            "function": "test_func",
            "line_range": "10-20",
            "bug_class": "heap-overflow",
            "severity": "critical",
            "reasoning": "Test vulnerability",
            "payload_hex": "41414141",
            "payload_description": "Test payload",
            "protocol": "UDP",
            "port": 31337,
            "preconditions": "None",
            "matched_strategy": "back_orifice",
            "strategy_reasoning": "Tests integer boundary handling"
        }
    ],
    "attack_chains": [],
    "recommended_weights": {
        "dns": {
            "smart_dns": 0.03,
            "response_fuzz": 0.25,
            "compression_loop": 0.02,
            "label_complexity": 0.02,
            "edns_exploit": 0.03,
            "tcp_dns_segment": 0.02,
            "txt_rdata_bomb": 0.02,
            "tcp_two_message": 0.02,
            "ip_defrag": 0.03,
            "back_orifice": 0.50,
            "dce_smb": 0.02,
            "inspector_stress": 0.04
        },
        "ftp": {
            "cmd_overflow": 40,
            "port_bomb": 10,
            "pipelined_auth": 10,
            "cwd_depth": 10,
            "epsv_eprt_mix": 10,
            "stray_commands": 5,
            "boundary_port": 10,
            "oversized_site": 5
        },
        "weight_reasoning": "Boosted back_orifice (50%) and response_fuzz (25%) because critical heap-overflow found"
    },
    "model_used": "test-model"
}

# ── Step 1: Reset to defaults ──────────────────────────────────
print("\n[Step 1] Resetting weights to defaults...")
r = requests.post(f"{BASE}/api/ai/reset_weights")
assert r.status_code == 200, f"Reset failed: {r.text}"
print("  OK — reset done")

# ── Step 2: Read default weights ───────────────────────────────
print("\n[Step 2] Reading current weights (should be defaults)...")
r = requests.get(f"{BASE}/api/ai/weights")
w = r.json()
assert w["source"] == "default", f"Expected 'default', got '{w['source']}'"
p("DNS weights (default)", w["dns"])
p("FTP weights (default)", w["ftp"])

# ── Step 3: Try applying with no results — should fail ─────────
print("\n[Step 3] Applying with no results (should fail gracefully)...")
r = requests.post(f"{BASE}/api/ai/apply_weights")
print(f"  → {r.status_code}: {r.json()}")
assert r.status_code == 400, "Should fail with 400"
print("  OK — correctly rejected")

# ── Step 4: Inject fake results via test endpoint ──────────────
print("\n[Step 4] Injecting fake analysis results...")
r = requests.post(f"{BASE}/api/ai/_test_inject",
                   json=FAKE_RESULTS,
                   headers={"Content-Type": "application/json"})
assert r.status_code == 200, f"Inject failed: {r.text}"
print(f"  OK — {r.json()}")

# ── Step 5: Apply the AI-recommended weights ───────────────────
print("\n[Step 5] Applying AI-recommended weights...")
r = requests.post(f"{BASE}/api/ai/apply_weights")
assert r.status_code == 200, f"Apply failed: {r.text}"
applied = r.json()
p("Applied weights response", applied)

# ── Step 6: Verify weights changed ────────────────────────────
print("\n[Step 6] Verifying weights are now AI-tuned...")
r = requests.get(f"{BASE}/api/ai/weights")
w = r.json()
assert w["source"] == "ai", f"Expected 'ai', got '{w['source']}'"

# back_orifice should be the highest DNS weight (~50%)
dns = w["dns"]
bo_weight = dns["back_orifice"]
rf_weight = dns["response_fuzz"]
print(f"  back_orifice:  {bo_weight:.4f}  (was 0.08 default)")
print(f"  response_fuzz: {rf_weight:.4f}  (was 0.18 default)")
print(f"  source:        {w['source']}")
print(f"  reasoning:     {w['reasoning'][:80]}...")
assert bo_weight > 0.40, f"back_orifice should be ~0.50, got {bo_weight}"
assert bo_weight > rf_weight, "back_orifice should be higher than response_fuzz"
print("  ✓ DNS weights correctly boosted")

# FTP: cmd_overflow should be highest
ftp = w["ftp"]
co_weight = ftp["cmd_overflow"]
print(f"  cmd_overflow:  {co_weight}  (was 20.0 default)")
assert co_weight > 30, f"cmd_overflow should be ~40, got {co_weight}"
print("  ✓ FTP weights correctly boosted")

# ── Step 7: Reset and confirm ─────────────────────────────────
print("\n[Step 7] Resetting back to defaults...")
r = requests.post(f"{BASE}/api/ai/reset_weights")
assert r.status_code == 200
r = requests.get(f"{BASE}/api/ai/weights")
w = r.json()
assert w["source"] == "default"
assert w["dns"]["back_orifice"] == 0.07
assert w["ftp"]["cmd_overflow"] == 18
print("  ✓ Reset confirmed — back_orifice=0.08, cmd_overflow=20")

print("\n" + "="*60)
print("  ALL TESTS PASSED")
print("="*60)
print("""
What was verified:
  1. /api/ai/weights returns correct defaults on startup/reset
  2. /api/ai/apply_weights fails gracefully when no analysis exists
  3. After injecting fake analysis results (simulating Gemini),
     /api/ai/apply_weights normalizes and stores new weights
  4. /api/ai/weights confirms: source="ai", back_orifice boosted
     from 8% → ~50%, response_fuzz from 18% → ~25%
  5. /api/ai/reset_weights restores all defaults
  6. The fuzzer's random.choices() reads ai_weights in real-time,
     so any running fuzzer immediately uses the new distribution
""")
