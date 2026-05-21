import os
import json
import time
import threading
from flask import Flask, render_template, jsonify, Response, send_file, request
from main import fuzzer_state, event_log, reset_state, run_fuzzer, log_event

app = Flask(__name__)

SNORT_BUILD = "/Users/soghatak/snort3/build"
CRASHES_DIR = os.path.join(os.path.dirname(__file__), "crashes")
fuzzer_thread = None


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

    data = {
        "iteration": fuzzer_state["iteration"],
        "status": fuzzer_state["status"],
        "running": fuzzer_state["running"],
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
        "runtime": f"{hours:02d}:{mins:02d}:{secs:02d}",
        "trigger_detail": fuzzer_state.get("trigger_detail"),
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

            data = {
                "iteration": fuzzer_state["iteration"],
                "status": fuzzer_state["status"],
                "running": fuzzer_state["running"],
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
                "runtime": f"{hours:02d}:{mins:02d}:{secs:02d}",
                "trigger_detail": fuzzer_state.get("trigger_detail"),
                "events": event_log[-20:],
            }
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/start", methods=["POST"])
def api_start():
    global fuzzer_thread
    if fuzzer_state["running"]:
        return jsonify({"error": "Fuzzer is already running"}), 400

    reset_state()
    log_event("INFO", "Fuzzer started from UI")

    def _run():
        try:
            run_fuzzer(SNORT_BUILD)
        except Exception as e:
            log_event("ERROR", f"Fuzzer crashed: {e}")
            fuzzer_state["status"] = "error"
            fuzzer_state["running"] = False

    fuzzer_thread = threading.Thread(target=_run, daemon=True)
    fuzzer_thread.start()
    return jsonify({"status": "started"})


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
    for fname in sorted(os.listdir(CRASHES_DIR), reverse=True):
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(CRASHES_DIR, fname)
        stat = os.stat(fpath)
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


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
