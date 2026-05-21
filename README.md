# Protocol Fuzzing Framework

A high-performance, specialized protocol fuzzer designed to uncover memory corruption, logical vulnerabilities, algorithmic complexity bugs, and state exhaustion in deep packet inspection engines like Snort 3.

## Key Features

* **Deep Parser Fuzzing:** Targets complex protocol parsers (like DNS responses, QR=1) with intentional RFC violations, including `RDLENGTH` mismatches, out-of-bounds CNAME pointers, and overlapping compression records to trigger Heap Overflows and Out-Of-Bounds (OOB) reads.
* **Algorithmic Complexity Exploitation:** Crafts cyclic compression pointer loops and label floods designed to trap the IDS parser in infinite recursion or exhaust CPU cycles.
* **State Exhaustion & Memory Leak Amplification:** Automatically spoofs millions of unique 5-tuples (IPs/Ports) paired with synchronized wall-clock timestamps to force the IDS to track massive concurrent sessions, triggering memory leaks and state table exhaustion.
* **Intelligent Watchdog:** A background thread that continuously monitors the target process's RSS memory footprint and processing latency. It can accurately detect silent hangs (infinite loops) and massive RAM bloat (>500MB over baseline).
* **Automated Crash Reporting:** Upon detecting an anomaly or crash, the fuzzer extracts the AddressSanitizer (ASan) stack trace from `stderr` and dumps a detailed diagnostic log containing the exact fuzzing iteration and strategy that caused the failure.
* **Dual Delivery Modes:** 
  * **PCAP Pipe Mode:** Wraps raw payloads in synthetic Ethernet/IP/UDP headers and streams them into the IDS via a POSIX named pipe (highly performant, offline replay).
  * **Live Mode:** Injects actual UDP datagrams over the loopback interface using a pre-bound socket pool to prevent socket exhaustion.

## High-Level Workflow

The fuzzer operates in a continuous, automated loop governed by the main orchestrator (`main.py`):

1. **Initialization:** The orchestrator launches the target IDS (e.g., Snort 3 built with ASan) and establishes a baseline memory footprint.
2. **Seed Generation:** A valid protocol seed (e.g., a standard DNS query) is generated to serve as the structural base.
3. **Strategy Rotation & Mutation:** The engine randomly selects a weighted fuzzing strategy:
    * *Smart DNS:* Swaps fields with boundary values.
    * *Response Fuzz:* Injects deep anomaly structures (e.g., mismatched data counts, zero-length pointers).
    * *Compression/Label:* Injects cyclic loops and massive labels.
    * *State Exhaustion:* Randomizes source IPs/ports.
    * *Byte Fuzz:* Applies random bit-flips to the final byte array.
4. **Delivery:** The mutated byte payload is packed into the appropriate transport wrapper (synthetic PCAP stream with real-time clock syncing, or live UDP datagrams) and pushed to the IDS.
5. **Monitoring:** Simultaneously, the background Watchdog monitors the target. If the IDS fails to process packets for a specific duration, or if memory usage suddenly spikes, the Watchdog intervenes.
6. **Crash Handling:** If the IDS crashes (segfault, ASan violation) or is killed by the Watchdog, the fuzzer gracefully halts, captures the standard error output, and writes a forensic report to the `crashes/` directory for analysis.
