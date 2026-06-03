"""
Phase 3 & 4 of the Agentic Analysis Pipeline — Explorers & Dossier Store.

Each Explorer is an isolated, ephemeral LLM session that analyzes a small set
of code chunks retrieved via semantic search. It outputs a JSON "dossier"
containing both vulnerability findings AND extracted protocol constants.

Explorers run concurrently via ThreadPoolExecutor so the total wall-clock
time is bounded by the slowest single task, not the sum of all tasks.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from engine.llm_client import ai_call
from engine.semantic_search import query_codebase

# ---------------------------------------------------------------------------
# Explorer prompt — asks for BOTH vulns AND extracted constants
# ---------------------------------------------------------------------------
EXPLORER_PROMPT = """You are an expert security researcher analyzing a small section of a network software codebase.

You will receive source code chunks from specific functions/classes. Your job is TWO-FOLD:

## TASK 1: Find Vulnerabilities
For each vulnerability found, provide:
- function: exact function name
- line_range: approximate line range
- bug_class: heap-overflow | stack-overflow | integer-overflow | integer-underflow | oob-read | oob-write | use-after-free | null-deref | infinite-loop | format-string | race-condition | state-corruption | memory-leak
- severity: critical | high | medium | low
- reasoning: step-by-step chain of what input triggers the bug
- payload_hex: concrete byte-level payload (hex string)
- payload_description: human-readable description
- protocol: which protocol (TCP/UDP/SMTP/HTTP/FTP/DNS)
- port: target port number
- matched_strategy: which fuzzer mutation strategy best triggers this

## TASK 2: Extract Protocol Constants
Search the code for values that a fuzzer should know about:
- **magic_bytes**: hex constants compared against input (e.g., 0xDEADBEEF, magic numbers in headers)
- **buffer_sizes**: array sizes, length limits, max values used in bounds checks (e.g., `char buf[1024]`, `if (len > 8192)`)
- **commands**: string literals used in command parsing (e.g., "EHLO", "QUIT", "GET", switch/case labels)
- **string_literals**: other interesting strings (error messages, version strings, headers)
- **states**: enum values or state machine constants
- **thresholds**: rate limits, max counts, timeout values

AVAILABLE MUTATION STRATEGIES:
- cmd_overflow, header_overflow, mime_decode_bomb, mime_boundary_confusion
- data_desync, state_machine_violation, pipeline_flood, rcpt_bomb
- xlink2state, bdat_chunk, auth_overflow, starttls_evasion
- encoding_attack, command_fuzz
- uri_overflow, chunked_encoding, smuggling, method_fuzz
- header_bomb, multipart_bomb, content_length_mismatch
- path_traversal, command_injection, passive_aggressive
- smart_dns, response_fuzz, compression_loop, label_complexity, edns_exploit

Respond in valid JSON:
{
  "file_summary": "What these code chunks do",
  "vulnerabilities": [
    {
      "id": 1,
      "function": "parse_cmd",
      "line_range": "45-67",
      "bug_class": "heap-overflow",
      "severity": "critical",
      "reasoning": "Step by step...",
      "payload_hex": "414141...",
      "payload_description": "...",
      "protocol": "TCP",
      "port": 25,
      "matched_strategy": "cmd_overflow",
      "strategy_reasoning": "Why this strategy"
    }
  ],
  "extracted_constants": {
    "magic_bytes": [{"value": "0xDEADBEEF", "context": "header magic check in parse_header()"}],
    "buffer_sizes": [{"value": 1024, "context": "char buf[1024] in process_data()"}],
    "commands": [{"value": "EHLO", "context": "command dispatch in handle_cmd()"}],
    "string_literals": [{"value": "HTTP/1.1", "context": "version check"}],
    "states": [{"value": "STATE_DATA", "context": "SMTP state machine"}],
    "thresholds": [{"value": 100, "context": "max recipients in rcpt_count check"}]
  },
  "attack_chains": [
    {"description": "Multi-step attack", "steps": ["Step 1", "Step 2"]}
  ]
}

If no vulnerabilities or constants are found in a category, use an empty list [].
Be thorough but precise — only report concrete findings with evidence from the code.
"""


def _explore_single_task(task: dict,
                         collection_name: str,
                         n_chunks: int = 15) -> dict:
    """Run one Explorer agent: retrieve chunks, call LLM, return dossier.

    Args:
        task: a task dict from the Orchestrator (must have search_query, task_id, etc.)
        collection_name: ChromaDB collection to query
        n_chunks: how many chunks to retrieve per task

    Returns:
        A dossier dict with keys: task_id, description, file_summary,
        vulnerabilities, extracted_constants, attack_chains, error
    """
    task_id = task.get("task_id", "?")
    desc = task.get("description", "")
    query = task.get("search_query", desc)

    dossier = {
        "task_id": task_id,
        "description": desc,
        "file_summary": "",
        "vulnerabilities": [],
        "extracted_constants": {},
        "attack_chains": [],
        "error": None,
        "chunks_used": 0,
    }

    try:
        # Retrieve relevant code chunks from ChromaDB
        hits = query_codebase(query, n_results=n_chunks, collection_name=collection_name)
        if not hits:
            dossier["error"] = "No relevant code chunks found for this task"
            return dossier

        dossier["chunks_used"] = len(hits)

        # Build isolated context from retrieved chunks
        context_parts = []
        for h in hits:
            context_parts.append(
                f"=== {h['file']} :: {h['name']} ({h['node_type']}) "
                f"L{h['start_line']}-{h['end_line']} ===\n"
                f"{h['code']}\n"
                f"=== END {h['file']} :: {h['name']} ==="
            )
        context = "\n\n".join(context_parts)

        user_prompt = (
            f"INVESTIGATION TASK: {desc}\n\n"
            f"CODE CHUNKS ({len(hits)} chunks retrieved via semantic search):\n\n"
            f"{context}"
        )

        # Call LLM
        result, model = ai_call(EXPLORER_PROMPT, user_prompt)

        dossier["file_summary"] = result.get("file_summary", "")
        dossier["vulnerabilities"] = _extract_vulns(result)
        dossier["extracted_constants"] = result.get("extracted_constants", {})
        dossier["attack_chains"] = result.get("attack_chains", [])

        # Tag each vuln with source task
        for v in dossier["vulnerabilities"]:
            v["source_task"] = task_id

    except Exception as e:
        dossier["error"] = f"{type(e).__name__}: {e}"

    return dossier


def _extract_vulns(result: dict) -> list:
    """Pull vulnerability list from LLM response, tolerating alternate keys."""
    if not isinstance(result, dict):
        return []
    vulns = result.get("vulnerabilities", [])
    if vulns:
        return vulns
    for key, val in result.items():
        if isinstance(val, list) and val and isinstance(val[0], dict):
            if any(k in val[0] for k in ["bug_class", "severity", "function", "matched_strategy"]):
                return val
        elif isinstance(val, dict) and "vulnerabilities" in val:
            return val["vulnerabilities"]
    return []


def run_explorers(tasks: list[dict],
                  collection_name: str = "fuzzer_code_graph",
                  max_workers: int = 5,
                  n_chunks_per_task: int = 15,
                  on_progress: Optional[Callable] = None) -> list[dict]:
    """Run all Explorer agents concurrently.

    Args:
        tasks: list of task dicts from the Orchestrator
        collection_name: ChromaDB collection name
        max_workers: max concurrent LLM calls
        n_chunks_per_task: chunks to retrieve per task
        on_progress: optional callback(completed, total, dossier) for UI updates

    Returns:
        List of dossier dicts, one per task
    """
    if not tasks:
        return []

    print(f"[Explorers] Launching {len(tasks)} explorer agents (max {max_workers} concurrent)...")
    dossiers = []
    completed = 0
    workers = min(max_workers, len(tasks))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_explore_single_task, t, collection_name, n_chunks_per_task): t
            for t in tasks
        }

        for fut in as_completed(futures):
            task = futures[fut]
            dossier = fut.result()
            dossiers.append(dossier)
            completed += 1

            status = "ERROR" if dossier["error"] else f"{len(dossier['vulnerabilities'])} vulns"
            print(
                f"[Explorers]   [{completed}/{len(tasks)}] Task {dossier['task_id']}: "
                f"{status}, {len(dossier.get('extracted_constants', {}))} const categories, "
                f"{dossier['chunks_used']} chunks"
            )

            if on_progress:
                try:
                    on_progress(completed, len(tasks), dossier)
                except Exception:
                    pass

    # Sort by task_id for stable output
    dossiers.sort(key=lambda d: d.get("task_id", 0))

    total_vulns = sum(len(d["vulnerabilities"]) for d in dossiers)
    errors = sum(1 for d in dossiers if d["error"])
    print(f"[Explorers] Done: {total_vulns} total vulns, {errors} errors, {len(dossiers)} dossiers")

    return dossiers
