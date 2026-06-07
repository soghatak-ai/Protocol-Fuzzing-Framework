"""
Phase 2 of the Agentic Analysis Pipeline — The Orchestrator.

The Orchestrator is the "Principal Engineer": it reads only the repo map
(chunk metadata — file names, function names, node types) and generates a
list of discrete investigation tasks for the Explorer agents.

It NEVER sees raw source code — only the structural skeleton.

For large codebases the repo map is split into multiple chunks, each sent
to the LLM independently, and the resulting tasks are merged & deduplicated.
"""

from __future__ import annotations
import re
import time

from engine.llm_client import ai_call

# Security-relevant patterns for prioritizing symbols in large repos
_SECURITY_PATTERNS = re.compile(
    r'parse|decode|encode|handler|process|recv|send|read|write|'
    r'buffer|alloc|free|copy|auth|login|command|packet|header|'
    r'session|state|normalize|inspect|detect|eval|exec|format|'
    r'overflow|length|size|offset|fragment|chunk|boundary',
    re.IGNORECASE
)

CHUNK_TOKEN_BUDGET = 8000  # tokens per chunk sent to the LLM

# ---------------------------------------------------------------------------
# Orchestrator prompts
# ---------------------------------------------------------------------------
ORCHESTRATOR_PROMPT = """You are a Principal Security Engineer planning a vulnerability audit of a network software codebase.

You will receive a REPO MAP CHUNK: a structured list of code symbols (functions, classes, structs) with their file paths, types, and line ranges. You do NOT have the actual source code — only the skeleton. This is ONE CHUNK of a larger codebase — focus only on what you see here.

YOUR TASK: Generate focused investigation tasks for junior security analysts (Explorer agents). Each task must be small enough that one analyst can review it using only the relevant code chunks.

For each task, provide:
1. A clear description of what to investigate
2. A semantic search query that will retrieve the relevant code from a vector database
3. The task type: "vulnerability" (find bugs), "extraction" (extract protocol constants), or "both"
4. Priority: "critical", "high", "medium", or "low"

GUIDELINES:
- Group related functions into the same task (e.g., all SMTP command parsers in one task)
- Create separate tasks for: parser functions, memory operations, protocol state machines, encoding/decoding, authentication, error handling
- For "extraction" tasks, the goal is to find: magic bytes/constants, buffer size limits, command strings, hidden features
- Generate 3-10 tasks for this chunk
- Each task should target a specific subsystem or concern

Respond in valid JSON:
{
  "chunk_summary": "Brief overview of what this chunk of the codebase covers",
  "tasks": [
    {
      "task_id": 1,
      "description": "Analyze SMTP command parsing for buffer overflows",
      "search_query": "SMTP command parser buffer memcpy strcpy",
      "task_type": "both",
      "priority": "critical",
      "target_files": ["smtp_inspect.cc", "smtp_normalize.cc"],
      "focus_symbols": ["parse_command", "normalize_header"]
    }
  ]
}
"""


def _score_symbol(c: dict) -> int:
    """Score a symbol for security relevance."""
    name = c.get("name", "")
    fname = c.get("file", "")
    score = 0
    if _SECURITY_PATTERNS.search(name):
        score += 10
    if _SECURITY_PATTERNS.search(fname):
        score += 5
    span = (c.get("end_line", 0) or 0) - (c.get("start_line", 0) or 0)
    if span > 50:
        score += 3
    if span > 200:
        score += 5
    return score


def _build_entries(chunks_metadata: list[dict]) -> list[tuple[str, str, int]]:
    """Build scored (file, line, score) entries from chunk metadata."""
    by_file: dict[str, list[dict]] = {}
    for c in chunks_metadata:
        by_file.setdefault(c["file"], []).append(c)

    all_entries = []
    for fname in sorted(by_file.keys()):
        for c in sorted(by_file[fname], key=lambda x: x.get("start_line", 0)):
            line = (f"  [{c.get('node_type', '?')}] {c.get('name', '?')}  "
                    f"L{c.get('start_line', '?')}-{c.get('end_line', '?')}  "
                    f"({c.get('language', '?')})")
            all_entries.append((fname, line, _score_symbol(c)))
    return all_entries


def _chunk_repo_map(entries: list[tuple[str, str, int]],
                    total_symbols: int,
                    total_files: int,
                    token_budget: int = CHUNK_TOKEN_BUDGET) -> list[str]:
    """Split scored entries into repo map chunks, each under token_budget.

    Entries are sorted by security relevance (highest first) so the most
    important symbols land in the earlier chunks.
    """
    sorted_entries = sorted(entries, key=lambda x: x[2], reverse=True)
    char_budget = token_budget * 4

    chunks: list[str] = []
    current_lines: list[str] = []
    current_files: set[str] = set()
    current_chars = 0

    for fname, line, _score in sorted_entries:
        entry_cost = len(line) + 1
        file_header_cost = 0
        if fname not in current_files:
            file_header_cost = len(fname) + 10

        if current_chars + entry_cost + file_header_cost > char_budget and current_lines:
            # Flush current chunk
            header = (f"REPO MAP CHUNK {len(chunks)+1} — "
                      f"{len(current_lines)} symbols from {len(current_files)} files "
                      f"(codebase total: {total_symbols} symbols, {total_files} files)\n")
            # Group by file for readability
            by_f: dict[str, list[str]] = {}
            for cl in current_lines:
                cf = cl[0]
                by_f.setdefault(cf, []).append(cl[1])
            body = [header]
            for f in sorted(by_f.keys()):
                body.append(f"\n=== {f} ===")
                body.extend(by_f[f])
            chunks.append("\n".join(body))
            current_lines = []
            current_files = set()
            current_chars = 0

        current_lines.append((fname, line))
        current_files.add(fname)
        current_chars += entry_cost + file_header_cost

    # Flush remaining
    if current_lines:
        header = (f"REPO MAP CHUNK {len(chunks)+1} — "
                  f"{len(current_lines)} symbols from {len(current_files)} files "
                  f"(codebase total: {total_symbols} symbols, {total_files} files)\n")
        by_f: dict[str, list[str]] = {}
        for cl in current_lines:
            cf = cl[0]
            by_f.setdefault(cf, []).append(cl[1])
        body = [header]
        for f in sorted(by_f.keys()):
            body.append(f"\n=== {f} ===")
            body.extend(by_f[f])
        chunks.append("\n".join(body))

    return chunks


def _dedup_tasks(all_tasks: list[dict]) -> list[dict]:
    """Deduplicate tasks by description similarity (exact match on search_query)."""
    seen_queries = set()
    deduped = []
    for t in all_tasks:
        q = t.get("search_query", "").strip().lower()
        if q and q in seen_queries:
            continue
        seen_queries.add(q)
        deduped.append(t)
    return deduped


def generate_tasks(chunks_metadata: list[dict],
                   protocol_hint: str | None = None) -> tuple[list[dict], str]:
    """Run the Orchestrator: generate investigation tasks from chunk metadata.

    For large codebases the repo map is split into chunks, each sent to the
    LLM independently, and the resulting tasks are merged & deduplicated.

    Args:
        chunks_metadata: list of dicts with keys: file, name, node_type,
                         language, start_line, end_line (no code!)
        protocol_hint: optional hint like "smtp" to focus task generation

    Returns:
        (tasks_list, codebase_summary)
    """
    entries = _build_entries(chunks_metadata)
    total_files = len({c["file"] for c in chunks_metadata})
    total_symbols = len(entries)

    # Estimate total size
    total_chars = sum(len(e[1]) + 1 for e in entries)
    est_tokens = total_chars // 4

    if est_tokens <= CHUNK_TOKEN_BUDGET:
        # Small codebase — single call
        repo_chunks = [_chunk_repo_map(entries, total_symbols, total_files,
                                       token_budget=CHUNK_TOKEN_BUDGET)[0]]
    else:
        repo_chunks = _chunk_repo_map(entries, total_symbols, total_files)

    print(f"[Orchestrator] Repo map: {est_tokens} tokens, {total_symbols} symbols, "
          f"{total_files} files → {len(repo_chunks)} chunk(s)")

    hint_suffix = ""
    if protocol_hint:
        hint_suffix = (
            f"\n\nFOCUS HINT: The user is primarily fuzzing the {protocol_hint.upper()} "
            f"protocol. Prioritize tasks related to {protocol_hint.upper()} parsing, "
            f"but do not ignore other attack surfaces."
        )

    all_tasks: list[dict] = []
    summaries: list[str] = []

    for idx, chunk_text in enumerate(repo_chunks):
        user_prompt = chunk_text + hint_suffix
        prompt_tokens = len(user_prompt) // 4
        print(f"[Orchestrator] Sending chunk {idx+1}/{len(repo_chunks)} "
              f"(~{prompt_tokens} tokens) to LLM...")

        try:
            result, model = ai_call(ORCHESTRATOR_PROMPT, user_prompt, max_tokens=16384)
        except Exception as e:
            print(f"[Orchestrator] Chunk {idx+1} failed: {type(e).__name__}: {e}")
            continue

        chunk_tasks = result.get("tasks", [])
        chunk_summary = result.get("chunk_summary", result.get("codebase_summary", ""))
        summaries.append(chunk_summary)

        # Re-number task IDs to be globally unique
        for t in chunk_tasks:
            t["task_id"] = len(all_tasks) + 1
            all_tasks.append(t)

        print(f"[Orchestrator]   Chunk {idx+1}: {len(chunk_tasks)} tasks (model: {model})")
        for t in chunk_tasks:
            print(f"    [{t.get('priority', '?')}] Task {t['task_id']}: "
                  f"{t.get('description', '')[:80]}")

        # Rate-limit courtesy pause between chunks
        if idx < len(repo_chunks) - 1:
            time.sleep(2)

    # Dedup and finalize
    tasks = _dedup_tasks(all_tasks)

    # Re-number after dedup
    for i, t in enumerate(tasks, 1):
        t["task_id"] = i

    codebase_summary = " | ".join(s for s in summaries if s)

    print(f"[Orchestrator] Total: {len(all_tasks)} raw → {len(tasks)} after dedup")
    return tasks, codebase_summary
