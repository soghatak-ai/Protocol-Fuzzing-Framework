"""
Phase 2 of the Agentic Analysis Pipeline — The Orchestrator.

The Orchestrator is the "Principal Engineer": it reads only the repo map
(chunk metadata — file names, function names, node types) and generates a
list of discrete investigation tasks for the Explorer agents.

It NEVER sees raw source code — only the structural skeleton.
"""

from __future__ import annotations
import re

from engine.llm_client import ai_call

# Security-relevant patterns for prioritizing symbols in large repos
_SECURITY_PATTERNS = re.compile(
    r'parse|decode|encode|handler|process|recv|send|read|write|'
    r'buffer|alloc|free|copy|auth|login|command|packet|header|'
    r'session|state|normalize|inspect|detect|eval|exec|format|'
    r'overflow|length|size|offset|fragment|chunk|boundary',
    re.IGNORECASE
)

MAX_REPO_MAP_TOKENS = 50000  # ~200K chars, fits in GPT-5 context with room for response

# ---------------------------------------------------------------------------
# Orchestrator prompt
# ---------------------------------------------------------------------------
ORCHESTRATOR_PROMPT = """You are a Principal Security Engineer planning a vulnerability audit of a network software codebase.

You will receive a REPO MAP: a structured list of code symbols (functions, classes, structs) with their file paths, types, and line ranges. You do NOT have the actual source code — only the skeleton.

YOUR TASK: Generate a list of focused investigation tasks for junior security analysts (Explorer agents). Each task must be small enough that one analyst can review it using only the relevant code chunks.

For each task, provide:
1. A clear description of what to investigate
2. A semantic search query that will retrieve the relevant code from a vector database
3. The task type: "vulnerability" (find bugs), "extraction" (extract protocol constants), or "both"
4. Priority: "critical", "high", "medium", or "low"

GUIDELINES:
- Group related functions into the same task (e.g., all SMTP command parsers in one task)
- Create separate tasks for: parser functions, memory operations, protocol state machines, encoding/decoding, authentication, error handling
- For "extraction" tasks, the goal is to find: magic bytes/constants, buffer size limits, command strings, hidden features
- Aim for 10-30 tasks depending on codebase size
- Each task should target a specific subsystem or concern

Respond in valid JSON:
{
  "codebase_summary": "Brief overview of what this codebase does",
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


def build_repo_map(chunks_metadata: list[dict]) -> str:
    """Build a compact repo map string from chunk metadata for the Orchestrator.

    Each entry is one line:  FILE | TYPE | NAME | LINES
    Grouped by file for readability.

    For large codebases (>MAX_REPO_MAP_TOKENS), prioritizes security-relevant
    symbols and truncates with a summary of what was omitted.
    """
    by_file: dict[str, list[dict]] = {}
    for c in chunks_metadata:
        by_file.setdefault(c["file"], []).append(c)

    # Score each symbol for security relevance
    def _score(c: dict) -> int:
        name = c.get("name", "")
        fname = c.get("file", "")
        score = 0
        if _SECURITY_PATTERNS.search(name):
            score += 10
        if _SECURITY_PATTERNS.search(fname):
            score += 5
        # Larger functions are more interesting
        span = (c.get("end_line", 0) or 0) - (c.get("start_line", 0) or 0)
        if span > 50:
            score += 3
        if span > 200:
            score += 5
        return score

    # Build full map
    all_entries = []
    for fname in sorted(by_file.keys()):
        all_entries.append((fname, None, 0))  # file header
        for c in sorted(by_file[fname], key=lambda x: x.get("start_line", 0)):
            line = (f"  [{c.get('node_type', '?')}] {c.get('name', '?')}  "
                    f"L{c.get('start_line', '?')}-{c.get('end_line', '?')}  "
                    f"({c.get('language', '?')})")
            all_entries.append((fname, line, _score(c)))

    # Estimate total size
    total_chars = sum(len(e[1] or f"\n=== {e[0]} ===") + 1 for e in all_entries)
    est_tokens = total_chars // 4

    if est_tokens <= MAX_REPO_MAP_TOKENS:
        # Small enough — emit everything
        lines = [f"REPO MAP — {len(chunks_metadata)} symbols across {len(by_file)} files\n"]
        cur_file = None
        for fname, line, _ in all_entries:
            if line is None:
                lines.append(f"\n=== {fname} ===")
                cur_file = fname
            else:
                lines.append(line)
        return "\n".join(lines)

    # Too large — prioritize security-relevant symbols
    print(f"[Orchestrator] Repo map too large ({est_tokens} tokens, max {MAX_REPO_MAP_TOKENS}). "
          f"Prioritizing security-relevant symbols...")

    # Separate file headers from symbol entries
    symbol_entries = [(f, l, s) for f, l, s in all_entries if l is not None]
    symbol_entries.sort(key=lambda x: x[2], reverse=True)

    # Take top symbols until we fit
    selected = []
    char_budget = MAX_REPO_MAP_TOKENS * 4  # rough chars
    used_chars = 200  # header overhead
    files_seen = set()
    for fname, line, score in symbol_entries:
        entry_cost = len(line) + 1
        if fname not in files_seen:
            entry_cost += len(fname) + 10  # file header cost
        if used_chars + entry_cost > char_budget:
            break
        selected.append((fname, line, score))
        files_seen.add(fname)
        used_chars += entry_cost

    omitted = len(symbol_entries) - len(selected)

    # Rebuild map grouped by file
    by_file_selected: dict[str, list[str]] = {}
    for fname, line, _ in selected:
        by_file_selected.setdefault(fname, []).append(line)

    lines = [f"REPO MAP — {len(chunks_metadata)} symbols across {len(by_file)} files "
             f"(showing {len(selected)} most security-relevant, {omitted} omitted)\n"]
    for fname in sorted(by_file_selected.keys()):
        lines.append(f"\n=== {fname} ===")
        lines.extend(by_file_selected[fname])

    if omitted > 0:
        lines.append(f"\n[... {omitted} lower-priority symbols across "
                     f"{len(by_file) - len(files_seen)} additional files omitted ...]")

    print(f"[Orchestrator] Repo map trimmed: {len(selected)}/{len(symbol_entries)} symbols, "
          f"{len(files_seen)}/{len(by_file)} files")
    return "\n".join(lines)


def generate_tasks(chunks_metadata: list[dict],
                   protocol_hint: str | None = None) -> tuple[list[dict], str]:
    """Run the Orchestrator: generate investigation tasks from chunk metadata.

    Args:
        chunks_metadata: list of dicts with keys: file, name, node_type,
                         language, start_line, end_line (no code!)
        protocol_hint: optional hint like "smtp" to focus task generation

    Returns:
        (tasks_list, codebase_summary)
    """
    repo_map = build_repo_map(chunks_metadata)

    user_prompt = repo_map
    if protocol_hint:
        user_prompt += (
            f"\n\nFOCUS HINT: The user is primarily fuzzing the {protocol_hint.upper()} "
            f"protocol. Prioritize tasks related to {protocol_hint.upper()} parsing, "
            f"but do not ignore other attack surfaces."
        )

    print(f"[Orchestrator] Sending repo map ({len(chunks_metadata)} symbols) to LLM...")
    result, model = ai_call(ORCHESTRATOR_PROMPT, user_prompt, max_tokens=8192)

    tasks = result.get("tasks", [])
    summary = result.get("codebase_summary", "")

    print(f"[Orchestrator] Generated {len(tasks)} tasks (model: {model})")
    for t in tasks:
        print(f"  [{t.get('priority', '?')}] Task {t.get('task_id')}: {t.get('description', '')[:80]}")

    return tasks, summary
