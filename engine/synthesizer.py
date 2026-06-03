"""
Phase 5 of the Agentic Analysis Pipeline — The Synthesizer.

Pure Python (no LLM call). Reads all Explorer dossiers and produces:
  1. Merged & deduplicated vulnerability list
  2. Mutation strategy weights (via existing deterministic formula)
  3. A master dynamic_dictionary.json of extracted protocol constants
"""

from __future__ import annotations

import json
import os
from typing import Optional


def merge_dossiers(dossiers: list[dict]) -> dict:
    """Merge all Explorer dossiers into a single unified result.

    Returns:
        {
            "vulnerabilities": [...],       # deduplicated, re-numbered
            "attack_chains": [...],
            "extracted_constants": {...},    # merged across all dossiers
            "file_summaries": {...},         # task_id -> summary
            "errors": [...],                 # tasks that failed
            "stats": {...},
        }
    """
    all_vulns = []
    all_chains = []
    all_errors = []
    file_summaries = {}

    # Merged constants: each category is a list of {value, context} dicts
    merged_constants = {
        "magic_bytes": [],
        "buffer_sizes": [],
        "commands": [],
        "string_literals": [],
        "states": [],
        "thresholds": [],
    }

    for d in dossiers:
        task_id = d.get("task_id", "?")

        if d.get("error"):
            all_errors.append({"task_id": task_id, "error": d["error"]})
            continue

        if d.get("file_summary"):
            file_summaries[task_id] = d["file_summary"]

        # Collect vulns
        for v in d.get("vulnerabilities", []):
            v = dict(v)  # shallow copy
            v["source_task"] = task_id
            all_vulns.append(v)

        # Collect attack chains
        for chain in d.get("attack_chains", []):
            chain = dict(chain)
            chain["source_task"] = task_id
            all_chains.append(chain)

        # Merge extracted constants
        ec = d.get("extracted_constants", {})
        if isinstance(ec, dict):
            for category in merged_constants:
                items = ec.get(category, [])
                if isinstance(items, list):
                    merged_constants[category].extend(items)

    # Deduplicate vulnerabilities by (function, bug_class, file-if-available)
    deduped_vulns = _dedup_vulns(all_vulns)

    # Deduplicate constants by value
    for cat in merged_constants:
        merged_constants[cat] = _dedup_constants(merged_constants[cat])

    # Re-number vulnerability IDs
    for i, v in enumerate(deduped_vulns, 1):
        v["id"] = i

    stats = {
        "total_dossiers": len(dossiers),
        "successful_dossiers": len(dossiers) - len(all_errors),
        "failed_dossiers": len(all_errors),
        "raw_vulns": len(all_vulns),
        "deduped_vulns": len(deduped_vulns),
        "attack_chains": len(all_chains),
        "constants": {cat: len(items) for cat, items in merged_constants.items()},
    }

    print(f"[Synthesizer] Merged: {stats['raw_vulns']} raw → {stats['deduped_vulns']} unique vulns, "
          f"{sum(stats['constants'].values())} constants across {len(merged_constants)} categories")

    return {
        "vulnerabilities": deduped_vulns,
        "attack_chains": all_chains,
        "extracted_constants": merged_constants,
        "file_summaries": file_summaries,
        "errors": all_errors,
        "stats": stats,
    }


def _dedup_vulns(vulns: list[dict]) -> list[dict]:
    """Deduplicate vulnerabilities by (function, bug_class) key.
    Keeps the highest-severity instance when duplicates are found."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    seen: dict[str, dict] = {}
    for v in vulns:
        key = f"{v.get('function', '?')}:{v.get('bug_class', '?')}"
        existing = seen.get(key)
        if existing is None:
            seen[key] = v
        else:
            # Keep the one with higher severity
            new_rank = severity_rank.get(v.get("severity", "low"), 0)
            old_rank = severity_rank.get(existing.get("severity", "low"), 0)
            if new_rank > old_rank:
                seen[key] = v
    return list(seen.values())


def _dedup_constants(items: list) -> list:
    """Deduplicate constant entries by their 'value' field."""
    seen = set()
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        val = str(item.get("value", ""))
        if val and val not in seen:
            seen.add(val)
            result.append(item)
    return result


def build_dynamic_dictionary(merged: dict,
                             output_path: Optional[str] = None) -> dict:
    """Build the dynamic_dictionary.json from merged extracted constants.

    This dictionary is what the fuzzer protocol generators will load at
    runtime to replace static guesses with source-code-derived values.

    Returns the dictionary dict and optionally writes it to disk.
    """
    ec = merged.get("extracted_constants", {})

    dictionary = {
        "magic_bytes": [item.get("value") for item in ec.get("magic_bytes", [])
                        if item.get("value")],
        "buffer_sizes": [],
        "commands": [item.get("value") for item in ec.get("commands", [])
                     if item.get("value")],
        "string_literals": [item.get("value") for item in ec.get("string_literals", [])
                            if item.get("value")],
        "states": [item.get("value") for item in ec.get("states", [])
                   if item.get("value")],
        "thresholds": [],
        # Keep the full context-rich version for reference
        "detailed": ec,
    }

    # Extract numeric values for buffer_sizes and thresholds
    for item in ec.get("buffer_sizes", []):
        val = item.get("value")
        if isinstance(val, (int, float)):
            dictionary["buffer_sizes"].append(int(val))
        elif isinstance(val, str):
            try:
                dictionary["buffer_sizes"].append(int(val, 0))  # handles 0x prefix
            except (ValueError, TypeError):
                pass

    for item in ec.get("thresholds", []):
        val = item.get("value")
        if isinstance(val, (int, float)):
            dictionary["thresholds"].append(int(val))
        elif isinstance(val, str):
            try:
                dictionary["thresholds"].append(int(val, 0))
            except (ValueError, TypeError):
                pass

    # Sort for determinism
    dictionary["buffer_sizes"].sort()
    dictionary["thresholds"].sort()

    if output_path is None:
        output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                   "dynamic_dictionary.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dictionary, f, indent=2, default=str)
    print(f"[Synthesizer] Wrote dynamic dictionary to {output_path} "
          f"({len(dictionary['magic_bytes'])} magic, "
          f"{len(dictionary['buffer_sizes'])} sizes, "
          f"{len(dictionary['commands'])} cmds, "
          f"{len(dictionary['string_literals'])} strings)")

    return dictionary
