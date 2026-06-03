"""
Dynamic Dictionary Loader for Protocol Generators.

Loads `dynamic_dictionary.json` (produced by the agentic analysis pipeline)
and provides helper functions that protocol generators call to augment their
static payloads with source-code-derived constants.

If the dictionary file does not exist (analysis hasn't run yet), every helper
gracefully falls back to an empty list so the fuzzer still works with its
original static data.
"""

import json
import os
import random
from typing import Optional

_DICT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "dynamic_dictionary.json")

_cache: Optional[dict] = None
_cache_mtime: float = 0.0


def _load() -> dict:
    """Load and cache the dynamic dictionary, auto-refreshing on file change."""
    global _cache, _cache_mtime
    try:
        mt = os.path.getmtime(_DICT_PATH)
        if _cache is not None and mt == _cache_mtime:
            return _cache
        with open(_DICT_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
        _cache_mtime = mt
        return _cache
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def get_magic_bytes() -> list[str]:
    """Return extracted magic byte values (hex strings)."""
    return _load().get("magic_bytes", [])


def get_buffer_sizes() -> list[int]:
    """Return extracted buffer size values (integers)."""
    return _load().get("buffer_sizes", [])


def get_commands() -> list[str]:
    """Return extracted command strings."""
    return _load().get("commands", [])


def get_string_literals() -> list[str]:
    """Return extracted string literals."""
    return _load().get("string_literals", [])


def get_thresholds() -> list[int]:
    """Return extracted threshold values."""
    return _load().get("thresholds", [])


def get_states() -> list[str]:
    """Return extracted state names."""
    return _load().get("states", [])


def random_command(fallback: str = "NOOP") -> str:
    """Pick a random extracted command, or return fallback."""
    cmds = get_commands()
    return random.choice(cmds) if cmds else fallback


def random_buffer_size(fallback: int = 4096) -> int:
    """Pick a random extracted buffer size, or return fallback."""
    sizes = get_buffer_sizes()
    return random.choice(sizes) if sizes else fallback


def random_magic(fallback: bytes = b"\xDE\xAD\xBE\xEF") -> bytes:
    """Pick a random extracted magic bytes value, or return fallback.
    Tries to decode hex strings like '0xDEADBEEF' into raw bytes."""
    magics = get_magic_bytes()
    if not magics:
        return fallback
    choice = random.choice(magics)
    try:
        clean = choice.replace("0x", "").replace("0X", "").replace(" ", "")
        return bytes.fromhex(clean)
    except (ValueError, AttributeError):
        return fallback


def has_dynamic_data() -> bool:
    """Return True if a dynamic dictionary has been loaded with any data."""
    d = _load()
    return any(d.get(k) for k in ("magic_bytes", "buffer_sizes", "commands",
                                   "string_literals", "states", "thresholds"))
