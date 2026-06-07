import os
import re
import json
import time
import uuid
import queue
import hashlib
import traceback
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, Response, send_file, request
from openai import AzureOpenAI

try:
    from pymongo import MongoClient, DESCENDING
    _PYMONGO_AVAILABLE = True
except ImportError:
    _PYMONGO_AVAILABLE = False
from main import (fuzzer_state, event_log, reset_state, run_fuzzer, run_fuzzer_live,
                  log_event, ai_weights, DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS,
                  FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS,
                  HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS,
                  SMTP_STRATEGY_NAMES, SMTP_DEFAULT_WEIGHTS,
                  SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS,
                  SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS,
                  HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS,
                  DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS,
                  dns_bandit, ftp_bandit, http_bandit, smtp_bandit,
                  smb2_bandit, smb3_bandit, http2_bandit, dcerpc_bandit)
from protocol.ftp import FTP_STRATEGY_LABELS
from protocol.http import HTTP_STRATEGY_LABELS
from protocol.smtp import SMTP_STRATEGY_LABELS
from protocol.smb import SMB2_STRATEGY_LABELS, SMB3_STRATEGY_LABELS
from protocol.http2 import HTTP2_STRATEGY_LABELS
from protocol.dcerpc import DCERPC_STRATEGY_LABELS
from engine.code_collector import (collect_to_dict, collect_to_single_text, VALID_EXTENSIONS,
                                    minify_code, hotspot_filter, extract_repo_map,
                                    build_optimized_context, estimate_tokens)
from transport.file_sender import send_file_http, send_file_ftp, send_file_smtp, send_file_smb, send_file_http2, send_file_dcerpc
from engine.semantic_search import index_codebase, get_all_chunks
from engine.orchestrator import generate_tasks
from engine.explorers import run_explorers
from engine.synthesizer import merge_dossiers, build_dynamic_dictionary

load_dotenv()

DNS_STRATEGY_LABELS = {
    "smart_dns":          "Smart DNS",
    "response_fuzz":      "Response Fuzz",
    "compression_loop":   "Compression Loop",
    "label_complexity":   "Label Complexity",
    "edns_exploit":       "EDNS Exploit",
    "tcp_dns_segment":    "TCP Segment",
    "txt_rdata_bomb":     "TXT RDATA Bomb",
    "tcp_two_message":    "TCP Two-Message",
    "inspector_stress":   "Inspector Stress",
    "ip_defrag":          "IP Defrag Exploit",
    "back_orifice":       "Back Orifice Exploit",
    "dce_smb":            "DCE/RPC SMB Exploit",
    "dnssec_exploit":     "DNSSEC Exploit",
    "dns_dynamic_update": "DNS Dynamic Update",
    "multi_query_storm":  "Multi-Query Storm",
}

def _labels_for(protocol):
    if protocol == "ftp":
        return FTP_STRATEGY_LABELS
    if protocol == "http":
        return HTTP_STRATEGY_LABELS
    if protocol == "smtp":
        return SMTP_STRATEGY_LABELS
    if protocol == "smb2":
        return SMB2_STRATEGY_LABELS
    if protocol == "smb3":
        return SMB3_STRATEGY_LABELS
    if protocol == "http2":
        return HTTP2_STRATEGY_LABELS
    if protocol == "dcerpc":
        return DCERPC_STRATEGY_LABELS
    return DNS_STRATEGY_LABELS


def _bandit_for_proto(protocol):
    if protocol == "ftp":
        return ftp_bandit
    if protocol == "http":
        return http_bandit
    if protocol == "smtp":
        return smtp_bandit
    if protocol == "smb2":
        return smb2_bandit
    if protocol == "smb3":
        return smb3_bandit
    if protocol == "http2":
        return http2_bandit
    if protocol == "dcerpc":
        return dcerpc_bandit
    return dns_bandit


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2 GB upload limit


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "Upload too large. Maximum size is 2 GB."}), 413


SNORT_BUILD = "/Users/soghatak/snort3/build"
CRASHES_DIR = os.path.join(os.path.dirname(__file__), "crashes")
fuzzer_thread = None

# ---------------------------------------------------------------------------
# Azure OpenAI configuration
# ---------------------------------------------------------------------------
AZURE_OPENAI_ENDPOINT = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_API_KEY = os.environ.get("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_API_VERSION = os.environ.get("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
AZURE_OPENAI_MODEL = os.environ.get("AZURE_OPENAI_MODEL", "gpt-5")

# ---------------------------------------------------------------------------
# MongoDB — persistent analysis history + chat conversations
# ---------------------------------------------------------------------------
MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB = os.environ.get("MONGODB_DB", "protocol_fuzzer")
MONGODB_COLLECTION = os.environ.get("MONGODB_COLLECTION", "analyses")

_mongo_client = None
_conversations = None


def _init_mongo():
    """Connect to MongoDB (local or Atlas). Degrades gracefully if unavailable."""
    global _mongo_client, _conversations
    if not _PYMONGO_AVAILABLE:
        print("[DB] pymongo not installed — history disabled")
        return
    if not MONGODB_URI:
        print("[DB] MONGODB_URI not set — history disabled")
        return
    # Mask credentials when logging the URI
    safe_uri = MONGODB_URI
    if "@" in safe_uri:
        safe_uri = safe_uri.split("@", 1)[0].split("//", 1)[0] + "//***@" + safe_uri.split("@", 1)[1]
    is_atlas = MONGODB_URI.startswith("mongodb+srv://")
    try:
        print(f"[DB] Connecting to MongoDB{' Atlas' if is_atlas else ''}: {safe_uri}")
        _mongo_client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=8000,
            connectTimeoutMS=8000,
            appname="protocol-fuzzer",
        )
        _mongo_client.admin.command("ping")
        _conversations = _mongo_client[MONGODB_DB][MONGODB_COLLECTION]
        _conversations.create_index([("created_at", DESCENDING)])
        _conversations.create_index("codebase_hash")
        print(f"[DB] Connected to MongoDB (db={MONGODB_DB}, col={MONGODB_COLLECTION})")
    except Exception as e:
        _mongo_client = None
        _conversations = None
        print(f"[DB] MongoDB unavailable ({e}) — history disabled")


def mongo_ok():
    return _conversations is not None


def compute_codebase_hash(files: dict) -> str:
    """Deterministic SHA-256 of all file paths + contents."""
    h = hashlib.sha256()
    for path in sorted(files.keys()):
        h.update(path.encode("utf-8", errors="replace"))
        h.update(b"\x00")
        h.update(files[path].encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()


def _derive_title(files: dict) -> str:
    names = list(files.keys())
    if not names:
        return "Empty analysis"
    if len(names) == 1:
        return os.path.basename(names[0])
    tops = {n.replace("\\", "/").split("/")[0] for n in names}
    if len(tops) == 1:
        return f"{tops.pop()} ({len(names)} files)"
    return f"{os.path.basename(names[0])} +{len(names) - 1} more"


def db_create_conversation(title, codebase_hash, files, code_context, analysis):
    if not mongo_ok():
        print("[DB] create_conversation skipped — MongoDB not available")
        return None
    now = datetime.now(timezone.utc)
    # Sanitize analysis through JSON round-trip to ensure BSON compatibility
    try:
        safe_analysis = json.loads(json.dumps(analysis, default=str))
    except (TypeError, ValueError) as e:
        print(f"[DB] WARNING: analysis serialization issue: {e}")
        safe_analysis = {}
    doc = {
        "_id": uuid.uuid4().hex,
        "title": title,
        "codebase_hash": codebase_hash,
        "files": files,
        "code_context": code_context,
        "analysis": safe_analysis,
        "messages": [],
        "created_at": now,
        "updated_at": now,
    }
    try:
        _conversations.insert_one(doc)
        print(f"[DB] ✓ Conversation saved: {doc['_id']} ({title})")
        return doc["_id"]
    except Exception as e:
        print(f"[DB] create_conversation failed: {e}")
        import traceback; traceback.print_exc()
        return None


def db_list_conversations():
    if not mongo_ok():
        return []
    out = []
    try:
        cursor = _conversations.find({}, {"code_context": 0}).sort("created_at", DESCENDING)
        for d in cursor:
            analysis = d.get("analysis", {}) or {}
            out.append({
                "id": d["_id"],
                "title": d.get("title", "Untitled"),
                "created_at": d["created_at"].isoformat() if d.get("created_at") else "",
                "vulns_found": len(analysis.get("vulnerabilities", [])),
                "message_count": len(d.get("messages", [])),
            })
    except Exception as e:
        print(f"[DB] list_conversations failed: {e}")
    return out


def db_get_conversation(conv_id):
    if not mongo_ok():
        return None
    try:
        return _conversations.find_one({"_id": conv_id})
    except Exception as e:
        print(f"[DB] get_conversation failed: {e}")
        return None


def db_add_messages(conv_id, messages):
    if not mongo_ok():
        return
    try:
        _conversations.update_one(
            {"_id": conv_id},
            {"$push": {"messages": {"$each": messages}},
             "$set": {"updated_at": datetime.now(timezone.utc)}},
        )
    except Exception as e:
        print(f"[DB] add_messages failed: {e}")


def db_delete_conversation(conv_id):
    if not mongo_ok():
        return
    try:
        _conversations.delete_one({"_id": conv_id})
    except Exception as e:
        print(f"[DB] delete_conversation failed: {e}")


_init_mongo()

STRATEGY_DESCRIPTIONS = """
The fuzzer has these MUTATION STRATEGIES available. Each generates a specific type of malformed packet:

DNS STRATEGIES (used when fuzzing DNS/network inspectors):
- smart_dns: Swaps DNS header fields with boundary values (0x0000, 0xFFFF, etc.). Triggers: integer-overflow, null-deref, header-parsing bugs
- response_fuzz: Injects deep anomaly structures in DNS responses (mismatched RDLENGTH, zero-length pointers, OOB CNAME pointers). Triggers: oob-read, heap-overflow, buffer-overread
- compression_loop: Creates cyclic DNS compression pointer loops to cause infinite recursion. Triggers: infinite-loop, stack-overflow, algorithmic-complexity
- label_complexity: Generates massive DNS label floods to exhaust CPU. Triggers: algorithmic-complexity, memory-exhaustion, DoS
- edns_exploit: Crafts malformed EDNS OPT records. Triggers: oob-read, integer-overflow, heap-overflow
- tcp_dns_segment: Splits DNS-over-TCP at adversarial byte offsets to break reassembly. Triggers: oob-read, buffer-overflow, off-by-one
- txt_rdata_bomb: Oversized TXT RDATA payloads to overflow record parsing buffers. Triggers: heap-overflow, buffer-overflow
- tcp_two_message: Sends two DNS messages in one TCP segment to confuse message boundary parsing. Triggers: oob-read, buffer-overflow, state-corruption
- ip_defrag: Creates overlapping/malformed IP fragments targeting the IP defragmentation engine. Triggers: heap-overflow, oob-write, memory-corruption
- back_orifice: Sends crafted Back Orifice UDP packets (port 31337) with XOR-encrypted payloads. Triggers: oob-read, integer-underflow, heap-overflow
- dce_smb: Sends malformed DCE/RPC over SMB (TCP port 445) with crafted NetBIOS+SMB headers. Triggers: oob-read, heap-overflow, pointer-arithmetic bugs
- inspector_stress: Randomizes source IPs/ports to force massive concurrent session tracking. Triggers: memory-leak, state-table-exhaustion, DoS
- dnssec_exploit: Crafts malformed DNSSEC records (RRSIG OOB signer names, NSEC3 hash overflow, DNSKEY flag exploits, NSEC bitmap overflow). Triggers: oob-read, heap-overflow, buffer-overread
- dns_dynamic_update: Sends DNS UPDATE (RFC 2136) packets with malformed zone/prereq/update sections, forged TSIG records. Targets rarely-exercised opcode=5 parser path. Triggers: oob-read, state-corruption, integer-overflow
- multi_query_storm: Multiple questions per packet with conflicting/unusual types (CHAOS class, OPT-in-question, root-label floods). Triggers: type-confusion, oob-read, algorithmic-complexity

FTP STRATEGIES (used when fuzzing FTP inspectors):
- cmd_overflow: Sends oversized FTP commands (USER/PASS/RETR) to overflow command parsing buffers. Triggers: stack-overflow, heap-overflow, buffer-overflow
- port_bomb: Floods with malformed PORT commands with invalid IP/port values. Triggers: memory-leak, integer-overflow, state-exhaustion
- pipelined_auth: Sends rapid pipelined AUTH sequences to confuse state machines. Triggers: state-corruption, use-after-free, race-condition
- cwd_depth: Deeply nested CWD commands to exhaust path traversal logic. Triggers: stack-overflow, algorithmic-complexity, DoS
- epsv_eprt_mix: Mixes EPSV and EPRT commands to confuse extended passive/active mode handling. Triggers: state-corruption, null-deref
- stray_commands: Sends unexpected/invalid FTP commands mid-session. Triggers: state-corruption, null-deref, use-after-free
- boundary_port: PORT commands with boundary values (0, 255, 65535). Triggers: integer-overflow, integer-underflow, oob-write
- oversized_site: Oversized SITE command arguments. Triggers: format-string, heap-overflow, buffer-overflow
- encoding_attack: Null bytes, UTF-8 BOM, overlong UTF-8, backslash confusion, Telnet IAC sequences in FTP stream. Targets command normalization. Triggers: evasion, oob-read, state-corruption
- rest_overflow: REST command with boundary integer values (LLONG_MAX, negative, sequential overflow). Targets file position tracking. Triggers: integer-overflow, integer-underflow, oob-write
- data_channel_confusion: Rapid PASV/PORT mode switching, simultaneous transfers, aborted transfers. Targets data channel state tracking. Triggers: use-after-free, state-corruption, memory-leak
- feat_negotiate: AUTH TLS cleartext evasion, FEAT floods, OPTS overflow, rapid mode switching. Targets feature negotiation state. Triggers: evasion, state-corruption, buffer-overflow

HTTP STRATEGIES (used when fuzzing HTTP inspectors, e.g. Snort 3 http_inspect):
- method_overflow: Valid method but colossal URI/query/path-segment counts. Overflows request-line field allocation and URI normalization buffers. Triggers: buffer-overflow, heap-overflow, oob-write
- header_bomb: Thousands of headers, one giant header value/name, or duplicate headers. Exhausts the header field table. Triggers: memory-exhaustion, heap-overflow, oob-write
- chunked_confusion: Malformed Transfer-Encoding chunked bodies (oversized/overflowing chunk-size hex, chunk extensions, size/data mismatch, missing terminators, bare-LF). Targets the dechunker. Triggers: integer-overflow, oob-read, buffer-overflow
- request_smuggling: CL.TE / TE.CL desync and obfuscated Transfer-Encoding/Content-Length (duplicate, space-before-colon, tab, conflicting values). Targets boundary reconciliation. Triggers: state-corruption, request-smuggling, oob-read
- uri_evasion: URI normalization bypasses (double percent-encoding, overlong UTF-8, dot-segment floods, null-byte, backslash, IIS unicode). Targets the URI normalizer. Triggers: evasion, oob-read, buffer-overflow
- pipeline_flood: Hundreds of pipelined requests in one TCP session. Stresses per-transaction state tracking and message-boundary detection. Triggers: state-corruption, memory-leak, use-after-free
- header_folding: Obsolete line folding, bare CR, bare LF, mixed line endings, leading whitespace. Targets header line reassembly. Triggers: state-corruption, oob-read, evasion
- version_confusion: Malformed HTTP versions (HTTP/0.9, HTTP/9.9, overflowing minor, extra dots, missing version, leading zeros). Targets version parser. Triggers: integer-overflow, null-deref, state-corruption
- content_length_attack: Content-Length integer torture (huge, negative, plus-sign, hex, leading zeros, whitespace, conflicting). Targets body-length tracking. Triggers: integer-overflow, integer-underflow, oob-write
- multipart_boundary: multipart/form-data boundary parser stress (missing close, oversized boundary, nested, many parts, invalid boundary chars). Triggers: oob-read, buffer-overflow, state-corruption
- gzip_bomb: Content-Encoding decompression attacks (compression bomb, malformed gzip, lying encoding, double gzip). Targets the decompressor. Triggers: memory-exhaustion, oob-write, heap-overflow
- absolute_uri_confusion: Absolute-form/authority-form targets, embedded credentials, multiple/oversized Host headers, junk host ports. Targets URI host reconciliation. Triggers: state-corruption, oob-read, evasion
- method_fuzz: RFC2616 §9 request methods and their specific rules — OPTIONS * / OPTIONS uri, real CONNECT authority-form (host:port, incl. junk port), TRACE/HEAD with illegal bodies, body-bearing PUT/DELETE, lowercase/mixed-case/unknown/oversized method tokens, tab/multi-space/leading-space method-URI separators, missing URI, extra request-line field. Targets the request-line/method parser and per-method handling. Triggers: state-corruption, oob-read, buffer-overflow, evasion
- header_field_fuzz: RFC2616 §14 parser-relevant request headers — Range (basic/overlapping/huge/negative/suffix/thousands), If-Range, Content-Range, Expect 100-continue/unknown, TE with q-values, Trailer in a chunked body, Connection+Upgrade negotiation, base64 Authorization (huge/invalid), Accept-Encoding with thousands of q-codings, Cache-Control integer/overflow directives, huge Max-Forwards. Targets range reassembly, header-value parsing, integer fields, base64 decode. Triggers: integer-overflow, oob-read, buffer-overflow, state-corruption

HTTP RESPONSE STRATEGIES (server->client; model the HTTP Evader "semantic gap" evasions — they target how http_inspect parses RESPONSES and extracts the body for inspection, where a mismatch vs the browser lets payload slip through):
- resp_http09: HTTP/0.9 response — bare body, no status line/headers, ended by TCP close. Targets response classification / EOF body handling. Triggers: evasion, state-corruption, oob-read
- resp_deflate_ambiguity: Content-Encoding: deflate as raw RFC1951 vs zlib RFC1950 vs gzip-mislabelled vs truncated vs x-deflate. Targets the inflate path. Triggers: oob-read, decompression-bypass, integer-overflow
- resp_chunked_evasion: response chunked tricks — TE+Content-Length (incl. double CL), HTTP/1.0+chunked, duplicate/triple Transfer-Encoding, value fuzzing (xchunked / "x chunked" / "chunked foo" / mixed-case chUnked / "chunked;"), CR-based hiding (TE:<CR>chunked, chunked<CR>SP), CRLF-fold inside the value token, chunked declared via Content-Encoding, chunk extensions, chunk-size 0x/negative/leading-ws/caps. Targets the response dechunker and TE header parsing. Triggers: integer-overflow, oob-read, evasion, request-smuggling
- resp_double_encoding: stacked/odd Content-Encoding — deflate+gzip, deflate+deflate, gzip+gzip, two headers, gzip-header-over-zlib-body, identity stacked/alone, "gzip," trailing comma, declared-double-but-served-single, declared-vs-served wrong order, and bare-LF/CR X-Foo header injected between two CE headers. Targets multi-layer decompression (devices decompress once / trust the headers). Triggers: decompression-bypass, oob-read, resource-exhaustion
- resp_gzip_quirks: gzip with bad CRC32/ISIZE, truncated trailer (last 4/8 bytes), reserved FLG bits, FNAME/FCOMMENT/FTEXT, bad FHCRC, raw data appended after the gzip stream. Targets gzip header/trailer parsing. Triggers: oob-read, oob-write, decompression-bypass
- resp_whitespace_evasion: response header white-space — obsolete folding, LF-only folding, bare LF, bare CR separator, leading blank line, space before status line, space before colon. Targets response header line parsing. Triggers: state-corruption, oob-read, evasion
- resp_lucky_status: unusual/invalid status codes (100, 3xx w/o Location, 401/407 w/o auth, 5xx, 0200, 2, 20x, 2xx, 000, 600). Targets status-line parsing and "only 2xx has a body" assumptions. Triggers: state-corruption, integer-overflow, evasion
- resp_nul_injection: control-character obfuscation in the response status line / field names / values — NUL, VT (\\x0b), FF (\\x0c), Latin-1 NBSP (\\xa0), DEL (\\x7f), UTF-8 BOM/NBSP — around the colon, inside/around the value, plus junk/control-only lines before the real Transfer-Encoding header. Targets control-char handling in header parsing. Triggers: oob-read, state-corruption, evasion
- resp_version_confusion: response version robustness (http/1.1 lowercase, HTTP/2.0, HTTP/1.2, HTTP/1.01, HTTP/1.010, junk after version, hTTp, ICY). Targets status-line version parsing and chunked-applicability. Triggers: integer-overflow, state-corruption, evasion
- resp_header_end: header-terminator variants (\\n\\n, SP/TAB in the empty line, \\n\\r\\r\\n, double colon Transfer-Encoding::chunked). Targets header/body boundary detection. Triggers: oob-read, state-corruption, evasion
- resp_content_length: response Content-Length parsing tricks — double/half declared length, junk around the value (;/,/quotes/leading-trailing alpha/space/NBSP), decimals, NUL inside, hex (0x), uint32 overflow, >64bit huge, 1GB, 1000-zero padding, empty, invalid. Body has trailing junk past the declared length. Targets body-length tracking and body boundary. Triggers: integer-overflow, integer-underflow, oob-read, evasion

SMB2 STRATEGIES (used when fuzzing SMBv2 inspectors, e.g. Snort 3 dce_smb — targets SMBv2 on port 445):
- negotiate_confusion: Dialect negotiation attacks — huge dialect lists (500+), invalid dialect values (0x0000/0xFFFF), SMBv1 NEGOTIATE after SMBv2, SMB 3.1.1 negotiate context overflow, duplicate dialects. Targets version tracking and dialect selection. Triggers: buffer-overflow, state-corruption, oob-write
- header_manipulation: SMB2 64-byte header field corruption — wrong protocol magic bytes, StructureSize != 64, CreditCharge/CreditRequest at 0xFFFF, all reserved flags set, command codes beyond OPLOCK_BREAK, MessageId at max 64-bit. Targets header parser field validation and command dispatch. Triggers: integer-overflow, oob-read, null-deref
- compound_abuse: SMB2 compound/chained request attacks — circular NextCommand offsets (self-referential), 500+ deep compound chains, overlapping NextCommand offsets, NextCommand past packet boundary, RELATED flag with mismatched SessionId/TreeId, zero-body compounds. Targets message boundary tracking. Triggers: infinite-loop, oob-read, heap-overflow
- netbios_desync: NetBIOS session layer framing attacks — length >> actual payload (50KB mismatch), zero-length messages, max length (16MB), multiple SMB messages in single NetBIOS frame, SMB header split across two NetBIOS frames, keepalive (0x85) injection between messages. Targets TCP reassembly and length-field parsing. Triggers: oob-read, buffer-overflow, state-corruption
- session_state_attack: State machine violations — TREE_CONNECT before NEGOTIATE, double NEGOTIATE, SESSION_SETUP without NEGOTIATE, TREE_CONNECT with SessionId=0, commands after LOGOFF, random 8-byte SessionIds. Targets session/tree state tracking. Triggers: state-corruption, use-after-free, null-deref
- tree_path_overflow: TREE_CONNECT UNC path attacks — 60KB paths, dot-dot traversal, null bytes in path, Unicode surrogates/non-BMP/BIDI markers, IPC$ traversal to admin$, empty paths. Targets UNC path parsing and buffer allocation. Triggers: buffer-overflow, heap-overflow, evasion
- create_fuzz: CREATE request attacks — 64KB filenames, 100+ CREATE_CONTEXT entries with oversized data, DesiredAccess=0xFFFFFFFF, duplicate LeaseKey across files, conflicting CreateOptions, oversized Extended Attributes. Targets file handle allocation and name parsing. Triggers: heap-overflow, oob-write, memory-exhaustion
- read_write_overflow: READ/WRITE buffer management attacks — ReadLength=0xFFFFFFFF (4GB), WriteOffset at max signed 64-bit, CreditCharge not matching payload size, zero-length write with data present, RDMA channel field confusion, 1000+ rapid WRITE flood. Targets data transfer buffer management. Triggers: integer-overflow, oob-write, memory-exhaustion
- dce_pipe_attack: DCE/RPC over named pipes (IPC$) — BIND with 200+ context items, fragment length 0xFFFF, AUTH3 with 60KB auth blob, CallID=0xFFFFFFFF, 100 nested BINDs, rapid ALTER_CONTEXT switching. Targets RPC parsing and context management. Triggers: heap-overflow, oob-read, state-corruption
- ioctl_attack: IOCTL/FSCTL dispatch attacks — non-existent FSCTL codes (0xDEADBEEF), FSCTL_PIPE_TRANSCEIVE with 60KB data, corrupted FSCTL_VALIDATE_NEGOTIATE_INFO, FSCTL_DFS_GET_REFERRALS with 60KB path, FSCTL_SRV_COPYCHUNK with invalid offsets, FSCTL_LMR_REQUEST_RESILIENCY with corrupt timeouts. Targets control code dispatch and buffer handling. Triggers: oob-read, heap-overflow, integer-overflow
- oplock_lease_flood: Oplock/Lease mechanism attacks — oplock break with unknown level (0xFF), lease break for non-existent LeaseKey, rapid CREATE+CLOSE oplock cycle (500+), conflicting lease states, break acknowledgment without pending break, mixed v1/v2 lease contexts. Targets lock tracking and break handling. Triggers: state-corruption, use-after-free, null-deref
- multi_protocol_evasion: Protocol confusion/evasion — SMBv1 header + SMBv2 body, interleaved SMBv1/SMBv2 headers, HTTP request on port 445, protocol ID switch mid-stream, random bytes before NEGOTIATE, TLS ClientHello wrapping SMB. Targets protocol identification and dispatch. Triggers: evasion, state-corruption, oob-read
- query_info_overflow: QUERY_INFO/SET_INFO attacks — invalid InfoType/FileInfoClass combinations, OutputBufferLength=0xFFFFFFFF, oversized security descriptor in SET_INFO, oversized EA list, corrupt quota data, boundary buffer lengths (0, 1, 0xFFFF, 0xFFFFFFFF). Targets info class dispatch and buffer handling. Triggers: integer-overflow, oob-read, heap-overflow

SMB3 STRATEGIES (used when fuzzing SMBv3 inspectors — targets SMBv3 encryption/compression/signing on port 445):
- negotiate_confusion: SMB3 dialect negotiation attacks — SMB 3.1.1 negotiate context overflow with oversized preauth/encryption contexts, context type 0xFFFF with 8KB data, duplicate 3.x dialects. Targets SMB3-specific version negotiation. Triggers: buffer-overflow, state-corruption, oob-write
- signing_evasion: Signing/integrity manipulation — corrupted 16-byte signature, unsigned message mid-signed session, preauth integrity hash tampering, wrong signing algorithm (AES-CMAC vs HMAC-SHA256), signed packet replay with different command. Targets authentication and integrity verification. Triggers: evasion, state-corruption, authentication-bypass
- transform_header_attack: SMB3 encryption transform header attacks — invalid transform signature (0xFD'SMX'), all-0xFF nonce, OriginalMessageSize mismatch, non-negotiated cipher algorithm, double-wrapped transform, SMBv1 packet inside SMBv3 transform envelope. Targets decryption engine. Triggers: oob-read, heap-overflow, state-corruption
- compression_attack: SMB3 compression transform attacks — invalid compression algorithm ID, decompression bomb (tiny compressed → huge output), chained compression with offset past buffer, PATTERN_V1 with invalid pattern, OriginalCompressedSegmentSize=0xFFFFFFFF, LZ77 data with match offset before buffer start. Targets decompression engine. Triggers: memory-exhaustion, oob-read, heap-overflow
- multi_protocol_evasion: Protocol confusion/evasion — SMBv1 header + SMBv2 body, interleaved SMBv1/SMBv2 headers, HTTP request on port 445, protocol ID switch mid-stream, random bytes before NEGOTIATE, TLS ClientHello wrapping SMB. Targets protocol identification and dispatch. Triggers: evasion, state-corruption, oob-read

HTTP/2 STRATEGIES (used when fuzzing HTTP/2 inspectors, e.g. Snort 3 http2_inspect — binary framing + HPACK on port 80/443):
- hpack_state_desync: HPACK dynamic table desync — rapid table size updates (0→4096→0→65536), integer overflow in variable-length encoding (20 continuation bytes), out-of-bounds index references (index 200 on empty table), eviction boundary races, invalid Huffman padding, bomb entries (16KB values). Targets HPACK decoder state. Triggers: oob-read, compression-error, state-corruption, heap-overflow
- continuation_flood: CVE-2024-27316 pattern — HEADERS without END_HEADERS + many CONTINUATION frames (500 tiny/200 medium/1000 empty), never-ending CONTINUATIONs, illegal interleave (DATA mid-CONTINUATION). Targets header block reassembly buffer. Triggers: memory-exhaustion, oob-read, state-corruption
- stream_interleave_evasion: Spread payloads across 50 interleaved streams round-robin, use near-max stream IDs (0x7FFFFFFE), rapid open+RST_STREAM (200 streams), DATA before HEADERS, stream ID reuse. Targets per-stream state tracking. Triggers: state-corruption, use-after-free, memory-exhaustion
- settings_manipulation: SETTINGS abuse — MAX_FRAME_SIZE=2^24-1 + oversized DATA, rapid HEADER_TABLE_SIZE toggle, INITIAL_WINDOW_SIZE=2^31-1 + WINDOW_UPDATE overflow, unknown settings (0xFF/0xFFFF), non-multiple-of-6 payload, 500-frame flood. Targets parameter tracking. Triggers: integer-overflow, state-corruption, resource-exhaustion
- pseudo_header_smuggling: HTTP/2 semantic reconstruction attacks — duplicate :path (which does IDS use?), pseudo-headers after regular headers, uppercase field names, :authority vs Host mismatch, missing :method, prohibited Connection/TE/Upgrade headers, URL-encoded/null-byte/traversal :path values. Targets request reconstruction. Triggers: evasion, state-corruption, oob-read
- unknown_frame_injection: Unknown frame types (0x0A–0xFF) injected between valid frames — between HEADERS and DATA, 50KB unknown payload, zero-length unknowns, all 246 undefined types. Tests length-based frame skipping alignment. Triggers: state-corruption, oob-read, evasion
- flow_control_evasion: Flow control window manipulation — 100KB DATA exceeding 65535 window, zero-increment WINDOW_UPDATE (PROTOCOL_ERROR), SETTINGS reducing INITIAL_WINDOW_SIZE causing negative windows, 2000 1-byte DATA frames, DATA with max padding (255 bytes). Targets flow control accounting. Triggers: integer-overflow, oob-write, state-corruption
- goaway_desync: GOAWAY then continue sending frames (IDS may stop tracking), increasing last-stream-id (prohibited), 50KB debug data overflow, 100 rapid GOAWAYs, GOAWAY on non-zero stream. Targets connection lifecycle. Triggers: evasion, state-corruption, oob-read
- priority_tree_attack: Dependency tree abuse — self-dependency (stream depends on itself), 500-deep chains, 200 exclusive deps restructuring entire tree, weight=0 (invalid), PRIORITY on never-opened streams. Targets priority processing (deprecated but still parsed). Triggers: infinite-loop, memory-exhaustion, state-corruption
- push_promise_confusion: Client sending PUSH_PROMISE (server-only), odd promised stream ID (must be even), PUSH_PROMISE on closed/RST streams, push after SETTINGS_ENABLE_PUSH=0, reuse same promised stream ID 10 times. Targets server push state. Triggers: state-corruption, oob-read, null-deref
- data_padding_evasion: DATA/HEADERS padding extraction — max 255-byte padding with hidden payload, padding length exceeding frame payload (PROTOCOL_ERROR → OOB-read), padded HEADERS, alternating padded/unpadded DATA, padding-only DATA (no actual content). Targets padding subtraction logic. Triggers: oob-read, oob-write, integer-underflow
- rst_stream_race: Race condition attacks — HEADERS+DATA+RST_STREAM in rapid succession (IDS may discard before inspecting), HEADERS without END_HEADERS then RST, RST on idle/closed streams, 100 streams opened with DATA then immediately cancelled. Targets stream cleanup vs inspection lifecycle. Triggers: use-after-free, evasion, state-corruption
- preface_manipulation: Connection preface attacks — truncated magic (12 bytes only), junk before preface, HTTP/1.1 Upgrade then h2 preface, single-byte preface corruption, double SETTINGS after preface. Targets protocol detection/classification. Triggers: evasion, state-corruption, oob-read
- header_block_fragmentation: HPACK header block split at adversarial boundaries — 1-byte CONTINUATION fragments, split mid-integer encoding, split mid-string literal, 30KB header block across 150 CONTINUATIONs, random-sized fragments (1-300 bytes). Targets HPACK partial-state buffering. Triggers: oob-read, state-corruption, buffer-overflow

DCE/RPC STRATEGIES (used when fuzzing DCE/RPC inspectors, e.g. Snort 3 dce_tcp / dce_smb — CO protocol on port 135/445):
- bind_flood: BIND PDU attacks — 200+ context elements exhausting context table, oversized context list with 50 transfer syntaxes, max_xmit_frag=0xFFFF/max_recv=0, 100 rapid re-BINDs, circular abstract syntax references, zero-context BIND. Targets BIND processing and context allocation. Triggers: memory-exhaustion, state-corruption, oob-write
- frag_reassembly_attack: Fragment reassembly attacks — overlapping fragments (500-byte overlap), out-of-order delivery (last before first), 50 FIRST_FRAG without LAST_FRAG (hangs reassembly), zero-length fragments (header only), frag_length=0xFFFF mismatch, 500-fragment bomb with unique call_ids. Targets PDU reassembly engine. Triggers: oob-read, heap-overflow, memory-exhaustion
- ptype_confusion: PDU type confusion — undefined PTYPE values (20-255), client sending server-only PDUs (BIND_ACK, RESPONSE, SHUTDOWN), PTYPE=0xFF with large body. Targets PTYPE dispatch and validation. Triggers: state-corruption, oob-read, null-deref
- auth_verifier_overflow: Authentication verifier attacks — 60KB AUTH3 credentials blob, invalid auth_type=0xFF, auth_length header/actual mismatch (claims 5000, actual 50), auth_pad_length=255, oversized NTLMSSP NEGOTIATE (60KB domain/workstation), fake Kerberos AP-REQ with huge ticket. Targets auth verifier parsing. Triggers: heap-overflow, oob-read, integer-overflow
- context_negotiation_abuse: Presentation context negotiation attacks — duplicate context_ids (3 contexts all id=0), unknown/garbage transfer syntax UUIDs, 255 context elements (uint8 max), same abstract syntax with conflicting versions, NDR32/NDR64 transfer syntax mixing. Targets context table management. Triggers: state-corruption, oob-write, type-confusion
- stub_data_overflow: Stub data and NDR format attacks — 60KB stub data, alloc_hint=4 but 10KB actual stub (mismatch), NDR conformant array with max_count=0xFFFFFFFF, NDR varying string with actual_count=50000 but only 200 bytes, dynamic commands from target analysis, empty stub (0 bytes). Targets stub data extraction and NDR parsing. Triggers: heap-overflow, oob-read, integer-overflow
- alter_context_race: ALTER_CONTEXT state attacks — ALTER_CONTEXT without prior BIND, 100 rapid ALTER_CONTEXTs with random UUIDs, ALTER_CONTEXT interleaved between request fragments, interface switching (EPM→SAMR) mid-session, context_id=0xFFFF. Targets context switching and state machine. Triggers: state-corruption, use-after-free, null-deref
- cl_header_manipulation: Connectionless (CL) header attacks — invalid rpc_vers (0xFF instead of 4), frag_num=0xFFFF, ahint=0 (body length hint mismatch), max serial numbers (255/255), 50 requests with same activity UUID but different opnums. Targets CL header parsing. Triggers: oob-read, integer-overflow, state-corruption
- endian_drep_confusion: Data representation (DREP) confusion — big-endian DREP with little-endian body, mixed character/float encoding flags, all-0xFF DREP, DREP switch between fragments (LE first, BE second), EBCDIC character encoding flag. Targets byte-order interpretation. Triggers: integer-overflow, oob-read, state-corruption
- opnum_dispatch_fuzz: Operation number dispatch attacks — opnum=0xFFFF, sequential opnums 0-99, opnum=0 with 40KB stub, REQUEST with PFC_OBJECT_UUID flag + random UUID, rapid opnum switching between 0/5/15/31/0xFFFF. Targets opnum dispatch table and stub routing. Triggers: oob-read, null-deref, state-corruption
- cancel_orphan_attack: CO_CANCEL/ORPHANED attacks — CO_CANCEL without pending request, 100 ORPHANED PDUs for non-existent call_ids, request then immediate cancel+orphan, interleaved requests with random cancels/orphans. Targets call lifecycle management. Triggers: use-after-free, state-corruption, null-deref
- record_marking_desync: TCP Record Marking (RM) attacks — RM length=0x7FFFFFFF (2GB claim), split RM header across segments, zero-length RM record, max-length RM but only 100 bytes sent, single PDU split across multiple RM records. Targets TCP framing and reassembly. Triggers: oob-read, integer-overflow, buffer-overflow
- multi_bind_ack_confusion: BIND/BIND_ACK state confusion — BIND on ctx 0 then REQUEST on ctx 99, BIND with EPM+SRVSVC+SAMR simultaneously, client spoofing BIND_ACK, double BIND for different interfaces, BIND_NAK then REQUEST anyway. Targets connection state tracking. Triggers: state-corruption, oob-read, use-after-free
- uuid_manipulation: Interface UUID manipulation — all-zero UUIDs, all-0xFF UUIDs, 20 random high-entropy UUIDs, known UUIDs with wrong versions (0 and 0xFFFF), same UUID repeated 50 times. Targets UUID matching and interface lookup. Triggers: state-corruption, oob-read, null-deref
"""

# ---------------------------------------------------------------------------
# PASS 1: HUNTER — finds all potential vulnerabilities (no weights)
# ---------------------------------------------------------------------------
HUNTER_PROMPT = """You are an expert security researcher specializing in memory corruption vulnerabilities in C/C++ network software.

You will be given source code file(s) from a network intrusion detection system (IDS).

YOUR ONLY TASK: Find ALL potential vulnerabilities. Do NOT compute weights — that will be done later.

For each vulnerability found, provide:
  - The exact function name and line range
  - The bug class: heap-overflow | stack-overflow | integer-overflow | integer-underflow | oob-read | oob-write | use-after-free | null-deref | infinite-loop | format-string | race-condition | state-corruption | memory-leak
  - A step-by-step reasoning chain: what input → what code path → what goes wrong
  - A concrete byte-level payload (hex string) that triggers it
  - The severity: critical | high | medium | low
    (critical = RCE/arbitrary write; high = crash/DoS; medium = info leak; low = minor)
  - Protocol and port the payload should be sent on
  - Which mutation strategy from the list below BEST triggers this vulnerability

Be thorough but precise:
- Do NOT report theoretical bugs guarded by runtime checks
- Only report bugs where you can construct a concrete input that reaches the vulnerable code
- Pay attention to the GAP between validation and the dangerous operation
- Consider multi-packet stateful attacks

AVAILABLE MUTATION STRATEGIES:
""" + STRATEGY_DESCRIPTIONS + """

Respond in valid JSON:
{
  "file_summary": "What this code does",
  "vulnerabilities": [
    {
      "id": 1,
      "function": "function_name",
      "line_range": "100-120",
      "bug_class": "heap-overflow",
      "severity": "critical",
      "reasoning": "Step-by-step chain...",
      "payload_hex": "deadbeef...",
      "payload_description": "Human-readable payload description",
      "protocol": "UDP",
      "port": 31337,
      "preconditions": "Setup needed",
      "matched_strategy": "back_orifice",
      "strategy_reasoning": "Why this strategy triggers it"
    }
  ],
  "attack_chains": [
    {
      "description": "Multi-step attack",
      "steps": ["Step 1", "Step 2"]
    }
  ]
}

If no exploitable vulnerabilities are found:
{
  "file_summary": "...",
  "vulnerabilities": [],
  "attack_chains": [],
  "notes": "Why the code appears safe"
}
"""



# ---------------------------------------------------------------------------
# TRIAGE: MAP PROMPT — picks riskiest files from repo map
# ---------------------------------------------------------------------------
MAP_PROMPT = """You are an expert security researcher triaging a large C/C++ codebase for vulnerability analysis.

You will receive a REPO MAP: a list of source files with their function signatures and struct declarations.

Your task: Select the TOP 20 files most likely to contain exploitable vulnerabilities.

Prioritize files that have:
1. Functions handling raw network input (recv, read, packet parsing)
2. Memory operations without obvious bounds checking (memcpy, strcpy, sprintf with pointer params)
3. Buffer manipulation, pointer arithmetic, or manual memory management
4. Protocol parsers, decoders, or inspectors
5. Functions with size/length parameters that could overflow

DO NOT select:
- Test files, build scripts, or configuration files
- Files with only simple getters/setters or logging
- Files that are clearly auto-generated

Respond in valid JSON:
{
  "selected_files": [
    {
      "path": "relative/path/to/file.c",
      "risk_reason": "Brief reason why this file is risky"
    }
  ],
  "summary": "Brief overview of the codebase and its attack surface"
}
"""

# ---------------------------------------------------------------------------
# DETERMINISTIC PYTHON WEIGHER — no LLM involved
# ---------------------------------------------------------------------------
SEVERITY_MULTIPLIERS = {
    "critical": 5.0,
    "high":     3.0,
    "medium":   2.0,
    "low":      1.5,
}

def compute_weights_from_vulns(verified_vulns):
    """Deterministic weight computation from verified vulnerabilities.
    Returns (dns_weights, ftp_weights, http_weights, smtp_weights, smb2_weights, smb3_weights, http2_weights, dcerpc_weights, reasoning_str)."""

    # Start with default weights
    dns_w = dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS))
    ftp_w = dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS))
    http_w = dict(zip(HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS))
    smtp_w = dict(zip(SMTP_STRATEGY_NAMES, SMTP_DEFAULT_WEIGHTS))
    smb2_w = dict(zip(SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS))
    smb3_w = dict(zip(SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS))
    http2_w = dict(zip(HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS))
    dcerpc_w = dict(zip(DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS))

    reasoning_lines = ["Weight computation (deterministic formula):"]
    reasoning_lines.append(f"  Starting from default weights. {len(verified_vulns)} verified vulnerabilities.")

    # Apply multipliers
    for v in verified_vulns:
        strat = v.get("matched_strategy", "")
        sev = v.get("severity", "medium").lower()
        mult = SEVERITY_MULTIPLIERS.get(sev, 1.5)
        conf = v.get("confidence", 80) / 100.0  # scale multiplier by confidence

        effective_mult = 1.0 + (mult - 1.0) * conf
        func = v.get("function", "?")

        if strat in dns_w:
            old = dns_w[strat]
            dns_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  DNS/{strat}: {old:.4f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {dns_w[strat]:.4f}")
        elif strat in ftp_w:
            old = ftp_w[strat]
            ftp_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  FTP/{strat}: {old:.1f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {ftp_w[strat]:.1f}")
        elif strat in http_w:
            old = http_w[strat]
            http_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  HTTP/{strat}: {old:.1f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {http_w[strat]:.1f}")
        elif strat in smtp_w:
            old = smtp_w[strat]
            smtp_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  SMTP/{strat}: {old:.1f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {smtp_w[strat]:.1f}")
        elif strat in smb2_w:
            old = smb2_w[strat]
            smb2_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  SMB2/{strat}: {old:.1f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {smb2_w[strat]:.1f}")
            if strat in smb3_w:
                old3 = smb3_w[strat]
                smb3_w[strat] = old3 * effective_mult
        elif strat in smb3_w:
            old = smb3_w[strat]
            smb3_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  SMB3/{strat}: {old:.1f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {smb3_w[strat]:.1f}")
        elif strat in http2_w:
            old = http2_w[strat]
            http2_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  HTTP2/{strat}: {old:.1f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {http2_w[strat]:.1f}")
        elif strat in dcerpc_w:
            old = dcerpc_w[strat]
            dcerpc_w[strat] = old * effective_mult
            reasoning_lines.append(
                f"  DCERPC/{strat}: {old:.1f} × {effective_mult:.2f} "
                f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {dcerpc_w[strat]:.1f}")
        else:
            reasoning_lines.append(f"  WARNING: strategy '{strat}' not recognized, skipping")

    # Normalize DNS to sum=1.0
    dns_total = sum(dns_w.values())
    if dns_total > 0:
        dns_w = {s: round(v / dns_total, 4) for s, v in dns_w.items()}
    reasoning_lines.append(f"  DNS normalized (sum was {dns_total:.4f})")

    # Normalize FTP to sum=100
    ftp_total = sum(ftp_w.values())
    if ftp_total > 0:
        ftp_w = {s: round(v / ftp_total * 100, 1) for s, v in ftp_w.items()}
    reasoning_lines.append(f"  FTP normalized (sum was {ftp_total:.1f})")

    # Normalize HTTP to sum=100
    http_total = sum(http_w.values())
    if http_total > 0:
        http_w = {s: round(v / http_total * 100, 1) for s, v in http_w.items()}
    reasoning_lines.append(f"  HTTP normalized (sum was {http_total:.1f})")

    # Normalize SMTP to sum=100
    smtp_total = sum(smtp_w.values())
    if smtp_total > 0:
        smtp_w = {s: round(v / smtp_total * 100, 1) for s, v in smtp_w.items()}
    reasoning_lines.append(f"  SMTP normalized (sum was {smtp_total:.1f})")

    # Normalize SMB2 to sum=100
    smb2_total = sum(smb2_w.values())
    if smb2_total > 0:
        smb2_w = {s: round(v / smb2_total * 100, 1) for s, v in smb2_w.items()}
    reasoning_lines.append(f"  SMB2 normalized (sum was {smb2_total:.1f})")

    # Normalize SMB3 to sum=100
    smb3_total = sum(smb3_w.values())
    if smb3_total > 0:
        smb3_w = {s: round(v / smb3_total * 100, 1) for s, v in smb3_w.items()}
    reasoning_lines.append(f"  SMB3 normalized (sum was {smb3_total:.1f})")

    # Normalize HTTP2 to sum=100
    http2_total = sum(http2_w.values())
    if http2_total > 0:
        http2_w = {s: round(v / http2_total * 100, 1) for s, v in http2_w.items()}
    reasoning_lines.append(f"  HTTP2 normalized (sum was {http2_total:.1f})")

    # Normalize DCERPC to sum=100
    dcerpc_total = sum(dcerpc_w.values())
    if dcerpc_total > 0:
        dcerpc_w = {s: round(v / dcerpc_total * 100, 1) for s, v in dcerpc_w.items()}
    reasoning_lines.append(f"  DCERPC normalized (sum was {dcerpc_total:.1f})")

    return dns_w, ftp_w, http_w, smtp_w, smb2_w, smb3_w, http2_w, dcerpc_w, "\n".join(reasoning_lines)

# AI analysis state
analysis_state = {
    "files": {},
    "results": None,
    "status": "idle",
    "error": None,
}



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

    protocol = fuzzer_state.get("protocol", "dns")
    labels = _labels_for(protocol)
    data = {
        "iteration": fuzzer_state["iteration"],
        "status": fuzzer_state["status"],
        "running": fuzzer_state["running"],
        "protocol": protocol,
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
        "strategy_labels": labels,
        "runtime": f"{hours:02d}:{mins:02d}:{secs:02d}",
        "trigger_detail": fuzzer_state.get("trigger_detail"),
        "bandit_stats": _bandit_for_proto(protocol).get_stats(
            base_weights=ai_weights.get(protocol, {})),
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

            protocol = fuzzer_state.get("protocol", "dns")
            labels = _labels_for(protocol)
            data = {
                "iteration": fuzzer_state["iteration"],
                "status": fuzzer_state["status"],
                "running": fuzzer_state["running"],
                "protocol": protocol,
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
                "strategy_labels": labels,
                "runtime": f"{hours:02d}:{mins:02d}:{secs:02d}",
                "trigger_detail": fuzzer_state.get("trigger_detail"),
                "bandit_stats": _bandit_for_proto(protocol).get_stats(
                    base_weights=ai_weights.get(protocol, {})),
                "events": event_log[-20:],
            }
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/config", methods=["GET"])
def api_config_get():
    return jsonify(fuzzer_state.get("live_config", {}))


@app.route("/api/config", methods=["POST"])
def api_config_set():
    body = request.json or {}
    fuzzer_state["live_config"] = body
    return jsonify({"status": "saved"})


@app.route("/api/start", methods=["POST"])
def api_start():
    global fuzzer_thread
    if fuzzer_state["running"]:
        return jsonify({"error": "Fuzzer is already running"}), 400

    body = request.json or {}
    protocol = body.get("protocol", "dns").lower()
    if protocol not in ("dns", "ftp", "http", "smtp", "smb2", "smb3", "http2", "dcerpc"):
        protocol = "dns"
    mode = body.get("mode", "pipe").lower()
    live_config = body.get("live_config", {})

    fuzzer_state["protocol"] = protocol
    fuzzer_state["mode"] = mode
    if live_config:
        fuzzer_state["live_config"] = live_config
    reset_state()
    fuzzer_state["mode"] = mode
    log_event("INFO", f"Fuzzer started from UI (protocol: {protocol.upper()}, mode: {mode})")

    def _run():
        try:
            if mode == "live":
                cfg = fuzzer_state.get("live_config", {})
                run_fuzzer_live(cfg)
            else:
                run_fuzzer(SNORT_BUILD)
        except Exception as e:
            log_event("ERROR", f"Fuzzer crashed: {e}")
            fuzzer_state["status"] = "error"
            fuzzer_state["running"] = False

    fuzzer_thread = threading.Thread(target=_run, daemon=True)
    fuzzer_thread.start()
    return jsonify({"status": "started", "mode": mode})


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
    
    files_with_mtime = []
    for fname in os.listdir(CRASHES_DIR):
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(CRASHES_DIR, fname)
        files_with_mtime.append((fname, fpath, os.stat(fpath)))
        
    files_with_mtime.sort(key=lambda x: x[2].st_mtime, reverse=True)
    
    for fname, fpath, stat in files_with_mtime:
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
            "mtime": stat.st_mtime  
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


# ---------------------------------------------------------------------------
# File-as-packet sender: upload files and ship them verbatim as legit
# HTTP / FTP traffic (no mutation — the payload lives inside the file).
# ---------------------------------------------------------------------------
@app.route("/api/filesend/send", methods=["POST"])
def api_filesend_send():
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400
    uploaded = [f for f in request.files.getlist("files") if f.filename]
    if not uploaded:
        return jsonify({"error": "No files provided"}), 400

    protocol = (request.form.get("protocol") or "http").lower().strip()
    if protocol not in ("http", "ftp", "smtp", "smb2", "smb3", "http2", "dcerpc"):
        return jsonify({"error": "protocol must be 'http', 'ftp', 'smtp', 'smb2', 'smb3', 'http2', or 'dcerpc'"}), 400

    host = (request.form.get("host") or "").strip()
    if not host:
        return jsonify({"error": "Target host is required"}), 400

    default_port = {"http": 80, "ftp": 21, "smtp": 25, "smb2": 445, "smb3": 445, "http2": 80, "dcerpc": 135}[protocol]
    try:
        port = int(request.form.get("port") or default_port)
    except ValueError:
        return jsonify({"error": "Invalid port"}), 400

    results = []
    for f in uploaded:
        data = f.read()
        if protocol == "http":
            res = send_file_http(
                host, port, f.filename, data,
                method=request.form.get("http_method") or "POST",
                path=request.form.get("http_path") or None,
                host_header=request.form.get("http_host_header") or None,
            )
        elif protocol == "smtp":
            res = send_file_smtp(
                host, port, f.filename, data,
                mail_from=request.form.get("smtp_from") or "sender@example.com",
                rcpt_to=request.form.get("smtp_to") or "recipient@example.com",
                subject=request.form.get("smtp_subject") or None,
                user=request.form.get("smtp_user") or None,
                password=request.form.get("smtp_pass") or None,
            )
        elif protocol in ("smb2", "smb3"):
            res = send_file_smb(
                host, port, f.filename, data,
                share=request.form.get("smb_share") or "shared",
                username=request.form.get("smb_user") or "",
                password=request.form.get("smb_pass") or "",
                protocol_label=protocol,
            )
        elif protocol == "http2":
            res = send_file_http2(
                host, port, f.filename, data,
                method=request.form.get("http_method") or "POST",
                path=request.form.get("http_path") or None,
                host_header=request.form.get("http_host_header") or None,
            )
        elif protocol == "dcerpc":
            res = send_file_dcerpc(
                host, port, f.filename, data,
            )
        else:
            res = send_file_ftp(
                host, port, f.filename, data,
                user=request.form.get("ftp_user") or "anonymous",
                password=request.form.get("ftp_pass") or "anonymous@",
                remote_dir=request.form.get("ftp_dir") or None,
            )
        results.append(res)
        status = "ok" if res["ok"] else "error"
        log_event(
            "INFO" if res["ok"] else "WARN",
            f"File-send [{protocol.upper()}] {res['file']} -> {host}:{port} "
            f"({status}: {res['detail']})",
        )

    sent_ok = sum(1 for r in results if r["ok"])
    return jsonify({
        "status": "done",
        "protocol": protocol,
        "target": f"{host}:{port}",
        "sent_ok": sent_ok,
        "total": len(results),
        "results": results,
    })


# Max bytes of each wire packet streamed to the UI as a hex preview. The true
# length is always reported; only the displayed hex is capped to keep the
# stream light for multi-megabyte attachments.
_FILESEND_PKT_PREVIEW = 2048


@app.route("/api/filesend/stream", methods=["POST"])
def api_filesend_stream():
    """Same as /api/filesend/send, but streams every wire packet (TX/RX) to the
    client as newline-delimited JSON in real time, so the UI can render a live
    hex view of the bytes as they cross the wire."""
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400
    uploaded = [f for f in request.files.getlist("files") if f.filename]
    if not uploaded:
        return jsonify({"error": "No files provided"}), 400

    protocol = (request.form.get("protocol") or "http").lower().strip()
    if protocol not in ("http", "ftp", "smtp", "smb2", "smb3", "http2", "dcerpc"):
        return jsonify({"error": "protocol must be 'http', 'ftp', 'smtp', 'smb2', 'smb3', 'http2', or 'dcerpc'"}), 400

    host = (request.form.get("host") or "").strip()
    if not host:
        return jsonify({"error": "Target host is required"}), 400

    default_port = {"http": 80, "ftp": 21, "smtp": 25, "smb2": 445, "smb3": 445, "http2": 80, "dcerpc": 135}[protocol]
    try:
        port = int(request.form.get("port") or default_port)
    except ValueError:
        return jsonify({"error": "Invalid port"}), 400

    # Read all uploads + form fields NOW — the worker thread has no request ctx.
    files = [(f.filename, f.read()) for f in uploaded]
    opts = {
        "http_method": request.form.get("http_method") or "POST",
        "http_path": request.form.get("http_path") or None,
        "http_host_header": request.form.get("http_host_header") or None,
        "ftp_user": request.form.get("ftp_user") or "anonymous",
        "ftp_pass": request.form.get("ftp_pass") or "anonymous@",
        "ftp_dir": request.form.get("ftp_dir") or None,
        "smtp_from": request.form.get("smtp_from") or "sender@example.com",
        "smtp_to": request.form.get("smtp_to") or "recipient@example.com",
        "smtp_subject": request.form.get("smtp_subject") or None,
        "smtp_user": request.form.get("smtp_user") or None,
        "smtp_pass": request.form.get("smtp_pass") or None,
        "smb_share": request.form.get("smb_share") or "shared",
        "smb_user": request.form.get("smb_user") or "",
        "smb_pass": request.form.get("smb_pass") or "",
    }

    q = queue.Queue()
    _SENTINEL = object()

    def worker():
        results = []
        try:
            for idx, (fname, data) in enumerate(files):
                seq = {"n": 0}

                def on_packet(direction, label, pkt, _fname=fname, _seq=seq):
                    _seq["n"] += 1
                    q.put({
                        "event": "packet",
                        "file": _fname,
                        "seq": _seq["n"],
                        "dir": direction,
                        "label": label,
                        "len": len(pkt),
                        "hex": pkt[:_FILESEND_PKT_PREVIEW].hex(),
                        "truncated": len(pkt) > _FILESEND_PKT_PREVIEW,
                    })

                q.put({"event": "file_start", "file": fname, "index": idx,
                       "size": len(data), "protocol": protocol,
                       "target": f"{host}:{port}"})

                if protocol == "http":
                    res = send_file_http(host, port, fname, data,
                                         method=opts["http_method"], path=opts["http_path"],
                                         host_header=opts["http_host_header"], on_packet=on_packet)
                elif protocol == "smtp":
                    res = send_file_smtp(host, port, fname, data,
                                         mail_from=opts["smtp_from"], rcpt_to=opts["smtp_to"],
                                         subject=opts["smtp_subject"], user=opts["smtp_user"],
                                         password=opts["smtp_pass"], on_packet=on_packet)
                elif protocol in ("smb2", "smb3"):
                    res = send_file_smb(host, port, fname, data,
                                        share=opts["smb_share"], username=opts["smb_user"],
                                        password=opts["smb_pass"], protocol_label=protocol)
                elif protocol == "http2":
                    res = send_file_http2(host, port, fname, data,
                                          method=opts["http_method"], path=opts["http_path"],
                                          host_header=opts["http_host_header"], on_packet=on_packet)
                elif protocol == "dcerpc":
                    res = send_file_dcerpc(host, port, fname, data,
                                           on_packet=on_packet)
                else:
                    res = send_file_ftp(host, port, fname, data,
                                        user=opts["ftp_user"], password=opts["ftp_pass"],
                                        remote_dir=opts["ftp_dir"], on_packet=on_packet)

                results.append(res)
                status = "ok" if res["ok"] else "error"
                log_event("INFO" if res["ok"] else "WARN",
                          f"File-send [{protocol.upper()}] {res['file']} -> {host}:{port} "
                          f"({status}: {res['detail']})")
                q.put({"event": "file_done", **res})
        except Exception as e:
            q.put({"event": "error", "detail": f"{type(e).__name__}: {e}"})
        finally:
            sent_ok = sum(1 for r in results if r.get("ok"))
            q.put({"event": "done", "protocol": protocol, "target": f"{host}:{port}",
                   "sent_ok": sent_ok, "total": len(files)})
            q.put(_SENTINEL)

    threading.Thread(target=worker, daemon=True).start()

    def generate():
        while True:
            item = q.get()
            if item is _SENTINEL:
                break
            yield json.dumps(item) + "\n"

    return Response(generate(), mimetype="application/x-ndjson")


# ---------------------------------------------------------------------------
# AI Analysis Routes
# ---------------------------------------------------------------------------
@app.route("/api/ai/upload", methods=["POST"])
def ai_upload():
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


@app.route("/api/ai/upload-directory", methods=["POST"])
def ai_upload_directory():
    """Accept a local directory path, collect all source files, and load them."""
    body = request.json or {}
    dir_path = body.get("path", "").strip()
    if not dir_path:
        return jsonify({"error": "No directory path provided"}), 400
    dir_path = os.path.expanduser(dir_path)
    if not os.path.isdir(dir_path):
        return jsonify({"error": f"Directory not found: {dir_path}"}), 400

    try:
        collected = collect_to_dict(dir_path)
        if not collected:
            return jsonify({"error": "No source files found in directory"}), 400

        analysis_state["files"].update(collected)
        total_lines = sum(c.count("\n") + 1 for c in collected.values())
        total_size_mb = sum(len(c) for c in collected.values()) / (1024 * 1024)
        print(f"[AI] Directory loaded: {len(collected)} files from {dir_path} ({total_size_mb:.2f} MB)")

        return jsonify({
            "status": "ok",
            "new_files": len(collected),
            "total_files": len(analysis_state["files"]),
            "total_lines": total_lines,
            "size_mb": round(total_size_mb, 2),
            "files": list(analysis_state["files"].keys()),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/files", methods=["GET"])
def ai_files():
    files = []
    for name, content in analysis_state["files"].items():
        files.append({"name": name, "lines": content.count("\n") + 1, "size": len(content)})
    return jsonify({"files": files})


@app.route("/api/ai/files/<filename>", methods=["DELETE"])
def ai_delete_file(filename):
    if filename in analysis_state["files"]:
        del analysis_state["files"][filename]
        return jsonify({"status": "removed", "files": list(analysis_state["files"].keys())})
    return jsonify({"error": "File not found"}), 404


def _ai_call(prompt_text, user_text):
    """Call Azure OpenAI. Returns (parsed_json, model_name)."""
    client = AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_API_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
    )
    model_name = AZURE_OPENAI_MODEL
    print(f"[AI] Calling Azure OpenAI model: {model_name}")
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": prompt_text},
                {"role": "user", "content": user_text},
            ],
            max_completion_tokens=65536,
            response_format={"type": "json_object"},
            timeout=600,
        )
        # Log rate limit headers to show quota details
        http_resp = getattr(response, '_response', None)
        if http_resp:
            headers = http_resp.headers
            print(f"[AI] ── Rate Limit Info ──")
            for h in ['x-ratelimit-limit-requests', 'x-ratelimit-remaining-requests',
                       'x-ratelimit-limit-tokens', 'x-ratelimit-remaining-tokens',
                       'x-ratelimit-reset-requests', 'x-ratelimit-reset-tokens']:
                val = headers.get(h)
                if val:
                    print(f"[AI]   {h}: {val}")

        raw_text = response.choices[0].message.content.strip()
        print(f"[AI] Success with model: {model_name}")
        print(f"[AI] Response length: {len(raw_text)} chars")
        print(f"[AI] Tokens used — prompt: {response.usage.prompt_tokens}, completion: {response.usage.completion_tokens}, total: {response.usage.total_tokens}")

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            if "```json" in raw_text:
                json_str = raw_text.split("```json")[1].split("```")[0].strip()
                parsed = json.loads(json_str)
            elif "```" in raw_text:
                json_str = raw_text.split("```")[1].split("```")[0].strip()
                parsed = json.loads(json_str)
            else:
                parsed = {"raw_response": raw_text, "parse_error": True}

        print(f"[AI] Parsed JSON keys: {list(parsed.keys()) if isinstance(parsed, dict) else type(parsed).__name__}")
        return parsed, model_name
    except Exception as err:
        print(f"[AI] {model_name} failed: {err}")
        raise


@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze():
    if not analysis_state["files"]:
        return jsonify({"error": "No files uploaded"}), 400
    if not AZURE_OPENAI_API_KEY:
        return jsonify({"error": "AZURE_OPENAI_API_KEY not set in .env"}), 500

    analysis_state["status"] = "analyzing"
    analysis_state["results"] = None
    analysis_state["error"] = None

    try:
        all_files = dict(analysis_state["files"])
        total_raw = sum(len(v) for v in all_files.values())
        print(f"[AI] ── Input: {len(all_files)} files, {total_raw/1024:.1f} KB, ~{estimate_tokens(total_raw)} tokens (raw)")

        # ── STAGE 1: MINIFY (local, instant) ──────────────────────
        print("[AI] ══ STAGE 1: Minifying code (strip comments/blanks) ══")
        analysis_state["status"] = "analyzing (stage 1/4: minifying)"
        minified_files = {}
        for path, content in all_files.items():
            minified_files[path] = minify_code(content)
        total_minified = sum(len(v) for v in minified_files.values())
        reduction_1 = (1 - total_minified / max(total_raw, 1)) * 100
        print(f"[AI]   Minified: {total_minified/1024:.1f} KB, ~{estimate_tokens(total_minified)} tokens ({reduction_1:.0f}% reduction)")

        # ── STAGE 2: HOTSPOT FILTER (local, instant) ──────────────
        print("[AI] ══ STAGE 2: Hotspot filtering (dangerous patterns) ══")
        analysis_state["status"] = "analyzing (stage 2/4: hotspot filtering)"
        hotspot_files = hotspot_filter(minified_files)
        total_hotspot = sum(len(v) for v in hotspot_files.values())
        print(f"[AI]   Hotspots: {len(hotspot_files)}/{len(minified_files)} files, {total_hotspot/1024:.1f} KB, ~{estimate_tokens(total_hotspot)} tokens")

        # If small enough (<=20 files or <=100K tokens), skip triage and analyze directly
        DIRECT_THRESHOLD_FILES = 20
        DIRECT_THRESHOLD_TOKENS = 100_000
        hotspot_tokens = estimate_tokens(total_hotspot)

        if len(hotspot_files) <= DIRECT_THRESHOLD_FILES or hotspot_tokens <= DIRECT_THRESHOLD_TOKENS:
            print(f"[AI]   Small enough for direct analysis — skipping repo map triage")
            selected_paths = list(hotspot_files.keys())
            map_summary = "Direct analysis (small codebase)"
            triage_details = []
            code_context = build_optimized_context(hotspot_files, selected_paths)
        else:
            # ── STAGE 3: REPO MAP TRIAGE (1 API call) ─────────────
            print("[AI] ══ STAGE 3: Repo map triage (LLM picks top-20 files) ══")
            analysis_state["status"] = "analyzing (stage 3/4: triage)"
            repo_map = extract_repo_map(hotspot_files)
            map_tokens = estimate_tokens(repo_map)
            print(f"[AI]   Repo map: {map_tokens} tokens ({len(hotspot_files)} files)")

            triage_results, _ = _ai_call(MAP_PROMPT, repo_map)

            selected_entries = triage_results.get("selected_files", [])
            map_summary = triage_results.get("summary", "")
            triage_details = selected_entries

            # Extract paths, handling both exact and fuzzy matches
            selected_paths = []
            available = set(hotspot_files.keys())
            for entry in selected_entries:
                p = entry.get("path", "")
                if p in available:
                    selected_paths.append(p)
                else:
                    for avail_path in available:
                        if avail_path.endswith(p) or p.endswith(avail_path):
                            selected_paths.append(avail_path)
                            break

            if not selected_paths:
                print(f"[AI]   WARNING: No path matches — falling back to all hotspot files")
                selected_paths = list(hotspot_files.keys())

            print(f"[AI]   Selected {len(selected_paths)} files for deep analysis")
            code_context = build_optimized_context(hotspot_files, selected_paths)

        context_tokens = estimate_tokens(code_context)
        reduction_total = (1 - len(code_context) / max(total_raw, 1)) * 100
        print(f"[AI]   Final context: {len(code_context)/1024:.1f} KB, ~{context_tokens} tokens ({reduction_total:.0f}% total reduction)")

        # Save consolidated context to disk
        context_path = os.path.join(os.path.expanduser("~"), "ai_context.txt")
        with open(context_path, "w", encoding="utf-8") as ctx_file:
            ctx_file.write(code_context)

        # ── STAGE 4: DEEP ANALYSIS (1 API call) ──────────────────
        print("[AI] ══ STAGE 4: Deep vulnerability analysis ══")
        analysis_state["status"] = "analyzing (stage 4/4: deep analysis)"
        hunter_prompt = f"""Analyze the following source code file(s) for security vulnerabilities.
For each vulnerability, provide a concrete byte-level payload that would trigger it.

{code_context}"""

        hunter_results, model_used = _ai_call(HUNTER_PROMPT, hunter_prompt)
        raw_vulns = hunter_results.get("vulnerabilities", [])

        # Deep search: model sometimes nests vulns under a different key
        if not raw_vulns and isinstance(hunter_results, dict):
            for key, val in hunter_results.items():
                if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                    if any(k in val[0] for k in ["bug_class", "severity", "function", "matched_strategy"]):
                        print(f"[AI] Found vulnerabilities under key '{key}' instead of 'vulnerabilities'")
                        raw_vulns = val
                        break
                elif isinstance(val, dict) and "vulnerabilities" in val:
                    print(f"[AI] Found nested vulnerabilities under '{key}.vulnerabilities'")
                    raw_vulns = val["vulnerabilities"]
                    break

        print(f"[AI] Deep analysis found {len(raw_vulns)} potential vulnerabilities")

        if not raw_vulns:
            debug_path = os.path.join(os.path.expanduser("~"), "ai_hunter_debug.json")
            with open(debug_path, "w") as f:
                json.dump(hunter_results, f, indent=2)
            print(f"[AI] 0 vulns found — raw response saved to {debug_path}")
            hunter_results["model_used"] = model_used
            hunter_results["pipeline"] = {
                "total_files": len(all_files),
                "hotspot_files": len(hotspot_files),
                "analyzed_files": len(selected_paths),
                "raw_tokens": estimate_tokens(total_raw),
                "final_tokens": context_tokens,
                "reduction_pct": round(reduction_total, 1),
                "vulns_found": 0,
            }
            hunter_results["recommended_weights"] = None

            conv_id = db_create_conversation(
                _derive_title(all_files),
                compute_codebase_hash(all_files),
                list(all_files.keys()),
                code_context,
                hunter_results,
            )
            hunter_results["conversation_id"] = conv_id
            analysis_state["results"] = hunter_results
            analysis_state["status"] = "done"
            return jsonify({"status": "done", "results": hunter_results, "conversation_id": conv_id})

        # ── WEIGHER: DETERMINISTIC PYTHON ─────────────────────────
        print("[AI] ══ Computing weights (Python) ══")
        dns_w, ftp_w, http_w, smtp_w, smb2_w, smb3_w, http2_w, dcerpc_w, reasoning = compute_weights_from_vulns(raw_vulns)
        print(f"[AI] Weights computed deterministically.")

        # Assemble final results
        results = {
            "file_summary": hunter_results.get("file_summary", ""),
            "map_summary": map_summary,
            "vulnerabilities": raw_vulns,
            "attack_chains": hunter_results.get("attack_chains", []),
            "recommended_weights": {
                "dns": dns_w,
                "ftp": ftp_w,
                "http": http_w,
                "smtp": smtp_w,
                "smb2": smb2_w,
                "smb3": smb3_w,
                "http2": http2_w,
                "dcerpc": dcerpc_w,
                "weight_reasoning": reasoning,
            },
            "model_used": model_used,
            "pipeline": {
                "total_files": len(all_files),
                "hotspot_files": len(hotspot_files),
                "analyzed_files": len(selected_paths),
                "raw_tokens": estimate_tokens(total_raw),
                "final_tokens": context_tokens,
                "reduction_pct": round(reduction_total, 1),
                "vulns_found": len(raw_vulns),
            },
        }

        conv_id = db_create_conversation(
            _derive_title(all_files),
            compute_codebase_hash(all_files),
            list(all_files.keys()),
            code_context,
            results,
        )
        results["conversation_id"] = conv_id

        analysis_state["results"] = results
        analysis_state["status"] = "done"
        return jsonify({"status": "done", "results": results, "conversation_id": conv_id})

    except Exception as e:
        analysis_state["status"] = "error"
        analysis_state["error"] = str(e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/results", methods=["GET"])
def ai_results():
    return jsonify({
        "status": analysis_state["status"],
        "results": analysis_state["results"],
        "error": analysis_state["error"],
    })


# ---------------------------------------------------------------------------
# Conversational chat over a stored analysis
# ---------------------------------------------------------------------------
CHAT_MAX_CONTEXT_CHARS = 120_000  # hard cap on code context sent per chat turn
CHAT_SNIPPET_MAX_CHARS = 16_000   # cap on vuln-relevant snippets sent per chat turn
CHAT_SNIPPET_WINDOW = 24          # lines of code captured around each vuln anchor
CHAT_HISTORY_TURNS = 8            # number of recent user+assistant turns to replay


def _parse_context_files(code_context):
    """Split a build_optimized_context() string into [(path, code), ...]."""
    files = []
    if not code_context:
        return files
    pattern = re.compile(r"=== FILE: (.*?) ===\n(.*?)\n=== END: \1 ===", re.DOTALL)
    for m in pattern.finditer(code_context):
        files.append((m.group(1).strip(), m.group(2)))
    if not files:
        files.append(("(code)", code_context))
    return files


def _extract_relevant_snippets(code_context, vulns,
                               max_chars=CHAT_SNIPPET_MAX_CHARS,
                               window=CHAT_SNIPPET_WINDOW):
    """Return only the code regions near reported vulnerabilities.

    Because the stored context is minified, vuln line numbers no longer line up,
    so we anchor on function names instead and grab a window around each match.
    Returns "" if nothing useful can be extracted (caller should fall back).
    """
    files = _parse_context_files(code_context)
    if not files:
        return ""

    func_names = []
    for v in vulns:
        fn = (v.get("function") or "").strip()
        fn = re.sub(r"\(.*$", "", fn).strip()  # drop arg list if present
        if fn and fn not in func_names:
            func_names.append(fn)
    if not func_names:
        return ""

    out_parts = []
    total = 0
    for path, code in files:
        lines = code.split("\n")
        ranges = []  # [start, end, label]
        for fn in func_names:
            anchor = re.compile(r"\b" + re.escape(fn) + r"\b")
            for i, line in enumerate(lines):
                if anchor.search(line):
                    start = max(0, i - window // 2)
                    end = min(len(lines), i + window)
                    ranges.append([start, end, fn])
                    break  # first occurrence per function per file
        if not ranges:
            continue

        ranges.sort()
        merged = []
        for r in ranges:
            if merged and r[0] <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], r[1])
                merged[-1][2] = merged[-1][2] + ", " + r[2]
            else:
                merged.append(r)

        for start, end, label in merged:
            snippet = "\n".join(lines[start:end])
            block = f"--- {path} (near {label}) ---\n{snippet}"
            if total + len(block) > max_chars:
                out_parts.append("... [further snippets omitted to save tokens] ...")
                return "\n\n".join(out_parts)
            out_parts.append(block)
            total += len(block)

    return "\n\n".join(out_parts)


def _ai_chat_call(messages):
    """Call Azure OpenAI for free-form chat. Returns plain text reply."""
    client = AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_API_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
    )
    response = client.chat.completions.create(
        model=AZURE_OPENAI_MODEL,
        messages=messages,
        max_completion_tokens=8192,
        timeout=300,
    )
    return response.choices[0].message.content.strip()


def _build_chat_system_prompt(conv):
    """Ground the chat model in the prior analysis + relevant source snippets."""
    analysis = conv.get("analysis", {}) or {}
    full_context = conv.get("code_context", "") or ""
    vulns = analysis.get("vulnerabilities", [])

    # Prefer compact, vuln-relevant snippets; fall back to truncated full context.
    snippets = _extract_relevant_snippets(full_context, vulns)
    if snippets:
        code_label = "RELEVANT SOURCE SNIPPETS (regions around reported vulnerabilities)"
        code_section = snippets
    else:
        code_label = "SOURCE CODE CONTEXT (minified)"
        code_section = full_context[:CHAT_MAX_CONTEXT_CHARS]
        if len(full_context) > CHAT_MAX_CONTEXT_CHARS:
            code_section += "\n\n... [context truncated] ..."

    try:
        vulns_json = json.dumps(vulns, indent=2)
    except Exception:
        vulns_json = "[]"

    return f"""You are a senior security engineer assistant embedded in a protocol fuzzing platform.
You are discussing ONE specific codebase that has already been analyzed for vulnerabilities.

CODEBASE: {conv.get('title', 'Unknown')}
FILES: {', '.join(conv.get('files', [])) or 'n/a'}

SUMMARY: {analysis.get('file_summary', 'n/a')}

PRIOR VULNERABILITY ANALYSIS (JSON):
{vulns_json}

{code_label}:
{code_section}

INSTRUCTIONS:
- Answer the user's questions about THIS codebase: its vulnerabilities, exploitability, payloads, fixes, and fuzzing strategy.
- Reference specific functions, line ranges, and bug classes from the analysis when relevant.
- Be concise, technical, and accurate. If something is not present in the code/analysis, say so.
- Use Markdown for formatting (code blocks, lists, bold)."""


@app.route("/api/ai/history", methods=["GET"])
def ai_history():
    return jsonify({
        "db_available": mongo_ok(),
        "conversations": db_list_conversations(),
    })


@app.route("/api/ai/history/<conv_id>", methods=["GET"])
def ai_history_get(conv_id):
    conv = db_get_conversation(conv_id)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    return jsonify({
        "id": conv["_id"],
        "title": conv.get("title", "Untitled"),
        "files": conv.get("files", []),
        "analysis": conv.get("analysis", {}),
        "messages": conv.get("messages", []),
        "created_at": conv["created_at"].isoformat() if conv.get("created_at") else "",
    })


@app.route("/api/ai/history/<conv_id>", methods=["DELETE"])
def ai_history_delete(conv_id):
    if not mongo_ok():
        return jsonify({"error": "Database unavailable"}), 503
    db_delete_conversation(conv_id)
    return jsonify({"status": "deleted"})


@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    if not mongo_ok():
        return jsonify({"error": "Database unavailable — history/chat disabled"}), 503
    body = request.json or {}
    conv_id = body.get("conversation_id")
    user_msg = (body.get("message") or "").strip()
    if not user_msg:
        return jsonify({"error": "Empty message"}), 400
    if not AZURE_OPENAI_API_KEY:
        return jsonify({"error": "AZURE_OPENAI_API_KEY not set in .env"}), 500

    conv = db_get_conversation(conv_id)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404

    messages = [{"role": "system", "content": _build_chat_system_prompt(conv)}]
    history = [m for m in conv.get("messages", []) if m.get("role") in ("user", "assistant")]
    # Replay only the most recent N turns (1 turn = user + assistant) to cap token growth
    recent = history[-(CHAT_HISTORY_TURNS * 2):]
    for m in recent:
        messages.append({"role": m["role"], "content": m.get("content", "")})
    messages.append({"role": "user", "content": user_msg})

    try:
        reply = _ai_chat_call(messages)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

    now_iso = datetime.now(timezone.utc).isoformat()
    db_add_messages(conv_id, [
        {"role": "user", "content": user_msg, "ts": now_iso},
        {"role": "assistant", "content": reply, "ts": now_iso},
    ])
    return jsonify({"reply": reply})


@app.route("/api/ai/weights", methods=["GET"])
def ai_get_weights():
    """Return current weights (AI or default) plus defaults for comparison."""
    dns_default = dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS))
    ftp_default = dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS))
    http_default = dict(zip(HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS))
    smtp_default = dict(zip(SMTP_STRATEGY_NAMES, SMTP_DEFAULT_WEIGHTS))
    smb2_default = dict(zip(SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS))
    smb3_default = dict(zip(SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS))
    http2_default = dict(zip(HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS))
    dcerpc_default = dict(zip(DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS))
    return jsonify({
        "source": ai_weights.get("source", "default"),
        "dns": ai_weights.get("dns", dns_default),
        "ftp": ai_weights.get("ftp", ftp_default),
        "http": ai_weights.get("http", http_default),
        "smtp": ai_weights.get("smtp", smtp_default),
        "smb2": ai_weights.get("smb2", smb2_default),
        "smb3": ai_weights.get("smb3", smb3_default),
        "http2": ai_weights.get("http2", http2_default),
        "dcerpc": ai_weights.get("dcerpc", dcerpc_default),
        "reasoning": ai_weights.get("reasoning", ""),
        "dns_default": dns_default,
        "ftp_default": ftp_default,
        "http_default": http_default,
        "smtp_default": smtp_default,
        "smb2_default": smb2_default,
        "smb3_default": smb3_default,
        "http2_default": http2_default,
        "dcerpc_default": dcerpc_default,
    })


@app.route("/api/ai/apply_weights", methods=["POST"])
def ai_apply_weights():
    """Apply AI-recommended weights from a specific conversation or the current analysis."""
    # If a conversation_id is provided, load results from MongoDB
    body = request.get_json(silent=True) or {}
    conv_id = body.get("conversation_id")

    if conv_id:
        conv = db_get_conversation(conv_id)
        if not conv or not conv.get("analysis"):
            return jsonify({"error": f"No analysis found for conversation {conv_id}"}), 400
        results = conv["analysis"]
        print(f"[AI] Loading weights from conversation: {conv.get('title', conv_id)}")
    else:
        results = analysis_state.get("results")

    if not results:
        return jsonify({"error": "No analysis results available. Open a previous analysis or run a new one."}), 400

    rec = results.get("recommended_weights")
    if not rec or not isinstance(rec, dict):
        return jsonify({"error": "No weight recommendations in analysis results"}), 400

    dns_raw = rec.get("dns", {})
    ftp_raw = rec.get("ftp", {})
    http_raw = rec.get("http", {})
    smtp_raw = rec.get("smtp", {})
    smb2_raw = rec.get("smb2", {})
    smb3_raw = rec.get("smb3", {})
    http2_raw = rec.get("http2", {})
    dcerpc_raw = rec.get("dcerpc", {})

    # Normalize DNS weights
    dns_total = sum(dns_raw.get(s, 0) for s in DNS_STRATEGY_NAMES)
    if dns_total > 0:
        ai_weights["dns"] = {s: round(dns_raw.get(s, 0) / dns_total, 4) for s in DNS_STRATEGY_NAMES}
    
    # Normalize FTP weights
    ftp_total = sum(ftp_raw.get(s, 0) for s in FTP_STRATEGY_NAMES)
    if ftp_total > 0:
        ai_weights["ftp"] = {s: round(ftp_raw.get(s, 0) / ftp_total * 100, 1) for s in FTP_STRATEGY_NAMES}

    # Normalize HTTP weights
    http_total = sum(http_raw.get(s, 0) for s in HTTP_STRATEGY_NAMES)
    if http_total > 0:
        ai_weights["http"] = {s: round(http_raw.get(s, 0) / http_total * 100, 1) for s in HTTP_STRATEGY_NAMES}

    # Normalize SMTP weights
    smtp_total = sum(smtp_raw.get(s, 0) for s in SMTP_STRATEGY_NAMES)
    if smtp_total > 0:
        ai_weights["smtp"] = {s: round(smtp_raw.get(s, 0) / smtp_total * 100, 1) for s in SMTP_STRATEGY_NAMES}

    # Normalize SMB2 weights
    smb2_total = sum(smb2_raw.get(s, 0) for s in SMB2_STRATEGY_NAMES)
    if smb2_total > 0:
        ai_weights["smb2"] = {s: round(smb2_raw.get(s, 0) / smb2_total * 100, 1) for s in SMB2_STRATEGY_NAMES}

    # Normalize SMB3 weights
    smb3_total = sum(smb3_raw.get(s, 0) for s in SMB3_STRATEGY_NAMES)
    if smb3_total > 0:
        ai_weights["smb3"] = {s: round(smb3_raw.get(s, 0) / smb3_total * 100, 1) for s in SMB3_STRATEGY_NAMES}

    # Normalize HTTP2 weights
    http2_total = sum(http2_raw.get(s, 0) for s in HTTP2_STRATEGY_NAMES)
    if http2_total > 0:
        ai_weights["http2"] = {s: round(http2_raw.get(s, 0) / http2_total * 100, 1) for s in HTTP2_STRATEGY_NAMES}

    # Normalize DCERPC weights
    dcerpc_total = sum(dcerpc_raw.get(s, 0) for s in DCERPC_STRATEGY_NAMES)
    if dcerpc_total > 0:
        ai_weights["dcerpc"] = {s: round(dcerpc_raw.get(s, 0) / dcerpc_total * 100, 1) for s in DCERPC_STRATEGY_NAMES}

    ai_weights["source"] = "ai"
    ai_weights["reasoning"] = rec.get("weight_reasoning", "")

    # Reset RL bandits so they start fresh with new AI base weights
    dns_bandit.reset()
    ftp_bandit.reset()
    http_bandit.reset()
    smtp_bandit.reset()
    smb2_bandit.reset()
    smb3_bandit.reset()
    http2_bandit.reset()
    dcerpc_bandit.reset()

    log_event("INFO", f"AI weights applied — source: {results.get('model_used', 'unknown')}, RL bandits reset")
    print(f"[AI] Weights applied: DNS={ai_weights['dns']}")
    print(f"[AI] Weights applied: FTP={ai_weights['ftp']}")
    print(f"[AI] Weights applied: HTTP={ai_weights['http']}")
    print(f"[AI] Weights applied: SMTP={ai_weights['smtp']}")
    print(f"[AI] Weights applied: SMB2={ai_weights['smb2']}")
    print(f"[AI] Weights applied: SMB3={ai_weights['smb3']}")
    print(f"[AI] Weights applied: HTTP2={ai_weights['http2']}")
    print(f"[AI] Weights applied: DCERPC={ai_weights['dcerpc']}")

    return jsonify({"status": "applied", "dns": ai_weights["dns"], "ftp": ai_weights["ftp"], "http": ai_weights["http"], "smtp": ai_weights["smtp"], "smb2": ai_weights["smb2"], "smb3": ai_weights["smb3"], "http2": ai_weights["http2"], "dcerpc": ai_weights["dcerpc"]})


@app.route("/api/ai/reset_weights", methods=["POST"])
def ai_reset_weights():
    """Reset weights back to defaults."""
    ai_weights["dns"] = dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS))
    ai_weights["ftp"] = dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS))
    ai_weights["http"] = dict(zip(HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS))
    ai_weights["smtp"] = dict(zip(SMTP_STRATEGY_NAMES, SMTP_DEFAULT_WEIGHTS))
    ai_weights["smb2"] = dict(zip(SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS))
    ai_weights["smb3"] = dict(zip(SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS))
    ai_weights["http2"] = dict(zip(HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS))
    ai_weights["dcerpc"] = dict(zip(DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS))
    ai_weights["source"] = "default"
    ai_weights["reasoning"] = ""

    # Reset RL bandits
    dns_bandit.reset()
    ftp_bandit.reset()
    http_bandit.reset()
    smtp_bandit.reset()
    smb2_bandit.reset()
    smb3_bandit.reset()
    http2_bandit.reset()
    dcerpc_bandit.reset()

    log_event("INFO", "Strategy weights reset to defaults, RL bandits reset")
    return jsonify({"status": "reset"})


@app.route("/api/ai/_test_inject", methods=["POST"])
def ai_test_inject():
    """DEBUG: Inject fake analysis results to test weight pipeline without OpenAI."""
    data = request.json
    analysis_state["results"] = data
    analysis_state["status"] = "done" if data else "idle"
    return jsonify({"status": "injected" if data else "cleared"})


@app.route("/api/ai/clear", methods=["POST"])
def ai_clear():
    analysis_state["files"].clear()
    analysis_state["results"] = None
    analysis_state["status"] = "idle"
    analysis_state["error"] = None
    return jsonify({"status": "cleared"})


# ── AGENTIC ANALYSIS PIPELINE (v2) ────────────────────────────────────────
@app.route("/api/ai/analyze-v2", methods=["POST"])
def ai_analyze_v2():
    """Full agentic analysis pipeline:
       Phase 1 → Semantic Graph (AST parse + embed + ChromaDB)
       Phase 2 → Orchestrator (generate investigation tasks)
       Phase 3&4 → Explorers (concurrent per-task LLM analysis)
       Phase 5 → Synthesizer (merge dossiers → weights + dynamic dictionary)
    """
    if not analysis_state["files"]:
        return jsonify({"error": "No files uploaded"}), 400
    if not AZURE_OPENAI_API_KEY:
        return jsonify({"error": "AZURE_OPENAI_API_KEY not set in .env"}), 500

    analysis_state["status"] = "analyzing"
    analysis_state["results"] = None
    analysis_state["error"] = None

    try:
        all_files = dict(analysis_state["files"])
        total_raw = sum(len(v) for v in all_files.values())
        print(f"[AI-v2] ── Input: {len(all_files)} files, {total_raw/1024:.1f} KB")

        # ── PHASE 1: SEMANTIC GRAPH ───────────────────────────────
        print("[AI-v2] ══ PHASE 1: Semantic Graph (AST parse + embed + ChromaDB) ══")
        analysis_state["status"] = "analyzing (phase 1/5: building semantic graph)"

        # Reuse existing ChromaDB index if file count matches (avoids re-embedding)
        from engine.semantic_search import get_or_create_collection
        existing = get_or_create_collection()
        existing_count = existing.count()
        if existing_count > 0 and abs(len(all_files) - analysis_state.get("_last_file_count", 0)) == 0:
            print(f"[AI-v2]   Reusing existing ChromaDB index ({existing_count} chunks)")
            total_chunks = existing_count
            index_result = {"total_files": len(all_files), "total_chunks": total_chunks, "chunks": []}
        else:
            index_result = index_codebase(all_files, fresh=True)
            total_chunks = index_result["total_chunks"]
            analysis_state["_last_file_count"] = len(all_files)
            import time as _time
            print("[AI-v2]   Waiting 15s for rate-limit cooldown before LLM calls...")
            _time.sleep(15)

        print(f"[AI-v2]   Indexed {total_chunks} chunks from {index_result['total_files']} files")

        if total_chunks == 0:
            analysis_state["status"] = "error"
            analysis_state["error"] = "No code chunks could be extracted from the uploaded files."
            return jsonify({"error": analysis_state["error"]}), 400

        # ── PHASE 2: ORCHESTRATOR ─────────────────────────────────
        print("[AI-v2] ══ PHASE 2: Orchestrator (generating investigation tasks) ══")
        analysis_state["status"] = "analyzing (phase 2/5: orchestrating tasks)"

        # Build metadata-only list for the Orchestrator (no raw code)
        all_chunk_meta = get_all_chunks()
        chunk_meta_slim = [{
            "file": c["file"], "name": c["name"],
            "node_type": c["node_type"], "language": c["language"],
            "start_line": c["start_line"], "end_line": c["end_line"],
        } for c in all_chunk_meta]

        tasks, codebase_summary = generate_tasks(chunk_meta_slim)

        if not tasks:
            analysis_state["status"] = "error"
            analysis_state["error"] = "Orchestrator generated 0 tasks."
            return jsonify({"error": analysis_state["error"]}), 500

        # ── PHASE 3 & 4: EXPLORERS ───────────────────────────────
        print(f"[AI-v2] ══ PHASES 3&4: Running {len(tasks)} Explorer agents ══")

        explorer_done = [0]

        def on_explorer_progress(completed, total, dossier):
            explorer_done[0] = completed
            analysis_state["status"] = (
                f"analyzing (phase 3-4/5: exploring {completed}/{total} tasks)"
            )

        analysis_state["status"] = f"analyzing (phase 3-4/5: exploring 0/{len(tasks)} tasks)"
        dossiers = run_explorers(
            tasks,
            max_workers=5,
            n_chunks_per_task=15,
            on_progress=on_explorer_progress,
        )

        # ── PHASE 5: SYNTHESIZER ──────────────────────────────────
        print("[AI-v2] ══ PHASE 5: Synthesizing results ══")
        analysis_state["status"] = "analyzing (phase 5/5: synthesizing)"

        merged = merge_dossiers(dossiers)
        raw_vulns = merged["vulnerabilities"]

        # Build dynamic dictionary
        dynamic_dict = build_dynamic_dictionary(merged)

        # Compute weights from merged vulns
        if raw_vulns:
            dns_w, ftp_w, http_w, smtp_w, smb2_w, smb3_w, http2_w, dcerpc_w, reasoning = compute_weights_from_vulns(raw_vulns)
            recommended_weights = {
                "dns": dns_w, "ftp": ftp_w, "http": http_w, "smtp": smtp_w,
                "smb2": smb2_w, "smb3": smb3_w, "http2": http2_w, "dcerpc": dcerpc_w, "weight_reasoning": reasoning,
            }
        else:
            recommended_weights = None

        # Assemble final results
        results = {
            "file_summary": codebase_summary,
            "codebase_summary": codebase_summary,
            "vulnerabilities": raw_vulns,
            "attack_chains": merged["attack_chains"],
            "extracted_constants": merged["extracted_constants"],
            "dynamic_dictionary": dynamic_dict,
            "recommended_weights": recommended_weights,
            "model_used": "gpt-5 (agentic pipeline)",
            "pipeline": {
                "version": "v2-agentic",
                "total_files": len(all_files),
                "total_chunks": total_chunks,
                "tasks_generated": len(tasks),
                "dossiers_completed": merged["stats"]["successful_dossiers"],
                "dossiers_failed": merged["stats"]["failed_dossiers"],
                "raw_vulns": merged["stats"]["raw_vulns"],
                "deduped_vulns": merged["stats"]["deduped_vulns"],
                "constants_extracted": sum(
                    merged["stats"]["constants"].values()
                ),
            },
            "dossier_errors": merged["errors"],
            "file_summaries": merged["file_summaries"],
        }

        conv_id = db_create_conversation(
            _derive_title(all_files),
            compute_codebase_hash(all_files),
            list(all_files.keys()),
            json.dumps({"chunks": total_chunks, "tasks": len(tasks)}),
            results,
        )
        results["conversation_id"] = conv_id

        analysis_state["results"] = results
        analysis_state["status"] = "done"
        print(f"[AI-v2] ✓ Pipeline complete: {len(raw_vulns)} vulns, "
              f"{results['pipeline']['constants_extracted']} constants extracted")
        return jsonify({"status": "done", "results": results, "conversation_id": conv_id})

    except Exception as e:
        analysis_state["status"] = "error"
        analysis_state["error"] = str(e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    if not AZURE_OPENAI_API_KEY:
        print("[!] WARNING: AZURE_OPENAI_API_KEY not set in .env")
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port, threaded=True)

