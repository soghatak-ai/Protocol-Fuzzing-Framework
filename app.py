import os
import re
import json
import time
import uuid
import queue
import hashlib
import traceback
import threading
import subprocess as _subprocess
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
                  create_instance, get_instance, list_instances, destroy_instance,
                  run_instance_live, FuzzerInstance,
                  log_event, ai_weights, DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS,
                  FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS,
                  HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS,
                  SMTP_STRATEGY_NAMES, SMTP_DEFAULT_WEIGHTS,
                  SSH_STRATEGY_NAMES, SSH_DEFAULT_WEIGHTS,
                  SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS,
                  SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS,
                  HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS,
                  DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS,
                  DHCP_STRATEGY_NAMES, DHCP_DEFAULT_WEIGHTS,
                  DHCPV6_STRATEGY_NAMES, DHCPV6_DEFAULT_WEIGHTS,
                  SNMP_STRATEGY_NAMES, SNMP_DEFAULT_WEIGHTS,
                  ICMP_STRATEGY_NAMES, ICMP_DEFAULT_WEIGHTS,
                  ICMPV6_STRATEGY_NAMES, ICMPV6_DEFAULT_WEIGHTS,
                  SIP_STRATEGY_NAMES, SIP_DEFAULT_WEIGHTS,
                  MGCP_STRATEGY_NAMES, MGCP_DEFAULT_WEIGHTS,
                  RTSP_STRATEGY_NAMES, RTSP_DEFAULT_WEIGHTS,
                  RADIUS_STRATEGY_NAMES, RADIUS_DEFAULT_WEIGHTS,
                  TACACS_STRATEGY_NAMES, TACACS_DEFAULT_WEIGHTS,
                  LDAP_STRATEGY_NAMES, LDAP_DEFAULT_WEIGHTS,
                  CIFS_STRATEGY_NAMES, CIFS_DEFAULT_WEIGHTS,
                  SUNRPC_STRATEGY_NAMES, SUNRPC_DEFAULT_WEIGHTS,
                  TELNET_STRATEGY_NAMES, TELNET_DEFAULT_WEIGHTS,
                  TFTP_STRATEGY_NAMES, TFTP_DEFAULT_WEIGHTS,
                  dns_bandit, ftp_bandit, http_bandit, smtp_bandit, ssh_bandit,
                  smb2_bandit, smb3_bandit, http2_bandit, dcerpc_bandit, dhcp_bandit,
                  dhcpv6_bandit, snmp_bandit, icmp_bandit, icmpv6_bandit, sip_bandit,
                  mgcp_bandit, rtsp_bandit, radius_bandit, tacacs_bandit, ldap_bandit,
                  cifs_bandit, sunrpc_bandit, telnet_bandit, tftp_bandit)
from protocol.ftp import FTP_STRATEGY_LABELS
from protocol.http import HTTP_STRATEGY_LABELS
from protocol.smtp import SMTP_STRATEGY_LABELS
from protocol.ssh import SSH_STRATEGY_LABELS
from protocol.smb import SMB2_STRATEGY_LABELS, SMB3_STRATEGY_LABELS
from protocol.http2 import HTTP2_STRATEGY_LABELS
from protocol.dcerpc import DCERPC_STRATEGY_LABELS
from protocol.dhcp import DHCP_STRATEGY_LABELS
from protocol.dhcpv6 import DHCPV6_STRATEGY_LABELS
from protocol.snmp import SNMP_STRATEGY_LABELS
from protocol.icmp import ICMP_STRATEGY_LABELS
from protocol.icmpv6 import ICMPV6_STRATEGY_LABELS
from protocol.sip import SIP_STRATEGY_LABELS
from protocol.mgcp import MGCP_STRATEGY_LABELS
from protocol.rtsp import RTSP_STRATEGY_LABELS
from protocol.radius import RADIUS_STRATEGY_LABELS
from protocol.tacacs import TACACS_STRATEGY_LABELS
from protocol.ldap import LDAP_STRATEGY_LABELS
from protocol.cifs import CIFS_STRATEGY_LABELS
from protocol.sunrpc import SUNRPC_STRATEGY_LABELS
from protocol.telnet import TELNET_STRATEGY_LABELS
from protocol.tftp import TFTP_STRATEGY_LABELS
from engine.code_collector import (collect_to_dict, collect_to_single_text, VALID_EXTENSIONS,
                                    minify_code, hotspot_filter, extract_repo_map,
                                    build_optimized_context, estimate_tokens)
from transport.file_sender import send_file_http, send_file_ftp, send_file_smtp, send_file_ssh, send_file_smb, send_file_http2, send_file_dcerpc, send_file_dhcp, send_file_dhcpv6, send_file_snmp, send_file_icmp, send_file_icmpv6, send_file_sip, send_file_mgcp, send_file_rtsp, send_file_radius, send_file_tacacs, send_file_ldap, send_file_cifs, send_file_sunrpc, send_file_telnet, send_file_tftp
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
    if protocol == "ssh":
        return SSH_STRATEGY_LABELS
    if protocol == "smb2":
        return SMB2_STRATEGY_LABELS
    if protocol == "smb3":
        return SMB3_STRATEGY_LABELS
    if protocol == "http2":
        return HTTP2_STRATEGY_LABELS
    if protocol == "dcerpc":
        return DCERPC_STRATEGY_LABELS
    if protocol == "dhcp":
        return DHCP_STRATEGY_LABELS
    if protocol == "dhcpv6":
        return DHCPV6_STRATEGY_LABELS
    if protocol == "snmp":
        return SNMP_STRATEGY_LABELS
    if protocol == "icmp":
        return ICMP_STRATEGY_LABELS
    if protocol == "icmpv6":
        return ICMPV6_STRATEGY_LABELS
    if protocol == "sip":
        return SIP_STRATEGY_LABELS
    if protocol == "mgcp":
        return MGCP_STRATEGY_LABELS
    if protocol == "rtsp":
        return RTSP_STRATEGY_LABELS
    if protocol == "radius":
        return RADIUS_STRATEGY_LABELS
    if protocol == "tacacs":
        return TACACS_STRATEGY_LABELS
    if protocol == "ldap":
        return LDAP_STRATEGY_LABELS
    if protocol == "cifs":
        return CIFS_STRATEGY_LABELS
    if protocol == "sunrpc":
        return SUNRPC_STRATEGY_LABELS
    if protocol == "telnet":
        return TELNET_STRATEGY_LABELS
    if protocol == "tftp":
        return TFTP_STRATEGY_LABELS
    return DNS_STRATEGY_LABELS


def _bandit_for_proto(protocol):
    if protocol == "ftp":
        return ftp_bandit
    if protocol == "http":
        return http_bandit
    if protocol == "smtp":
        return smtp_bandit
    if protocol == "ssh":
        return ssh_bandit
    if protocol == "smb2":
        return smb2_bandit
    if protocol == "smb3":
        return smb3_bandit
    if protocol == "http2":
        return http2_bandit
    if protocol == "dcerpc":
        return dcerpc_bandit
    if protocol == "dhcp":
        return dhcp_bandit
    if protocol == "dhcpv6":
        return dhcpv6_bandit
    if protocol == "snmp":
        return snmp_bandit
    if protocol == "icmp":
        return icmp_bandit
    if protocol == "icmpv6":
        return icmpv6_bandit
    if protocol == "sip":
        return sip_bandit
    if protocol == "mgcp":
        return mgcp_bandit
    if protocol == "rtsp":
        return rtsp_bandit
    if protocol == "radius":
        return radius_bandit
    if protocol == "tacacs":
        return tacacs_bandit
    if protocol == "ldap":
        return ldap_bandit
    if protocol == "cifs":
        return cifs_bandit
    if protocol == "sunrpc":
        return sunrpc_bandit
    if protocol == "telnet":
        return telnet_bandit
    if protocol == "tftp":
        return tftp_bandit
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


_BSON_INT_MAX = (1 << 63) - 1
_BSON_INT_MIN = -(1 << 63)

def _clamp_ints(obj):
    """Recursively clamp Python ints that exceed BSON 64-bit range to strings."""
    if isinstance(obj, dict):
        return {k: _clamp_ints(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clamp_ints(v) for v in obj]
    if isinstance(obj, int) and not isinstance(obj, bool):
        if obj > _BSON_INT_MAX or obj < _BSON_INT_MIN:
            return str(obj)
    return obj

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
    safe_analysis = _clamp_ints(safe_analysis)
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


def db_save_trigger_packets(conv_id, trigger_packets, vuln_packets):
    """Persist trigger packets into the conversation document."""
    if not mongo_ok() or not conv_id:
        return
    try:
        safe_tp = json.loads(json.dumps(trigger_packets, default=str))
        safe_vp = json.loads(json.dumps(vuln_packets, default=str))
        _conversations.update_one(
            {"_id": conv_id},
            {"$set": {
                "trigger_packets": safe_tp,
                "vuln_packets": safe_vp,
                "updated_at": datetime.now(timezone.utc),
            }},
        )
        print(f"[DB] Trigger packets saved ({len(trigger_packets)} packets) → conv {conv_id}")
    except Exception as e:
        print(f"[DB] save_trigger_packets failed: {e}")


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
- connection_state_uaf: CVE-2026-20026/CVE-2026-20027 — sustained multi-REQUEST flood on an established connection targeting buffer lifecycle bugs: 200-500 REQUESTs with escalating call_ids (free-list stress), interleaved ALTER_CONTEXT+REQUEST (context table realloc UAF), same call_id reused 300× (tracking state collision), rapid context_id switching with OOB ids (0-9 when only 0-7 bound), stub size oscillation tiny↔huge (realloc OOB read), REQUEST+CO_CANCEL+immediate reuse (freed tracking state access), 300 random opnum storm (dispatch table confusion), 400 first-fragments-only (reassembly state never freed → stale pointer read on flush). Targets per-call and per-context buffer allocation/deallocation in the DCE/RPC inspector. Triggers: use-after-free, oob-read, crash, info-leak

DHCP STRATEGIES (used when fuzzing DHCPv4 inspectors — UDP ports 67/68, BOOTP+options format):
- rogue_server_attack: Rogue DHCPOFFER/DHCPACK with attacker-controlled gateway/DNS/WPAD/NTP — gateway redirect, DNS hijack, WPAD proxy injection, full MITM (all services redirected), rapid offer racing, NAK-then-offer forcing client back to INIT. Targets rogue server detection. Triggers: evasion, state-corruption, configuration-hijack
- starvation_flood: DHCP pool exhaustion — 50-MAC burst DISCOVER, slow drip with realistic vendor classes, vendor fingerprint mixing, DISCOVER+REQUEST confirm pairs, DECLINE flood marking addresses unavailable, INFORM flood from random IPs. Targets rate-based detection. Triggers: resource-exhaustion, evasion, threshold-bypass
- option_tlv_overflow: TLV option parsing abuse — max length=255 options, length exceeding remaining packet (OOB read), missing end marker (0xFF), options past end marker, 200+ tiny options stressing loop counters, duplicate option 53 with conflicting message types, zero-length options, 1200-byte option chain bomb. Targets option parser. Triggers: oob-read, buffer-overflow, integer-overflow
- option_overload_attack: Option 52 (overload) semantic gap — sname holds options (IDS misses), file holds options, both overloaded, conflicting DNS in main vs sname (IDS sees safe value, server sees attacker value), no end marker in overloaded field, nested overload (option 52 inside sname). Targets option field discovery. Triggers: evasion, oob-read, state-corruption
- magic_cookie_corruption: Magic cookie (0x63825363) manipulation — wrong last byte, all-zero cookie (BOOTP fallback), partial cookie (2/4 bytes), pure BOOTP vendor area (no cookie), shifted cookie (4 pad bytes before), doubled cookie. Targets DHCP vs BOOTP detection. Triggers: evasion, state-corruption, oob-read
- relay_agent_injection: Option 82 (Relay Agent Info) spoofing — forged circuit-ID with trusted switch port, 250-byte oversized sub-option, contradictory giaddr vs circuit-ID subnet, multiple option 82 instances, nested sub-options, fake multi-hop relay chain (hops=3). Targets relay authentication and subnet-aware rules. Triggers: evasion, oob-read, access-control-bypass
- state_machine_violation: Illegal DHCP state transitions — DHCPREQUEST without prior DISCOVER, RELEASE then immediate reuse, FORCERENEW from spoofed server (RFC 3203), 10 rapid DORA cycles churning state tables, DECLINE before REQUEST, 20 duplicate DISCOVERs. Targets stateful detection. Triggers: state-corruption, evasion, resource-exhaustion
- bootp_crossover: Pure BOOTP / mixed BOOTP-DHCP — BOOTP with no options (zero vendor area), BOOTP with magic cookie but no option 53, concatenated BOOTP+DHCP packets, op code mismatch (BOOTREPLY op with DISCOVER options). Targets protocol classification. Triggers: evasion, state-corruption
- field_boundary_attack: Fixed-header field abuse — hlen=20 (overflow past 16-byte chaddr), truncated packet (cut at 100 bytes), oversized packet (1KB+ options), NULL-embedded sname, secs=0xFFFF. Targets header parsing boundaries. Triggers: oob-read, buffer-overflow, integer-overflow
- xid_collision: Transaction ID manipulation — XID reuse across 10 clients, XID=0, XID=0xFFFFFFFF, rapid sequential XIDs (0-29), same XID with different MACs and message types. Targets transaction tracking. Triggers: state-corruption, evasion
- lease_time_confusion: Lease time option manipulation — lease=0 (immediate expiration), lease=0xFFFFFFFF (infinite), T1>T2 (reversed renewal/rebinding), micro-lease (1 second), signed-negative-like value (0x80000001). Targets timer management. Triggers: integer-overflow, state-corruption
- broadcast_flag_abuse: Flags field manipulation — all reserved bits set (0x7FFF), broadcast flag on unicast-only renewal, cleared broadcast on broadcast-required discovery, flags=0xFFFF. Targets flag validation. Triggers: evasion, state-corruption
- client_id_spoof: Option 61 (Client Identifier) attacks — 200-byte oversized ID, client ID contradicting chaddr MAC, multiple option 61 instances, empty (zero-length) client ID, invalid hardware type byte (0xFF), htype mismatch (IEEE 802 vs Ethernet). Targets client identification. Triggers: evasion, oob-read, identity-confusion
- sname_file_injection: sname (64B) / file (128B) field payload injection — path traversal (../../../../etc/passwd), shell metacharacters ($(wget...)), format strings (%n%x), non-NUL-terminated overflow, embedded magic cookie + options in sname, random binary payload. Targets string handling in fixed fields. Triggers: command-injection, buffer-overflow, oob-read

DHCPv6 STRATEGIES (used when fuzzing DHCPv6 inspectors — UDP ports 546/547, 4-byte header + 16-bit TLV options):
- rogue_server_advertise: Rogue DHCPv6 server attacks — fake Advertise with attacker-controlled DNS (option 23), domain search list (option 24), SIP servers (options 21/22), preference=255 to always win server selection, Rapid Commit hijack (single-message Reply), full MITM (DNS+domain+SIP+NTP redirected), 20 competing Advertise race. Targets rogue server detection. Triggers: evasion, configuration-hijack, state-corruption
- duid_identity_attack: DUID manipulation (IEEE DHCPv6 starvation paper) — oversized DUID >130 bytes (RFC max violation), zero-length DUID, DUID type switching between messages (LLT→EN→UUID), DUID-LLT with extreme time values (0, 0x7FFFFFFF, 0xFFFFFFFF), enterprise number spoofing (Cisco=9, Microsoft=311), DUID-UUID with nil/max/pattern UUIDs, Client ID = Server ID contradiction, 50 unique DUID flood. Targets DUID parsing and identity tracking. Triggers: oob-read, identity-confusion, resource-exhaustion, evasion
- starvation_solicit_flood: DHCPv6 address pool exhaustion (IEEE paper core attack) — 50-MAC burst Solicit with unique DUID-LL, Solicit+Request confirm pairs, single client with 20 IAIDs, IA_PD prefix delegation exhaustion, Rapid Commit flood (single-message assignment), Decline flood marking addresses unusable, DUID type mixing to evade rate limiting. Targets rate-based detection. Triggers: resource-exhaustion, evasion, threshold-bypass
- option_nested_overflow: DHCPv6 option TLV exploitation (16-bit option-len, nestable containers) — option-len=0xFFFF with 10 bytes (OOB read), IA_NA with option-len=0 (missing IAID+T1+T2), 15-deep recursive IA_NA nesting, 64KB single option, 500 tiny options stressing allocators, duplicate singleton Client ID options, unknown option codes (0, 0xFFFF), container sub-option overflow past declared length. Targets option parser. Triggers: oob-read, buffer-overflow, integer-overflow, memory-exhaustion
- relay_chain_injection: DHCPv6 relay agent message manipulation — 50-deep relay nesting (recursive Relay Message option 9), link-address spoofing (unspecified, loopback, multicast, v4-mapped), peer-address as multicast, Client Link-Layer option (79) outside Relay-Forward, missing Relay Message option, cross-scope relay (link-local link with GUA peer), hop-count=255 with deep nesting. Targets relay processing. Triggers: oob-read, stack-overflow, state-corruption, evasion
- ia_lifetime_confusion: IA_NA/IA_PD lifetime and timer manipulation — T1>T2 (reversed renewal/rebinding), all values=0xFFFFFFFF (infinity), preferred-lifetime>valid-lifetime (RFC violation), zero valid-lifetime (immediate deprecation), prefix-length extremes (0=entire space, 128=single address), conflicting lifetimes across multiple IA addresses. Targets timer management. Triggers: integer-overflow, state-corruption
- state_machine_desync: DHCPv6 state machine violations — Request without prior Solicit, Renew to wrong server (Server ID mismatch), Release of addresses not owned, Confirm on wrong link, Information-Request with IA_NA (stateless+stateful mix), 10 rapid SARR cycles churning state tables, Rebind with active binding. Targets stateful detection. Triggers: state-corruption, evasion, resource-exhaustion
- reconfigure_forge: Reconfigure message exploitation — forged Reconfigure without Authentication option, bad RKAP HMAC-MD5, invalid Reconfigure msg-type values (1,3,7,255), Reconfigure Accept in client Solicit, wrong Server ID, 30 rapid Reconfigure flood. Targets Reconfigure authentication. Triggers: evasion, state-corruption, auth-bypass
- dns_option_injection: DNS/domain option manipulation (options 23, 24, 39) — DNS label >63 bytes (RFC violation), compression pointers in DHCPv6 (not allowed), null bytes embedded in domain names, FQDN option with contradictory S+N flags, DNS servers pointing to loopback/all-zeros/all-ones, domain name >255 bytes total. Targets DNS-encoded data parsing. Triggers: oob-read, buffer-overflow, evasion
- vendor_class_exploit: Vendor Class/Opts options (16/17) manipulation — enterprise number 0 and 0xFFFFFFFF, spoofed Cisco enterprise (9), vendor-class-data length mismatch (claims 100, sends 5), multiple Vendor Class options, 64KB oversized vendor-specific data. Targets vendor data parsing. Triggers: oob-read, buffer-overflow, integer-overflow
- transaction_id_manipulation: 24-bit transaction-id attacks — txid=0 (edge case), txid=0xFFFFFF (max), txid reuse across 10 clients, sequential cycling (0-99), Reply spoofing with guessed txids, same txid across different message types (Solicit/Request/Renew/Release/Decline/Confirm). Targets transaction tracking. Triggers: state-corruption, evasion
- prefix_delegation_abuse: IA_PD specific attacks — /0 prefix (entire address space), /128 prefix (single address), duplicate IAID across IA_PD options, IPv4-mapped IPv6 prefix (::ffff:10.0.0.0/96), overlapping prefix requests, 100 mass IA_PD requests. Targets prefix delegation handling. Triggers: oob-read, resource-exhaustion, state-corruption
- multiprotocol_evasion: Cross-protocol and encapsulation attacks — DHCPv4-in-DHCPv6 (DHCPV4-QUERY msg-type 20, RFC 7341), invalid message types (0, 24, 50, 128, 255), STARTTLS (msg-type 23) on UDP (should be TCP per RFC 7653), unauthorized LEASEQUERY, Relay Message option inside client message, msg-type=0 (undefined). Targets protocol classification. Triggers: evasion, state-corruption
- elapsed_time_preference_fuzz: Elapsed Time and Preference option edge cases — elapsed=0xFFFF (max 655.35s), elapsed=0 in non-initial Renew, Preference in non-Advertise Solicit, multiple Elapsed Time options, unknown status codes (7, 100, 0xFFFF), 64KB oversized status-message. Targets option validation. Triggers: integer-overflow, oob-read, state-corruption

SSH STRATEGIES (used when fuzzing SSH inspectors, e.g. Snort 3 ssh — the inspector only parses the UNENCRYPTED handshake on port 22: version exchange, binary packet protocol, KEXINIT/KEXDH/NEWKEYS; gid 135 events):
- version_overflow: SSH identification-string abuse (RFC 4253 §4.2: max 255 chars incl. CR LF, no NUL) — giant softwareversion/comments, no CRLF terminator, embedded NUL, bare-LF, extra dashes splitting protoversion. Targets the version-string buffer (max_server_version_len). Triggers: buffer-overflow, oob-read, evasion (135:3 SECURECRT, 135:7 VERSION)
- version_confusion: protocol version mismatch/downgrade (RFC 4253 §5) — SSH-1.5 banner then SSH2 body, "1.99" compatibility confusion, malformed protoversion (9.9/2/./2.0.0), missing "SSH-" magic, SSH2-then-SSH1-packet, double version line. Targets version detection and the SSH1<->SSH2 state machine. Triggers: state-corruption, evasion, null-deref (135:4 PROTOMISMATCH)
- banner_flood: pre-version line abuse (server MAY send lines before the version string, which MUST NOT begin with "SSH-") — thousands of pre-lines, one giant pre-line, unterminated pre-data, illegal "SSH-"-prefixed pre-lines, bare-CR lines, NUL lines. Targets pre-version line buffering/reassembly. Triggers: memory-exhaustion, oob-read, state-corruption
- packet_length_attack: binary-packet packet_length (uint32) field torture (RFC 4253 §6) — 0xFFFFFFFF, 0, 1, ~16MB declared with few bytes, packet_length vs padding_length underflow (payload_len = packet_length - padding_length - 1), length>>actual, genuinely-huge well-formed packet. Targets the length field and the payload_len computation. Triggers: integer-overflow, integer-underflow, oob-read, heap-overflow (135:6 PAYLOAD_SIZE)
- padding_corruption: padding_length byte abuse (RFC 4253 §6: MUST be 4..255, total a multiple of the block size) — padding=0, <4, 255 with small packet, padding>packet, padding==packet_length (payload_len=-1), total not a block multiple. Targets padding subtraction. Triggers: integer-underflow, oob-read, buffer-overflow (135:6 PAYLOAD_SIZE)
- kexinit_namelist_overflow: KEXINIT name-list (uint32 length-prefixed) parser abuse (RFC 4253 §7.1) — first name-list claims 0xFFFFFFFF with few bytes (OOB read), thousands of algorithm names, one 50KB name, all 10 lists zero-length, name-list length past packet boundary, names with embedded NUL/comma/control chars, every list a count flood. Targets KEXINIT parsing and allocation. Triggers: oob-read, memory-exhaustion, heap-overflow
- challenge_response_overflow: CVE-2002-1357 Challenge-Response Buffer Overflow — the client sends more than max_client_bytes (default 19600) BEFORE key exchange completes: one giant pre-KEX packet, many medium packets with no NEWKEYS, a KEXDH_INIT whose mpint alone exceeds the limit, a slow drip of tiny packets past the threshold. Targets the pre-KEX byte accounting. Triggers: buffer-overflow, resource-exhaustion (135:1 RESPOVERFLOW)
- crc32_attack: CVE-2001-0144 SSH1 CRC32 compensation attack — SSH-1.5 banner then SSH1 packets with oversized length, many identical 8-byte padding blocks (the deattack heuristic), all-zero blocks, malformed SSH_CMSG_SESSION_KEY. Targets the SSH1 CRC32 deattack detector. Triggers: integer-overflow, oob-read, buffer-overflow (135:2 CRC32)
- kexdh_mpint_overflow: KEXDH_INIT/REPLY mpint & string length parsing (RFC 4253 §8) — mpint declares 0xFFFFFFFF length with few bytes, negative mpint (high bit set), zero-length mpint, unnecessary leading zeros, KEXDH_REPLY (server-only) from client with giant host-key/signature strings, mpint length past packet boundary. Targets the bignum/string parser. Triggers: oob-read, integer-overflow, heap-overflow (135:5 WRONGDIR)
- state_machine_desync: out-of-order / wrong-direction key-exchange messages (RFC 4253 §7) — KEXDH_INIT before KEXINIT, premature NEWKEYS, triple KEXINIT, SERVICE_REQUEST before NEWKEYS, server-only SERVICE_ACCEPT from client, NEWKEYS then cleartext KEX, KEXINIT storm. Targets the inspector's KEX state tracking. Triggers: state-corruption, evasion, null-deref (135:5 WRONGDIR)
- encrypted_packet_evasion: abuse max_encrypted_packets (default 25 — the inspector stops deep inspection after this many encrypted packets) — complete a fake KEX then push >25 "encrypted" packets so Snort gives up, then send an overflow that should now be missed; rapid NEWKEYS; post-encryption overflow; many small encrypted packets. Targets the inspect-then-give-up lifecycle. Triggers: evasion, state-corruption
- disconnect_desync: transport-layer message abuse (RFC 4253 §11) — data after DISCONNECT, SSH_MSG_IGNORE flood, SSH_MSG_DEBUG with a huge message, SSH_MSG_UNIMPLEMENTED storm, DISCONNECT with reason 0xFFFFFFFF + oversized description, DEBUG with terminal-control escapes. Targets transport message handling and post-disconnect tracking. Triggers: state-corruption, oob-read, evasion
- guess_kex_confusion: KEX guessing logic (RFC 4253 §7.1) — first_kex_packet_follows=1 with a guessed packet that won't match, all-zero / all-0xFF cookie, the trailing reserved uint32 set non-zero, multiple guessed packets, a guessed packet with an oversized mpint. Targets the "ignore the wrongly-guessed packet" branch and cookie/reserved validation. Triggers: state-corruption, oob-read
- gex_group_attack: Diffie-Hellman Group Exchange (RFC 4419) integer/bignum parser — GEX_REQUEST with min>max, n=0xFFFFFFFF, all-zero min/n/max, GEX_GROUP with an oversized prime p, GEX_REQUEST_OLD with max n, GEX_INIT with an oversized e, GEX_GROUP with negative p/g. Targets the group-exchange parser (distinct from fixed group1/group14 DH). Triggers: integer-overflow, oob-read, heap-overflow

SNMP STRATEGIES (used when fuzzing SNMP stacks/agents — UDP 161 requests, 162 traps. Snort 3 has NO dedicated SNMP inspector: detection is via gid-1 text rules (community public/private sid 1407-1410, request/trap sid 1417-1420) plus whatever BER/ASN.1 decoding runs. Canonical fuzz corpus is PROTOS c06-SNMPv1, CVE-2002-0012/0013):
- ber_length_overflow: BER length-field integer overflow — long-form length declaring 0xFFFFFFFF/0x7FFFFFFF bytes with a tiny body, 5-octet length (0x85, illegal), length > remaining buffer at SEQUENCE/OCTET-STRING/INTEGER/VarBind/PDU level, 64-bit length that wraps when added to the read offset. Targets the length-parsing arithmetic. Triggers: integer-overflow, heap-overflow, oob-read
- ber_indefinite_nonminimal: Indefinite-length form (0x80 + EOC, ambiguous for SNMP) and redundant non-minimal length octets (RFC 3417 explicitly permits non-minimal lengths: 0x81 0x06, 0x83 00 00 06, 4-octet long form everywhere). Snort and the target disagree on field boundaries. Triggers: evasion, state-corruption, oob-read
- truncated_tlv: Declared length exceeds the bytes actually present at every nesting level — outer SEQUENCE body halved, community/PDU/VarBind-SEQUENCE/OID/INTEGER claim more than supplied, OID then no value. OOB read past the packet end. Triggers: oob-read, crash
- version_pdu_confusion: version INTEGER abuse + version/PDU mismatch — negative version (-1), 8-byte huge version, 0-length INTEGER (illegal), v1(version=0) carrying a GetBulk[A5] (v2-only) PDU, msgVersion=3 with a v1 community wrapper, unknown version 99, non-minimal padded version. Downgrade + dispatcher state confusion. Triggers: state-corruption, evasion, null-deref
- getbulk_amplification: GetBulkRequest[A5] resource exhaustion — max-repetitions=0x7FFFFFFF, non-repeaters=0x7FFFFFFF, negative non-repeaters, 400-OID lists, non-repeaters > varbind count, 9-byte oversized max-repetitions (RFC 3416 max-bindings=2147483647). Forces enormous responses (amplification DoS). Triggers: resource-exhaustion, integer-overflow, dos
- oid_encoding_attack: OID parser abuse — >128 sub-identifiers (RFC 3416 limit), sub-id > 2^32-1 (5-byte base-128), overlong non-minimal encoding (leading 0x80 continuation bytes), unterminated sub-id (high bit set on last byte), empty OID (length 0), giant 0xFFFFFFFF sub-ids, invalid first byte 0xFF. OID parser integer overflow. Triggers: integer-overflow, oob-read, buffer-overflow
- varbind_bomb: VarBindList abuse — 2000-varbind flood, response-only exception tags (noSuchObject[80]/noSuchInstance[81]/endOfMibView[82]) inside a request, type-confused values (nested PDU/OID where a scalar is expected), 40KB OCTET-STRING values, zero-length varbind SEQUENCEs, deeply nested value. Memory exhaustion + type confusion. Triggers: memory-exhaustion, type-confusion, oob-read
- trap_v1_malform: SNMPv1 Trap-PDU[A4] torture (the historically broken parser, PROTOS c06 / CVE-2002-0012) sent to UDP 162 — agent-addr IpAddress not 4 bytes (0/16), generic-trap out of 0..6 range (huge/negative), malformed enterprise OID, oversized specific-trap, >32-bit TimeTicks, missing fields, oversized varbinds, empty-field 'protos_classic'. Triggers: buffer-overflow, integer-overflow, dos
- integer_field_overflow: INTEGER encoding abuse across request-id/error-status/error-index and application integers — 9-byte request-id (>64-bit), 0-length INTEGER (illegal), error-status outside 0..18 (0xFFFF), 10-byte Counter64 (>64-bit), negative via padding, non-minimal leading-zero integer, huge error-index. Integer parser overflow. Triggers: integer-overflow, oob-read
- community_overflow: community OCTET-STRING abuse — 40KB oversized, embedded NUL bytes, format-string (%n%s%x), the rule-tripping 'public'/'private', zero-length community, random binary, length-field lie (declares 4, supplies more). Buffer overflow + Snort rule evasion. Triggers: buffer-overflow, evasion, format-string
- nested_sequence_bomb: Deeply nested SEQUENCE-of-SEQUENCE (1500 levels), deep VarBind nesting (800), alternating SEQUENCE/context tags (600), wide-then-deep. Exhausts recursive-descent BER parsers. Triggers: stack-overflow, resource-exhaustion, crash
- v3_header_malform: SNMPv3 HeaderData / dispatcher abuse — invalid msgFlags (0x02 priv-without-auth reserved, 0xFF), unknown msgSecurityModel (0/99/huge), msgMaxSize < 484 (RFC violation), 6-byte huge msgMaxSize, truncated msgGlobalData, ScopedPduData CHOICE confusion (encryptedPDU where plaintext expected), msgFlags wrong OCTET-STRING size. Triggers: state-corruption, oob-read, evasion
- usm_param_overflow: USM UsmSecurityParameters abuse (RFC 3414/3411 size bounds) — msgUserName > 32 bytes (SIZE 0..32), engineID > 32 / < 5 bytes (SIZE 5..32), oversized auth params (≠12), oversized priv params (≠8), engineBoots/engineTime > 2^31, truncated inner SEQUENCE, all-oversize. USM parser buffer overflow. Triggers: buffer-overflow, integer-overflow, oob-read
- engineid_scopedpdu_abuse: engineID discovery (RFC 5343) + ScopedPDU context-field abuse — empty-engineID/empty-user discovery, invalid engineID format byte (0x00/0x7F/0xFF), 20KB contextEngineID, 20KB contextName, NUL-laden contextName, client-sent Report-PDU[A8] (engine-to-engine only), scopedPDU SEQUENCE length mismatch. Triggers: state-corruption, oob-read, dos

ICMP STRATEGIES (used when fuzzing ICMPv4 processing — IP protocol 1, Snort 3 GID 124 ICMP4 / GID 116 IP decoder / GID 123 frag3):
- fragment_reassembly_evasion: IP fragmentation of ICMP packets — overlapping fragments (BSD vs Windows reassembly policy disagreement), tiny fragments splitting ICMP header across boundary (itype/icode rules can't match), out-of-order delivery, duplicate first fragments, fragment chains with gaps, oversized reassembled total exceeding 65535. Targets IP defrag engine. Triggers: oob-read, heap-overflow, evasion, memory-corruption
- embedded_header_confusion: ICMP error messages (type 3/11/12) carry the "original datagram" IP+8 bytes — malformed embedded IP header (IHL=0/15, protocol mismatch, truncated), embedded header contradicting outer header (different src/dst IP), embedded TCP/UDP ports crafted to confuse 5-tuple tracking, oversized embedded payload (>576 bytes), embedded header with IP options shifting the ICMP data offset. Targets error-message inner-header parser. Triggers: oob-read, state-corruption, type-confusion
- type_code_matrix_attack: Full type×code combinatorial sweep including undefined/reserved pairs — type 0-255 × code 0-255, emphasis on rarely-tested types (type 40 Photuris, type 42 Extended Echo, type 253/254 experimental), valid types with invalid codes (Echo Reply code=255), type 3 with code>15 (undefined Destination Unreachable sub-codes). Targets type/code dispatch and validation. Triggers: oob-read, null-deref, state-corruption
- checksum_desync: ICMP checksum manipulation — correct checksum (baseline), intentionally wrong checksum (IDS may drop while target accepts with offloading), checksum=0x0000 (special?), checksum=0xFFFF, near-miss checksum (off by 1), checksum computed over truncated packet. IDS/target disagreement on validity. Triggers: evasion, state-corruption
- redirect_route_injection: ICMP Redirect (type 5) with crafted gateway addresses — redirect to attacker IP, redirect to 127.0.0.1 (loopback), redirect to multicast/broadcast, code 0-3 (network/host/ToS+network/ToS+host), oversized embedded original datagram, rapid redirect flood from spoofed router IP. Targets route table manipulation detection. Triggers: evasion, state-corruption, route-hijack
- tunnel_payload_evasion: ICMP Echo payloads carrying covert protocol data — DNS query in echo payload, HTTP request in echo payload, shellcode/NOP sled pattern, ICMP-over-ICMP nesting, payload matching IDS content rules but inside ICMP data field (cross-protocol evasion), oversized echo data (>1400 bytes). Targets deep inspection of ICMP payload. Triggers: evasion, oob-read
- pmtud_blackhole: Path MTU Discovery abuse via ICMP type 3 code 4 (Fragmentation Needed) — next-hop MTU=0 (implementation-dependent), MTU=68 (minimum), MTU=1 (absurd), MTU > outer packet size (invalid), MTU=0xFFFF, rapid PMTUD messages from spoofed intermediate routers, embedded packet not matching any active flow. Targets PMTUD state tracking. Triggers: integer-overflow, state-corruption, dos
- unreachable_state_exhaustion: ICMP Destination Unreachable (type 3) flood with unique embedded 5-tuples — each message references a different src_ip/dst_ip/src_port/dst_port/proto, forcing the IDS to look up/create state entries for flows that don't exist, mixed sub-codes (port/host/network/admin unreachable), rapid burst of 500+ unique entries. Targets connection tracking state table. Triggers: memory-exhaustion, state-corruption, dos
- ip_option_header_shift: IP header with options before the ICMP payload — Record Route (type 7), Timestamp (type 68), Loose/Strict Source Route (type 131/137), Security (type 130), maximum IHL=15 (60-byte IP header), multiple options filling all 40 option bytes, options with invalid lengths, NOP padding patterns. Shifts the ICMP payload offset; IDS may read wrong bytes as ICMP header. Triggers: oob-read, evasion, buffer-overflow
- ping_of_death_reassembly: Classic Ping of Death (CVE-1999-0128) and modern variants — fragment chain whose reassembled total exceeds 65535 bytes (IP length overflow), last fragment with offset+size > 65535, Jolt2-style identical fragments, teardrop-style negative fragment length, land attack (src=dst IP) with oversized echo. Targets IP reassembly buffer allocation. Triggers: integer-overflow, heap-overflow, dos
- rate_limit_bypass: Circumvent ICMP rate limiting — slow drip below threshold (1 pkt/sec), burst then pause pattern, mixed ICMP types to avoid per-type counters, source IP rotation across /24, alternating echo request/reply direction, fragmented ICMP (fragments may bypass ICMP rate counter since type isn't visible until reassembly). Targets rate-limiting logic. Triggers: evasion, threshold-bypass
- echo_id_seq_desync: ICMP Echo identifier/sequence number tracking confusion — ID=0, ID=0xFFFF, seq=0xFFFF, ID reuse across different source IPs, rapid ID cycling (0-1000), seq number going backwards, matching echo reply for non-existent request, ID/seq mismatch between request and reply. Targets session/flow tracking. Triggers: state-corruption, evasion
- source_quench_deprecated: ICMP Source Quench (type 4, deprecated by RFC 6633) — some IDS still parse it, others ignore; valid source quench with embedded datagram, source quench with all codes (0-255, only 0 is defined), oversized embedded data, rapid flood. Tests deprecated-type handling code paths. Triggers: state-corruption, oob-read, evasion
- timestamp_address_mask_probe: ICMP Timestamp (type 13/14) and Address Mask (type 17/18) requests/replies — information-leak probes that reveal host uptime/clock and subnet mask; malformed timestamp fields (originate=0xFFFFFFFF, oversized payload), address mask with wrong length, types 15/16 (Information Request/Reply, obsolete), rapid probe sweep. Targets rarely-exercised parser branches. Triggers: oob-read, info-leak, state-corruption

ICMPv6 STRATEGIES (used when fuzzing ICMPv6 processing — IP protocol 58, Snort 3 GID 125 ICMP6 / GID 116 IP decoder):
- ndp_ra_spoofing: Rogue Router Advertisement injection — spoofed RA with crafted prefix info (rogue /64 prefix, zero-lifetime flush, MTU manipulation to force fragmentation, RDNSS injection for DNS hijack), SLLA option with attacker MAC, multiple prefix options with conflicting flags (L/A/R). Targets NDP RA parser and SLAAC autoconfiguration. Triggers: route-hijack, dns-hijack, evasion, state-corruption
- ndp_ns_na_confusion: Neighbor Solicitation/Advertisement manipulation — NA with Override+Solicited flags on unsolicited messages, NS with invalid hop limit (≠255), target address spoofing (link-local vs global confusion), TLLA option with broadcast MAC, DAD interference (NA for tentative address), rapid NS/NA flood with rotating addresses. Targets NDP neighbor cache and DAD. Triggers: cache-poisoning, state-corruption, dos
- ndp_option_tlv_overflow: NDP option TLV abuse — oversized option (length=255, 2040 bytes), zero-length option (infinite loop in parsers), option length exceeding packet boundary, deeply nested/chained options, unknown option types (128-255), option with length=0 causing division-by-zero in 8-byte unit calculation. Targets NDP option parser. Triggers: buffer-overflow, oob-read, infinite-loop, crash
- fragment_header_evasion: IPv6 Fragment Header (NH=44) abuse — overlapping fragments (RFC 5722 violation), atomic fragments (M=0, offset=0), tiny first fragment hiding ICMPv6 type/code, out-of-order delivery, fragment ID reuse, reassembled size exceeding 65535, fragment chain with conflicting Next Header values. Targets IPv6 fragment reassembly engine. Triggers: heap-overflow, oob-read, evasion, memory-corruption
- extension_header_chain: IPv6 extension header chain manipulation — long chains (HbH→Dst→Routing→Fragment→AH→ESP→Dst→ICMPv6), duplicate extension headers (RFC 8200 violation), unknown Next Header values (143-252), Hop-by-Hop with oversized PadN/unknown options, Routing Header type 0 (deprecated, source routing), Destination Options with huge TLV. Targets extension header chain parser. Triggers: stack-overflow, evasion, oob-read, resource-exhaustion
- pseudo_header_checksum_desync: ICMPv6 checksum uses IPv6 pseudo-header (src+dst+length+NH=58) — correct checksum baseline, intentionally wrong checksum (IDS drops but target with offloading accepts), checksum=0x0000 (special per RFC), near-miss off-by-one, checksum computed with wrong source address, checksum over truncated payload, upper-layer length mismatch in pseudo-header. IDS/target checksum disagreement. Triggers: evasion, state-corruption
- mld_multicast_abuse: Multicast Listener Discovery v1/v2 (types 130-132, 143) abuse — MLDv1 Report/Done for sensitive groups (ff02::1, ff02::2, ff02::fb), MLDv2 Report with oversized number of group records, MLD with source address not link-local (RFC violation), MLD Query with max response code manipulation, forged Done messages to trigger group leave, oversized auxiliary data in MLDv2 records. Targets MLD state machine. Triggers: state-corruption, dos, evasion
- packet_too_big_pmtud: ICMPv6 Packet Too Big (type 2) PMTUD manipulation — MTU=0 (implementation-dependent), MTU=1280 (IPv6 minimum, forces fragmentation), MTU=1 (absurd), MTU > original packet (invalid), MTU=0xFFFFFFFF, rapid PTB from spoofed intermediate routers, embedded packet not matching any active flow. Targets PMTUD state tracking. Triggers: integer-overflow, state-corruption, dos
- parameter_problem_pointer: ICMPv6 Parameter Problem (type 4) with crafted pointer — pointer=0 (version field), pointer=4 (payload length), pointer=6 (next header), pointer=7 (hop limit), pointer=40+ (into extension headers), pointer beyond packet length (oob read trigger), all three codes (erroneous header/unrecognized NH/unrecognized option), embedded packet with malformed extension headers. Targets error-message inner-packet parser. Triggers: oob-read, state-corruption, crash
- echo_tunnel_covert_channel: ICMPv6 Echo Request/Reply (types 128/129) payload abuse — DNS query in echo payload, HTTP request in echo payload, shellcode/NOP sled, ICMPv6-over-ICMPv6 nesting, payload matching IDS content rules inside echo data (cross-protocol evasion), oversized echo data (>1400 bytes), echo with IPv6 extension headers before ICMPv6. Targets deep payload inspection. Triggers: evasion, oob-read
- redirect_route_hijack: ICMPv6 Redirect (type 137) manipulation — redirect target to attacker link-local, redirect to multicast address, redirect with options containing spoofed TLLA, redirect for off-link destinations (RFC violation), rapid redirect flood from spoofed router, embedded original packet manipulation. Targets route table and neighbor cache manipulation detection. Triggers: route-hijack, cache-poisoning, evasion
- dest_unreachable_state_exhaustion: ICMPv6 Destination Unreachable (type 1) flood with unique embedded 5-tuples — each message references different src/dst IPv6 + ports + NH, forcing IDS to look up/create state entries for non-existent flows, mixed codes (no-route/admin-prohibited/beyond-scope/addr-unreachable/port-unreachable/src-addr-failed/reject-route), burst of 500+ unique entries. Targets connection tracking state table. Triggers: memory-exhaustion, state-corruption, dos
- hop_limit_manipulation: IPv6 Hop Limit field abuse — hop_limit=0 (should be discarded), hop_limit=1 (link-local only), hop_limit=255 (NDP requirement, valid for on-link), ICMPv6 messages with wrong hop limit for their type (Echo with HL=1, RA with HL≠255), Time Exceeded (type 3) generation trigger, mixed hop limits in fragment chain. Targets hop limit validation and time-exceeded generation. Triggers: evasion, state-corruption
- rpl_dao_dis_attack: RPL (Routing Protocol for Low-Power Networks, RFC 6550) ICMPv6 message abuse — RPL DIS (type 155 code 0) flood, DAO (code 2) with crafted RPL Instance ID and DODAG ID, oversized RPL options, RPL messages outside LLN context (sent to general IPv6 infrastructure), DIO (code 1) with conflicting rank/version, Security section with invalid algorithm. Targets RPL-aware IDS parsers processing ICMPv6 type 155. Triggers: state-corruption, oob-read, evasion, crash

SIP STRATEGIES (used when fuzzing SIP inspectors, e.g. Snort 3 sip inspector gid 140 — text-based, UDP 5060, RFC 3261 core + RFC 4566 SDP body):
- comment_recursion_bomb: CVE-2023-32887 (MediaTek) pattern — deeply nested parenthesized comments (500-2000 levels) in Via/From/Contact/display-name headers. RFC 3261 BNF allows recursive comments: comment = LPAREN *(ctext / quoted-pair / comment) RPAREN. Each '(' pushes ~0x30 bytes on the stack in recursive-descent parsers. Variants: single-header deep nesting, multi-header compound, incremental depth sweep to find exact crash threshold. Targets comment parser recursion. Triggers: stack-overflow, crash, dos
- content_length_overflow: OpenSIPS GHSA-c6j5-f4h4-2xrq — Content-Length integer overflow when number = number*10 + digit wraps negative/huge. Values: 2^31, 2^63, 2^64-1, negative (-1, -2147483648), non-numeric ("AAAA", "0x1000", "1e10"), leading zeros (200 zero digits), whitespace-padded, multiple conflicting Content-Length headers. Targets CL parser arithmetic and body boundary detection. Triggers: integer-overflow, oob-read, heap-overflow
- oversized_header_overflow: sngrep PR#480 (stack buffer overflow in Call-ID/Warning) — headers with 20-50KB values: giant Call-ID, oversized Via branch parameter, Contact URI with huge userinfo, Warning text, display-name, tag parameter, Reason header text, or multiple oversized headers simultaneously. Targets fixed-size buffer copies. Triggers: buffer-overflow, oob-write, heap-overflow
- invite_flood_dos: Asterisk PJSIP INVITE flood DoS — rapid INVITE with unique branch/CSeq/Call-ID creating distinct transactions (unique_dialog), or re-INVITE storm sharing same Call-ID (same_dialog), REGISTER flood, OPTIONS flood, mixed-method flood, CANCEL race (INVITE+immediate CANCEL), ACK storm for non-existent dialogs, out-of-dialog BYE flood. Targets connection/dialog/transaction state exhaustion. Triggers: memory-exhaustion, state-corruption, dos
- compact_form_desync: IDS evasion via SIP compact header forms — RFC 3261 defines compact alternatives: Via=v, From=f, To=t, Call-ID=i, Contact=m, Content-Type=c, Content-Length=l, Subject=s, Supported=k. Send same header in both long and compact form with conflicting values (Via:safe + v:evil). IDS keys on one form, UA reads the other. Variants: all-compact message, mixed same-header duplicates, CL/l conflict for body desync. Targets header normalization. Triggers: evasion, state-corruption
- hcolon_whitespace_evasion: RFC 3261 HCOLON = *(SP/HTAB) ":" SWS — whitespace before colon is legal but most IDS signatures match "Via:" without whitespace. Inject space/tab/multiple-whitespace before colon on all mandatory headers ("Via : ...", "From\t: ...", extreme 2000-char whitespace padding). Also test \x0b/\x0c (VT/FF) as whitespace variants. Targets signature-based detection. Triggers: evasion, state-corruption
- line_folding_obfuscation: RFC 3261 header continuation — lines beginning with SP/HTAB fold into previous header value as single SP. Split Via value, From URI, Call-ID, branch parameter across continuation lines to break contiguous-string signature matching. Variants: single fold, multi-fold (20+ continuation lines), fold mid-branch to hide z9hG4bK magic cookie, fold Content-Length to confuse body boundary, every header using folding. Targets header reassembly. Triggers: evasion, oob-read, state-corruption
- content_length_smuggling: Content-Length vs actual body desync for request smuggling — CL shorter than body (IDS stops reading, UA sees all), CL longer (IDS reads into next message), CL=0 with body present, safe SDP + hidden evil SDP appended past CL boundary, no CL on UDP (body goes to datagram end), two SIP messages concatenated in one datagram, NUL bytes in body truncating IDS string matching. Targets body boundary detection. Triggers: evasion, oob-read, state-corruption
- uri_escape_injection: Request-URI manipulation — %00 (null byte) in URI, %0d%0a (CRLF injection for header injection), oversized userinfo (5-20KB), malformed IPv6reference ([::1 missing bracket, oversized [FFF...]), embedded ?headers in URI (?Route=<evil>), transport= parameter confusion (tls/sctp/ws/unknown/\x00), hundreds of semicolon-delimited URI parameters, double percent-encoding (%2540). Targets URI parser. Triggers: oob-read, header-injection, buffer-overflow
- multipart_mime_wrap: Hide payload inside MIME structures — multipart/mixed with SDP + hidden text/plain part, message/sipfrag containing inner INVITE, deeply nested boundaries (multipart inside multipart), boundary with special characters ('/"/=), missing closing boundary (parser reads past), oversized boundary (500-2000 chars), Content-Type says application/sdp but body is multipart, fake S/MIME application/pkcs7-mime envelope. Targets body content-type dispatch. Triggers: evasion, oob-read, state-corruption
- malformed_startline: Request-Line / Status-Line malformation — bad SIP-Version (SIP/9.9, sip/2.0, SIP/2.0foo, HTTP/1.1, empty), method case manipulation (invite, InViTe), lines terminated with bare LF or bare CR instead of CRLF, leading CRLF flood (10-500), extra spaces between method/URI/version, missing URI, oversized method token (5-20KB), malformed status lines (code 999/0, missing reason, double space). Targets start-line parser. Triggers: state-corruption, oob-read, evasion
- mandatory_header_omission: Missing or duplicated mandatory headers — drop Via/From/To/Call-ID/CSeq/Max-Forwards individually, CSeq method mismatch with Request-Line method (INVITE line but CSeq says BYE), duplicate Call-ID with different values, Max-Forwards=0 (loop), all mandatory headers missing (only start-line + Content-Length). Targets header validation and state machine. Triggers: state-corruption, null-deref, evasion
- sdp_body_malformation: RFC 4566 SDP body torture — out-of-order lines violating required v/o/s/c/t/m order, missing required fields (v=, s=, o=), bad port in m= line (-1, 0, 99999, 4294967296, non-numeric), oversized o= origin username (5-20KB), malformed c= connection address (invalid IP, c=XX YY, TTL>255, oversized), NUL bytes in SDP values (illegal per byte-string BNF), m= line with 256 format types, huge a= attributes (5-20KB). Targets SDP parser. Triggers: oob-read, buffer-overflow, integer-overflow
- digest_auth_state_desync: Malformed Digest auth + SIP state machine attacks — broken Authorization (oversized nonce 10-30KB, algorithm confusion SHA-512/UNKNOWN/empty, HTTP Basic instead of Digest, comma-only field list), out-of-dialog BYE flood (random To-tag referencing non-existent dialogs), 1xx provisional response flood (50-200 rapid 100/180/183), retransmit storm (same INVITE 50-200 times with identical branch = same transaction), REGISTER hijack (forged Contact for victim AOR), ACK for non-INVITE (CSeq method mismatch). Targets auth parser and transaction state machine. Triggers: state-corruption, oob-read, auth-bypass, dos

MGCP STRATEGIES (used when fuzzing MGCP — text-based, UDP 2427/2727, RFC 3435 Media Gateway Control Protocol; Snort 3 has NO dedicated MGCP inspector, detection via text rules + appid):
- verb_line_overflow: Command line buffer overflow — oversized verb (5-50KB), oversized transaction-id (>9 digits, 10-50KB digits), oversized endpoint name (deep 100-500 level "/" hierarchy, domain >255 chars), missing components (no txid/endpoint/version), null bytes in fields, extra junk after MGCP version. Grounded in CVE-2007-4293 (Cisco IOS MGCP crash on abnormal messages) and CSCej20505 (hang on oversized packets). Targets command line parser fixed buffers. Triggers: buffer-overflow, crash, hang
- transaction_id_desync: Transaction state machine confusion — integer boundary values (0, 2^31, 2^32, 2^63), duplicate txid with different commands (violates 3-min reuse rule), response for unknown txid, non-numeric txid, leading zeros mass (100-10000 zeros), txid=0 (outside valid 1..999999999 range), negative txid, response-before-request race. Targets T-HIST ~30s cache and integer parsing. Triggers: state-corruption, integer-overflow, crash
- endpoint_wildcard_abuse: Wildcard and endpoint naming attacks — double wildcard *@*, $ wildcard in wrong commands (NTFY), deep wildcard hierarchy (50-200 levels mixing * and literals), range wildcard overflow ([0-4294967296], 500-item ranges, non-numeric), mixed wildcards (*/$/ range), null bytes in endpoint, missing/duplicate @ separator, IPv6 endpoint host forms (oversized brackets). Targets wildcard expansion engine and resource allocation. Triggers: dos-amplification, oob-read, resource-exhaustion
- parameter_injection: Single-letter parameter abuse — CRLF injection in param value (fake command injection via C: value), oversized hex IDs (CallId/ConnectionId/RequestIdentifier >32 hex, up to 50KB), unknown parameter codes (Y,W,V,J), duplicate params with conflicting values, empty values (no data after colon), hundreds of parameter lines (200-500), non-hex in hex fields, X+/X- vendor extension critical/non-critical forcing error 511/525. Targets parameter parser and value validation. Triggers: header-injection, buffer-overflow, state-corruption
- digit_map_bomb: DigitMap regex compiler exploitation — exponential backtracking (ReDoS) via pathological patterns like (x|xx|xxx|xxxx)*, deeply nested parentheses (500-2000 levels causing stack overflow), oversized map (10-50KB, well over 2048 byte recommendation), unbalanced brackets/parens, null bytes in map, all 20 extension letters (force error 537), empty alternatives (||), huge range lists ([0,1,...,5000]). Targets egrep-like DigitMap compiler/interpreter. Triggers: stack-overflow, ReDoS, crash
- local_connection_opts_overflow: LocalConnectionOptions (L: parameter) manipulation — codec list overflow (a: with 500-2000 codecs), bandwidth integer overflow (b: at 2^32/negative), packetization period overflow (p:0, p:2^32), encryption key abuse (k:clear: with 5-30KB key, k:uri: with huge URL), unknown LCO keys, duplicate keys with conflicting values, malformed ToS bits, all fields oversized simultaneously. Targets LCO parser, codec negotiation, integer arithmetic. Triggers: integer-overflow, buffer-overflow, crash
- sdp_mgcp_body_mismatch: SDP body framing abuse — MGCP has NO Content-Length header (unlike SIP), body framing relies on packet end or piggyback dot separator. Variants: no blank line before SDP, binary data instead of SDP, double SDP bodies (local+remote), SDP containing piggyback dot ".\r\n" (message boundary confusion), oversized SDP (>4000 bytes forcing IP fragmentation), SDP with null bytes, truncated SDP, connection address mismatch with endpoint. Targets SDP parser in MGCP body-framing context. Triggers: body-smuggling, oob-read, crash
- event_package_overflow: Event/signal package abuse — massive event list (500-2000 events in single R: line), deeply nested embedded RQNT E(R(...),S(...),D(...)) chains (20-100 levels of recursion), unknown package names, oversized action parameters (5-20KB), wildcard connection events (@*/@ $/@huge-id), observed events flood (200-1000 events in NTFY O: line), infinite-duration signals, nested E() inside E(). Targets event parser recursion and memory allocation. Triggers: stack-overflow, memory-exhaustion, crash
- piggyback_smuggling: Message boundary parser attacks — legitimate AUEP + malicious DLCX piggybacked via "." separator, command+response in same datagram (protocol confusion), mass piggyback (100-300 messages), dot separator variations (bare ".\n", ". \r\n", "..\r\n", ".\x00\r\n"), dot inside SDP body confusing message boundary, no dot between commands (boundary confusion), dot-only datagram, response-then-command reversed order. Unique to MGCP among VoIP protocols. Triggers: evasion, state-corruption, parser-confusion
- provisional_response_flood: Response processing abuse — flood of 50-200 provisional responses (100/101) for same txid, return codes outside valid range (0, -1, 999, 1000, 2^31), oversized commentary string (20-50KB), multiple final responses for same txid (200 then 500 then 200), ResponseAck (K:) with huge ranges (1-999999999 = ack ALL transactions), package-specific 8xx codes with/without /packageName. Targets response state machine and T-HIST cache. Triggers: memory-exhaustion, state-corruption, integer-overflow
- version_protocol_confusion: Protocol identification attacks — bad MGCP version (2.0, 0.1, 99.99, -1.0), SIP INVITE sent to MGCP port 2427 (cross-protocol confusion for appid), HTTP request on MGCP port, verb case manipulation (mgcp/Mgcp/mGcP — case-insensitive per RFC), NCS/TGCP/MEGACO variant identifiers, missing MGCP keyword entirely, extra fields after version string, mixed MGCP+SIP in piggybacked datagram. No dedicated Snort MGCP inspector makes this especially effective. Triggers: appid-confusion, evasion, parser-error
- notified_entity_hijack: N: parameter spoofing — redirect notifications to attacker address, oversized domain (5-20KB), port number overflow (99999, -1, 2^32), empty N: (disables DNS failover per RFC), multiple N: parameters (which wins?), IPv6 forms (missing bracket, oversized), null bytes in entity, CRLF injection in N: value to inject fake DLCX command. No built-in auth means any source can redefine the controlling Call Agent. Triggers: notification-hijack, buffer-overflow, command-injection
- quarantine_handling_abuse: Quarantine state machine manipulation — Q:loop causing infinite event notification cycle, unknown quarantine methods, quarantine buffer flood (100-500 rapid NTFY piggybacked), conflicting Q: values (process+discard+loop simultaneously), Q:loop + embedded RQNT (complex state interaction), rapid RQNT commands racing each other with different Q: values. Targets quarantine event buffer management. Triggers: infinite-loop, memory-exhaustion, state-corruption
- restart_cascade_dos: RSIP restart manipulation DoS — RSIP with RM:forced on wildcard endpoint * (all endpoints restart), RestartDelay integer overflow (RD: at 2^32/-1), rapid restart/cancel-graceful oscillation (state machine confusion), one RSIP per restart method (graceful/forced/restart/disconnected/cancel-graceful), RSIP with all reason codes including undefined ones, mass RSIP from many spoofed gateway addresses. Targets restart state machine and resource cleanup. Triggers: dos, state-corruption, resource-exhaustion

RTSP STRATEGIES (used when fuzzing RTSP — text-based, TCP 554, RFC 2326/7826 Real Time Streaming Protocol; Snort 3 has NO dedicated RTSP inspector, detection via AppID + generic text content rules):
- request_line_malformation: CVE-2013-6933/6934 (Live555) pattern — leading space/tab before method causes infinite loop writing to stack in parseRTSPRequestString, missing/oversized method token (20KB), bad RTSP version (RTSP/9.9, HTTP/1.1, empty, lowercase rtsp/1.0), malformed URI with path traversal (../../etc/passwd), oversized URI path (>4KB), extra spaces between request-line fields. Targets request-line parser fixed buffers. Triggers: stack-overflow, crash, infinite-loop, buffer-overflow
- content_length_smuggling: HTTP CL.0/CL.TE adapted for RTSP — Content-Length shorter than body (IDS stops reading, server sees all), CL longer than body (server reads into next request), CL=0 with body present, huge CL (2^31/2^63 trigger allocation), negative CL (-1, -2147483648), multiple conflicting CL headers, non-numeric CL (AAAA, 0x1000, 1e10), CL on bodyless methods (OPTIONS). Targets body boundary detection. Triggers: evasion, oob-read, integer-overflow, state-corruption
- transport_header_overflow: SETUP Transport header abuse — conflicting unicast+multicast, bad port ranges (0-0, 99999, -1, 65536), huge TTL (>255), interleaved channel overlap, unknown lower-transport (SCTP/QUIC/unknown), oversized ssrc (>8 hex, up to 5000), many conflicting parameters simultaneously, oversized transport header (>4KB with vendor extension params). Targets Transport header parser. Triggers: buffer-overflow, integer-overflow, state-corruption
- interleaved_binary_injection: RTSP-unique $ (0x24) framing — interleaved binary: $ + 1-byte channel + 2-byte length (big-endian) + data. Bad channel IDs (200-255), huge length field (0xFFFF with small data), $ injected mid-RTSP-header, interleaved data without prior SETUP, nested $ frames ($ inside $ data payload), zero-length frames, rapid frame flood (100-500), $ frame mixed with partial RTSP request. Targets interleaved binary framing parser. Triggers: oob-read, buffer-overflow, state-corruption, crash
- session_state_confusion: CVE-2019-15232 (duplicate session ID UAF), CVE-2019-7314 (UAF on stream termination) — PLAY without prior SETUP (Init state, should fail 455), wrong/invalid session ID, duplicate session IDs in consecutive SETUPs, rapid create/teardown cycles (20-100 SETUP+TEARDOWN), PAUSE in Init state, RECORD without SETUP, TEARDOWN with empty session, SETUP flood (50-200 rapid SETUPs for resource exhaustion). Targets session state machine. Triggers: use-after-free, state-corruption, memory-exhaustion, dos
- http_tunneling_abuse: CVE-2018-4013 (stack BOF in lookForHeader), CVE-2019-6256 (crash in handleHTTPCmd_TunnelingPOST) — oversized HTTP GET/POST headers for RTSP-over-HTTP tunneling (5-30KB), x-sessioncookie manipulation (oversized/empty/null-bytes/path-traversal/header-injection), Content-Base injection with malicious URI, HTTP POST with base64-encoded RTSP body, oversized POST body, many HTTP headers (50-200), mixed HTTP+RTSP in same connection, HTTP CONNECT tunnel attempt. Targets HTTP tunneling parser. Triggers: stack-overflow, crash, buffer-overflow, header-injection
- sdp_body_malformation: RFC 4566 SDP body torture — out-of-order SDP lines violating v/o/s/c/t/m order, missing mandatory SDP fields (no v=/s=/o=), oversized m= line (256 format types), CL vs SDP body size mismatch, null bytes in SDP values, oversized SDP (>10KB with huge a=fmtp attributes), bad port in m= line (-1/0/99999/4294967296), malformed c= connection address (XX YY, 999.999.999.999, oversized). Targets SDP parser. Triggers: oob-read, buffer-overflow, integer-overflow, crash
- oversized_header_overflow: SSD Advisory (URI suffix concatenation BOF) — oversized CSeq (non-numeric 5-30KB), oversized Session ID (500-5000 chars, RFC says ≥8), oversized Range header (10KB of 9s), many headers simultaneously (200-400 X-Fuzz headers), single header >64KB, oversized User-Agent (10-50KB), URI suffix overflow (5-20KB path), all headers oversized simultaneously. Targets fixed-size buffer copies. Triggers: buffer-overflow, oob-write, heap-overflow
- cseq_pipelining_abuse: CSeq integer wrap (2^31/2^32/2^63), duplicate CSeq in same request, non-numeric CSeq (abc/-1/1.5/empty), missing CSeq entirely, huge pipelined request burst (100-500 OPTIONS), pipelined PLAY with overlapping time ranges, CSeq=0 boundary value, CSeq with embedded method name (SIP-style "1 OPTIONS" vs RTSP integer-only). Targets CSeq parser and pipelining state machine. Triggers: integer-overflow, state-corruption, memory-exhaustion
- method_verb_fuzzing: IoTFuzzSentry pattern — RTSP methods are CASE-SENSITIVE (unlike SIP/MGCP): case mutations (describe, Describe, dESCRIBE), HTTP methods as RTSP (GET/POST/PUT/DELETE/HEAD), empty method, null bytes in method (DES\x00CRIBE), oversized method token (1-10KB), unknown extension methods (XPLAY/SUBSCRIBE/NOTIFY), methods with special characters (PLAY;/DESCRIBE\t/OPTIONS\r), mixed valid+invalid in pipelined requests. Targets method dispatch. Triggers: state-corruption, evasion, crash
- uri_encoding_evasion: Percent-encoding of path components (%6D%65%64%69%61 = media), double-encoding (%252e%252e = %2e%2e = ..), mixed case URI scheme (RtSp://rTsP://), null bytes in path (%00), path traversal with encoding (%2e%2e/), overlong UTF-8 encoding of / (C0 AF / E0 80 AF), fragment identifiers (undefined in RTSP), oversized percent-encoded URI (2000-5000 encoded chars). No Snort RTSP inspector means encoding evasion is especially effective. Triggers: evasion, path-traversal, oob-read
- crlf_header_injection: CRLF (\r\n) injection in header values to inject extra headers, CRLF to inject fake RTSP response (response splitting), Unicode line separators (U+2028/U+2029/U+0085), bare LF without CR, bare CR without LF, header folding with continuation lines (SP/HTAB), percent-encoded CRLF in URI (%0d%0a), multiple injection points across different headers. Targets header parser line termination. Triggers: header-injection, evasion, response-splitting
- tcp_segmentation_evasion: Ptacek & Newsham IDS evasion — full RTSP message designed for tiny TCP segments (1-byte), split at method/URI boundary, split mid-header-name, large payload requiring many segments (5-20KB padding), interleaved binary between RTSP headers, duplicate request (overlap simulation), null bytes between headers (segment boundary marker), very small request (under minimum segment check). NOTE: payload delivered as one block; actual TCP segmentation handled by transport layer. Triggers: evasion, framing-confusion
- range_time_format_abuse: NPT overflow (50-digit numbers, 99999999999999999, -1, inf), SMPTE overflow (99:99:99:99.99, negative, 20-digit hours), UTC clock overflow (99999999T999999Z), negative range (end before start, npt=100-50), mixed formats in same Range header (npt + smpte), unsupported format (bytes=, frames=, unknown=), Range on wrong method (OPTIONS), multiple Range headers in single request. Targets time range parser. Triggers: integer-overflow, state-corruption, crash

RADIUS STRATEGIES (used when fuzzing RADIUS — binary, UDP 1812 auth / 1813 acct / 3799 CoA; RFC 2865/2866/3579/5176/6929; Snort 3 has NO dedicated RADIUS inspector, detection via generic byte_test/content rules + AppID):
- authenticator_manipulation: CVE-2024-3596 BlastRADIUS surface — all-zero Authenticator, repeated-byte patterns, all-0xFF, correct MD5 hash then flipped bit, Request Authenticator copied from a previous response, random entropy. Targets MD5-based authentication model. Triggers: auth-bypass, state-corruption, evasion
- attribute_tlv_overflow: Attribute Type-Length-Value parser abuse — length=2 (zero-value, minimum), length=1 (underflow), length=0xFF (oversize), length exceeding remaining packet, 200 tiny attributes stressing loop, unknown type codes (192-255), duplicate attributes with conflicting values, attribute chain exactly filling 4096-byte packet. Targets attribute parser. Triggers: oob-read, buffer-overflow, integer-overflow
- user_password_encryption_abuse: User-Password (attr 2) MD5 XOR chain abuse (RFC 2865 §5.2) — max 128-byte password, zero-length password, 129-byte overflow, all-zero cipher blocks, repeating plaintext forcing identical cipher blocks, non-16-aligned length, shared-secret="" (empty key). Targets the encrypt/decrypt XOR chain. Triggers: oob-read, buffer-overflow, crypto-weakness
- vendor_specific_overflow: Vendor-Specific (type 26) attribute abuse (RFC 2865 §5.26) — vendor-id=0/0xFFFFFFFF/Cisco(9)/Microsoft(311), oversized vendor-data (253 bytes), vendor-type=0/0xFF, vendor-length mismatch, multiple VSAs in single attribute, 50-VSA flood, nested vendor TLVs. Targets vendor attribute dispatch. Triggers: oob-read, buffer-overflow, integer-overflow
- wimax_continuation_attack: WiMAX continuation attribute attack (CVE-2017-10984/10985) — Vendor-Id 24757 with continuation flag set, zero-length continuation (infinite loop), oversized continuation chain (50KB across 200+ attributes), continuation flag on non-WiMAX vendor, alternating continuation/non-continuation, truncated mid-continuation. Targets WiMAX continuation coalescing. Triggers: infinite-loop, heap-overflow, oob-write, crash
- eap_message_fragmentation: EAP-Message (attr 79) fragmentation abuse (RFC 3579) — 20KB EAP split across 80+ attributes, single oversized EAP-Message (253 bytes), EAP with no Message-Authenticator (RFC violation), conflicting EAP Code/Identifier across fragments, EAP-TLS with 10KB certificate blob, zero-length EAP-Message, out-of-order fragment reassembly. Targets EAP reassembly. Triggers: heap-overflow, oob-read, state-corruption
- message_authenticator_malform: Message-Authenticator (attr 80) malformation (RFC 3579 §3.2) — wrong length (not 18 bytes), all-zero HMAC, truncated (8 bytes), oversized (24 bytes), correct HMAC then bit-flipped, duplicate Message-Authenticator attributes, Message-Authenticator without EAP-Message. Targets HMAC-MD5 verification. Triggers: auth-bypass, oob-read, state-corruption
- extended_attribute_abuse: Extended attribute abuse (RFC 6929) — Extended-Type (241-244) with oversized data, Long-Extended-Type (245-246) with More flag chaining (50 fragments), nested TLV inside extended, Extended Vendor-Specific (EVS) with unknown vendor, truncated extended attribute, zero-length extended data, More flag without continuation. Targets extended attribute parser. Triggers: oob-read, buffer-overflow, state-corruption
- length_field_desync: Packet Length field desynchronization — Length < 20 (below minimum), Length > actual UDP payload (OOB read), Length = 20 (header only, no attributes), Length = 4096 (max), Length = 0xFFFF, Length contradicting attribute chain total, off-by-one length. Targets packet boundary detection. Triggers: oob-read, integer-overflow, buffer-overflow
- code_confusion: RADIUS Code / packet type confusion — undefined codes (14-39, 50-252), Code=0 (invalid), Code=255, server-only codes from client (Access-Accept/Reject/Challenge), Status-Server/Status-Client probes, rapid code cycling. Targets code dispatch and validation. Triggers: state-corruption, oob-read, null-deref
- proxy_state_injection: Proxy-State (attr 33) injection (BlastRADIUS attack vector) — 200 Proxy-State attributes consuming packet space, oversized Proxy-State (253 bytes), Proxy-State carrying chosen-prefix collision data, empty Proxy-State, Proxy-State with embedded NUL/control bytes, duplicate Proxy-State chain. MUST be forwarded unmodified by proxies. Triggers: auth-bypass, buffer-overflow, evasion
- coa_disconnect_abuse: CoA / Disconnect abuse (RFC 5176, port 3799) — CoA-Request with unknown attributes, Disconnect-Request with conflicting session identifiers, CoA with oversized Event-Timestamp, Disconnect-NAK spoofing, rapid CoA flood (100+), CoA with empty Authenticator, Disconnect with all error-cause codes (401-603). Targets dynamic authorization. Triggers: state-corruption, dos, auth-bypass
- accounting_desync: Accounting protocol desynchronization (port 1813) — Acct-Status-Type cycling (Start/Stop/Interim-Update/On/Off), Acct-Session-Id reuse across different NAS-IP, Acct-Delay-Time = 0xFFFFFFFF (huge backlog), duplicate Accounting-Request with different Acct-Status, missing mandatory attributes, Acct-Input/Output-Gigawords overflow, rapid accounting flood. Targets accounting state machine. Triggers: state-corruption, integer-overflow, dos
- nas_filter_rule_crash: NAS-Filter-Rule (attr 92) pre-auth crash — 253-byte oversized filter rule (FreeRADIUS 2026 vulnerability), 100+ NAS-Filter-Rule attributes, NAS-Filter-Rule with embedded NUL bytes, filter rule with format string characters (%n%s), empty filter rule, filter rule in Access-Request (pre-auth, no authentication needed). Targets filter rule parsing. Triggers: buffer-overflow, crash, format-string
- ip_frag_cache_exhaustion: IP fragment cache exhaustion (stream_ip.max_frags=8192) — incomplete fragment chains (first-fragment only, held 60s), overlapping fragments at same offsets (max_overlaps=0 unlimited), 8-byte tiny fragments (below MTU), teardrop-variant overlapping offsets, many unique IP ID values each incomplete. Targets Snort stream_ip defragmentation cache. Triggers: dos, evasion, resource-exhaustion
- udp_session_spray: UDP session spray for flow cache exhaustion (stream.max_flows=476288) — multi-port spray across 1812/1813/3799, unique Identifier spray with varying NAS-IP-Address, max-attribute packets maximizing per-flow memory cost, Accounting-Request flood with unique session IDs on port 1813. Targets Snort flow cache via cheap UDP session creation. Triggers: dos, evasion, resource-exhaustion

TACACS+ STRATEGIES (used when fuzzing TACACS+ — binary, TCP 49; RFC 8907; 12-byte cleartext header + MD5 XOR pad obfuscated body; Snort 3 has NO dedicated TACACS+ inspector, detection via generic byte_test/content rules):
- header_manipulation: TACACS+ 12-byte header abuse — invalid major/minor version nibbles (0x00, 0xFF, 0xD0), undefined packet types (0x00, 0x04-0xFF), seq_no=0 (invalid), seq_no=even (server-only), flags field manipulation (TAC_PLUS_UNENCRYPTED_FLAG toggling, undefined flag bits 0xFE), session_id=0/0xFFFFFFFF, body_length=0xFFFFFFFF vs actual body. Targets header parser and version/type dispatch. Triggers: oob-read, integer-overflow, state-corruption
- length_field_overflow: Body length field desynchronization — declared length > actual body (OOB read into next packet), declared length=0 with non-empty body, declared length=0xFFFFFFFF (4GB allocation attempt), off-by-one length, length < minimum body size for packet type, length contradicting TCP segment boundary. Targets body length validation and buffer allocation. Triggers: heap-overflow, oob-read, integer-overflow, dos
- obfuscation_confusion: MD5 XOR pad obfuscation abuse (RFC 8907 §4.6) — empty shared secret (cleartext fallback), all-zero pseudo_pad forcing, key/body alignment mismatch, obfuscated body with TAC_PLUS_UNENCRYPTED_FLAG set (contradiction), cleartext body without flag, truncated pseudo_pad chain, key rotation mid-session. Targets encrypt/decrypt XOR chain. Triggers: auth-bypass, crypto-weakness, state-corruption
- authentication_start_fuzz: Authentication START body abuse — invalid action codes (0x00, 0x05-0xFF), invalid authen_type (0x00, 0x07-0xFF beyond ASCII/PAP/CHAP/MSCHAP/MSCHAPv2/ARAP), invalid authen_service (0x00, 0x09-0xFF), user_len=255 with short user, port_len/rem_addr_len/data_len mismatches, oversized user field (255 bytes), empty user for authorization bypass, data field with embedded NUL. Targets authentication START parser. Triggers: oob-read, buffer-overflow, auth-bypass
- authentication_continue_fuzz: Authentication CONTINUE body abuse — user_msg_len=0xFFFF with short data, data_len=0xFFFF, TAC_PLUS_CONTINUE_FLAG_ABORT set with valid data, abort flag without flag, oversized user_msg (65535 bytes), empty continue (zero-length both fields), continue without prior START (state violation). Targets authentication CONTINUE parser and state machine. Triggers: oob-read, state-corruption, integer-overflow
- authorization_arg_overflow: Authorization REQUEST argument overflow — arg_cnt=255 with 255 arg_len bytes, individual arg_len=255, total args exceeding body length, zero-length args, arg containing embedded NUL/newline, duplicate service/cmd/protocol args with conflicting values, oversized authen_method/priv_lvl/authen_type/authen_service fields. Targets authorization argument parser and loop. Triggers: heap-overflow, oob-read, integer-overflow
- accounting_flag_confusion: Accounting REQUEST flag abuse — undefined flag combinations (all bits set 0x1E), TAC_PLUS_ACCT_FLAG_START|STOP simultaneously, WATCHDOG without START, WATCHDOG|STOP simultaneously, flags=0x00 (no flag), rapid flag cycling across packets in same session. Targets accounting state machine and flag validation. Triggers: state-corruption, logic-error, dos
- session_state_desync: Session state machine desynchronization — CONTINUE without START, REPLY without REQUEST, seq_no regression (5→3), seq_no gap (1→5 skipping 3), response on client seq_no (even), request on server seq_no (odd from server perspective), session_id reuse after completion, interleaved sessions on single TCP connection. Targets session tracking and state machine. Triggers: state-corruption, use-after-free, auth-bypass
- single_connection_abuse: TAC_PLUS_SINGLE_CONNECT_FLAG abuse — flag set in first packet then ignored, flag toggling mid-connection, multiplexed sessions exceeding implementation limits (100+ concurrent), rapid session creation/teardown, single-connect with connection reset mid-body. Targets connection multiplexing. Triggers: dos, state-corruption, resource-exhaustion
- bit_flip_attack: Targeted bit-flip mutations — single-bit flips in header version/type/flags fields, bit flips in body length field (especially MSB), bit flips in obfuscation pseudo_pad alignment bytes, bit flips in authentication status codes, systematic walking-ones pattern across first 24 bytes (header + body start). Targets parser edge cases and error handling. Triggers: crash, state-corruption, oob-read
- session_id_collision_replay: Session-ID collision and replay — reuse completed session_id with new seq_no=1, two simultaneous sessions with same session_id, session_id=0 (potentially special-cased), session_id from captured traffic replayed with modified body, session_id brute-force (sequential IDs), collision with server-originated session. Targets session lookup and disambiguation. Triggers: auth-bypass, state-corruption, use-after-free
- follow_status_abuse: FOLLOW status response exploitation — crafted REPLY with status=TAC_PLUS_AUTHEN_STATUS_FOLLOW (0x04) containing malicious server_msg with redirect data, FOLLOW with oversized data field, FOLLOW chain loop (redirect to self), FOLLOW with invalid server address format, multiple FOLLOW in sequence (chain depth). Targets FOLLOW redirect handling. Triggers: ssrf, infinite-loop, oob-read
- oversized_field_bomb: Oversized field and packet bombs — single packet at TCP segment max (~64KB body), 100+ small packets in rapid succession, body filled with repeated 0xFF pattern (worst-case obfuscation), authentication START with all variable fields at max (user=255, port=255, rem_addr=255, data=255), total packet exceeding 65535 bytes via multiple TCP segments. Targets memory allocation and processing limits. Triggers: dos, heap-overflow, resource-exhaustion
- tcp_segmentation_evasion: TCP segmentation for IDS evasion — split 12-byte header across two TCP segments (6+6), split at header/body boundary (12 + body), single-byte TCP segments for entire packet, out-of-order TCP segments, overlapping TCP segments with conflicting header bytes, PSH flag manipulation, TCP urgent pointer overlapping TACACS+ header. Targets TCP reassembly and TACACS+ parser interaction. Triggers: evasion, oob-read, state-corruption
- flow_cache_exhaustion: Snort flow cache exhaustion (stream.max_flows=476288) — 200 TACACS+ packets with unique session-ids (established flood), 500 minimal 13-byte packets (minimal data flood), 100 session-ids cycled through seq 1/3/5 (interleaved sessions). Targets Snort stream flow cache pruning. Triggers: dos, evasion, resource-exhaustion
- tcp_overlap_desync: TCP overlapping segment desync (Ptacek-Newsham 1998) — decoy in first segment / real in overlapping second (BSD first-wins vs Linux last-wins), partial 50% overlap, retransmit with different payload (insertion attack), triple overlap at same offset. Exploits stream_tcp.overlap_limit=0 (unlimited) and policy=bsd. Triggers: evasion, state-corruption, detection-bypass
- segment_queue_exhaustion: TCP segment queue exhaustion (stream_tcp queue_limit) — 3100 single-byte segments exceeding max_segments=3072, 4MB fill with TACACS+ noise exceeding max_bytes, alternating 1-byte and normal-sized segments. Exploits small_segments detection being DISABLED by default. Triggers: dos, evasion, resource-exhaustion
- reassembly_policy_confusion: Reassembly policy mismatch exploitation (BSD vs Linux/Windows) — payload in overlapping second segment for Linux last-wins targets, Windows-specific trim boundary exploit, TTL-based evasion (short TTL decoy reaches Snort but not target), multi-region mixed-policy interleave. Exploits stream_tcp.policy=bsd default mismatch with target OS. Triggers: evasion, detection-bypass
- embryonic_connection_flood: Embryonic (half-open) connection flood — SYN+data with TACACS+ payload (triggers 129:2), RST race after minimal data, FIN before established with partial headers, SYN with extreme TCP options (window scale=14). Exploits embryonic_timeout=30s to hold state. Triggers: dos, resource-exhaustion, state-corruption

LDAP STRATEGIES (used when fuzzing LDAP — binary ASN.1 BER, TCP 389; RFC 4511; Snort 3 has NO dedicated LDAP inspector, detection via generic content rules on port 389/636):
- ber_length_overflow: BER length-field overflow (CVE-2015-6908 pattern) — 4GB outer SEQUENCE length (0x84 0xFF 0xFF 0xFF 0xFF), 5-octet illegal length form (0x85), declared length >> actual body, messageID with huge length, DN octet string with 2GB length, bind body length lie, address-wrapping length offset, exact CVE-2015-6908 PoC bytes. Targets ber_get_next and length-parsing arithmetic. Triggers: heap-overflow, oob-read, assert-crash, integer-overflow
- ber_nonminimal_encoding: Non-minimal BER length encoding for Snort content-rule bypass — same logical BindRequest encoded with 0x81 (1-byte long form), 0x84 (4-byte long form), leading-zero long form (0x83 0x00 0x00 N), all elements non-minimal, messageID non-minimal, mixed minimal/non-minimal. Snort content patterns match specific byte offsets; non-minimal encoding shifts all subsequent bytes. Triggers: evasion, parser-desync
- ber_indefinite_constructed: BER constructs forbidden by RFC 4511 S5.1 — indefinite-form length (0x80 + 0x00 0x00 EOC) on outer SEQUENCE, indefinite on BindRequest body, constructed OCTET STRING (0x24) for DN, non-standard boolean values (0x01/0x7F/0x80 instead of 0xFF), multi-byte tag encoding for single-byte tags, injected EOC markers. Targets parsers that accept full BER but violate LDAP restrictions. Triggers: state-corruption, evasion, parser-confusion
- truncated_tlv: Declared BER length exceeds available bytes — outer message truncated at 50%, DN claims 200 bytes but only 3 present, BindRequest body claims 127 bytes with none following, SearchRequest filter claims 64 bytes, cut in middle of multi-byte length field, single SEQUENCE tag byte alone, BindRequest with version but no DN/password. Targets ber_get_next style readers. Triggers: oob-read, assert-crash, null-deref
- bind_auth_confusion: Malformed BindRequests — version=0, negative version (0xFF), version=0x7FFFFFFF, empty DN with non-empty password (RFC 4513 violation), SASL with unknown/empty/NUL-embedded mechanism, SASL credentials >64KB, reserved context-specific auth tags ([1]/[2]/[4]), non-minimal version INTEGER encoding. Targets bind authentication dispatch and version validation. Triggers: auth-bypass, oob-read, buffer-overflow, state-corruption
- search_filter_bomb: CVE-2020-12243 pattern — deeply nested AND filters (100-500 levels), alternating OR/NOT nesting (80-300 levels), SubstringFilter with 20-100 wildcard components, AND/OR with zero children (empty SET), undefined filter context-specific tags (0xAA-0xBF), SubstringFilter with 10KB initial+final values, attribute description >10KB. Targets filter parser recursion and evaluation. Triggers: stack-overflow, dos, crash, infinite-loop
- search_request_malform: Invalid SearchRequest fields — scope values 3/127/255 (only 0-2 valid), derefAliases 4/127/255 (only 0-3 valid), sizeLimit/timeLimit as negative integers (0xFFFFFFFF), sizeLimit/timeLimit as INT_MAX, oversized baseDN (8KB+ with random RDN components), 1500 attributes in attribute list, embedded NUL bytes in baseDN. Targets search parameter validation. Triggers: integer-overflow, dos, oob-read
- message_id_confusion: Boundary and illegal messageID values — ID=0 (reserved for unsolicited notifications), negative ID (-1 as 0xFFFFFFFF), ID=INT_MAX (0x7FFFFFFF), non-minimal encoding (5 leading zero bytes), two pipelined requests with same ID, 9-byte integer >2^31, zero-length INTEGER for messageID. Targets IDS correlation and server session tracking. Triggers: state-corruption, evasion, oob-read
- modify_add_dn_overflow: Oversized DNs and attribute values — 60KB DN in ModifyRequest/AddRequest/DeleteRequest, 500-component deep RDN nesting, NUL bytes in DN, invalid UTF-8 sequences in DN (0xFF 0xFE 0x80 0xC0 0xAF), 50KB attribute values in Modify replace, circular ModDN (newSuperior = self). Targets DN parsing, UTF-8 validation, and memory allocation. Triggers: buffer-overflow, dos, heap-overflow
- extended_starttls_abuse: ExtendedRequest manipulation — StartTLS followed immediately by plaintext BindRequest, double StartTLS, unknown OIDs with 50KB random values, malformed OID strings (empty, double-dot, negative, NUL-embedded, non-numeric), ExtendedRequest with missing requestName, StartTLS with 60KB unexpected value, Who Am I? with 40KB payload. Targets extended operation dispatch and TLS state machine. Triggers: state-corruption, oob-read, dos
- control_injection: LDAP control manipulation — unknown OIDs with critical=TRUE and random values, paged results with pageSize=0 (known crash vector), paged results with negative pageSize, 200 controls on single message, garbage BER in paged results control value, triplicate paged results controls, controls attached to UnbindRequest. Targets control processing and server-side pagination. Triggers: crash, dos, state-corruption, infinite-loop
- nested_sequence_bomb: Deep BER SEQUENCE nesting for stack exhaustion — 1500 levels SEQUENCE nesting in BindRequest DN field, 800 levels packed inside DN octet string value, alternating SEQUENCE/SET 600 levels, 1000 levels inside control value. Targets recursive BER decoders in both IDS and LDAP servers. Triggers: stack-overflow, dos, crash
- tcp_segment_evasion: TCP segmentation for IDS evasion — split outer SEQUENCE tag+length across TCP segments, split DN value across segments, split filter across segments, single-byte TCP segments for entire message, split inside non-minimal multi-byte length field, PSH flag at TLV boundaries, 10 pipelined LDAP messages to overwhelm reassembly. Snort has no LDAP-aware reassembly. Triggers: evasion, parser-desync
- version_pdu_tag_confusion: Wrong/swapped APPLICATION-class tags — BindRequest tag (0x60) wrapping SearchRequest body, private-class tags (0xE0-0xFF) where application-class expected, LDAPv2 version with v3-only operations, multi-byte APPLICATION tag encoding, primitive/constructed bit flip (0x40 instead of 0x60), undefined APPLICATION tag numbers (30), SearchRequest tag on DeleteRequest body. Targets protocol operation dispatch and tag validation. Triggers: state-corruption, crash, evasion

CIFS/SMB1 STRATEGIES (used when fuzzing CIFS — binary SMB1/NT LM 0.12 over TCP 445/139; [MS-CIFS]; Snort 3 dce_smb inspector GID 133 with deep protocol-aware parsing):
- dialect_negotiation: Dialect negotiation attacks — oversized dialect list (100+ entries), empty dialect strings, invalid/binary dialect names, duplicate NT LM 0.12 entries, multiple NEGOTIATE commands on single connection, zero dialects. Targets SMB_COM_NEGOTIATE parser and dialect selection. Triggers: crash, state-corruption, dos
- header_manipulation: SMB1 header field manipulation — corrupted \xffSMB magic bytes, invalid command codes (0xFE/0xFF), FLAGS/FLAGS2 bit confusion (all bits set, contradictory flags), PID/TID/UID/MID boundary values (0x0000, 0xFFFF), PidHigh overflow, signature field corruption. Targets Snort dce_smb header validation (GID 133:3, 133:4). Triggers: evasion, crash, state-corruption
- wordcount_bytecount_desync: WordCount/ByteCount mismatch — WordCount claims N words but provides different amount, ByteCount larger/smaller than actual data, zero WordCount with non-empty parameters, WordCount=127 (max) with minimal data. Targets Snort rules 133:5 (bad word count) and 133:6 (bad byte count). Triggers: oob-read, heap-overflow, crash
- andx_chain_abuse: AndX command chaining abuse — chain 10+ commands exceeding Snort smb_max_chain=3, circular AndXOffset creating infinite loops, invalid AndXOffset pointing outside message, chained SESSION_SETUP+LOGOFF (login+immediate logout), mixed valid/invalid AndX commands. Targets Snort rule 133:20 (excessive chaining) and 133:21 (multiple chained login). Triggers: dos, infinite-loop, state-corruption
- transaction_fragmentation: SMB transaction fragmentation — oversized TotalDataCount in TRANSACTION/TRANSACTION2/NT_TRANSACT, mismatched primary/secondary fragment sizes, NTtrans 32-bit field overflow, overlapping transaction fragments, zero-length transaction with non-zero TotalDataCount. Targets DCE/RPC defragmentation in Snort dce_smb inspector. Triggers: heap-overflow, integer-overflow, dos
- named_pipe_mailslot: Named Pipe and Mailslot injection — pipe name buffer overflow (\\PIPE\\ + 64KB name), \\PIPE\\LANMAN RAP abuse, mailslot name overflow (\\MAILSLOT\\ + oversized), TRANSACTION with both pipe and mailslot setup flags, NUL-embedded pipe names. Targets named pipe handling in SMB transport layer. Triggers: buffer-overflow, injection, state-corruption
- authentication_attack: SMB1 authentication manipulation — malformed LM/NTLM challenge responses (truncated, oversized, all-zero), SPNEGO token corruption (invalid ASN.1/DER), empty security blob with non-zero length, oversized NTLMv2 blob (64KB+ target info), anonymous login followed by privileged commands. Targets SESSION_SETUP_ANDX authentication dispatch. Triggers: auth-bypass, heap-overflow, crash
- oplock_state_confusion: OpLock state manipulation — unsolicited OpLock break responses, invalid OpLock type values (0xFF), OpLock break on non-existent FID, batch OpLock request on already-open file, rapid OpLock acquire/release cycling. Targets OpLock state machine in SMB server. Triggers: state-corruption, race-condition, dos
- dfs_referral_attack: DFS referral path manipulation — deeply recursive DFS paths (\\\\server\\share\\a\\b\\...\\z 100+ components), self-referential DFS referral, malformed Unicode in DFS path, TRANSACTION2 GET_DFS_REFERRAL with oversized path, DFS flag set without valid referral data. Targets DFS path resolution and referral processing. Triggers: infinite-loop, stack-overflow, dos
- signing_bypass: SMB message signing bypass — corrupted 8-byte signature field, valid signature with altered message body, signature field all-zeros when signing required (FLAGS2 bit 2), signature with wrong session key, alternating signed/unsigned messages. Targets MAC verification in SMB security layer. Triggers: evasion, auth-bypass, state-corruption
- nbt_session_layer: NetBIOS session layer attacks — invalid session type bytes (0x84 Retarget, 0x85 Keepalive, 0xFF undefined), oversized NetBIOS length (0x01FFFF, exceeding 17-bit max), zero-length session message, session request (0x81) on port 445 (direct SMB), NetBIOS length mismatch with actual payload. Targets Snort rule 133:2 (bad NetBIOS session type) and NBT framing. Triggers: crash, evasion, dos
- file_attribute_ea_overflow: Extended Attributes and file attribute overflow — oversized EA list (64KB+ total), individual EA value > 65535 bytes, long filename (255+ Unicode chars), EA with NUL-embedded name, TRANS2_SET_FILE_INFORMATION with contradictory attributes. Targets EA parsing and file attribute handling. Triggers: heap-overflow, buffer-overflow, dos
- deprecated_command_abuse: Deprecated/obsolete SMB command usage — SMB_COM_COPY (0x29), SMB_COM_MOVE (0x2A), SMB_COM_GET_PRINT_QUEUE (0xC3), PROCESS_EXIT (0x11), and other commands removed in modern implementations. Targets Snort rule 133:53 (deprecated command) and legacy code paths. Triggers: crash, state-corruption, evasion
- tcp_segmentation_evasion: TCP segmentation for dce_smb inspector evasion — split 4-byte NetBIOS header across TCP segments, split \xffSMB magic across segments, single-byte TCP segments for entire SMB message, split at WordCount/ByteCount boundary, interleaved PSH flags at non-message boundaries. Targets TCP reassembly interaction with Snort dce_smb desegmentation. Triggers: evasion, parser-desync

SUN RPC / ONC RPC STRATEGIES (used when fuzzing SUN RPC — binary, UDP/TCP 111 portmapper + 2049 NFS; RFC 5531/4506/1833; Snort 3 GID 106 sunrpc inspector + gid 1 protocol-rpc rules):
- xdr_string_overflow: XDR string length field abuse — rpcbomb-style CVE-2017-8779 (huge length, tiny data), string length > remaining packet, length 0xFFFFFFFF integer overflow, non-NUL-terminated strings, embedded NUL bytes. Targets XDR decode_string in libtirpc/glibc. Triggers: heap-overflow, dos, oob-read
- xdr_array_overflow: XDR array element count overflow — CVE-2003-0028 element_count × element_size integer wrap (calloc(n,s) → small alloc), array count 0xFFFFFFFF, array count mismatch with data length, nested array-of-array recursion. Targets XDR decode_array. Triggers: integer-overflow, heap-overflow, oob-write
- record_marking_abuse: TCP Record Marking framing attacks — Snort 106:1-5 surface. Fragment bit confusion (last=0 never terminated), 4-byte RM header with length 0/0x7FFFFFFF, RM length mismatch with actual data, multiple small RM fragments reassembling to oversized message, RM fragment splitting RPC header mid-field. Targets Snort sunrpc inspector RM reassembly. Triggers: dos, evasion, heap-overflow
- rpc_header_manipulation: RPC message header field corruption — invalid msg_type (not 0/1), rpcvers != 2, XID=0/0xFFFFFFFF, call with reply msg_type, swapped prog/vers/proc fields, oversized opaque_auth bodies. Targets RPC message dispatch. Triggers: crash, state-corruption, evasion
- auth_sys_overflow: AUTH_SYS credential overflow — machinename > 255 bytes (Snort 1:9624), uid/gid 0xFFFFFFFF, aux_gid array > 16 elements (RFC limit), oversized stamp field, total AUTH_SYS body > 400 bytes. Targets AUTH_SYS decode in rpc.mountd/nfsd. Triggers: buffer-overflow, heap-overflow, crash
- auth_flavor_confusion: Authentication flavor mismatch — credential says AUTH_NONE but includes body, verifier flavor != credential flavor, unknown flavor numbers (7-99, 300000+), AUTH_SHORT with oversized opaque handle, RPCSEC_GSS with invalid gss_proc/service values. Targets auth dispatch. Triggers: state-corruption, crash, auth-bypass
- portmap_abuse: Portmapper/RPCBIND abuse — GETPORT for program 100000 (recursive), SET/UNSET to redirect services (Snort 1:1280/1950), CALLIT amplification (Snort 1:2015), DUMP flood for service enumeration, registration of privileged programs from unprivileged port. Targets rpcbind service. Triggers: dos, amplification, service-hijack
- nfs_compound_overflow: NFS COMPOUND operation overflow — CVE-2022-30136 surface. Oversized argarray (1000+ operations), deeply nested COMPOUND, tag string > 2^20 bytes, single huge operation (WRITE with 10MB data), mixed valid/invalid opcodes forcing partial rollback. Targets NFS v4 COMPOUND dispatch. Triggers: heap-overflow, dos, state-corruption
- program_version_mismatch: Program/version mismatch probing — valid program with version 0 or 0xFFFFFFFF, non-existent program numbers (0, 0x40000000-0x5FFFFFFF), procedure number > known max, version range abuse (low > high in PROG_MISMATCH reply). Targets program lookup and version negotiation. Triggers: crash, info-leak, state-corruption
- xdr_padding_violation: XDR alignment/padding violations — string/opaque data not padded to 4-byte boundary, extra padding bytes, non-zero pad bytes, data length not multiple of 4 without padding, truncated mid-XDR-word. Targets XDR decode assumptions about 4-byte alignment. Triggers: oob-read, crash, evasion
- tcp_segmentation_evasion: TCP segmentation for sunrpc inspector evasion — split 4-byte RM header across TCP segments, split RPC XID across segments, single-byte TCP segments for entire RPC message, split inside XDR string length field, interleaved PSH flags at non-message boundaries. Targets TCP reassembly interaction with Snort sunrpc RM desegmentation. Triggers: evasion, parser-desync
- reply_fuzzing: RPC reply message fuzzing — MSG_DENIED with invalid reject_stat, PROG_MISMATCH with inverted version range, SYSTEM_ERR with oversized data, accepted reply with garbage accept_stat, reply with XID matching no outstanding call. Targets reply parsing in client stacks. Triggers: state-corruption, crash, info-leak
- null_procedure_abuse: RPC NULL procedure (proc 0) abuse — NULL call with non-empty payload, rapid NULL flood for resource exhaustion, NULL with AUTH_SYS creds requesting privileged portmapper operations, NULL to every registered program in sequence. Targets service availability and auth bypass. Triggers: dos, auth-bypass, info-leak
- rpc_service_daemon_fuzz: RPC service daemon targeting — statd STAT/STAT_CALLBACK with format strings in hostname (CVE-2000-0666), cmsd oversized calendar name, sadmind AUTH_SYS bypass (CVE-2003-0722), ypupdated command injection, tooltalk buffer overflow. Targets specific RPC program implementations. Triggers: rce, buffer-overflow, command-injection

TELNET STRATEGIES (used when fuzzing Telnet — text-based NVT + binary IAC escape, TCP 23; RFC 854/855/856/1091/1572/2941/2946/2217; Snort 3 telnet inspector GID 126):
- iac_sequence_injection: IAC command sequence injection — CVE-2001-0554 AYT flood heap corruption, orphaned IAC at stream end, IAC with invalid command bytes (0x00-0xEC), rapid IAC NOP flood, IAC followed by 0x00 (reserved), sequential IAC GA half-duplex confusion, mixed valid command flood, IAC EOR flood. Targets telnetd command parser and Snort telnet inspector. Triggers: heap-overflow, dos, crash
- option_negotiation_flood: Option negotiation exhaustion — WILL for all 256 options, contradictory WILL+WONT for same option, DO for unknown options (128-254), rapid WILL/WONT cycling for Echo, EXOPL (option 255) abuse causing IAC parsing ambiguity, all four commands for every option, DO/DONT SGA flood. Targets option state machine in telnetd. Triggers: dos, state-corruption, memory-exhaustion
- subnegotiation_overflow: Sub-negotiation payload overflow — CVE-2011-4862 FreeBSD encrypt_keyid heap overflow pattern, SB without matching SE (unterminated), nested SB inside SB, zero-length SB, 64KB SB data, SB for un-negotiated option, unescaped IAC in SB data, multiple overlapping SBs. Targets SB data parsing. Triggers: heap-overflow, crash, buffer-overflow
- naws_window_manipulation: NAWS (RFC 1073) window size abuse — zero dimensions (0x0), maximum dimensions (0xFFFF x 0xFFFF), wrong data length (3 or 100 bytes instead of 4), NAWS flood with rapid resizing, NAWS without prior negotiation, NAWS with IAC bytes in dimension values requiring escaping. Targets terminal size handling. Triggers: integer-overflow, dos, state-corruption
- terminal_type_overflow: Terminal-Type (RFC 1091) SB overflow — oversized type string (5-30KB), empty type, null bytes in type string, raw unescaped IAC in type, format string characters (%n%s), flood of TERMTYPE IS responses, shell metacharacters, non-printable byte sequences. Targets TERM environment variable handling. Triggers: buffer-overflow, format-string, command-injection
- environment_variable_injection: NEW-ENVIRON (RFC 1572) variable injection — CVE-2023-33230 Sitecom router command injection pattern, oversized VAR value, shell injection in VAR, LD_PRELOAD/PATH injection, hundreds of VARs, embedded NUL in values, conflicting VAR/USERVAR, empty VAR name, ESC byte abuse. Targets environment processing in login shell. Triggers: command-injection, buffer-overflow, auth-bypass
- authentication_option_abuse: Telnet Authentication Option (RFC 2941) abuse — oversized NAME field, unknown auth types (128-255), empty auth IS, IS without prior SEND, many auth-type pairs, auth with modifier bits set incorrectly, rapid auth cycling. Targets authentication state machine. Triggers: crash, state-corruption, auth-bypass
- encrypt_option_exploit: Telnet Encryption Option (RFC 2946) exploitation — CVE-2011-4862 oversized encrypt_keyid exact pattern, unknown encryption types, empty ENCRYPT SB, ENCRYPT_IS with huge data, ENCRYPT_SUPPORT with all 256 types, ENCRYPT_START without negotiation, format strings in ENCRYPT_REPLY, oversized DEC_KEYID. Targets encrypt key handling buffer. Triggers: heap-overflow, crash, rce
- command_injection_evasion: Telnet command injection with IDS evasion — CVE-2022-29153 Consul smuggling, IAC NOP between every command byte, IAC IAC literal 0xFF insertion, backspace (EC) evasion, Go Ahead insertion between chars, null byte insertion, command split across SB/SE, EL then real command, mixed NOP+AYT interleaving. Targets IDS content matching. Triggers: evasion, command-injection
- line_ending_confusion: NVT line-ending rule violations — bare CR without LF/NUL (RFC 854 violation), bare LF, CR followed by arbitrary byte, mixed line endings, oversized line (64KB+) without CRLF, Unicode line separators (U+2028/U+2029), CR CR LF sequences. Targets NVT CR handling in telnetd and IDS. Triggers: evasion, parser-desync, crash
- data_mark_urgent_abuse: Data Mark (DM) and TCP Urgent pointer abuse — DM flood without TCP urgent, DM interleaved with data, IP+DM Synch rapid sequence, multiple DMs in sequence, DM inside sub-negotiation (illegal), AO+DM combination, BRK+DM rapid cycling. Targets Synch signal processing. Triggers: state-corruption, dos, evasion
- iac_escape_desync: IAC escape sequence parser desynchronization — single IAC at buffer boundaries (255, 511, 1023, 4095), triple IAC (odd count), IAC IAC before WILL/WONT commands, IAC splitting option negotiation, rapid data/command mode toggling, 5-byte IAC sequences, IAC at power-of-2 boundaries, alternating IAC-data patterns. Targets IAC parser state machine. Triggers: evasion, parser-desync, crash
- comport_option_overflow: COM Port Control Option (RFC 2217) overflow — oversized baud rate (0xFFFFFFFF), all command codes in sequence, unknown command codes (128-255), SET_CONTROL with invalid flow control, SET_LINESTATE with all bits, rapid baud rate cycling, oversized signature. Targets serial-port emulation layer. Triggers: buffer-overflow, crash, dos
- tcp_segmentation_evasion: TCP segmentation for telnet inspector evasion — login sequence with IAC options designed for tiny segments, 1-byte TCP segments with NOP interleaving, option negotiation + command with split-friendly padding, many small SB sequences, duplicate login with overlap simulation, minimal request under segment threshold. Targets TCP reassembly interaction with Snort telnet inspector. Triggers: evasion, parser-desync

TFTP STRATEGIES (used when fuzzing TFTP — binary UDP port 69; RFC 1350/2347/2348/2349/7440/2090; Snort SID 518/519/520/1289/1441-1444/1941/2337/2339/18767/32637):
- rrq_filename_overflow: RRQ Read Request filename overflow — CVE-2002-0813 Cisco IOS >100 bytes, CVE-2006-6184 AT-TFTP stack overflow, CVE-2021-44428 Serva stack overflow, CVE-2021-44429 Pinkie buffer overflow. Snort SID 1941 checks isdataat:100. Variants: giant ASCII fill, non-ASCII charset confusion, NUL at byte 99 (SID 1941 boundary evasion), format string specifiers (%n%s%x%p), no NUL terminator, embedded path separators, all-0xFF bytes. Targets filename buffer in TFTP server. Triggers: buffer-overflow, stack-overflow, rce
- wrq_filename_overflow: WRQ Write Request filename overflow — CVE-2003-0380 AT-TFTP PUT overflow, CVE-2008-1611 TFTP Server filename overflow. Snort SID 2337 checks opcode 0x0002 + isdataat:100. Same variant matrix as RRQ but with opcode 2. Targets filename buffer on write path. Triggers: buffer-overflow, stack-overflow, rce
- directory_traversal_injection: Path traversal in RRQ/WRQ filenames — CVE-1999-0183 generic "../" traversal, CVE-2009-0271 SolarWinds "..../" collapse bypass. Snort SID 519 checks ".." at offset 2, SID 520 checks absolute path. Evasion: URL-encoded (%2e%2e/%2f), overlong UTF-8 (%c0%ae), SolarWinds collapse (....//) , NUL byte truncation, mixed encoding, double mangling (..././), backslash substitution. Targets file path resolution. Triggers: info-leak, arbitrary-file-read, arbitrary-file-write
- error_packet_overflow: ERROR packet message overflow — CVE-2008-2161 Open TFTP heap overflow, CVE-2018-10387 heap overflow, CVE-2019-12567 stack overflow in logMess. NO Snort TFTP rule covers ERROR message length. Variants: giant message (1-32KB), missing NUL terminator, format strings, non-ASCII bytes, invalid error codes (9-65535), zero-length message, embedded NULs. Targets error message logging/display buffer. Triggers: heap-overflow, stack-overflow, format-string
- opcode_abuse: Invalid/unexpected TFTP opcodes — CVE-2007-3948 NULL opcode crash. Snort SID 2339 catches 0x0000 only; opcodes 7-255 undetected. Variants: NULL opcode (0x0000), undefined opcodes 7-255, maximum 0xFFFF, single-byte truncated, valid opcode with random body, unsolicited OACK, three-byte opcode. Targets opcode dispatch. Triggers: crash, dos, undefined-behavior
- option_negotiation_abuse: Malformed RFC 2347/2348/2349/7440 options in RRQ/WRQ — CVE-2018-8476 Windows WDS TFTP UAF via blksize+windowsize (PXE Dust). NO Snort rule inspects TFTP option fields. Variants: blksize=0 (divide-by-zero), blksize>65464, tsize integer overflow, windowsize=0 or 65535, many options exceeding 512-byte request, missing NUL between key/value, PXE Dust exact trigger (blksize=1456+windowsize=64), duplicate options, unknown option names with long values. Targets option parsing. Triggers: uaf, integer-overflow, dos, memory-exhaustion
- mode_string_abuse: Mutated transfer mode field — Metasploit 3Com TFTP Fuzzer crash via long mode. Snort rules check opcode+filename but NOT mode content. Variants: oversized mode (500-5000 bytes), unknown modes (binary/foobar/MAIL), empty mode, missing NUL, embedded NUL in mode, non-ASCII bytes, case variations. Targets mode string parsing. Triggers: buffer-overflow, crash, dos
- block_number_manipulation: Block number abuse in DATA/ACK — block#=0 in DATA (invalid), block#=0xFFFF rollover boundary, ACK for future unsent block, duplicate ACK concatenation (Sorcerer's Apprentice Syndrome trigger), oversized DATA > blocksize, ACK with trailing data. Targets transfer state machine. Triggers: state-corruption, dos, infinite-loop
- malformed_packet_structure: Structurally invalid TFTP packets — CVE-2008-4441 Tftpd32 malformed packet crash. Variants: empty payload, single byte, opcode only, RRQ with no filename, RRQ with filename but no mode, DATA with no block number, near-64KB payload, all-NUL packets. Targets parser robustness. Triggers: crash, oob-read, dos
- ip_fragmentation_evasion: Oversized TFTP payloads forcing IP fragmentation for IDS evasion — padding pushes traversal/overflow content into second IP fragment beyond Snort reassembly window. Variants: 1400-byte padding before traversal filename, NUL padding to fragment boundary, oversized DATA blocks (2-16KB), many options filling multiple fragments, NOP sled patterns, near-max UDP payload. Targets IP reassembly interaction with TFTP inspection. Triggers: evasion, parser-desync
- multicast_option_abuse: Malformed RFC 2090 multicast options — invalid multicast IP (999.999.999.999), port > 65535, invalid master client flag, empty value, overflow in address field, missing comma delimiters, non-numeric port. Most servers don't implement RFC 2090; malformed values may crash parsers. Triggers: crash, dos, oob-read
- unsolicited_response_injection: Server-side packets (OACK/DATA/ACK/ERROR) sent to port 69 where only RRQ/WRQ expected — OACK with options, DATA block#1 with payload, ACK block#0 mimicking WRQ ack, ERROR with crafted message, DATA block#0 (should never exist), OACK with extreme option values. Tests undefined behavior on listening port. Triggers: state-corruption, crash, dos
- tid_spoofing_confusion: Transfer ID session confusion — ACK with random block# to port 69, multiple RRQs concatenated in one datagram, DATA response to port 69, RRQ+ERROR in same datagram, ACK with appended option-like data, multiple RRQs for different files. Tests parser boundary detection and session management. Triggers: state-corruption, evasion, session-hijack
- pxe_boot_payload_injection: PXE/WDS-specific RRQ packets — CVE-2018-8476 Windows WDS TFTP UAF (PXE Dust, all Windows Server ≥2008SP2), PixieFail CVE-2023-45229-45237 EDK II UEFI PXE stack. Variants: standard PXE Dust option combo (blksize=1456+windowsize=64), extreme windowsize memory exhaustion, msftwindow non-standard option, UNC path injection, blksize×windowsize > cache overflow, PXE path + directory traversal. Targets PXE boot infrastructure. Triggers: uaf, memory-exhaustion, rce, arbitrary-file-read
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
  - Which mutation strategy from the list below BEST triggers this vulnerability (matched_strategy)
  - strategy_protocol: the protocol family that the matched strategy belongs to — EXACTLY one of:
    dns, ftp, http, smtp, ssh, smb2, smb3, http2, dcerpc, dhcp, dhcpv6, snmp, icmp, icmpv6, sip, mgcp, rtsp, radius, tacacs, ldap, cifs, sunrpc, telnet, tftp
    (this disambiguates strategy names shared by multiple protocols, e.g. cmd_overflow, version_confusion)
  - confidence: an integer 0-100 — how confident you are this is a REAL, triggerable bug (not theoretical)

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
      "strategy_protocol": "dns",
      "confidence": 90,
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
    Returns (dns_weights, ftp_weights, http_weights, smtp_weights, ssh_weights, smb2_weights, smb3_weights, http2_weights, dcerpc_weights, dhcp_weights, dhcpv6_weights, snmp_weights, icmp_weights, icmpv6_weights, sip_weights, mgcp_weights, rtsp_weights, radius_weights, tacacs_weights, ldap_weights, cifs_weights, sunrpc_weights, telnet_weights, tftp_weights, reasoning_str)."""

    # Start with default weights
    dns_w = dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS))
    ftp_w = dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS))
    http_w = dict(zip(HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS))
    smtp_w = dict(zip(SMTP_STRATEGY_NAMES, SMTP_DEFAULT_WEIGHTS))
    ssh_w = dict(zip(SSH_STRATEGY_NAMES, SSH_DEFAULT_WEIGHTS))
    smb2_w = dict(zip(SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS))
    smb3_w = dict(zip(SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS))
    http2_w = dict(zip(HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS))
    dcerpc_w = dict(zip(DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS))
    dhcp_w = dict(zip(DHCP_STRATEGY_NAMES, DHCP_DEFAULT_WEIGHTS))
    dhcpv6_w = dict(zip(DHCPV6_STRATEGY_NAMES, DHCPV6_DEFAULT_WEIGHTS))
    snmp_w = dict(zip(SNMP_STRATEGY_NAMES, SNMP_DEFAULT_WEIGHTS))
    icmp_w = dict(zip(ICMP_STRATEGY_NAMES, ICMP_DEFAULT_WEIGHTS))
    icmpv6_w = dict(zip(ICMPV6_STRATEGY_NAMES, ICMPV6_DEFAULT_WEIGHTS))
    sip_w = dict(zip(SIP_STRATEGY_NAMES, SIP_DEFAULT_WEIGHTS))
    mgcp_w = dict(zip(MGCP_STRATEGY_NAMES, MGCP_DEFAULT_WEIGHTS))
    rtsp_w = dict(zip(RTSP_STRATEGY_NAMES, RTSP_DEFAULT_WEIGHTS))
    radius_w = dict(zip(RADIUS_STRATEGY_NAMES, RADIUS_DEFAULT_WEIGHTS))
    tacacs_w = dict(zip(TACACS_STRATEGY_NAMES, TACACS_DEFAULT_WEIGHTS))
    ldap_w = dict(zip(LDAP_STRATEGY_NAMES, LDAP_DEFAULT_WEIGHTS))
    cifs_w = dict(zip(CIFS_STRATEGY_NAMES, CIFS_DEFAULT_WEIGHTS))
    sunrpc_w = dict(zip(SUNRPC_STRATEGY_NAMES, SUNRPC_DEFAULT_WEIGHTS))
    telnet_w = dict(zip(TELNET_STRATEGY_NAMES, TELNET_DEFAULT_WEIGHTS))
    tftp_w = dict(zip(TFTP_STRATEGY_NAMES, TFTP_DEFAULT_WEIGHTS))

    reasoning_lines = ["Weight computation (deterministic formula):"]
    reasoning_lines.append(f"  Starting from default weights. {len(verified_vulns)} verified vulnerabilities.")

    # Registry of protocol weight dicts. Order = deterministic first-match
    # fallback (matches the legacy if/elif precedence). Each entry is
    # (protocol_key, weight_dict, display_label, decimal_places).
    _weight_dicts = [
        ("dns", dns_w, "DNS", 4),
        ("ftp", ftp_w, "FTP", 1),
        ("http", http_w, "HTTP", 1),
        ("smtp", smtp_w, "SMTP", 1),
        ("ssh", ssh_w, "SSH", 1),
        ("smb2", smb2_w, "SMB2", 1),
        ("smb3", smb3_w, "SMB3", 1),
        ("http2", http2_w, "HTTP2", 1),
        ("dcerpc", dcerpc_w, "DCERPC", 1),
        ("dhcp", dhcp_w, "DHCP", 1),
        ("dhcpv6", dhcpv6_w, "DHCPv6", 1),
        ("snmp", snmp_w, "SNMP", 1),
        ("icmp", icmp_w, "ICMP", 1),
        ("icmpv6", icmpv6_w, "ICMPv6", 1),
        ("sip", sip_w, "SIP", 1),
        ("mgcp", mgcp_w, "MGCP", 1),
        ("rtsp", rtsp_w, "RTSP", 1),
        ("radius", radius_w, "RADIUS", 1),
        ("tacacs", tacacs_w, "TACACS+", 1),
        ("ldap", ldap_w, "LDAP", 1),
        ("cifs", cifs_w, "CIFS", 1),
        ("sunrpc", sunrpc_w, "SUNRPC", 1),
        ("telnet", telnet_w, "Telnet", 1),
        ("tftp", tftp_w, "TFTP", 1),
    ]
    _by_key = {k: (wd, disp, dec) for k, wd, disp, dec in _weight_dicts}
    # strategy name -> list of protocol keys that define it (in registry order)
    _name_index = {}
    for k, wd, _disp, _dec in _weight_dicts:
        for s in wd:
            _name_index.setdefault(s, []).append(k)
    # Common ways the model may spell a protocol family hint.
    _hint_aliases = {"smb": "smb2", "icmpv4": "icmp", "dhcp6": "dhcpv6", "tacacs+": "tacacs", "ldap+": "ldap", "smb1": "cifs", "rpc": "sunrpc", "oncrpc": "sunrpc", "nfs": "sunrpc", "portmapper": "sunrpc", "rpcbind": "sunrpc", "tel": "telnet", "trivial": "tftp", "pxe": "tftp"}

    # Apply multipliers
    for v in verified_vulns:
        strat = v.get("matched_strategy", "")
        sev = v.get("severity", "medium").lower()
        mult = SEVERITY_MULTIPLIERS.get(sev, 1.5)
        conf = v.get("confidence", 80) / 100.0  # scale multiplier by confidence

        effective_mult = 1.0 + (mult - 1.0) * conf
        func = v.get("function", "?")

        candidates = _name_index.get(strat, [])
        if not candidates:
            reasoning_lines.append(f"  WARNING: strategy '{strat}' not recognized, skipping")
            continue

        # Disambiguate strategy names shared across protocols (e.g. cmd_overflow
        # in FTP+SMTP, version_confusion in HTTP+SSH) using the model-provided
        # strategy_protocol hint. Falls back to deterministic first-match.
        hint = (v.get("strategy_protocol") or "").strip().lower()
        hint = _hint_aliases.get(hint, hint)
        if hint in candidates:
            target = hint
        elif len(candidates) == 1:
            target = candidates[0]
        else:
            target = candidates[0]  # deterministic first-match fallback
            reasoning_lines.append(
                f"  NOTE: '{strat}' is ambiguous across {candidates}; "
                f"strategy_protocol hint '{hint or 'none'}' invalid → defaulting to {_by_key[target][1]}")

        wd, disp, dec = _by_key[target]
        old = wd[strat]
        wd[strat] = old * effective_mult
        reasoning_lines.append(
            f"  {disp}/{strat}: {old:.{dec}f} × {effective_mult:.2f} "
            f"(sev={sev}, conf={v.get('confidence',80)}%, func={func}) = {wd[strat]:.{dec}f}")
        # SMB2 and SMB3 share strategy names — bump the SMB3 twin too
        # (preserves prior behavior when a vuln matches an SMB2 strategy).
        if target == "smb2" and strat in smb3_w:
            smb3_w[strat] = smb3_w[strat] * effective_mult

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

    # Normalize SSH to sum=100
    ssh_total = sum(ssh_w.values())
    if ssh_total > 0:
        ssh_w = {s: round(v / ssh_total * 100, 1) for s, v in ssh_w.items()}
    reasoning_lines.append(f"  SSH normalized (sum was {ssh_total:.1f})")

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

    # Normalize DHCP to sum=100
    dhcp_total = sum(dhcp_w.values())
    if dhcp_total > 0:
        dhcp_w = {s: round(v / dhcp_total * 100, 1) for s, v in dhcp_w.items()}
    reasoning_lines.append(f"  DHCP normalized (sum was {dhcp_total:.1f})")

    # Normalize DHCPv6 to sum=100
    dhcpv6_total = sum(dhcpv6_w.values())
    if dhcpv6_total > 0:
        dhcpv6_w = {s: round(v / dhcpv6_total * 100, 1) for s, v in dhcpv6_w.items()}
    reasoning_lines.append(f"  DHCPv6 normalized (sum was {dhcpv6_total:.1f})")

    # Normalize SNMP to sum=100
    snmp_total = sum(snmp_w.values())
    if snmp_total > 0:
        snmp_w = {s: round(v / snmp_total * 100, 1) for s, v in snmp_w.items()}
    reasoning_lines.append(f"  SNMP normalized (sum was {snmp_total:.1f})")

    # Normalize ICMP to sum=100
    icmp_total = sum(icmp_w.values())
    if icmp_total > 0:
        icmp_w = {s: round(v / icmp_total * 100, 1) for s, v in icmp_w.items()}
    reasoning_lines.append(f"  ICMP normalized (sum was {icmp_total:.1f})")

    # Normalize ICMPv6 to sum=100
    icmpv6_total = sum(icmpv6_w.values())
    if icmpv6_total > 0:
        icmpv6_w = {s: round(v / icmpv6_total * 100, 1) for s, v in icmpv6_w.items()}
    reasoning_lines.append(f"  ICMPv6 normalized (sum was {icmpv6_total:.1f})")

    # Normalize SIP to sum=100
    sip_total = sum(sip_w.values())
    if sip_total > 0:
        sip_w = {s: round(v / sip_total * 100, 1) for s, v in sip_w.items()}
    reasoning_lines.append(f"  SIP normalized (sum was {sip_total:.1f})")

    # Normalize MGCP to sum=100
    mgcp_total = sum(mgcp_w.values())
    if mgcp_total > 0:
        mgcp_w = {s: round(v / mgcp_total * 100, 1) for s, v in mgcp_w.items()}
    reasoning_lines.append(f"  MGCP normalized (sum was {mgcp_total:.1f})")

    # Normalize RTSP to sum=100
    rtsp_total = sum(rtsp_w.values())
    if rtsp_total > 0:
        rtsp_w = {s: round(v / rtsp_total * 100, 1) for s, v in rtsp_w.items()}
    reasoning_lines.append(f"  RTSP normalized (sum was {rtsp_total:.1f})")

    # Normalize RADIUS to sum=100
    radius_total = sum(radius_w.values())
    if radius_total > 0:
        radius_w = {s: round(v / radius_total * 100, 1) for s, v in radius_w.items()}
    reasoning_lines.append(f"  RADIUS normalized (sum was {radius_total:.1f})")

    # Normalize TACACS+ to sum=100
    tacacs_total = sum(tacacs_w.values())
    if tacacs_total > 0:
        tacacs_w = {s: round(v / tacacs_total * 100, 1) for s, v in tacacs_w.items()}
    reasoning_lines.append(f"  TACACS+ normalized (sum was {tacacs_total:.1f})")

    # Normalize LDAP to sum=100
    ldap_total = sum(ldap_w.values())
    if ldap_total > 0:
        ldap_w = {s: round(v / ldap_total * 100, 1) for s, v in ldap_w.items()}
    reasoning_lines.append(f"  LDAP normalized (sum was {ldap_total:.1f})")

    # Normalize CIFS to sum=100
    cifs_total = sum(cifs_w.values())
    if cifs_total > 0:
        cifs_w = {s: round(v / cifs_total * 100, 1) for s, v in cifs_w.items()}
    reasoning_lines.append(f"  CIFS normalized (sum was {cifs_total:.1f})")

    # Normalize SUNRPC to sum=100
    sunrpc_total = sum(sunrpc_w.values())
    if sunrpc_total > 0:
        sunrpc_w = {s: round(v / sunrpc_total * 100, 1) for s, v in sunrpc_w.items()}
    reasoning_lines.append(f"  SUNRPC normalized (sum was {sunrpc_total:.1f})")

    # Normalize Telnet to sum=100
    telnet_total = sum(telnet_w.values())
    if telnet_total > 0:
        telnet_w = {s: round(v / telnet_total * 100, 1) for s, v in telnet_w.items()}
    reasoning_lines.append(f"  Telnet normalized (sum was {telnet_total:.1f})")

    # Normalize TFTP to sum=100
    tftp_total = sum(tftp_w.values())
    if tftp_total > 0:
        tftp_w = {s: round(v / tftp_total * 100, 1) for s, v in tftp_w.items()}
    reasoning_lines.append(f"  TFTP normalized (sum was {tftp_total:.1f})")

    return dns_w, ftp_w, http_w, smtp_w, ssh_w, smb2_w, smb3_w, http2_w, dcerpc_w, dhcp_w, dhcpv6_w, snmp_w, icmp_w, icmpv6_w, sip_w, mgcp_w, rtsp_w, radius_w, tacacs_w, ldap_w, cifs_w, sunrpc_w, telnet_w, tftp_w, "\n".join(reasoning_lines)

# AI analysis state
analysis_state = {
    "files": {},
    "results": None,
    "status": "idle",
    "error": None,
    "trigger_packets": {},   # pid -> packet dict
    "vuln_packets": {},      # str(vuln_id) -> [pid, ...]
}


# ---------------------------------------------------------------------------
# Per-vulnerability trigger-packet sender tracking
# ---------------------------------------------------------------------------
_vuln_senders = {}          # vid -> sender state dict
_vuln_sender_threads = {}   # vid -> Thread
_vuln_sender_locks = {}     # vid -> Lock (created on demand)
_vuln_senders_global_lock = threading.Lock()


def _get_vuln_sender_lock(vid):
    """Return or create a per-vuln Lock under the global lock."""
    with _vuln_senders_global_lock:
        if vid not in _vuln_sender_locks:
            _vuln_sender_locks[vid] = threading.Lock()
        return _vuln_sender_locks[vid]


_DEFAULT_SENDER_STATE = {
    "running": False,
    "stop_requested": False,
    "tx_count": 0,
    "errors_count": 0,
    "current_packet_id": None,
    "started_at": None,
    "mode": None,
    "target_ip": None,
    "selected_count": 0,
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
        "payload_mode": fuzzer_state.get("payload_mode", "default"),
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
    if protocol not in ("dns", "ftp", "http", "smtp", "ssh", "smb2", "smb3", "http2", "dcerpc", "dhcp", "dhcpv6", "snmp", "icmp", "icmpv6", "sip", "mgcp", "rtsp", "radius", "tacacs", "ldap", "cifs", "sunrpc", "telnet", "tftp"):
        protocol = "dns"
    mode = body.get("mode", "pipe").lower()
    live_config = body.get("live_config", {})

    payload_mode = body.get("payload_mode", "default").lower()
    custom_payload = body.get("custom_payload", "")

    fuzzer_state["protocol"] = protocol
    fuzzer_state["mode"] = mode
    fuzzer_state["payload_mode"] = payload_mode
    if payload_mode == "custom" and custom_payload:
        fuzzer_state["payload_override"] = custom_payload.encode("utf-8", errors="replace") if isinstance(custom_payload, str) else custom_payload
    else:
        fuzzer_state["payload_override"] = None
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


# ── Multi-instance API ────────────────────────────────────────────────────

@app.route("/api/instances", methods=["GET"])
def api_instances_list():
    """List all fuzzer instances."""
    result = []
    for inst in list_instances():
        st = inst.get_state()
        result.append({
            "id": inst.id,
            "protocol": inst.protocol,
            "status": st.get("status", "idle"),
            "running": st.get("running", False),
            "iteration": st.get("iteration", 0),
            "packets_per_sec": st.get("packets_per_sec", 0),
        })
    return jsonify(result)


@app.route("/api/instances", methods=["POST"])
def api_instance_create():
    """Create a new fuzzer instance and start it."""
    body = request.json or {}
    protocol = body.get("protocol", "dns").lower()
    valid_protos = ("dns", "ftp", "http", "smtp", "ssh", "smb2", "smb3",
                    "http2", "dcerpc", "dhcp", "dhcpv6", "snmp", "icmp",
                    "icmpv6", "sip", "mgcp", "rtsp", "radius", "tacacs",
                    "ldap", "cifs", "sunrpc", "telnet", "tftp")
    if protocol not in valid_protos:
        protocol = "dns"

    live_config = body.get("live_config", {})
    if not live_config.get("server_ip"):
        return jsonify({"error": "live_config.server_ip is required"}), 400

    inst = create_instance(protocol=protocol, config=live_config)
    inst.reset_state()
    inst.state["protocol"] = protocol

    inst.start_as_process()
    return jsonify({"status": "started", "instance_id": inst.id, "protocol": protocol}), 201


@app.route("/api/instances/<instance_id>", methods=["GET"])
def api_instance_status(instance_id):
    """Get status of a specific instance."""
    inst = get_instance(instance_id)
    if not inst:
        return jsonify({"error": "Instance not found"}), 404

    state = inst.get_state()
    elapsed = 0
    if state.get("start_time"):
        if state.get("running"):
            elapsed = time.time() - state["start_time"]
        else:
            elapsed = state.get("_frozen_elapsed", 0)
    hours, rem = divmod(int(elapsed), 3600)
    mins, secs = divmod(rem, 60)

    protocol = inst.protocol
    labels = _labels_for(protocol)

    data = {
        "instance_id": inst.id,
        "protocol": protocol,
        "iteration": state.get("iteration", 0),
        "status": state.get("status", "idle"),
        "running": state.get("running", False),
        "anomaly_detected": state.get("anomaly_detected"),
        "current_strategy": state.get("current_strategy", ""),
        "baseline_mem_mb": state.get("baseline_mem_mb"),
        "peak_mem_mb": state.get("peak_mem_mb"),
        "current_mem_mb": state.get("current_mem_mb"),
        "snort_pid": state.get("snort_pid"),
        "total_crashes": state.get("total_crashes", 0),
        "last_crash_time": state.get("last_crash_time"),
        "last_crash_type": state.get("last_crash_type"),
        "packets_per_sec": state.get("packets_per_sec", 0),
        "strategy_stats": state.get("strategy_stats", {}),
        "strategy_labels": labels,
        "runtime": f"{hours:02d}:{mins:02d}:{secs:02d}",
        "trigger_detail": state.get("trigger_detail"),
        "bandit_stats": inst.get_bandit_stats(),
        "events": inst.get_events(),
    }
    return jsonify(data)


@app.route("/api/instances/<instance_id>/stop", methods=["POST"])
def api_instance_stop(instance_id):
    """Stop a specific instance."""
    inst = get_instance(instance_id)
    if not inst:
        return jsonify({"error": "Instance not found"}), 404
    st = inst.get_state()
    if not st.get("running"):
        return jsonify({"error": "Instance is not running"}), 400
    inst.request_stop()
    return jsonify({"status": "stopping", "instance_id": instance_id})


@app.route("/api/instances/<instance_id>", methods=["DELETE"])
def api_instance_destroy(instance_id):
    """Destroy a fuzzer instance."""
    ok = destroy_instance(instance_id)
    if not ok:
        return jsonify({"error": "Instance not found"}), 404
    return jsonify({"status": "destroyed", "instance_id": instance_id})


@app.route("/api/instances/<instance_id>/stream")
def api_instance_stream(instance_id):
    """SSE stream for a specific instance."""
    inst = get_instance(instance_id)
    if not inst:
        return jsonify({"error": "Instance not found"}), 404

    def generate():
        while True:
            state = inst.get_state()
            elapsed = 0
            if state.get("start_time"):
                if state.get("running"):
                    elapsed = time.time() - state["start_time"]
                else:
                    elapsed = state.get("_frozen_elapsed", 0)
            hours, rem = divmod(int(elapsed), 3600)
            mins, secs = divmod(rem, 60)

            protocol = inst.protocol
            labels = _labels_for(protocol)
            data = {
                "instance_id": inst.id,
                "protocol": protocol,
                "iteration": state.get("iteration", 0),
                "status": state.get("status", "idle"),
                "running": state.get("running", False),
                "anomaly_detected": state.get("anomaly_detected"),
                "current_strategy": state.get("current_strategy", ""),
                "baseline_mem_mb": state.get("baseline_mem_mb"),
                "peak_mem_mb": state.get("peak_mem_mb"),
                "current_mem_mb": state.get("current_mem_mb"),
                "snort_pid": state.get("snort_pid"),
                "total_crashes": state.get("total_crashes", 0),
                "last_crash_time": state.get("last_crash_time"),
                "last_crash_type": state.get("last_crash_type"),
                "packets_per_sec": state.get("packets_per_sec", 0),
                "strategy_stats": state.get("strategy_stats", {}),
                "strategy_labels": labels,
                "runtime": f"{hours:02d}:{mins:02d}:{secs:02d}",
                "trigger_detail": state.get("trigger_detail"),
                "bandit_stats": inst.get_bandit_stats(),
                "events": inst.get_events(),
            }
            yield f"data: {json.dumps(data)}\n\n"
            if not state.get("running") and state.get("status") != "running":
                yield f"data: {json.dumps(data)}\n\n"
                break
            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")


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
    if protocol not in ("http", "ftp", "smtp", "ssh", "smb2", "smb3", "http2", "dcerpc", "dhcp", "dhcpv6", "snmp", "icmp", "icmpv6", "sip", "mgcp", "rtsp", "radius", "tacacs", "ldap", "cifs", "sunrpc", "telnet", "tftp"):
        return jsonify({"error": "protocol must be one of: http, ftp, smtp, ssh, smb2, smb3, http2, dcerpc, dhcp, dhcpv6, snmp, icmp, icmpv6, sip, mgcp, rtsp, radius, tacacs, ldap, cifs, sunrpc, telnet, tftp"}), 400

    host = (request.form.get("host") or "").strip()
    if not host:
        return jsonify({"error": "Target host is required"}), 400

    default_port = {"http": 80, "ftp": 21, "smtp": 25, "ssh": 22, "smb2": 445, "smb3": 445, "http2": 80, "dcerpc": 135, "dhcp": 67, "dhcpv6": 547, "snmp": 161, "icmp": 0, "icmpv6": 0, "sip": 5060, "mgcp": 2427, "rtsp": 554, "radius": 1812, "tacacs": 49, "ldap": 389, "cifs": 445, "sunrpc": 111, "telnet": 23, "tftp": 69}[protocol]
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
        elif protocol == "ssh":
            res = send_file_ssh(
                host, port, f.filename, data,
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
        elif protocol == "dhcp":
            res = send_file_dhcp(
                host, port, f.filename, data,
            )
        elif protocol == "dhcpv6":
            res = send_file_dhcpv6(
                host, port, f.filename, data,
            )
        elif protocol == "snmp":
            res = send_file_snmp(
                host, port, f.filename, data,
            )
        elif protocol == "icmp":
            res = send_file_icmp(
                host, port, f.filename, data,
            )
        elif protocol == "icmpv6":
            res = send_file_icmpv6(
                host, port, f.filename, data,
            )
        elif protocol == "sip":
            res = send_file_sip(
                host, port, f.filename, data,
            )
        elif protocol == "mgcp":
            res = send_file_mgcp(
                host, port, f.filename, data,
            )
        elif protocol == "rtsp":
            res = send_file_rtsp(
                host, port, f.filename, data,
            )
        elif protocol == "radius":
            res = send_file_radius(
                host, port, f.filename, data,
            )
        elif protocol == "tacacs":
            res = send_file_tacacs(
                host, port, f.filename, data,
            )
        elif protocol == "ldap":
            res = send_file_ldap(
                host, port, f.filename, data,
            )
        elif protocol == "cifs":
            res = send_file_cifs(
                host, port, f.filename, data,
            )
        elif protocol == "sunrpc":
            res = send_file_sunrpc(
                host, port, f.filename, data,
            )
        elif protocol == "telnet":
            res = send_file_telnet(
                host, port, f.filename, data,
            )
        elif protocol == "tftp":
            res = send_file_tftp(
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
    if protocol not in ("http", "ftp", "smtp", "ssh", "smb2", "smb3", "http2", "dcerpc", "dhcp", "dhcpv6", "snmp", "icmp", "icmpv6", "sip", "mgcp", "rtsp", "radius", "tacacs", "ldap", "cifs", "sunrpc", "telnet", "tftp"):
        return jsonify({"error": "protocol must be one of: http, ftp, smtp, ssh, smb2, smb3, http2, dcerpc, dhcp, dhcpv6, snmp, icmp, icmpv6, sip, mgcp, rtsp, radius, tacacs, ldap, cifs, sunrpc, telnet, tftp"}), 400

    host = (request.form.get("host") or "").strip()
    if not host:
        return jsonify({"error": "Target host is required"}), 400

    default_port = {"http": 80, "ftp": 21, "smtp": 25, "ssh": 22, "smb2": 445, "smb3": 445, "http2": 80, "dcerpc": 135, "dhcp": 67, "dhcpv6": 547, "snmp": 161, "icmp": 0, "icmpv6": 0, "sip": 5060, "mgcp": 2427, "rtsp": 554, "radius": 1812, "tacacs": 49, "ldap": 389, "cifs": 445, "sunrpc": 111, "telnet": 23, "tftp": 69}[protocol]
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
                elif protocol == "ssh":
                    res = send_file_ssh(host, port, fname, data, on_packet=on_packet)
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
                elif protocol == "dhcp":
                    res = send_file_dhcp(host, port, fname, data,
                                         on_packet=on_packet)
                elif protocol == "dhcpv6":
                    res = send_file_dhcpv6(host, port, fname, data,
                                           on_packet=on_packet)
                elif protocol == "snmp":
                    res = send_file_snmp(host, port, fname, data,
                                         on_packet=on_packet)
                elif protocol == "icmp":
                    res = send_file_icmp(host, port, fname, data,
                                         on_packet=on_packet)
                elif protocol == "icmpv6":
                    res = send_file_icmpv6(host, port, fname, data,
                                           on_packet=on_packet)
                elif protocol == "sip":
                    res = send_file_sip(host, port, fname, data,
                                       on_packet=on_packet)
                elif protocol == "mgcp":
                    res = send_file_mgcp(host, port, fname, data,
                                        on_packet=on_packet)
                elif protocol == "rtsp":
                    res = send_file_rtsp(host, port, fname, data,
                                        on_packet=on_packet)
                elif protocol == "radius":
                    res = send_file_radius(host, port, fname, data,
                                          on_packet=on_packet)
                elif protocol == "tacacs":
                    res = send_file_tacacs(host, port, fname, data,
                                          on_packet=on_packet)
                elif protocol == "ldap":
                    res = send_file_ldap(host, port, fname, data,
                                        on_packet=on_packet)
                elif protocol == "cifs":
                    res = send_file_cifs(host, port, fname, data,
                                        on_packet=on_packet)
                elif protocol == "sunrpc":
                    res = send_file_sunrpc(host, port, fname, data,
                                          on_packet=on_packet)
                elif protocol == "telnet":
                    res = send_file_telnet(host, port, fname, data,
                                          on_packet=on_packet)
                elif protocol == "tftp":
                    res = send_file_tftp(host, port, fname, data,
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
        dns_w, ftp_w, http_w, smtp_w, ssh_w, smb2_w, smb3_w, http2_w, dcerpc_w, dhcp_w, dhcpv6_w, snmp_w, icmp_w, icmpv6_w, sip_w, mgcp_w, rtsp_w, radius_w, tacacs_w, ldap_w, cifs_w, sunrpc_w, telnet_w, tftp_w, reasoning = compute_weights_from_vulns(raw_vulns)
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
                "ssh": ssh_w,
                "smb2": smb2_w,
                "smb3": smb3_w,
                "http2": http2_w,
                "dcerpc": dcerpc_w,
                "dhcp": dhcp_w,
                "dhcpv6": dhcpv6_w,
                "snmp": snmp_w,
                "icmp": icmp_w,
                "icmpv6": icmpv6_w,
                "sip": sip_w,
                "mgcp": mgcp_w,
                "rtsp": rtsp_w,
                "radius": radius_w,
                "tacacs": tacacs_w,
                "ldap": ldap_w,
                "cifs": cifs_w,
                "sunrpc": sunrpc_w,
                "telnet": telnet_w,
                "tftp": tftp_w,
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
CHAT_MAX_CONTEXT_CHARS = 24_000   # hard cap on code context sent per chat turn
CHAT_SNIPPET_MAX_CHARS = 12_000   # cap on vuln-relevant snippets sent per chat turn
CHAT_SNIPPET_WINDOW = 16          # lines of code captured around each vuln anchor
CHAT_HISTORY_TURNS = 4            # number of recent user+assistant turns to replay
CHAT_MAX_VULNS = 40               # max vulns included in chat context
CHAT_MAX_SUMMARY_CHARS = 1_000    # cap on codebase summary length


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

    # Slim down vulns to essential fields only to save tokens
    slim_vulns = []
    # Sort by severity for priority (critical first)
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    sorted_vulns = sorted(vulns, key=lambda v: sev_order.get(v.get('severity', 'low'), 3))
    for v in sorted_vulns[:CHAT_MAX_VULNS]:
        slim_vulns.append({
            'id': v.get('original_id') or v.get('id', '?'),
            'function': v.get('function', '?'),
            'bug_class': v.get('bug_class', '?'),
            'severity': v.get('severity', '?'),
            'line_range': v.get('line_range', '?'),
            'matched_strategy': v.get('matched_strategy', ''),
        })
    try:
        vulns_json = json.dumps(slim_vulns, indent=1)
    except Exception:
        vulns_json = "[]"
    vulns_note = f" (showing top {CHAT_MAX_VULNS} of {len(vulns)} by severity)" if len(vulns) > CHAT_MAX_VULNS else ""

    # Truncate the summary
    summary = analysis.get('file_summary', 'n/a') or 'n/a'
    if len(summary) > CHAT_MAX_SUMMARY_CHARS:
        summary = summary[:CHAT_MAX_SUMMARY_CHARS] + '... [truncated]'

    # Cap file list
    files_list = conv.get('files', []) or []
    files_str = ', '.join(files_list[:20])
    if len(files_list) > 20:
        files_str += f' ... and {len(files_list) - 20} more'

    return f"""You are a senior security engineer assistant embedded in a protocol fuzzing platform.
You are discussing ONE specific codebase that has already been analyzed for vulnerabilities.

CODEBASE: {conv.get('title', 'Unknown')}
FILES: {files_str or 'n/a'}

SUMMARY: {summary}

PRIOR VULNERABILITY ANALYSIS ({len(vulns)} total{vulns_note}):
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

    # Rehydrate analysis_state so vuln-bound endpoints (trigger-packet
    # generation, chat) operate on the same vulns the UI is rendering.
    # Otherwise _find_vuln() looks in a stale/empty results blob and 404s.
    analysis = conv.get("analysis", {}) or {}
    if isinstance(analysis, dict):
        analysis["conversation_id"] = conv["_id"]
        analysis_state["results"] = analysis
        analysis_state["status"] = "done"
        analysis_state["error"] = None
        for st in _vuln_senders.values():
            if st.get("running"):
                st["stop_requested"] = True

        # Restore trigger packets saved with this conversation (or clear)
        saved_tp = conv.get("trigger_packets") or {}
        saved_vp = conv.get("vuln_packets") or {}
        analysis_state["trigger_packets"].clear()
        analysis_state["trigger_packets"].update(saved_tp)
        analysis_state["vuln_packets"].clear()
        analysis_state["vuln_packets"].update(saved_vp)

    return jsonify({
        "id": conv["_id"],
        "title": conv.get("title", "Untitled"),
        "files": conv.get("files", []),
        "analysis": analysis,
        "trigger_packets": list((conv.get("trigger_packets") or {}).values()),
        "vuln_packets": conv.get("vuln_packets") or {},
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
    ssh_default = dict(zip(SSH_STRATEGY_NAMES, SSH_DEFAULT_WEIGHTS))
    smb2_default = dict(zip(SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS))
    smb3_default = dict(zip(SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS))
    http2_default = dict(zip(HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS))
    dcerpc_default = dict(zip(DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS))
    dhcp_default = dict(zip(DHCP_STRATEGY_NAMES, DHCP_DEFAULT_WEIGHTS))
    dhcpv6_default = dict(zip(DHCPV6_STRATEGY_NAMES, DHCPV6_DEFAULT_WEIGHTS))
    snmp_default = dict(zip(SNMP_STRATEGY_NAMES, SNMP_DEFAULT_WEIGHTS))
    icmp_default = dict(zip(ICMP_STRATEGY_NAMES, ICMP_DEFAULT_WEIGHTS))
    icmpv6_default = dict(zip(ICMPV6_STRATEGY_NAMES, ICMPV6_DEFAULT_WEIGHTS))
    sip_default = dict(zip(SIP_STRATEGY_NAMES, SIP_DEFAULT_WEIGHTS))
    mgcp_default = dict(zip(MGCP_STRATEGY_NAMES, MGCP_DEFAULT_WEIGHTS))
    rtsp_default = dict(zip(RTSP_STRATEGY_NAMES, RTSP_DEFAULT_WEIGHTS))
    radius_default = dict(zip(RADIUS_STRATEGY_NAMES, RADIUS_DEFAULT_WEIGHTS))
    tacacs_default = dict(zip(TACACS_STRATEGY_NAMES, TACACS_DEFAULT_WEIGHTS))
    ldap_default = dict(zip(LDAP_STRATEGY_NAMES, LDAP_DEFAULT_WEIGHTS))
    cifs_default = dict(zip(CIFS_STRATEGY_NAMES, CIFS_DEFAULT_WEIGHTS))
    sunrpc_default = dict(zip(SUNRPC_STRATEGY_NAMES, SUNRPC_DEFAULT_WEIGHTS))
    telnet_default = dict(zip(TELNET_STRATEGY_NAMES, TELNET_DEFAULT_WEIGHTS))
    tftp_default = dict(zip(TFTP_STRATEGY_NAMES, TFTP_DEFAULT_WEIGHTS))
    return jsonify({
        "source": ai_weights.get("source", "default"),
        "dns": ai_weights.get("dns", dns_default),
        "ftp": ai_weights.get("ftp", ftp_default),
        "http": ai_weights.get("http", http_default),
        "smtp": ai_weights.get("smtp", smtp_default),
        "ssh": ai_weights.get("ssh", ssh_default),
        "smb2": ai_weights.get("smb2", smb2_default),
        "smb3": ai_weights.get("smb3", smb3_default),
        "http2": ai_weights.get("http2", http2_default),
        "dcerpc": ai_weights.get("dcerpc", dcerpc_default),
        "dhcp": ai_weights.get("dhcp", dhcp_default),
        "dhcpv6": ai_weights.get("dhcpv6", dhcpv6_default),
        "snmp": ai_weights.get("snmp", snmp_default),
        "icmp": ai_weights.get("icmp", icmp_default),
        "icmpv6": ai_weights.get("icmpv6", icmpv6_default),
        "sip": ai_weights.get("sip", sip_default),
        "mgcp": ai_weights.get("mgcp", mgcp_default),
        "rtsp": ai_weights.get("rtsp", rtsp_default),
        "radius": ai_weights.get("radius", radius_default),
        "tacacs": ai_weights.get("tacacs", tacacs_default),
        "ldap": ai_weights.get("ldap", ldap_default),
        "cifs": ai_weights.get("cifs", cifs_default),
        "sunrpc": ai_weights.get("sunrpc", sunrpc_default),
        "telnet": ai_weights.get("telnet", telnet_default),
        "tftp": ai_weights.get("tftp", tftp_default),
        "reasoning": ai_weights.get("reasoning", ""),
        "dns_default": dns_default,
        "ftp_default": ftp_default,
        "http_default": http_default,
        "smtp_default": smtp_default,
        "ssh_default": ssh_default,
        "smb2_default": smb2_default,
        "smb3_default": smb3_default,
        "http2_default": http2_default,
        "dcerpc_default": dcerpc_default,
        "dhcp_default": dhcp_default,
        "dhcpv6_default": dhcpv6_default,
        "snmp_default": snmp_default,
        "icmp_default": icmp_default,
        "icmpv6_default": icmpv6_default,
        "sip_default": sip_default,
        "mgcp_default": mgcp_default,
        "rtsp_default": rtsp_default,
        "radius_default": radius_default,
        "tacacs_default": tacacs_default,
        "ldap_default": ldap_default,
        "cifs_default": cifs_default,
        "sunrpc_default": sunrpc_default,
        "telnet_default": telnet_default,
        "tftp_default": tftp_default,
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
    ssh_raw = rec.get("ssh", {})
    smb2_raw = rec.get("smb2", {})
    smb3_raw = rec.get("smb3", {})
    http2_raw = rec.get("http2", {})
    dcerpc_raw = rec.get("dcerpc", {})
    dhcp_raw = rec.get("dhcp", {})
    dhcpv6_raw = rec.get("dhcpv6", {})
    snmp_raw = rec.get("snmp", {})
    icmp_raw = rec.get("icmp", {})
    icmpv6_raw = rec.get("icmpv6", {})
    sip_raw = rec.get("sip", {})
    mgcp_raw = rec.get("mgcp", {})
    rtsp_raw = rec.get("rtsp", {})
    radius_raw = rec.get("radius", {})
    tacacs_raw = rec.get("tacacs", {})
    ldap_raw = rec.get("ldap", {})
    cifs_raw = rec.get("cifs", {})
    sunrpc_raw = rec.get("sunrpc", {})
    telnet_raw = rec.get("telnet", {})
    tftp_raw = rec.get("tftp", {})

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

    # Normalize SSH weights
    ssh_total = sum(ssh_raw.get(s, 0) for s in SSH_STRATEGY_NAMES)
    if ssh_total > 0:
        ai_weights["ssh"] = {s: round(ssh_raw.get(s, 0) / ssh_total * 100, 1) for s in SSH_STRATEGY_NAMES}

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

    # Normalize DHCP weights
    dhcp_total = sum(dhcp_raw.get(s, 0) for s in DHCP_STRATEGY_NAMES)
    if dhcp_total > 0:
        ai_weights["dhcp"] = {s: round(dhcp_raw.get(s, 0) / dhcp_total * 100, 1) for s in DHCP_STRATEGY_NAMES}

    # Normalize DHCPv6 weights
    dhcpv6_total = sum(dhcpv6_raw.get(s, 0) for s in DHCPV6_STRATEGY_NAMES)
    if dhcpv6_total > 0:
        ai_weights["dhcpv6"] = {s: round(dhcpv6_raw.get(s, 0) / dhcpv6_total * 100, 1) for s in DHCPV6_STRATEGY_NAMES}

    # Normalize SNMP weights
    snmp_total = sum(snmp_raw.get(s, 0) for s in SNMP_STRATEGY_NAMES)
    if snmp_total > 0:
        ai_weights["snmp"] = {s: round(snmp_raw.get(s, 0) / snmp_total * 100, 1) for s in SNMP_STRATEGY_NAMES}

    # Normalize ICMP weights
    icmp_total = sum(icmp_raw.get(s, 0) for s in ICMP_STRATEGY_NAMES)
    if icmp_total > 0:
        ai_weights["icmp"] = {s: round(icmp_raw.get(s, 0) / icmp_total * 100, 1) for s in ICMP_STRATEGY_NAMES}

    # Normalize ICMPv6 weights
    icmpv6_total = sum(icmpv6_raw.get(s, 0) for s in ICMPV6_STRATEGY_NAMES)
    if icmpv6_total > 0:
        ai_weights["icmpv6"] = {s: round(icmpv6_raw.get(s, 0) / icmpv6_total * 100, 1) for s in ICMPV6_STRATEGY_NAMES}

    # Normalize SIP weights
    sip_total = sum(sip_raw.get(s, 0) for s in SIP_STRATEGY_NAMES)
    if sip_total > 0:
        ai_weights["sip"] = {s: round(sip_raw.get(s, 0) / sip_total * 100, 1) for s in SIP_STRATEGY_NAMES}

    # Normalize MGCP weights
    mgcp_total = sum(mgcp_raw.get(s, 0) for s in MGCP_STRATEGY_NAMES)
    if mgcp_total > 0:
        ai_weights["mgcp"] = {s: round(mgcp_raw.get(s, 0) / mgcp_total * 100, 1) for s in MGCP_STRATEGY_NAMES}

    # Normalize RTSP weights
    rtsp_total = sum(rtsp_raw.get(s, 0) for s in RTSP_STRATEGY_NAMES)
    if rtsp_total > 0:
        ai_weights["rtsp"] = {s: round(rtsp_raw.get(s, 0) / rtsp_total * 100, 1) for s in RTSP_STRATEGY_NAMES}

    # Normalize RADIUS weights
    radius_total = sum(radius_raw.get(s, 0) for s in RADIUS_STRATEGY_NAMES)
    if radius_total > 0:
        ai_weights["radius"] = {s: round(radius_raw.get(s, 0) / radius_total * 100, 1) for s in RADIUS_STRATEGY_NAMES}

    # Normalize TACACS+ weights
    tacacs_total = sum(tacacs_raw.get(s, 0) for s in TACACS_STRATEGY_NAMES)
    if tacacs_total > 0:
        ai_weights["tacacs"] = {s: round(tacacs_raw.get(s, 0) / tacacs_total * 100, 1) for s in TACACS_STRATEGY_NAMES}

    # Normalize LDAP weights
    ldap_total = sum(ldap_raw.get(s, 0) for s in LDAP_STRATEGY_NAMES)
    if ldap_total > 0:
        ai_weights["ldap"] = {s: round(ldap_raw.get(s, 0) / ldap_total * 100, 1) for s in LDAP_STRATEGY_NAMES}

    # Normalize CIFS weights
    cifs_total = sum(cifs_raw.get(s, 0) for s in CIFS_STRATEGY_NAMES)
    if cifs_total > 0:
        ai_weights["cifs"] = {s: round(cifs_raw.get(s, 0) / cifs_total * 100, 1) for s in CIFS_STRATEGY_NAMES}

    # Normalize SUNRPC weights
    sunrpc_total = sum(sunrpc_raw.get(s, 0) for s in SUNRPC_STRATEGY_NAMES)
    if sunrpc_total > 0:
        ai_weights["sunrpc"] = {s: round(sunrpc_raw.get(s, 0) / sunrpc_total * 100, 1) for s in SUNRPC_STRATEGY_NAMES}

    # Normalize Telnet weights
    telnet_total = sum(telnet_raw.get(s, 0) for s in TELNET_STRATEGY_NAMES)
    if telnet_total > 0:
        ai_weights["telnet"] = {s: round(telnet_raw.get(s, 0) / telnet_total * 100, 1) for s in TELNET_STRATEGY_NAMES}

    # Normalize TFTP weights
    tftp_total = sum(tftp_raw.get(s, 0) for s in TFTP_STRATEGY_NAMES)
    if tftp_total > 0:
        ai_weights["tftp"] = {s: round(tftp_raw.get(s, 0) / tftp_total * 100, 1) for s in TFTP_STRATEGY_NAMES}

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
    dhcp_bandit.reset()
    dhcpv6_bandit.reset()
    snmp_bandit.reset()
    icmp_bandit.reset()
    icmpv6_bandit.reset()
    sip_bandit.reset()
    mgcp_bandit.reset()
    rtsp_bandit.reset()
    radius_bandit.reset()
    tacacs_bandit.reset()
    ldap_bandit.reset()
    cifs_bandit.reset()
    sunrpc_bandit.reset()
    telnet_bandit.reset()
    tftp_bandit.reset()

    log_event("INFO", f"AI weights applied — source: {results.get('model_used', 'unknown')}, RL bandits reset")
    print(f"[AI] Weights applied: DNS={ai_weights['dns']}")
    print(f"[AI] Weights applied: FTP={ai_weights['ftp']}")
    print(f"[AI] Weights applied: HTTP={ai_weights['http']}")
    print(f"[AI] Weights applied: SMTP={ai_weights['smtp']}")
    print(f"[AI] Weights applied: SMB2={ai_weights['smb2']}")
    print(f"[AI] Weights applied: SMB3={ai_weights['smb3']}")
    print(f"[AI] Weights applied: HTTP2={ai_weights['http2']}")
    print(f"[AI] Weights applied: DCERPC={ai_weights['dcerpc']}")
    print(f"[AI] Weights applied: DHCP={ai_weights['dhcp']}")
    print(f"[AI] Weights applied: DHCPv6={ai_weights['dhcpv6']}")
    print(f"[AI] Weights applied: SNMP={ai_weights['snmp']}")
    print(f"[AI] Weights applied: ICMP={ai_weights.get('icmp', {})}")
    print(f"[AI] Weights applied: ICMPv6={ai_weights.get('icmpv6', {})}")
    print(f"[AI] Weights applied: SIP={ai_weights.get('sip', {})}")
    print(f"[AI] Weights applied: MGCP={ai_weights.get('mgcp', {})}")
    print(f"[AI] Weights applied: RTSP={ai_weights.get('rtsp', {})}")
    print(f"[AI] Weights applied: RADIUS={ai_weights.get('radius', {})}")
    print(f"[AI] Weights applied: TACACS+={ai_weights.get('tacacs', {})}")
    print(f"[AI] Weights applied: LDAP={ai_weights.get('ldap', {})}")
    print(f"[AI] Weights applied: CIFS={ai_weights.get('cifs', {})}")
    print(f"[AI] Weights applied: SUNRPC={ai_weights.get('sunrpc', {})}")

    return jsonify({"status": "applied", "dns": ai_weights["dns"], "ftp": ai_weights["ftp"], "http": ai_weights["http"], "smtp": ai_weights["smtp"], "ssh": ai_weights["ssh"], "smb2": ai_weights["smb2"], "smb3": ai_weights["smb3"], "http2": ai_weights["http2"], "dcerpc": ai_weights["dcerpc"], "dhcp": ai_weights["dhcp"], "dhcpv6": ai_weights["dhcpv6"], "snmp": ai_weights["snmp"], "icmp": ai_weights.get("icmp", {}), "icmpv6": ai_weights.get("icmpv6", {}), "sip": ai_weights.get("sip", {}), "mgcp": ai_weights.get("mgcp", {}), "rtsp": ai_weights.get("rtsp", {}), "radius": ai_weights.get("radius", {}), "tacacs": ai_weights.get("tacacs", {}), "ldap": ai_weights.get("ldap", {}), "cifs": ai_weights.get("cifs", {}), "sunrpc": ai_weights.get("sunrpc", {})})


@app.route("/api/ai/reset_weights", methods=["POST"])
def ai_reset_weights():
    """Reset weights back to defaults."""
    ai_weights["dns"] = dict(zip(DNS_STRATEGY_NAMES, DNS_DEFAULT_WEIGHTS))
    ai_weights["ftp"] = dict(zip(FTP_STRATEGY_NAMES, FTP_DEFAULT_WEIGHTS))
    ai_weights["http"] = dict(zip(HTTP_STRATEGY_NAMES, HTTP_DEFAULT_WEIGHTS))
    ai_weights["smtp"] = dict(zip(SMTP_STRATEGY_NAMES, SMTP_DEFAULT_WEIGHTS))
    ai_weights["ssh"] = dict(zip(SSH_STRATEGY_NAMES, SSH_DEFAULT_WEIGHTS))
    ai_weights["smb2"] = dict(zip(SMB2_STRATEGY_NAMES, SMB2_DEFAULT_WEIGHTS))
    ai_weights["smb3"] = dict(zip(SMB3_STRATEGY_NAMES, SMB3_DEFAULT_WEIGHTS))
    ai_weights["http2"] = dict(zip(HTTP2_STRATEGY_NAMES, HTTP2_DEFAULT_WEIGHTS))
    ai_weights["dcerpc"] = dict(zip(DCERPC_STRATEGY_NAMES, DCERPC_DEFAULT_WEIGHTS))
    ai_weights["dhcp"] = dict(zip(DHCP_STRATEGY_NAMES, DHCP_DEFAULT_WEIGHTS))
    ai_weights["dhcpv6"] = dict(zip(DHCPV6_STRATEGY_NAMES, DHCPV6_DEFAULT_WEIGHTS))
    ai_weights["snmp"] = dict(zip(SNMP_STRATEGY_NAMES, SNMP_DEFAULT_WEIGHTS))
    ai_weights["icmp"] = dict(zip(ICMP_STRATEGY_NAMES, ICMP_DEFAULT_WEIGHTS))
    ai_weights["icmpv6"] = dict(zip(ICMPV6_STRATEGY_NAMES, ICMPV6_DEFAULT_WEIGHTS))
    ai_weights["sip"] = dict(zip(SIP_STRATEGY_NAMES, SIP_DEFAULT_WEIGHTS))
    ai_weights["mgcp"] = dict(zip(MGCP_STRATEGY_NAMES, MGCP_DEFAULT_WEIGHTS))
    ai_weights["rtsp"] = dict(zip(RTSP_STRATEGY_NAMES, RTSP_DEFAULT_WEIGHTS))
    ai_weights["radius"] = dict(zip(RADIUS_STRATEGY_NAMES, RADIUS_DEFAULT_WEIGHTS))
    ai_weights["tacacs"] = dict(zip(TACACS_STRATEGY_NAMES, TACACS_DEFAULT_WEIGHTS))
    ai_weights["ldap"] = dict(zip(LDAP_STRATEGY_NAMES, LDAP_DEFAULT_WEIGHTS))
    ai_weights["cifs"] = dict(zip(CIFS_STRATEGY_NAMES, CIFS_DEFAULT_WEIGHTS))
    ai_weights["sunrpc"] = dict(zip(SUNRPC_STRATEGY_NAMES, SUNRPC_DEFAULT_WEIGHTS))
    ai_weights["telnet"] = dict(zip(TELNET_STRATEGY_NAMES, TELNET_DEFAULT_WEIGHTS))
    ai_weights["tftp"] = dict(zip(TFTP_STRATEGY_NAMES, TFTP_DEFAULT_WEIGHTS))
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
    dhcp_bandit.reset()
    dhcpv6_bandit.reset()
    snmp_bandit.reset()
    icmp_bandit.reset()
    icmpv6_bandit.reset()
    sip_bandit.reset()
    mgcp_bandit.reset()
    rtsp_bandit.reset()
    radius_bandit.reset()
    tacacs_bandit.reset()
    ldap_bandit.reset()
    cifs_bandit.reset()
    sunrpc_bandit.reset()
    telnet_bandit.reset()
    tftp_bandit.reset()

    log_event("INFO", "Strategy weights reset to defaults, RL bandits reset")
    return jsonify({"status": "reset"})


@app.route("/api/ai/_test_inject", methods=["POST"])
def ai_test_inject():
    """DEBUG: Inject fake analysis results to test weight pipeline without OpenAI."""
    data = request.json
    analysis_state["results"] = data
    analysis_state["status"] = "done" if data else "idle"
    return jsonify({"status": "injected" if data else "cleared"})


@app.route("/api/ai/resave", methods=["POST"])
def ai_resave():
    """Retry saving in-memory analysis results to MongoDB."""
    results = analysis_state.get("results")
    if not results:
        return jsonify({"error": "No results in memory to save"}), 400
    all_files = dict(analysis_state.get("files", {}))
    conv_id = db_create_conversation(
        _derive_title(list(all_files.keys()) if all_files else ["unknown"]),
        compute_codebase_hash(all_files) if all_files else "unknown",
        list(all_files.keys()),
        results.get("code_context", ""),
        results,
    )
    if conv_id:
        results["conversation_id"] = conv_id
        return jsonify({"status": "saved", "conversation_id": conv_id})
    return jsonify({"error": "MongoDB save failed — check server logs"}), 500


# ---------------------------------------------------------------------------
# Per-vuln Trigger Packet generation + targeted send (AI Analysis page)
#
# Flow:
#   1) UI clicks "Generate Trigger Packets" on a vuln -> POST
#      /api/ai/vulns/<vid>/generate_packets.  Server queries ChromaDB for the
#      most relevant chunks for that vuln, builds a prompt, and asks the LLM
#      for N (default 6) distinct application-layer packets, each as raw hex.
#   2) Packets are stored under analysis_state["trigger_packets"] keyed by a
#      short UUID and indexed per-vuln in analysis_state["vuln_packets"].
#   3) UI lets the user check packets across many vulns, then POST
#      /api/ai/packets/send/stream with a target IP.  A background thread
#      walks the selected packets either once (send_once) or round-robin
#      forever (round_robin), streaming NDJSON tx events back to the UI.
#      /api/ai/packets/send/stop is the cooperative kill switch.
# ---------------------------------------------------------------------------
PACKET_GEN_PROMPT = """You are an elite network-protocol exploit researcher.
You are given:
  - A single vulnerability identified by an earlier analysis pass (function,
    bug class, severity, reasoning, target protocol and port).
  - A short summary of the wider codebase.
  - The most-relevant source-code chunks around that vulnerability.

Your task: produce N DISTINCT application-layer packets that would each drive
execution into the vulnerable function and exercise the bug from a different
angle.  Use the angles below; pick the most useful ones for this specific
bug class:

  - Minimal valid baseline that simply reaches the function.
  - Boundary-condition payload (one unit past the bug threshold).
  - Deep overflow / extreme value to stress arithmetic and reassembly.
  - Variant with different field ordering, packing or whitespace.
  - State-machine variant that drives the parser into the vulnerable state.
  - Fragmented / partial / split variant when reassembly is in play.

Hard rules for the "hex" field:
  - It MUST be the EXACT bytes you would put on the wire at the application
    layer (no Ethernet, no IP, no TCP/UDP header — the transport adds those).
  - For TCP-DNS include the 2-byte length prefix in the hex.
  - For TCP-based protocols (HTTP, FTP, SMTP, SMB, DCERPC, ...) the hex is
    the application payload sent over a single TCP connection.
  - For UDP-based protocols (DNS, SNMP, DHCP, ...) the hex is the UDP body.
  - For ICMP / ICMPv6 the hex is the ICMP message starting at the ICMP type.
  - KEEP EACH PACKET SMALL — target under 2048 bytes (4096 hex characters).
    Use a compact, representative payload, not a maximum-length flood. For
    overflow bugs, just exceed the boundary by 32–256 bytes — the wire size
    is the trigger, the boundary itself is the bug.
  - The hex string must be even-length and contain ONLY 0-9 a-f A-F.

Hard rules for the JSON envelope:
  - Keep "name" under 60 characters and "description" under 240 characters.
    Do NOT restate the vulnerability's reasoning — only say what THIS packet
    does differently from the others.
  - Emit the packets in increasing complexity (minimal first, fragmented last).
  - Output ONE compact JSON object on a single line. No trailing commentary.

Output strict JSON in this exact shape:
{
  "packets": [
    {
      "name": "short label (<= 80 chars)",
      "description": "one or two sentences explaining what this packet does and why it triggers the bug",
      "protocol": "tcp" | "udp" | "icmp" | "icmpv6",
      "port": <int>,
      "hex": "deadbeef...",
      "send_strategy": "single" | "split_tcp",
      "split_at": <int or null, only when send_strategy=split_tcp>
    }
  ]
}

Return ONLY the JSON object.  No prose, no markdown fences.
"""

_VALID_PROTOS = {"tcp", "udp", "icmp", "icmpv6"}


def _normalise_hex(s):
    """Return a clean lower-case even-length hex string, or None if invalid."""
    if not isinstance(s, str):
        return None
    s = s.strip().replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
    if s.startswith(("0x", "0X")):
        s = s[2:]
    if not s or len(s) % 2 != 0:
        return None
    try:
        bytes.fromhex(s)
    except ValueError:
        return None
    return s.lower()


def _find_vuln(vid):
    """Look up a vuln in the current analysis_state by id or original_id."""
    results = analysis_state.get("results") or {}
    target = str(vid)
    for v in results.get("vulnerabilities", []):
        if str(v.get("id")) == target or str(v.get("original_id")) == target:
            return v
    return None


def _generate_trigger_packets_llm(vuln, codebase_summary, n_packets=6):
    """Call the LLM to produce N trigger packets for a single vulnerability.

    Pulls the most-relevant code chunks for the vuln from ChromaDB to give
    the model concrete context rather than relying on its earlier guess.
    """
    from engine.semantic_search import query_codebase
    from engine.llm_client import ai_call

    fn = (vuln.get("function") or "").strip()
    bug = vuln.get("bug_class") or ""
    proto = vuln.get("protocol") or ""
    port = vuln.get("port") or ""
    reasoning = (vuln.get("reasoning") or "")[:800]
    strategy_reason = (vuln.get("strategy_reasoning") or "")[:400]

    query = " ".join(x for x in [fn, bug, proto, reasoning[:200]] if x)
    try:
        hits = query_codebase(query, n_results=10)
    except Exception:
        hits = []

    code_parts = []
    for h in hits[:10]:
        code_parts.append(
            f"=== {h.get('file','?')} :: {h.get('name','?')} "
            f"({h.get('node_type','?')}) "
            f"L{h.get('start_line','?')}-{h.get('end_line','?')} ===\n"
            f"{h.get('code','')}\n"
            f"=== END ==="
        )
    code_context = "\n\n".join(code_parts) or "(no code chunks retrieved)"
    if len(code_context) > 18000:
        code_context = code_context[:18000] + "\n... [truncated] ..."

    user_prompt = (
        f"CODEBASE SUMMARY (truncated):\n{(codebase_summary or '')[:1500]}\n\n"
        f"TARGET VULNERABILITY:\n"
        f"  function:    {fn}\n"
        f"  bug_class:   {bug}\n"
        f"  severity:    {vuln.get('severity','?')}\n"
        f"  protocol:    {proto}\n"
        f"  port:        {port}\n"
        f"  line_range:  {vuln.get('line_range','?')}\n"
        f"  reasoning:   {reasoning}\n"
        f"  strategy:    {vuln.get('matched_strategy','?')} ({strategy_reason})\n\n"
        f"RELEVANT CODE CHUNKS:\n{code_context}\n\n"
        f"Now produce {n_packets} distinct trigger packets per the system instructions."
    )

    print(f"[gen_packets] vuln '{fn}' ({bug}) — calling Azure LLM "
          f"with {len(hits)} chunks (~{len(user_prompt)//1024} KB prompt)")
    _t0 = time.time()
    # GPT-5 is a reasoning model: completion_tokens covers both the hidden
    # reasoning trace and the visible JSON, so we match the Explorer budget
    # (65536) to leave room for both even on heavy bugs.
    result, _model = ai_call(PACKET_GEN_PROMPT, user_prompt,
                             max_tokens=65536, timeout=600)
    print(f"[gen_packets] vuln '{fn}' — LLM returned in {time.time()-_t0:.1f}s")

    if not isinstance(result, dict):
        return []

    pkts = result.get("packets")
    if not isinstance(pkts, list):
        # Tolerate the model returning the list under a different top-level key.
        for v in result.values():
            if isinstance(v, list) and v and isinstance(v[0], dict) and \
                    ("hex" in v[0] or "payload_hex" in v[0]):
                pkts = v
                break

    # Truncated-JSON recovery: when GPT-5 hits the completion-token cap mid
    # array, llm_client wraps the raw text in {"raw_response": ..., "parse_error": True}.
    # Walk the partial array, balance braces, and salvage whatever full packet
    # objects already finished serialising.
    if (not pkts) and result.get("parse_error") and result.get("raw_response"):
        salvaged = _recover_packets_from_truncated_json(result["raw_response"])
        if salvaged:
            print(f"[gen_packets] vuln '{fn}' — recovered {len(salvaged)} packets "
                  f"from truncated JSON")
            pkts = salvaged

    return pkts or []


def _recover_packets_from_truncated_json(raw: str):
    """Salvage complete packet objects from a JSON response that was cut off.

    The model usually emits ``{"packets": [{...}, {...}, {...truncated``.
    We locate the opening ``[`` of the packets array, then scan forward with a
    bracket / string-state counter, peeling off each top-level ``{...}`` whose
    closing brace we actually saw. Returns the list of recovered dicts (may
    be empty).
    """
    if not isinstance(raw, str) or not raw:
        return []
    # Find "packets":[
    key_idx = raw.find('"packets"')
    if key_idx < 0:
        return []
    open_idx = raw.find('[', key_idx)
    if open_idx < 0:
        return []

    out = []
    depth = 0
    in_str = False
    escape = False
    obj_start = None
    i = open_idx + 1  # skip the opening [
    n = len(raw)
    while i < n:
        c = raw[i]
        if escape:
            escape = False
        elif c == '\\':
            escape = True
        elif c == '"':
            in_str = not in_str
        elif not in_str:
            if c == '{':
                if depth == 0:
                    obj_start = i
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0 and obj_start is not None:
                    chunk = raw[obj_start:i + 1]
                    try:
                        out.append(json.loads(chunk))
                    except Exception:
                        pass
                    obj_start = None
            elif c == ']' and depth == 0:
                break
        i += 1
    return out


def _store_packets_for_vuln(vid, raw_packets):
    """Validate, assign ids, and replace any previous packets for this vuln."""
    stored = []
    pid_list = []
    rejected = 0
    for raw in raw_packets:
        if not isinstance(raw, dict):
            rejected += 1
            continue
        hex_str = _normalise_hex(raw.get("hex") or raw.get("payload_hex"))
        if not hex_str:
            rejected += 1
            continue
        proto = (raw.get("protocol") or "").lower().strip()
        if proto not in _VALID_PROTOS:
            rejected += 1
            continue
        try:
            port = int(raw.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        send_strategy = (raw.get("send_strategy") or "single").lower()
        if send_strategy not in ("single", "split_tcp"):
            send_strategy = "single"
        split_at = raw.get("split_at")
        try:
            split_at = int(split_at) if split_at is not None else None
        except (TypeError, ValueError):
            split_at = None

        pid = uuid.uuid4().hex[:12]
        pkt = {
            "id": pid,
            "vuln_id": str(vid),
            "name": (raw.get("name") or f"packet-{pid[:6]}")[:120],
            "description": (raw.get("description") or "")[:600],
            "protocol": proto,
            "port": port,
            "hex": hex_str,
            "size": len(hex_str) // 2,
            "send_strategy": send_strategy,
            "split_at": split_at,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        analysis_state["trigger_packets"][pid] = pkt
        pid_list.append(pid)
        stored.append(pkt)

    # Replace previous packets for this vuln (drop their entries from the global map too)
    for old_pid in analysis_state["vuln_packets"].get(str(vid), []):
        analysis_state["trigger_packets"].pop(old_pid, None)
    analysis_state["vuln_packets"][str(vid)] = pid_list
    return stored, rejected


def _send_one_packet(pkt, target_ip, port_override, interface, transport=None):
    """Drive LiveNetworkTransport to put one packet on the wire.

    If *transport* is supplied (a pre-existing LiveNetworkTransport), TCP
    packets are sent via its persistent connection.  Otherwise a fresh
    transport (and socket) is created for each call.
    """
    from transport.network import LiveNetworkTransport

    proto = pkt["protocol"]
    port = port_override if port_override else pkt.get("port") or 0
    data = bytes.fromhex(pkt["hex"])
    start = time.time()
    err = None
    sent = 0

    try:
        tx = transport or LiveNetworkTransport(target_ip, port or 0, interface or None)
        if proto == "udp":
            tx.send_udp(data, port=port or None)
            sent = len(data)
        elif proto == "tcp":
            if transport:
                tx.send_persistent_tcp(
                    data, port=port or None,
                    split_at=(pkt.get("split_at")
                              if pkt.get("send_strategy") == "split_tcp" else None),
                )
            else:
                if pkt.get("send_strategy") == "split_tcp":
                    tx.send_split_tcp(data, split_at=pkt.get("split_at") or 1)
                else:
                    tx.send_tcp(data, port=port or None)
            sent = len(data)
        elif proto == "icmp":
            tx.send_icmp(data)
            sent = len(data)
        elif proto == "icmpv6":
            tx.send_icmpv6(data, dst_ipv6=target_ip)
            sent = len(data)
        else:
            err = f"unsupported protocol: {proto}"
    except Exception as e:
        err = f"{type(e).__name__}: {e}"

    return {
        "type": "tx",
        "packet_id": pkt["id"],
        "name": pkt.get("name"),
        "vuln_id": pkt.get("vuln_id"),
        "protocol": proto,
        "dst": (f"{target_ip}:{port}" if port else target_ip),
        "size": len(data),
        "sent": sent,
        "ok": err is None,
        "error": err,
        "duration_ms": int((time.time() - start) * 1000),
    }


def _packet_sender_loop(vid, packets, target_ip, port_override, interface,
                        mode, delay_ms, q):
    """Background worker: walks packets in send_once or round_robin mode."""
    from transport.network import LiveNetworkTransport

    state = _vuln_senders[vid]
    has_tcp = any(p["protocol"] == "tcp" for p in packets)
    persistent_tx = None
    if mode == "round_robin" and has_tcp:
        persistent_tx = LiveNetworkTransport(target_ip, port_override or 0, interface or None)

    try:
        state.update({
            "running": True,
            "stop_requested": False,
            "tx_count": 0,
            "errors_count": 0,
            "started_at": time.time(),
            "mode": mode,
            "target_ip": target_ip,
            "selected_count": len(packets),
            "current_packet_id": None,
        })
        q.put({"type": "start", "count": len(packets), "mode": mode,
               "target_ip": target_ip, "delay_ms": delay_ms, "vuln_id": vid})

        def _interruptible_sleep(ms):
            if ms <= 0:
                return
            end = time.time() + ms / 1000.0
            while time.time() < end and not state["stop_requested"]:
                time.sleep(min(0.05, max(0.0, end - time.time())))

        if mode == "round_robin":
            i = 0
            while not state["stop_requested"]:
                pkt = packets[i % len(packets)]
                state["current_packet_id"] = pkt["id"]
                tx = persistent_tx if pkt["protocol"] == "tcp" and persistent_tx else None
                evt = _send_one_packet(pkt, target_ip, port_override, interface, transport=tx)
                state["tx_count"] += 1
                if not evt["ok"]:
                    state["errors_count"] += 1
                evt["iter"] = i + 1
                q.put(evt)
                i += 1
                _interruptible_sleep(delay_ms)
        else:  # send_once
            for i, pkt in enumerate(packets):
                if state["stop_requested"]:
                    break
                state["current_packet_id"] = pkt["id"]
                evt = _send_one_packet(pkt, target_ip, port_override, interface, transport=None)
                state["tx_count"] += 1
                if not evt["ok"]:
                    state["errors_count"] += 1
                evt["iter"] = i + 1
                q.put(evt)
                if i < len(packets) - 1:
                    _interruptible_sleep(delay_ms)
    except Exception as e:
        traceback.print_exc()
        q.put({"type": "error", "error": f"{type(e).__name__}: {e}"})
    finally:
        if persistent_tx:
            persistent_tx.close_persistent_tcp()
        q.put({
            "type": "done",
            "vuln_id": vid,
            "tx_count": state["tx_count"],
            "errors": state["errors_count"],
            "elapsed_ms": int((time.time() - (state["started_at"] or time.time())) * 1000),
        })
        state["running"] = False
        state["current_packet_id"] = None


@app.route("/api/ai/vulns/<vid>/generate_packets", methods=["POST"])
def api_ai_generate_packets(vid):
    if not AZURE_OPENAI_API_KEY:
        return jsonify({"error": "AZURE_OPENAI_API_KEY not set in .env"}), 500
    body = request.json or {}
    try:
        n = int(body.get("n_packets") or 6)
    except (TypeError, ValueError):
        n = 6
    n = max(1, min(n, 10))

    vuln = _find_vuln(vid)
    if not vuln:
        return jsonify({"error": f"Vulnerability {vid} not found"}), 404

    results = analysis_state.get("results") or {}
    summary = results.get("codebase_summary") or results.get("file_summary") or ""

    try:
        raw_packets = _generate_trigger_packets_llm(vuln, summary, n_packets=n)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"LLM call failed: {e}"}), 500

    stored, rejected = _store_packets_for_vuln(vid, raw_packets)
    if not stored:
        return jsonify({
            "error": "LLM returned no valid packets",
            "raw_count": len(raw_packets),
            "rejected": rejected,
        }), 502

    conv_id = results.get("conversation_id")
    if conv_id:
        db_save_trigger_packets(
            conv_id,
            dict(analysis_state["trigger_packets"]),
            dict(analysis_state["vuln_packets"]),
        )

    return jsonify({
        "vuln_id": str(vid),
        "packets": stored,
        "count": len(stored),
        "rejected": rejected,
    })


@app.route("/api/ai/packets", methods=["GET"])
def api_ai_packets_list():
    return jsonify({
        "packets": list(analysis_state["trigger_packets"].values()),
        "by_vuln": analysis_state["vuln_packets"],
    })


@app.route("/api/ai/packets/<pid>", methods=["DELETE"])
def api_ai_packet_delete(pid):
    pkt = analysis_state["trigger_packets"].pop(pid, None)
    if not pkt:
        return jsonify({"error": "Packet not found"}), 404
    vid = pkt["vuln_id"]
    lst = analysis_state["vuln_packets"].get(vid, [])
    if pid in lst:
        lst.remove(pid)
        analysis_state["vuln_packets"][vid] = lst

    conv_id = (analysis_state.get("results") or {}).get("conversation_id")
    if conv_id:
        db_save_trigger_packets(
            conv_id,
            dict(analysis_state["trigger_packets"]),
            dict(analysis_state["vuln_packets"]),
        )

    return jsonify({"status": "deleted"})


@app.route("/api/ai/vulns/<vid>/packets/send/stream", methods=["POST"])
def api_ai_packets_send_stream(vid):
    lock = _get_vuln_sender_lock(vid)
    with lock:
        state = _vuln_senders.get(vid)
        if state and state["running"]:
            return jsonify({"error": f"Sender for vuln {vid} is already running"}), 409

        body = request.json or {}
        pids = body.get("packet_ids") or []
        if not isinstance(pids, list) or not pids:
            return jsonify({"error": "packet_ids must be a non-empty list"}), 400

        target_ip = (body.get("target_ip") or "").strip()
        if not target_ip:
            return jsonify({"error": "target_ip is required"}), 400

        port_override = body.get("port_override")
        try:
            port_override = (int(port_override)
                             if port_override not in (None, "", 0, "0") else None)
        except (TypeError, ValueError):
            port_override = None

        interface = (body.get("interface") or "").strip() or None

        mode = (body.get("mode") or "round_robin").lower()
        if mode not in ("send_once", "round_robin"):
            mode = "round_robin"

        try:
            delay_ms = max(0, int(body.get("delay_ms") or 50))
        except (TypeError, ValueError):
            delay_ms = 50

        packets = [analysis_state["trigger_packets"].get(p) for p in pids]
        packets = [p for p in packets if p]
        if not packets:
            return jsonify({"error": "No valid packets resolved from packet_ids"}), 400

        _vuln_senders[vid] = dict(_DEFAULT_SENDER_STATE)
        cur_state = _vuln_senders[vid]
        q = queue.Queue(maxsize=4096)

        def gen():
            while True:
                try:
                    evt = q.get(timeout=15.0)
                except queue.Empty:
                    yield "\n"
                    if not cur_state["running"]:
                        break
                    continue
                yield json.dumps(evt) + "\n"
                if evt.get("type") == "done":
                    break

        t = threading.Thread(
            target=_packet_sender_loop,
            args=(vid, packets, target_ip, port_override, interface,
                  mode, delay_ms, q),
            daemon=True,
        )
        _vuln_sender_threads[vid] = t
        t.start()

    log_event("INFO",
              f"Packet sender started for vuln {vid} "
              f"({mode}, {len(packets)} packets -> {target_ip})")
    return Response(gen(), mimetype="application/x-ndjson")


@app.route("/api/ai/vulns/<vid>/packets/send/stop", methods=["POST"])
def api_ai_packets_send_stop(vid):
    state = _vuln_senders.get(vid)
    if not state or not state["running"]:
        return jsonify({"error": f"No send in progress for vuln {vid}"}), 400
    state["stop_requested"] = True
    log_event("WARNING", f"Packet sender stop requested for vuln {vid}")
    return jsonify({"status": "stopping"})


@app.route("/api/ai/vulns/<vid>/packets/send/status", methods=["GET"])
def api_ai_packets_send_status(vid):
    state = _vuln_senders.get(vid, dict(_DEFAULT_SENDER_STATE))
    return jsonify(state)


@app.route("/api/ai/clear", methods=["POST"])
def ai_clear():
    for st in _vuln_senders.values():
        if st.get("running"):
            st["stop_requested"] = True
    analysis_state["files"].clear()
    analysis_state["results"] = None
    analysis_state["status"] = "idle"
    analysis_state["error"] = None
    analysis_state["trigger_packets"].clear()
    analysis_state["vuln_packets"].clear()
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
            dns_w, ftp_w, http_w, smtp_w, ssh_w, smb2_w, smb3_w, http2_w, dcerpc_w, dhcp_w, dhcpv6_w, snmp_w, icmp_w, icmpv6_w, sip_w, mgcp_w, rtsp_w, radius_w, tacacs_w, ldap_w, cifs_w, sunrpc_w, telnet_w, tftp_w, reasoning = compute_weights_from_vulns(raw_vulns)
            recommended_weights = {
                "dns": dns_w, "ftp": ftp_w, "http": http_w, "smtp": smtp_w, "ssh": ssh_w,
                "smb2": smb2_w, "smb3": smb3_w, "http2": http2_w, "dcerpc": dcerpc_w,
                "dhcp": dhcp_w, "dhcpv6": dhcpv6_w, "snmp": snmp_w, "icmp": icmp_w, "icmpv6": icmpv6_w, "sip": sip_w, "mgcp": mgcp_w, "rtsp": rtsp_w, "radius": radius_w, "tacacs": tacacs_w, "ldap": ldap_w, "cifs": cifs_w, "sunrpc": sunrpc_w, "telnet": telnet_w, "tftp": tftp_w, "weight_reasoning": reasoning,
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



# ---------------------------------------------------------------------------
# Multi-Protocol Attack (Snort Blinder UI)
# ---------------------------------------------------------------------------
_BLINDER_PROTOCOL_REGISTRY = {
    "dns":     ("udp",  53),   "dhcp":    ("udp",  67),
    "snmp":    ("udp",  161),  "sip":     ("udp",  5060),
    "mgcp":    ("udp",  2427), "radius":  ("udp",  1812),
    "sunrpc":  ("udp",  111),  "tftp":    ("udp",  69),
    "http":    ("tcp",  80),   "ftp":     ("tcp",  21),
    "smtp":    ("tcp",  25),   "ssh":     ("tcp",  22),
    "smb2":    ("tcp",  445),  "http2":   ("tcp",  80),
    "dcerpc":  ("tcp",  135),  "rtsp":    ("tcp",  554),
    "tacacs":  ("tcp",  49),   "ldap":    ("tcp",  389),
    "cifs":    ("tcp",  445),  "telnet":  ("tcp",  23),
    "icmp":    ("icmp", 0),
}

_BLINDER_INTENSITY = {
    1: {"udp": 3,  "tcp": 2,  "label": "Normal"},
    2: {"udp": 6,  "tcp": 4,  "label": "Elevated"},
    3: {"udp": 10, "tcp": 6,  "label": "High"},
    4: {"udp": 15, "tcp": 8,  "label": "Extreme"},
    5: {"udp": 20, "tcp": 12, "label": "Maximum"},
}

# Snort alert log — shared Docker volume mounted at /shared/snort_logs (kali)
# and /var/log/snort (firewall).  Falls back to local path if running on host.
_SNORT_LOG_PATHS = [
    "/shared/snort_logs/alert_fast.txt",   # inside kali via shared volume
    "/var/log/snort/alert_fast.txt",        # if running directly on firewall
]
_CANARY_SIDS = ["1000001", "1000006"]  # TCP and UDP canary rules


class FtdSnortStats:
    """SSH into FTD, drop to expert bash, and run 'show snort statistics'
    by PIPING it into clish via stdin: echo "show snort statistics" | clish

    Why this works:
    - 'clish -c "cmd"' fails on this FTD ("Illegal command line")
    - Interactive CLISH is flaky (echo/timing/\r issues)
    - But bash with echo-markers is 100% reliable (RemoteSnortMonitor)
    - Piping into clish's stdin runs commands non-interactively
    """

    def __init__(self, host, port=22, username="admin", password="", log_fn=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._client = None
        self._shell = None
        self._stats_cmd = None   # bash command that yields stats
        self._clear_cmd = None   # bash command that clears stats
        self._alert_glob = None  # glob for per-instance perfmon base CSVs
        self._alert_files = []   # resolved perf_monitor_base.csv paths (1 per instance)
        self._alert_arg = ""     # explicit space-joined quoted file paths for tail/awk
        self._alert_col = None   # 0-based column index of detection.alerts
        self._alert_baseline = 0 # summed alert count at connect (cumulative mode only)
        self._alert_cumulative = True  # detected: True=running total, False=per-interval
        self._alert_since_ts = 0 # epoch cutoff for per-interval summation
        self._perf_interval = 0  # seconds between perfmon CSV samples (empirical)
        self._sudo = ""          # 'sudo ' prefix if needed/available for root-owned files
        self._log_fn = log_fn or (lambda msg: None)

    def _log(self, msg):
        print(f"[FtdSnortStats] {msg}")
        self._log_fn(f"[FTD] {msg}")

    def connect(self):
        try:
            import paramiko
        except ImportError:
            self._log("paramiko not installed")
            return False
        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._client.connect(
                self.host, port=self.port, username=self.username,
                password=self.password, timeout=10,
                look_for_keys=False, allow_agent=False,
            )
            shell = self._client.invoke_shell(width=511, height=2048)
            self._drain(shell, 2.0)  # eat CLISH banner

            # CLISH -> expert bash (stay as admin so 'clish' is in PATH)
            shell.send("expert\n")
            self._drain(shell, 3.0)

            # Clean prompt + disable echo for marker-based parsing
            shell.send("export PS1='FTDX> '; stty -echo 2>/dev/null\n")
            self._drain(shell, 1.0)

            # Verify bash
            shell.send("echo FTDREADY\n")
            verify = self._strip_ansi(self._drain(shell, 2.0))
            self._shell = shell
            if "FTDREADY" in verify:
                self._log("Expert bash ready")
            else:
                self._log(f"Bash verify warning: {repr(verify[:80])}")

            # Perfmon CSVs are root-owned; expert bash runs as admin.
            # Detect passwordless sudo so we can read them.
            sudo_test = self._exec("sudo -n id -u 2>&1", timeout=8)
            tail_line = (sudo_test or "").strip().split("\n")[-1].strip() if sudo_test else ""
            self._sudo = "sudo " if tail_line == "0" else ""
            self._log(f"sudo available: {bool(self._sudo)} ({repr((sudo_test or '')[:60])})")

            # Probe: find a working way to pipe commands into clish
            self._probe_stats_command()
            # Probe: locate Snort perfmon CSV that tracks alert counts
            self._probe_alert_source()
            return True
        except Exception as e:
            self._log(f"Connection failed: {e}")
            import traceback; traceback.print_exc()
            return False

    def _probe_stats_command(self):
        """Find a bash command that pipes 'show snort statistics' into clish."""
        candidates = [
            ('echo "show snort statistics" | clish',
             'echo "clear snort statistics" | clish'),
            ('printf "show snort statistics\\n" | clish',
             'printf "clear snort statistics\\n" | clish'),
            ('clish <<< "show snort statistics"',
             'clish <<< "clear snort statistics"'),
            ('echo "show snort statistics" | sudo clish',
             'echo "clear snort statistics" | sudo clish'),
        ]
        for show_cmd, clear_cmd in candidates:
            self._log(f"Probing: {show_cmd}")
            out = self._exec(show_cmd, timeout=15)
            if out and ("packet" in out.lower() or "snort" in out.lower() and "statistic" in out.lower()):
                self._stats_cmd = show_cmd
                self._clear_cmd = clear_cmd
                self._log(f"WORKS \u2014 stats via: {show_cmd} ({len(out)}c)")
                return
            else:
                self._log(f"  no data: {repr((out or '')[:100])}")
        self._log("WARNING: no working pipe-to-clish command found")

    def _probe_alert_source(self):
        """Locate Snort3 perfmon base CSVs and the 'detection.alerts' column.

        FTD runs one Snort instance per core, each writing its own
        perf_monitor_base.csv:
          /ngfw/var/sf/detection_engines/<UUID>/instance-N/perf_monitor_base.csv
        The 'detection.alerts' column counts events that triggered an
        IPS alert.  Alerts must be SUMMED across all instances.

        We glob (not hardcode the UUID), read one header to find the
        column index dynamically, then record a baseline for deltas.
        """
        try:
            # Enumerate with `find` (traverses as root) instead of a shell
            # glob, which fails to expand when the dirs aren't listable by
            # the calling shell.
            glob = ("/ngfw/var/sf/detection_engines/*/instance-*/"
                    "perf_monitor_base.csv")
            listing = self._exec(
                f'{self._sudo}find /ngfw/var/sf/detection_engines '
                f'-name perf_monitor_base.csv 2>&1', timeout=20)
            files = [l.strip() for l in (listing or "").split("\n")
                     if l.strip().endswith("perf_monitor_base.csv")]
            if not files:
                self._log(f"No perf_monitor_base.csv found \u2014 alerts n/a "
                           f"(find said: {repr((listing or '')[:160])})")
                return
            self._alert_glob = glob
            self._alert_files = files
            self._alert_arg = " ".join(f'"{f}"' for f in files)
            self._log(f"Found {len(files)} perfmon base file(s)")

            # Detect the detection.alerts column from one header
            header = self._exec(f'{self._sudo}head -1 "{files[0]}"', timeout=10)
            if not header or "," not in header:
                self._log(f"Could not read perfmon header: {repr((header or '')[:80])}")
                return
            cols = [c.strip().lstrip("#").strip() for c in header.split(",")]
            idx = None
            for want in ("detection.alerts", "detection.total_alerts"):
                if want in cols:
                    idx = cols.index(want)
                    break
            if idx is None:  # fallback: a detection.* alert col (not the limit)
                for i, c in enumerate(cols):
                    cl = c.lower()
                    if "detection" in cl and "alert" in cl and "limit" not in cl:
                        idx = i
                        break
            if idx is None:
                self._log("No detection.alerts column in perfmon header")
                return

            self._alert_col = idx

            # Detect cumulative (running total) vs per-interval (resets each
            # sample).  Inspect recent rows of one instance: a running total
            # is non-decreasing; per-interval values rise and fall.
            awk_col = idx + 1  # awk fields are 1-based
            sample = self._exec(
                f"{self._sudo}tail -n 20 \"{files[0]}\" | awk -F',' '{{print ${awk_col}}}'",
                timeout=10)
            vals = []
            for x in (sample or "").split("\n"):
                x = x.strip()
                try:
                    vals.append(int(float(x)))
                except ValueError:
                    pass
            # Per-interval if any row is smaller than a previous one
            self._alert_cumulative = not any(
                vals[i] > vals[i + 1] for i in range(len(vals) - 1))
            mode = "cumulative" if self._alert_cumulative else "per-interval"

            # Empirically measure the perfmon flush interval = gap between
            # the last two sample timestamps in one instance file.
            self._perf_interval = self._detect_interval()

            if self._alert_cumulative:
                self._alert_baseline = self._sum_last_rows() or 0
                self._log(f"Alert col[{idx}]='{cols[idx]}' mode={mode} "
                           f"{len(files)} instances baseline={self._alert_baseline} "
                           f"interval~{self._perf_interval}s")
            else:
                self._alert_since_ts = self._latest_timestamp() or 0
                self._log(f"Alert col[{idx}]='{cols[idx]}' mode={mode} "
                           f"{len(files)} instances since_ts={self._alert_since_ts} "
                           f"interval~{self._perf_interval}s")
        except Exception as e:
            self._log(f"alert probe failed: {e}")

    def _detect_interval(self):
        """Seconds between perfmon samples = diff of last two timestamps."""
        if not self._alert_files:
            return 0
        out = self._exec(f'{self._sudo}tail -n 3 "{self._alert_files[0]}" | cut -d"," -f1',
                         timeout=10)
        ts = []
        for x in (out or "").split("\n"):
            x = x.strip()
            try:
                ts.append(int(float(x)))
            except ValueError:
                pass
        return (ts[-1] - ts[-2]) if len(ts) >= 2 and ts[-1] > ts[-2] else 0

    def wait_for_flush(self, timeout=None):
        """After an attack, block until perfmon writes a NEW sample row so
        the final interval's alerts are captured on disk.  Returns True if
        a new row appeared, False on timeout / no source."""
        if not self._alert_arg or self._alert_col is None:
            return False
        # Allow ~1.5 sample intervals plus a small buffer (cap at 6 min)
        if timeout is None:
            timeout = min(int(self._perf_interval * 1.5) + 15, 360) \
                if self._perf_interval else 90
        start_latest = self._latest_timestamp()
        self._log(f"Waiting up to {timeout}s for perfmon flush "
                   f"(last sample ts={start_latest})...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(min(5, max(1, self._perf_interval // 4 or 5)))
            cur = self._latest_timestamp()
            if cur > start_latest:
                self._log(f"Perfmon flushed (new ts={cur})")
                return True
        self._log("Perfmon flush wait timed out — alert count may be partial")
        return False

    def reset_alert_baseline(self):
        """Re-mark the alert baseline/cutoff at the moment fuzzing starts,
        so get_alerts() counts only alerts generated during the attack."""
        if self._alert_col is None:
            return
        if self._alert_cumulative:
            self._alert_baseline = self._sum_last_rows() or 0
            self._log(f"Alert baseline reset = {self._alert_baseline}")
        else:
            self._alert_since_ts = self._latest_timestamp() or 0
            self._log(f"Alert cutoff reset = {self._alert_since_ts}")

    def _sum_last_rows(self):
        """Sum detection.alerts from the last row of each instance CSV."""
        out = self._exec(f'{self._sudo}tail -q -n1 {self._alert_arg} 2>/dev/null', timeout=12)
        if not out:
            return None
        total, got = 0, False
        for line in out.split("\n"):
            parts = line.split(",")
            if self._alert_col < len(parts):
                try:
                    total += int(float(parts[self._alert_col].strip()))
                    got = True
                except (ValueError, IndexError):
                    pass
        return total if got else None

    def _latest_timestamp(self):
        """Largest #timestamp (field 1) currently present across instances."""
        out = self._exec(f'{self._sudo}tail -q -n1 {self._alert_arg} 2>/dev/null', timeout=12)
        mx = 0
        for line in (out or "").split("\n"):
            parts = line.split(",")
            if parts:
                try:
                    mx = max(mx, int(float(parts[0].strip())))
                except (ValueError, IndexError):
                    pass
        return mx

    def get_alerts(self, absolute=False):
        """Return alert events caused by fuzzing.

        Cumulative mode:   current_total - baseline.
        Per-interval mode: sum of detection.alerts across ALL rows newer
                           than the baseline timestamp, over all instances.
        """
        if not self._alert_arg or self._alert_col is None:
            return None

        if not self._alert_cumulative:
            # Sum detection.alerts for rows with timestamp > cutoff (all files).
            awk_col = self._alert_col + 1  # 1-based
            t = 0 if absolute else self._alert_since_ts
            cmd = (f"{self._sudo}awk -F',' -v t={t} 'FNR>1 && ($1+0)>t "
                   f"{{s+=${awk_col}}} END{{print s+0}}' "
                   f"{self._alert_arg} 2>/dev/null")
            out = self._exec(cmd, timeout=15)
            if not out:
                return None
            try:
                return int(float(out.strip().split("\n")[-1].strip()))
            except (ValueError, IndexError):
                return None

        # Cumulative running total
        total = self._sum_last_rows()
        if total is None:
            return None
        return total if absolute else max(total - self._alert_baseline, 0)

    def _drain(self, shell, seconds=2.0):
        buf = ""
        deadline = time.time() + seconds
        while time.time() < deadline:
            time.sleep(0.1)
            if shell.recv_ready():
                buf += shell.recv(65535).decode("utf-8", errors="ignore")
        return buf

    @classmethod
    def _strip_ansi(cls, text):
        text = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', text)  # CSI
        text = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', text)  # OSC
        text = re.sub(r'\x1b[=>()#%][0-9A-Za-z]?', '', text)
        text = re.sub(r'\x1b[78DEHMc]', '', text)
        text = re.sub(r'\x1b.', '', text)
        text = ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)
        return text

    def _exec(self, cmd, timeout=15):
        """Run a bash command using echo start/end markers (100% reliable).
        Returns clean stdout between markers, or None on failure."""
        if not self._shell or self._shell.closed:
            return None
        try:
            ts = int(time.time() * 1000) % 999999
            marker_s = f"XSTART{ts}X"
            marker_e = f"XEND{ts}X"

            if self._shell.recv_ready():
                self._shell.recv(65535)

            # bash accepts \n; wrap the command between echo markers
            self._shell.send(f"echo {marker_s}; {cmd}; echo {marker_e}\n")

            output = ""
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.1)
                if self._shell.recv_ready():
                    output += self._shell.recv(65535).decode("utf-8", errors="ignore")
                    if marker_e in self._strip_ansi(output):
                        break

            clean = self._strip_ansi(output)
            if marker_e not in clean:
                self._log(f"exec timeout ({timeout}s) '{cmd[:40]}' \u2014 {len(clean)}c")
                return None

            # Extract text strictly between the two markers
            lines = clean.split("\n")
            result = []
            collecting = False
            for line in lines:
                s = line.strip()
                if marker_e in s:
                    break
                if collecting:
                    result.append(s)
                if marker_s in s:
                    collecting = True
            return "\n".join(result).strip()
        except Exception as e:
            self._log(f"exec failed: {e}")
            return None

    def get_stats(self):
        """Run the probed stats command and parse key counters.
        Returns dict: {passed, blocked, bypassed_down, bypassed_busy}."""
        if not self._stats_cmd:
            self._log("get_stats: no working stats command")
            return None

        raw = self._exec(self._stats_cmd, timeout=15)
        if not raw:
            self._log("get_stats: no output")
            return None

        stats = {}
        for line in raw.split("\n"):
            lo = line.strip().lower()
            if not lo:
                continue
            if "passed packets" in lo:
                stats["passed"] = self._parse_int(line)
            elif "blocked packets" in lo:
                stats["blocked"] = self._parse_int(line)
            elif "packets bypassed" in lo and "down" in lo:
                stats["bypassed_down"] = self._parse_int(line)
            elif "packets bypassed" in lo and "busy" in lo:
                stats["bypassed_busy"] = self._parse_int(line)

        if "passed" in stats or "blocked" in stats:
            passed = stats.get("passed", 0)
            # Alert events from perfmon CSV (delta since connect), if available
            alerts = self.get_alerts(absolute=False)
            if alerts is not None:
                stats["alerts"] = alerts
                # Truly clean = passed that neither blocked nor alerted
                stats["clean_passed"] = max(passed - alerts, 0)
            self._log(f"passed={passed} blocked={stats.get('blocked',0)} "
                       f"byp_down={stats.get('bypassed_down',0)} byp_busy={stats.get('bypassed_busy',0)}"
                       + (f" alerts={alerts} clean_passed={stats['clean_passed']}"
                          if alerts is not None else " (alerts: n/a)"))
        else:
            lines = [l.strip() for l in raw.split("\n") if l.strip()]
            preview = " | ".join(lines[:6])
            self._log(f"Parse fail ({len(raw)}c): {preview[:200]}")
        return stats if ("passed" in stats or "blocked" in stats) else None

    def clear_stats(self):
        if self._clear_cmd:
            self._exec(self._clear_cmd, timeout=15)
            self._log("clear_stats done")
        else:
            self._log("clear_stats skipped (no command)")

    @staticmethod
    def _parse_int(line):
        m = re.search(r'(\d+)\s*$', line.strip())
        return int(m.group(1)) if m else 0

    def close(self):
        if self._shell:
            try:
                self._shell.close()
            except Exception:
                pass
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass


def _find_snort_log():
    """Return the first readable Snort alert log path, or None."""
    for p in _SNORT_LOG_PATHS:
        if os.path.exists(p):
            return p
    return None


def _count_alerts(log_path, pattern=None):
    """Count lines matching pattern in Snort alert log (fast, via grep/wc)."""
    if not log_path or not os.path.exists(log_path):
        return 0
    try:
        if pattern is None:
            r = _subprocess.run(["wc", "-l", log_path],
                                capture_output=True, text=True, timeout=3)
            return int(r.stdout.strip().split()[0]) if r.returncode == 0 else 0
        else:
            r = _subprocess.run(["grep", "-c", "-F", pattern, log_path],
                                capture_output=True, text=True, timeout=3)
            return int(r.stdout.strip()) if r.returncode == 0 else 0
    except Exception:
        return 0


def _count_canary_alerts(log_path):
    """Count Snort alert lines matching any canary SID (fast, via grep)."""
    if not log_path or not os.path.exists(log_path):
        return 0
    try:
        # grep -c with alternation for all canary SIDs
        pattern = r"\|".join(_CANARY_SIDS)
        r = _subprocess.run(["grep", "-c", pattern, log_path],
                            capture_output=True, text=True, timeout=3)
        return int(r.stdout.strip()) if r.returncode == 0 else 0
    except Exception:
        return 0


def _clear_snort_log(log_path):
    """Truncate the Snort alert log for a clean test."""
    if log_path and os.path.exists(log_path):
        try:
            with open(log_path, "w") as f:
                f.truncate(0)
        except Exception:
            pass


def _send_canary(target_ip, port=80):
    """Send a UDP packet containing the EICAR canary string that Snort rule
    SID 1000006 must match.  UDP is fire-and-forget — never blocks."""
    import socket as _sock
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.sendto(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!", (target_ip, port))
        s.close()
        return True
    except Exception:
        return False


multiattack_state = {
    "running": False,
    "stop_requested": False,
    "config": {},
    "start_time": None,
    "elapsed": 0,
    "pps": 0,
    "mbps": 0,
    "total_packets": 0,
    "total_bytes": 0,
    "per_proto": {},
    "errors": {},
    "canary_sent": 0,
    "canary_detected": 0,
    "snort_alerts": 0,
    "detection_rate": 100.0,
    "verdict": "IDLE",
    "log": [],
    "active_protos": 0,
}

_multiattack_thread = None
_multiattack_procs = []


def _multiattack_log(msg):
    multiattack_state["log"].append({
        "time": time.strftime("%H:%M:%S"),
        "msg": msg
    })
    if len(multiattack_state["log"]) > 200:
        multiattack_state["log"] = multiattack_state["log"][-200:]
    print(f"[MULTI-ATTACK] {msg}")


def _multiattack_worker(target_ip, protocols, duration, intensity, processes, ftd_config=None):
    """
    Pure live-network flood.  Spawns snort_blinder.py --flood sub-processes
    locally.  Packets are sent directly from this machine to <target_ip>
    via real sockets — no Docker orchestration needed.
    ftd_config: optional dict {host, port, username, password} for SSH-based
    Snort monitoring on FTD (replaces Docker alert_fast.txt approach).
    """
    global _multiattack_procs
    try:
        multiattack_state["running"] = True
        multiattack_state["stop_requested"] = False
        multiattack_state["start_time"] = time.time()
        multiattack_state["log"] = []
        multiattack_state["verdict"] = "WARMING"
        multiattack_state["total_packets"] = 0
        multiattack_state["total_bytes"] = 0
        multiattack_state["per_proto"] = {}
        multiattack_state["errors"] = {}
        multiattack_state["canary_sent"] = 0
        multiattack_state["canary_detected"] = 0
        multiattack_state["snort_alerts"] = 0
        multiattack_state["detection_rate"] = 100.0

        _multiattack_log(f"Target: {target_ip}")
        _multiattack_log(f"Protocols: {', '.join(p.upper() for p in protocols)}")

        # --- Snort monitoring: FTD SSH or Docker file-based ---
        ftd_monitor = None
        snort_log = None
        snort_available = False
        use_ftd_ssh = False

        if ftd_config:
            _multiattack_log(f"Connecting to FTD {ftd_config['host']}:{ftd_config.get('port', 22)} via SSH...")
            ftd_monitor = FtdSnortStats(
                host=ftd_config["host"],
                port=ftd_config.get("port", 22),
                username=ftd_config.get("username", "admin"),
                password=ftd_config.get("password", ""),
                log_fn=_multiattack_log,
            )
            if ftd_monitor.connect():
                use_ftd_ssh = True
                snort_available = True
                _multiattack_log("FTD SSH connected — clearing Snort statistics...")
                ftd_monitor.clear_stats()
                ftd_monitor.reset_alert_baseline()  # mark alert cutoff at attack start
                time.sleep(1)
                baseline = ftd_monitor.get_stats()
                if baseline:
                    _multiattack_log(f"Snort baseline: passed={baseline.get('passed',0)}, blocked={baseline.get('blocked',0)}")
                else:
                    _multiattack_log("Warning: could not read baseline Snort stats")
            else:
                _multiattack_log("FTD SSH failed — falling back to file-based detection")
                ftd_monitor = None

        if not use_ftd_ssh:
            snort_log = _find_snort_log()
            snort_available = snort_log is not None
            if snort_available:
                _multiattack_log(f"Snort alert log found: {snort_log}")
                _clear_snort_log(snort_log)
            else:
                _multiattack_log("No Snort monitoring available — verdict will be throughput-only")

        # Quick connectivity check
        import socket as _socket
        _multiattack_log("Testing connectivity...")
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(b"\x00", (target_ip, 53))
            s.close()
            _multiattack_log(f"Target {target_ip} reachable")
        except Exception as e:
            _multiattack_log(f"Warning: connectivity probe ({e}) — continuing anyway")

        # Canary pre-test (file-based only — FTD doesn't have canary rules)
        if snort_available and not use_ftd_ssh:
            _multiattack_log("Sending canary probe (EICAR via UDP+TCP)...")
            pre_alerts = _count_canary_alerts(snort_log)
            _send_canary(target_ip)
            time.sleep(2)
            post_alerts = _count_canary_alerts(snort_log)
            if post_alerts > pre_alerts:
                _multiattack_log(f"Canary DETECTED by Snort ({post_alerts - pre_alerts} alerts)")
            else:
                _multiattack_log("Canary NOT detected — Snort may not be running or rule missing")
            _clear_snort_log(snort_log)

        # Clean old stats files
        _subprocess.run(["bash", "-c", "rm -f /tmp/blinder_stats_*.json"],
                        capture_output=True, timeout=5)

        # Build process groups — distribute protocols across N processes
        preset = _BLINDER_INTENSITY.get(intensity, _BLINDER_INTENSITY[1])
        n_procs = processes

        if n_procs <= len(protocols):
            proto_groups = [[] for _ in range(n_procs)]
            for i, p in enumerate(protocols):
                proto_groups[i % n_procs].append(p)
        else:
            base_n = min(n_procs, len(protocols))
            proto_groups = [[] for _ in range(base_n)]
            for i, p in enumerate(protocols):
                proto_groups[i % base_n].append(p)
            base_groups = list(proto_groups)
            while len(proto_groups) < n_procs:
                proto_groups.append(list(base_groups[len(proto_groups) % len(base_groups)]))

        # Estimate total thread count
        total_workers = 0
        for g in proto_groups:
            for p in g:
                t = _BLINDER_PROTOCOL_REGISTRY[p][0]
                if t == "udp":
                    total_workers += preset["udp"]
                elif t == "tcp":
                    total_workers += preset["tcp"]
                else:
                    total_workers += 1

        _multiattack_log(f"Intensity {intensity} [{preset['label']}] — "
                         f"UDP: {preset['udp']} threads/proto, TCP: {preset['tcp']} conns/proto")
        _multiattack_log(f"Launching {len(proto_groups)} processes (~{total_workers} workers)")

        # Resolve script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Fraction of flood payloads that carry the detection string (EICAR
        # content) so IPS alerts scale with packet volume.  Set 0 to disable.
        inject_rate = 0.1

        # Launch flood sub-processes directly on this machine
        stats_files = []
        _multiattack_procs = []
        for gi, group in enumerate(proto_groups):
            sf = f"/tmp/blinder_stats_{gi}.json"
            stats_files.append(sf)
            proto_list = ",".join(group)
            flood_cmd = (
                f"cd {script_dir} && python3 Testing/snort_blinder.py "
                f"--flood --target {target_ip} --duration {duration} "
                f"--phase-duration 15 --intensity {intensity} "
                f"--protocols {proto_list} --stats-file {sf} "
                f"--inject-rate {inject_rate}"
            )
            proc = _subprocess.Popen(
                ["bash", "-c", flood_cmd],
                stdout=_subprocess.PIPE, stderr=_subprocess.STDOUT, text=True
            )
            _multiattack_procs.append(proc)

        _multiattack_log(f"All {len(proto_groups)} flood processes launched — firing at {target_ip}")

        # Canary tracking — sent from app.py directly, not from snort_blinder
        _canary_sent = 0
        _canary_interval = 5  # seconds between canary probes
        _last_canary_time = 0

        # Monitor loop — read stats directly from local /tmp/ files
        def _aggregate():
            agg = {"elapsed": 0, "pps": 0, "mbps": 0, "per_proto": {},
                   "canary_sent": 0, "total_packets": 0, "total_bytes": 0, "errors": {}}
            for sf in stats_files:
                try:
                    with open(sf, "r") as fh:
                        s = json.load(fh)
                    agg["total_packets"] += s.get("total_packets", 0)
                    agg["total_bytes"] += s.get("total_bytes", 0)
                    agg["canary_sent"] += s.get("canary_sent", 0)
                    agg["elapsed"] = max(agg["elapsed"], s.get("elapsed", 0))
                    for p, c in s.get("per_proto", {}).items():
                        agg["per_proto"][p] = agg["per_proto"].get(p, 0) + c
                    for p, c in s.get("errors", {}).items():
                        agg["errors"][p] = agg["errors"].get(p, 0) + c
                except Exception:
                    continue
            el = max(agg["elapsed"], 1)
            agg["pps"] = round(agg["total_packets"] / el)
            agg["mbps"] = round((agg["total_bytes"] * 8) / (el * 1_000_000), 2)
            return agg

        while any(p.poll() is None for p in _multiattack_procs):
            if multiattack_state["stop_requested"]:
                _multiattack_log("Stop requested — terminating flood processes")
                for p in _multiattack_procs:
                    p.terminate()
                break

            snap = _aggregate()
            pps = snap.get("pps", 0)

            # --- Snort health check ---
            alerts = 0
            canary_detected = 0
            canary_sent = _canary_sent
            det_rate = 0.0
            verdict = "WARMING" if pps == 0 else "FLOODING"
            ftd_stats_snap = None

            if use_ftd_ssh and ftd_monitor:
                ftd_stats_snap = ftd_monitor.get_stats()
                if ftd_stats_snap:
                    passed = ftd_stats_snap.get("passed", 0)
                    blocked = ftd_stats_snap.get("blocked", 0)
                    bypassed_down = ftd_stats_snap.get("bypassed_down", 0)
                    bypassed_busy = ftd_stats_snap.get("bypassed_busy", 0)
                    total_inspected = passed + blocked
                    total_traffic = total_inspected + bypassed_down + bypassed_busy
                    alerts = blocked

                    if total_traffic == 0:
                        verdict = "WARMING"
                    elif bypassed_down > 0:
                        verdict = "BLINDED"
                    elif bypassed_busy > 0 and bypassed_busy > total_inspected * 0.3:
                        verdict = "DEGRADED"
                    elif total_inspected > 0:
                        verdict = "DETECTING"
                    else:
                        verdict = "WARMING"

                    det_rate = round(total_inspected / max(total_traffic, 1) * 100, 2)
            elif snort_available and not use_ftd_ssh:
                now = time.time()
                if (now - _last_canary_time) >= _canary_interval:
                    if _send_canary(target_ip):
                        _canary_sent += 1
                    _last_canary_time = now
                canary_sent = _canary_sent
                alerts = _count_alerts(snort_log, "[**]")
                canary_detected = _count_canary_alerts(snort_log)
                det_rate = min(round(canary_detected / canary_sent * 100, 1), 100.0) if canary_sent > 0 else 100.0
                if canary_sent < 2:
                    verdict = "WARMING"
                elif det_rate >= 80:
                    verdict = "DETECTING"
                elif det_rate >= 30:
                    verdict = "DEGRADED"
                else:
                    verdict = "BLINDED"

            update = {
                "elapsed": round(time.time() - multiattack_state["start_time"]),
                "pps": pps,
                "mbps": snap.get("mbps", 0),
                "total_packets": snap.get("total_packets", 0),
                "total_bytes": snap.get("total_bytes", 0),
                "per_proto": snap.get("per_proto", {}),
                "errors": snap.get("errors", {}),
                "canary_sent": canary_sent,
                "canary_detected": canary_detected,
                "snort_alerts": alerts,
                "detection_rate": det_rate,
                "verdict": verdict,
                "active_protos": len([p for p, c in snap.get("per_proto", {}).items() if c > 0]),
            }
            if ftd_stats_snap:
                update["ftd_stats"] = ftd_stats_snap
            multiattack_state.update(update)

            time.sleep(1 if use_ftd_ssh else 2)

        # Final stats
        for p in _multiattack_procs:
            try:
                p.wait(timeout=10)
            except Exception:
                p.kill()

        snap = _aggregate()
        canary_sent = _canary_sent
        canary_detected = 0
        final_stats = None

        # --- Final verdict ---
        if use_ftd_ssh and ftd_monitor:
            # Wait for perfmon to flush so the final interval's alerts land on
            # disk before we read them (perfmon writes on a fixed interval).
            _multiattack_log("Waiting for Snort perfmon to flush final alerts...")
            ftd_monitor.wait_for_flush()
            final_stats = ftd_monitor.get_stats()
            if final_stats:
                passed = final_stats.get("passed", 0)
                blocked = final_stats.get("blocked", 0)
                bypassed_down = final_stats.get("bypassed_down", 0)
                bypassed_busy = final_stats.get("bypassed_busy", 0)
                total_inspected = passed + blocked
                total_traffic = total_inspected + bypassed_down + bypassed_busy
                alerts = blocked  # drop-action only; alert-only rules counted in passed
                fuzz_alerts = final_stats.get("alerts")  # alert events during attack
                clean_passed = final_stats.get("clean_passed")
                if fuzz_alerts is not None:
                    _multiattack_log(f"Snort alert events from fuzzing: {fuzz_alerts:,} "
                                     f"| clean passed (no block, no alert): "
                                     f"{(clean_passed if clean_passed is not None else passed):,}")
                det_rate = round(total_inspected / max(total_traffic, 1) * 100, 2)

                if bypassed_down > 0:
                    verdict = "BLINDED"
                elif bypassed_busy > 0 and bypassed_busy > total_inspected * 0.3:
                    verdict = "DEGRADED"
                elif total_inspected > 0:
                    verdict = "WITHSTOOD"
                else:
                    verdict = "NO DATA"

                _multiattack_log(f"FTD Final: passed={passed:,}, blocked={blocked:,}, "
                                 f"bypassed_down={bypassed_down}, bypassed_busy={bypassed_busy}")
            else:
                alerts = 0
                det_rate = 0.0
                verdict = "COMPLETE"
        elif snort_available:
            alerts = _count_alerts(snort_log, "[**]")
            canary_detected = _count_canary_alerts(snort_log)
            det_rate = min(round(canary_detected / canary_sent * 100, 1), 100.0) if canary_sent > 0 else 100.0
            if canary_sent == 0:
                verdict = "NO DATA"
            elif det_rate >= 80:
                verdict = "WITHSTOOD"
            elif det_rate >= 30:
                verdict = "DEGRADED"
            else:
                verdict = "BLINDED"
        else:
            alerts = 0
            canary_detected = 0
            det_rate = 0.0
            verdict = "COMPLETE"

        final_update = {
            "elapsed": round(time.time() - multiattack_state["start_time"]),
            "pps": snap.get("pps", 0),
            "mbps": snap.get("mbps", 0),
            "total_packets": snap.get("total_packets", 0),
            "total_bytes": snap.get("total_bytes", 0),
            "per_proto": snap.get("per_proto", {}),
            "errors": snap.get("errors", {}),
            "canary_sent": canary_sent,
            "canary_detected": canary_detected,
            "snort_alerts": alerts,
            "detection_rate": det_rate,
            "verdict": verdict,
            "active_protos": len([p for p, c in snap.get("per_proto", {}).items() if c > 0]),
        }
        if use_ftd_ssh and final_stats:
            final_update["ftd_stats"] = final_stats
        multiattack_state.update(final_update)
        _multiattack_log(f"FINISHED — {verdict} | {snap.get('total_packets',0):,} pkts, "
                         f"{snap.get('pps',0):,} pps | Snort blocked: {alerts}, "
                         f"detection rate: {det_rate}%")

    except Exception as e:
        _multiattack_log(f"Error: {e}")
        multiattack_state["verdict"] = "ERROR"
        traceback.print_exc()
    finally:
        if ftd_monitor:
            try:
                ftd_monitor.close()
            except Exception:
                pass
        multiattack_state["running"] = False
        _multiattack_procs = []


@app.route("/api/multiattack/protocols", methods=["GET"])
def api_multiattack_protocols():
    protos = []
    for name, (transport, port) in sorted(_BLINDER_PROTOCOL_REGISTRY.items()):
        protos.append({"name": name, "transport": transport, "port": port})
    return jsonify({"protocols": protos})


@app.route("/api/multiattack/start", methods=["POST"])
def api_multiattack_start():
    global _multiattack_thread
    if multiattack_state["running"]:
        return jsonify({"error": "Attack already running"}), 400

    body = request.json or {}
    target_ip = body.get("target_ip", "").strip()
    if not target_ip:
        return jsonify({"error": "Target IP is required"}), 400

    protocols = body.get("protocols", list(_BLINDER_PROTOCOL_REGISTRY.keys()))
    duration = body.get("duration", 60)
    intensity = body.get("intensity", 3)
    processes = body.get("processes", 6)
    ftd_config = body.get("ftd_config", None)  # {host, port, username, password}

    # Validate
    valid_protos = [p for p in protocols if p in _BLINDER_PROTOCOL_REGISTRY]
    if not valid_protos:
        return jsonify({"error": "No valid protocols selected"}), 400
    if intensity < 1 or intensity > 5:
        intensity = 3
    if processes < 1 or processes > 50:
        processes = 6
    if duration < 10 or duration > 600:
        duration = 60

    multiattack_state["config"] = {
        "target_ip": target_ip,
        "protocols": valid_protos,
        "duration": duration,
        "intensity": intensity,
        "processes": processes,
    }

    # Set state immediately so the UI knows we're starting
    multiattack_state["running"] = True
    multiattack_state["verdict"] = "WARMING"
    multiattack_state["elapsed"] = 0
    multiattack_state["total_packets"] = 0
    multiattack_state["pps"] = 0
    multiattack_state["log"] = []

    _multiattack_thread = threading.Thread(
        target=_multiattack_worker,
        args=(target_ip, valid_protos, duration, intensity, processes, ftd_config),
        daemon=True
    )
    _multiattack_thread.start()
    return jsonify({"status": "started", "config": multiattack_state["config"]})


@app.route("/api/multiattack/stop", methods=["POST"])
def api_multiattack_stop():
    if not multiattack_state["running"]:
        return jsonify({"error": "No attack running"}), 400
    multiattack_state["stop_requested"] = True
    return jsonify({"status": "stopping"})


@app.route("/api/multiattack/status", methods=["GET"])
def api_multiattack_status():
    return jsonify(multiattack_state)


if __name__ == "__main__":
    if not AZURE_OPENAI_API_KEY:
        print("[!] WARNING: AZURE_OPENAI_API_KEY not set in .env")
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port, threaded=True)

