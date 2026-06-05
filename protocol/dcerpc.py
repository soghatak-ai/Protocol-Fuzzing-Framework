import struct
import random
import os
from protocol.dynamic_data import get_commands, random_buffer_size, has_dynamic_data

# ---------------------------------------------------------------------------
# DCE/RPC mutation strategies for Snort 3's `dce_smb` / `dce_tcp` / `dce_udp`
# service inspectors.
#
# Design (grounded in the DCE 1.1 RPC specification (Open Group C706),
# MS-RPCE, RFC 5531 (ONC RPC v2), and Snort 3 dce2 inspector internals):
#
# Snort's DCE/RPC inspector (dce2) handles three transports:
#   * dce_tcp  — Connection-Oriented (CO) DCE/RPC over raw TCP (port 135)
#   * dce_udp  — Connectionless (CL) DCE/RPC over UDP (port 135)
#   * dce_smb  — DCE/RPC over SMB named pipes (port 445)
#
# The CO protocol uses a fixed 16-byte PDU header:
#   rpc_vers(1) | rpc_vers_minor(1) | PTYPE(1) | pfc_flags(1) |
#   packed_drep[4] | frag_length(2) | auth_length(2) | call_id(4)
#
# Key inspection surfaces:
#   * PDU header parsing — version, PTYPE dispatch, frag_length validation
#   * Fragmentation/reassembly — PFC_FIRST_FRAG / PFC_LAST_FRAG flags
#   * BIND / ALTER_CONTEXT — p_context_elem_t arrays, transfer syntax UUIDs
#   * Stub data extraction — opnum dispatch, NDR format parsing
#   * Authentication — auth_verifier parsing (auth_type, auth_level, auth_pad)
#   * CL header — 80-byte fixed header with activity UUID, server_boot, ahint
#
# Every payload begins with a valid DCE/RPC connection preface (BIND) so
# Snort classifies the stream as DCE/RPC and engages the inspector BEFORE
# it reaches the malicious frames.
#
# All strategies are client->server and are delivered with
# StreamTransport.wrap_tcp_session (pipe mode) or
# LiveNetworkTransport.send_tcp(port=135) (live mode).
# ---------------------------------------------------------------------------

DCERPC_STRATEGIES = [
    "bind_flood",
    "frag_reassembly_attack",
    "ptype_confusion",
    "auth_verifier_overflow",
    "context_negotiation_abuse",
    "stub_data_overflow",
    "alter_context_race",
    "cl_header_manipulation",
    "endian_drep_confusion",
    "opnum_dispatch_fuzz",
    "cancel_orphan_attack",
    "record_marking_desync",
    "multi_bind_ack_confusion",
    "uuid_manipulation",
]

# Base weights (raw; normalised downstream). The deepest / highest-yield
# parser surfaces (fragmentation, bind/context, stub data, auth) get the
# most mass; edge-case strategies get less.
DCERPC_WEIGHTS = [
    12, 14, 8, 10, 10, 12, 6, 7, 5, 10, 4, 8, 6, 7,
]

DCERPC_STRATEGY_LABELS = {
    "bind_flood":                  "BIND Flood",
    "frag_reassembly_attack":      "Fragment Reassembly Attack",
    "ptype_confusion":             "PTYPE Confusion",
    "auth_verifier_overflow":      "Auth Verifier Overflow",
    "context_negotiation_abuse":   "Context Negotiation Abuse",
    "stub_data_overflow":          "Stub Data Overflow",
    "alter_context_race":          "ALTER_CONTEXT Race",
    "cl_header_manipulation":      "CL Header Manipulation",
    "endian_drep_confusion":       "Endian/DREP Confusion",
    "opnum_dispatch_fuzz":         "Opnum Dispatch Fuzz",
    "cancel_orphan_attack":        "Cancel/Orphan Attack",
    "record_marking_desync":       "Record Marking Desync",
    "multi_bind_ack_confusion":    "Multi-BIND_ACK Confusion",
    "uuid_manipulation":           "UUID Manipulation",
}


# ===== DCE/RPC binary constants ==============================================

# CO protocol versions
_RPC_VERS = 5
_RPC_VERS_MINOR = 0

# PDU types (PTYPE) — Connection-Oriented
_PTYPE_REQUEST        = 0
_PTYPE_PING           = 1
_PTYPE_RESPONSE       = 2
_PTYPE_FAULT          = 3
_PTYPE_WORKING        = 4
_PTYPE_NOCALL         = 5
_PTYPE_REJECT         = 6
_PTYPE_ACK            = 7
_PTYPE_CL_CANCEL      = 8
_PTYPE_FACK           = 9
_PTYPE_CANCEL_ACK     = 10
_PTYPE_BIND           = 11
_PTYPE_BIND_ACK       = 12
_PTYPE_BIND_NAK       = 13
_PTYPE_ALTER_CONTEXT   = 14
_PTYPE_ALTER_CONTEXT_RESP = 15
_PTYPE_AUTH3          = 16
_PTYPE_SHUTDOWN       = 17
_PTYPE_CO_CANCEL      = 18
_PTYPE_ORPHANED       = 19

# PFC flags
_PFC_FIRST_FRAG  = 0x01
_PFC_LAST_FRAG   = 0x02
_PFC_PENDING_CANCEL = 0x04
_PFC_CONC_MPX    = 0x10
_PFC_DID_NOT_EXECUTE = 0x20
_PFC_MAYBE       = 0x40
_PFC_OBJECT_UUID = 0x80

# Data representation (little-endian, ASCII, IEEE float)
_DREP_LE = b'\x10\x00\x00\x00'
_DREP_BE = b'\x00\x00\x00\x00'

# Well-known UUIDs
_UUID_NDR = bytes.fromhex('045d888aeb1cc9119fe808002b104860')    # NDR transfer syntax
_UUID_NDR64 = bytes.fromhex('33057145f2bc0211b79be211aea43ee0')  # NDR64
_UUID_EPMAPPER = bytes.fromhex('e1af8308555d11c9a0eb08002b2e09fb')  # EPM
_UUID_SRVSVC = bytes.fromhex('c84f324b70160d30ab6d00c04fd20d32')    # srvsvc
_UUID_SAMR = bytes.fromhex('787a44d280cf6611a3270000f8084f08')     # SAMR
_UUID_NULL = b'\x00' * 16


# ===== Helper functions ======================================================

def _co_header(ptype: int, frag_length: int, call_id: int = 1,
               flags: int = _PFC_FIRST_FRAG | _PFC_LAST_FRAG,
               auth_length: int = 0, drep: bytes = _DREP_LE) -> bytes:
    """Build a 16-byte CO PDU header."""
    return struct.pack('<BBBB4sHHI',
                       _RPC_VERS, _RPC_VERS_MINOR, ptype, flags,
                       drep, frag_length, auth_length, call_id)


def _bind_pdu(contexts: list = None, call_id: int = 1,
              max_xmit: int = 4280, max_recv: int = 4280) -> bytes:
    """Build a BIND PDU with one or more p_context_elem_t entries.
    Each context is (context_id, abstract_syntax_uuid, abstract_syntax_ver,
                     transfer_syntax_uuid, transfer_syntax_ver).
    """
    if contexts is None:
        contexts = [(0, _UUID_EPMAPPER, 3, _UUID_NDR, 2)]

    # BIND body: max_xmit(2) + max_recv(2) + assoc_group(4) +
    #            num_ctx(1) + padding(3) + context elements
    num_ctx = len(contexts)
    body = struct.pack('<HHI', max_xmit, max_recv, 0)
    body += struct.pack('<BBH', num_ctx, 0, 0)  # p_context_list_t header

    for ctx_id, abs_uuid, abs_ver, xfer_uuid, xfer_ver in contexts:
        # p_context_elem_t: context_id(2) + num_transfer(1) + reserved(1)
        #                    + abstract_syntax(20) + transfer_syntax(20)
        body += struct.pack('<HBB', ctx_id, 1, 0)
        body += abs_uuid + struct.pack('<I', abs_ver)  # abstract syntax
        body += xfer_uuid + struct.pack('<I', xfer_ver)  # transfer syntax

    frag_len = 16 + len(body)
    hdr = _co_header(_PTYPE_BIND, frag_len, call_id=call_id)
    return hdr + body


def _request_pdu(stub_data: bytes, opnum: int = 0, call_id: int = 1,
                 context_id: int = 0, flags: int = _PFC_FIRST_FRAG | _PFC_LAST_FRAG,
                 object_uuid: bytes = None) -> bytes:
    """Build a REQUEST PDU with the given stub data."""
    # REQUEST body: alloc_hint(4) + context_id(2) + opnum(2) [+ object(16)]
    body = struct.pack('<IHH', len(stub_data), context_id, opnum)
    if object_uuid:
        flags |= _PFC_OBJECT_UUID
        body += object_uuid
    body += stub_data

    frag_len = 16 + len(body)
    hdr = _co_header(_PTYPE_REQUEST, frag_len, call_id=call_id, flags=flags)
    return hdr + body


def _alter_context_pdu(ctx_id: int = 0, abs_uuid: bytes = None,
                       abs_ver: int = 3, call_id: int = 2) -> bytes:
    """Build an ALTER_CONTEXT PDU."""
    if abs_uuid is None:
        abs_uuid = _UUID_SRVSVC
    contexts = [(ctx_id, abs_uuid, abs_ver, _UUID_NDR, 2)]
    num_ctx = 1
    body = struct.pack('<HHI', 4280, 4280, 0)
    body += struct.pack('<BBH', num_ctx, 0, 0)
    body += struct.pack('<HBB', ctx_id, 1, 0)
    body += abs_uuid + struct.pack('<I', abs_ver)
    body += _UUID_NDR + struct.pack('<I', 2)
    frag_len = 16 + len(body)
    hdr = _co_header(_PTYPE_ALTER_CONTEXT, frag_len, call_id=call_id)
    return hdr + body


def _auth3_pdu(auth_blob: bytes, call_id: int = 1) -> bytes:
    """Build an AUTH3 PDU carrying an auth_verifier blob."""
    # AUTH3 body is just padding(4) + auth_verifier
    # auth_verifier: auth_type(1) + auth_level(1) + auth_pad(1) +
    #                auth_reserved(1) + auth_context_id(4) + credentials
    auth_type = 0x0A  # NTLMSSP
    auth_level = 0x02  # connect
    verifier = struct.pack('<BBBI', auth_type, auth_level, 0, 0)
    verifier += auth_blob
    body = struct.pack('<I', 0)  # pad
    body += verifier
    auth_length = len(auth_blob)
    frag_len = 16 + len(body)
    hdr = _co_header(_PTYPE_AUTH3, frag_len, call_id=call_id, auth_length=auth_length)
    return hdr + body


def _co_cancel_pdu(call_id: int = 1) -> bytes:
    """Build a CO_CANCEL PDU."""
    # CO_CANCEL has no body beyond the header + optional auth verifier
    frag_len = 16
    hdr = _co_header(_PTYPE_CO_CANCEL, frag_len, call_id=call_id,
                     flags=0)
    return hdr


def _orphaned_pdu(call_id: int = 1) -> bytes:
    """Build an ORPHANED PDU."""
    frag_len = 16
    hdr = _co_header(_PTYPE_ORPHANED, frag_len, call_id=call_id,
                     flags=0)
    return hdr


def _cl_header(ptype: int = 0, activity: bytes = None,
               frag_num: int = 0, serial_hi: int = 0, serial_lo: int = 0,
               server_boot: int = 0, if_uuid: bytes = None,
               if_ver: int = 0, opnum: int = 0, ahint: int = 0xFFFF,
               drep: bytes = _DREP_LE) -> bytes:
    """Build an 80-byte CL (connectionless) PDU header."""
    if activity is None:
        activity = os.urandom(16)
    if if_uuid is None:
        if_uuid = _UUID_EPMAPPER

    # CL header layout (80 bytes):
    # rpc_vers(1) | ptype(1) | flags1(1) | flags2(1) |
    # drep[3] | serial_hi(1) | object_uuid(16) | if_uuid(16) |
    # activity(16) | server_boot(4) | if_ver(4) | seqnum(4) |
    # opnum(2) | ihint(2) | ahint(2) | frag_len(2) | frag_num(2) |
    # auth_proto(1) | serial_lo(1)
    hdr = struct.pack('<BBBB',
                      4,           # rpc_vers (CL is version 4)
                      ptype, 0, 0)
    hdr += drep[:3] + struct.pack('B', serial_hi)
    hdr += _UUID_NULL       # object UUID
    hdr += if_uuid          # interface UUID
    hdr += activity         # activity UUID
    hdr += struct.pack('<I', server_boot)
    hdr += struct.pack('<I', if_ver)
    hdr += struct.pack('<I', 1)       # sequence number
    hdr += struct.pack('<HHH', opnum, 0xFFFF, ahint)
    hdr += struct.pack('<HH', 0, frag_num)  # frag_len filled later, frag_num
    hdr += struct.pack('BB', 0, serial_lo)
    return hdr


def _tcp_record_mark(data: bytes, last: bool = True) -> bytes:
    """Build an ONC RPC Record Marking header (RFC 5531 §11)."""
    length = len(data)
    flag = 0x80000000 if last else 0
    return struct.pack('>I', flag | (length & 0x7FFFFFFF)) + data


# ===== Strategy payload builders =============================================

def build_dcerpc_payload(strategy: str) -> bytes:
    """Return raw bytes for the given DCE/RPC fuzzing strategy."""

    # ── bind_flood ──────────────────────────────────────────────────────
    if strategy == "bind_flood":
        variant = random.choice([
            "many_contexts", "huge_context_list", "max_xmit_overflow",
            "rapid_rebind", "nested_bind", "zero_context"
        ])

        if variant == "many_contexts":
            # 200+ context elements in a single BIND — exhausts context table
            contexts = []
            for i in range(200):
                uuid = os.urandom(16)
                contexts.append((i & 0xFFFF, uuid, random.randint(0, 0xFFFF),
                                 _UUID_NDR, 2))
            return _bind_pdu(contexts, max_xmit=0xFFFF, max_recv=0xFFFF)

        elif variant == "huge_context_list":
            # Single context with oversized abstract syntax UUID area
            body = struct.pack('<HHI', 4280, 4280, 0)
            body += struct.pack('<BBH', 1, 0, 0)
            body += struct.pack('<HBB', 0, 50, 0)  # 50 transfer syntaxes
            body += _UUID_EPMAPPER + struct.pack('<I', 3)
            for _ in range(50):
                body += os.urandom(16) + struct.pack('<I', random.randint(0, 0xFFFF))
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_BIND, frag_len, call_id=1)
            return hdr + body

        elif variant == "max_xmit_overflow":
            # BIND with max_xmit_frag = 0xFFFF and max_recv_frag = 0
            return _bind_pdu(max_xmit=0xFFFF, max_recv=0)

        elif variant == "rapid_rebind":
            # 100 sequential BINDs with different call_ids
            frames = b""
            for i in range(100):
                frames += _bind_pdu(call_id=i + 1)
            return frames

        elif variant == "nested_bind":
            # BIND with abstract syntax pointing to itself (circular)
            contexts = [(0, _UUID_NDR, 2, _UUID_NDR, 2)]
            frames = _bind_pdu(contexts)
            frames += _bind_pdu(contexts, call_id=2)
            frames += _alter_context_pdu(ctx_id=0, abs_uuid=_UUID_NDR, abs_ver=2, call_id=3)
            return frames

        else:  # zero_context
            # BIND with 0 context elements
            body = struct.pack('<HHI', 4280, 4280, 0)
            body += struct.pack('<BBH', 0, 0, 0)  # num_ctx = 0
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_BIND, frag_len, call_id=1)
            return hdr + body

    # ── frag_reassembly_attack ──────────────────────────────────────────
    elif strategy == "frag_reassembly_attack":
        variant = random.choice([
            "overlapping_frags", "out_of_order", "missing_last",
            "zero_length_frag", "max_frag_length", "frag_bomb"
        ])

        if variant == "overlapping_frags":
            # BIND preamble + REQUEST split into overlapping fragments
            frames = _bind_pdu()
            stub = os.urandom(4000)
            # Fragment 1: first half
            f1_stub = stub[:2500]
            f1 = _request_pdu(f1_stub, opnum=0, call_id=2,
                              flags=_PFC_FIRST_FRAG)
            # Fragment 2: overlapping (starts at 2000, overlaps 500 bytes)
            f2_stub = stub[2000:]
            f2 = _request_pdu(f2_stub, opnum=0, call_id=2,
                              flags=_PFC_LAST_FRAG)
            return frames + f1 + f2

        elif variant == "out_of_order":
            # Send last fragment before first
            frames = _bind_pdu()
            stub = os.urandom(2000)
            f1 = _request_pdu(stub[:1000], opnum=0, call_id=2,
                              flags=_PFC_FIRST_FRAG)
            f2 = _request_pdu(stub[1000:], opnum=0, call_id=2,
                              flags=_PFC_LAST_FRAG)
            return frames + f2 + f1  # reversed order

        elif variant == "missing_last":
            # Send FIRST_FRAG but never LAST_FRAG — hangs reassembly
            frames = _bind_pdu()
            for i in range(50):
                frag = _request_pdu(os.urandom(200), opnum=0,
                                    call_id=2, flags=_PFC_FIRST_FRAG)
                frames += frag
            return frames

        elif variant == "zero_length_frag":
            # Fragment with frag_length = 16 (header only, no body)
            frames = _bind_pdu()
            hdr = _co_header(_PTYPE_REQUEST, 16, call_id=2,
                             flags=_PFC_FIRST_FRAG | _PFC_LAST_FRAG)
            return frames + hdr

        elif variant == "max_frag_length":
            # Fragment claiming frag_length = 0xFFFF
            frames = _bind_pdu()
            stub = os.urandom(50000)
            body = struct.pack('<IHH', len(stub), 0, 0) + stub
            frag_len = 0xFFFF  # lies about the length
            hdr = _co_header(_PTYPE_REQUEST, frag_len, call_id=2)
            return frames + hdr + body

        else:  # frag_bomb
            # 500 first-fragments with different call_ids
            frames = _bind_pdu()
            for i in range(500):
                frag = _request_pdu(os.urandom(100), opnum=0,
                                    call_id=i + 2, flags=_PFC_FIRST_FRAG)
                frames += frag
            return frames

    # ── ptype_confusion ─────────────────────────────────────────────────
    elif strategy == "ptype_confusion":
        variant = random.choice([
            "invalid_ptype", "server_ptype", "response_as_request",
            "shutdown_from_client", "ptype_ff"
        ])

        if variant == "invalid_ptype":
            # PTYPE values 20-255 are undefined
            ptype = random.randint(20, 255)
            hdr = _co_header(ptype, 16 + 100, call_id=1)
            return _bind_pdu() + hdr + os.urandom(100)

        elif variant == "server_ptype":
            # Client sends BIND_ACK (server-only PDU)
            body = struct.pack('<HHI', 4280, 4280, 1)  # fake bind_ack body
            body += struct.pack('<H', 0)  # sec_addr length
            body += struct.pack('<BBH', 0, 0, 0)  # result list
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_BIND_ACK, frag_len, call_id=1)
            return hdr + body

        elif variant == "response_as_request":
            # Client sends RESPONSE PDU
            stub = os.urandom(200)
            body = struct.pack('<IHH', len(stub), 0, 0) + stub  # alloc_hint, ctx, cancel_count+pad
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_RESPONSE, frag_len, call_id=1)
            return _bind_pdu() + hdr + body

        elif variant == "shutdown_from_client":
            # SHUTDOWN is server-only
            return _bind_pdu() + _co_header(_PTYPE_SHUTDOWN, 16, call_id=1)

        else:  # ptype_ff
            # PTYPE = 0xFF with large body
            hdr = _co_header(0xFF, 16 + 5000, call_id=1)
            return hdr + os.urandom(5000)

    # ── auth_verifier_overflow ──────────────────────────────────────────
    elif strategy == "auth_verifier_overflow":
        variant = random.choice([
            "oversized_blob", "invalid_auth_type", "auth_length_mismatch",
            "zero_auth_pad", "ntlmssp_overflow", "kerberos_bomb"
        ])

        if variant == "oversized_blob":
            # AUTH3 with 60KB auth credentials blob
            return _bind_pdu() + _auth3_pdu(os.urandom(60000))

        elif variant == "invalid_auth_type":
            # BIND with auth_verifier using invalid auth_type = 0xFF
            frames = _bind_pdu()
            verifier = struct.pack('<BBBI', 0xFF, 0x06, 0, 0)
            verifier += os.urandom(100)
            # Append auth verifier to a REQUEST
            stub = b"A" * 100
            body = struct.pack('<IHH', len(stub), 0, 0) + stub + verifier
            auth_len = len(verifier) - 8  # subtract auth header
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_REQUEST, frag_len, call_id=2,
                             auth_length=auth_len)
            return frames + hdr + body

        elif variant == "auth_length_mismatch":
            # auth_length in header says 5000 but actual verifier is 50 bytes
            frames = _bind_pdu()
            verifier = struct.pack('<BBBI', 0x0A, 0x02, 0, 0) + os.urandom(50)
            stub = b"B" * 200
            body = struct.pack('<IHH', len(stub), 0, 0) + stub + verifier
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_REQUEST, frag_len, call_id=2,
                             auth_length=5000)  # lies about auth length
            return frames + hdr + body

        elif variant == "zero_auth_pad":
            # Auth verifier with auth_pad_length claiming 255 bytes
            frames = _bind_pdu()
            verifier = struct.pack('<BBBI', 0x0A, 0x02, 255, 0)
            verifier += os.urandom(100)
            return frames + _auth3_pdu(verifier)

        elif variant == "ntlmssp_overflow":
            # NTLMSSP NEGOTIATE message with oversized domain/workstation
            ntlmssp = b"NTLMSSP\x00"
            ntlmssp += struct.pack('<I', 1)  # NEGOTIATE_MESSAGE
            ntlmssp += struct.pack('<I', 0xE2088297)  # flags
            # Domain: offset past buffer
            ntlmssp += struct.pack('<HHI', 0xFFFF, 0xFFFF, 0)
            # Workstation: 60KB
            ntlmssp += struct.pack('<HHI', 60000, 60000, 40)
            ntlmssp += os.urandom(60000)
            return _bind_pdu() + _auth3_pdu(ntlmssp)

        else:  # kerberos_bomb
            # Fake Kerberos AP-REQ with oversized ticket
            krb = b"\x60" + b"\x82\xff\xff"  # ASN.1 APPLICATION 0 with huge len
            krb += os.urandom(40000)
            verifier = struct.pack('<BBBI', 0x10, 0x06, 0, 0)  # auth_type=16 (Kerberos)
            verifier += krb
            return _bind_pdu() + _auth3_pdu(verifier)

    # ── context_negotiation_abuse ───────────────────────────────────────
    elif strategy == "context_negotiation_abuse":
        variant = random.choice([
            "duplicate_context_ids", "unknown_transfer_syntax",
            "max_contexts", "conflicting_abstract", "ndr64_confusion"
        ])

        if variant == "duplicate_context_ids":
            # Multiple contexts with the same context_id
            contexts = [(0, _UUID_EPMAPPER, 3, _UUID_NDR, 2),
                        (0, _UUID_SRVSVC, 1, _UUID_NDR, 2),
                        (0, _UUID_SAMR, 1, _UUID_NDR, 2)]
            return _bind_pdu(contexts)

        elif variant == "unknown_transfer_syntax":
            # Unknown/garbage transfer syntax UUIDs
            contexts = [(0, _UUID_EPMAPPER, 3, os.urandom(16), 0xFFFF)]
            return _bind_pdu(contexts)

        elif variant == "max_contexts":
            # 255 context elements (uint8 max for num_ctx field)
            contexts = []
            for i in range(255):
                contexts.append((i, os.urandom(16), 1, _UUID_NDR, 2))
            return _bind_pdu(contexts)

        elif variant == "conflicting_abstract":
            # Same abstract syntax, different versions
            contexts = [(0, _UUID_EPMAPPER, 3, _UUID_NDR, 2),
                        (1, _UUID_EPMAPPER, 0, _UUID_NDR, 2),
                        (2, _UUID_EPMAPPER, 0xFFFF, _UUID_NDR, 2)]
            return _bind_pdu(contexts)

        else:  # ndr64_confusion
            # Mix NDR32 and NDR64 transfer syntaxes
            contexts = [(0, _UUID_EPMAPPER, 3, _UUID_NDR, 2),
                        (1, _UUID_EPMAPPER, 3, _UUID_NDR64, 1)]
            return _bind_pdu(contexts)

    # ── stub_data_overflow ──────────────────────────────────────────────
    elif strategy == "stub_data_overflow":
        variant = random.choice([
            "huge_stub", "alloc_hint_mismatch", "ndr_conformant_overflow",
            "ndr_string_overflow", "dynamic_stub", "null_stub"
        ])

        if variant == "huge_stub":
            # 60KB stub data
            return _bind_pdu() + _request_pdu(os.urandom(60000), opnum=0)

        elif variant == "alloc_hint_mismatch":
            # alloc_hint says 4 bytes, actual stub is 10000
            frames = _bind_pdu()
            stub = os.urandom(10000)
            body = struct.pack('<IHH', 4, 0, 0) + stub  # alloc_hint=4 but 10K stub
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_REQUEST, frag_len, call_id=2)
            return frames + hdr + body

        elif variant == "ndr_conformant_overflow":
            # NDR conformant array with max_count = 0xFFFFFFFF
            frames = _bind_pdu()
            stub = struct.pack('<I', 0xFFFFFFFF)  # max_count
            stub += struct.pack('<I', 0)           # offset
            stub += struct.pack('<I', 0xFFFFFFFF)  # actual_count
            stub += os.urandom(1000)               # partial data
            return frames + _request_pdu(stub, opnum=0)

        elif variant == "ndr_string_overflow":
            # NDR varying string with actual_count past buffer
            frames = _bind_pdu()
            stub = struct.pack('<I', 100)    # max_count
            stub += struct.pack('<I', 0)     # offset
            stub += struct.pack('<I', 50000) # actual_count (lies!)
            stub += b"A" * 200               # only 200 bytes of data
            return frames + _request_pdu(stub, opnum=15)

        elif variant == "dynamic_stub":
            # Use commands from target source code analysis
            dyn_cmds = get_commands()
            frames = _bind_pdu()
            if dyn_cmds:
                overflow_sz = random_buffer_size(8192)
                stub = b""
                for cmd in dyn_cmds:
                    cmd_bytes = cmd.encode("utf-8", errors="replace") if isinstance(cmd, str) else cmd
                    stub += cmd_bytes + b"\x00" * overflow_sz
                return frames + _request_pdu(stub[:60000], opnum=0)
            else:
                return frames + _request_pdu(os.urandom(8192), opnum=0)

        else:  # null_stub
            # REQUEST with empty stub (0 bytes)
            return _bind_pdu() + _request_pdu(b"", opnum=0)

    # ── alter_context_race ──────────────────────────────────────────────
    elif strategy == "alter_context_race":
        variant = random.choice([
            "alter_before_bind", "rapid_alter", "alter_during_request",
            "alter_to_different_iface", "alter_context_id_overflow"
        ])

        if variant == "alter_before_bind":
            # ALTER_CONTEXT without prior BIND
            return _alter_context_pdu(ctx_id=0, call_id=1)

        elif variant == "rapid_alter":
            # BIND + 100 ALTER_CONTEXTs rapidly
            frames = _bind_pdu()
            for i in range(100):
                frames += _alter_context_pdu(ctx_id=i & 0xFFFF,
                                             abs_uuid=os.urandom(16),
                                             call_id=i + 2)
            return frames

        elif variant == "alter_during_request":
            # Interleave ALTER_CONTEXT between request fragments
            frames = _bind_pdu()
            stub = os.urandom(2000)
            f1 = _request_pdu(stub[:1000], opnum=0, call_id=2,
                              flags=_PFC_FIRST_FRAG)
            alter = _alter_context_pdu(ctx_id=1, call_id=3)
            f2 = _request_pdu(stub[1000:], opnum=0, call_id=2,
                              flags=_PFC_LAST_FRAG)
            return frames + f1 + alter + f2

        elif variant == "alter_to_different_iface":
            # ALTER_CONTEXT switching to SAMR after BIND to EPM
            frames = _bind_pdu()  # BIND to EPM
            frames += _alter_context_pdu(ctx_id=0, abs_uuid=_UUID_SAMR,
                                         abs_ver=1, call_id=2)
            frames += _request_pdu(os.urandom(100), opnum=5, call_id=3)
            return frames

        else:  # alter_context_id_overflow
            # ALTER_CONTEXT with context_id = 0xFFFF
            frames = _bind_pdu()
            frames += _alter_context_pdu(ctx_id=0xFFFF, call_id=2)
            return frames

    # ── cl_header_manipulation ──────────────────────────────────────────
    elif strategy == "cl_header_manipulation":
        variant = random.choice([
            "invalid_rpc_vers", "huge_frag_num", "zero_ahint",
            "max_serial", "forged_activity"
        ])

        if variant == "invalid_rpc_vers":
            # CL with rpc_vers != 4
            hdr = _cl_header(ptype=0)
            # Patch rpc_vers to 0xFF
            hdr = bytes([0xFF]) + hdr[1:]
            return hdr + os.urandom(200)

        elif variant == "huge_frag_num":
            # CL with frag_num = 0xFFFF
            hdr = _cl_header(ptype=0, frag_num=0xFFFF)
            return hdr + os.urandom(500)

        elif variant == "zero_ahint":
            # CL with ahint = 0 (should be body length hint)
            hdr = _cl_header(ptype=0, ahint=0)
            return hdr + os.urandom(1000)

        elif variant == "max_serial":
            # CL with serial_hi=255, serial_lo=255
            hdr = _cl_header(ptype=0, serial_hi=255, serial_lo=255)
            return hdr + os.urandom(300)

        else:  # forged_activity
            # 50 CL requests with the same activity UUID but different opnums
            activity = os.urandom(16)
            frames = b""
            for i in range(50):
                hdr = _cl_header(ptype=0, activity=activity, opnum=i)
                frames += hdr + os.urandom(100)
            return frames

    # ── endian_drep_confusion ───────────────────────────────────────────
    elif strategy == "endian_drep_confusion":
        variant = random.choice([
            "be_header_le_body", "mixed_drep", "invalid_drep_char",
            "drep_switch_mid_frag", "ebcdic_drep"
        ])

        if variant == "be_header_le_body":
            # Big-endian DREP in header, but body encoded little-endian
            body = struct.pack('<HHI', 4280, 4280, 0)
            body += struct.pack('<BBH', 1, 0, 0)
            body += struct.pack('<HBB', 0, 1, 0)
            body += _UUID_EPMAPPER + struct.pack('<I', 3)
            body += _UUID_NDR + struct.pack('<I', 2)
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_BIND, frag_len, drep=_DREP_BE)
            return hdr + body

        elif variant == "mixed_drep":
            # DREP with conflicting character/float fields
            drep = b'\x10\x01\x03\x00'  # LE int, EBCDIC char, VAX float
            return _co_header(_PTYPE_BIND, 16 + 12, drep=drep) + struct.pack('<HHI', 4280, 4280, 0) + struct.pack('<BBH', 0, 0, 0)

        elif variant == "invalid_drep_char":
            # All 0xFF in DREP
            drep = b'\xFF\xFF\xFF\xFF'
            hdr = _co_header(_PTYPE_BIND, 16 + 12, drep=drep)
            body = struct.pack('<HHI', 4280, 4280, 0) + struct.pack('<BBH', 0, 0, 0)
            return hdr + body

        elif variant == "drep_switch_mid_frag":
            # First fragment LE, second fragment BE
            frames = _bind_pdu()
            stub = os.urandom(2000)
            f1_body = struct.pack('<IHH', len(stub), 0, 0) + stub[:1000]
            f1_len = 16 + len(f1_body)
            f1 = _co_header(_PTYPE_REQUEST, f1_len, call_id=2,
                            flags=_PFC_FIRST_FRAG, drep=_DREP_LE) + f1_body
            f2_body = struct.pack('>IHH', len(stub), 0, 0) + stub[1000:]
            f2_len = 16 + len(f2_body)
            f2 = _co_header(_PTYPE_REQUEST, f2_len, call_id=2,
                            flags=_PFC_LAST_FRAG, drep=_DREP_BE) + f2_body
            return frames + f1 + f2

        else:  # ebcdic_drep
            # EBCDIC character encoding flag
            drep = b'\x10\x01\x00\x00'  # LE, EBCDIC
            hdr = _co_header(_PTYPE_BIND, 16 + 12, drep=drep)
            body = struct.pack('<HHI', 4280, 4280, 0) + struct.pack('<BBH', 0, 0, 0)
            return hdr + body

    # ── opnum_dispatch_fuzz ─────────────────────────────────────────────
    elif strategy == "opnum_dispatch_fuzz":
        variant = random.choice([
            "max_opnum", "sequential_opnums", "zero_opnum_huge_stub",
            "opnum_with_object_uuid", "opnum_rapid_switch"
        ])

        if variant == "max_opnum":
            # opnum = 0xFFFF
            return _bind_pdu() + _request_pdu(os.urandom(100), opnum=0xFFFF)

        elif variant == "sequential_opnums":
            # Requests with opnum 0 through 99
            frames = _bind_pdu()
            for i in range(100):
                frames += _request_pdu(os.urandom(50), opnum=i, call_id=i + 2)
            return frames

        elif variant == "zero_opnum_huge_stub":
            # opnum=0 with 40KB stub (common for EPM lookup)
            return _bind_pdu() + _request_pdu(os.urandom(40000), opnum=0)

        elif variant == "opnum_with_object_uuid":
            # REQUEST with PFC_OBJECT_UUID flag + object UUID
            return _bind_pdu() + _request_pdu(os.urandom(200), opnum=5,
                                              object_uuid=os.urandom(16))

        else:  # opnum_rapid_switch
            # Alternate between opnums rapidly
            frames = _bind_pdu()
            for i in range(200):
                opnum = random.choice([0, 5, 15, 31, 0xFFFF])
                frames += _request_pdu(os.urandom(50), opnum=opnum, call_id=i + 2)
            return frames

    # ── cancel_orphan_attack ────────────────────────────────────────────
    elif strategy == "cancel_orphan_attack":
        variant = random.choice([
            "cancel_no_request", "orphan_flood", "cancel_completed",
            "rapid_cancel_orphan"
        ])

        if variant == "cancel_no_request":
            # CO_CANCEL without a pending request
            return _bind_pdu() + _co_cancel_pdu(call_id=999)

        elif variant == "orphan_flood":
            # 100 ORPHANED PDUs for non-existent call_ids
            frames = _bind_pdu()
            for i in range(100):
                frames += _orphaned_pdu(call_id=i + 1)
            return frames

        elif variant == "cancel_completed":
            # Send request, then immediately cancel and orphan
            frames = _bind_pdu()
            frames += _request_pdu(os.urandom(100), opnum=0, call_id=2)
            frames += _co_cancel_pdu(call_id=2)
            frames += _orphaned_pdu(call_id=2)
            return frames

        else:  # rapid_cancel_orphan
            # Interleave requests with cancels/orphans
            frames = _bind_pdu()
            for i in range(50):
                cid = i + 2
                frames += _request_pdu(os.urandom(50), opnum=0, call_id=cid)
                if random.random() > 0.5:
                    frames += _co_cancel_pdu(call_id=cid)
                else:
                    frames += _orphaned_pdu(call_id=cid)
            return frames

    # ── record_marking_desync ───────────────────────────────────────────
    elif strategy == "record_marking_desync":
        variant = random.choice([
            "length_overflow", "split_rm_header", "zero_length_record",
            "max_length_record", "multi_record_single_pdu"
        ])

        if variant == "length_overflow":
            # RM header claiming 0x7FFFFFFF bytes (2GB)
            bind = _bind_pdu()
            return struct.pack('>I', 0xFFFFFFFF) + bind

        elif variant == "split_rm_header":
            # RM header split: first 2 bytes, then last 2 bytes + PDU
            bind = _bind_pdu()
            rm = struct.pack('>I', 0x80000000 | len(bind))
            return rm[:2] + b"\x00" * 100 + rm[2:] + bind

        elif variant == "zero_length_record":
            # RM header with length=0
            return struct.pack('>I', 0x80000000) + _bind_pdu()

        elif variant == "max_length_record":
            # RM header with length=0x7FFFFFFF but only send 100 bytes
            return struct.pack('>I', 0xFFFFFFFF) + os.urandom(100)

        else:  # multi_record_single_pdu
            # Single PDU split across multiple RM records
            bind = _bind_pdu()
            half = len(bind) // 2
            frame = _tcp_record_mark(bind[:half], last=False)
            frame += _tcp_record_mark(bind[half:], last=True)
            return frame

    # ── multi_bind_ack_confusion ────────────────────────────────────────
    elif strategy == "multi_bind_ack_confusion":
        variant = random.choice([
            "bind_then_request_wrong_ctx", "bind_all_interfaces",
            "bind_ack_spoof", "double_bind_different_iface",
            "bind_nak_then_request"
        ])

        if variant == "bind_then_request_wrong_ctx":
            # BIND on ctx 0, REQUEST on ctx 99
            frames = _bind_pdu()
            frames += _request_pdu(os.urandom(100), opnum=0,
                                   call_id=2, context_id=99)
            return frames

        elif variant == "bind_all_interfaces":
            # BIND with EPM + SRVSVC + SAMR all at once
            contexts = [
                (0, _UUID_EPMAPPER, 3, _UUID_NDR, 2),
                (1, _UUID_SRVSVC, 3, _UUID_NDR, 2),
                (2, _UUID_SAMR, 1, _UUID_NDR, 2),
            ]
            frames = _bind_pdu(contexts)
            # Then request on each
            for ctx in range(3):
                frames += _request_pdu(os.urandom(100), opnum=0,
                                       call_id=ctx + 2, context_id=ctx)
            return frames

        elif variant == "bind_ack_spoof":
            # Client sends a fake BIND_ACK
            body = struct.pack('<HHI', 4280, 4280, 1)
            body += struct.pack('<H', 6) + b"\\pipe\x00\x00"  # sec_addr
            body += struct.pack('<BBH', 1, 0, 0)
            body += struct.pack('<HH', 0, 0)  # result, reason
            body += _UUID_NDR + struct.pack('<I', 2)
            frag_len = 16 + len(body)
            hdr = _co_header(_PTYPE_BIND_ACK, frag_len, call_id=1)
            return hdr + body

        elif variant == "double_bind_different_iface":
            # Two BINDs back-to-back for different interfaces
            frames = _bind_pdu([(0, _UUID_EPMAPPER, 3, _UUID_NDR, 2)])
            frames += _bind_pdu([(0, _UUID_SRVSVC, 3, _UUID_NDR, 2)], call_id=2)
            return frames

        else:  # bind_nak_then_request
            # Client sends BIND_NAK then tries to REQUEST anyway
            nak_body = struct.pack('<H', 2)  # reject reason: local_limit_exceeded
            frag_len = 16 + len(nak_body)
            hdr = _co_header(_PTYPE_BIND_NAK, frag_len, call_id=1)
            frames = hdr + nak_body
            frames += _request_pdu(os.urandom(100), opnum=0, call_id=2)
            return frames

    # ── uuid_manipulation ───────────────────────────────────────────────
    elif strategy == "uuid_manipulation":
        variant = random.choice([
            "null_uuid", "max_uuid", "random_high_entropy",
            "uuid_version_fuzz", "repeated_uuid"
        ])

        if variant == "null_uuid":
            # BIND with all-zero UUIDs
            contexts = [(0, _UUID_NULL, 0, _UUID_NULL, 0)]
            return _bind_pdu(contexts)

        elif variant == "max_uuid":
            # BIND with all-0xFF UUIDs
            max_uuid = b'\xFF' * 16
            contexts = [(0, max_uuid, 0xFFFF, max_uuid, 0xFFFF)]
            return _bind_pdu(contexts)

        elif variant == "random_high_entropy":
            # 20 contexts with random UUIDs
            contexts = [(i, os.urandom(16), random.randint(0, 100),
                         _UUID_NDR, 2) for i in range(20)]
            return _bind_pdu(contexts)

        elif variant == "uuid_version_fuzz":
            # Known UUIDs but with wrong versions
            contexts = [
                (0, _UUID_EPMAPPER, 0, _UUID_NDR, 0),
                (1, _UUID_EPMAPPER, 0xFFFF, _UUID_NDR, 0xFFFF),
                (2, _UUID_SRVSVC, 0, _UUID_NDR64, 0),
            ]
            return _bind_pdu(contexts)

        else:  # repeated_uuid
            # Same UUID repeated 50 times
            contexts = [(i, _UUID_EPMAPPER, 3, _UUID_NDR, 2) for i in range(50)]
            return _bind_pdu(contexts)

    # ── fallback ────────────────────────────────────────────────────────
    else:
        # Benign, valid DCE/RPC BIND + REQUEST — baseline / control
        return _bind_pdu() + _request_pdu(b"\x00" * 100, opnum=0)


# ===== Mutator class (same interface as SmtpMutator / HttpMutator) ===========

class DcerpcMutator:
    def __init__(self, external_weights: dict = None, bandit=None):
        self.strategies = DCERPC_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return DCERPC_WEIGHTS

    def mutate(self) -> tuple:
        """Returns (payload_bytes, strategy_name)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_dcerpc_payload(strategy)
        return payload, strategy
