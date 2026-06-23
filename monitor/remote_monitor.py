import re
import time
import threading

_SSH_FAILURE = object()
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\r')


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes and carriage returns from terminal output."""
    return _ANSI_RE.sub('', text)


class RemoteSnortMonitor:
  
    def __init__(self, host: str, snort_pid: int,
                 username: str = "admin", password: str = "",
                 ssh_port: int = 22):
        self.host = host
        self.snort_pid = int(snort_pid)
        self.username = username
        self.password = password
        self.ssh_port = ssh_port
        self._client = None
        self._lock = threading.Lock()
        self._shell = None
        self._use_shell = False

    def _get_client(self):
        try:
            import paramiko
        except ImportError:
            raise RuntimeError(
                "paramiko is required for remote monitoring. "
                "Install it with:  pip install paramiko"
            )
        with self._lock:
            transport = self._client.get_transport() if self._client else None
            if self._client is None or transport is None or not transport.is_active():
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    self.host,
                    port=self.ssh_port,
                    username=self.username,
                    password=self.password,
                    timeout=10,
                    look_for_keys=False,
                    allow_agent=False,
                )
                if self._client:
                    try:
                        self._client.close()
                    except Exception:
                        pass
                self._client = client
                self._shell = None
            return self._client

    def connect(self) -> bool:
        """Establish SSH session and probe shell type.
        On FTD, admin SSH gives CLISH — auto-switches to interactive shell."""
        try:
            self._get_client()
            if not self._use_shell:
                self._probe_shell_type()
            return True
        except Exception as e:
            print(f"[RemoteMonitor] SSH to {self.host}:{self.ssh_port} failed: {e}")
            return False

    def _probe_shell_type(self):
        """Detect whether exec_command gives a real bash shell or CLISH.
        Run 'echo PROBE_OK' — if result doesn't contain PROBE_OK,
        switch to interactive shell (expert → root) immediately."""
        try:
            client = self._get_client()
            chan = client.get_transport().open_session()
            chan.settimeout(5)
            chan.exec_command("echo PROBE_OK")
            out = b""
            try:
                while True:
                    chunk = chan.recv(4096)
                    if not chunk:
                        break
                    out += chunk
            except Exception:
                pass
            chan.close()
            decoded = out.decode("utf-8", errors="ignore").strip()
            if "PROBE_OK" in decoded:
                print(f"[RemoteMonitor] {self.host} — bash shell detected (exec_command works)")
                return
        except Exception:
            pass
        print(f"[RemoteMonitor] {self.host} — CLISH/restricted shell detected, switching to interactive mode")
        self._use_shell = True
        self._init_shell()

    def _drain(self, shell, seconds: float = 1.0) -> str:
        """Read all available data from shell for up to `seconds`."""
        buf = ""
        deadline = time.time() + seconds
        while time.time() < deadline:
            time.sleep(0.1)
            if shell.recv_ready():
                buf += shell.recv(65535).decode("utf-8", errors="ignore")
        return buf

    def _init_shell(self):
        """Create an interactive shell and navigate through FTD CLISH to root.
        On FTD: admin SSH → CLISH → expert → sudo su - → root bash.
        Sets TERM=dumb and simple PS1 to eliminate ANSI noise.
        Verifies the shell actually works before returning."""
        try:
            client = self._get_client()
            shell = client.invoke_shell(width=200, height=50)
            self._drain(shell, 2.0)

            shell.send("expert\n")
            expert_out = self._drain(shell, 3.0)

            shell.send("sudo su -\n")
            sudo_out = self._drain(shell, 2.0)

            if "assword" in sudo_out:
                shell.send(f"{self.password}\n")
                self._drain(shell, 1.5)

            shell.send("export TERM=dumb; export PS1='RMON$ '; stty -echo 2>/dev/null\n")
            self._drain(shell, 1.0)

            shell.send("echo SHELL_VERIFIED\n")
            verify = self._drain(shell, 2.0)

            if "SHELL_VERIFIED" in _strip_ansi(verify):
                self._shell = shell
                self._use_shell = True
                print(f"[RemoteMonitor] Interactive shell established and verified on {self.host} (expert→root)")
                return shell
            else:
                print(f"[RemoteMonitor] WARNING: Shell verification failed on {self.host}, output: {repr(verify[:200])}")
                self._shell = shell
                self._use_shell = True
                return shell
        except Exception as e:
            print(f"[RemoteMonitor] Failed to init interactive shell: {e}")
            self._shell = None
            return None

    def _shell_exec(self, cmd: str, timeout: int = 8):
        """Run a command through the interactive shell using start/end markers.
        Returns cleaned stdout string on success, _SSH_FAILURE on failure."""
        try:
            if self._shell is None or self._shell.closed:
                if not self._init_shell():
                    return _SSH_FAILURE

            shell = self._shell
            ts = int(time.time() * 1000) % 999999
            marker_s = f"XSTART{ts}X"
            marker_e = f"XEND{ts}X"

            if shell.recv_ready():
                shell.recv(65535)

            shell.send(f"echo {marker_s}; {cmd}; echo {marker_e}\n")

            output = ""
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.1)
                if shell.recv_ready():
                    chunk = shell.recv(65535).decode("utf-8", errors="ignore")
                    output += chunk
                    if marker_e in output:
                        break

            clean = _strip_ansi(output)

            if marker_e not in clean:
                self._shell = None
                return _SSH_FAILURE

            lines = clean.split("\n")
            result = []
            collecting = False
            for line in lines:
                stripped = line.strip()
                if stripped == marker_e or marker_e in stripped:
                    break
                if collecting:
                    result.append(stripped)
                if stripped == marker_s or marker_s in stripped:
                    collecting = True

            return "\n".join(result).strip()
        except Exception:
            self._shell = None
            return _SSH_FAILURE

    def _exec(self, cmd: str, timeout: int = 5):
        """Run a command over SSH.
        Returns stdout string on success, _SSH_FAILURE sentinel on failure.
        Uses interactive shell if CLISH was detected, else exec_command."""
        if self._use_shell:
            return self._shell_exec(cmd, timeout)

        try:
            client = self._get_client()
            _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="ignore").strip()
            return out
        except Exception:
            try:
                self.connect()
            except Exception:
                pass
            return _SSH_FAILURE

    def is_alive(self):
        """
        Returns True  if snort_pid is running on the remote host,
                False if it has vanished (crashed/killed),
                None  if the SSH check itself failed.
        """
        result = self._exec(
            f"ps -p {self.snort_pid} -o pid= 2>/dev/null"
        )
        if result is _SSH_FAILURE:
            return None
        pid_str = result.strip()
        if pid_str:
            try:
                return int(pid_str) == self.snort_pid
            except ValueError:
                return None
        return False

    def find_snort_pid(self):
        """Find any running snort3 process on the remote host.
        Returns the PID (int) if found, None otherwise.
        Used to detect PID rotation vs actual crash on FTD."""
        result = self._exec(
            "ps aux 2>/dev/null | grep snort3 | grep -v grep | awk '{print $2}' | head -1"
        )
        if result is _SSH_FAILURE:
            return None
        if result.strip():
            try:
                return int(result.strip())
            except ValueError:
                pass
        return None

    def update_pid(self, new_pid: int):
        """Update the tracked Snort PID after a rotation."""
        self.snort_pid = int(new_pid)

    def get_memory_mb(self):
        """
        Returns RSS in MB. Tries Linux /proc first, falls back to
        POSIX 'ps' so it works on macOS (test laptop) and Linux (FTD).
        Returns None if the process is gone or unreadable.
        """
        line = self._exec(
            f"grep VmRSS /proc/{self.snort_pid}/status 2>/dev/null"
        )
        if line and line is not _SSH_FAILURE:
            try:
                kb = int(line.split()[1])
                return kb / 1024.0
            except (ValueError, IndexError):
                pass

        result = self._exec(
            f"ps -o rss= -p {self.snort_pid} 2>/dev/null"
        )
        if result and result is not _SSH_FAILURE:
            if result.strip():
                try:
                    return int(result.strip()) / 1024.0
                except ValueError:
                    pass

        return None

    def get_cpu_percent(self):
        """
        Returns Snort's current CPU usage (%) using /proc/<pid>/stat.
        Returns None on failure.
        """
        return None

    def close(self):
        with self._lock:
            if self._shell:
                try:
                    self._shell.close()
                except Exception:
                    pass
                self._shell = None
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
