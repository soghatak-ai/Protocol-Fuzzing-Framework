import time
import threading

_SSH_FAILURE = object()


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
        """Establish SSH session. Returns True on success."""
        try:
            self._get_client()
            return True
        except Exception as e:
            print(f"[RemoteMonitor] SSH to {self.host}:{self.ssh_port} failed: {e}")
            return False

    def _init_shell(self):
        """Create an interactive shell and navigate through FTD CLISH to root.
        On FTD: admin SSH → CLISH → expert → sudo su - root → bash."""
        try:
            client = self._get_client()
            shell = client.invoke_shell(width=200, height=50)
            time.sleep(1.5)
            if shell.recv_ready():
                shell.recv(65535)

            shell.send("expert\n")
            time.sleep(2.0)
            out = ""
            if shell.recv_ready():
                out = shell.recv(65535).decode("utf-8", errors="ignore")

            shell.send("sudo su -\n")
            time.sleep(1.5)
            prompt = ""
            if shell.recv_ready():
                prompt = shell.recv(65535).decode("utf-8", errors="ignore")

            if "assword" in prompt:
                shell.send(f"{self.password}\n")
                time.sleep(1.0)
                if shell.recv_ready():
                    shell.recv(65535)

            self._shell = shell
            self._use_shell = True
            print(f"[RemoteMonitor] Interactive shell established on {self.host} (expert→root)")
            return shell
        except Exception as e:
            print(f"[RemoteMonitor] Failed to init interactive shell: {e}")
            self._shell = None
            return None

    def _shell_exec(self, cmd: str, timeout: int = 5):
        """Run a command through the interactive shell with marker-based output delimiting.
        Returns stdout string on success, _SSH_FAILURE on failure."""
        try:
            if self._shell is None or self._shell.closed:
                if not self._init_shell():
                    return _SSH_FAILURE

            shell = self._shell
            marker = f"XEND{int(time.time() * 1000) % 999999}X"

            if shell.recv_ready():
                shell.recv(65535)

            shell.send(f"{cmd}; echo {marker}\n")

            output = ""
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.1)
                if shell.recv_ready():
                    chunk = shell.recv(65535).decode("utf-8", errors="ignore")
                    output += chunk
                    if marker in output:
                        break

            if marker not in output:
                self._shell = None
                return _SSH_FAILURE

            lines = output.split("\n")
            result = []
            collecting = False
            for line in lines:
                if marker in line:
                    break
                if collecting:
                    result.append(line)
                elif cmd.split(";")[0].strip()[:20] in line:
                    collecting = True

            return "\n".join(result).strip()
        except Exception:
            self._shell = None
            return _SSH_FAILURE

    def _exec(self, cmd: str, timeout: int = 5):
        """Run a command over SSH.
        Returns stdout string on success, _SSH_FAILURE sentinel on failure.
        Tries exec_command first; if CLISH is detected, switches to
        interactive shell mode (expert→root) for FTD compatibility."""
        if self._use_shell:
            return self._shell_exec(cmd, timeout)

        try:
            client = self._get_client()
            _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="ignore").strip()
            err = stderr.read().decode("utf-8", errors="ignore").strip()

            if not out and ("Invalid" in err or "nrecognized" in err
                           or "ommand not found" in err or "CLISH" in err):
                print(f"[RemoteMonitor] CLISH detected on {self.host}, switching to interactive shell")
                self._use_shell = True
                return self._shell_exec(cmd, timeout)

            return out
        except Exception:
            if not self._use_shell:
                print(f"[RemoteMonitor] exec_command failed, trying interactive shell")
                self._use_shell = True
                return self._shell_exec(cmd, timeout)
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
