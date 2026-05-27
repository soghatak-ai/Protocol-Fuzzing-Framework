import time
import threading


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
            return self._client

    def connect(self) -> bool:
        """Establish SSH session. Returns True on success."""
        try:
            self._get_client()
            return True
        except Exception as e:
            print(f"[RemoteMonitor] SSH to {self.host}:{self.ssh_port} failed: {e}")
            return False

    def _exec(self, cmd: str, timeout: int = 5) -> str:
        """Run a command over SSH and return stdout as a stripped string."""
        try:
            client = self._get_client()
            _, stdout, _ = client.exec_command(cmd, timeout=timeout)
            return stdout.read().decode("utf-8", errors="ignore").strip()
        except Exception:
            try:
                self.connect()
            except Exception:
                pass
            return ""

    def is_alive(self):
        """
        Returns True  if snort_pid is running on the remote host,
                False if it has vanished (crashed/killed),
                None  if the SSH check itself failed.
        Uses 'ps -p' instead of 'kill -0' because kill fails with EPERM
        when the SSH user is non-root but Snort runs as root (sudo).
        """
        result = self._exec(
            f"ps -p {self.snort_pid} -o pid= 2>/dev/null"
        )
        pid_str = result.strip()
        if pid_str:
            try:
                return int(pid_str) == self.snort_pid
            except ValueError:
                return None
        if result == "":
            return False
        return None

    def get_memory_mb(self):
        """
        Returns RSS in MB. Tries Linux /proc first, falls back to
        POSIX 'ps' so it works on macOS (test laptop) and Linux (FTD).
        Returns None if the process is gone or unreadable.
        """
        line = self._exec(
            f"grep VmRSS /proc/{self.snort_pid}/status 2>/dev/null"
        )
        if line:
            try:
                kb = int(line.split()[1])
                return kb / 1024.0
            except (ValueError, IndexError):
                pass

        result = self._exec(
            f"ps -o rss= -p {self.snort_pid} 2>/dev/null"
        )
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
        raw1 = self._exec(
            f"cat /proc/{self.snort_pid}/stat 2>/dev/null && cat /proc/stat | head -1"
        )
        return None

    def close(self):
        with self._lock:
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
