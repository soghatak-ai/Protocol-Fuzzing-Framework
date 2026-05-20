import subprocess
import os

class ServerOracle:
    def __init__(self, process_handle: subprocess.Popen):
        """
        Accepts the running process object directly to monitor 
        its lifecycle status.
        """
        self.process = process_handle

    def check_health(self) -> bool:
        """
        Checks if the monitored local application is still executing.
        """
        # poll() returns None if the process is running normally.
        # If it returns an integer (exit code), the process has terminated.
        if self.process.poll() is not None:
            print(f"[-] ORACLE ALERT: Target process terminated with exit status {self.process.poll()}")
            return False
        return True