# fuzzer_framework/monitor/oracle.py
from transport.network import DNSTransport
from corpus.seed_generator import generate_basic_query
import time

class ServerOracle:
    """Monitors the target server to detect crashes or hangs."""
    
    def __init__(self, target_host: str, target_port: int = 53, protocol: str = "UDP"):
        self.host = target_host
        self.port = target_port
        self.protocol = protocol.upper()
        
        # We use a shorter timeout for the oracle. If the server is slow to respond
        # to a valid query, it might be suffering from CPU exhaustion.
        self.transport = DNSTransport(target_host, target_port, timeout=1.0)
        
        # Generate a perfectly pristine packet to use as our heartbeat
        self.heartbeat_payload = generate_basic_query("example.com")

    def check_health(self) -> bool:
        """
        Sends a valid heartbeat to the server.
        Returns True if the server is alive and healthy.
        Returns False if the server has crashed or frozen.
        """
        if self.protocol == "UDP":
            response = self.transport.send_udp(self.heartbeat_payload)
        else:
            response = self.transport.send_tcp(self.heartbeat_payload)
            
        # 1. Did the operating system reject the connection? (Hard crash)
        if response == b"CONNECTION_REFUSED":
            print("[-] ORACLE ALERT: Connection refused! The server process died.")
            return False
            
        # 2. Did the server freeze and stop answering? (Hang / Deadlock)
        if response == b"TIMEOUT":
            print("[-] ORACLE ALERT: Timeout! The server is frozen or dead.")
            return False
            
        # 3. Did a lower-level socket error occur?
        if isinstance(response, bytes) and response.startswith(b"ERROR"):
            print(f"[-] ORACLE ALERT: Network error: {response.decode()}")
            return False

        # If we got anything else back, the server is still processing traffic
        return True