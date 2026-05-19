# fuzzer_framework/transport/network.py
import socket

class DNSTransport:
    def __init__(self, target_host: str, target_port: int = 53, timeout: float = 1.0):
        self.host = target_host
        self.port = target_port
        self.timeout = timeout

    def send_udp(self, payload: bytes) -> bytes:
        """Blasts a packet over UDP and waits for a response (or timeout)."""
        # SOCK_DGRAM specifies UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.sendto(payload, (self.host, self.port))
                # Read response up to 65535 bytes (max UDP packet size)
                response, _ = sock.recvfrom(65535)
                return response
            except socket.timeout:
                # In fuzzing, a timeout is very interesting! It could mean a crash or hang.
                return b"TIMEOUT"
            except Exception as e:
                return f"ERROR: {str(e)}".encode()

    def send_tcp(self, payload: bytes) -> bytes:
        """Sends a packet over TCP, enforcing RFC 1035 2-byte length prefix syntax."""
        # SOCK_STREAM specifies TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.connect((self.host, self.port))
                
                # CRITICAL STEP FOR DNS OVER TCP: 
                # Prefix the packet with a 2-byte unsigned short (!H) containing the length
                import struct
                tcp_prefix = struct.pack("!H", len(payload))
                full_payload = tcp_prefix + payload
                
                sock.sendall(full_payload)
                
                # Read the 2-byte response length prefix first
                res_len_bytes = sock.recv(2)
                if not res_len_bytes or len(res_len_bytes) < 2:
                    return b"EMPTY_RESPONSE"
                    
                response_len = struct.unpack("!H", res_len_bytes)[0]
                
                # Read the actual response payload based on that length
                response = sock.recv(response_len)
                return response
                
            except socket.timeout:
                return b"TIMEOUT"
            except ConnectionRefusedError:
                # High priority event: The server completely shut down its port (Crash indicator)
                return b"CONNECTION_REFUSED"
            except Exception as e:
                return f"ERROR: {str(e)}".encode()