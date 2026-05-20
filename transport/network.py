import socket

class DNSTransport:
    def __init__(self, target_host: str, target_port: int = 53, timeout: float = 1.0):
        self.host = target_host
        self.port = target_port
        self.timeout = timeout

    def send_udp(self, payload: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                # Fire the packet onto the wire without waiting for a reply
                sock.sendto(payload, (self.host, self.port))
                return b"SENT" 
            except Exception as e:
                return f"ERROR: {str(e)}".encode()

    def send_tcp(self, payload: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.connect((self.host, self.port))
                
                import struct
                tcp_prefix = struct.pack("!H", len(payload))
                full_payload = tcp_prefix + payload
                
                sock.sendall(full_payload)
                
                res_len_bytes = sock.recv(2)
                if not res_len_bytes or len(res_len_bytes) < 2:
                    return b"EMPTY_RESPONSE"
                    
                response_len = struct.unpack("!H", res_len_bytes)[0]
                
                response = sock.recv(response_len)
                return response
                
            except socket.timeout:
                return b"TIMEOUT"
            except ConnectionRefusedError:
                return b"CONNECTION_REFUSED"
            except Exception as e:
                return f"ERROR: {str(e)}".encode()