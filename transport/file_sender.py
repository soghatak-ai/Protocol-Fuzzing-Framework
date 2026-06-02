"""
File-as-packet sender.

Takes an uploaded file's raw bytes and delivers them to a target as a fully
legitimate HTTP or FTP exchange — WITHOUT mutating the bytes. The payload
("the problem") lives inside the file; this module's only job is to wrap it in
correct protocol framing (valid headers / a real FTP STOR session) and send it.

Used by the dashboard "File Send" section.
"""
import io
import socket
import ftplib
import posixpath


def _sanitize_name(name: str) -> str:
    """Keep only the basename and strip anything path-ish/unsafe."""
    base = posixpath.basename((name or "").replace("\\", "/")).strip()
    return base or "upload.bin"


def send_file_http(host: str, port: int, file_name: str, file_bytes: bytes,
                   method: str = "POST", path: str = None,
                   host_header: str = None, timeout: float = 8.0) -> dict:
    """
    Deliver file_bytes as the body of a single, well-formed HTTP/1.1 request
    over a real TCP connection. The bytes are sent verbatim (no mutation).

    Returns a result dict describing the outcome.
    """
    safe_name = _sanitize_name(file_name)
    method = (method or "POST").upper().strip()
    if not path:
        path = "/" + safe_name
    if not path.startswith("/"):
        path = "/" + path
    host_header = host_header or host

    head = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: protocol-fuzzer-filesend/1.0\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Disposition: attachment; filename=\"{safe_name}\"\r\n"
        f"Content-Length: {len(file_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1")
    request = head + file_bytes

    result = {
        "file": safe_name,
        "protocol": "http",
        "ok": False,
        "sent_bytes": 0,
        "response": "",
        "detail": "",
    }
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)
            result["sent_bytes"] = len(request)
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            chunks = []
            try:
                while True:
                    b = s.recv(4096)
                    if not b:
                        break
                    chunks.append(b)
                    if sum(len(c) for c in chunks) > 8192:
                        break
            except socket.timeout:
                pass
        resp = b"".join(chunks)
        status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp else ""
        result["response"] = status_line
        result["ok"] = True
        result["detail"] = status_line or f"sent {len(request)} bytes (no response)"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_ftp(host: str, port: int, file_name: str, file_bytes: bytes,
                  user: str = "anonymous", password: str = "anonymous@",
                  remote_dir: str = None, timeout: float = 12.0) -> dict:
    """
    Deliver file_bytes via a real FTP STOR upload (binary mode). ftplib handles
    the full, correct control sequence (USER/PASS/TYPE I/PASV/STOR), so what
    reaches the target is legitimate FTP traffic. Bytes are sent verbatim.

    Returns a result dict describing the outcome.
    """
    safe_name = _sanitize_name(file_name)
    result = {
        "file": safe_name,
        "protocol": "ftp",
        "ok": False,
        "sent_bytes": 0,
        "response": "",
        "detail": "",
    }
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, int(port), timeout=timeout)
        ftp.login(user or "anonymous", password or "anonymous@")
        ftp.set_pasv(True)
        if remote_dir:
            ftp.cwd(remote_dir)
        resp = ftp.storbinary(f"STOR {safe_name}", io.BytesIO(file_bytes))
        result["sent_bytes"] = len(file_bytes)
        result["response"] = str(resp)
        result["ok"] = str(resp).startswith(("226", "250"))
        result["detail"] = str(resp)
    except ftplib.all_errors as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass
    return result
