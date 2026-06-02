"""
File-as-packet sender.

Takes an uploaded file's raw bytes and delivers them to a target as a fully
legitimate HTTP, FTP, or SMTP exchange — WITHOUT mutating the bytes. The payload
("the problem") lives inside the file; this module's only job is to wrap it in
correct protocol framing (valid headers / a real FTP STOR session / a real SMTP
MIME attachment) and send it.

Used by the dashboard "File Send" section.
"""
import io
import socket
import ftplib
import smtplib
import posixpath
from email.message import EmailMessage


def _sanitize_name(name: str) -> str:
    """Keep only the basename and strip anything path-ish/unsafe."""
    base = posixpath.basename((name or "").replace("\\", "/")).strip()
    return base or "upload.bin"


def _emit(on_packet, direction: str, label: str, data: bytes):
    """Safely invoke the optional real-time packet callback.

    direction: 'tx' (sent to target) or 'rx' (received from target).
    label:     human-readable description of this wire chunk.
    data:      the exact bytes that crossed the wire.
    """
    if on_packet and data:
        try:
            on_packet(direction, label, bytes(data))
        except Exception:
            pass


class _EmittingReader:
    """Wraps file bytes so each block ftplib reads (and immediately sends on the
    data connection) is surfaced as a real-time 'tx' packet."""

    def __init__(self, data: bytes, on_packet):
        self._bio = io.BytesIO(data)
        self._on_packet = on_packet

    def read(self, n=-1):
        buf = self._bio.read(n)
        _emit(self._on_packet, "tx", "FTP DATA (file bytes)", buf)
        return buf


class _RecordingFTP(ftplib.FTP):
    """FTP client that mirrors every control command/reply to on_packet."""

    on_packet = None

    def putline(self, line):
        _emit(self.on_packet, "tx", "FTP command", (line + "\r\n").encode("latin-1", "replace"))
        return super().putline(line)

    def getline(self):
        line = super().getline()
        _emit(self.on_packet, "rx", "FTP reply", line.encode("latin-1", "replace"))
        return line


class _RecordingSMTP(smtplib.SMTP):
    """SMTP client that mirrors every command/data chunk and reply to on_packet."""

    on_packet = None

    def send(self, s):
        data = s.encode("ascii", "replace") if isinstance(s, str) else s
        label = "SMTP DATA (message+attachment)" if len(data) > 512 else "SMTP command"
        _emit(self.on_packet, "tx", label, data)
        return super().send(s)

    def getreply(self):
        code, msg = super().getreply()
        _emit(self.on_packet, "rx", f"SMTP reply {code}", str(code).encode() + b" " + msg)
        return code, msg


def send_file_http(host: str, port: int, file_name: str, file_bytes: bytes,
                   method: str = "POST", path: str = None,
                   host_header: str = None, timeout: float = 8.0,
                   on_packet=None) -> dict:
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
            _emit(on_packet, "tx", "HTTP request headers", head)
            _emit(on_packet, "tx", "HTTP request body (file bytes)", file_bytes)
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
                    _emit(on_packet, "rx", "HTTP response", b)
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
                  remote_dir: str = None, timeout: float = 12.0,
                  on_packet=None) -> dict:
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
    ftp = _RecordingFTP()
    ftp.on_packet = on_packet
    try:
        ftp.connect(host, int(port), timeout=timeout)
        ftp.login(user or "anonymous", password or "anonymous@")
        ftp.set_pasv(True)
        if remote_dir:
            ftp.cwd(remote_dir)
        resp = ftp.storbinary(f"STOR {safe_name}", _EmittingReader(file_bytes, on_packet))
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


def send_file_smtp(host: str, port: int, file_name: str, file_bytes: bytes,
                   mail_from: str = "sender@example.com",
                   rcpt_to: str = "recipient@example.com",
                   subject: str = None, user: str = None, password: str = None,
                   timeout: float = 15.0, on_packet=None) -> dict:
    """
    Deliver file_bytes as a base64 MIME attachment inside a real SMTP message
    (EHLO/MAIL/RCPT/DATA), sent over a cleartext connection so an on-path IDS
    can inspect it. The file bytes are attached verbatim (no mutation) — Python's
    email/smtplib build correct multipart/mixed framing and the base64 transfer
    encoding around them.

    Auth is optional and intentionally NOT wrapped in STARTTLS: keeping the
    transaction in cleartext is what lets Snort's SMTP inspector see and decode
    the attachment. Returns a result dict describing the outcome.
    """
    safe_name = _sanitize_name(file_name)
    result = {
        "file": safe_name,
        "protocol": "smtp",
        "ok": False,
        "sent_bytes": 0,
        "response": "",
        "detail": "",
    }

    msg = EmailMessage()
    msg["From"] = mail_from or "sender@example.com"
    msg["To"] = rcpt_to or "recipient@example.com"
    msg["Subject"] = subject or f"File transfer: {safe_name}"
    msg.set_content(f"Attached file: {safe_name} ({len(file_bytes)} bytes).")
    # Attaching bytes with a generic maintype forces base64 transfer encoding,
    # exactly how real mailers ship binary attachments.
    msg.add_attachment(file_bytes, maintype="application", subtype="octet-stream",
                       filename=safe_name)
    raw = msg.as_bytes()

    smtp = None
    try:
        smtp = _RecordingSMTP(host, int(port), timeout=timeout)
        smtp.on_packet = on_packet
        smtp.ehlo()
        if user:
            # Best-effort cleartext AUTH; ignored if the server doesn't support it.
            try:
                smtp.login(user, password or "")
            except smtplib.SMTPException as e:
                result["detail"] = f"AUTH skipped: {type(e).__name__}: {e}; "
        refused = smtp.send_message(msg, from_addr=msg["From"],
                                    to_addrs=[msg["To"]])
        result["sent_bytes"] = len(raw)
        if refused:
            result["response"] = f"refused: {refused}"
            result["detail"] += f"some recipients refused: {refused}"
        else:
            result["ok"] = True
            result["response"] = "250 message accepted"
            result["detail"] += f"sent {len(raw)} bytes ({safe_name} attached)"
    except smtplib.SMTPException as e:
        result["detail"] += f"{type(e).__name__}: {e}"
    except Exception as e:
        result["detail"] += f"{type(e).__name__}: {e}"
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass
    return result
