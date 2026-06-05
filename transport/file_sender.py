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
import struct
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


def send_file_smb(host, port, filename, raw, share="shared", username="", password="", protocol_label="smb2"):
    """
    Send a file over raw TCP to port 445 wrapped in minimal SMB2 framing.

    Builds a valid SMB2 NEGOTIATE preamble followed by the file bytes
    wrapped in a WRITE request so an inline IDS sees the data as SMB
    traffic.  No real SMB session is established (no auth handshake),
    so the server will reject the WRITE — but the IDS inspection engine
    will still parse and inspect the payload, which is the goal.
    """
    import struct as _st
    result = {"file": filename, "protocol": protocol_label, "ok": False,
              "sent_bytes": 0, "response": "", "detail": ""}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, int(port)))

        SMB2_MAGIC = b'\xfeSMB'

        def _nb(length):
            return b'\x00' + _st.pack("!I", length)[1:]

        def _smb2_hdr(cmd, mid=0, sid=0, tid=0):
            return _st.pack("<4sHHIHHIIQIIQ16s",
                SMB2_MAGIC, 64, 1, 0, cmd, 1, 0, 0, mid, 0, tid, sid,
                b'\x00' * 16)

        # --- SMB2 NEGOTIATE ---
        neg_hdr = _smb2_hdr(0x0000, mid=0)
        guid = os.urandom(16)
        dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
        neg_body = _st.pack("<HHHI", 36, len(dialects), 0x01, 0)
        neg_body += _st.pack("<I", 0) + guid + _st.pack("<IHH", 0, 0, 0)
        for d in dialects:
            neg_body += _st.pack("<H", d)
        neg_msg = neg_hdr + neg_body
        sock.sendall(_nb(len(neg_msg)) + neg_msg)

        # --- SMB2 WRITE (file payload) ---
        fid = os.urandom(16)
        write_hdr = _smb2_hdr(0x0009, mid=1, sid=1, tid=1)
        data_offset = 64 + 49
        write_body = _st.pack("<HHI Q", 49, data_offset, len(raw), 0)
        write_body += fid
        write_body += _st.pack("<III", 0, 0, 0)
        write_body += b'\x00'
        write_body += raw
        write_msg = write_hdr + write_body
        sock.sendall(_nb(len(write_msg)) + write_msg)

        result["ok"] = True
        result["sent_bytes"] = len(raw)
        result["response"] = "SMB2 WRITE sent"
        result["detail"] = f"sent {len(raw)} bytes as SMB2 WRITE to \\\\{host}\\{share}"

        try:
            resp = sock.recv(4096)
            if resp:
                result["response"] = f"SMB2 WRITE sent ({len(resp)} bytes response)"
        except Exception:
            pass

    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return result


# ---------------------------------------------------------------------------
# HTTP/2 file send  (cleartext h2c via prior-knowledge)
# ---------------------------------------------------------------------------

def _h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    hdr = struct.pack("!I", length)[1:]  # 3-byte big-endian
    hdr += struct.pack("!BB", ftype, flags)
    hdr += struct.pack("!I", stream_id & 0x7FFFFFFF)
    return hdr + payload


def _h2_hpack_str(s: bytes) -> bytes:
    return bytes([len(s) & 0x7F]) + s if len(s) < 127 else (
        bytes([0x7F]) + bytes([(len(s) - 127) & 0x7F]) + s
    )


def send_file_http2(host: str, port: int, file_name: str, file_bytes: bytes,
                    method: str = "POST", path: str = None,
                    host_header: str = None, timeout: float = 8.0,
                    on_packet=None) -> dict:
    """
    Deliver file_bytes as an HTTP/2 POST request over cleartext TCP (h2c
    prior-knowledge). Constructs the connection preface, SETTINGS, HEADERS,
    and DATA frames manually — no h2 library dependency.

    The file bytes are sent verbatim in DATA frame(s).
    """
    safe_name = _sanitize_name(file_name)
    method_bytes = (method or "POST").upper().strip().encode()
    if not path:
        path = "/" + safe_name
    if not path.startswith("/"):
        path = "/" + path
    host_header = (host_header or host).encode()
    path_bytes = path.encode()

    result = {
        "file": safe_name,
        "protocol": "http2",
        "ok": False,
        "sent_bytes": 0,
        "response": "",
        "detail": "",
    }

    # Build connection preface + SETTINGS
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = _h2_frame(0x4, 0, 0, b"")  # empty SETTINGS

    # Build HPACK header block (using indexed + literal representations)
    block = b""
    # :method — use static table index for common methods
    if method_bytes == b"GET":
        block += b"\x82"       # indexed :method GET (index 2)
    elif method_bytes == b"POST":
        block += b"\x83"       # indexed :method POST (index 3)
    else:
        block += b"\x42" + _h2_hpack_str(method_bytes)  # literal indexed, name idx 2
    block += b"\x86"           # :scheme http (index 6)
    block += b"\x41" + _h2_hpack_str(host_header)       # :authority (name idx 1)
    block += b"\x44" + _h2_hpack_str(path_bytes)        # :path (name idx 4)
    # content-type
    ct_name = b"content-type"
    ct_val = b"application/octet-stream"
    block += b"\x40" + _h2_hpack_str(ct_name) + _h2_hpack_str(ct_val)
    # content-length
    cl_name = b"content-length"
    cl_val = str(len(file_bytes)).encode()
    block += b"\x40" + _h2_hpack_str(cl_name) + _h2_hpack_str(cl_val)

    headers_frame = _h2_frame(0x1, 0x04, 1, block)  # HEADERS, END_HEADERS, stream 1

    # Build DATA frame(s) — split into 16384-byte chunks (default MAX_FRAME_SIZE)
    data_frames = b""
    max_frame = 16384
    for i in range(0, max(len(file_bytes), 1), max_frame):
        chunk = file_bytes[i:i + max_frame]
        is_last = (i + max_frame >= len(file_bytes))
        flags = 0x01 if is_last else 0x00  # END_STREAM on last
        data_frames += _h2_frame(0x0, flags, 1, chunk)

    wire = preface + settings + headers_frame + data_frames

    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(wire)
            _emit(on_packet, "tx", "HTTP/2 connection preface", preface + settings)
            _emit(on_packet, "tx", "HTTP/2 HEADERS frame", headers_frame)
            _emit(on_packet, "tx", "HTTP/2 DATA frames (file bytes)", data_frames)
            result["sent_bytes"] = len(wire)
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
                    _emit(on_packet, "rx", "HTTP/2 response", b)
                    if sum(len(c) for c in chunks) > 8192:
                        break
            except socket.timeout:
                pass
        resp = b"".join(chunks)
        result["ok"] = True
        if resp:
            result["response"] = f"received {len(resp)} bytes"
            result["detail"] = f"sent {len(wire)} bytes as HTTP/2 POST, {len(resp)} bytes back"
        else:
            result["detail"] = f"sent {len(wire)} bytes as HTTP/2 POST (no response)"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_dcerpc(host, port, filename, data, on_packet=None, timeout=10):
    """Send a file over DCE/RPC (Connection-Oriented) to a remote endpoint.

    Wraps the file contents inside a valid DCE/RPC BIND + REQUEST sequence so
    Snort's dce_tcp inspector classifies the stream and inspects the stub data.
    The file bytes are placed in the REQUEST stub_data field.
    """
    import struct as _st

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    # ── DCE/RPC constants ─────────────────────────────────────────────
    RPC_VERS = 5
    RPC_VERS_MINOR = 0
    PTYPE_BIND = 11
    PTYPE_REQUEST = 0
    PFC_FIRST_LAST = 0x03  # PFC_FIRST_FRAG | PFC_LAST_FRAG
    DREP_LE = b'\x10\x00\x00\x00'

    # NDR transfer syntax UUID
    NDR_UUID = bytes.fromhex('045d888aeb1cc9119fe808002b104860')
    # Endpoint Mapper UUID (generic interface for file delivery)
    EPM_UUID = bytes.fromhex('e1af8308555d11c9a0eb08002b2e09fb')

    def _co_hdr(ptype, frag_len, call_id=1, auth_len=0):
        return _st.pack('<BBBB4sHHI',
                        RPC_VERS, RPC_VERS_MINOR, ptype, PFC_FIRST_LAST,
                        DREP_LE, frag_len, auth_len, call_id)

    # ── BIND PDU ──────────────────────────────────────────────────────
    bind_body = _st.pack('<HHI', 4280, 4280, 0)       # max_xmit, max_recv, assoc_group
    bind_body += _st.pack('<BBH', 1, 0, 0)             # num_ctx=1, padding
    bind_body += _st.pack('<HBB', 0, 1, 0)             # ctx_id=0, num_transfer=1, pad
    bind_body += EPM_UUID + _st.pack('<I', 3)           # abstract syntax
    bind_body += NDR_UUID + _st.pack('<I', 2)           # transfer syntax
    bind_hdr = _co_hdr(PTYPE_BIND, 16 + len(bind_body))
    bind_pdu = bind_hdr + bind_body

    # ── REQUEST PDU (file as stub data) ───────────────────────────────
    # Clamp to 60000 bytes to stay within a single TCP segment
    stub = data[:60000]
    req_body = _st.pack('<IHH', len(stub), 0, 0)  # alloc_hint, ctx_id, opnum
    req_body += stub
    req_hdr = _co_hdr(PTYPE_REQUEST, 16 + len(req_body), call_id=2)
    req_pdu = req_hdr + req_body

    wire = bind_pdu + req_pdu

    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(wire)
            _emit(on_packet, "tx", "DCE/RPC BIND PDU", bind_pdu)
            _emit(on_packet, "tx", "DCE/RPC REQUEST PDU (file payload)", req_pdu)
            result["sent_bytes"] = len(wire)
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
                    _emit(on_packet, "rx", "DCE/RPC response", b)
                    if sum(len(c) for c in chunks) > 8192:
                        break
            except socket.timeout:
                pass
        resp = b"".join(chunks)
        result["ok"] = True
        if resp:
            result["response"] = f"received {len(resp)} bytes"
            result["detail"] = f"sent {len(wire)} bytes as DCE/RPC BIND+REQUEST, {len(resp)} bytes back"
        else:
            result["detail"] = f"sent {len(wire)} bytes as DCE/RPC BIND+REQUEST (no response)"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result
