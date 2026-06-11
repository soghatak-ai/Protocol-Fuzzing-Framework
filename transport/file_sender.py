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
import os
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


def send_file_ssh(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file over an SSH-framed TCP exchange.

    A real SCP/SFTP transfer rides inside the SSH ENCRYPTED tunnel, which Snort's
    ssh inspector cannot see. To keep the bytes inspectable (and avoid a full
    crypto handshake), this wraps the file contents in the CLEARTEXT portion of
    the SSH protocol that the inspector actually parses: a valid version banner,
    a KEXINIT, then the raw file bytes carried inside SSH_MSG_IGNORE packets
    (RFC 4253 §11.2 — opaque 'string' payload). The filename is carried in an
    SSH_MSG_DEBUG message so it shows up in the handshake too.
    """
    import struct as _st

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    def _u32(n):
        return _st.pack("!I", n & 0xFFFFFFFF)

    def _string(b):
        return _u32(len(b)) + b

    def _ssh_packet(payload):
        # Pre-encryption binary packet: no MAC. Pad to an 8-byte block, pad >= 4.
        block = 8
        unpadded = 1 + len(payload)
        pad_len = block - ((4 + unpadded) % block)
        if pad_len < 4:
            pad_len += block
        packet_length = 1 + len(payload) + pad_len
        return _u32(packet_length) + bytes([pad_len]) + payload + (b"\x00" * pad_len)

    version = b"SSH-2.0-FuzzFileSender_1.0\r\n"

    # Minimal KEXINIT (msg 20) so the inspector engages the SSH parser.
    import random as _rnd
    cookie = bytes(_rnd.choices(range(256), k=16))

    def _namelist(names):
        joined = b",".join(names)
        return _u32(len(joined)) + joined

    kexinit = bytes([20]) + cookie
    for nl in ([b"diffie-hellman-group14-sha1"], [b"ssh-rsa"],
               [b"aes128-ctr"], [b"aes128-ctr"], [b"hmac-sha2-256"],
               [b"hmac-sha2-256"], [b"none"], [b"none"], [], []):
        kexinit += _namelist(nl)
    kexinit += b"\x00" + _u32(0)

    # Filename in an SSH_MSG_DEBUG (msg 4): always_display + message + lang.
    safe_name = filename.encode("utf-8", errors="replace")
    debug = bytes([4]) + b"\x01" + _string(b"file: " + safe_name) + _string(b"en")

    wire = bytearray()
    wire += version
    wire += _ssh_packet(kexinit)
    wire += _ssh_packet(debug)

    # File bytes carried in SSH_MSG_IGNORE (msg 2) packets, chunked to stay
    # within a single segment per packet.
    file_packets = []
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 16000]
        file_packets.append(_ssh_packet(bytes([2]) + _string(chunk)))
        offset += 16000
    if not file_packets:  # empty file
        file_packets.append(_ssh_packet(bytes([2]) + _string(b"")))
    for fp in file_packets:
        wire += fp

    wire = bytes(wire)

    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(wire)
            _emit(on_packet, "tx", "SSH version banner", version)
            _emit(on_packet, "tx", "SSH KEXINIT", _ssh_packet(kexinit))
            _emit(on_packet, "tx", "SSH DEBUG (filename)", _ssh_packet(debug))
            _emit(on_packet, "tx", "SSH IGNORE packets (file payload)",
                  b"".join(file_packets))
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
                    _emit(on_packet, "rx", "SSH response", b)
                    if sum(len(c) for c in chunks) > 8192:
                        break
            except socket.timeout:
                pass
        resp = b"".join(chunks)
        result["ok"] = True
        if resp:
            result["response"] = f"received {len(resp)} bytes"
            result["detail"] = (f"sent {len(wire)} bytes as SSH banner+KEXINIT+IGNORE "
                                f"(file payload), {len(resp)} bytes back")
        else:
            result["detail"] = (f"sent {len(wire)} bytes as SSH banner+KEXINIT+IGNORE "
                                f"(file payload) (no response)")
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_dhcp(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as a DHCP packet over UDP.

    Wraps the file contents inside DHCP option 43 (Vendor-Specific Information)
    of a DHCPINFORM message so that Snort's DHCP rules will inspect the payload.
    The raw file bytes are embedded as the option value.
    """
    import struct as _st
    import random as _rnd

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    # Build a minimal DHCPINFORM (op=1, htype=1, hlen=6, hops=0)
    xid = _rnd.randint(1, 0xFFFFFFFF)
    mac = bytes([_rnd.randint(0, 255) for _ in range(6)])
    ciaddr = bytes([192, 168, 1, _rnd.randint(2, 254)])

    hdr = _st.pack("!BBBB I HH 4s 4s 4s 4s",
                    1,        # op = BOOTREQUEST
                    1,        # htype = Ethernet
                    6,        # hlen
                    0,        # hops
                    xid,
                    0,        # secs
                    0x8000,   # flags (broadcast)
                    ciaddr,   # ciaddr
                    b"\x00" * 4,  # yiaddr
                    b"\x00" * 4,  # siaddr
                    b"\x00" * 4)  # giaddr
    hdr += (mac + b"\x00" * 10)  # chaddr (16 bytes)
    hdr += b"\x00" * 64          # sname
    hdr += b"\x00" * 128         # file

    magic = bytes([99, 130, 83, 99])

    # Option 53 = DHCPINFORM (8)
    opt53 = bytes([53, 1, 8])
    # Option 43 = Vendor-Specific: embed file data (max 255 per option, chain if needed)
    opt_payload = b""
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 255]
        opt_payload += bytes([43, len(chunk)]) + chunk
        offset += 255
    # Option 12 = hostname (filename)
    safe_name = filename.encode("ascii", errors="replace")[:63]
    opt12 = bytes([12, len(safe_name)]) + safe_name
    opt_end = b"\xff"

    pkt = hdr + magic + opt53 + opt12 + opt_payload + opt_end

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(pkt, (host, int(port)))
            _emit(on_packet, "tx", "DHCP INFORM (file payload)", pkt)
            result["sent_bytes"] = len(pkt)
            try:
                resp, _ = s.recvfrom(4096)
                _emit(on_packet, "rx", "DHCP response", resp)
                result["response"] = f"received {len(resp)} bytes"
            except socket.timeout:
                pass
        result["ok"] = True
        result["detail"] = f"sent {len(pkt)} bytes as DHCP INFORM on UDP/{port}"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_dhcpv6(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as a DHCPv6 packet over UDP.

    Wraps the file contents inside DHCPv6 option 17 (Vendor-specific Information)
    of an Information-Request message so that Snort's DHCPv6 rules will inspect
    the payload.  The raw file bytes are embedded as the option value.
    """
    import struct as _st
    import random as _rnd

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    # DHCPv6 Information-Request: msg-type=11, transaction-id=random 24-bit
    txid = _rnd.randint(0, 0xFFFFFF)
    hdr = _st.pack("!I", (11 << 24) | txid)  # 1 byte msg-type + 3 bytes txid

    # Option 1 — Client Identifier (DUID-LL, type=3, hw=1 Ethernet, 6 random bytes)
    duid_ll = _st.pack("!HH", 3, 1) + bytes([_rnd.randint(0, 255) for _ in range(6)])
    opt_cid = _st.pack("!HH", 1, len(duid_ll)) + duid_ll

    # Option 6 — Option Request (request DNS Recursive Name Server option 23)
    opt_oro = _st.pack("!HH H", 6, 2, 23)

    # Option 8 — Elapsed Time (0 hundredths)
    opt_elapsed = _st.pack("!HH H", 8, 2, 0)

    # Option 17 — Vendor-specific Information: embed file data
    # enterprise-number (4 bytes) + vendor data
    enterprise = _st.pack("!I", 0)  # enterprise 0
    vendor_data = b""
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 65535]
        # sub-option code=1, length=len(chunk)
        vendor_data += _st.pack("!HH", 1, len(chunk)) + chunk
        offset += 65535
    opt17_value = enterprise + vendor_data
    opt17 = _st.pack("!HH", 17, len(opt17_value)) + opt17_value

    pkt = hdr + opt_cid + opt_oro + opt_elapsed + opt17

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (host, int(port)))
            _emit(on_packet, "tx", "DHCPv6 Information-Request (file payload)", pkt)
            result["sent_bytes"] = len(pkt)
            try:
                resp, _ = s.recvfrom(4096)
                _emit(on_packet, "rx", "DHCPv6 response", resp)
                result["response"] = f"received {len(resp)} bytes"
            except socket.timeout:
                pass
        result["ok"] = True
        result["detail"] = f"sent {len(pkt)} bytes as DHCPv6 Information-Request on UDP/{port}"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_snmp(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as one or more SNMPv2c SetRequest packets over UDP.

    Wraps the file contents inside varbind OCTET STRING values (community
    'public') so that Snort's SNMP rules / any BER decoder inspect the payload.
    The filename goes in the first varbind; the file bytes are chunked across
    subsequent varbinds, each datagram kept inside a single UDP packet.
    """
    from protocol.snmp import (_sequence, _integer, _octet_string, _oid,
                               _varbind, _varbindlist, _std_pdu, _message_v1v2c,
                               _PDU_SET, _rid)

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    # Base OID for embedded file data (under enterprises.fuzzer experimental arc)
    base_oid = [1, 3, 6, 1, 4, 1, 99999, 1]
    community = b"public"
    # Per-datagram budget: keep each BER message well under the OS UDP
    # send limit (SO_SNDBUF / EMSGSIZE) so real-socket sends never fail.
    CHUNK = 512
    MAX_VARBINDS = 8  # ~4 KB of file per SetRequest

    try:
        total_sent = 0
        total_resp = 0
        # First packet carries the filename varbind.
        safe_name = filename.encode("utf-8", errors="replace")
        offset = 0
        pkt_index = 0
        first = True
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
            except OSError:
                pass
            while offset < len(data) or first:
                varbinds = []
                if first:
                    varbinds.append(_varbind(base_oid + [0], _octet_string(safe_name)))
                    first = False
                while len(varbinds) < MAX_VARBINDS and offset < len(data):
                    chunk = data[offset:offset + CHUNK]
                    varbinds.append(_varbind(base_oid + [1, pkt_index, len(varbinds)],
                                             _octet_string(chunk)))
                    offset += CHUNK
                pdu = _std_pdu(_PDU_SET, _varbindlist(varbinds), request_id=_rid())
                pkt = _message_v1v2c(1, community, pdu)
                s.sendto(pkt, (host, int(port)))
                _emit(on_packet, "tx", f"SNMP SetRequest #{pkt_index} (file payload)", pkt)
                total_sent += len(pkt)
                pkt_index += 1
                try:
                    resp, _ = s.recvfrom(4096)
                    _emit(on_packet, "rx", "SNMP response", resp)
                    total_resp += len(resp)
                except socket.timeout:
                    pass
                if offset >= len(data):
                    break
        result["sent_bytes"] = total_sent
        result["ok"] = True
        if total_resp:
            result["response"] = f"received {total_resp} bytes"
        result["detail"] = (f"sent {total_sent} bytes across {pkt_index} SNMP "
                            f"SetRequest packet(s) on UDP/{port}")
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_icmp(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as ICMP Echo Request payloads via raw socket.

    The file bytes are chunked across successive Echo Request packets (type 8,
    code 0) with a proper ICMP checksum. Requires root / CAP_NET_RAW.
    The *port* argument is unused (ICMP has no ports) but accepted for API
    consistency with other send_file_* functions.
    """
    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    CHUNK = 1400  # stay well under typical MTU
    icmp_id = struct.pack("!H", hash(filename) & 0xFFFF)

    def _icmp_cksum(msg: bytes) -> int:
        if len(msg) % 2:
            msg += b'\x00'
        s = sum(struct.unpack("!%dH" % (len(msg) // 2), msg))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    try:
        total_sent = 0
        total_resp = 0
        offset = 0
        seq = 0
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
            s.settimeout(timeout)
            while offset < len(data) or seq == 0:
                chunk = data[offset:offset + CHUNK]
                offset += len(chunk)
                seq_bytes = struct.pack("!H", seq & 0xFFFF)
                # type=8 (Echo Request), code=0, checksum placeholder, id, seq
                hdr = b'\x08\x00\x00\x00' + icmp_id + seq_bytes
                pkt_raw = hdr + chunk
                cs = _icmp_cksum(pkt_raw)
                pkt = pkt_raw[:2] + struct.pack("!H", cs) + pkt_raw[4:]

                s.sendto(pkt, (host, 0))
                _emit(on_packet, "tx", f"ICMP Echo Request seq={seq} ({len(chunk)}B payload)", pkt)
                total_sent += len(pkt)
                seq += 1

                try:
                    resp, _ = s.recvfrom(4096)
                    _emit(on_packet, "rx", "ICMP Echo Reply", resp)
                    total_resp += len(resp)
                except socket.timeout:
                    pass

                if offset >= len(data):
                    break

        result["sent_bytes"] = total_sent
        result["ok"] = True
        if total_resp:
            result["response"] = f"received {total_resp} bytes"
        result["detail"] = (f"sent {total_sent} bytes across {seq} ICMP Echo Request "
                            f"packet(s) to {host}")
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_icmpv6(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as ICMPv6 Echo Request payloads via raw socket.

    The file bytes are chunked across successive Echo Request packets (type 128,
    code 0).  The kernel computes the ICMPv6 pseudo-header checksum automatically
    for IPPROTO_ICMPV6 raw sockets.  Requires root / CAP_NET_RAW.
    The *port* argument is unused (ICMPv6 has no ports) but accepted for API
    consistency with other send_file_* functions.
    """
    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    CHUNK = 1400  # stay well under typical MTU
    icmpv6_id = struct.pack("!H", hash(filename) & 0xFFFF)

    try:
        total_sent = 0
        total_resp = 0
        offset = 0
        seq = 0
        with socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58) as s:
            s.settimeout(timeout)
            while offset < len(data) or seq == 0:
                chunk = data[offset:offset + CHUNK]
                offset += len(chunk)
                seq_bytes = struct.pack("!H", seq & 0xFFFF)
                # type=128 (Echo Request), code=0, checksum=0 (kernel fills), id, seq
                hdr = b'\x80\x00\x00\x00' + icmpv6_id + seq_bytes
                pkt = hdr + chunk

                s.sendto(pkt, (host, 0, 0, 0))
                _emit(on_packet, "tx", f"ICMPv6 Echo Request seq={seq} ({len(chunk)}B payload)", pkt)
                total_sent += len(pkt)
                seq += 1

                try:
                    resp, _ = s.recvfrom(4096)
                    _emit(on_packet, "rx", "ICMPv6 Echo Reply", resp)
                    total_resp += len(resp)
                except socket.timeout:
                    pass

                if offset >= len(data):
                    break

        result["sent_bytes"] = total_sent
        result["ok"] = True
        if total_resp:
            result["response"] = f"received {total_resp} bytes"
        result["detail"] = (f"sent {total_sent} bytes across {seq} ICMPv6 Echo Request "
                            f"packet(s) to {host}")
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_sip(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as a SIP MESSAGE over UDP.

    Wraps the file contents as the body of a SIP MESSAGE request
    (Content-Type: application/octet-stream) so that Snort's SIP inspector
    (gid 140) will parse the headers and body.
    """
    import random as _rnd

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    branch = "z9hG4bK" + "".join(_rnd.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))
    tag = "".join(_rnd.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
    callid = "".join(_rnd.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=24)) + "@filesend"
    cseq = _rnd.randint(1, 999999)
    uri = f"sip:target@{host}:{port}"

    headers = (
        f"MESSAGE {uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {host}:{port};branch={branch}\r\n"
        f"From: <sip:fuzzer@filesend.local>;tag={tag}\r\n"
        f"To: <{uri}>\r\n"
        f"Call-ID: {callid}\r\n"
        f"CSeq: {cseq} MESSAGE\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(data)}\r\n"
        f"\r\n"
    ).encode("utf-8")

    pkt = headers + data

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (host, int(port)))
            _emit(on_packet, "tx", "SIP MESSAGE (file payload)", pkt)
            result["sent_bytes"] = len(pkt)
            try:
                resp, _ = s.recvfrom(4096)
                _emit(on_packet, "rx", "SIP response", resp)
                result["response"] = f"received {len(resp)} bytes"
            except socket.timeout:
                pass
        result["ok"] = True
        result["detail"] = f"sent {len(pkt)} bytes as SIP MESSAGE on UDP/{port}"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_mgcp(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as an MGCP NTFY message over UDP.

    Wraps the file contents as the body of an MGCP NTFY (Notify) command
    so that IDS text rules on UDP 2427/2727 will parse the MGCP headers
    and body.  The file bytes are placed as SDP-like payload after
    the blank-line separator.
    """
    import random as _rnd

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    txid = str(_rnd.randint(1, 999999999))
    req_id = ''.join(_rnd.choices("0123456789ABCDEF", k=16))
    endpoint = f"aaln/{_rnd.randint(1, 24)}@{host}"

    headers = (
        f"NTFY {txid} {endpoint} MGCP 1.0\r\n"
        f"N: ca@{host}:{port}\r\n"
        f"X: {req_id}\r\n"
        f"O: L/hd\r\n"
        f"\r\n"
    ).encode("utf-8")

    pkt = headers + data

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (host, int(port)))
            _emit(on_packet, "tx", "MGCP NTFY (file payload)", pkt)
            result["sent_bytes"] = len(pkt)
            try:
                resp, _ = s.recvfrom(4096)
                _emit(on_packet, "rx", "MGCP response", resp)
                result["response"] = f"received {len(resp)} bytes"
            except socket.timeout:
                pass
        result["ok"] = True
        result["detail"] = f"sent {len(pkt)} bytes as MGCP NTFY on UDP/{port}"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_rtsp(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as an RTSP SET_PARAMETER request over TCP.

    Wraps the file contents as the body of an RTSP SET_PARAMETER request
    (Content-Type: application/octet-stream) so that Snort's generic
    text rules on TCP 554 will parse the RTSP headers and body.
    RTSP uses TCP (unlike SIP/MGCP which use UDP).
    """
    import random as _rnd

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    cseq = _rnd.randint(1, 999999)
    session_id = "".join(_rnd.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))
    uri = f"rtsp://{host}:{port}/filesend"

    headers = (
        f"SET_PARAMETER {uri} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"Session: {session_id}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(data)}\r\n"
        f"\r\n"
    ).encode("utf-8")

    pkt = headers + data

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, int(port)))
            s.sendall(pkt)
            _emit(on_packet, "tx", "RTSP SET_PARAMETER (file payload)", pkt)
            result["sent_bytes"] = len(pkt)
            try:
                resp = s.recv(4096)
                _emit(on_packet, "rx", "RTSP response", resp)
                result["response"] = f"received {len(resp)} bytes"
            except socket.timeout:
                pass
        result["ok"] = True
        result["detail"] = f"sent {len(pkt)} bytes as RTSP SET_PARAMETER on TCP/{port}"
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_tacacs(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as a TACACS+ Authentication START packet over TCP.

    Wraps the file contents inside the data field of a TACACS+ Authentication
    START body (cleartext / UNENCRYPTED_FLAG set) so that any TACACS+ content
    rules on TCP 49 will parse the header and body.  The filename is carried
    in the user field.  Uses the standard TACACS+ binary packet format with a
    12-byte header (version 0xC0, type=AUTHEN, seq_no=1, flags=0x01
    TAC_PLUS_UNENCRYPTED_FLAG, random session_id).
    """
    import random as _rnd

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    try:
        total_sent = 0
        safe_name = filename.encode("utf-8", errors="replace")[:255]
        session_id = _rnd.randint(0, 0xFFFFFFFF)

        # Build Authentication START body (RFC 8907 §5.1)
        # action=LOGIN(1), priv_lvl=USER(1), authen_type=ASCII(1),
        # authen_service=LOGIN(1)
        user = safe_name
        port_field = b"filesend"
        rem_addr = b"127.0.0.1"
        data_field = data

        user_len = min(len(user), 255)
        port_len = min(len(port_field), 255)
        rem_len = min(len(rem_addr), 255)
        data_len = len(data_field) & 0xFF  # 8-bit, wraps for large files

        body = struct.pack("!BBBBBBBB",
                           0x01, 0x01, 0x01, 0x01,
                           user_len, port_len, rem_len, data_len)
        body += user[:user_len] + port_field[:port_len] + rem_addr[:rem_len]

        # Chunk data into segments that fit in a single TCP send
        CHUNK = 4096
        offset = 0
        pkt_index = 0

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, int(port)))

            while offset < len(data_field) or pkt_index == 0:
                chunk = data_field[offset:offset + CHUNK]
                if pkt_index == 0:
                    pkt_body = body + chunk
                else:
                    # Subsequent chunks as CONTINUE bodies
                    # user_msg_len(2) + data_len(2) + flags(1) + data
                    pkt_body = struct.pack("!HHB", 0, len(chunk), 0) + chunk

                # Build 12-byte header
                version = 0xC1 if pkt_index == 0 else 0xC0
                pkt_type = 0x01  # AUTHEN
                seq_no = (pkt_index * 2 + 1) & 0xFF  # odd: 1, 3, 5, ...
                flags = 0x01  # TAC_PLUS_UNENCRYPTED_FLAG
                hdr = struct.pack("!BBBBI", version, pkt_type, seq_no, flags,
                                  session_id) + struct.pack("!I", len(pkt_body))
                pkt = hdr + pkt_body

                s.sendall(pkt)
                _emit(on_packet, "tx",
                      f"TACACS+ Auth {'START' if pkt_index == 0 else 'CONTINUE'} "
                      f"#{pkt_index} (file payload)", pkt)
                total_sent += len(pkt)
                pkt_index += 1
                offset += CHUNK

                try:
                    resp = s.recv(4096)
                    _emit(on_packet, "rx", "TACACS+ response", resp)
                    result["response"] = f"received {len(resp)} bytes"
                except socket.timeout:
                    pass

                if offset >= len(data_field) and pkt_index > 0:
                    break

        result["sent_bytes"] = total_sent
        result["ok"] = True
        result["detail"] = (f"sent {total_sent} bytes across {pkt_index} TACACS+ "
                            f"packet(s) on TCP/{port}")
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_radius(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as one or more RADIUS Access-Request packets over UDP.

    Wraps the file contents inside User-Password attribute values so that
    Snort's RADIUS content rules inspect the payload.  The filename is
    carried in a Proxy-State attribute in the first packet; file bytes are
    chunked across subsequent packets (each kept inside a single UDP
    datagram).  Uses the standard RADIUS binary packet format (Code 1 =
    Access-Request, random Identifier, random Authenticator).
    """
    import hashlib as _hl

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    # Per-datagram budget: keep well within UDP send limit.
    CHUNK = 128  # max User-Password value per RFC 2865 is 128 bytes
    # Attribute helpers (inline to avoid importing the full radius module)
    def _tlv(t, v):
        ln = 2 + len(v)
        if ln > 255:
            v = v[:253]
            ln = 255
        return bytes([t, ln]) + v

    try:
        total_sent = 0
        total_resp = 0
        safe_name = filename.encode("utf-8", errors="replace")
        offset = 0
        pkt_index = 0
        first = True
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
            except OSError:
                pass
            while offset < len(data) or first:
                import os as _os, struct as _st, random as _rnd
                ident = _rnd.randint(0, 255)
                auth = _os.urandom(16)
                attrs = []
                # User-Name
                attrs.append(_tlv(1, b"filesend@fuzzer"))
                # NAS-IP-Address
                attrs.append(_tlv(4, _st.pack("!I", 0xC0A80101)))
                if first:
                    # Carry filename in Proxy-State
                    attrs.append(_tlv(33, safe_name[:253]))
                    first = False
                # File data chunk in User-Password attribute (type 2)
                chunk = data[offset:offset + CHUNK]
                if chunk:
                    attrs.append(_tlv(2, chunk))
                    offset += CHUNK
                attrs_bytes = b"".join(attrs)
                length = 20 + len(attrs_bytes)
                header = _st.pack("!BBH", 1, ident, length)
                pkt = header + auth + attrs_bytes
                s.sendto(pkt, (host, int(port)))
                _emit(on_packet, "tx", f"RADIUS Access-Request #{pkt_index} (file payload)", pkt)
                total_sent += len(pkt)
                pkt_index += 1
                try:
                    resp, _ = s.recvfrom(4096)
                    _emit(on_packet, "rx", "RADIUS response", resp)
                    total_resp += len(resp)
                except socket.timeout:
                    pass
                if offset >= len(data) and not first:
                    break
        result["sent_bytes"] = total_sent
        result["ok"] = True
        if total_resp:
            result["response"] = f"received {total_resp} bytes"
        result["detail"] = (f"sent {total_sent} bytes across {pkt_index} RADIUS "
                            f"Access-Request packet(s) on UDP/{port}")
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def send_file_ldap(host, port, filename, data, on_packet=None, timeout=5):
    """Send a file as one or more LDAP BindRequest messages over TCP.

    Wraps the file contents inside the password (simple authentication)
    field of an LDAP BindRequest so that any Snort content rules on
    TCP 389 will see well-formed LDAP BER traffic.  The filename is
    carried in the DN (bindDN) field.  Each chunk produces a separate
    LDAPMessage SEQUENCE with an incrementing messageID.
    """

    result = {"file": filename, "ok": False, "detail": "", "sent_bytes": 0, "response": None}

    # ---- Inline BER helpers (avoids importing the full ldap module) ----
    def _ber_len(length):
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0x84,
                          (length >> 24) & 0xFF, (length >> 16) & 0xFF,
                          (length >> 8) & 0xFF, length & 0xFF])

    def _ber_int(value, tag=0x02):
        """Encode an ASN.1 INTEGER."""
        if value == 0:
            payload = b'\x00'
        elif value > 0:
            raw = value.to_bytes((value.bit_length() + 8) // 8, 'big')
            payload = raw
        else:
            payload = value.to_bytes((value.bit_length() + 9) // 8, 'big', signed=True)
        return bytes([tag]) + _ber_len(len(payload)) + payload

    def _ber_str(value, tag=0x04):
        """Encode an ASN.1 OCTET STRING."""
        return bytes([tag]) + _ber_len(len(value)) + value

    def _ber_seq(contents, tag=0x30):
        """Encode an ASN.1 SEQUENCE / constructed wrapper."""
        return bytes([tag]) + _ber_len(len(contents)) + contents

    CHUNK = 4000  # keep each BindRequest body well under TCP segment limit

    try:
        total_sent = 0
        safe_name = filename.encode("utf-8", errors="replace")[:1024]
        offset = 0
        pkt_index = 0

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, int(port)))

            while offset < len(data) or pkt_index == 0:
                msg_id = (pkt_index + 1) & 0x7FFFFFFF
                chunk = data[offset:offset + CHUNK]

                # BindRequest ::= [APPLICATION 0] SEQUENCE {
                #   version  INTEGER (3),
                #   name     LDAPDN (OCTET STRING),
                #   authentication CHOICE { simple [0] OCTET STRING }
                # }
                version = _ber_int(3)
                dn = _ber_str(safe_name)
                # simple auth: context-specific [0] primitive
                auth = _ber_str(chunk, tag=0x80)

                bind_body = version + dn + auth
                bind_req = _ber_seq(bind_body, tag=0x60)  # APPLICATION 0 constructed

                ldap_msg = _ber_int(msg_id) + bind_req
                pkt = _ber_seq(ldap_msg)  # outer LDAPMessage SEQUENCE

                s.sendall(pkt)
                _emit(on_packet, "tx",
                      f"LDAP BindRequest #{pkt_index} (file payload)", pkt)
                total_sent += len(pkt)
                pkt_index += 1
                offset += CHUNK

                try:
                    resp = s.recv(4096)
                    _emit(on_packet, "rx", "LDAP BindResponse", resp)
                    result["response"] = f"received {len(resp)} bytes"
                except socket.timeout:
                    pass

                if offset >= len(data) and pkt_index > 0:
                    break

        result["sent_bytes"] = total_sent
        result["ok"] = True
        result["detail"] = (f"sent {total_sent} bytes across {pkt_index} LDAP "
                            f"BindRequest(s) on TCP/{port}")
    except Exception as e:
        result["detail"] = f"{type(e).__name__}: {e}"
    return result
