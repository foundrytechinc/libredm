"""Capability: authenticated HTTP file upload/download on the chat port.

Upload requires a bearer token issued to a logged-in user via
/http_file_upload token
"""

import json
import mimetypes
import os
import shutil
import threading
import time
import uuid

from caps.caps import Capability


def _upload_dir():
    from dmcd import config
    return config.data_path(config.UPLOAD_DIR)


_cleanup_started = False
_cleanup_lock = threading.Lock()


def _ensure_uploads():
    os.makedirs(_upload_dir(), exist_ok=True)


def _start_cleanup_once():
    global _cleanup_started
    with _cleanup_lock:
        if _cleanup_started:
            return
        _ensure_uploads()

        def _worker():
            while True:
                from dmcd import config
                cutoff = time.time() - config.UPLOAD_TTL_SECONDS
                base = _upload_dir()
                try:
                    for entry in os.listdir(base):
                        full = os.path.join(base, entry)
                        try:
                            if os.path.getmtime(full) < cutoff:
                                if os.path.isdir(full):
                                    shutil.rmtree(full, ignore_errors=True)
                                else:
                                    os.remove(full)
                        except Exception:
                            pass
                except Exception:
                    pass
                time.sleep(config.CLEANUP_INTERVAL_SECONDS)

        threading.Thread(target=_worker, daemon=True).start()
        _cleanup_started = True


def _safe_filename(name):
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    cleaned = "".join(ch for ch in name if ch in allowed)
    # Reject traversal / empty after cleanup ("..", ".", "").
    if cleaned.strip(".") == "":
        return "file"
    return cleaned


def _safe_join_upload(*parts):
    """Join under the upload dir and ensure the result stays inside it."""
    base = os.path.realpath(_upload_dir())
    path = os.path.realpath(os.path.join(base, *parts))
    if path != base and not path.startswith(base + os.sep):
        return None
    return path


def _http_response(sock, code, headers, body):
    reason = {
        200: "OK", 400: "Bad Request", 401: "Unauthorized",
        404: "Not Found", 413: "Payload Too Large", 500: "Internal Server Error",
    }.get(code, "OK")
    head = f"HTTP/1.1 {code} {reason}\r\n".encode("utf-8")
    for k, v in headers.items():
        head += f"{k}: {v}\r\n".encode("utf-8")
    head += b"\r\n"
    try:
        sock.sendall(head)
        if body:
            sock.sendall(body)
    except Exception:
        pass


def _extract_token(headers, path):
    # Bearer only. Tokens in the query string leak via logs/Referer/history.
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


# Served back to browsers — never let these execute as active content.
_DANGEROUS_EXTS = frozenset({
    ".html", ".htm", ".xhtml", ".svg", ".xml", ".xsl", ".xslt",
    ".js", ".mjs", ".css", ".pdf", ".swf", ".php", ".shtml",
})


def _safe_download_mime(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in _DANGEROUS_EXTS:
        return "application/octet-stream"
    mime, _ = mimetypes.guess_type(filename)
    if not mime or mime.startswith("text/") or "javascript" in mime or "xml" in mime:
        return "application/octet-stream"
    return mime


class HttpFileUploadCapability(Capability):
    def __init__(self):
        super().__init__(
            name="http_file_upload",
            commands={
                "info": "- Show upload endpoint, TTL and max file size",
                "token": "- Issue a temporary upload token for your account",
            },
        )
        _start_cleanup_once()

    def sniff_raw_connection(self, peek_bytes):
        if not peek_bytes:
            return False
        head = peek_bytes[:8].upper()
        return head.startswith(b"GET ") or head.startswith(b"POST ")

    def handle_raw_connection(self, client_socket, client_address):
        from dmcd import config
        try:
            client_socket.settimeout(10)
            req = b""
            while b"\r\n\r\n" not in req and len(req) < 65536:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                req += chunk
            if not req:
                client_socket.close()
                return

            try:
                head, body = req.split(b"\r\n\r\n", 1)
            except ValueError:
                head, body = req, b""
            lines = head.split(b"\r\n")
            if not lines:
                client_socket.close()
                return
            request_line = lines[0].decode("utf-8", errors="ignore")
            parts = request_line.split(" ")
            method = parts[0] if parts else ""
            path = parts[1] if len(parts) > 1 else "/"
            headers = {}
            for ln in lines[1:]:
                if b":" in ln:
                    k, v = ln.split(b":", 1)
                    headers[
                        k.strip().decode("utf-8", errors="ignore").lower()
                    ] = v.strip().decode("utf-8", errors="ignore")

            try:
                cl = int(headers.get("content-length", "0") or "0")
            except Exception:
                cl = 0
            # Reject oversized bodies before reading them into memory.
            if cl < 0 or (0 < config.MAX_UPLOAD_SIZE_BYTES < cl):
                _http_response(client_socket, 413, {"Content-Length": "0", "Connection": "close"}, b"")
                return
            missing = max(0, cl - len(body))
            while missing > 0:
                chunk = client_socket.recv(min(65536, missing))
                if not chunk:
                    break
                body += chunk
                missing -= len(chunk)
            if len(body) > config.MAX_UPLOAD_SIZE_BYTES > 0:
                _http_response(client_socket, 413, {"Content-Length": "0", "Connection": "close"}, b"")
                return

            if method == "POST" and path.startswith("/upload"):
                self._handle_upload(client_socket, headers, body, path)
                return
            if method == "GET" and path.startswith("/file/"):
                self._handle_download(client_socket, path)
                return

            _http_response(client_socket, 404, {"Content-Length": "0", "Connection": "close"}, b"")
        except Exception:
            _http_response(client_socket, 500, {"Content-Length": "0", "Connection": "close"}, b"")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _authorize_upload(self, headers, path):
        from dmcd.app import app
        token = _extract_token(headers, path)
        if not token:
            return None
        return app.upload_tokens.validate(token)

    def _handle_upload(self, sock, headers, body, path):
        from dmcd import config

        username = self._authorize_upload(headers, path)
        if not username:
            _http_response(
                sock,
                401,
                {
                    "Content-Length": "0",
                    "Connection": "close",
                    "WWW-Authenticate": "Bearer",
                },
                b"",
            )
            return

        ctype = headers.get("content-type", "")
        if "multipart/form-data" not in ctype:
            _http_response(sock, 400, {"Content-Length": "0", "Connection": "close"}, b"")
            return
        try:
            cl = int(headers.get("content-length", "0") or "0")
        except Exception:
            cl = 0
        if 0 < config.MAX_UPLOAD_SIZE_BYTES < cl:
            _http_response(sock, 400, {"Content-Length": "0", "Connection": "close"}, b"")
            return
        boundary = None
        for part in ctype.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part.split("=", 1)[1]
                if boundary.startswith('"') and boundary.endswith('"'):
                    boundary = boundary[1:-1]
        if not boundary:
            _http_response(sock, 400, {"Content-Length": "0", "Connection": "close"}, b"")
            return

        bmark = ("--" + boundary).encode("utf-8")
        sections = body.split(bmark)
        saved = False
        for sec in sections:
            if b"Content-Disposition" in sec and b"filename=" in sec:
                try:
                    header_blob, file_payload = sec.split(b"\r\n\r\n", 1)
                except ValueError:
                    continue
                if file_payload.endswith(b"\r\n"):
                    file_payload = file_payload[:-2]
                if file_payload.endswith(b"--"):
                    file_payload = file_payload[:-2]
                filename = "file"
                try:
                    disp = next(
                        (ln for ln in header_blob.split(b"\r\n") if b"Content-Disposition" in ln),
                        b"",
                    )
                    if b"filename=" in disp:
                        fn = disp.split(b"filename=")[1].strip()
                        if fn.startswith(b'"') and fn.endswith(b'"'):
                            fn = fn[1:-1]
                        filename = _safe_filename(fn.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
                if 0 < config.MAX_UPLOAD_SIZE_BYTES < len(file_payload):
                    _http_response(sock, 400, {"Content-Length": "0", "Connection": "close"}, b"")
                    break
                file_id = uuid.uuid4().hex
                target_dir = _safe_join_upload(file_id)
                if not target_dir:
                    _http_response(sock, 500, {"Content-Length": "0", "Connection": "close"}, b"")
                    break
                try:
                    os.makedirs(target_dir, exist_ok=True)
                    with open(os.path.join(target_dir, filename), "wb") as f:
                        f.write(file_payload)
                    host = config.MY_SERVER_HOST
                    port = config.TCP_PORT
                    payload = {
                        "status": "ok",
                        "id": file_id,
                        "filename": filename,
                        "size": len(file_payload),
                        "uploaded_by": username,
                        "url": f"http://{host}:{port}/file/{file_id}/{filename}",
                    }
                    resp_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                    _http_response(
                        sock,
                        200,
                        {
                            "Content-Type": "application/json; charset=utf-8",
                            "Content-Length": str(len(resp_body)),
                            "Connection": "close",
                        },
                        resp_body,
                    )
                    saved = True
                except Exception:
                    pass
                break

        if not saved:
            _http_response(sock, 400, {"Content-Length": "0", "Connection": "close"}, b"")

    def _handle_download(self, sock, path):
        from dmcd import config

        parts = path.split("/")
        if len(parts) < 4:
            _http_response(sock, 404, {"Content-Length": "0", "Connection": "close"}, b"")
            return
        file_id = _safe_filename(parts[2])
        filename = _safe_filename(parts[3])
        full_path = _safe_join_upload(file_id, filename)
        if not full_path or not os.path.isfile(full_path):
            _http_response(sock, 404, {"Content-Length": "0", "Connection": "close"}, b"")
            return
        mime = _safe_download_mime(filename)
        try:
            size = os.path.getsize(full_path)
            headers = {
                "Content-Type": mime,
                "Content-Length": str(size),
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; sandbox",
                "Connection": "close",
            }
            _http_response(sock, 200, headers, b"")
            with open(full_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    try:
                        sock.sendall(chunk)
                    except Exception:
                        break
        except Exception:
            _http_response(sock, 500, {"Content-Length": "0", "Connection": "close"}, b"")

    def handle_info(self, args, session, client_socket, client_key, server_context=None):
        from dmcd import config
        host = config.MY_SERVER_HOST
        port = config.TCP_PORT
        msg = (
            f"HTTP upload endpoint: http://{host}:{port}/upload\n"
            f"Download URL: http://{host}:{port}/file/<id>/<filename>\n"
            f"Auth: Authorization: Bearer <token> (get one with /http_file_upload token)\n"
            f"Retention (TTL): {config.UPLOAD_TTL_SECONDS} seconds.\n"
            f"Max file size: {config.MAX_UPLOAD_SIZE_BYTES} bytes."
        )
        return self.send_message(msg, client_socket, client_key)

    def handle_token(self, args, session, client_socket, client_key, server_context=None):
        if not session or not getattr(session, "username", None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True
        from dmcd.app import app
        from dmcd import config
        token = app.upload_tokens.issue(
            session.username, ttl_seconds=config.UPLOAD_TTL_SECONDS
        )
        self.send_message(
            f"Upload token (valid {config.UPLOAD_TTL_SECONDS}s): {token}",
            client_socket,
            client_key,
        )
        return True
