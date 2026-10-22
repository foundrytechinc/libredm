"""Text stream handling: Telnet negotiation, line editing, encodings."""

import select

from dmcd import config

try:
    from dmcd.native import dmcd_native as _native
except Exception:
    _native = None

CTRL_ESC = config.CTRL_ESC
OPT_CMDS = config.OPT_CMDS
ECHO_ERASE = config.ECHO_ERASE
BACKSPACE_KEYS = config.BACKSPACE_KEYS
STREAM_ENCODINGS = config.STREAM_ENCODINGS


def squeeze_backspace(chunk: bytes) -> bytes:
    if _native is not None:
        return _native.squeeze_backspace(chunk)
    out = bytearray()
    i = 0
    n = len(chunk)
    while i < n:
        b = chunk[i]
        if b in BACKSPACE_KEYS:
            out.append(b)
            if i + 1 < n and chunk[i + 1] in BACKSPACE_KEYS and chunk[i] != chunk[i + 1]:
                i += 2
            else:
                i += 1
        else:
            out.append(b)
            i += 1
    return bytes(out)


def filter_stream(sock, data: bytes, stream=None) -> bytes:
    """Strip Telnet IAC negotiations, answering a few options."""
    if stream is not None and CTRL_ESC in data:
        stream.mark_telnet()

    if _native is not None:
        payload, replies = _native.filter_telnet(data)
        if replies:
            _try_send(sock, replies)
        # Native path handles IAC but not echo-state side effects for DO ECHO.
        if stream is not None and CTRL_ESC in data and b"\xff\xfd\x01" in data:
            stream.echo = True
            stream.plain_candidate = False
        return payload

    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b != CTRL_ESC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        cmd = data[i + 1]
        if cmd == CTRL_ESC:
            out.append(CTRL_ESC)
            i += 2
        elif cmd == 253 and i + 2 < n:  # DO
            opt = data[i + 2]
            if opt == 1:  # ECHO
                _try_send(sock, bytes([255, 251, 1]))
                if stream is not None:
                    stream.echo = True
                    stream.plain_candidate = False
            elif opt == 3:  # SGA
                _try_send(sock, bytes([255, 251, 3]))
            elif opt == 24:  # TTYPE
                _try_send(sock, bytes([255, 252, 24]))
            i += 3
        elif cmd == 251 and i + 2 < n:  # WILL
            opt = data[i + 2]
            if opt == 3:
                _try_send(sock, bytes([255, 253, 3]))
            i += 3
        elif cmd in OPT_CMDS:
            i += 3 if i + 2 < n else n
        elif cmd == 250:  # SB ... SE
            i += 2
            while i < n:
                if data[i] == CTRL_ESC and i + 1 < n and data[i + 1] == 240:
                    i += 2
                    break
                i += 1
        else:
            i += 2
    return bytes(out)


def _try_send(sock, data: bytes):
    try:
        sock.send(data)
    except Exception:
        pass


class TextStream:
    def __init__(self):
        self.pending = b""
        self.mode = "interactive"
        self.encoding = "cp866"
        self.encoding_set = False
        self.echo = False
        self.telnet = False
        self.plain_candidate = True
        self.first_line = True
        self.break_next = False
        self.cursor = 0

    @property
    def interactive(self):
        return self.mode == "interactive"

    def mark_telnet(self):
        self.telnet = True
        self.plain_candidate = False
        if self.encoding == "utf-8" or not self.encoding_set:
            self.encoding = "cp866"
            self.encoding_set = False

    def outbound_encoding(self):
        if self.mode == "plain":
            return "utf-8"
        if self.mode == "interactive":
            if self.encoding in STREAM_ENCODINGS:
                return self.encoding
            return "cp866"
        return "utf-8"

    def _uses_console_encoding(self):
        return self.telnet or self.mode == "interactive"

    @staticmethod
    def looks_like_tcp_batch(chunk: bytes) -> bool:
        if not chunk or CTRL_ESC in chunk or chunk[0] == 27:
            return False
        if b"\n" in chunk or b"\r" in chunk:
            return False
        if len(chunk) <= 1:
            return False
        if chunk.startswith(b"{") or chunk.startswith(b"/"):
            return chunk.isascii()
        return False

    @staticmethod
    def looks_like_plain_line_protocol(chunk: bytes, telnet=False) -> bool:
        if not chunk or telnet or CTRL_ESC in chunk:
            return False
        if b"\n" not in chunk:
            return False
        if b"\r\n" in chunk:
            return True
        if b"\r" in chunk:
            return False
        return True

    def activate_plain(self, initial_data=b""):
        self.mode = "plain"
        self.encoding = "utf-8"
        self.pending = b""
        return initial_data

    def _pending_is_keepalive(self):
        return self.pending in (b"/", b"//")

    def _try_activate_plain(self, sock, data):
        data = self.activate_plain(data)
        self.plain_candidate = False
        return self.read_plain(sock, data)

    def finalize_line(self, text):
        if text is None:
            return None
        if not text:
            return text
        if self.first_line:
            self.first_line = False
            if text.startswith("//"):
                text = text[1:]
        return text

    def finish_line(self, text):
        result = self.finalize_line(text)
        if result is not None:
            self.break_next = True
        return result

    def note_encoding(self, raw: bytes):
        if not any(b >= 0x80 for b in raw):
            return
        if self._uses_console_encoding():
            for enc in STREAM_ENCODINGS:
                try:
                    text = raw.decode(enc)
                    if text.encode(enc) == raw:
                        self.encoding = enc
                        self.encoding_set = True
                        return
                except UnicodeDecodeError:
                    continue
            return
        if self.encoding_set:
            return
        try:
            text = raw.decode("utf-8")
            if text.encode("utf-8") == raw:
                self.encoding = "utf-8"
                self.encoding_set = True
                return
        except UnicodeDecodeError:
            pass
        for enc in STREAM_ENCODINGS:
            try:
                raw.decode(enc)
                self.encoding = enc
                self.encoding_set = True
                return
            except UnicodeDecodeError:
                continue
        self.encoding_set = True

    def decode_bytes(self, raw: bytes) -> str:
        if not raw:
            return ""
        self.note_encoding(raw)
        try:
            return raw.decode(self.encoding).strip()
        except UnicodeDecodeError:
            return raw.decode(self.encoding, errors="replace").strip()

    def _delete_before_cursor(self):
        if self.cursor <= 0 or not self.pending:
            return False
        if self.encoding != "utf-8":
            size = 1
        else:
            size = 1
            for sz in range(1, min(5, self.cursor + 1)):
                try:
                    self.pending[self.cursor - sz : self.cursor].decode("utf-8")
                    size = sz
                    break
                except UnicodeDecodeError:
                    continue
        self.pending = self.pending[: self.cursor - size] + self.pending[self.cursor :]
        self.cursor -= size
        return True

    def _insert_byte(self, sock, b: int):
        if len(self.pending) >= config.MAX_LINE_BYTES:
            return
        self.pending = self.pending[: self.cursor] + bytes([b]) + self.pending[self.cursor :]
        self.cursor += 1
        if not self.echo:
            return
        try:
            after = self.pending[self.cursor :]
            sock.send(bytes([b]))
            if after:
                sock.send(after)
                sock.send(b"\x1b[" + str(len(after)).encode() + b"D")
        except Exception:
            pass

    def _echo_backspace_at_cursor(self, sock):
        try:
            after = self.pending[self.cursor :]
            sock.send(b"\x08 \x08")
            if after:
                sock.send(after)
                sock.send(b" ")
                sock.send(b"\x1b[" + str(len(after) + 1).encode() + b"D")
        except Exception:
            pass

    def _handle_escape_sequence(self, sock, seq: bytes):
        if not self.echo:
            return
        try:
            if seq in (b"D", b"2D"):
                if self.cursor > 0:
                    self.cursor -= 1
                    sock.send(b"\x1b[D")
            elif seq in (b"C", b"2C"):
                if self.cursor < len(self.pending):
                    self.cursor += 1
                    sock.send(b"\x1b[C")
            elif seq in (b"H", b"1~", b"7~"):
                if self.cursor > 0:
                    sock.send(b"\x1b[" + str(self.cursor).encode() + b"D")
                    self.cursor = 0
            elif seq in (b"F", b"4~"):
                move = len(self.pending) - self.cursor
                if move > 0:
                    sock.send(b"\x1b[" + str(move).encode() + b"C")
                    self.cursor = len(self.pending)
        except Exception:
            pass

    def trim_last(self):
        if not self.pending:
            return 0
        if self.encoding != "utf-8":
            self.pending = self.pending[:-1]
            return 1
        for size in range(1, min(5, len(self.pending) + 1)):
            try:
                self.pending[-size:].decode("utf-8")
                self.pending = self.pending[:-size]
                return 1
            except UnicodeDecodeError:
                continue
        self.pending = self.pending[:-1]
        return 1

    def erase_echo(self, sock, steps=1):
        try:
            sock.send(ECHO_ERASE * steps)
        except Exception:
            pass

    def feed(self, sock, chunk: bytes):
        self.plain_candidate = False
        chunk = squeeze_backspace(filter_stream(sock, chunk, self))
        i = 0
        n = len(chunk)
        while i < n:
            b = chunk[i]
            if b in BACKSPACE_KEYS:
                if self._delete_before_cursor() and self.echo:
                    self._echo_backspace_at_cursor(sock)
                i += 1
                continue
            if b == 27 and i + 1 < n and chunk[i + 1] == ord("["):
                i += 2
                param = bytearray()
                while i < n and not (64 <= chunk[i] <= 126):
                    param.append(chunk[i])
                    i += 1
                if i < n:
                    final = chunk[i]
                    i += 1
                    seq = bytes(param) + bytes([final])
                    self._handle_escape_sequence(sock, seq[1:] if seq[:1] == b"[" else seq)
                continue
            if b in (13, 10):
                if len(self.pending) < config.MAX_LINE_BYTES:
                    self.pending += bytes([b])
                i += 1
                continue
            if b < 32:
                i += 1
                continue
            self._insert_byte(sock, b)
            i += 1

    def pop_line(self):
        for sep in (b"\r\n", b"\n", b"\r"):
            idx = self.pending.find(sep)
            if idx != -1:
                line = self.pending[:idx]
                self.pending = self.pending[idx + len(sep) :]
                if self.pending.startswith(b"\n") and sep == b"\r":
                    self.pending = self.pending[1:]
                self.cursor = 0
                text = self.decode_bytes(line)
                return text if text else ""
        return None

    def drain(self):
        if not self.pending:
            return None
        text = self.decode_bytes(self.pending)
        self.pending = b""
        self.cursor = 0
        return text if text else None

    def _strip_keepalive_prefix(self, data: bytes):
        if data in (b"/", b"//"):
            return data
        if data.startswith(b"//"):
            return data[1:]
        return data

    def read_plain(self, sock, first_chunk=None):
        chunk = first_chunk
        if chunk is None:
            try:
                chunk = sock.recv(config.MAX_PACKET_SIZE)
            except Exception:
                return None
        if not chunk and not self.pending:
            return None
        data = self.pending + chunk if chunk else self.pending
        self.pending = b""
        if len(data) > config.MAX_LINE_BYTES:
            data = data[: config.MAX_LINE_BYTES]
        data = self._strip_keepalive_prefix(data)
        for sep in (b"\r\n", b"\n", b"\r"):
            idx = data.find(sep)
            if idx != -1:
                line = data[: idx]
                self.pending = data[idx + len(sep) :]
                text = line.decode("utf-8", errors="replace").strip()
                if text.startswith("//"):
                    text = text[1:]
                return text if text else ""
        text = data.decode("utf-8", errors="replace").strip()
        if text.startswith("//"):
            text = text[1:]
        return text if text else None

    def read(self, sock):
        if self.mode == "plain":
            return self.read_plain(sock)

        while True:
            line = self.pop_line()
            if line is not None:
                return self.finish_line(line)

            try:
                chunk = sock.recv(config.MAX_PACKET_SIZE)
            except Exception:
                return self.finish_line(self.drain())

            if not chunk:
                return self.finish_line(self.drain())

            if self.mode != "plain":
                if (
                    self.plain_candidate
                    and not self.pending
                    and self.looks_like_plain_line_protocol(chunk, self.telnet)
                ):
                    return self._try_activate_plain(sock, chunk)
                if self.plain_candidate and not self.pending and self.looks_like_tcp_batch(chunk):
                    return self._try_activate_plain(sock, chunk)
                if self._pending_is_keepalive() and self.looks_like_tcp_batch(chunk):
                    return self._try_activate_plain(sock, self.pending + chunk)

            self.feed(sock, chunk)

            line = self.pop_line()
            if line is not None:
                return self.finish_line(line)


def plain_text_out(message: str, encoding: str = "utf-8") -> bytes:
    message = message.replace("\r\n", "\n").replace("\r", "\n")
    message = message.replace("\n", "\r\n")
    if not message.endswith("\r\n"):
        message += "\r\n"
    return message.encode(encoding, errors="replace")


def plain_send(sock, message: str, stream=None, line_break: bool = False):
    enc = stream.outbound_encoding() if stream else "utf-8"
    out = plain_text_out(message, enc)
    if stream and stream.interactive and stream.echo and (line_break or stream.break_next):
        out = b"\r\n" + out
        stream.break_next = False
    sock.sendall(out)
