"""Server-to-server federation with real dialback verification."""

import json
import socket
import struct
import threading
import time
import hashlib

from dmcd import config
from dmcd import crypto


def log_message(message: str):
    print(f"[{time.strftime('%H:%M:%S')}] {message}")


def generate_msg_id(sender: str, recipient: str, message: str) -> str:
    base = f"{sender}:{recipient}:{message}:{time.time_ns()}"
    return hashlib.sha256(base.encode()).hexdigest()


class DialbackLedger:
    """Tracks outbound messages so inbound dialback checks can be verified.

    This is what makes dialback real: a peer asking "did you send msg_id X?"
    only gets 'ok' if we actually originated X and the fields match.
    """

    def __init__(self, ttl: int = config.DIALBACK_OUTBOUND_TTL):
        self._lock = threading.RLock()
        self._entries = {}  # msg_id -> (timestamp, record_dict)
        self._ttl = ttl

    def record(self, msg_id: str, record: dict):
        if not msg_id:
            return
        now = time.time()
        with self._lock:
            self._entries[msg_id] = (now, dict(record))
            self._sweep(now)

    def verify(self, msg_id: str, msg_type: str = None, **fields) -> bool:
        with self._lock:
            item = self._entries.get(msg_id)
            if not item:
                return False
            ts, record = item
            if time.time() - ts > self._ttl:
                self._entries.pop(msg_id, None)
                return False
            if msg_type and record.get("type") != msg_type:
                return False
            for key, value in fields.items():
                if value is None:
                    continue
                if record.get(key) != value:
                    return False
            return True

    def _sweep(self, now: float):
        expired = [k for k, (ts, _) in self._entries.items() if now - ts > self._ttl]
        for k in expired:
            self._entries.pop(k, None)


class S2SLink:
    def __init__(self, my_host_fn, outbound_ledger: DialbackLedger, identity=None):
        self.port = config.TCP_PORT
        self.my_host_fn = my_host_fn
        self.outbound = outbound_ledger
        self.identity = identity
        self._lock = threading.RLock()
        self._caps = {}
        self._sessions = {}

    # -- capability cache --------------------------------------------------

    def _cap_get(self, host):
        with self._lock:
            item = self._caps.get(host)
            if not item:
                return None
            mode, ts = item
            if time.time() - ts > config.S2S_CAP_TTL:
                del self._caps[host]
                return None
            return mode

    def _cap_set(self, host, mode):
        with self._lock:
            self._caps[host] = (mode, time.time())

    def _close_session(self, host):
        with self._lock:
            sess = self._sessions.pop(host, None)
        if sess:
            try:
                sess["sock"].close()
            except Exception:
                pass

    # -- plain transport ---------------------------------------------------

    def _connect(self, host, timeout):
        """Dial a validated public address for host (anti DNS-rebinding)."""
        from dmcd.s2s_identity import resolve_public_s2s_addr
        addr = resolve_public_s2s_addr(host)
        if not addr:
            raise ConnectionRefusedError(f"S2S destination not allowed: {host}")
        return socket.create_connection((addr, self.port), timeout=timeout)

    def _plain_send(self, host, data, timeout, wait_response):
        payload = (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")
        with self._connect(host, timeout) as sock:
            _tcp_nodelay(sock)
            sock.sendall(payload)
            if not wait_response:
                return {"status": "ok"}
            sock.settimeout(timeout)
            resp = b""
            while not resp.endswith(b"\n"):
                chunk = sock.recv(config.MAX_PACKET_SIZE)
                if not chunk:
                    break
                resp += chunk
            if not resp:
                return None
            return json.loads(resp.decode("utf-8", errors="replace").strip())

    # -- encrypted transport -----------------------------------------------

    def _open_encrypted_session(self, host, timeout):
        sock = self._connect(host, timeout)
        _tcp_nodelay(sock)
        sock.settimeout(timeout)
        sock.sendall(config.S2S_MAGIC)
        enc_key, mac_key = crypto.dh_client(sock)
        return {
            "sock": sock,
            "enc": enc_key,
            "mac": mac_key,
            "lock": threading.Lock(),
            "last_used": time.time(),
        }

    def _get_session(self, host, timeout):
        now = time.time()
        with self._lock:
            sess = self._sessions.get(host)
            if sess and now - sess["last_used"] < config.S2S_SESSION_TTL:
                return sess
            if sess:
                try:
                    sess["sock"].close()
                except Exception:
                    pass
                self._sessions.pop(host, None)
        sess = self._open_encrypted_session(host, timeout)
        with self._lock:
            self._sessions[host] = sess
        return sess

    def _encrypted_send(self, host, data, timeout, wait_response):
        sock = self._connect(host, timeout)
        try:
            _tcp_nodelay(sock)
            sock.settimeout(timeout)
            sock.sendall(config.S2S_MAGIC)
            enc_key, mac_key = crypto.dh_client(sock)
            text = json.dumps(data, ensure_ascii=False)
            if not crypto.send_encrypted(sock, text, enc_key, mac_key):
                raise ConnectionError("S2S encrypted send failed.")
            if not wait_response:
                return {"status": "ok"}
            raw = crypto.receive_encrypted(sock, enc_key, mac_key)
            if not raw:
                raise ConnectionError("S2S encrypted recv failed.")
            return json.loads(raw)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # -- public API --------------------------------------------------------

    def probe_cap(self, host, timeout=config.S2S_CONNECT_TIMEOUT):
        from dmcd.s2s_identity import is_allowed_s2s_host
        if not is_allowed_s2s_host(host):
            return None
        cached = self._cap_get(host)
        if cached:
            return cached
        data = {"type": "s2s_cap", "from_host": self.my_host_fn()}
        try:
            payload = (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")
            with self._connect(host, timeout) as sock:
                _tcp_nodelay(sock)
                sock.sendall(payload)
                sock.settimeout(config.S2S_CAP_PROBE_TIMEOUT)
                resp = b""
                try:
                    while not resp.endswith(b"\n"):
                        chunk = sock.recv(config.MAX_PACKET_SIZE)
                        if not chunk:
                            break
                        resp += chunk
                except socket.timeout:
                    pass
                if resp:
                    line = resp.split(b"\n", 1)[0].strip()
                    parsed = json.loads(line.decode("utf-8", errors="replace"))
                    if isinstance(parsed, dict) and parsed.get("status") == "ok" and parsed.get("encrypted"):
                        self._cap_set(host, "encrypted")
                        return "encrypted"
        except Exception:
            pass
        self._cap_set(host, "plain")
        return "plain"

    def send_json(self, host, data, timeout=config.S2S_IO_TIMEOUT, wait_response=True):
        from dmcd.s2s_identity import is_allowed_s2s_host

        if not host or not is_allowed_s2s_host(host):
            return None
        if not isinstance(data, dict):
            return None
        if self.identity is not None and getattr(self.identity, "enabled", False):
            data = self.identity.sign(data)
        elif config.S2S_REQUIRE_SIGNATURE:
            return None
        msg_id = data.get("msg_id")
        if msg_id and data.get("type") != "dialback_check":
            self.outbound.record(msg_id, data)
        mode = self.probe_cap(host, timeout=min(timeout, config.S2S_CONNECT_TIMEOUT))
        if mode is None:
            return None
        if mode == "encrypted":
            try:
                return self._encrypted_send(host, data, timeout, wait_response)
            except Exception:
                self._close_session(host)
                try:
                    return self._encrypted_send(host, data, timeout, wait_response)
                except Exception:
                    self._cap_set(host, "plain")
        if config.S2S_REQUIRE_ENCRYPTED:
            return None
        return self._plain_send(host, data, timeout, wait_response)

    def handle_inbound(self, sock, process_fn):
        try:
            head = sock.recv(len(config.S2S_MAGIC))
            if head != config.S2S_MAGIC:
                return
            enc_key, mac_key = crypto.dh_server(sock)
            raw = crypto.receive_encrypted(sock, enc_key, mac_key)
            if not raw:
                return
            msg = json.loads(raw)

            def reply(data):
                crypto.send_encrypted(sock, json.dumps(data, ensure_ascii=False), enc_key, mac_key)

            process_fn(msg, reply, sock)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass


def _tcp_nodelay(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


class DialbackChecker:
    """Performs outbound dialback checks against a peer's claimed origin."""

    def __init__(self, link: S2SLink, my_host_fn):
        self.link = link
        self.my_host_fn = my_host_fn
        self._cache = {}
        self._lock = threading.RLock()

    def cached(self, host: str, msg_type: str):
        key = f"{host}:{msg_type}"
        with self._lock:
            item = self._cache.get(key)
            if not item:
                return None
            ts, result = item
            # Negative cache only; keep it short so transient failures recover.
            ttl = min(config.DIALBACK_CACHE_TTL, 30.0)
            if time.time() - ts > ttl:
                del self._cache[key]
                return None
            return result

    def cache(self, host: str, msg_type: str, result: bool):
        with self._lock:
            self._cache[f"{host}:{msg_type}"] = (time.time(), result)

    def check(self, from_host: str, msg_id: str, msg_type: str, **kwargs) -> bool:
        """Ask from_host whether it really sent msg_id. Returns True on verified.

        Positive results are intentionally NOT cached as authorization:
        one successful dialback must not allow further spoofed messages
        from that host. Only negative results are cached (fail-fast).
        """
        if not from_host or not msg_id:
            return False
        cached = self.cached(from_host, msg_type)
        if cached is False:
            return False

        def _send():
            data = {
                "type": "dialback_check",
                "msg_id": msg_id,
                "msg_type": msg_type,
                "from_host": self.my_host_fn(),
                **kwargs,
            }
            resp = self.link.send_json(from_host, data)
            if not isinstance(resp, dict):
                return False
            return resp.get("result") == "ok"

        result = False
        try:
            result = bool(_send())
        except Exception as e:
            log_message(f"[dialback] error contacting {from_host}: {e}")
            for _ in range(config.MAX_RETRIES - 1):
                try:
                    time.sleep(config.RETRY_DELAY)
                    result = bool(_send())
                    if result:
                        break
                except Exception:
                    break
        if not result:
            self.cache(from_host, msg_type, False)
        return result
