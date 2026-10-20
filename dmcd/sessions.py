"""Session tracking: connected clients indexed by user, room, and socket."""

import threading
import time

from dmcd import config
from dmcd.textstream import TextStream, plain_send
from dmcd import crypto


class Session:
    def __init__(self, client_socket, address):
        self.client_socket = client_socket
        self.address = address
        self.username = None
        self.server_name = None
        self.created_at = time.time()
        self.text_in = None
        self.client_key = None  # (enc_key, mac_key) or None

    def send_text(self, message: str, message_type: str = "system") -> bool:
        return self.registry.send_to_session(self, message, message_type)


class SessionRegistry:
    """Thread-safe bookkeeping for all connected sessions."""

    def __init__(self):
        self._lock = threading.RLock()
        self.by_user = {}       # username -> set[Session]
        self.by_room = {}       # room_name -> set[Session]
        self.by_socket = {}     # socket -> Session
        self._send_queues = {}
        self._send_workers = {}
        self._send_lock = threading.RLock()

    # -- lookups -----------------------------------------------------------

    @property
    def lock(self):
        return self._lock

    def get_by_socket(self, sock):
        with self._lock:
            return self.by_socket.get(sock)

    def user_sessions(self, username: str):
        with self._lock:
            return list(self.by_user.get(username, set()))

    def room_sessions(self, room: str):
        with self._lock:
            return list(self.by_room.get(room, set()))

    def is_user_online(self, username: str) -> bool:
        with self._lock:
            return bool(self.by_user.get(username))

    def online_usernames(self):
        with self._lock:
            return [u for u, s in self.by_user.items() if s]

    # -- registration ------------------------------------------------------

    def register(self, session: Session):
        with self._lock:
            self.by_socket[session.client_socket] = session
            if session.username:
                self.by_user.setdefault(session.username, set()).add(session)
            if session.server_name:
                self.by_room.setdefault(session.server_name, set()).add(session)

    def set_username(self, session: Session, username: str):
        with self._lock:
            old = session.username
            if old and old in self.by_user:
                self.by_user[old].discard(session)
                if not self.by_user[old]:
                    del self.by_user[old]
            session.username = username
            self.by_user.setdefault(username, set()).add(session)

    def set_room(self, session: Session, room: str):
        with self._lock:
            old = session.server_name
            if old and old in self.by_room:
                self.by_room[old].discard(session)
                if not self.by_room[old]:
                    del self.by_room[old]
            session.server_name = room
            if room:
                self.by_room.setdefault(room, set()).add(session)

    def unregister(self, session: Session):
        """Returns True if this was the user's last session."""
        with self._lock:
            self.by_socket.pop(session.client_socket, None)
            last = False
            if session.username and session.username in self.by_user:
                self.by_user[session.username].discard(session)
                if not self.by_user[session.username]:
                    del self.by_user[session.username]
                    last = True
            if session.server_name and session.server_name in self.by_room:
                self.by_room[session.server_name].discard(session)
                if not self.by_room[session.server_name]:
                    del self.by_room[session.server_name]
            return last

    # -- sending -----------------------------------------------------------

    def send_to_session(self, session: Session, message: str, message_type: str = "system") -> bool:
        return send_to_client(
            session.client_socket, message, session.client_key, message_type, self
        )

    def shutdown_socket(self, sock):
        with self._send_lock:
            q = self._send_queues.pop(sock, None)
            self._send_workers.pop(sock, None)
        if q is not None:
            try:
                q.put_nowait(None)
            except Exception:
                pass


# Global registry instance, wired by the server at startup.
registry = SessionRegistry()


def get_client_key(session: Session):
    return session.client_key if session else None


def _send_immediate(sock, message, client_key=None, message_type="system", reg=None) -> bool:
    try:
        if client_key:
            if isinstance(client_key, tuple):
                enc_key, mac_key = client_key
            else:
                enc_key, mac_key = client_key, None
            return crypto.send_encrypted(sock, message, enc_key, mac_key)
        stream = None
        if reg is not None:
            sess = reg.get_by_socket(sock)
            if sess is not None:
                stream = getattr(sess, "text_in", None)
        plain_send(sock, message, stream=stream, line_break=message_type in config.DELAYED_MESSAGE_TYPES)
        return True
    except Exception:
        return False


def _send_worker(sock, q, reg):
    import time as _time
    last_sent_at = 0.0
    while True:
        try:
            item = q.get()
            if item is None:
                break
            message, client_key, message_type = item
            now = _time.time()
            delta = now - last_sent_at
            if config.SEND_DELAY_SECONDS > 0 and delta < config.SEND_DELAY_SECONDS:
                _time.sleep(config.SEND_DELAY_SECONDS - delta)
            if not _send_immediate(sock, message, client_key, message_type, reg):
                break
            last_sent_at = _time.time()
        except Exception:
            break
    reg.shutdown_socket(sock)


def enqueue_send(sock, message, client_key=None, message_type="system", reg=None) -> bool:
    reg = reg or registry
    try:
        if message_type not in config.DELAYED_MESSAGE_TYPES:
            return _send_immediate(sock, message, client_key, message_type, reg)
        import queue
        import threading
        with reg._send_lock:
            q = reg._send_queues.get(sock)
            if q is None:
                q = queue.Queue()
                reg._send_queues[sock] = q
            worker = reg._send_workers.get(sock)
            if worker is None or not worker.is_alive():
                worker = threading.Thread(target=_send_worker, args=(sock, q, reg), daemon=True)
                reg._send_workers[sock] = worker
                worker.start()
        q.put((message, client_key, message_type))
        return True
    except Exception:
        return False


def send_to_client(client_socket, message, client_key=None, message_type="system", reg=None) -> bool:
    return enqueue_send(client_socket, message, client_key, message_type, reg)
