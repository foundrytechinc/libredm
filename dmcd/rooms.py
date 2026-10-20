"""Room (chat-server) membership and message broadcasting."""

import threading

from dmcd import config
from dmcd.storage import RoomStore
from dmcd.sessions import registry, send_to_client


class RoomManager:
    def __init__(self, store: RoomStore):
        self.store = store
        self._lock = threading.RLock()
        # room -> {(username, origin_host): refcount}
        self._members = {}
        # room -> set of remote hosts with subscribers
        self._remote_subs = {}
        # (username, room, host) -> refcount for multi-session remote joins
        self._remote_counters = {}

    @property
    def lock(self):
        return self._lock

    def members_map(self, room: str):
        with self._lock:
            return dict(self._members.setdefault(room, {}))

    def member_names(self, room: str, viewer_host: str):
        with self._lock:
            return [
                display_name_for(viewer_host, u, h)
                for (u, h) in self._members.setdefault(room, {}).keys()
            ]

    def remote_subscribers(self, room: str):
        with self._lock:
            return set(self._remote_subs.setdefault(room, set()))

    def add_member(self, room: str, username: str, origin_host: str) -> bool:
        """Increment refcount. Returns True if this is the first reference."""
        with self._lock:
            room_map = self._members.setdefault(room, {})
            key = (username, origin_host)
            prev = room_map.get(key, 0)
            room_map[key] = prev + 1
            return prev == 0

    def remove_member(self, room: str, username: str, origin_host: str) -> bool:
        """Decrement refcount. Returns True if the last reference was removed."""
        with self._lock:
            room_map = self._members.setdefault(room, {})
            key = (username, origin_host)
            prev = room_map.get(key, 0)
            if prev <= 1:
                room_map.pop(key, None)
                return prev == 1
            room_map[key] = prev - 1
            return False

    def member_exists(self, room: str, username: str, origin_host: str) -> bool:
        with self._lock:
            return (username, origin_host) in self._members.get(room, {})

    def update_remote_subscriber(self, room: str, origin_host: str):
        with self._lock:
            room_map = self._members.setdefault(room, {})
            present = any(h == origin_host for (_, h) in room_map.keys())
            subs = self._remote_subs.setdefault(room, set())
            if present:
                subs.add(origin_host)
            else:
                subs.discard(origin_host)

    def remote_counter_inc(self, key):
        with self._lock:
            self._remote_counters[key] = self._remote_counters.get(key, 0) + 1
            return self._remote_counters[key]

    def remote_counter_dec(self, key) -> bool:
        """Returns True if this was the last reference."""
        with self._lock:
            prev = self._remote_counters.get(key, 0)
            if prev > 1:
                self._remote_counters[key] = prev - 1
                return False
            self._remote_counters.pop(key, None)
            return True

    def remote_counter(self, key) -> int:
        with self._lock:
            return self._remote_counters.get(key, 0)

    def local_members_for_cleanup(self, room: str):
        with self._lock:
            return list(self._members.get(room, {}).keys())

    def all_rooms(self):
        return self.store.names()

    def drop_host_members(self, host: str):
        """Remove all members belonging to a dead remote host."""
        results = []  # (room, username, origin_host, was_last)
        with self._lock:
            for room in list(self._members.keys()):
                room_map = self._members[room]
                for key in list(room_map.keys()):
                    username, origin_host = key
                    if origin_host != host:
                        continue
                    prev = room_map.pop(key, None)
                    was_last = (prev or 0) >= 1
                    results.append((room, username, origin_host, was_last))
                self._remote_subs.setdefault(room, set()).discard(host)
        return results


def display_name_for(viewer_host: str, username: str, origin_host: str) -> str:
    return username if origin_host == viewer_host else f"{username}@{origin_host}"


def format_room_event_text(viewer_host: str, event: str, username: str, origin_host: str, payload=None) -> str:
    disp = display_name_for(viewer_host, username, origin_host)
    if event == "joined":
        return f"*** {disp} has joined the server."
    if event == "left":
        return f"*** {disp} has left the server."
    if event == "message":
        text = payload.get("text") if payload else ""
        return f"{disp}: {text}"
    if event == "act":
        act = payload.get("act") if payload else ""
        return f"*** {disp} {act}"
    return ""


def parse_room_and_host(name: str):
    if "@" in name:
        idx = name.rfind("@")
        return name[:idx], name[idx + 1 :]
    return name, None


def broadcast_message(
    message,
    server_name,
    sender_session=None,
    message_type="broadcast_message",
    sender=None,
    exclude_username=None,
    filter_fn=None,
):
    """Send message to every session in a room.

    filter_fn(recipient_username, sender_username, context) -> True to drop.
    """
    try:
        sessions = registry.room_sessions(server_name)
        from dmcd.s2s import log_message
        log_message(f"broadcast to '{server_name}': {len(sessions)} sessions, type={message_type}, message='{message[:80]}'")
        for sess in sessions:
            if sender_session is not None and sess is sender_session:
                continue
            if exclude_username and getattr(sess, "username", None) == exclude_username:
                continue
            if (
                sender
                and getattr(sess, "username", None)
                and filter_fn
                and filter_fn(sess.username, sender, "server")
            ):
                log_message(f"  → filtered for {sess.username}")
                continue
            from dmcd.sessions import send_to_client
            result = send_to_client(sess.client_socket, message, sess.client_key, message_type)
            log_message(f"  → sent to {sess.username}: {result}")
    except Exception:
        pass
