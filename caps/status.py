"""Capability: presence / online status with subscriptions (local + federated)."""

import json
import os
import threading
import time

from caps.caps import Capability

_state_lock = threading.RLock()
_app = None  # bound at startup via bind_app()


def _subs_path():
    from dmcd import config
    return config.data_path(config.STATUS_SUBS_FILE)


def _remote_subs_path():
    from dmcd import config
    return config.data_path(config.STATUS_REMOTE_SUBS_FILE)


_subscriptions = None
_last_state = {}

_remote_subs = None

_REMOTE_CHECK_TIMEOUT = 5


def bind_app(app):
    global _app
    _app = app


def _get_app():
    return _app


def _my_host():
    from dmcd import config
    return config.MY_SERVER_HOST


# ---------------------------------------------------------------------------
# Local subscriptions persistence
# ---------------------------------------------------------------------------

def _load_subscriptions():
    global _subscriptions
    with _state_lock:
        if _subscriptions is not None:
            return
        subs = {}
        path = _subs_path()
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for subscriber, targets in data.items():
                        if isinstance(subscriber, str) and isinstance(targets, list):
                            subs[subscriber] = set(str(t) for t in targets if t)
        except Exception:
            subs = {}
        _subscriptions = subs


def _save_subscriptions():
    with _state_lock:
        if _subscriptions is None:
            return
        data = {k: sorted(list(v)) for k, v in _subscriptions.items() if v}
    try:
        path = _subs_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        os.replace(tmp, path)
    except Exception:
        pass


def _load_remote_subs():
    global _remote_subs
    with _state_lock:
        if _remote_subs is not None:
            return
        out = {}
        path = _remote_subs_path()
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    for local_user, by_host in raw.items():
                        if not isinstance(local_user, str) or not isinstance(by_host, dict):
                            continue
                        out.setdefault(local_user, {})
                        for host, users in by_host.items():
                            if not isinstance(host, str) or not isinstance(users, list):
                                continue
                            out[local_user][host] = set(str(u) for u in users if u)
        except Exception:
            out = {}
        _remote_subs = out


def _save_remote_subs():
    _load_remote_subs()
    with _state_lock:
        data = {}
        for local_user, by_host in _remote_subs.items():
            if not by_host:
                continue
            data[local_user] = {h: sorted(list(us)) for h, us in by_host.items() if us}
    try:
        path = _remote_subs_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        os.replace(tmp, path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# S2S helpers
# ---------------------------------------------------------------------------

def _send_s2s(host, payload):
    a = _get_app()
    if a is None:
        return None
    try:
        out = dict(payload or {})
        out.setdefault("from_host", _my_host())
        out.setdefault(
            "msg_id",
            f"{out.get('type', 'presence')}:{host}:{time.time_ns()}",
        )
        return a.s2s.send_json(host, out)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Remote presence subscriptions
# ---------------------------------------------------------------------------

def handle_presence_subscribe(from_host, subscriber_user, target_local_user):
    _load_remote_subs()
    if not from_host or not subscriber_user or not target_local_user:
        return False
    with _state_lock:
        by_host = _remote_subs.setdefault(target_local_user, {})
        users = by_host.setdefault(from_host, set())
        users.add(subscriber_user)
    _save_remote_subs()
    return True


def handle_presence_unsubscribe(from_host, subscriber_user, target_local_user):
    _load_remote_subs()
    if not from_host or not subscriber_user or not target_local_user:
        return False
    changed = False
    with _state_lock:
        by_host = _remote_subs.get(target_local_user, {})
        users = by_host.get(from_host, set())
        if subscriber_user in users:
            users.remove(subscriber_user)
            changed = True
        if not users:
            by_host.pop(from_host, None)
        if not by_host:
            _remote_subs.pop(target_local_user, None)
    if changed:
        _save_remote_subs()
    return True


def handle_presence_update(from_host, user, online):
    if not from_host or not user:
        return False
    notify_status_change(f"{user}@{from_host}", bool(online))
    return True


# ---------------------------------------------------------------------------
# Local subscription API
# ---------------------------------------------------------------------------

def _normalize_target(raw):
    try:
        t = (raw or "").strip().replace(" ", "")
        if not t:
            return None
        if "@" in t:
            u, h = t.rsplit("@", 1)
            if not u or not h:
                return None
            if h == _my_host():
                return u
            return f"{u}@{h}"
        return t
    except Exception:
        return None


def sub_add(subscriber, target_raw):
    _load_subscriptions()
    t = _normalize_target(target_raw)
    if not subscriber:
        return False, "Please log in first."
    if not t:
        return False, "Invalid username."
    if t == subscriber:
        return False, "You cannot subscribe to yourself."
    with _state_lock:
        targets = _subscriptions.get(subscriber)
        if targets is None:
            targets = set()
            _subscriptions[subscriber] = targets
        if t in targets:
            return True, f"Already subscribed to {t}."
        targets.add(t)
    _save_subscriptions()
    return True, f"Subscribed to {t}."


def sub_del(subscriber, target_raw):
    _load_subscriptions()
    t = _normalize_target(target_raw)
    if not subscriber:
        return False, "Please log in first."
    if not t:
        return False, "Invalid username."
    with _state_lock:
        targets = _subscriptions.get(subscriber, set())
        if t not in targets:
            return True, f"Not subscribed to {t}."
        targets.remove(t)
        if not targets:
            _subscriptions.pop(subscriber, None)
    _save_subscriptions()
    return True, f"Unsubscribed from {t}."


def sub_list(subscriber):
    _load_subscriptions()
    if not subscriber:
        return []
    with _state_lock:
        return sorted(list(_subscriptions.get(subscriber, set())))


def sub_clear(subscriber):
    _load_subscriptions()
    if not subscriber:
        return
    with _state_lock:
        _subscriptions.pop(subscriber, None)
    _save_subscriptions()


def notify_status_change(target_identifier, online):
    _load_subscriptions()
    key = _normalize_target(target_identifier)
    if not key:
        return
    now = bool(online)

    with _state_lock:
        prev = _last_state.get(key)
        if prev is not None and prev == now:
            return
        _last_state[key] = now
        subs_snapshot = {k: set(v) for k, v in (_subscriptions or {}).items()}

    msg = f"{key} is {'online' if now else 'offline'}."
    a = _get_app()
    if a is not None:
        from dmcd.sessions import send_to_client
        for subscriber, targets in subs_snapshot.items():
            if key not in targets:
                continue
            for sess in a.sessions.user_sessions(subscriber):
                try:
                    send_to_client(sess.client_socket, msg, sess.client_key, "system")
                except Exception:
                    pass

    try:
        _load_remote_subs()
        if "@" in key:
            return
        with _state_lock:
            by_host = dict(_remote_subs.get(key, {}))
        for host in by_host.keys():
            if host:
                _send_s2s(host, {"type": "presence_update", "user": key, "online": now})
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Capability
# ---------------------------------------------------------------------------

class StatusCapability(Capability):
    def __init__(self):
        super().__init__(
            name="status",
            commands={
                "check": "<username> - Check if a user is online or offline",
                "sub-add": "<username> - Subscribe to status notifications",
                "sub-del": "<username> - Unsubscribe from status notifications",
                "sub-list": "- Show your subscription list",
                "sub-clear": "- Clear your subscription list",
            },
        )

    def handle_check(self, args, session, client_socket, client_key, server_context=None):
        if len(args) < 1:
            self.send_message("Usage: /status-check <username>", client_socket, client_key)
            return True

        username = args[0]
        a = _get_app()

        if "@" in username:
            user_part, host_part = username.rsplit("@", 1)
            if host_part == _my_host():
                username = user_part
            else:
                try:
                    out = a.s2s.send_json(
                        host_part,
                        {
                            "type": "status_request",
                            "usernames": [user_part],
                            "from_host": _my_host(),
                        },
                        timeout=_REMOTE_CHECK_TIMEOUT,
                    )
                    online_map = out.get("online_map") if isinstance(out, dict) else None
                    online = (
                        bool(online_map.get(user_part, False))
                        if isinstance(online_map, dict)
                        else False
                    )
                    self.send_message(
                        f"{user_part}@{host_part} is {'online' if online else 'offline'}.",
                        client_socket,
                        client_key,
                    )
                except Exception:
                    self.send_message(
                        f"{user_part}@{host_part} is offline.", client_socket, client_key
                    )
                return True

        online = a.sessions.is_user_online(username) if a else False
        self.send_message(
            f"{username} is {'online' if online else 'offline'}.",
            client_socket,
            client_key,
        )
        return True

    def handle_sub_add(self, args, session, client_socket, client_key, server_context=None):
        if not getattr(session, "username", None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True
        if len(args) < 1:
            self.send_message("Usage: /status-sub-add <username>", client_socket, client_key)
            return True

        ok, msg = sub_add(session.username, args[0])
        self.send_message(msg, client_socket, client_key)

        try:
            t = _normalize_target(args[0])
            if t and "@" in t:
                user_part, host_part = t.rsplit("@", 1)
                if host_part and host_part != _my_host():
                    resp = _send_s2s(host_part, {
                        "type": "presence_subscribe",
                        "subscriber": session.username,
                        "target": user_part,
                    })
                    if not isinstance(resp, dict) or resp.get("status") != "ok":
                        self.send_message("User does not exist.", client_socket, client_key)
        except Exception:
            pass
        return True

    def handle_sub_del(self, args, session, client_socket, client_key, server_context=None):
        if not getattr(session, "username", None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True
        if len(args) < 1:
            self.send_message("Usage: /status-sub-del <username>", client_socket, client_key)
            return True

        ok, msg = sub_del(session.username, args[0])
        self.send_message(msg, client_socket, client_key)

        try:
            t = _normalize_target(args[0])
            if t and "@" in t:
                user_part, host_part = t.rsplit("@", 1)
                if host_part and host_part != _my_host():
                    resp = _send_s2s(host_part, {
                        "type": "presence_unsubscribe",
                        "subscriber": session.username,
                        "target": user_part,
                    })
                    if not isinstance(resp, dict) or resp.get("status") != "ok":
                        self.send_message("Remote unsubscribe failed.", client_socket, client_key)
        except Exception:
            pass
        return True

    def handle_sub_list(self, args, session, client_socket, client_key, server_context=None):
        if not getattr(session, "username", None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True
        subs = sub_list(session.username)
        if not subs:
            self.send_message("Subscriptions list is empty.", client_socket, client_key)
        else:
            self.send_message("Subscriptions list: " + ", ".join(subs), client_socket, client_key)
        return True

    def handle_sub_clear(self, args, session, client_socket, client_key, server_context=None):
        if not getattr(session, "username", None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True
        try:
            for t in sub_list(session.username):
                if "@" not in t:
                    continue
                user_part, host_part = t.rsplit("@", 1)
                if host_part and host_part != _my_host():
                    _send_s2s(host_part, {
                        "type": "presence_unsubscribe",
                        "subscriber": session.username,
                        "target": user_part,
                    })
        except Exception:
            pass
        sub_clear(session.username)
        self.send_message("Subscriptions cleared.", client_socket, client_key)
        return True
