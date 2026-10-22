"""Thread-safe JSON persistence for users, bans, rooms, and tokens."""

import json
import os
import threading
import time

from dmcd import config


class JsonStore:
    """A JSON object file guarded by an RLock."""

    def __init__(self, path: str, default=None):
        self.path = path
        self._default = default if default is not None else {}
        self._lock = threading.RLock()
        self._data = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return json.loads(json.dumps(self._default))
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return json.loads(json.dumps(self._default))

    def save(self):
        with self._lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=4)
            os.replace(tmp, self.path)

    def get(self, key, default=None):
        with self._lock:
            return self._data.get(key, default)

    def __contains__(self, key):
        with self._lock:
            return key in self._data

    def __getitem__(self, key):
        with self._lock:
            return self._data[key]

    def __setitem__(self, key, value):
        with self._lock:
            self._data[key] = value
            self.save()

    def __delitem__(self, key):
        with self._lock:
            del self._data[key]
            self.save()

    def pop(self, key, default=None):
        with self._lock:
            val = self._data.pop(key, default)
            self.save()
            return val

    def keys(self):
        with self._lock:
            return list(self._data.keys())

    def items(self):
        with self._lock:
            return list(self._data.items())

    def get_all(self):
        with self._lock:
            return json.loads(json.dumps(self._data))

    def set_all(self, data):
        with self._lock:
            self._data = data
            self.save()

    @property
    def lock(self):
        return self._lock


class RoomStore:
    """servers/ directory: one JSON file per room holding its member list."""

    def __init__(self, directory: str):
        self.dir = directory
        self._lock = threading.RLock()
        self._rooms = {}
        os.makedirs(self.dir, exist_ok=True)
        self._load_all()

    def _load_all(self):
        for filename in os.listdir(self.dir):
            if filename.endswith(".json"):
                name = filename[:-5]
                try:
                    with open(os.path.join(self.dir, filename), "r", encoding="utf-8") as f:
                        self._rooms[name] = json.load(f)
                except Exception:
                    self._rooms[name] = []

    def _persist(self, name: str):
        path = self._path_for(name)
        if not path:
            return
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._rooms.get(name, []), f, ensure_ascii=False, indent=4)
        os.replace(tmp, path)

    def names(self):
        with self._lock:
            return list(self._rooms.keys())

    def exists(self, name: str) -> bool:
        with self._lock:
            return name in self._rooms

    def members(self, name: str):
        with self._lock:
            return list(self._rooms.get(name, []))

    def _path_for(self, name: str):
        safe = name.replace("/", "_").replace("\\", "_").replace("\x00", "").replace("..", "_")
        if not safe or safe.strip("."):
            pass
        else:
            return None
        path = os.path.join(self.dir, f"{safe}.json")
        real_dir = os.path.realpath(self.dir)
        real_path = os.path.realpath(path)
        if real_path != real_dir and not real_path.startswith(real_dir + os.sep):
            return None
        return path

    def create(self, name: str):
        with self._lock:
            if name in self._rooms:
                return False
            path = self._path_for(name)
            if not path:
                return False
            self._rooms[name] = []
            self._persist(name)
            return True

    def delete(self, name: str):
        with self._lock:
            if name not in self._rooms:
                return False
            del self._rooms[name]
            path = self._path_for(name)
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass
            return True

    def add_member(self, room: str, username: str):
        with self._lock:
            members = self._rooms.get(room)
            if members is None:
                return
            if username not in members:
                members.append(username)
                self._persist(room)

    def remove_member(self, room: str, username: str):
        with self._lock:
            members = self._rooms.get(room)
            if members is None:
                return
            if username in members:
                members.remove(username)
                self._persist(room)


class TokenStore:
    """Named tokens with expiry (used for HTTP upload auth)."""

    def __init__(self, path: str):
        self._store = JsonStore(path, default={})
        self._lock = self._store.lock

    def issue(self, username: str, ttl_seconds: int = 86400) -> str:
        import secrets
        token = secrets.token_urlsafe(32)
        with self._lock:
            data = self._store.get_all()
            now = time.time()
            data = {k: v for k, v in data.items() if v.get("expires", 0) > now}
            data[token] = {"user": username, "expires": now + ttl_seconds}
            self._store.set_all(data)
        return token

    def validate(self, token: str):
        if not token:
            return None
        with self._lock:
            data = self._store.get_all()
            rec = data.get(token)
            if not rec:
                return None
            if rec.get("expires", 0) < time.time():
                data.pop(token, None)
                self._store.set_all(data)
                return None
            return rec.get("user")

    def revoke(self, token: str):
        with self._lock:
            data = self._store.get_all()
            if token in data:
                data.pop(token, None)
                self._store.set_all(data)


class UserStore:
    """Users with PBKDF2 hashes and atomic registration."""

    def __init__(self, path: str):
        self._store = JsonStore(path, default={})
        self._lock = self._store.lock

    def exists(self, username: str) -> bool:
        return username in self._store

    def get_hash(self, username: str):
        return self._store.get(username)

    def register(self, username: str, password: str) -> bool:
        from dmcd.crypto import hash_password
        with self._lock:
            if username in self._store:
                return False
            self._store[username] = hash_password(password)
            return True

    def set_hash(self, username: str, password_hash: str):
        self._store[username] = password_hash

    def remove(self, username: str):
        if username in self._store:
            del self._store[username]

    def usernames(self):
        return self._store.keys()


class BanStore:
    def __init__(self, path: str):
        self._store = JsonStore(path, default={})

    def is_banned(self, username: str) -> bool:
        return username in self._store

    def ban(self, username: str, reason: str = "BANNED"):
        self._store[username] = reason

    def unban(self, username: str):
        if username in self._store:
            del self._store[username]
