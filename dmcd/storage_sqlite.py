"""SQLite storage backend for LibreDM."""

import sqlite3
import threading
from datetime import datetime, timedelta
from . import config


class SQLiteConnection:
    """Thread-local SQLite connection pool."""

    def __init__(self, db_path):
        self.db_path = db_path
        self._local = threading.local()

    def get(self):
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for concurrent reads
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def checkpoint(self):
        """Fold WAL into the main database file (durability)."""
        try:
            self.get().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            pass


class SQLiteUserStore:
    """User storage backed by SQLite."""

    def __init__(self, conn_pool):
        self.conn = conn_pool

    def exists(self, username):
        db = self.conn.get()
        cur = db.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cur.fetchone() is not None

    def get_hash(self, username):
        db = self.conn.get()
        cur = db.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        )
        row = cur.fetchone()
        return row["password_hash"] if row else None

    def register(self, username, password):
        """Register new user with password hashing. Returns True if created, False if exists."""
        from dmcd.crypto import hash_password

        db = self.conn.get()
        if self.exists(username):
            return False

        password_hash = hash_password(password)
        db.execute(
            """INSERT INTO users (username, password_hash, created_at)
               VALUES (?, ?, ?)""",
            (username, password_hash, datetime.utcnow().isoformat()),
        )
        db.commit()
        return True

    def set_hash(self, username, password_hash):
        db = self.conn.get()
        db.execute(
            """INSERT INTO users (username, password_hash, created_at)
               VALUES (?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash""",
            (username, password_hash, datetime.utcnow().isoformat()),
        )
        db.commit()

    def remove(self, username):
        """Remove a user from the database."""
        db = self.conn.get()
        db.execute("DELETE FROM users WHERE username = ?", (username,))
        db.commit()

    def usernames(self):
        db = self.conn.get()
        cur = db.execute("SELECT username FROM users ORDER BY username")
        return [row["username"] for row in cur.fetchall()]


class SQLiteBanStore:
    """Ban storage backed by SQLite."""

    def __init__(self, conn_pool):
        self.conn = conn_pool

    def is_banned(self, username):
        db = self.conn.get()
        cur = db.execute("SELECT 1 FROM bans WHERE username = ?", (username,))
        return cur.fetchone() is not None

    def ban(self, username, reason=""):
        db = self.conn.get()
        db.execute(
            """INSERT INTO bans (username, reason, banned_at)
               VALUES (?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET reason = excluded.reason""",
            (username, reason, datetime.utcnow().isoformat()),
        )
        db.commit()

    def unban(self, username):
        db = self.conn.get()
        db.execute("DELETE FROM bans WHERE username = ?", (username,))
        db.commit()

    def all(self):
        db = self.conn.get()
        cur = db.execute("SELECT username, reason, banned_at FROM bans")
        return {
            row["username"]: {"reason": row["reason"], "banned_at": row["banned_at"]}
            for row in cur.fetchall()
        }


class SQLiteRoomStore:
    """Room storage backed by SQLite."""

    def __init__(self, conn_pool):
        self.conn = conn_pool

    def exists(self, room_name):
        db = self.conn.get()
        cur = db.execute("SELECT 1 FROM rooms WHERE name = ?", (room_name,))
        return cur.fetchone() is not None

    def create(self, room_name):
        """Create a room. Returns True if created, False if it already exists."""
        db = self.conn.get()
        cur = db.execute(
            "INSERT OR IGNORE INTO rooms (name, created_at) VALUES (?, ?)",
            (room_name, datetime.utcnow().isoformat()),
        )
        db.commit()
        return cur.rowcount > 0

    def delete(self, room_name):
        """Delete a room. Returns True if deleted, False if it did not exist."""
        db = self.conn.get()
        # Foreign key cascade will delete members
        cur = db.execute("DELETE FROM rooms WHERE name = ?", (room_name,))
        db.commit()
        return cur.rowcount > 0

    def add_member(self, room_name, username):
        db = self.conn.get()
        db.execute(
            """INSERT OR IGNORE INTO room_members (room, username, joined_at)
               VALUES (?, ?, ?)""",
            (room_name, username, datetime.utcnow().isoformat()),
        )
        db.commit()

    def remove_member(self, room_name, username):
        db = self.conn.get()
        db.execute(
            "DELETE FROM room_members WHERE room = ? AND username = ?",
            (room_name, username),
        )
        db.commit()

    def members(self, room_name):
        db = self.conn.get()
        cur = db.execute(
            "SELECT username FROM room_members WHERE room = ?", (room_name,)
        )
        return [row["username"] for row in cur.fetchall()]

    def names(self):
        db = self.conn.get()
        cur = db.execute("SELECT name FROM rooms ORDER BY name")
        return [row["name"] for row in cur.fetchall()]


class SQLiteTokenStore:
    """Upload token storage backed by SQLite."""

    def __init__(self, conn_pool):
        self.conn = conn_pool

    def issue(self, username, ttl_seconds=86400):
        """Issue a new token with TTL. Returns token string."""
        import secrets

        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

        db = self.conn.get()
        db.execute(
            "INSERT OR REPLACE INTO upload_tokens (token, username, expires_at) VALUES (?, ?, ?)",
            (token, username, expires_at.isoformat()),
        )
        db.commit()
        return token

    def validate(self, token):
        """Validate token and return username if valid, None otherwise. Cleans up expired tokens."""
        if not token:
            return None

        db = self.conn.get()
        cur = db.execute(
            "SELECT username, expires_at FROM upload_tokens WHERE token = ?", (token,)
        )
        row = cur.fetchone()

        if not row:
            return None

        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at < datetime.utcnow():
            # Token expired, delete it
            db.execute("DELETE FROM upload_tokens WHERE token = ?", (token,))
            db.commit()
            return None

        return row["username"]

    def revoke(self, token):
        """Revoke (delete) a token."""
        db = self.conn.get()
        db.execute("DELETE FROM upload_tokens WHERE token = ?", (token,))
        db.commit()

    def create(self, token, username, expires_at):
        db = self.conn.get()
        db.execute(
            "INSERT OR REPLACE INTO upload_tokens (token, username, expires_at) VALUES (?, ?, ?)",
            (token, username, expires_at),
        )
        db.commit()

    def get(self, token):
        db = self.conn.get()
        cur = db.execute(
            "SELECT username, expires_at FROM upload_tokens WHERE token = ?", (token,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return {"username": row["username"], "expires_at": row["expires_at"]}

    def delete(self, token):
        db = self.conn.get()
        db.execute("DELETE FROM upload_tokens WHERE token = ?", (token,))
        db.commit()

    def cleanup_expired(self, now_iso):
        db = self.conn.get()
        db.execute("DELETE FROM upload_tokens WHERE expires_at < ?", (now_iso,))
        db.commit()


class SQLiteMessageStore:
    """Message history storage (SQLite only)."""

    def __init__(self, conn_pool):
        self.conn = conn_pool

    def save_message(self, room, sender, text, origin_host=None):
        """Save a chat message."""
        if origin_host is None:
            origin_host = config.MY_SERVER_HOST
        db = self.conn.get()
        db.execute(
            """INSERT INTO messages (room, sender, origin_host, text, sent_at)
               VALUES (?, ?, ?, ?, ?)""",
            (room, sender, origin_host, text, datetime.utcnow().isoformat()),
        )
        db.commit()

    def get_recent_messages(self, room, limit=50):
        """Get recent messages from a room."""
        db = self.conn.get()
        cur = db.execute(
            """SELECT sender, origin_host, text, sent_at
               FROM messages
               WHERE room = ?
               ORDER BY sent_at DESC
               LIMIT ?""",
            (room, limit),
        )
        messages = cur.fetchall()
        # Return in chronological order (oldest first)
        return [
            {
                "sender": row["sender"],
                "origin_host": row["origin_host"],
                "text": row["text"],
                "sent_at": row["sent_at"],
            }
            for row in reversed(messages)
        ]

    def search_messages(self, room, keyword, limit=100):
        """Search messages containing keyword."""
        db = self.conn.get()
        cur = db.execute(
            """SELECT sender, origin_host, text, sent_at
               FROM messages
               WHERE room = ? AND text LIKE ?
               ORDER BY sent_at DESC
               LIMIT ?""",
            (room, f"%{keyword}%", limit),
        )
        messages = cur.fetchall()
        return [
            {
                "sender": row["sender"],
                "origin_host": row["origin_host"],
                "text": row["text"],
                "sent_at": row["sent_at"],
            }
            for row in reversed(messages)
        ]


def init_db(db_path):
    """Initialize SQLite database schema."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # Create schema
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS bans (
            username TEXT PRIMARY KEY,
            reason TEXT,
            banned_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS rooms (
            name TEXT PRIMARY KEY,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS room_members (
            room TEXT NOT NULL,
            username TEXT NOT NULL,
            joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (room, username),
            FOREIGN KEY (room) REFERENCES rooms(name) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS upload_tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            sender TEXT NOT NULL,
            origin_host TEXT NOT NULL,
            text TEXT NOT NULL,
            sent_at TEXT NOT NULL,
            FOREIGN KEY (room) REFERENCES rooms(name) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_messages_room_time ON messages(room, sent_at DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_search ON messages(room, text);
        CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(username);
        CREATE INDEX IF NOT EXISTS idx_tokens_expires ON upload_tokens(expires_at);
        """
    )

    conn.commit()
    conn.close()

