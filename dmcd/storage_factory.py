"""Storage backend factory."""

from . import config


def init_storage():
    """Initialize storage backend based on config.STORAGE_BACKEND."""
    return create_stores()


def create_stores():
    """Create storage backends based on config.STORAGE_BACKEND."""
    backend = config.STORAGE_BACKEND

    if backend == "json":
        from .storage import UserStore, BanStore, RoomStore, TokenStore

        return {
            "users": UserStore(config.USERS_FILE),
            "bans": BanStore(config.BANS_FILE),
            "rooms": RoomStore(config.SERVERS_DIR),
            "tokens": TokenStore(config.UPLOAD_TOKENS_FILE),
            "messages": None,  # JSON backend doesn't support message history
            "db": None,  # No direct DB access for JSON
        }

    elif backend == "sqlite":
        from .storage_sqlite import (
            SQLiteConnection,
            SQLiteUserStore,
            SQLiteBanStore,
            SQLiteRoomStore,
            SQLiteTokenStore,
            SQLiteMessageStore,
        )

        # Initialize schema if needed
        db_path = config.DATABASE_FILE
        _init_sqlite_schema(db_path)

        conn_pool = SQLiteConnection(db_path)
        return {
            "users": SQLiteUserStore(conn_pool),
            "bans": SQLiteBanStore(conn_pool),
            "rooms": SQLiteRoomStore(conn_pool),
            "tokens": SQLiteTokenStore(conn_pool),
            "messages": SQLiteMessageStore(conn_pool),
            "db": conn_pool,  # Direct DB access if needed
        }

    else:
        raise ValueError(f"STORAGE_BACKEND must be 'json' or 'sqlite', got '{backend}'")


def _init_sqlite_schema(db_path):
    """Create SQLite schema if it doesn't exist."""
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # Users
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Bans
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bans (
            username TEXT PRIMARY KEY,
            reason TEXT,
            banned_at TEXT NOT NULL
        )
    """)

    # Rooms
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            name TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
    """)

    # Room members
    conn.execute("""
        CREATE TABLE IF NOT EXISTS room_members (
            room TEXT NOT NULL,
            username TEXT NOT NULL,
            joined_at TEXT NOT NULL,
            PRIMARY KEY (room, username),
            FOREIGN KEY (room) REFERENCES rooms(name) ON DELETE CASCADE
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_members_room ON room_members(room)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_members_username ON room_members(username)"
    )

    # Upload tokens
    conn.execute("""
        CREATE TABLE IF NOT EXISTS upload_tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_upload_tokens_expires ON upload_tokens(expires_at)"
    )

    # Messages (history)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            sender TEXT NOT NULL,
            origin_host TEXT NOT NULL,
            text TEXT NOT NULL,
            sent_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_room_time ON messages(room, sent_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_search ON messages(room, text)"
    )

    conn.commit()
    conn.close()
