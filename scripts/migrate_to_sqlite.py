#!/usr/bin/env python3
"""Migrate data from JSON files to SQLite database."""

import sys
import os
import json

# Add parent dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dmcd import config
from dmcd.storage import UserStore, BanStore, RoomStore, TokenStore
from dmcd.storage_sqlite import (
    SQLiteUserStore,
    SQLiteBanStore,
    SQLiteRoomStore,
    SQLiteTokenStore,
    SQLiteConnection,
)


def migrate():
    """Migrate all data from JSON to SQLite."""
    print(f"Migrating from JSON to SQLite ({config.DATABASE_FILE})...")

    # Initialize SQLite database schema
    from dmcd.storage_sqlite import init_db
    init_db(config.DATABASE_FILE)

    # Load JSON stores
    json_users = UserStore(config.USERS_FILE)
    json_bans = BanStore(config.BANS_FILE)
    json_rooms = RoomStore(config.SERVERS_DIR)
    json_tokens = TokenStore(config.UPLOAD_TOKENS_FILE)

    # Create SQLite connection
    db = SQLiteConnection(config.DATABASE_FILE)

    # Initialize SQLite stores
    sqlite_users = SQLiteUserStore(db)
    sqlite_bans = SQLiteBanStore(db)
    sqlite_rooms = SQLiteRoomStore(db)
    sqlite_tokens = SQLiteTokenStore(db)

    # Migrate users
    print("Migrating users...")
    user_count = 0
    for username in json_users.usernames():
        password_hash = json_users.get_hash(username)
        if password_hash:
            conn = db.get()
            conn.execute(
                "INSERT OR REPLACE INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            conn.commit()
            user_count += 1
    print(f"✓ Migrated {user_count} users")

    # Migrate bans
    print("Migrating bans...")
    ban_count = 0
    with json_bans._store.lock:
        bans_data = json_bans._store.get_all()
        conn = db.get()
        for username, reason in bans_data.items():
            conn.execute(
                "INSERT OR REPLACE INTO bans (username, reason) VALUES (?, ?)",
                (username, reason or ""),
            )
            ban_count += 1
        conn.commit()
    print(f"✓ Migrated {ban_count} bans")

    # Migrate rooms
    print("Migrating rooms...")
    room_count = 0
    member_count = 0
    conn = db.get()
    with json_rooms._lock:
        for room_name in json_rooms.names():
            # Create room
            conn.execute("INSERT OR IGNORE INTO rooms (name) VALUES (?)", (room_name,))
            room_count += 1

            # Migrate members
            members = json_rooms.members(room_name)
            for member in members:
                # Extract username (handle remote users like "user@host.com")
                username = member.split("@")[0] if "@" in member else member
                conn.execute(
                    "INSERT OR IGNORE INTO room_members (room, username) VALUES (?, ?)",
                    (room_name, username),
                )
                member_count += 1
        conn.commit()

    print(f"✓ Migrated {room_count} rooms with {member_count} members")

    # Migrate tokens
    print("Migrating upload tokens...")
    token_count = 0
    conn = db.get()
    with json_tokens._lock:
        tokens_data = json_tokens._store.get_all()
        for token, data in tokens_data.items():
            username = data.get("username", "")
            expires = data.get("expires_at", 0)
            conn.execute(
                "INSERT OR REPLACE INTO upload_tokens (token, username, expires_at) VALUES (?, ?, ?)",
                (token, username, expires),
            )
            token_count += 1
        conn.commit()
    print(f"✓ Migrated {token_count} upload tokens")

    print("\n Migration completed successfully!")
    print(f"   Users: {user_count}")
    print(f"   Bans: {ban_count}")
    print(f"   Rooms: {room_count}")
    print(f"   Members: {member_count}")
    print(f"   Tokens: {token_count}")
    print(f"\nDatabase: {config.DATABASE_FILE}")


if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
