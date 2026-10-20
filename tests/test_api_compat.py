#!/usr/bin/env python3
"""Test API compatibility between JSON and SQLite stores."""

import inspect
from dmcd.storage import UserStore, BanStore, RoomStore, TokenStore
from dmcd.storage_sqlite import (
    SQLiteUserStore,
    SQLiteBanStore,
    SQLiteRoomStore,
    SQLiteTokenStore,
)


def get_public_methods(cls):
    """Get all public methods of a class (excluding __init__)."""
    return {
        name
        for name, _ in inspect.getmembers(cls, predicate=inspect.isfunction)
        if not name.startswith("_") or name == "__contains__"
    }


def compare_apis(json_cls, sqlite_cls, name):
    """Compare methods between JSON and SQLite implementations."""
    json_methods = get_public_methods(json_cls)
    sqlite_methods = get_public_methods(sqlite_cls)

    missing = json_methods - sqlite_methods
    extra = sqlite_methods - json_methods

    print(f"\n=== {name} ===")
    print(f"JSON methods:   {sorted(json_methods)}")
    print(f"SQLite methods: {sorted(sqlite_methods)}")

    if missing:
        print(f"❌ Missing in SQLite: {sorted(missing)}")
        return False
    elif extra:
        print(f" Compatible (SQLite has extra: {sorted(extra)})")
        return True
    else:
        print(f" Perfect match")
        return True


def main():
    """Run API compatibility tests."""
    print("API Compatibility Check: JSON vs SQLite Stores")
    print("=" * 60)

    results = []
    results.append(compare_apis(UserStore, SQLiteUserStore, "UserStore"))
    results.append(compare_apis(BanStore, SQLiteBanStore, "BanStore"))
    results.append(compare_apis(RoomStore, SQLiteRoomStore, "RoomStore"))
    results.append(compare_apis(TokenStore, SQLiteTokenStore, "TokenStore"))

    print("\n" + "=" * 60)
    if all(results):
        print(" ALL STORES COMPATIBLE")
        return 0
    else:
        print("❌ COMPATIBILITY ISSUES FOUND")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
