# SQLite Backend - Usage Guide

## New Features

### 1. Message History
```
# View last 50 messages in current room
/history

# View last 100 messages
/history 100

# Search messages
/search keyword

# Search in specific room
/search keyword general
```

### 2. Statistics (admin only)
```
# Server statistics
/stats
→ Total users: 42
→ Active rooms: 5
→ Messages today: 156
→ Top users: alice(23), bob(19), charlie(15)

# Room statistics
/room_stats general
→ Room: general
→ Members: 12
→ Messages: 1,234
→ Active users: alice(45), bob(32)
```

### 3. Performance
- Instant user lookups (indexed)
- Concurrent reads without blocking
- Transaction safety (ACID guarantees)
- Efficient message search

## Migration

### Automatic (recommended)
```bash
./migrate_to_sqlite.sh
```

This will:
1. Backup all JSON files → `backup_YYYY-MM-DD_HH-MM-SS/`
2. Migrate to SQLite
3. Test migration integrity
4. Update config automatically

### Manual
```bash
# 1. Backup
cp -r servers/ backup/
cp users.json bans.json backup/

# 2. Migrate
python3 scripts/migrate_to_sqlite.py

# 3. Test
python3 test_migration.py

# 4. Update config
# Edit dmcd/config.py:
STORAGE_BACKEND = "sqlite"
```

## Rollback to JSON

```bash
# Edit dmcd/config.py:
STORAGE_BACKEND = "json"

# Restore backup if needed
cp -r backup_YYYY-MM-DD_HH-MM-SS/* .
```

## Configuration

In `dmcd/config.py`:
```python
STORAGE_BACKEND = "sqlite"  # or "json"
SQLITE_DB = "dmcd.db"
MESSAGE_HISTORY_LIMIT = 1000  # per room
MESSAGE_SEARCH_LIMIT = 50
```

## Database Maintenance

### Backup
```bash
# Online backup (no downtime)
sqlite3 dmcd.db ".backup backup.db"
```

### Optimize
```bash
# Compact database (run weekly)
sqlite3 dmcd.db "VACUUM"
```

### Inspect
```bash
# Open SQL shell
sqlite3 dmcd.db

# Useful queries:
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM messages;
SELECT room, COUNT(*) FROM messages GROUP BY room;
```

## Performance Tuning

### For high-traffic servers (>100 concurrent users):
```python
# dmcd/config.py
SQLITE_DB = "dmcd.db"
SQLITE_BUSY_TIMEOUT = 5000  # 5 seconds
SQLITE_CACHE_SIZE = -64000  # 64MB cache
```

### For message-heavy rooms:
```python
MESSAGE_HISTORY_LIMIT = 10000  # keep more history
MESSAGE_SEARCH_LIMIT = 100    # return more results
```

## Troubleshooting

### "database is locked"
Increase busy timeout in `storage_sqlite.py`:
```python
conn.execute("PRAGMA busy_timeout = 10000")  # 10 seconds
```

### Slow searches
Add custom indexes:
```sql
CREATE INDEX idx_messages_sender ON messages(sender);
CREATE INDEX idx_messages_fulltext ON messages(text);
```

### Database corruption
```bash
# Check integrity
sqlite3 dmcd.db "PRAGMA integrity_check"

# Recover from backup
cp backup.db dmcd.db
```

## API for Capabilities

New capabilities can use `app.messages`:
```python
from dmcd.app import app

# Get last 100 messages from room
if app.messages:
    history = app.messages.get_history("general", limit=100)
    for msg in history:
        print(f"{msg['sender']}: {msg['text']}")

# Search messages
if app.messages:
    results = app.messages.search("keyword", room="general")
```
