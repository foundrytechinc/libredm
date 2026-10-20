# LibreDM

Free (Apache-2.0) server implementation of the decentralized **DM** protocol,
written from scratch to unencumber the protocol from GPL/AGPL copyleft.

Lightweight TCP chat backend with rooms, private messages, Telnet support,
and federation between servers (S2S). You can connect with Telnet or any
raw TCP client.

> [!Note]
> Protocol documentation (DM): [DMconnect wiki](https://github.com/DMconnect/DMCD/wiki/Protocol-documentation.)

## Requirements

- **Python 3.8+**
- **pycryptodome**

## Storage Backends

LibreDM supports two storage backends:

### JSON (Default)
- Simple file-based storage
- Good for small deployments (< 100 users)
- No dependencies

### SQLite (Recommended)
- **10-100x faster** queries
- Concurrent access with WAL mode
- Message history & search
- ACID transactions

**Enable SQLite:**
```python
# dmcd/config.py
STORAGE_BACKEND = "sqlite"
```

**Migrate from JSON:**
```bash
python3 scripts/migrate_to_sqlite.py
```

See [SQLITE_MIGRATION.md](docs/SQLITE_MIGRATION.md) for details.

---

## Installation

1. Clone or download this repository.

2. Install the dependency:

```bash
pip install pycryptodome
```

On Debian/Ubuntu you can use the system package instead:

```bash
sudo apt install python3-pycryptodome
```

3. Edit `dmcd/config.py` and set:

- `MY_SERVER_HOST` — your server's public domain name or IP
- `ADMIN_USERNAME` — administrator username

4. Start the server:

```bash
python3 DMCD.py
```

## Architecture

```
DMCD.py                entry point
dmcd/
  config.py            settings (host, ports, limits, storage backend)
  crypto.py            PBKDF2 passwords, AES-CBC + HMAC (Encrypt-then-MAC), DH
  storage.py           JSON backend (thread-safe)
  storage_sqlite.py    SQLite backend (concurrent, ACID, message history)
  storage_factory.py   backend selection
  migrate_json_to_sqlite.py  data migration tool
  sessions.py          connected client registry
  rooms.py             room membership and broadcasting
  textstream.py        Telnet / line editing / encodings
  s2s.py               federation transport + dialback ledger
  s2s_handler.py       inbound S2S message processing
  commands.py          chat commands
  client.py            per-connection protocol loop
  server.py            TCP listeners and maintenance
  ratelimit.py         per-IP rate limiting
caps/                  capability plugins (auto-loaded)
```

## Storage Backends

LibreDM supports two storage backends:

- **JSON** (default) — simple, file-based, human-readable
- **SQLite** — fast, concurrent, with message history and search

To enable SQLite:

```bash
./migrate_to_sqlite.sh
```

See [SQLITE_MIGRATION.md](SQLITE_MIGRATION.md) for details.

### SQLite Features

- **Message history**: `/history [limit]`
- **Search**: `/search <keyword>`
- **10-100x faster** queries for large installations
- **Concurrent writes** (no race conditions)
- **ACID transactions**

## Security notes

- Passwords are stored as salted PBKDF2-HMAC-SHA256 (legacy hashes are upgraded on login).
- Encrypted transport uses AES-CBC with mandatory HMAC-SHA256 (Encrypt-then-MAC).
- S2S dialback is a real challenge-response: a message is accepted only if the
  originating server confirms it actually sent that `msg_id`.
- HTTP file upload requires a bearer token issued to a logged-in user
  (`/http_file_upload token`).
- Login and registration are rate-limited per IP.
- Optional TLS can be enabled via `TLS_CERTFILE` / `TLS_KEYFILE` in `dmcd/config.py`.

## License

LibreDM is licensed under the **Apache License, Version 2.0** — free of GPL
constraints, so the DM protocol stack can be reused in permissive projects.

See the [LICENSE](LICENSE) file for details.
