# LibreDM

A from-scratch server for the **DM** chat protocol, under **Apache-2.0**.


---

## Why does this exist?

The original **DMConnect** (and its server, DMCD) is under **AGPL/GPL**.

That matters if you want to:

- ship a modified server inside a commercial product,
- reuse the protocol code in a permissively licensed project,
- run a private fork without publishing your changes under AGPL.

LibreDM is a clean-room-style rewrite of the same *idea*: rooms, private
messages, optional encryption, Telnet-friendly clients, server-to-server
federation. It is licensed **Apache-2.0**, so you can use it and keep your
changes private.

It is **not** a drop-in fork of the AGPL codebase. The wire protocol for
**clients** is intentionally DMConnect-compatible. The **server-to-server**
protocol is not: LibreDM signs federated messages and refuses the old,
unauthenticated S2S by default.

---

## What you get

| Piece | What it is |
|---|---|
| Chat server | Rooms (`/join_server`), private messages (`/pm`), `/act`, `/help` |
| Clients | Anything that speaks DMConnect-style plain TCP — including the official-style `dsconnect.py` GUI and plain Telnet |
| Ports | `42439` plain text, `42440` Diffie-Hellman encrypted |
| Storage | SQLite by default, JSON optional |
| Auth | Username + password (PBKDF2-SHA256), rate limits, account lockout |
| Federation | Server-to-server (S2S) between LibreDM nodes, signed with Ed25519 |
| Extras | HTTP file upload, ignore lists, presence/status, message history (SQLite) |
| Native code | Optional C module (OpenSSL) for AES/PBKDF2/DH/HMAC |

---

## What it is not

- Not a web app. No HTTP UI, no browser client, no REST API.
- Not Slack/Discord/Mattermost. No SSO, no LDAP, no mobile push.
- Not compatible with **old DMConnect servers** for federation, unless you turn
  the security flags off (see `dmcd/config.py`).
- Not “E2EE everything”. The DMConnect client does RSA for private messages;
  chat lines on the wire are not end-to-end encrypted by the protocol.

---

## Quick start

Requirements: **Python 3.8+**, **pycryptodome**, OpenSSL headers (for the
optional native module).

```bash
pip install pycryptodome

# optional, recommended
python3 dmcd/native/build.py

# set admin password before first start (otherwise one is generated and printed)
export DMCD_ADMIN_PASSWORD='choose-something-long'

# edit dmcd/config.py — at least MY_SERVER_HOST
python3 DMCD.py
```

Server listens on `0.0.0.0:42439` and `0.0.0.0:42440` unless you change
`BIND_HOST` / ports in `dmcd/config.py`.

Connect with a DMConnect client or Telnet:

```bash
telnet your-server 42439
/login alice mypassword
/join_server general
hello
```

Full walkthrough: **[TUTORIAL.md](TUTORIAL.md)**.

---

## Configuration

All knobs live in [`dmcd/config.py`](dmcd/config.py). The ones you usually
touch:

```python
MY_SERVER_HOST = "chat.example.com"  # address other people use
ADMIN_USERNAME = "ADMIN"
BIND_HOST = "0.0.0.0"
TCP_PORT = 42439
ENCRYPTED_PORT = 42440

STORAGE_BACKEND = "sqlite"   # or "json"
DATABASE_FILE = "dmcd.db"

REQUIRE_ENCRYPTED_AUTH = False  # True if every client supports TLS/DH
TLS_CERTFILE = ""               # enable TLS for the client port
TLS_KEYFILE = ""
```

Data files (`dmcd.db`, uploads, identity keys) are always placed under the
project root, not under whatever directory you happened to `cd` into.

---

## Clients and compatibility

**Client protocol — compatible with DMConnect.**

The official-style Python client (`dsconnect.py`) works: plain TCP, commands
like `/login user pass` (no newline required), keepalive `/`, message format
`nick: text`. You can also use Telnet.

**Federation (S2S) — LibreDM-only by default.**

| | Old DMConnect server | LibreDM |
|---|---|---|
| Client login / chat | yes | yes |
| S2S with old DMCD | yes | **no** (signatures required) |
| S2S with other LibreDM | — | yes |
| Password storage | plain/md5 mess | PBKDF2 + salt |
| Dialback | always says “ok” | real outbound ledger check |

If you must talk to an old server for a while, `dmcd/config.py` has switches
(`S2S_REQUIRE_SIGNATURE`, `S2S_REQUIRE_ENCRYPTED`, `S2S_BLOCK_PRIVATE_HOSTS`).
That weakens security on purpose. Prefer a separate “gateway” instance for
legacy peers and keep the main server strict.

---

## Security (short version)

- Passwords: PBKDF2-HMAC-SHA256, salted, ~310k iterations.
- Transport on 42440: AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC).
- Diffie-Hellman (RFC 3526 2048-bit) with subgroup checks.
- S2S messages signed with Ed25519; peer keys pinned (TOFU or config).
- Dialback verifies that the other server really sent a given `msg_id`.
- Rate limits and account lockout on login.
- Path traversal and upload XSS are handled.

**Know this:**

- DMConnect clients use **plaintext** TCP unless you add TLS. On a shared
  network, anyone can see passwords and messages.
- There is no end-to-end encryption for room chat.
- `ADMIN` is just a username. The first account registered as `ADMIN` is the
  admin — set `DMCD_ADMIN_PASSWORD` on first boot.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

DMConnect is a separate project with its own (A)GPL license. LibreDM does not
contain that code. If you need strict AGPL compatibility with DMConnect
servers, use DMConnect itself.
