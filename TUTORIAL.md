# LibreDM Tutorial

How to run LibreDM and actually use it. 

---

## 1. Requirements

- Python 3.8 or newer
- `pycryptodome`
- For the optional fast crypto module: a C compiler and OpenSSL headers
  (`libssl-dev` on Debian/Ubuntu)

```bash
pip install pycryptodome

# Debian/Ubuntu, if you want the native module
sudo apt install build-essential libssl-dev python3-dev
```

---

## 2. Install

Clone or copy the project, then go into the folder:

```bash
cd DMCD
```

Build the optional native module (recommended, not required):

```bash
python3 dmcd/native/build.py
```

If this prints `built ...dmcd_native...so`, you are done. If it fails, the
server still runs — just slower on crypto.

---

## 3. Configure

Open `dmcd/config.py` in a text editor.

**You should change these:**

```python
MY_SERVER_HOST = "chat.example.com"
ADMIN_USERNAME = "ADMIN"
```

| Setting | What to put |
|---|---|
| `MY_SERVER_HOST` | DNS name or IP that other people use to reach the server. Used in file URLs and federation. |
| `ADMIN_USERNAME` | Name of the admin account. Do not register it yourself by hand — the server creates it on first start. |

**Optional:**

```python
BIND_HOST = "0.0.0.0"   # "0.0.0.0" = all interfaces; or a single IP
TCP_PORT = 42439        # plain clients (DMConnect / Telnet)
ENCRYPTED_PORT = 42440  # DH-encrypted clients
```

**Storage** (default is fine for almost everyone):

```python
STORAGE_BACKEND = "sqlite"   # or "json"
DATABASE_FILE = "dmcd.db"
```

SQLite file lives in the project folder as `dmcd.db`.

**TLS** (optional). If you have a certificate:

```python
TLS_CERTFILE = "/etc/ssl/certs/chat.pem"
TLS_KEYFILE = "/etc/ssl/private/chat.key"
```

Leave empty if you do not have one.

**Login over plaintext** (how DMConnect clients work):

```python
REQUIRE_ENCRYPTED_AUTH = False
```

`False` = official DMConnect clients can log in on port 42439 (passwords go
over the network in plain text).  
`True` = only TLS or DH-encrypted connections can log in. Stricter, but then
plain GUI clients will not work.

---

## 4. First start

Set the admin password **before** the first run:

```bash
export DMCD_ADMIN_PASSWORD='please-use-a-long-random-password'
python3 DMCD.py
```

You should see something like:

```
[12:00:00] Created admin account 'ADMIN'.
[12:00:00] Storage: sqlite /path/to/DMCD/dmcd.db
[12:00:00] TCP server started on 0.0.0.0:42439
[12:00:00] TCP encrypted server started on 0.0.0.0:42440
```

If you forgot `DMCD_ADMIN_PASSWORD`, the server generates one and **prints it
once** in the log. Save it, then change the password after login (see below).

Stop the server with `Ctrl+C`.

### systemd (optional)

Create `/etc/systemd/system/libredm.service`:

```ini
[Unit]
Description=LibreDM chat server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/DMCD
Environment=DMCD_ADMIN_PASSWORD=change-me
ExecStart=/usr/bin/python3 DMCD.py
Restart=on-failure
User=libredm

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now libredm
```

---

## 5. Connect

### Option A — DMConnect-style GUI client

Use any client that speaks the DM protocol (for example `dsconnect.py`).

1. Open the connect dialog.
2. Host: your `MY_SERVER_HOST` or IP.
3. Port: `42439`.
4. Then register or login from the menu.

### Option B — Telnet

```bash
telnet your-server 42439
```

You should see:

```
Enter command (/login /register):
```

---

## 6. Register and login

```
/register alice mypassword123
```

Rules:

- Username: letters, digits, `. _ -`, max 64 characters. No spaces.
- Password: at least 8 characters.
- `ADMIN`, `admin`, `system`, `root` are reserved.

Then:

```
/login alice mypassword123
```

You should get `Login successful.` and a list of rooms (servers).

There is **no** `/password` command yet. To rotate a password, ask an admin to
delete the account and register again, or update the hash in `dmcd.db`.

---

## 7. Rooms and chat

In DMConnect wording a room is called a **server**. Same thing.

```
/join_server general
```

Default room is `general`. Create another one:

```
/create_server project-x
/join_server project-x
```

List rooms:

```
/list_servers
```

People in the current room:

```
/members
```

Say something — just type a line without `/`:

```
hello everyone
```

Everyone in the room sees:

```
alice: hello everyone
```

### Commands cheat sheet

| Command | Meaning |
|---|---|
| `/login <user> <pass>` | Log in |
| `/register <user> <pass>` | Create account |
| `/join_server <room>` | Enter a room |
| `/create_server <room>` | Create a room |
| `/list_servers` | List rooms |
| `/members` | Who is in this room |
| `/pm <user> <text>` | Private message |
| `/act <text>` | Emote: `*** alice <text>` |
| `/history [n]` | Last n messages (SQLite only, default 50) |
| `/search <word>` | Search messages (SQLite only) |
| `/help` | Help |
| `/list_capabilities` | Extra plugins |
| `/` | Keepalive (what clients send) |

### Private messages

```
/pm bob this is secret
```

Bob sees:

```
(Private) alice: this is secret
```

DMConnect clients can also wrap PMs in RSA (client-side). The server only
forwards the text.

---

## 8. Admin

Login as `ADMIN` (the account created on first start).

```
/ban <username>
```

Disconnects that user and blocks them.

```
/delete_server <room>
```

Deletes a room you no longer need. You cannot delete `general`.

---

## 9. File upload (HTTP)

Get a token (must be logged in):

```
/http_file_upload token
```

You get something like:

```
Upload token (valid 86400s): <long-token>
```

Upload with `curl`:

```bash
curl -X POST http://your-server:42439/upload \
  -H "Authorization: Bearer <long-token>" \
  -F "file=@./notes.txt"
```

The answer is JSON with `url`. Share that URL to download the file.

Limits: see `MAX_UPLOAD_SIZE_BYTES` and `UPLOAD_TTL_SECONDS` in
`dmcd/config.py` (default 5 MB, 24 hours).

Do not put the token in the query string; use the `Authorization` header.

---

## 10. Ignore and status

```
/ignore-add <user>
/ignore-list
/ignore-del <user>
/ignore-clear
```

```
/status-check <user>
/status-sub-add <user>
/status-sub-list
```

Exact command names can be listed with `/list_capabilities` and
`/<capability>`.

---

## 11. Two servers (federation)

Only **LibreDM ↔ LibreDM** works by default. Old DMConnect servers will not
federate.

On both machines set a real `MY_SERVER_HOST` and open TCP between them.

Then from a client on server A:

```
/join_server room@other-host.example
/pm alice@other-host.example hello
```

Each server has a long-term signing key:

- `s2s_identity.pem` (created on first start, keep it private)
- `s2s_trusted_hosts.json` (pinned peer keys)

Backup those files with your database.

If the peer is on a private IP (LAN), set in `dmcd/config.py`:

```python
S2S_BLOCK_PRIVATE_HOSTS = False
S2S_ALLOWED_HOSTS = ["chat2.corp.local"]   # recommended
```

---

## 12. Backup

Stop the server (or not — SQLite WAL is safe), then copy:

```
dmcd.db
dmcd.db-wal
dmcd.db-shm
s2s_identity.pem
s2s_trusted_hosts.json
uploads/          # if you use file upload
```

Restore: put the files back in the project folder and start the server.

---

## 13. Troubleshooting

| Problem | What to do |
|---|---|
| `Login requires an encrypted connection` | You set `REQUIRE_ENCRYPTED_AUTH = True`. For DMConnect clients set it to `False`, or use TLS/DH. |
| `Username is reserved` | Do not use `ADMIN` / `system` / `root`. |
| `Account temporarily locked` | Too many bad passwords. Wait for the lockout (see `LOGIN_LOCKOUT_SECONDS`). |
| Users disappeared after restart | Data is always in `<project>/dmcd.db`, not in your shell’s current directory. Look at the log line `Storage: sqlite ...`. If you had an old `dmcd.db` in another folder, copy it into the project root. |
| `/history` says not available | You are on the JSON backend. Switch `STORAGE_BACKEND = "sqlite"`. |
| Federated messages fail | Other side is old DMCD, or `S2S_BLOCK_PRIVATE_HOSTS` blocks it, or signatures are off on one side. Check both logs. |
| Native module missing | `python3 dmcd/native/build.py`. Not fatal. |
| Password in old DB is plaintext | Set `ALLOW_LEGACY_PLAINTEXT_PASSWORDS = True`, log in once (it re-hashes), then set `False` again. |

---

## 14. Everyday checklist

```bash
# start
export DMCD_ADMIN_PASSWORD='...'   # only needed if admin does not exist yet
python3 DMCD.py

# backup
cp dmcd.db* /backup/
```

