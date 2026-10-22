"""Server configuration. Edit these values before deployment."""

import os

# Repository root (parent of the dmcd/ package). Data files are anchored here
# so the working directory at process start does not matter.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_path(name: str) -> str:
    """Absolute path for a data file/dir, relative names resolve to PROJECT_ROOT."""
    if os.path.isabs(name):
        return name
    return os.path.join(PROJECT_ROOT, name)


# Change this!
MY_SERVER_HOST = "example.com"
ADMIN_USERNAME = "ADMIN"

# TCP listeners
BIND_HOST = "0.0.0.0"
TCP_PORT = 42439
ENCRYPTED_PORT = 42440

# Connection sniffing / keepalive timings (seconds)
PEEK_TIMEOUT = 0.5
TLS_PEEK_TIMEOUT = 2.0
DRAIN_TIMEOUT = 0.15
CLEANUP_INTERVAL_SECONDS = 60
REMOTE_STATUS_TIMEOUT = 5.0
S2S_CAP_PROBE_TIMEOUT = 2.0

# Optional TLS (PEM files). Leave empty to disable.
TLS_CERTFILE = ""
TLS_KEYFILE = ""

# Reject /login and /register on unencrypted connections (plain TCP/Telnet).
# Official DMConnect clients (dsconnect.py and similar) speak plain text on
# TCP_PORT with no DH/TLS handshake — keep False for protocol compatibility.
# Set True only if every client supports TLS (TLS_CERTFILE) or the encrypted
# port's DH handshake.
REQUIRE_ENCRYPTED_AUTH = False

# Storage backend: "sqlite" or "json"
STORAGE_BACKEND = "sqlite"

# SQLite database file
DATABASE_FILE = "dmcd.db"

# JSON files (legacy, used when STORAGE_BACKEND = "json")
USERS_FILE = "users.json"
BANS_FILE = "bans.json"
SERVERS_DIR = "servers"
IGNORES_FILE = "ignores.json"
UPLOAD_TOKENS_FILE = "upload_tokens.json"
UPLOAD_DIR = "uploads"
STATUS_SUBS_FILE = "status_subs.json"
STATUS_REMOTE_SUBS_FILE = "status_remote_subs.json"

MAX_PACKET_SIZE = 32 * 1024
IV_SIZE = 16
MAC_SIZE = 32
# Must match #define IV_SIZE/MAC_SIZE/MAX_PACKET in dmcd/native/dmcd_native.c
DH_PRIV_BYTES = 32

# Input limits (DoS / injection hardening)
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 128
MAX_MESSAGE_LENGTH = 2000
MAX_LINE_BYTES = 8192

# S2S inbound rate limit (messages per IP per window)
S2S_RATE_LIMIT = 60
S2S_RATE_WINDOW = 60.0
S2S_MAX_USERNAMES_PER_REQUEST = 20

# Bounded worker pool for async S2S / fanout (replaces thread-per-message).
S2S_MAX_WORKERS = 32
S2S_WORK_QUEUE_SIZE = 256

# Diffie-Hellman: RFC 3526 2048-bit MODP group 14 by default.
# Set True only to interop with legacy clients on the original group.
LEGACY_DH_1024 = False

# Password hashing (PBKDF2-HMAC-SHA256)
PBKDF2_ITERATIONS = 310_000

# Legacy hash migration (old DMCD users.json / SQLite rows).
# Hex digests (md5/sha256/sha512) are accepted once and upgraded to PBKDF2
# on successful login. They are compared in constant time.
ALLOW_LEGACY_PASSWORD_HASHES = True
# Old DMCD stored some passwords in plaintext and accepted `stored == password`.
# Keep False: plaintext equality is disabled.
ALLOW_LEGACY_PLAINTEXT_PASSWORDS = False

# Rate limiting
LOGIN_RATE_LIMIT = 10        # attempts per window
LOGIN_RATE_WINDOW = 60.0     # seconds
REGISTER_RATE_LIMIT = 5
REGISTER_RATE_WINDOW = 60.0

# Per-account lockout after repeated failed logins
LOGIN_MAX_FAILURES = 5
LOGIN_FAILURE_WINDOW = 900.0   # seconds; failures older than this are ignored
LOGIN_LOCKOUT_SECONDS = 900.0

MAX_CONCURRENT_CONNECTIONS = 512
LISTEN_BACKLOG = 128

# S2S
S2S_MAGIC = b"DMCS\x01"
S2S_SESSION_TTL = 45
S2S_CONNECT_TIMEOUT = 4
S2S_IO_TIMEOUT = 5
S2S_CAP_TTL = 3600
S2S_PING_TIMEOUT = 8
S2S_PING_FAIL_THRESHOLD = 5
DIALBACK_CACHE_TTL = 3600
DIALBACK_OUTBOUND_TTL = 600
MAX_RETRIES = 2
RETRY_DELAY = 1

# Federation hardening
# Refuse cleartext S2S (no plain-JSON fallback).
S2S_REQUIRE_ENCRYPTED = True
# Require Ed25519 signatures on S2S messages (TOFU-pinned peer keys).
S2S_REQUIRE_SIGNATURE = True
# Refuse outbound S2S to loopback/RFC1918/link-local (SSRF).
S2S_BLOCK_PRIVATE_HOSTS = True
# Optional federation allowlist. Empty list = any public host.
S2S_ALLOWED_HOSTS = []
# Explicit peer key pins: {"peer.example.com": "<ed25519 der hex>"}.
S2S_TRUSTED_KEYS = {}
S2S_IDENTITY_FILE = "s2s_identity.pem"
S2S_TRUSTED_HOSTS_FILE = "s2s_trusted_hosts.json"

# HTTP upload
UPLOAD_TTL_SECONDS = 24 * 60 * 60
MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024

# Telnet / text stream
CTRL_ESC = 255
OPT_CMDS = {251, 252, 253, 254}
STREAM_ENCODINGS = ("cp866", "cp1251", "koi8-r")
ECHO_ERASE = b"\x08 \x08"
BACKSPACE_KEYS = (8, 127)

# Message send throttling (seconds between delayed messages; 0 = off)
SEND_DELAY_SECONDS = 0
DELAYED_MESSAGE_TYPES = frozenset()

DEFAULT_SERVER = "general"
