"""Server configuration. Edit these values before deployment."""

# Change this!
MY_SERVER_HOST = "example.com"
ADMIN_USERNAME = "ADMIN"

TCP_PORT = 42439
ENCRYPTED_PORT = 42440

# Optional TLS (PEM files). Leave empty to disable.
TLS_CERTFILE = ""
TLS_KEYFILE = ""

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

# Password hashing (PBKDF2-HMAC-SHA256)
PBKDF2_ITERATIONS = 310_000

# Rate limiting
LOGIN_RATE_LIMIT = 10        # attempts per window
LOGIN_RATE_WINDOW = 60.0     # seconds
REGISTER_RATE_LIMIT = 5
REGISTER_RATE_WINDOW = 60.0

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
