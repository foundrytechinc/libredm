"""Application context: wires storage, sessions, rooms, S2S, capabilities."""

import secrets
import threading

from dmcd import config
from dmcd.storage_factory import init_storage
from dmcd.sessions import SessionRegistry, registry
from dmcd.rooms import RoomManager
from dmcd.s2s import S2SLink, DialbackLedger, DialbackChecker, log_message
from dmcd.s2s_identity import S2SIdentity
from dmcd.ratelimit import RateLimiter, AccountLockout
from dmcd.jobs import BoundedTaskPool


class App:
    def __init__(self):
        # Initialize storage backend (SQLite or JSON)
        stores = init_storage()
        self.users = stores["users"]
        self.bans = stores["bans"]
        self.rooms_store = stores["rooms"]
        self.upload_tokens = stores["tokens"]
        self.messages = stores["messages"]  # None if JSON backend
        self.db = stores["db"]  # None if JSON backend
        if self.db is not None:
            log_message(f"Storage: sqlite {config.data_path(config.DATABASE_FILE)}")
        else:
            log_message(f"Storage: json under {config.PROJECT_ROOT}")

        # Use the global registry singleton to avoid duplicate instances
        self.sessions = registry
        self.rooms = RoomManager(self.rooms_store)

        self.outbound_dialback = DialbackLedger()
        self.s2s_identity = S2SIdentity()
        self.s2s = S2SLink(self.get_advertised_host, self.outbound_dialback, self.s2s_identity)
        self.dialback = DialbackChecker(self.s2s, self.get_advertised_host)

        self.login_limiter = RateLimiter(config.LOGIN_RATE_LIMIT, config.LOGIN_RATE_WINDOW)
        self.register_limiter = RateLimiter(config.REGISTER_RATE_LIMIT, config.REGISTER_RATE_WINDOW)
        self.s2s_limiter = RateLimiter(config.S2S_RATE_LIMIT, config.S2S_RATE_WINDOW)
        self.login_lockout = AccountLockout(
            config.LOGIN_MAX_FAILURES,
            config.LOGIN_FAILURE_WINDOW,
            config.LOGIN_LOCKOUT_SECONDS,
        )
        self.task_pool = BoundedTaskPool(
            config.S2S_MAX_WORKERS, config.S2S_WORK_QUEUE_SIZE, name="s2s"
        )

        self.capabilities_manager = None  # set after caps import
        self.message_filter = None        # callable(recipient, sender, context) -> bool

        self._conn_semaphore = threading.BoundedSemaphore(config.MAX_CONCURRENT_CONNECTIONS)

        if not self.rooms_store.exists(config.DEFAULT_SERVER):
            self.rooms_store.create(config.DEFAULT_SERVER)

        self._ensure_admin_account()
        self._audit_password_hashes()

    def _audit_password_hashes(self):
        """Warn about accounts still on legacy/plaintext password storage."""
        try:
            names = list(self.users.usernames())
        except Exception:
            return
        legacy = plaintext = 0
        for name in names:
            try:
                stored = self.users.get_hash(name)
            except Exception:
                continue
            from dmcd import crypto
            if crypto.looks_like_legacy_hash(stored):
                legacy += 1
            elif crypto.looks_like_plaintext_password(stored):
                plaintext += 1
        if legacy:
            log_message(
                f"{legacy} account(s) use legacy hex password hashes; "
                f"they will be upgraded to PBKDF2 at next successful login."
            )
        if plaintext and not config.ALLOW_LEGACY_PLAINTEXT_PASSWORDS:
            log_message(
                f"{plaintext} account(s) store plaintext passwords and cannot log in "
                f"unless ALLOW_LEGACY_PLAINTEXT_PASSWORDS is enabled. Reset those passwords."
            )
        elif plaintext:
            log_message(
                f"WARNING: {plaintext} account(s) still have plaintext passwords "
                f"(ALLOW_LEGACY_PLAINTEXT_PASSWORDS=True)."
            )

    def _ensure_admin_account(self):
        """Bootstrap the admin account so nobody can squat ADMIN_USERNAME."""
        admin = config.ADMIN_USERNAME
        if self.users.exists(admin):
            return
        import os
        password = os.environ.get("DMCD_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
        self.users.register(admin, password)
        log_message(
            f"Created admin account '{admin}'. "
            f"Set DMCD_ADMIN_PASSWORD before first start to choose the password."
        )
        if not os.environ.get("DMCD_ADMIN_PASSWORD"):
            log_message(f"TEMPORARY admin password (change it now): {password}")

    def get_advertised_host(self) -> str:
        return config.MY_SERVER_HOST

    def should_filter_message(self, recipient, sender, context) -> bool:
        if self.capabilities_manager is not None:
            return self.capabilities_manager.should_filter_message(recipient, sender, context)
        return False

    def acquire_connection(self) -> bool:
        return self._conn_semaphore.acquire(blocking=False)

    def release_connection(self):
        try:
            self._conn_semaphore.release()
        except ValueError:
            pass


app = App()
