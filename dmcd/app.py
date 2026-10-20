"""Application context: wires storage, sessions, rooms, S2S, capabilities."""

import threading

from dmcd import config
from dmcd.storage_factory import init_storage
from dmcd.sessions import SessionRegistry, registry
from dmcd.rooms import RoomManager
from dmcd.s2s import S2SLink, DialbackLedger, DialbackChecker
from dmcd.ratelimit import RateLimiter


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

        # Use the global registry singleton to avoid duplicate instances
        self.sessions = registry
        self.rooms = RoomManager(self.rooms_store)

        self.outbound_dialback = DialbackLedger()
        self.s2s = S2SLink(self.get_advertised_host, self.outbound_dialback)
        self.dialback = DialbackChecker(self.s2s, self.get_advertised_host)

        self.login_limiter = RateLimiter(config.LOGIN_RATE_LIMIT, config.LOGIN_RATE_WINDOW)
        self.register_limiter = RateLimiter(config.REGISTER_RATE_LIMIT, config.REGISTER_RATE_WINDOW)

        self.capabilities_manager = None  # set after caps import
        self.message_filter = None        # callable(recipient, sender, context) -> bool

        self._conn_semaphore = threading.BoundedSemaphore(config.MAX_CONCURRENT_CONNECTIONS)

        if not self.rooms_store.exists(config.DEFAULT_SERVER):
            self.rooms_store.create(config.DEFAULT_SERVER)

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
