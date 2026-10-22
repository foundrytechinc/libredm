"""Per-IP rate limiting (token bucket)."""

import threading
import time


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self._hits = {}
        self._lock = threading.Lock()
        self._last_sweep = time.time()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            if now - self._last_sweep > self.window:
                self._sweep(now)
            timestamps = self._hits.setdefault(key, [])
            # drop expired
            cutoff = now - self.window
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= self.limit:
                return False
            timestamps.append(now)
            return True

    def _sweep(self, now: float):
        cutoff = now - self.window
        for k in list(self._hits.keys()):
            ts = self._hits[k]
            ts[:] = [t for t in ts if t > cutoff]
            if not ts:
                del self._hits[k]
        self._last_sweep = now


class AccountLockout:
    """Lock an account after repeated failed logins (anti-brute-force)."""

    def __init__(self, max_failures: int, window_seconds: float, lockout_seconds: float):
        self.max_failures = max_failures
        self.window = window_seconds
        self.lockout = lockout_seconds
        self._failures = {}  # username -> (last_fail_ts, [fail_ts, ...])
        self._locked_until = {}  # username -> unlock_ts
        self._lock = threading.Lock()

    def is_locked(self, username: str):
        """Return remaining lockout seconds (float), or 0.0 if not locked."""
        now = time.time()
        with self._lock:
            until = self._locked_until.get(username)
            if until is None:
                return 0.0
            if now >= until:
                del self._locked_until[username]
                self._failures.pop(username, None)
                return 0.0
            return until - now

    def record_failure(self, username: str):
        """Record a failed login. Returns remaining lockout seconds (0 if none)."""
        now = time.time()
        with self._lock:
            if now < self._locked_until.get(username, 0):
                return self._locked_until[username] - now
            _, stamps = self._failures.get(username, (now, []))
            stamps = [t for t in stamps if now - t < self.window]
            stamps.append(now)
            self._failures[username] = (now, stamps)
            if len(stamps) >= self.max_failures:
                self._locked_until[username] = now + self.lockout
                self._failures.pop(username, None)
                return self.lockout
            return 0.0

    def clear(self, username: str):
        with self._lock:
            self._failures.pop(username, None)
            self._locked_until.pop(username, None)
