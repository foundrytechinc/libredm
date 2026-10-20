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
