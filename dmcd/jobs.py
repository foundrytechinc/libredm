"""Bounded async task pool for S2S / fan-out work.

Replaces thread-per-message. Under load the pool rejects new tasks instead
of exhausting the OS thread limit.
"""

import queue
import threading
from typing import Callable


class BoundedTaskPool:
    """Fixed worker threads + bounded queue."""

    def __init__(self, max_workers: int, max_queue: int, name: str = "s2s"):
        self.max_workers = max(1, int(max_workers))
        self.max_queue = max(1, int(max_queue))
        self.name = name
        self._q: queue.Queue = queue.Queue(maxsize=self.max_queue)
        self._lock = threading.Lock()
        self._started = 0
        self._dropped = 0
        self._shutdown = False

    def _ensure_workers(self):
        with self._lock:
            while self._started < self.max_workers:
                self._started += 1
                threading.Thread(
                    target=self._worker,
                    name=f"{self.name}-worker-{self._started}",
                    daemon=True,
                ).start()

    def _worker(self):
        while True:
            fn = self._q.get()
            if fn is None:
                self._q.task_done()
                return
            try:
                fn()
            except Exception:
                pass
            finally:
                self._q.task_done()

    def submit(self, fn: Callable[[], None]) -> bool:
        """Queue a zero-arg callable. Returns False if the queue is full."""
        if self._shutdown or not callable(fn):
            return False
        self._ensure_workers()
        try:
            self._q.put_nowait(fn)
            return True
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False

    def submit_thread(self, fn: Callable[[], None], *args, **kwargs) -> bool:
        """submit() a callable bound to *args/**kwargs."""

        def _run():
            fn(*args, **kwargs)

        return self.submit(_run)

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def pending(self) -> int:
        return self._q.qsize()
