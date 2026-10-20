"""Small in-memory sliding-window rate limiter (per process)."""
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key, limit, window, now=None):
        """Record an event. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - window:
                hits.popleft()
            if len(hits) >= limit:
                return False, max(1, int(hits[0] + window - now) + 1)
            hits.append(now)
            return True, 0

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)
