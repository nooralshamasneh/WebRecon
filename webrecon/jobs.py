"""Database-backed background job queue.

Scans are rows in the `scans` table. Worker threads claim queued rows atomically, run the scanner
and store the result, so jobs survive restarts and the UI can show live progress. For multi-host
scaling the same table can be consumed by Celery/RQ workers; the claim step is the only coupling.
"""
import json
import logging
import threading
import time

from .db import utcnow

log = logging.getLogger("webrecon.jobs")


class JobQueue:
    def __init__(self, cfg, db, runner, poll=1.0, stale_after=180):
        self.cfg, self.db, self.runner = cfg, db, runner
        self.poll, self.stale_after = poll, stale_after
        self._stop = threading.Event()
        self._threads = []

    def start(self):
        self.recover()
        for i in range(max(1, self.cfg["WORKERS"])):
            t = threading.Thread(target=self._loop, name=f"webrecon-worker-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)

    def recover(self):
        """Fail jobs whose worker stopped updating the heartbeat (crash or restart)."""
        cur = self.db.execute(
            "UPDATE scans SET status='failed', error='Worker stopped before the scan finished.', finished_at=? "
            "WHERE status='running' AND (heartbeat IS NULL OR heartbeat < ?)", (utcnow(), time.time() - self.stale_after))
        return cur.rowcount

    def claim(self):
        row = self.db.one("SELECT id, user_id, target FROM scans WHERE status='queued' ORDER BY created_at LIMIT 1")
        if row is None:
            return None
        cur = self.db.execute(
            "UPDATE scans SET status='running', stage='starting', started_at=?, heartbeat=? WHERE id=? AND status='queued'",
            (utcnow(), time.time(), row["id"]))
        return row if cur.rowcount == 1 else None

    def progress(self, scan_id, stage, pct):
        self.db.execute("UPDATE scans SET stage=?, progress=?, heartbeat=? WHERE id=?", (stage, int(pct), time.time(), scan_id))

    def run_one(self, row):
        scan_id = row["id"]
        try:
            result = self.runner(self.cfg, self.db, row["target"], lambda s, p: self.progress(scan_id, s, p))
            summary = result["summary"]
            self.db.execute(
                "UPDATE scans SET status='completed', stage='done', progress=100, finished_at=?, grade=?, score=?, result_json=? WHERE id=?",
                (utcnow(), summary["grade"], summary["score"], json.dumps(result), scan_id))
        except Exception as exc:
            log.warning("scan %s failed", scan_id, exc_info=True)
            self.db.execute("UPDATE scans SET status='failed', finished_at=?, error=? WHERE id=?",
                            (utcnow(), f"{type(exc).__name__}: {str(exc)[:300]}", scan_id))

    def _loop(self):
        last_recover = time.monotonic()
        while not self._stop.is_set():
            if time.monotonic() - last_recover > 30:
                self.recover()
                last_recover = time.monotonic()
            row = self.claim()
            if row:
                self.run_one(row)
            else:
                self._stop.wait(self.poll)
