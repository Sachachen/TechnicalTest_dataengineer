"""Log tailing workers with batched SQLite writes and retry logic.

Provides single-line and multiline tailers that feed parser callbacks while
handling transient database lock contention safely.
"""

import time
import sqlite3
from pathlib import Path
from db import get_connection

# Commit after this many inserts OR after this many seconds, whichever comes first.
BATCH_SIZE    = 100
BATCH_TIMEOUT = 2.0  # seconds
# Give startup enough time for fetch_ipsum to create malicious_ips.
MAX_DB_RETRIES = 40
RETRY_SLEEP = 0.05


def _should_commit(count: int, last_commit: float) -> bool:
    return count >= BATCH_SIZE or (time.monotonic() - last_commit) >= BATCH_TIMEOUT


def _run_with_retry(action_name: str, fn) -> bool:
    """Retry transient SQLite lock errors instead of killing the tail thread."""
    for attempt in range(1, MAX_DB_RETRIES + 1):
        try:
            fn()
            return True
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            # At startup the feed loader may not have created malicious_ips yet.
            # Treat this as transient and keep retrying instead of crashing.
            is_transient = (
                "locked" in msg
                or "busy" in msg
                or "no such table: malicious_ips" in msg
            )
            if not is_transient:
                raise
            if attempt == MAX_DB_RETRIES:
                print(f"[tailer] SQLite {action_name} failed after {MAX_DB_RETRIES} retries: {exc}")
                return False
            time.sleep(RETRY_SLEEP * attempt)


def tail_file(filepath: str, parse_fn) -> None:
    """Tail a single-line log file. Commits to DB in batches."""
    conn = get_connection()
    path = Path(filepath)

    while not path.exists():
        print(f"Waiting for {filepath}...")
        time.sleep(2)

    pending     = 0
    last_commit = time.monotonic()

    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                ok = _run_with_retry("write", lambda: parse_fn(line, conn))
                if ok:
                    pending += 1
                if _should_commit(pending, last_commit):
                    ok = _run_with_retry("commit", conn.commit)
                    if ok:
                        pending = 0
                    last_commit = time.monotonic()
            else:
                # No new data — flush any pending writes before sleeping
                if pending:
                    ok = _run_with_retry("commit", conn.commit)
                    if ok:
                        pending = 0
                    last_commit = time.monotonic()
                time.sleep(0.1)


def tail_multiline_file(filepath: str, parse_fn, separator: str = "Date:") -> None:
    """Tail a multi-line log file (endpoint). Commits to DB in batches."""
    conn = get_connection()
    path = Path(filepath)

    while not path.exists():
        print(f"Waiting for {filepath}...")
        time.sleep(2)

    buffer      = []
    pending     = 0
    last_commit = time.monotonic()

    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                if line.startswith(separator) and buffer:
                    ok = _run_with_retry("write", lambda: parse_fn("\n".join(buffer), conn))
                    buffer  = []
                    if ok:
                        pending += 1
                    if _should_commit(pending, last_commit):
                        ok = _run_with_retry("commit", conn.commit)
                        if ok:
                            pending = 0
                        last_commit = time.monotonic()
                buffer.append(line.strip())
            else:
                # No new data — flush pending writes before sleeping
                if pending:
                    ok = _run_with_retry("commit", conn.commit)
                    if ok:
                        pending = 0
                    last_commit = time.monotonic()
                time.sleep(0.1)
