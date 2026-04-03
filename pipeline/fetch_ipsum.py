"""Fetch and synchronize the IPsum threat feed into SQLite.

Supports one-shot execution and daemonized periodic refreshes used by Docker
and local scripts.
"""

import argparse
import sqlite3
import sys
import time
import threading
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "pipeline" / "data" / "ipsum.txt"
DEFAULT_DB_PATH = PROJECT_ROOT / "pipeline" / "data" / "security.db"

IPSUM_URLS = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
]

def download_ipsum(timeout: int = 20) -> str:
    """Download ipsum.txt content from GitHub."""
    headers = {"User-Agent": "TechnicalTest-dataengineer/1.0"}

    for url in IPSUM_URLS:
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError):
            continue

    raise RuntimeError("Unable to download ipsum.txt from GitHub.")


def save_content(content: str, output_path: Path) -> None:
    """Persist raw IPsum content to disk, creating parent directories."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


def load_to_db(txt_path: Path, db_path: Path, min_score: int = 3) -> int:
    """Parse ipsum.txt and sync malicious IPs into SQLite.

    Strategy: upsert all IPs from the current snapshot, then DELETE any row
    whose updated_at predates this run — i.e. IPs no longer in the feed.
    This keeps the table as a true mirror of the latest snapshot without ever
    leaving it empty (no full DELETE up front).
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    cursor = conn.cursor()

    cursor.execute("PRAGMA journal_mode=WAL;")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malicious_ips (
            ip          TEXT PRIMARY KEY,
            score       INTEGER NOT NULL,
            updated_at  TEXT DEFAULT (datetime('now'))
        )
    """)

    run_ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    rows = []
    for line in txt_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        ip, score = parts[0], int(parts[1])
        if score >= min_score:
            rows.append((ip, score, run_ts))

    cursor.executemany(
        "INSERT OR REPLACE INTO malicious_ips (ip, score, updated_at) VALUES (?, ?, ?)",
        rows,
    )

    cursor.execute("DELETE FROM malicious_ips WHERE updated_at < ?", (run_ts,))
    removed = cursor.rowcount

    conn.commit()
    conn.close()

    if removed:
        print(f"  Purged {removed} IPs no longer in the feed.")

    return len(rows)


def refresh(output_path: Path, db_path: Path, min_score: int, timeout: int) -> None:
    """Download feed and load it into the DB. Logs errors but does not raise."""
    try:
        print("Downloading IPsum feed...")
        content = download_ipsum(timeout=timeout)
        save_content(content, output_path)
        print(f"IPsum feed saved to: {output_path}")

        print(f"Loading IPs into database (min score >= {min_score})...")
        count = load_to_db(output_path, db_path, min_score=min_score)
        print(f"Loaded {count} malicious IPs into: {db_path}")

        try:
            from enricher import invalidate_cache
            invalidate_cache()
            print("[fetch_ipsum] Enricher cache invalidated.")
        except ImportError:
            pass
    except Exception as exc:
        print(f"[fetch_ipsum] Refresh error: {exc}", file=sys.stderr)


def start_scheduler(
    output_path: Path,
    db_path: Path,
    min_score: int,
    timeout: int,
    interval_hours: float = 24.0,
) -> threading.Thread:
    """Spawn a daemon thread that refreshes the feed every `interval_hours`.

    The first refresh happens immediately so the DB is populated at startup;
    subsequent ones run after each interval.  Using a daemon thread means it
    is killed automatically when the main process exits.
    """
    interval_seconds = interval_hours * 3600

    def _loop() -> None:
        while True:
            refresh(output_path, db_path, min_score, timeout)
            print(f"[fetch_ipsum] Next refresh in {interval_hours}h.")
            time.sleep(interval_seconds)

    thread = threading.Thread(target=_loop, name="ipsum-refresher", daemon=True)
    thread.start()
    return thread


def parse_args() -> argparse.Namespace:
    """Build and parse CLI arguments for feed refresh execution."""
    parser = argparse.ArgumentParser(
        description="Download IPsum threat feed and load into SQLite."
    )
    parser.add_argument(
        "-o", "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help=f"Output .txt file path (default: {DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help=f"SQLite database path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=3,
        help="Minimum blacklist score to include (default: 3)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="HTTP timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run as a background scheduler (refresh every 24 h) instead of exiting.",
    )
    parser.add_argument(
        "--interval-hours",
        type=float,
        default=24.0,
        help="Refresh interval in hours when --daemon is set (default: 24).",
    )
    return parser.parse_args()


def main() -> int:
    """Entry point for CLI execution.

    Returns:
        int: Process exit code (0 on success, non-zero on error).
    """
    args = parse_args()
    output_path = Path(args.output)
    db_path = Path(args.db)

    if args.daemon:
        thread = start_scheduler(
            output_path, db_path, args.min_score, args.timeout, args.interval_hours
        )
        print(f"[fetch_ipsum] Scheduler started (interval={args.interval_hours}h). "
              "Press Ctrl+C to stop.")
        try:
            thread.join()
        except KeyboardInterrupt:
            print("\n[fetch_ipsum] Stopped.")
        return 0

    try:
        refresh(output_path, db_path, args.min_score, args.timeout)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())