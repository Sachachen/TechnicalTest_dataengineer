"""Database utilities for the pipeline SQLite datastore.

This module centralizes connection settings (WAL mode, busy timeout)
and creates the base schema used by ingestion and dashboard components.
"""

import sqlite3
from pathlib import Path

# Resolve DB path relative to this file, not the working directory.
# pipeline/db.py sits one level below the project root → go up twice.
_HERE    = Path(__file__).resolve().parent        # pipeline/
_PROJECT = _HERE.parent                           # project root
DB_PATH  = str(_PROJECT / "pipeline" / "data" / "security.db")


def get_connection() -> sqlite3.Connection:
    """Return a configured SQLite connection for concurrent pipeline access."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create core tables required by the ingestion pipeline if missing."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp         TEXT,
            log_type          TEXT,
            src_ip            TEXT,
            dest_ip           TEXT,
            protocol          TEXT,
            severity          TEXT,
            alert_desc        TEXT,
            flags             TEXT,
            client_ip         TEXT,
            method            TEXT,
            status            INTEGER,
            resource          TEXT,
            is_malicious_src  INTEGER DEFAULT 0,
            threat_score_src  INTEGER DEFAULT 0,
            is_malicious_dst  INTEGER DEFAULT 0,
            threat_score_dst  INTEGER DEFAULT 0
        )
    """)
    conn.commit()