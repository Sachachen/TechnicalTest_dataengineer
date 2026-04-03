"""Threat-enrichment helpers for malicious IP lookups.

The module exposes a cached lookup used by parsers to annotate events with
malicious flags and confidence scores from the `malicious_ips` table.
"""

import sqlite3
from functools import lru_cache


@lru_cache(maxsize=4096)
def _cached_lookup(ip: str, db_path: str) -> tuple:
    """Return (is_malicious, score) for an IP. Result is cached in-process."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT score FROM malicious_ips WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        return (1, row[0]) if row else (0, 0)
    finally:
        conn.close()


def invalidate_cache() -> None:
    """Call this after an IPsum refresh so stale lookups are evicted."""
    _cached_lookup.cache_clear()


def enrich_ip(ip: str, conn: sqlite3.Connection) -> dict:
    """Lookup an IP in the malicious_ips table. Returns enrichment dict.

    Uses an in-process LRU cache keyed on (ip, db_path) to avoid redundant
    SELECT calls for recurring IPs — critical at high ingest rates.
    The conn parameter is kept for API compatibility but the lookup uses its
    own short-lived connection so the cache key stays stable across threads.
    """
    # Retrieve the DB path from the live connection so we don't hardcode it
    db_path = conn.execute("PRAGMA database_list").fetchone()[2]
    is_malicious, score = _cached_lookup(ip, db_path)
    return {"is_malicious": is_malicious, "threat_score": score}