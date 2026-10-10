import hashlib
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent.parent / "hash_cache.db"


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hash_results (
            sha256 TEXT PRIMARY KEY,
            malicious_count INTEGER NOT NULL,
            total_engines INTEGER NOT NULL,
            checked_at TEXT NOT NULL
        )
    """)
    return conn


def compute_sha256(file_path: str) -> str:
    """Reads a file in small chunks rather than all at once -- some
    executables can be large, and we don't want to load an entire file
    into memory just to hash it."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_cached_result(file_hash: str) -> dict | None:
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT malicious_count, total_engines, checked_at FROM hash_results WHERE sha256 = ?",
            (file_hash,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    return {"malicious_count": row[0], "total_engines": row[1], "checked_at": row[2]}


def store_result(file_hash: str, malicious_count: int, total_engines: int, checked_at: str) -> None:
    conn = _get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO hash_results (sha256, malicious_count, total_engines, checked_at) VALUES (?, ?, ?, ?)",
            (file_hash, malicious_count, total_engines, checked_at),
        )
        conn.commit()
    finally:
        conn.close()