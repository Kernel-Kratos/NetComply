"""Learned-mappings SQLite store and seed manager. Owner: P2."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from core.contracts import MappingIn
from core.schema import rule_paths

DB_PATH = Path("data/mappings.db")
SEED_PATH = Path("data/seed_mappings.json")


def _get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the mappings table and auto-seed from seed_mappings.json if empty."""
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor TEXT NOT NULL,
                os_pattern TEXT,
                line_regex TEXT NOT NULL,
                target_field TEXT NOT NULL,
                value_capture TEXT,
                created_by TEXT NOT NULL DEFAULT 'admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN NOT NULL DEFAULT 1
            )
            """
        )
        conn.commit()

        # Check if empty, then seed
        cursor = conn.execute("SELECT COUNT(*) FROM mappings")
        if cursor.fetchone()[0] == 0:
            _seed_from_file(conn)


def _seed_from_file(conn: sqlite3.Connection) -> None:
    if not SEED_PATH.exists():
        return
    try:
        data = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        for item in data.get("mappings", []):
            if item["target_field"] not in rule_paths():
                continue
            conn.execute(
                """
                INSERT INTO mappings (vendor, os_pattern, line_regex, target_field, value_capture, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    item["vendor"],
                    item.get("os_pattern"),
                    item["line_regex"],
                    item["target_field"],
                    item.get("value_capture"),
                    item.get("created_by", "seed"),
                ),
            )
        conn.commit()
    except Exception:
        pass


def lookup_mapping(vendor: str, line: str) -> dict | None:
    """Step 1 of normalization: match a config line against active vendor regexes."""
    init_db()
    with _get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT * FROM mappings 
            WHERE active = 1 AND (vendor = ? OR vendor = 'any')
            """,
            (vendor,),
        )
        for row in cursor.fetchall():
            import re
            try:
                if re.search(row["line_regex"], line):
                    return dict(row)
            except re.error:
                continue
    return None


def save_mapping(m: MappingIn) -> None:
    """Save an admin-approved mapping from the training UI."""
    if m.target_field not in rule_paths():
        raise ValueError(f"Invalid schema target field: {m.target_field}")
    init_db()
    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO mappings (vendor, os_pattern, line_regex, target_field, value_capture, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                m.vendor,
                m.os_pattern,
                m.line_regex,
                m.target_field,
                m.value_capture,
                m.created_by,
            ),
        )
        conn.commit()


def reset_db() -> None:
    """Wipe local DB and re-seed (used by scripts/reset_demo.py)."""
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()