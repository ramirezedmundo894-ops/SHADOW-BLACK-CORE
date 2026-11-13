"""SQLite-backed hash-linked audit log for the local MVP.

This detects edits to retained entries when verified from the beginning. It is
not a signature, WORM store, or protection against an attacker who can rewrite
the database and its entire chain. Tail truncation needs an external anchor.
"""

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class EvidenceStore:
    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path or os.environ.get("SHADOW_CORE_DB", "./data/shadow-core.sqlite3"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )""")
            db.commit()

    @staticmethod
    def _entry_hash(created_at: str, event_type: str, payload: str, previous_hash: str) -> str:
        content = canonical_json({
            "created_at": created_at,
            "event_type": event_type,
            "payload": json.loads(payload),
            "previous_hash": previous_hash,
        })
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event_type, str) or not 1 <= len(event_type) <= 80:
            raise ValueError("event_type must be 1..80 characters")
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        payload_json = canonical_json(payload)
        created_at = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT entry_hash FROM evidence ORDER BY id DESC LIMIT 1").fetchone()
            previous_hash = row[0] if row else GENESIS
            entry_hash = self._entry_hash(created_at, event_type, payload_json, previous_hash)
            cursor = db.execute(
                "INSERT INTO evidence(created_at,event_type,payload,previous_hash,entry_hash) VALUES(?,?,?,?,?)",
                (created_at, event_type, payload_json, previous_hash, entry_hash),
            )
            db.commit()
            return {"id": cursor.lastrowid, "created_at": created_at, "event_type": event_type,
                    "payload": payload, "previous_hash": previous_hash, "entry_hash": entry_hash}

    def list_entries(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute(
                "SELECT id,created_at,event_type,payload,previous_hash,entry_hash FROM evidence ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload"])} for row in reversed(rows)]

    def verify(self) -> dict[str, Any]:
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute(
                "SELECT id,created_at,event_type,payload,previous_hash,entry_hash FROM evidence ORDER BY id"
            ).fetchall()
        previous_hash = GENESIS
        for entry_id, created_at, event_type, payload, recorded_previous, recorded_hash in rows:
            expected_hash = self._entry_hash(created_at, event_type, payload, previous_hash)
            if recorded_previous != previous_hash or recorded_hash != expected_hash:
                return {"valid": False, "checked": entry_id - 1, "first_invalid_id": entry_id}
            previous_hash = recorded_hash
        return {"valid": True, "checked": len(rows), "head": previous_hash}
