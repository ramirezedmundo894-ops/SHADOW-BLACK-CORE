"""Server-side Google Play Integrity verification and single-use challenges."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Protocol


class AttestationError(ValueError):
    pass


class IntegrityDecoder(Protocol):
    def decode(self, integrity_token: str) -> dict[str, Any]: ...


class GooglePlayIntegrityDecoder:
    """Uses Google ADC and the official Play Integrity decode endpoint."""
    def __init__(self, package_name: str):
        if not package_name:
            raise ValueError("Android package name is required")
        self.package_name = package_name

    def decode(self, integrity_token: str) -> dict[str, Any]:
        try:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/playintegrity"])
            session = AuthorizedSession(credentials)
            response = session.post(
                f"https://playintegrity.googleapis.com/v1/{self.package_name}:decodeIntegrityToken",
                json={"integrityToken": integrity_token}, timeout=10,
            )
            response.raise_for_status()
            payload = response.json().get("tokenPayloadExternal")
            if not isinstance(payload, dict):
                raise AttestationError("Google returned no decoded token payload")
            return payload
        except AttestationError:
            raise
        except Exception as exc:
            raise AttestationError("Play Integrity verification service unavailable") from exc


def request_hash(nonce: str, operation_hash: str) -> str:
    digest = hashlib.sha256(f"{nonce}.{operation_hash}".encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class AttestationStore:
    def __init__(self, db_path: str | os.PathLike, challenge_ttl: int = 120, token_max_age_ms: int = 120_000):
        self.path = Path(db_path)
        self.challenge_ttl, self.token_max_age_ms = challenge_ttl, token_max_age_ms
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS attestation_challenges (
                challenge_id TEXT PRIMARY KEY, subject TEXT NOT NULL, nonce TEXT NOT NULL,
                operation_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS verified_attestations (
                subject TEXT NOT NULL, operation_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
                PRIMARY KEY(subject, operation_hash)
            )""")
            db.commit()

    def create(self, subject: str, operation_hash: str) -> dict[str, str | int]:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", operation_hash):
            raise ValueError("operation_hash must be a SHA-256 hex digest")
        challenge_id = secrets.token_urlsafe(18)
        nonce = secrets.token_urlsafe(24)
        expires_at = int(time.time()) + self.challenge_ttl
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute("INSERT INTO attestation_challenges VALUES(?,?,?,?,?,0)",
                       (challenge_id, subject, nonce, operation_hash.lower(), expires_at))
            db.commit()
        return {"challenge_id": challenge_id, "nonce": nonce, "expires_at": expires_at,
                "request_hash": request_hash(nonce, operation_hash.lower())}

    def validate_payload(self, claims: dict[str, Any], package_name: str,
                         challenge_id: str, subject: str) -> str:
        request = claims.get("requestDetails") or {}
        app = claims.get("appIntegrity") or {}
        device = claims.get("deviceIntegrity") or {}
        if request.get("requestPackageName") != package_name:
            raise AttestationError("package name mismatch")
        if app.get("appRecognitionVerdict") != "PLAY_RECOGNIZED":
            raise AttestationError("app is not Play recognized")
        verdicts = device.get("deviceRecognitionVerdict") or []
        if "MEETS_DEVICE_INTEGRITY" not in verdicts:
            raise AttestationError("device integrity verdict insufficient")
        timestamp = request.get("timestampMillis")
        if not isinstance(timestamp, (int, float)):
            raise AttestationError("missing integrity timestamp")
        age_ms = int(time.time() * 1000) - int(timestamp)
        if age_ms < -10_000 or age_ms > self.token_max_age_ms:
            raise AttestationError("integrity token outside freshness window")
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT subject,nonce,operation_hash,expires_at,consumed FROM attestation_challenges WHERE challenge_id=?",
                             (challenge_id,)).fetchone()
            if not row:
                db.rollback()
                raise AttestationError("unknown challenge")
            stored_subject, nonce, operation_hash, expires_at, consumed = row
            expected_hash = request_hash(nonce, operation_hash)
            if stored_subject != subject or consumed or expires_at <= int(time.time()):
                db.rollback()
                raise AttestationError("challenge expired, consumed, or belongs to another subject")
            if request.get("requestHash") != expected_hash:
                db.rollback()
                raise AttestationError("request hash mismatch")
            db.execute("UPDATE attestation_challenges SET consumed=1 WHERE challenge_id=?", (challenge_id,))
            db.execute("INSERT OR REPLACE INTO verified_attestations VALUES(?,?,?)",
                       (subject, operation_hash, int(time.time()) + 60))
            db.commit()
        return operation_hash

    def consume_for_operation(self, subject: str, operation_hash: str) -> bool:
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT expires_at FROM verified_attestations WHERE subject=? AND operation_hash=?",
                             (subject, operation_hash.lower())).fetchone()
            if not row or row[0] <= int(time.time()):
                db.rollback()
                return False
            db.execute("DELETE FROM verified_attestations WHERE subject=? AND operation_hash=?",
                       (subject, operation_hash.lower()))
            db.commit()
            return True
