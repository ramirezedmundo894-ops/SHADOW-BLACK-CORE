"""Small HS256 access/refresh token service for the local API.

Production deployments should use a managed identity provider and a secret manager.
This module never invents a development signing secret.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any


class TokenError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class JwtService:
    def __init__(self, secret: str, issuer: str = "shadow-core", audience: str = "shadow-core-api",
                 access_ttl: int = 900, high_risk_access_ttl: int = 20, refresh_ttl: int = 30 * 24 * 3600):
        if len(secret.encode("utf-8")) < 32:
            raise ValueError("SHADOW_CORE_JWT_SECRET must contain at least 32 bytes")
        if access_ttl < 1 or high_risk_access_ttl < 1 or refresh_ttl <= access_ttl:
            raise ValueError("invalid token lifetimes")
        self._secret = secret.encode("utf-8")
        self.issuer, self.audience = issuer, audience
        self.access_ttl, self.high_risk_access_ttl, self.refresh_ttl = access_ttl, high_risk_access_ttl, refresh_ttl

    def issue(self, subject: str, scopes: list[str], token_type: str, family_id: str | None = None,
              ttl_override: int | None = None) -> tuple[str, dict[str, Any]]:
        if token_type not in {"access", "refresh"}:
            raise ValueError("unsupported token type")
        now = int(time.time())
        ttl = (self.access_ttl if token_type == "access" else self.refresh_ttl) if ttl_override is None else ttl_override
        if ttl < 1 or (token_type == "refresh" and ttl_override is not None):
            raise ValueError("invalid token lifetime")
        claims: dict[str, Any] = {
            "iss": self.issuer, "aud": self.audience, "sub": subject,
            "iat": now, "nbf": now, "exp": now + ttl, "jti": secrets.token_urlsafe(24),
            "typ": token_type, "scope": sorted(set(scopes)),
        }
        claims["family"] = family_id or secrets.token_urlsafe(24)
        header = {"alg": "HS256", "typ": "JWT"}
        body = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}.{_b64(json.dumps(claims, separators=(',', ':')).encode())}"
        signature = _b64(hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{signature}", claims

    def verify(self, token: str, expected_type: str = "access") -> dict[str, Any]:
        try:
            encoded_header, encoded_claims, encoded_signature = token.split(".")
            signing_input = f"{encoded_header}.{encoded_claims}"
            expected = hmac.new(self._secret, signing_input.encode("ascii"), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _unb64(encoded_signature)):
                raise TokenError("invalid token signature")
            header = json.loads(_unb64(encoded_header))
            claims = json.loads(_unb64(encoded_claims))
        except TokenError:
            raise
        except Exception as exc:
            raise TokenError("malformed token") from exc
        now = int(time.time())
        if header != {"alg": "HS256", "typ": "JWT"}:
            raise TokenError("unsupported token algorithm")
        if (claims.get("iss") != self.issuer or claims.get("aud") != self.audience
                or claims.get("typ") != expected_type or not isinstance(claims.get("sub"), str)
                or not claims.get("sub") or not isinstance(claims.get("jti"), str)):
            raise TokenError("invalid token claims")
        if type(claims.get("exp")) is not int or type(claims.get("nbf")) is not int or type(claims.get("iat")) is not int:
            raise TokenError("invalid token timestamps")
        if not isinstance(claims.get("family"), str) or not claims["family"]:
            raise TokenError("invalid token family")
        if claims["exp"] <= now or claims["nbf"] > now + 30 or claims["iat"] > now + 30:
            raise TokenError("token expired or not yet valid")
        if not isinstance(claims.get("scope"), list) or any(not isinstance(s, str) for s in claims["scope"]):
            raise TokenError("invalid token scopes")
        return claims

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenStore:
    """Persistent one-use refresh-token registry; only token hashes are stored."""
    def __init__(self, db_path: str | os.PathLike):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, family_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
                replaced_by TEXT, created_at INTEGER NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id)")
            db.execute("""CREATE TABLE IF NOT EXISTS token_families (
                family_id TEXT PRIMARY KEY, subject TEXT NOT NULL, high_risk INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL
            )""")
            db.commit()

    def register(self, token_hash: str, subject: str, family_id: str, expires_at: int) -> None:
        now = int(time.time())
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO token_families VALUES(?,?,0,0,?)", (family_id, subject, now))
            db.execute("INSERT INTO refresh_tokens VALUES(?,?,?,?,0,NULL,?)",
                       (token_hash, subject, family_id, expires_at, now))
            db.commit()

    def family_state(self, family_id: str, subject: str) -> tuple[bool, bool]:
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            row = db.execute("SELECT high_risk,revoked FROM token_families WHERE family_id=? AND subject=?",
                             (family_id, subject)).fetchone()
        if row is None:
            # Fail closed: a signed token without registered family state is not an active session.
            raise KeyError("token family is not registered")
        return bool(row[0]), bool(row[1])

    def set_high_risk(self, family_id: str, subject: str) -> None:
        now = int(time.time())
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT subject FROM token_families WHERE family_id=?", (family_id,)).fetchone()
            if row is None:
                db.rollback()
                raise KeyError("token family is not registered")
            if row[0] != subject:
                db.rollback()
                raise ValueError("token family subject mismatch")
            db.execute("UPDATE token_families SET high_risk=1,updated_at=? WHERE family_id=? AND subject=?",
                       (now, family_id, subject))
            db.commit()

    def rotate(self, old_hash: str, subject: str, family_id: str,
               new_hash: str, new_expires_at: int) -> bool:
        now = int(time.time())
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT subject,family_id,expires_at,revoked,replaced_by FROM refresh_tokens WHERE token_hash=?",
                             (old_hash,)).fetchone()
            if row is None:
                db.rollback()
                return False
            old_subject, old_family, expires, revoked, replaced_by = row
            family = db.execute("SELECT subject,revoked FROM token_families WHERE family_id=?", (family_id,)).fetchone()
            if family is None:
                # Do not reconstruct family state from a refresh token if durable state vanished.
                db.rollback()
                return False
            if family[0] != subject or family[1]:
                db.rollback()
                return False
            if revoked or replaced_by or expires <= now:
                # Reuse of a consumed token invalidates every refresh token in its family.
                if old_subject == subject and old_family == family_id and replaced_by:
                    db.execute("UPDATE refresh_tokens SET revoked=1 WHERE family_id=?", (family_id,))
                    db.execute("UPDATE token_families SET revoked=1,updated_at=? WHERE family_id=?", (now, family_id))
                    db.commit()
                else:
                    db.rollback()
                return False
            if old_subject != subject or old_family != family_id:
                db.rollback()
                return False
            db.execute("UPDATE refresh_tokens SET revoked=1,replaced_by=? WHERE token_hash=?",
                       (new_hash, old_hash))
            db.execute("INSERT INTO refresh_tokens VALUES(?,?,?,?,0,NULL,?)",
                       (new_hash, subject, family_id, new_expires_at, now))
            db.commit()
            return True

    def revoke_family(self, family_id: str, subject: str) -> None:
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE refresh_tokens SET revoked=1 WHERE family_id=? AND subject=?", (family_id, subject))
            db.execute("UPDATE token_families SET revoked=1,updated_at=? WHERE family_id=? AND subject=?",
                       (int(time.time()), family_id, subject))
            db.commit()


def configured_auth(db_path: str | os.PathLike):
    secret = os.getenv("SHADOW_CORE_JWT_SECRET")
    if not secret:
        return None, None
    jwt = JwtService(secret,
                     issuer=os.getenv("SHADOW_CORE_JWT_ISSUER", "shadow-core"),
                     audience=os.getenv("SHADOW_CORE_JWT_AUDIENCE", "shadow-core-api"))
    return jwt, TokenStore(db_path)
