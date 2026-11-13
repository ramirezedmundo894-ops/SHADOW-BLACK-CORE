"""Optional fail-closed client for the internal Go policy service."""
from __future__ import annotations

import json
import uuid
import urllib.error
import urllib.request
from typing import Any

from .policy import Decision, Signals


class GoPolicyError(RuntimeError):
    pass


class GoPolicyClient:
    """Forward server-derived signals; the remote deterministic policy owns the verdict."""

    def __init__(self, base_url: str, internal_token: str, timeout_seconds: float = 1.5):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("Go policy URL must use HTTP or HTTPS")
        if len(internal_token) < 32:
            raise ValueError("Go internal token must have at least 32 characters")
        self.base_url = base_url.rstrip("/")
        self.internal_token = internal_token
        self.timeout_seconds = timeout_seconds

    def evaluate(self, signals: Signals, correlation: dict[str, Any], *, subject: str, request_id: str) -> Decision:
        payload = json.dumps({
            "request_id": str(uuid.UUID(request_id)),
            "subject": subject,
            "schema_version": "shadow.risk.v1",
            "signals": signals.to_dict(),
            "correlation": correlation,
        }, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/v1/decision",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Shadow-Internal-Token": self.internal_token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise GoPolicyError(f"Go policy returned HTTP {response.status}")
                result = json.loads(response.read(16_384))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise GoPolicyError("Go policy service unavailable or returned invalid JSON") from exc
        try:
            score = result["risk_score"]
            action = result["action"]
            allowed = result["session_allowed"]
            version = result["policy_version"]
            engine = result["policy_engine"]
            if (isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 1
                    or action not in {"ALLOW", "CHALLENGE", "SHORT_TTL", "DENY"}
                    or type(allowed) is not bool or not isinstance(version, str)
                    or engine != "go-deterministic"):
                raise ValueError("invalid policy response fields")
        except (KeyError, TypeError, ValueError) as exc:
            raise GoPolicyError("Go policy response failed contract validation") from exc
        return Decision(float(score), action, allowed, version)
