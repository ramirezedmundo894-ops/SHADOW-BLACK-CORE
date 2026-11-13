import hashlib
import time
from typing import Any


class ShadowCoreClient:
    """In-memory demonstration client; it is not a security enforcement SDK."""

    def __init__(self, env: str = "demo") -> None:
        self.env = env
        self.attack_intensity = "normal"
        self.vertex_ai_alive = True
        self._events: list[dict[str, Any]] = []
        self._improvement_actions: list[dict[str, Any]] = []

    @staticmethod
    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def simulate_frida_hook(self, vector: str) -> dict[str, Any]:
        self._events.append({"type": "frida_hook", "vector": vector})
        return {"detected": True, "blocked_before_exfil": True, "papr_confirmed": True}

    def simulate_magisk(self, attack: str) -> dict[str, Any]:
        self._events.append({"type": "magisk", "attack": attack})
        return {"merkle_root_mismatch": True, "risk_score": 0.97, "session_killed": True}

    def simulate_attack_intensity(self, level: str = "high") -> None:
        self.attack_intensity = level

    def get_jwt(self) -> dict[str, Any]:
        adaptive = self.attack_intensity != "normal"
        return {"ttl": 20 if adaptive else 900, "risk_adaptive": adaptive, "old_token_revoked": adaptive}

    @staticmethod
    def try_intercept_grpc() -> dict[str, Any]:
        # Simulated result only; this does not establish a real TLS connection.
        return {"intercepted": False, "tls_verified": True, "mutual_tls": True}

    def make_risk_decision(self, risk_score: float = 0.95) -> dict[str, Any]:
        if not 0 <= risk_score <= 1:
            raise ValueError("risk_score must be between 0 and 1")
        if not self.vertex_ai_alive:
            return {
                "pomp_proof": "demo-fail-safe",
                "merkle_root": self._sha256("demo-fail-safe"),
                "evidence_hash": self._sha256(f"demo:{risk_score}"),
                "auditable": True,
                "fail_mode": "fail_open_safe",
                "session_allowed": True,
                "alert_sent": True,
            }
        if risk_score >= 0.9:
            action, ttl, level = "KILL_SESSION", 0, "CRITICAL"
        elif risk_score >= 0.6:
            action, ttl, level = "ROTATE_JWT_20S", 20, "HIGH"
        elif risk_score >= 0.3:
            action, ttl, level = "CHALLENGE", 300, "MEDIUM"
        else:
            action, ttl, level = "ALLOW", 900, "LOW"
        proof = self._sha256(f"{risk_score}:{action}")
        return {
            "action": action,
            "jwt_ttl": ttl,
            "pomp": level,
            "risk_score": risk_score,
            "pomp_proof": proof,
            "merkle_root": self._sha256(f"root:{proof}"),
            "evidence_hash": self._sha256(f"evidence:{proof}"),
            "auditable": True,
        }

    def save_improvement_action(self, test: str, hash: str, status: str) -> dict[str, Any]:
        action = {"test": test, "hash": hash, "status": status, "created_at": time.time()}
        self._improvement_actions.append(action)
        return action

    def publish_event(self, event_id: str) -> dict[str, str]:
        event = {"id": event_id, "event": event_id}
        self._events.append(event)
        return event

    def replay_stream(self, from_id: str = "0") -> list[dict[str, Any]]:
        if from_id == "0":
            return self._events.copy()
        return [event for event in self._events if event["id"] >= from_id]

    def kill_vertex_ai(self) -> None:
        self.vertex_ai_alive = False

    @staticmethod
    def send_normal_traffic() -> dict[str, bool]:
        return {"adwin_detected": False, "model_retrain_triggered": False}

    @staticmethod
    def send_drift_traffic() -> dict[str, bool]:
        # Deterministic test stub, not an actual online drift detector.
        return {"adwin_detected": True, "model_retrain_triggered": True}
