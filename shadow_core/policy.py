"""Deterministic policy over caller-supplied signals; not a device detector."""

from dataclasses import asdict, dataclass
import math


@dataclass(frozen=True)
class Signals:
    frida_detected: bool = False
    root_integrity_failed: bool = False
    jwt_validation_failures: int = 0
    grpc_tls_verified: bool = True
    fft_beaconing_detected: bool = False

    def __post_init__(self):
        if type(self.frida_detected) is not bool or type(self.root_integrity_failed) is not bool:
            raise ValueError("detection flags must be booleans")
        if type(self.grpc_tls_verified) is not bool or type(self.fft_beaconing_detected) is not bool:
            raise ValueError("security flags must be booleans")
        if type(self.jwt_validation_failures) is not int or not 0 <= self.jwt_validation_failures <= 100:
            raise ValueError("jwt_validation_failures must be an integer from 0 to 100")

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Decision:
    risk_score: float
    action: str
    session_allowed: bool
    policy_version: str = "shadow-policy-2"

    def to_dict(self):
        return asdict(self)


def evaluate(signals: Signals) -> Decision:
    """Apply documented weights; high risk selects a short access-token TTL, not reauthentication."""
    score = 0.40 * signals.frida_detected
    score += 0.35 * signals.root_integrity_failed
    score += min(signals.jwt_validation_failures, 5) * 0.05
    score += 0.35 * (not signals.grpc_tls_verified)
    score += 0.60 * signals.fft_beaconing_detected
    score = round(min(float(score), 1.0), 4)

    if score >= 0.85:
        action, allowed = "DENY", False
    elif score >= 0.60:
        action, allowed = "SHORT_TTL", True
    elif score >= 0.30:
        action, allowed = "CHALLENGE", True
    else:
        action, allowed = "ALLOW", True
    return Decision(score, action, allowed)
