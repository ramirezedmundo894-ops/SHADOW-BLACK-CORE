"""Transparent, untrained signal-correlation prototype.

This is not a trained AI model and its score is not a calibrated probability.
It correlates server-derived FFT features with other available security signals
for analysis/evidence only. The deterministic server policy remains authoritative.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .policy import Signals


@dataclass(frozen=True)
class CorrelationResult:
    mode: str
    model_status: str
    score: float
    score_kind: str
    used_for_decision: bool
    signal_contributions: dict[str, float]
    interaction_contributions: dict[str, float]
    caveat: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "model_status": self.model_status,
            "score": self.score,
            "score_kind": self.score_kind,
            "used_for_decision": self.used_for_decision,
            "signal_contributions": self.signal_contributions,
            "interaction_contributions": self.interaction_contributions,
            "caveat": self.caveat,
        }


def correlate_signals(signals: Signals) -> CorrelationResult:
    """Produce an interpretable prototype score; never authorizes or blocks.

    FFT is the primary mathematical detector. Other signals may raise the
    correlation score, especially when they coincide with a periodicity finding.
    These fixed weights are engineering fixtures, not learned/calibrated values.
    """
    contributions = {
        "fft_periodicity": 0.45 if signals.fft_beaconing_detected else 0.0,
        "frida_claim": 0.18 if signals.frida_detected else 0.0,
        "root_integrity_claim": 0.16 if signals.root_integrity_failed else 0.0,
        "jwt_validation_anomaly": 0.10 * min(signals.jwt_validation_failures / 5, 1),
        "grpc_tls_failure": 0.11 if not signals.grpc_tls_verified else 0.0,
    }
    adverse_non_fft = sum(value > 0 for key, value in contributions.items() if key != "fft_periodicity")
    interactions = {
        "fft_with_independent_signal": round(min(adverse_non_fft, 2) * 0.05, 4)
        if signals.fft_beaconing_detected else 0.0
    }
    score = round(min(1.0, sum(contributions.values()) + sum(interactions.values())), 4)
    return CorrelationResult(
        mode="transparent_signal_correlation_prototype",
        model_status="untrained_fixed_weights",
        score=score,
        score_kind="uncalibrated_heuristic_score_not_probability",
        used_for_decision=False,
        signal_contributions=contributions,
        interaction_contributions=interactions,
        caveat=("Synthetic/testable prototype only; no trained model or measured efficacy. "
                "Client-reported flags are untrusted claims; server policy alone decides."),
    )
