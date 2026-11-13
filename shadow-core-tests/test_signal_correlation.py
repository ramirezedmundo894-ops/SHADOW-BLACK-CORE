import math

from fastapi.testclient import TestClient

from shadow_core.api import create_app
from shadow_core.correlation import correlate_signals
from shadow_core.evidence import EvidenceStore
from shadow_core.fft_detection import FFTConfig
from shadow_core.policy import Signals, evaluate
from shadow_core.security import JwtService


SYNTHETIC_FIXTURE = "synthetic-test-fixture; not real traffic or measured attack data"


def test_prototype_correlation_is_explicit_untrained_and_fft_prioritized():
    fft_only = correlate_signals(Signals(fft_beaconing_detected=True)).to_dict()
    combined = correlate_signals(Signals(
        fft_beaconing_detected=True, frida_detected=True, jwt_validation_failures=5
    )).to_dict()

    assert fft_only["mode"] == "transparent_signal_correlation_prototype"
    assert fft_only["model_status"] == "untrained_fixed_weights"
    assert fft_only["score_kind"] == "uncalibrated_heuristic_score_not_probability"
    assert fft_only["used_for_decision"] is False
    assert fft_only["signal_contributions"]["fft_periodicity"] == 0.45
    assert combined["score"] > fft_only["score"]
    assert combined["interaction_contributions"]["fft_with_independent_signal"] == 0.1
    assert "Synthetic/testable prototype only" in combined["caveat"]
    assert "not real traffic" in SYNTHETIC_FIXTURE


def test_prototype_correlation_cannot_override_deterministic_policy():
    signals = Signals(fft_beaconing_detected=True, frida_detected=True)
    correlation = correlate_signals(signals)
    decision = evaluate(signals)
    assert correlation.score > 0
    assert correlation.used_for_decision is False
    assert decision.risk_score == 1.0
    assert decision.action == "DENY"


def make_client(tmp_path):
    secret = "test-only-signing-secret-with-32-bytes-minimum"
    client = TestClient(create_app(
        EvidenceStore(tmp_path / "correlation.sqlite3"),
        jwt_secret=secret,
        issuer_token="trusted-test-issuer",
        fft_config=FFTConfig(sample_rate_hz=64, min_frequency_hz=4,
                             max_frequency_hz=6, peak_power_ratio_threshold=0.9,
                             window="rectangular"),
    ))
    tokens = client.post("/api/auth/token", headers={"Authorization": "Bearer trusted-test-issuer"},
                         json={"subject": "synthetic-correlation-test",
                               "scopes": ["risk:write", "risk:analyze", "evidence:read"]}).json()
    return client, tokens


def test_decision_endpoint_correlates_fft_with_existing_signals_but_policy_decides(tmp_path):
    client, tokens = make_client(tmp_path)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    # Synthetic periodic fixture: 5 Hz sine sampled uniformly at 64 Hz.
    samples = [math.cos(2 * math.pi * 5 * i / 64) for i in range(128)]
    response = client.post("/api/decision", headers=headers, json={
        "frida_detected": True,
        "root_integrity_failed": False,
        "jwt_validation_failures": 0,
        "grpc_tls_verified": True,
        "fft_samples": samples,
    })
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["fft"]["detected"] is True
    assert result["correlation"]["model_status"] == "untrained_fixed_weights"
    assert result["correlation"]["used_for_decision"] is False
    assert result["correlation"]["signal_contributions"]["fft_periodicity"] == 0.45
    assert result["action"] == "DENY"  # from deterministic policy, not correlation
    assert result["risk_score"] == 1.0
    evidence = client.get("/api/evidence", headers=headers).json()["entries"][-1]
    assert evidence["event_type"] == "risk_decision"
    assert evidence["payload"]["correlation"] == result["correlation"]


def test_decision_endpoint_rejects_invalid_fft_samples_without_deciding(tmp_path):
    client, tokens = make_client(tmp_path)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    response = client.post("/api/decision", headers=headers, json={"fft_samples": [1.0] * 31})
    assert response.status_code == 422
    assert client.get("/api/evidence", headers=headers).json()["entries"] == []


def test_no_fft_samples_keeps_policy_behavior_and_reports_no_fft():
    signals = Signals(frida_detected=True)
    assert evaluate(signals).action == "CHALLENGE"
    assert correlate_signals(signals).signal_contributions["fft_periodicity"] == 0.0
