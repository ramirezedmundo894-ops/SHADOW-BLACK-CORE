import math
import random
from unittest.mock import patch

from fastapi.testclient import TestClient

from shadow_core.api import create_app
from shadow_core.evidence import EvidenceStore
from shadow_core.fft_detection import FFTConfig, analyze_periodicity
from shadow_core.policy import Signals, evaluate
from shadow_core.security import JwtService


def test_fft_detects_configured_periodic_beacon_reproducibly():
    sample_rate = 64.0
    frequency = 5.0
    samples = [math.cos(2 * math.pi * frequency * i / sample_rate) for i in range(128)]
    config = FFTConfig(sample_rate_hz=sample_rate, min_frequency_hz=4.0,
                       max_frequency_hz=6.0, peak_power_ratio_threshold=0.9,
                       window="rectangular")
    first = analyze_periodicity(samples, config)
    second = analyze_periodicity(samples, config)
    assert first == second
    assert first["detected"] is True
    assert first["dominant_frequency_hz"] == 5.0
    assert first["peak_power_ratio"] > 0.99
    assert first["method"] == "mean_centered_windowed_radix2_fft"


def test_fft_no_signal_and_invalid_inputs():
    cfg = FFTConfig(sample_rate_hz=32, min_frequency_hz=1, max_frequency_hz=10,
                    peak_power_ratio_threshold=0.8)
    flat = analyze_periodicity([3.0] * 64, cfg)
    assert flat["detected"] is False
    assert flat["peak_power_ratio"] == 0
    noise = random.Random(7).uniform
    noisy = analyze_periodicity([noise(-1, 1) for _ in range(256)],
                                FFTConfig(sample_rate_hz=32, min_frequency_hz=1,
                                          max_frequency_hz=10, peak_power_ratio_threshold=0.8))
    assert noisy["detected"] is False
    # Scaling finite inputs cannot overflow the power calculation.
    huge = analyze_periodicity([1e300 * math.cos(2 * math.pi * 4 * i / 32) for i in range(64)],
                               FFTConfig(sample_rate_hz=32, min_frequency_hz=3,
                                         max_frequency_hz=5, peak_power_ratio_threshold=0.8,
                                         window="rectangular"))
    assert huge["detected"] is True
    assert math.isfinite(huge["peak_power_ratio"])
    try:
        analyze_periodicity([float("nan")] + [0.0] * 63, cfg)
    except ValueError as exc:
        assert "finite" in str(exc)
    else:
        raise AssertionError("non-finite sample accepted")
    try:
        analyze_periodicity([0.0] * 64,
                           FFTConfig(sample_rate_hz=32, min_frequency_hz=1, max_frequency_hz=17))
    except ValueError as exc:
        assert "Nyquist" in str(exc)
    else:
        raise AssertionError("out-of-Nyquist configuration accepted")
    try:
        analyze_periodicity([0.0] * 64,
                           FFTConfig(sample_rate_hz=64, min_frequency_hz=4,
                                     max_frequency_hz=5, peak_power_ratio_threshold=0.8))
    except ValueError as exc:
        assert "three FFT bins" in str(exc)
    else:
        raise AssertionError("single-bin band accepted; peak ratio would be meaningless")


def test_fft_policy_is_primary_high_risk_signal():
    result = evaluate(Signals(fft_beaconing_detected=True))
    assert result.risk_score == 0.6
    assert result.action == "SHORT_TTL"
    assert result.session_allowed is True


def _client(tmp_path):
    secret = "test-only-signing-secret-with-32-bytes-minimum"
    client = TestClient(create_app(EvidenceStore(tmp_path / "fft-auth.sqlite3"),
                                   jwt_secret=secret, issuer_token="trusted-test-issuer",
                                   fft_config=FFTConfig(sample_rate_hz=64, min_frequency_hz=4,
                                                        max_frequency_hz=6,
                                                        peak_power_ratio_threshold=0.9,
                                                        window="rectangular")))
    tokens = client.post("/api/auth/token", headers={"Authorization": "Bearer trusted-test-issuer"},
                         json={"subject": "beacon-test", "scopes": ["risk:analyze", "risk:write", "evidence:read"]}).json()
    return client, tokens, JwtService(secret)


def test_beaconing_endpoint_detects_then_refreshes_to_20_second_access(tmp_path):
    client, tokens, jwt = _client(tmp_path)
    samples = [math.cos(2 * math.pi * 5 * i / 64) for i in range(128)]
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    response = client.post("/api/analysis/beaconing", headers=headers, json={
        "samples": samples,
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detector"] == "fft_primary"
    assert body["fft"]["detected"] is True
    assert body["action"] == "SHORT_TTL"
    assert body["access_ttl_seconds"] == 20
    assert body["correlation"]["model_status"] == "untrained_fixed_weights"
    assert body["correlation"]["used_for_decision"] is False
    assert body["step_up_required"] is False
    # The existing long-lived access token is capped to 20 seconds once the family is high risk.
    claims = jwt.verify(tokens["access_token"])
    with patch("shadow_core.api.time.time", return_value=claims["iat"] + 20):
        capped = client.get("/api/evidence", headers=headers)
    assert capped.status_code == 401

    refreshed = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200, refreshed.text
    rotated = refreshed.json()
    assert rotated["expires_in"] == 20
    assert rotated["risk_mode"] == "high"
    assert rotated["step_up_required"] is False
    access_claims = jwt.verify(rotated["access_token"])
    assert access_claims["exp"] - access_claims["iat"] == 20


def test_normal_refresh_keeps_15_minute_access_ttl(tmp_path):
    client, tokens, jwt = _client(tmp_path)
    assert tokens["expires_in"] == 900
    normal_refresh = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert normal_refresh.status_code == 200
    body = normal_refresh.json()
    assert body["expires_in"] == 900
    assert body["risk_mode"] == "normal"
    claims = jwt.verify(body["access_token"])
    assert claims["exp"] - claims["iat"] == 900


def test_fft_settings_are_server_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOW_CORE_FFT_SAMPLE_RATE_HZ", "128")
    monkeypatch.setenv("SHADOW_CORE_FFT_MIN_HZ", "2")
    monkeypatch.setenv("SHADOW_CORE_FFT_MAX_HZ", "24")
    monkeypatch.setenv("SHADOW_CORE_FFT_POWER_THRESHOLD", "0.72")
    monkeypatch.setenv("SHADOW_CORE_FFT_WINDOW", "hamming")
    app = create_app(EvidenceStore(tmp_path / "configured-fft.sqlite3"),
                     jwt_secret="test-only-signing-secret-with-32-bytes-minimum",
                     issuer_token="trusted-test-issuer")
    config = app.state.fft_config
    assert config.sample_rate_hz == 128
    assert config.min_frequency_hz == 2
    assert config.max_frequency_hz == 24
    assert config.peak_power_ratio_threshold == 0.72
    assert config.window == "hamming"
