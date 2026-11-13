import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from shadow_core.api import create_app
from shadow_core.evidence import EvidenceStore
from shadow_core.go_policy import GoPolicyClient
from shadow_core.fft_detection import FFTConfig


INTERNAL_TOKEN = "python-go-bridge-test-secret-32-chars-minimum"


class PolicyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path == "/v1/decision"
        assert self.headers.get("X-Shadow-Internal-Token") == INTERNAL_TOKEN
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.received = body
        response = json.dumps({
            "risk_score": 0.6,
            "action": "SHORT_TTL",
            "session_allowed": True,
            "policy_version": "shadow-policy-2",
            "policy_engine": "go-deterministic",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


@pytest.fixture
def policy_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), PolicyHandler)
    server.received = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def get_test_tokens(client):
    return client.post("/api/auth/token", headers={"Authorization": "Bearer trusted-test-issuer"},
                       json={"subject": "go-bridge-test", "scopes": ["risk:write", "risk:analyze", "evidence:read"]}).json()


def test_fastapi_forwards_server_derived_fft_signals_to_go_policy(tmp_path, policy_server):
    policy_url = f"http://127.0.0.1:{policy_server.server_port}"
    client = TestClient(create_app(
        EvidenceStore(tmp_path / "go-bridge.sqlite3"),
        jwt_secret="test-only-signing-secret-with-32-bytes-minimum",
        issuer_token="trusted-test-issuer",
        go_policy_url=policy_url,
        go_policy_token=INTERNAL_TOKEN,
        fft_config=FFTConfig(sample_rate_hz=64, min_frequency_hz=4, max_frequency_hz=6,
                             peak_power_ratio_threshold=0.9, window="rectangular"),
    ))
    tokens = get_test_tokens(client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    response = client.post("/api/decision", headers=headers, json={"frida_detected": True})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["policy_engine"] == "go-deterministic"
    assert result["action"] == "SHORT_TTL"  # result from the configured Go policy fixture
    sent = policy_server.received
    assert sent["schema_version"] == "shadow.risk.v1"
    assert sent["subject"] == "go-bridge-test"
    assert len(sent["request_id"]) == 36
    assert sent["signals"]["frida_detected"] is True
    assert sent["signals"]["fft_beaconing_detected"] is False
    assert sent["correlation"]["used_for_decision"] is False


def test_configured_go_policy_fails_closed_instead_of_using_python_fallback(tmp_path):
    client = TestClient(create_app(
        EvidenceStore(tmp_path / "go-down.sqlite3"),
        jwt_secret="test-only-signing-secret-with-32-bytes-minimum",
        issuer_token="trusted-test-issuer",
        go_policy_url="http://127.0.0.1:1",
        go_policy_token=INTERNAL_TOKEN,
    ))
    tokens = get_test_tokens(client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    response = client.post("/api/decision", headers=headers, json={})
    assert response.status_code == 503
    assert client.get("/api/evidence", headers=headers).json()["entries"] == []


def test_go_policy_requires_internal_token_when_configured(tmp_path):
    with pytest.raises(ValueError, match="SHADOW_GO_INTERNAL_TOKEN"):
        create_app(EvidenceStore(tmp_path / "misconfigured.sqlite3"),
                   jwt_secret="test-only-signing-secret-with-32-bytes-minimum",
                   go_policy_url="http://127.0.0.1:8081")


def test_go_policy_client_rejects_invalid_engine_contract():
    with pytest.raises(ValueError):
        GoPolicyClient("ftp://localhost", INTERNAL_TOKEN)
    with pytest.raises(ValueError):
        GoPolicyClient("http://localhost", "short")
