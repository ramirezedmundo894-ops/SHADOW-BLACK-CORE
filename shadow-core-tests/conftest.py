from fastapi.testclient import TestClient
import pytest

from shadow_core.api import create_app
from shadow_core.evidence import EvidenceStore


SCOPES = ["risk:write", "risk:analyze", "evidence:read", "evidence:verify", "improvements:write", "device:attest"]


@pytest.fixture
def client(tmp_path):
    app = create_app(EvidenceStore(tmp_path / "test.sqlite3"),
                     jwt_secret="test-only-signing-secret-with-32-bytes-minimum",
                     issuer_token="trusted-test-issuer", android_package="com.example.shadow",
                     attestation_decoder=None, require_attestation=False)
    with TestClient(app) as test_client:
        issued = test_client.post("/api/auth/token", headers={"Authorization": "Bearer trusted-test-issuer"},
                                  json={"subject": "test-user", "scopes": SCOPES})
        assert issued.status_code == 200
        test_client.headers.update({"Authorization": f"Bearer {issued.json()['access_token']}"})
        yield test_client
