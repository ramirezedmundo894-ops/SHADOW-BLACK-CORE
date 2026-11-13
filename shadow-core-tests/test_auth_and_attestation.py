import hashlib
import time

from fastapi.testclient import TestClient

from shadow_core.api import create_app
from shadow_core.attestation import request_hash
from shadow_core.evidence import EvidenceStore, canonical_json


SCOPES = ["risk:write", "risk:analyze", "evidence:read", "evidence:verify", "improvements:write", "device:attest"]
ISSUER = "trusted-test-issuer"


def make_client(tmp_path, *, decoder=None, require_attestation=False):
    app = create_app(EvidenceStore(tmp_path / "auth.sqlite3"),
                     jwt_secret="test-only-signing-secret-with-32-bytes-minimum",
                     issuer_token=ISSUER, android_package="com.example.shadow",
                     attestation_decoder=decoder, require_attestation=require_attestation)
    client = TestClient(app)
    issued = client.post("/api/auth/token", headers={"Authorization": f"Bearer {ISSUER}"},
                         json={"subject": "alice", "scopes": SCOPES})
    assert issued.status_code == 200
    return client, issued.json()


def test_protected_api_rejects_missing_and_bad_scope(tmp_path):
    client, _ = make_client(tmp_path)
    assert client.post("/api/decision", json={}).status_code == 401
    assert client.get("/api/evidence").status_code == 401
    token = client.post("/api/auth/token", headers={"Authorization": f"Bearer {ISSUER}"},
                        json={"subject": "reader", "scopes": ["evidence:read"]}).json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    assert client.post("/api/decision", json={}).status_code == 403
    assert client.get("/api/evidence").status_code == 200


def test_refresh_rotates_once_and_reuse_revokes_family(tmp_path):
    client, pair = make_client(tmp_path)
    first = client.post("/api/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert first.status_code == 200
    second = client.post("/api/auth/refresh", json={"refresh_token": first.json()["refresh_token"]})
    assert second.status_code == 200
    replay = client.post("/api/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert replay.status_code == 401
    family_token = client.post("/api/auth/refresh", json={"refresh_token": second.json()["refresh_token"]})
    assert family_token.status_code == 401


def test_issuer_credentials_and_revoke_family(tmp_path):
    client, pair = make_client(tmp_path)
    assert client.post("/api/auth/token", json={"subject": "mallory", "scopes": ["risk:write"]}).status_code == 401
    assert client.post("/api/auth/revoke", json={"refresh_token": pair["refresh_token"]}).status_code == 204
    assert client.post("/api/auth/refresh", json={"refresh_token": pair["refresh_token"]}).status_code == 401


class FakeIntegrityDecoder:
    def __init__(self):
        self.payload = None

    def decode(self, integrity_token):
        assert integrity_token == "synthetic-integrity-token-value"
        return self.payload


def test_play_integrity_challenge_binds_one_request_and_is_consumed(tmp_path):
    decoder = FakeIntegrityDecoder()
    client, pair = make_client(tmp_path, decoder=decoder, require_attestation=True)
    headers = {"Authorization": f"Bearer {pair['access_token']}"}
    decision_body = {"frida_detected": False, "root_integrity_failed": False,
                     "jwt_validation_failures": 0, "grpc_tls_verified": True}
    operation_hash = hashlib.sha256(canonical_json(decision_body).encode()).hexdigest()
    challenge = client.post("/api/attestation/challenges", headers=headers,
                            json={"operation_hash": operation_hash})
    assert challenge.status_code == 200
    challenge_body = challenge.json()
    decoder.payload = {
        "requestDetails": {
            "requestPackageName": "com.example.shadow",
            "timestampMillis": int(time.time() * 1000),
            "requestHash": request_hash(challenge_body["nonce"], operation_hash),
        },
        "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED"},
        "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
    }
    verified = client.post("/api/attestation/verify", headers=headers,
                           json={"challenge_id": challenge_body["challenge_id"],
                                 "integrity_token": "synthetic-integrity-token-value"})
    assert verified.status_code == 200
    assert verified.json()["verified"] is True
    decision = client.post("/api/decision", headers=headers, json=decision_body)
    assert decision.status_code == 200
    assert client.post("/api/decision", headers=headers, json=decision_body).status_code == 403


def test_play_integrity_rejects_wrong_hash_and_replay(tmp_path):
    decoder = FakeIntegrityDecoder()
    client, pair = make_client(tmp_path, decoder=decoder)
    headers = {"Authorization": f"Bearer {pair['access_token']}"}
    operation_hash = "a" * 64
    challenge = client.post("/api/attestation/challenges", headers=headers,
                            json={"operation_hash": operation_hash}).json()
    decoder.payload = {
        "requestDetails": {"requestPackageName": "com.example.shadow",
                           "timestampMillis": int(time.time() * 1000), "requestHash": "wrong"},
        "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED"},
        "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
    }
    body = {"challenge_id": challenge["challenge_id"], "integrity_token": "synthetic-integrity-token-value"}
    assert client.post("/api/attestation/verify", headers=headers, json=body).status_code == 401
    decoder.payload["requestDetails"]["requestHash"] = request_hash(challenge["nonce"], operation_hash)
    assert client.post("/api/attestation/verify", headers=headers, json=body).status_code == 200
    assert client.post("/api/attestation/verify", headers=headers, json=body).status_code == 401


def test_missing_session_family_state_fails_closed_without_resurrection(tmp_path):
    import sqlite3

    client, pair = make_client(tmp_path)
    claims = client.app.state.jwt_service.verify(pair["access_token"])
    db_path = client.app.state.token_store.path
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM token_families WHERE family_id=?", (claims["family"],))
        db.commit()

    # Protected access and refresh both fail rather than recreating missing durable session state.
    headers = {"Authorization": f"Bearer {pair['access_token']}"}
    assert client.get("/api/evidence", headers=headers).status_code == 503
    assert client.post("/api/auth/refresh", json={"refresh_token": pair["refresh_token"]}).status_code == 401
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT 1 FROM token_families WHERE family_id=?", (claims["family"],)).fetchone() is None
