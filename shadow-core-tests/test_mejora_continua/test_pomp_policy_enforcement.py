def test_decision_is_computed_and_persisted(client):
    response = client.post("/api/decision", json={"frida_detected": True})
    assert response.status_code == 200
    result = response.json()
    assert result["risk_score"] == 0.4
    assert result["action"] == "CHALLENGE"
    assert result["evidence"]["event_type"] == "risk_decision"
    assert client.get("/api/evidence/verify").json()["valid"] is True


def test_high_risk_denies_session(client):
    result = client.post("/api/decision", json={
        "frida_detected": True, "root_integrity_failed": True, "grpc_tls_verified": False
    }).json()
    assert result["action"] == "DENY"
    assert result["session_allowed"] is False


def test_api_rejects_unknown_fields(client):
    assert client.post("/api/decision", json={"risk_score": 1, "admin": True}).status_code == 422


def test_invalid_improvement_action_is_rejected(client):
    assert client.post("/api/improvement-actions", json={"action": "", "test": "policy"}).status_code == 422
