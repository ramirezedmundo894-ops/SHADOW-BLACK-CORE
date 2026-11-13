from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_dashboard_does_not_claim_unconfigured_metrics():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    assert response.json()["total"] == 0
    assert response.json()["coverage"] is None


def test_improvement_action_is_demo_only():
    response = client.post("/api/accion-mejora", json={"action": "review policy", "test": "test_policy"})
    assert response.status_code == 200
    assert response.json()["status"] == "received_demo_only"
