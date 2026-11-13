from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_dashboard_and_health_routes():
    assert client.get("/").status_code == 200
    assert client.get("/health").json()["status"] == "ok"
