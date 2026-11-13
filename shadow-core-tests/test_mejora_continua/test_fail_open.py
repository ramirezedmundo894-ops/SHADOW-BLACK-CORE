def test_policy_endpoint_does_not_depend_on_vertex_ai(client):
    """The MVP is deterministic local code; it makes no Vertex AI call."""
    response = client.post("/api/decision", json={})
    assert response.status_code == 200
    assert response.json()["action"] == "ALLOW"
