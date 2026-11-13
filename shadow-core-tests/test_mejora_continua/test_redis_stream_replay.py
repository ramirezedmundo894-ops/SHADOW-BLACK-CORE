def test_events_are_persisted_in_order(client):
    for number in range(3):
        response = client.post("/api/improvement-actions", json={"action": f"review {number}", "test": "audit-test"})
        assert response.status_code == 201
    entries = client.get("/api/evidence").json()["entries"]
    assert len(entries) == 3
    assert [entry["payload"]["action"] for entry in entries] == ["review 0", "review 1", "review 2"]
