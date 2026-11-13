def test_fail_open(shadow_client):
    """T-10: Si falla Vertex AI, no se cae el banco. Fail Open seguro."""
    shadow_client.kill_vertex_ai()
    decision = shadow_client.make_risk_decision(risk_score=0.5)
    assert decision["fail_mode"] == "fail_open_safe"
    assert decision["session_allowed"] is True
    assert decision["alert_sent"] is True
