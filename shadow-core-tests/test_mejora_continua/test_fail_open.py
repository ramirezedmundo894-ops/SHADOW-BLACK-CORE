def test_vertex_failure_uses_documented_demo_fallback(shadow_client):
    shadow_client.kill_vertex_ai()
    decision = shadow_client.make_risk_decision(risk_score=0.5)
    assert decision["fail_mode"] == "fail_open_safe"
    assert decision["session_allowed"] is True
    assert decision["alert_sent"] is True
