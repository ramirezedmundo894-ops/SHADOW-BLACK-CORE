def test_adwin_demo_stub_reports_drift(shadow_client):
    assert shadow_client.send_normal_traffic()["adwin_detected"] is False
    assert shadow_client.send_drift_traffic()["adwin_detected"] is True
