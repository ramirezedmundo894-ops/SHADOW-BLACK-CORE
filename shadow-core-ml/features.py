def test_adwin_drift_detection(shadow_client):
    """T-06: ADWIN detecta que el atacante cambió de patrón."""
    for _ in range(50):
        shadow_client.send_normal_traffic()

    drift = shadow_client.send_drift_traffic()
    assert drift["adwin_detected"] is True
    assert drift["model_retrain_triggered"] is True
