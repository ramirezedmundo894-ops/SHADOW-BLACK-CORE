from shadow_core_ml.features import extract_features


def test_feature_extraction_handles_empty_events():
    result = extract_features([])
    assert result["frida_hooks"] == 0
    assert result["fft_beaconing"] == 0
    assert result["event_rate"] == 0


def test_feature_extraction_counts_event_types():
    result = extract_features([{"type": "frida_hook", "ts": 1}, {"type": "hook", "ts": 2}, {"type": "exfil", "ts": 3}])
    assert result["frida_hooks"] == 1
    assert result["markov_anomaly"] == 1
