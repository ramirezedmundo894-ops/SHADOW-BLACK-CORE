def test_event_replay_preserves_order(shadow_client):
    for i in range(100):
        shadow_client.publish_event(f"evento_{i:03d}")
    replay = shadow_client.replay_stream(from_id="0")
    assert len(replay) == 100
    assert replay[0]["id"] == "evento_000"
    assert replay[-1]["id"] == "evento_099"
