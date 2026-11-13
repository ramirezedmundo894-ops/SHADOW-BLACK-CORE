def test_redis_stream_replay(shadow_client):
    """T-12: Redis Streams debe poder reproducir toda la evidencia."""
    for i in range(100):
        shadow_client.publish_event(f"evento_{i}")

    replay = shadow_client.replay_stream(from_id="0")

    assert len(replay) == 100
    assert replay[0]["id"] == "evento_0"
    assert replay[-1]["id"] == "evento_99"
