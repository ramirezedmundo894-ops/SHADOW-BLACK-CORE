def test_grpc_encryption(shadow_client):
    """T-09: Intenta interceptar gRPC sin cifrado."""
    ataque = shadow_client.try_intercept_grpc()
    assert ataque["intercepted"] is False
    assert ataque["tls_verified"] is True
    assert ataque["mutual_tls"] is True
