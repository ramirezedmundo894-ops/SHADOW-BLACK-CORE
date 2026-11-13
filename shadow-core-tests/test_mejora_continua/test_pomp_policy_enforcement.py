def test_pomp_policy_evidence_shape(shadow_client, evidencia):
    decision = shadow_client.make_risk_decision(risk_score=0.95)
    assert decision["pomp_proof"]
    assert decision["merkle_root"]
    assert decision["evidence_hash"]
    assert decision["auditable"]
    digest = evidencia(str(decision))
    assert len(digest) == 64
    shadow_client.save_improvement_action("policy-demo", digest, "PASSED")
