from shadow_core.policy import Signals, evaluate


def test_policy_is_deterministic_for_identical_inputs():
    signals = Signals(jwt_validation_failures=2, root_integrity_failed=True)
    assert evaluate(signals) == evaluate(signals)
