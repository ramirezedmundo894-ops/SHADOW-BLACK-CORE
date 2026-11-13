import sqlite3

from shadow_core.evidence import EvidenceStore


def test_evidence_chain_detects_payload_tampering(tmp_path):
    store = EvidenceStore(tmp_path / "tamper.sqlite3")
    store.append("test", {"value": 1})
    store.append("test", {"value": 2})
    assert store.verify()["valid"] is True
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE evidence SET payload=? WHERE id=1", ('{"value":2}',))
    result = store.verify()
    assert result["valid"] is False
    assert result["first_invalid_id"] == 1
