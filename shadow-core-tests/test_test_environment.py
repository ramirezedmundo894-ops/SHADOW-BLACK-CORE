from pathlib import Path

from shadow_core.api import app as module_app


def test_import_time_app_uses_ephemeral_database(isolated_default_app_db_path):
    assert Path(module_app.state.evidence_store.path).resolve() == Path(
        isolated_default_app_db_path
    ).resolve()
