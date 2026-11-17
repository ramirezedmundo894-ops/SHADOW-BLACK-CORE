"""Shared pytest setup. Keep import-time app state away from developer data."""
import os
import tempfile
from pathlib import Path

# shadow_core.api creates a module-level app during import. Pin that app to an
# ephemeral test database before importing it, even when the shell/.env points
# SHADOW_CORE_DB at a developer's local database.
_PYTEST_DB_DIR = tempfile.TemporaryDirectory(prefix="shadow-core-pytest-")
PYTEST_ISOLATED_DB_PATH = Path(_PYTEST_DB_DIR.name) / "global-app.sqlite3"
os.environ["SHADOW_CORE_DB"] = str(PYTEST_ISOLATED_DB_PATH)

from fastapi.testclient import TestClient
import pytest

from shadow_core.api import app as _module_app, create_app
from shadow_core.evidence import EvidenceStore

# Fail at collection time if a future import/configuration change escapes the
# isolation guard above.
assert _module_app.state.evidence_store.path.resolve() == PYTEST_ISOLATED_DB_PATH.resolve()


SCOPES = ["risk:write", "risk:analyze", "evidence:read", "evidence:verify", "improvements:write", "device:attest"]


@pytest.fixture
def client(tmp_path):
    app = create_app(EvidenceStore(tmp_path / "test.sqlite3"),
                     jwt_secret="test-only-signing-secret-with-32-bytes-minimum",
                     issuer_token="trusted-test-issuer", android_package="com.example.shadow",
                     attestation_decoder=None, require_attestation=False)
    with TestClient(app) as test_client:
        issued = test_client.post("/api/auth/token", headers={"Authorization": "Bearer trusted-test-issuer"},
                                  json={"subject": "test-user", "scopes": SCOPES})
        assert issued.status_code == 200
        test_client.headers.update({"Authorization": f"Bearer {issued.json()['access_token']}"})
        yield test_client

@pytest.fixture(scope="session")
def isolated_default_app_db_path():
    return PYTEST_ISOLATED_DB_PATH
