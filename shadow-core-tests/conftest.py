from fastapi.testclient import TestClient
import pytest

from shadow_core.api import create_app
from shadow_core.evidence import EvidenceStore


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(EvidenceStore(tmp_path / "test.sqlite3")))
