import hashlib

import pytest


@pytest.fixture
def evidencia():
    def hash_evidence(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    return hash_evidence


@pytest.fixture
def shadow_client():
    from shadow_core import ShadowCoreClient

    return ShadowCoreClient(env="test")
