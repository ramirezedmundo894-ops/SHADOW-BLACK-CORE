"""SHADOW CORE local MVP: deterministic risk policy and audit logging."""

from .evidence import EvidenceStore
from .policy import Decision, Signals, evaluate

__all__ = ["Decision", "EvidenceStore", "Signals", "evaluate"]
