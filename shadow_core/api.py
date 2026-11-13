"""HTTP API for local risk evaluation and audit evidence."""

import os
from typing import Annotated

from fastapi import FastAPI, Query
from pydantic import BaseModel, ConfigDict, Field

from .evidence import EvidenceStore
from .policy import Signals, evaluate


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    frida_detected: bool = False
    root_integrity_failed: bool = False
    jwt_validation_failures: int = Field(default=0, ge=0, le=100)
    grpc_tls_verified: bool = True


class ImprovementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(min_length=1, max_length=500)
    test: str = Field(min_length=1, max_length=200)


def create_app(store: EvidenceStore | None = None) -> FastAPI:
    api = FastAPI(title="SHADOW CORE local MVP", version="0.1.0")
    api.state.evidence_store = store or EvidenceStore(os.environ.get("SHADOW_CORE_DB"))

    @api.get("/health")
    def health():
        return {"status": "ok", "mode": "local-mvp"}

    @api.post("/api/decision")
    def make_decision(request: DecisionRequest):
        signals = Signals(**request.model_dump())
        decision = evaluate(signals)
        evidence = api.state.evidence_store.append(
            "risk_decision", {"signals": signals.to_dict(), "decision": decision.to_dict()}
        )
        return {**decision.to_dict(), "evidence": evidence}

    @api.get("/api/evidence")
    def get_evidence(limit: Annotated[int, Query(ge=1, le=500)] = 100):
        return {"entries": api.state.evidence_store.list_entries(limit)}

    @api.get("/api/evidence/verify")
    def verify_evidence():
        return api.state.evidence_store.verify()

    @api.post("/api/improvement-actions", status_code=201)
    def save_improvement_action(request: ImprovementRequest):
        evidence = api.state.evidence_store.append("improvement_action", request.model_dump())
        return {"status": "saved", "evidence": evidence}

    return api


app = create_app()
