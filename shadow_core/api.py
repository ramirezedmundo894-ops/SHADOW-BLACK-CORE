"""HTTP API for risk evaluation, authentication and attested request binding."""
import hashlib
import hmac
import os
import time
import uuid
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from .attestation import (AttestationError, AttestationStore, GooglePlayIntegrityDecoder,
                          IntegrityDecoder)
from .correlation import correlate_signals
from .evidence import EvidenceStore, canonical_json
from .fft_detection import FFTConfig, analyze_periodicity
from .policy import Signals, evaluate
from .go_policy import GoPolicyClient, GoPolicyError
from .security import JwtService, TokenError, TokenStore


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    frida_detected: bool = False
    root_integrity_failed: bool = False
    jwt_validation_failures: int = Field(default=0, ge=0, le=100)
    grpc_tls_verified: bool = True
    fft_samples: list[float] | None = Field(default=None, min_length=32, max_length=8192)


class BeaconingAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    samples: list[float] = Field(min_length=32, max_length=8192)


class ImprovementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(min_length=1, max_length=500)
    test: str = Field(min_length=1, max_length=200)


class TokenIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=200)
    scopes: list[str] = Field(min_length=1, max_length=20)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: str = Field(min_length=20, max_length=8192)


class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_hash: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class AttestationVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(min_length=10, max_length=200)
    integrity_token: str = Field(min_length=20, max_length=20000)


def create_app(store: EvidenceStore | None = None, *, jwt_secret: str | None = None,
               issuer_token: str | None = None, attestation_decoder: IntegrityDecoder | None = None,
               android_package: str | None = None, require_attestation: bool | None = None,
               fft_config: FFTConfig | None = None, go_policy_url: str | None = None,
               go_policy_token: str | None = None) -> FastAPI:
    api = FastAPI(title="SHADOW CORE API", version="0.2.0", docs_url=None, redoc_url=None)
    evidence_store = store or EvidenceStore(os.environ.get("SHADOW_CORE_DB"))
    api.state.evidence_store = evidence_store
    signing_secret = jwt_secret if jwt_secret is not None else os.getenv("SHADOW_CORE_JWT_SECRET")
    if signing_secret:
        api.state.jwt_service = JwtService(
            signing_secret,
            issuer=os.getenv("SHADOW_CORE_JWT_ISSUER", "shadow-core"),
            audience=os.getenv("SHADOW_CORE_JWT_AUDIENCE", "shadow-core-api"),
        )
        api.state.token_store = TokenStore(evidence_store.path)
    else:
        api.state.jwt_service = None
        api.state.token_store = None
    api.state.issuer_token = issuer_token if issuer_token is not None else os.getenv("SHADOW_CORE_ISSUER_TOKEN")
    api.state.android_package = android_package if android_package is not None else os.getenv("SHADOW_CORE_ANDROID_PACKAGE")
    api.state.attestation_decoder = attestation_decoder
    api.state.require_attestation = (require_attestation if require_attestation is not None
                                     else os.getenv("SHADOW_CORE_REQUIRE_ATTESTATION", "false").lower() == "true")
    api.state.attestation_store = AttestationStore(evidence_store.path)
    policy_url = go_policy_url if go_policy_url is not None else os.getenv("SHADOW_GO_POLICY_URL")
    policy_token = go_policy_token if go_policy_token is not None else os.getenv("SHADOW_GO_INTERNAL_TOKEN")
    if policy_url and not policy_token:
        raise ValueError("SHADOW_GO_INTERNAL_TOKEN is required when SHADOW_GO_POLICY_URL is configured")
    api.state.go_policy_client = GoPolicyClient(policy_url, policy_token) if policy_url else None
    api.state.fft_config = fft_config or FFTConfig(
        sample_rate_hz=float(os.getenv("SHADOW_CORE_FFT_SAMPLE_RATE_HZ", "64")),
        min_frequency_hz=float(os.getenv("SHADOW_CORE_FFT_MIN_HZ", "0.05")),
        max_frequency_hz=(float(os.environ["SHADOW_CORE_FFT_MAX_HZ"])
                          if os.getenv("SHADOW_CORE_FFT_MAX_HZ") else None),
        peak_power_ratio_threshold=float(os.getenv("SHADOW_CORE_FFT_POWER_THRESHOLD", "0.5")),
        window=os.getenv("SHADOW_CORE_FFT_WINDOW", "hann"),
    )
    bearer = HTTPBearer(auto_error=False)

    def require_scope(scope: str):
        def authenticate(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
            jwt = request.app.state.jwt_service
            if jwt is None:
                raise HTTPException(status_code=503, detail="API authentication is not configured")
            if credentials is None or credentials.scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Bearer access token required",
                                    headers={"WWW-Authenticate": "Bearer"})
            try:
                claims = jwt.verify(credentials.credentials, "access")
            except TokenError:
                raise HTTPException(status_code=401, detail="Invalid or expired access token",
                                    headers={"WWW-Authenticate": "Bearer"})
            family = claims.get("family")
            try:
                high_risk, revoked = request.app.state.token_store.family_state(family, claims["sub"])
            except Exception:
                raise HTTPException(status_code=503, detail="Session state unavailable")
            if revoked:
                raise HTTPException(status_code=401, detail="Session family revoked",
                                    headers={"WWW-Authenticate": "Bearer"})
            if high_risk and int(time.time()) >= min(claims["exp"], claims["iat"] + jwt.high_risk_access_ttl):
                raise HTTPException(status_code=401, detail="High-risk access token expired; rotate refresh token",
                                    headers={"WWW-Authenticate": "Bearer"})
            if scope not in claims["scope"]:
                raise HTTPException(status_code=403, detail="Insufficient scope")
            return claims
        return authenticate

    def server_decision(request: Request, signals: Signals, correlation: dict[str, Any], subject: str, request_id: str):
        client: GoPolicyClient | None = request.app.state.go_policy_client
        if client is None:
            return evaluate(signals), "python-deterministic"
        try:
            return client.evaluate(signals, correlation, subject=subject, request_id=request_id), "go-deterministic"
        except GoPolicyError:
            # Once configured, never silently fall back to a different policy engine.
            raise HTTPException(status_code=503, detail="Authoritative Go policy service unavailable")

    @api.get("/health")
    def health():
        return {"status": "ok", "mode": "local-mvp"}

    @api.post("/api/auth/token")
    def issue_tokens(body: TokenIssueRequest, request: Request):
        jwt: JwtService | None = request.app.state.jwt_service
        configured_issuer = request.app.state.issuer_token
        if jwt is None or not configured_issuer:
            raise HTTPException(status_code=503, detail="Token issuer is not configured")
        # This endpoint is only for a trusted upstream identity service. It does not authenticate end users.
        supplied = request.headers.get("authorization", "")
        prefix, _, credential = supplied.partition(" ")
        if prefix.lower() != "bearer" or not hmac.compare_digest(credential, configured_issuer):
            raise HTTPException(status_code=401, detail="Trusted issuer credential required",
                                headers={"WWW-Authenticate": "Bearer"})
        if any(not scope or len(scope) > 100 for scope in body.scopes):
            raise HTTPException(status_code=422, detail="Invalid scope")
        family_id = os.urandom(24).hex()
        access, _ = jwt.issue(body.subject, body.scopes, "access", family_id)
        refresh, refresh_claims = jwt.issue(body.subject, body.scopes, "refresh", family_id)
        request.app.state.token_store.register(
            jwt.token_hash(refresh), body.subject, family_id, refresh_claims["exp"]
        )
        return {"token_type": "bearer", "access_token": access, "expires_in": jwt.access_ttl,
                "refresh_token": refresh, "refresh_expires_in": jwt.refresh_ttl,
                "scopes": sorted(set(body.scopes))}

    @api.post("/api/auth/refresh")
    def refresh_tokens(body: RefreshRequest, request: Request):
        jwt: JwtService | None = request.app.state.jwt_service
        if jwt is None:
            raise HTTPException(status_code=503, detail="Token service is not configured")
        try:
            claims = jwt.verify(body.refresh_token, "refresh")
        except TokenError:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        family = claims.get("family")
        new_refresh, new_claims = jwt.issue(claims["sub"], claims["scope"], "refresh", family)
        rotated = request.app.state.token_store.rotate(
            jwt.token_hash(body.refresh_token), claims["sub"], family,
            jwt.token_hash(new_refresh), new_claims["exp"],
        )
        if not rotated:
            raise HTTPException(status_code=401, detail="Refresh token invalidated; sign in again")
        high_risk, revoked = request.app.state.token_store.family_state(family, claims["sub"])
        if revoked:
            raise HTTPException(status_code=401, detail="Session family revoked; sign in again")
        access_ttl = jwt.high_risk_access_ttl if high_risk else jwt.access_ttl
        new_access, _ = jwt.issue(claims["sub"], claims["scope"], "access", family,
                                  ttl_override=access_ttl)
        return {"token_type": "bearer", "access_token": new_access, "expires_in": access_ttl,
                "risk_mode": "high" if high_risk else "normal", "step_up_required": False,
                "refresh_token": new_refresh, "refresh_expires_in": jwt.refresh_ttl,
                "scopes": claims["scope"]}

    @api.post("/api/auth/revoke", status_code=204)
    def revoke_tokens(body: RefreshRequest, request: Request):
        jwt: JwtService | None = request.app.state.jwt_service
        if jwt is None:
            raise HTTPException(status_code=503, detail="Token service is not configured")
        try:
            claims = jwt.verify(body.refresh_token, "refresh")
        except TokenError:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        request.app.state.token_store.revoke_family(claims["family"], claims["sub"])
        return None

    @api.post("/api/attestation/challenges")
    def create_attestation_challenge(body: ChallengeRequest,
                                     claims: dict[str, Any] = Depends(require_scope("device:attest"))):
        challenge = api.state.attestation_store.create(claims["sub"], body.operation_hash)
        return challenge

    @api.post("/api/attestation/verify")
    def verify_attestation(body: AttestationVerifyRequest,
                           claims: dict[str, Any] = Depends(require_scope("device:attest"))):
        package = api.state.android_package
        if not package:
            raise HTTPException(status_code=503, detail="Android package is not configured")
        decoder = api.state.attestation_decoder or GooglePlayIntegrityDecoder(package)
        try:
            decoded = decoder.decode(body.integrity_token)
            operation_hash = api.state.attestation_store.validate_payload(
                decoded, package, body.challenge_id, claims["sub"]
            )
        except AttestationError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        api.state.evidence_store.append("play_integrity_verified", {
            "subject": claims["sub"], "operation_hash": operation_hash,
            "package_name": package, "verdict": "PLAY_RECOGNIZED+MEETS_DEVICE_INTEGRITY",
        })
        return {"verified": True, "operation_hash": operation_hash, "one_use": True}

    @api.post("/api/decision")
    def make_decision(body: DecisionRequest, http_request: Request,
                      claims: dict[str, Any] = Depends(require_scope("risk:write"))):
        if api.state.require_attestation:
            operation_hash = hashlib.sha256(canonical_json(body.model_dump(exclude_none=True)).encode("utf-8")).hexdigest()
            if not api.state.attestation_store.consume_for_operation(claims["sub"], operation_hash):
                raise HTTPException(status_code=403, detail="Fresh Play Integrity attestation required for this request")
        request_values = body.model_dump()
        fft_samples = request_values.pop("fft_samples")
        fft_result = None
        if fft_samples is not None:
            try:
                fft_result = analyze_periodicity(fft_samples, api.state.fft_config)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            request_values["fft_beaconing_detected"] = fft_result["detected"]
        signals = Signals(**request_values)
        correlation = correlate_signals(signals).to_dict()
        request_id = http_request.headers.get("Idempotency-Key") or str(uuid.uuid4())
        try:
            request_id = str(uuid.UUID(request_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Idempotency-Key must be a UUID")
        decision, policy_engine = server_decision(http_request, signals, correlation, claims["sub"], request_id)
        if decision.action in {"SHORT_TTL", "DENY"}:
            try:
                api.state.token_store.set_high_risk(claims["family"], claims["sub"])
            except ValueError:
                raise HTTPException(status_code=401, detail="Invalid session family")
        evidence = api.state.evidence_store.append(
            "risk_decision", {"subject": claims["sub"], "signals": signals.to_dict(),
                              "fft": fft_result, "correlation": correlation,
                              "decision": decision.to_dict(), "policy_engine": policy_engine}
        )
        return {**decision.to_dict(), "policy_engine": policy_engine, "session_risk_mode": "high" if decision.action in {"SHORT_TTL", "DENY"} else "normal",
                "access_ttl_seconds": api.state.jwt_service.high_risk_access_ttl if decision.action in {"SHORT_TTL", "DENY"} else api.state.jwt_service.access_ttl,
                "step_up_required": False, "correlation": correlation, "fft": fft_result, "evidence": evidence}

    @api.post("/api/analysis/beaconing")
    def analyze_beaconing(body: BeaconingAnalysisRequest, request: Request,
                          claims: dict[str, Any] = Depends(require_scope("risk:analyze"))):
        try:
            fft_result = analyze_periodicity(body.samples, api.state.fft_config)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        signals = Signals(fft_beaconing_detected=fft_result["detected"])
        correlation = correlate_signals(signals).to_dict()
        request_id = request.headers.get("Idempotency-Key") or str(uuid.uuid4())
        try:
            request_id = str(uuid.UUID(request_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Idempotency-Key must be a UUID")
        decision, policy_engine = server_decision(request, signals, correlation, claims["sub"], request_id)
        if decision.action in {"SHORT_TTL", "DENY"}:
            api.state.token_store.set_high_risk(claims["family"], claims["sub"])
        evidence = api.state.evidence_store.append("fft_beaconing_analysis", {
            "subject": claims["sub"], "fft": fft_result, "signals": signals.to_dict(),
            "decision": decision.to_dict(), "correlation": correlation, "policy_engine": policy_engine,
        })
        high_risk = decision.action in {"SHORT_TTL", "DENY"}
        return {"detector": "fft_primary", "fft": fft_result, **decision.to_dict(),
                "session_risk_mode": "high" if high_risk else "normal",
                "access_ttl_seconds": api.state.jwt_service.high_risk_access_ttl if high_risk else api.state.jwt_service.access_ttl,
                "step_up_required": False, "correlation": correlation, "policy_engine": policy_engine, "evidence": evidence}

    @api.get("/api/evidence")
    def get_evidence(limit: Annotated[int, Query(ge=1, le=500)] = 100,
                     claims: dict[str, Any] = Depends(require_scope("evidence:read"))):
        del claims
        return {"entries": api.state.evidence_store.list_entries(limit)}

    @api.get("/api/evidence/verify")
    def verify_evidence(claims: dict[str, Any] = Depends(require_scope("evidence:verify"))):
        del claims
        return api.state.evidence_store.verify()

    @api.post("/api/improvement-actions", status_code=201)
    def save_improvement_action(request: ImprovementRequest,
                                claims: dict[str, Any] = Depends(require_scope("improvements:write"))):
        evidence = api.state.evidence_store.append("improvement_action", {
            **request.model_dump(), "subject": claims["sub"]
        })
        return {"status": "saved", "evidence": evidence}

    return api


app = create_app()
