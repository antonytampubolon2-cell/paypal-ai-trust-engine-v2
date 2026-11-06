"""Minimal TrustGuard Seller Service API. Skyfire validation never invokes PayPal."""
from __future__ import annotations

import hmac
import os
import sqlite3
import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Literal

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api_security import RequestGuardMiddleware, TokenCacheControlMiddleware
from skyfire_auth import (
    DRAFT_HEADER,
    LEGACY_HEADER,
    SkyfireSettings,
    SkyfireTokenError,
    SkyfireTokenVerifier,
    parse_profile_header,
    protocol_header,
)
from trustguard import CanonicalTransaction, Ledger, LedgerError, RiskScreeningPipeline, SecurityError

_DEFAULT_API_SCORER = object()


class SkyfireAuthorizationSignal(BaseModel):
    status: str
    amount: str | None = None
    currency: str | None = None


class AuthorizationResponse(BaseModel):
    valid: bool
    token_type: str
    subject_id: str
    subject_semantics: str
    audience: str
    buyer_agent_account_id: str | None = None
    seller_agent_account_id: str | None = None
    seller_service_id: str
    skyfire_payment_authorization: SkyfireAuthorizationSignal | None
    paypal_payment_status: str
    paypal_payment_authorized: bool


class TransactionScreenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transaction_id: StrictStr = Field(min_length=1, max_length=128)
    idempotency_key: StrictStr = Field(min_length=1, max_length=128)
    amount: StrictStr = Field(min_length=1, max_length=32)
    currency: StrictStr = Field(min_length=3, max_length=3)


class HoldReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["KEEP_HOLD", "RELEASE_RESERVATION"]
    reason: StrictStr = Field(min_length=1, max_length=1000)

class RiskFeatureSignal(BaseModel):
    feature: str
    value: float
    reason_code: str
    description: str


class RiskExplanationResponse(BaseModel):
    version: str
    reason_codes: list[str]
    summary: str
    feature_signals: list[RiskFeatureSignal]
    method: str


class RiskAssessmentResponse(BaseModel):
    anomaly_score: float | None = Field(description="Synthetic IsolationForest anomaly ranking signal; not a calibrated fraud probability.")
    model_version: str
    training_dataset_id: str
    scored_at: float
    decision: Literal["ALLOW", "HOLD"]
    explanation: RiskExplanationResponse


class TransactionScreenResponse(BaseModel):
    status: str
    transaction_state: str
    reason_code: str
    transaction_id: str
    currency: str
    amount: str
    skyfire_service_id: str
    paypal_merchant_id: str | None
    paypal_integration_status: Literal["CONFIGURED", "NOT_CONFIGURED"]
    risk_assessment: RiskAssessmentResponse
    paypal_dispatch: str = "DISABLED_NOT_CALLED"


class HoldReviewResponse(BaseModel):
    transaction_id: str
    transaction_state: str
    reviewer_id: str
    decision: Literal["KEEP_HOLD", "RELEASE_RESERVATION"]
    reason: str
    reviewed_at: float


def _configured_paypal_mapping(settings: SkyfireSettings) -> tuple[str, str | None]:
    mapped_service_id = os.environ.get("TRUSTGUARD_PAYPAL_MAPPED_SKYFIRE_SERVICE_ID", "").strip()
    merchant_id = os.environ.get("TRUSTGUARD_PAYPAL_MERCHANT_ID", "").strip()
    if (not mapped_service_id or not merchant_id
            or mapped_service_id != settings.seller_service_id
            or merchant_id == settings.seller_service_id
            or len(merchant_id) > 128):
        return "NOT_CONFIGURED", None
    return "CONFIGURED", merchant_id


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside the supported range")
    return value


def _allowed_hosts_from_env() -> list[str]:
    raw = os.environ.get("TRUSTGUARD_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver")
    hosts = [host.strip().lower() for host in raw.split(",") if host.strip()]
    return _validate_allowed_hosts(hosts)


def _validate_allowed_hosts(hosts: list[str]) -> list[str]:
    if not hosts or any(not isinstance(host, str) or not host.strip() or "*" in host or "/" in host or any(ch.isspace() for ch in host) for host in hosts):
        raise ValueError("TRUSTGUARD_ALLOWED_HOSTS must be a non-empty explicit host allowlist")
    return [host.strip().lower() for host in hosts]


def _openapi_path_from_env() -> str:
    path = os.environ.get("TRUSTGUARD_OPENAPI_PATH", "/openapi.json").strip()
    return _validate_openapi_path(path)


def _validate_openapi_path(path: str) -> str:
    if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path or ".." in path:
        raise ValueError("TRUSTGUARD_OPENAPI_PATH must be an absolute local path")
    return path


def create_app(*, settings: SkyfireSettings | None = None, ledger: Ledger | None = None,
               verifier: Any | None = None, ledger_factory: Callable[[str], Ledger] = Ledger,
               risk_scorer: Any = _DEFAULT_API_SCORER,
               openapi_enabled: bool | None = None, openapi_path: str | None = None,
               allowed_hosts: list[str] | None = None) -> FastAPI:
    """Create a configured app, or a fail-closed unready app when required config is absent."""
    error = False
    if settings is None:
        try:
            settings = SkyfireSettings.from_env()
        except SkyfireTokenError:
            error = True
    if settings is not None and ledger is None:
        try:
            ledger = ledger_factory(settings.database_path)
        except (OSError, sqlite3.Error, ValueError):
            error = True
    if settings is not None and verifier is None:
        verifier = SkyfireTokenVerifier(settings)
    ready = (
        settings is not None and ledger is not None and verifier is not None and not error
        and settings.account_configuration_confirmed
    )
    screening = (
        RiskScreeningPipeline(ledger) if risk_scorer is _DEFAULT_API_SCORER
        else RiskScreeningPipeline(ledger, risk_scorer)
    ) if ledger is not None else None
    mapping_status, paypal_merchant_id = (
        _configured_paypal_mapping(settings) if settings is not None
        else ("NOT_CONFIGURED", None)
    )
    reviewer_id = os.environ.get("TRUSTGUARD_REVIEWER_ID", "").strip()
    reviewer_credential = os.environ.get("TRUSTGUARD_REVIEWER_CREDENTIAL", "")
    reviewer_enabled = bool(reviewer_id and reviewer_credential)

    if openapi_enabled is None:
        publication_setting = os.environ.get("TRUSTGUARD_OPENAPI_ENABLED", "false").strip().lower()
        if publication_setting not in {"true", "false"}:
            raise ValueError("TRUSTGUARD_OPENAPI_ENABLED must be true or false")
        openapi_enabled = publication_setting == "true"
    configured_openapi_path = _validate_openapi_path(openapi_path) if openapi_path is not None else _openapi_path_from_env()
    trusted_hosts = _validate_allowed_hosts(allowed_hosts) if allowed_hosts is not None else _allowed_hosts_from_env()
    max_body_bytes = _env_int("TRUSTGUARD_MAX_REQUEST_BODY_BYTES", 1_048_576, minimum=1024, maximum=10_485_760)
    max_concurrent = _env_int("TRUSTGUARD_MAX_CONCURRENT_REQUESTS", 16, minimum=1, maximum=256)
    rate_limit = _env_int("TRUSTGUARD_RATE_LIMIT_REQUESTS", 120, minimum=1, maximum=10_000)
    rate_window = _env_int("TRUSTGUARD_RATE_LIMIT_WINDOW_SECONDS", 60, minimum=1, maximum=3600)
    request_timeout = _env_int("TRUSTGUARD_REQUEST_TIMEOUT_SECONDS", 30, minimum=1, maximum=300)

    application = FastAPI(
        title="TrustGuard Skyfire Seller Service",
        description=(
            "Validates one explicitly configured Skyfire KYAPay protocol profile and provides a separate "
            "provider-free, ledger-reserved ML transaction screening endpoint. No route creates or captures PayPal orders. "
            f"Selected profile: {settings.protocol_profile if settings is not None else 'UNCONFIGURED; requests fail closed'}. "
            "Account-specific activation requires SKYFIRE_ACCOUNT_CONFIGURATION_CONFIRMED=true after authoritative operator verification."
        ),
        version="1.0.0",
        openapi_url=configured_openapi_path if openapi_enabled and settings is not None else None,
        docs_url=None,
        redoc_url=None,
    )
    application.add_middleware(
        RequestGuardMiddleware,
        max_body_bytes=max_body_bytes,
        max_concurrent_requests=max_concurrent,
        rate_limit_requests=rate_limit,
        rate_limit_window_seconds=rate_window,
        request_timeout_seconds=float(request_timeout),
    )
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
    application.add_middleware(
        TokenCacheControlMiddleware,
        token_headers=[LEGACY_HEADER, DRAFT_HEADER],
    )
    application.state.ready = ready
    application.state.protocol_profile = settings.protocol_profile if settings is not None else None
    application.state.screening = screening
    application.state.paypal_mapping_status = mapping_status
    application.state.paypal_merchant_id = paypal_merchant_id
    application.state.reviewer_id = reviewer_id
    application.state.reviewer_credential = reviewer_credential
    application.state.reviewer_enabled = reviewer_enabled

    @application.exception_handler(RequestValidationError)
    async def sanitized_validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        # Validation libraries may include rejected input values in default details.
        return JSONResponse(status_code=422, content={"detail": "request validation failed"})

    @application.get("/healthz", tags=["system"], summary="Service readiness")
    def healthz() -> dict[str, str]:
        if not application.state.ready:
            raise HTTPException(status_code=503, detail="service configuration unavailable")
        return {"status": "ok"}

    def verify_request_token(request: Request, *, payment_required: bool) -> dict[str, Any]:
        if settings is None or verifier is None:
            raise SkyfireTokenError("Skyfire protocol profile is unavailable")
        selected_header = protocol_header(settings.protocol_profile)
        other_header = DRAFT_HEADER if selected_header == LEGACY_HEADER else LEGACY_HEADER

        def values_for(header_name: str) -> list[str]:
            target = header_name.lower().encode("ascii")
            return [value.decode("latin-1") for name, value in request.scope.get("headers", [])
                    if name.lower() == target]

        tokens = parse_profile_header(
            settings.protocol_profile,
            values_for(selected_header),
            values_for(other_header),
        )
        # This API operation has one authorization result and one transaction.
        # Reject multiple token members as ambiguous rather than choosing by order.
        if len(tokens) != 1:
            raise SkyfireTokenError("request must contain exactly one Skyfire token")
        verified = verifier.verify(tokens[0])
        if payment_required and verified.get("token_type") not in {"pay+jwt", "kya-pay+jwt"}:
            raise SkyfireTokenError("a payment token is required")
        return verified

    @application.post(
        "/v1/agent/authorize",
        response_model=AuthorizationResponse,
        tags=["agent"],
        summary="Validate a Skyfire token",
        responses={401: {"description": "Token missing or invalid"}, 503: {"description": "Service configuration or durable ledger unavailable"}},
    )
    def authorize(request: Request) -> AuthorizationResponse:
        if not application.state.ready:
            raise HTTPException(status_code=503, detail="service configuration unavailable")
        try:
            verified = verify_request_token(request, payment_required=False)
        except SkyfireTokenError:
            raise HTTPException(status_code=401, detail="Skyfire token validation failed") from None
        payment = None
        if verified["amount"] is not None:
            amount = verified["amount"]
            payment = SkyfireAuthorizationSignal(
                status="TOKEN_AUTHORIZATION_SIGNAL_ONLY",
                amount=format(amount if isinstance(amount, Decimal) else Decimal(str(amount)), "f"),
                currency=verified["currency"],
            )
        return AuthorizationResponse(
            valid=True,
            token_type=verified["token_type"],
            subject_id=verified["sub"],
            subject_semantics=verified["sub_semantics"],
            audience=verified["aud"],
            buyer_agent_account_id=verified["sub"] if settings.protocol_profile == "legacy-published" else None,
            seller_agent_account_id=verified["aud"] if settings.protocol_profile == "legacy-published" else None,
            seller_service_id=verified["service_id"],
            skyfire_payment_authorization=payment,
            paypal_payment_status="NOT_STARTED",
            paypal_payment_authorized=False,
        )

    @application.post(
        "/v1/agent/screen-transaction",
        response_model=TransactionScreenResponse,
        tags=["agent"],
        summary="Authorize and screen a transaction (no provider dispatch)",
        description=(
        "LOCAL TEST ONLY examples must use generated keys/tokens and fake JWKS only in local tests. "
            "The endpoint requires a valid configured Skyfire PAY/KYA-PAY token, caps transaction amount "
            "and binds currency to its signed payment claims and service ID to the selected profile's authenticated service claim. The configured "
            "PayPal merchant ID is loaded only from trusted server environment mapping and stored separately; "
            "request bodies cannot provide it. The endpoint durably reserves the canonical transaction and runs "
            "local IsolationForest screening. It never calls PayPal."
        ),
        responses={
            401: {"description": "Skyfire token missing or invalid"},
            403: {"description": "Token has no matching payment authorization"},
            409: {"description": "Transaction authorization, idempotency, or reservation rejected"},
            503: {"description": "Service configuration or durable ledger unavailable"},
        },
    )
    def screen_transaction(
        request: TransactionScreenRequest,
        http_request: Request,
    ) -> TransactionScreenResponse:
        if not application.state.ready or application.state.screening is None:
            raise HTTPException(status_code=503, detail="service configuration unavailable")
        try:
            verified = verify_request_token(http_request, payment_required=True)
        except SkyfireTokenError:
            raise HTTPException(status_code=401, detail="Skyfire token validation failed") from None
        if verified.get("amount") is None:
            raise HTTPException(status_code=403, detail="a valid Skyfire payment authorization is required")
        authorized_amount = verified["amount"]
        currency = verified.get("currency")
        service_id = verified.get("service_id")
        if not isinstance(authorized_amount, Decimal) or not authorized_amount.is_finite() or authorized_amount <= 0:
            raise HTTPException(status_code=403, detail="Skyfire payment authorization is invalid")
        if not isinstance(currency, str) or currency != "USD" or not isinstance(service_id, str) or not service_id:
            raise HTTPException(status_code=403, detail="Skyfire payment target authorization is invalid")
        try:
            submitted_amount = Decimal(request.amount)
            if not submitted_amount.is_finite() or submitted_amount <= 0 or submitted_amount > authorized_amount:
                raise HTTPException(status_code=403, detail="transaction amount exceeds Skyfire authorization")
            if request.currency != currency:
                raise HTTPException(status_code=403, detail="transaction currency does not match Skyfire authorization")
            amount_minor_decimal = authorized_amount * 100
            if amount_minor_decimal != amount_minor_decimal.to_integral_value():
                raise HTTPException(status_code=403, detail="authorized amount is not representable in currency minor units")
            tx = CanonicalTransaction.build(
                transaction_id=request.transaction_id,
                idempotency_key=request.idempotency_key,
                amount=request.amount,
                currency=request.currency,
                payee=paypal_merchant_id,
                skyfire_service_id=service_id,
                paypal_merchant_id=paypal_merchant_id,
                supported_currencies=("USD",),
            )
        except (InvalidOperation, ValueError, SecurityError):
            raise HTTPException(status_code=422, detail="canonical transaction is invalid") from None
        identity = json.dumps(
            [settings.issuer, verified.get("sub"), verified.get("aud"), service_id],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        grant_id = "skyfire:" + hashlib.sha256(identity).hexdigest()
        try:
            outcome = application.state.screening.screen_authorized_transaction(
                tx,
                grant_id=grant_id,
                max_spend_minor=int(amount_minor_decimal),
                grant_currency=currency,
                authorized_service_id=service_id,
            )
            record = ledger.get(tx.transaction_id)
        except SecurityError:
            raise HTTPException(status_code=409, detail="transaction authorization, idempotency, or reservation rejected") from None
        except (LedgerError, sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="durable transaction screening unavailable") from None
        if not record or not record.get("risk_model_version") or not record.get("risk_training_dataset_id") or record.get("risk_scored_at") is None:
            raise HTTPException(status_code=503, detail="durable risk assessment unavailable")
        return TransactionScreenResponse(
            status=outcome["status"],
            transaction_state=record["status"],
            reason_code=outcome["reason_code"],
            transaction_id=tx.transaction_id,
            currency=tx.currency,
            amount=format(tx.amount_decimal, "f"),
            skyfire_service_id=tx.skyfire_service_id or "",
            paypal_merchant_id=tx.paypal_merchant_id,
            paypal_integration_status=application.state.paypal_mapping_status,
            risk_assessment=RiskAssessmentResponse(
                anomaly_score=record["anomaly_score"],
                model_version=record["risk_model_version"],
                training_dataset_id=record["risk_training_dataset_id"],
                scored_at=record["risk_scored_at"],
                decision=record["risk_decision"],
                explanation=record["risk_explanation"],
            ),
            paypal_dispatch="DISABLED_NOT_CALLED",
        )

    @application.post(
        "/v1/admin/transactions/{transaction_id}/review",
        response_model=HoldReviewResponse,
        tags=["admin"],
        summary="Review a held transaction without authorizing payment",
        description=(
            "Requires TRUSTGUARD_REVIEWER_ID and TRUSTGUARD_REVIEWER_CREDENTIAL. "
            "KEEP_HOLD retains the reservation; RELEASE_RESERVATION only abandons a still-undispatched HOLD. "
            "Neither decision authorizes payment or calls PayPal. Identical retries return the original audit record."
        ),
        responses={401: {"description": "Reviewer credential invalid"}, 409: {"description": "Transaction is not safely reviewable or has a conflicting prior review"}, 503: {"description": "Review authentication or durable ledger unavailable"}},
    )
    def review_held_transaction(
        transaction_id: str,
        request: HoldReviewRequest,
        reviewer_credential: str = Header(..., alias="x-trustguard-reviewer-credential"),
    ) -> HoldReviewResponse:
        if not application.state.ready or ledger is None or not application.state.reviewer_enabled:
            raise HTTPException(status_code=503, detail="administrative review is not configured")
        if not hmac.compare_digest(
            reviewer_credential.encode("utf-8"),
            application.state.reviewer_credential.encode("utf-8"),
        ):
            raise HTTPException(status_code=401, detail="reviewer authentication failed")
        try:
            audit = ledger.review_hold(
                transaction_id,
                reviewer_id=application.state.reviewer_id,
                decision=request.decision,
                reason=request.reason,
            )
        except LedgerError:
            raise HTTPException(status_code=409, detail="transaction cannot be reviewed in its current state") from None
        except (sqlite3.Error, OSError):
            raise HTTPException(status_code=503, detail="durable review audit unavailable") from None
        return HoldReviewResponse(**audit)

    if settings is not None:
        def selected_profile_openapi() -> dict[str, Any]:
            if application.openapi_schema is not None:
                return application.openapi_schema
            schema = get_openapi(
                title=application.title,
                version=application.version,
                description=application.description,
                routes=application.routes,
            )
            if settings.protocol_profile == "legacy-published":
                contract = (
                    "Published Skyfire validation profile: one skyfire-pay-id compact JWT; "
                    "accepted typ values kya+jwt, pay+jwt, kya-pay+jwt; Seller Service binding uses ssi."
                )
            else:
                contract = (
                    "November 2026 KYAPay Internet-Draft profile (work in progress, not a finalized standard): "
                    "KYAPay-Token Structured Field List; this API operation accepts exactly one JWT member; "
                    "accepted typ values kya+jwt, pay+jwt, kya-pay+jwt; Seller Service binding uses tsi."
                )
            parameter = {
                "name": protocol_header(settings.protocol_profile),
                "in": "header",
                "required": True,
                "description": contract,
                "schema": {"type": "string"},
            }
            for path in ("/v1/agent/authorize", "/v1/agent/screen-transaction"):
                operation = schema.get("paths", {}).get(path, {}).get("post")
                if operation is not None:
                    operation.setdefault("parameters", []).append(parameter.copy())
                    operation["description"] = (operation.get("description", "") + "\n\n" + contract).strip()
            application.openapi_schema = schema
            return schema

        application.openapi = selected_profile_openapi  # type: ignore[method-assign]

    return application


# Keep the container importable when secrets/configuration are absent: health/readiness
# reports 503, the OpenAPI schema remains available, and authorization remains blocked.
app = create_app()
