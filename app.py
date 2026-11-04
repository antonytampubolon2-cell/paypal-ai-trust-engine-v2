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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from skyfire_auth import SkyfireSettings, SkyfireTokenError, SkyfireTokenVerifier
from trustguard import CanonicalTransaction, Ledger, LedgerError, RiskScreeningPipeline, SecurityError

_DEFAULT_API_SCORER = object()


class SkyfireAuthorizationSignal(BaseModel):
    status: str
    amount: str | None = None
    currency: str | None = None


class AuthorizationResponse(BaseModel):
    valid: bool
    token_type: str
    buyer_agent_account_id: str
    seller_agent_account_id: str
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

class RiskAssessmentResponse(BaseModel):
    anomaly_score: float | None
    model_version: str
    training_dataset_id: str
    scored_at: float


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


def create_app(*, settings: SkyfireSettings | None = None, ledger: Ledger | None = None,
               verifier: Any | None = None, ledger_factory: Callable[[str], Ledger] = Ledger,
               risk_scorer: Any = _DEFAULT_API_SCORER) -> FastAPI:
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
    ready = settings is not None and ledger is not None and verifier is not None and not error
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

    application = FastAPI(
        title="TrustGuard Skyfire Seller Service",
        description="Validates Skyfire tokens and provides a separate provider-free, ledger-reserved ML transaction screening endpoint. No route creates or captures PayPal orders.",
        version="1.0.0",
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url=None,
    )
    application.state.ready = ready
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

    @application.post(
        "/v1/agent/authorize",
        response_model=AuthorizationResponse,
        tags=["agent"],
        summary="Validate a Skyfire token",
        responses={401: {"description": "Token missing or invalid"}, 503: {"description": "Service configuration or durable ledger unavailable"}},
    )
    def authorize(skyfire_pay_id: str = Header(..., alias="skyfire-pay-id")) -> AuthorizationResponse:
        if not application.state.ready:
            raise HTTPException(status_code=503, detail="service configuration unavailable")
        try:
            verified = verifier.verify(skyfire_pay_id)
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
            buyer_agent_account_id=verified["sub"],
            seller_agent_account_id=verified["aud"],
            seller_service_id=verified["tsi"],
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
            "and binds currency to its signed payment claims and service ID to authenticated tsi. The configured "
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
        skyfire_pay_id: str = Header(..., alias="skyfire-pay-id"),
    ) -> TransactionScreenResponse:
        if not application.state.ready or application.state.screening is None:
            raise HTTPException(status_code=503, detail="service configuration unavailable")
        try:
            verified = verifier.verify(skyfire_pay_id)
        except SkyfireTokenError:
            raise HTTPException(status_code=401, detail="Skyfire token validation failed") from None
        if verified.get("token_type") not in {"pay+jwt", "kya-pay+jwt"} or verified.get("amount") is None:
            raise HTTPException(status_code=403, detail="a valid Skyfire payment authorization is required")
        authorized_amount = verified["amount"]
        currency = verified.get("currency")
        service_id = verified.get("tsi")
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

    return application


# Keep the container importable when secrets/configuration are absent: health/readiness
# reports 503, the OpenAPI schema remains available, and authorization remains blocked.
app = create_app()
