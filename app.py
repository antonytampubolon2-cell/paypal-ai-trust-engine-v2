"""Minimal TrustGuard Seller Service API. Skyfire validation never invokes PayPal."""
from __future__ import annotations

import sqlite3
import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Any, Callable

from fastapi import FastAPI, Header, HTTPException
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
    payee: StrictStr = Field(min_length=1, max_length=256)

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
    payee: str
    risk_assessment: RiskAssessmentResponse
    paypal_dispatch: str = "DISABLED_NOT_CALLED"


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
            "and binds currency to its signed payment claims and payee to its authenticated target service, reserves the "
            "canonical transaction durably, and runs local IsolationForest screening. It never calls PayPal."
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
            if request.currency != currency or request.payee != service_id:
                raise HTTPException(status_code=403, detail="transaction currency or payee does not match Skyfire authorization")
            amount_minor_decimal = authorized_amount * 100
            if amount_minor_decimal != amount_minor_decimal.to_integral_value():
                raise HTTPException(status_code=403, detail="authorized amount is not representable in currency minor units")
            tx = CanonicalTransaction.build(
                transaction_id=request.transaction_id,
                idempotency_key=request.idempotency_key,
                amount=request.amount,
                currency=request.currency,
                payee=request.payee,
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
                authorized_payees=(service_id,),
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
            payee=tx.payee,
            risk_assessment=RiskAssessmentResponse(
                anomaly_score=record["anomaly_score"],
                model_version=record["risk_model_version"],
                training_dataset_id=record["risk_training_dataset_id"],
                scored_at=record["risk_scored_at"],
            ),
            paypal_dispatch="DISABLED_NOT_CALLED",
        )

    return application


# Keep the container importable when secrets/configuration are absent: health/readiness
# reports 503, the OpenAPI schema remains available, and authorization remains blocked.
app = create_app()
