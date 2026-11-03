"""Minimal TrustGuard Seller Service API. Skyfire validation never invokes PayPal."""
from __future__ import annotations

import sqlite3
from decimal import Decimal
from typing import Any, Callable

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from skyfire_auth import SkyfireSettings, SkyfireTokenError, SkyfireTokenVerifier
from trustguard import Ledger, SecurityError


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


def create_app(*, settings: SkyfireSettings | None = None, ledger: Ledger | None = None,
               verifier: Any | None = None, ledger_factory: Callable[[str], Ledger] = Ledger) -> FastAPI:
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

    application = FastAPI(
        title="TrustGuard Skyfire Seller Service",
        description="Validates Skyfire KYAPay tokens. Token validation does not authorize or initiate PayPal payments.",
        version="1.0.0",
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url=None,
    )
    application.state.ready = ready

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
        responses={401: {"description": "Token missing, invalid, or already used"}, 503: {"description": "Service configuration or replay store unavailable"}},
    )
    def authorize(skyfire_pay_id: str = Header(..., alias="skyfire-pay-id")) -> AuthorizationResponse:
        if not application.state.ready:
            raise HTTPException(status_code=503, detail="service configuration unavailable")
        try:
            verified = verifier.verify(skyfire_pay_id)
        except SkyfireTokenError:
            raise HTTPException(status_code=401, detail="Skyfire token validation failed") from None
        try:
            ledger.claim_replay_id("skyfire", verified["jti"], float(verified["exp"]))
        except SecurityError:
            raise HTTPException(status_code=401, detail="Skyfire token validation failed") from None
        except Exception:
            raise HTTPException(status_code=503, detail="authorization replay store unavailable") from None

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
            seller_service_id=verified["ssi"],
            skyfire_payment_authorization=payment,
            paypal_payment_status="NOT_STARTED",
            paypal_payment_authorized=False,
        )

    return application


# Keep the container importable when secrets/configuration are absent: health/readiness
# reports 503, the OpenAPI schema remains available, and authorization remains blocked.
app = create_app()
