"""Fail-closed security primitives for PayPal AI Trust Engine.

The repository does not currently document a trusted KYAPay issuer, token format,
signing algorithm, or key-discovery mechanism. JWT verification here is therefore
an explicit adapter, not a claim that the current KYAPay integration is configured.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

import jwt




# Deliberately narrow allowlist: ISO 4217 minor units for currencies this
# adapter has explicitly elected to support. Expand only after PayPal/KYAPay
# contracts and merchant-account capabilities are verified.
SUPPORTED_CURRENCY_MINOR_UNITS = {
    "USD": 2, "EUR": 2, "GBP": 2, "CAD": 2, "AUD": 2,
    "JPY": 0, "KRW": 0, "BHD": 3, "KWD": 3,
}


@dataclass(frozen=True)
class CanonicalTransaction:
    """Validated immutable transaction used for both policy and PayPal payload."""
    merchant: str
    paypal_merchant_id: str
    amount: Decimal
    currency: str
    description: str = "Authorized transaction"

    @property
    def amount_text(self) -> str:
        return format(self.amount, f".{SUPPORTED_CURRENCY_MINOR_UNITS[self.currency]}f")

    def as_policy_mapping(self) -> Mapping[str, Any]:
        return {"merchant": self.merchant, "amount": self.amount, "currency": self.currency}


def canonicalize_transaction(
    transaction: Mapping[str, Any], *, merchant_mapping: Mapping[str, str]
) -> CanonicalTransaction:
    """Validate and freeze money and explicit internal-merchant -> PayPal ID mapping.

    The source merchant is a delegation identity, never implicitly a PayPal ID.
    """
    if not isinstance(transaction, Mapping):
        raise ValueError("Transaction must be a mapping.")
    merchant = transaction.get("merchant")
    currency = transaction.get("currency")
    raw_amount = transaction.get("amount")
    if not isinstance(merchant, str) or not merchant.strip():
        raise ValueError("Transaction merchant is required.")
    if not isinstance(currency, str) or currency not in SUPPORTED_CURRENCY_MINOR_UNITS:
        raise ValueError("Transaction currency is unsupported.")
    if isinstance(raw_amount, bool) or not isinstance(raw_amount, (str, int, Decimal)):
        raise ValueError("Transaction amount must be a decimal string, integer, or Decimal.")
    try:
        amount = Decimal(str(raw_amount))
    except (InvalidOperation, ValueError):
        raise ValueError("Transaction amount is malformed.") from None
    if not amount.is_finite():
        raise ValueError("Transaction amount must be finite.")
    if amount <= 0:
        raise ValueError("Transaction amount must be greater than zero.")
    minor_units = SUPPORTED_CURRENCY_MINOR_UNITS[currency]
    if amount.as_tuple().exponent < -minor_units:
        raise ValueError(f"Amount has more decimal places than {currency} permits.")
    # Normalize without rounding; the exponent check above makes this exact.
    amount = amount.quantize(Decimal(1).scaleb(-minor_units))
    if not isinstance(merchant_mapping, Mapping):
        raise ValueError("An explicit merchant mapping is required.")
    paypal_merchant_id = merchant_mapping.get(merchant)
    if not isinstance(paypal_merchant_id, str) or not paypal_merchant_id.strip():
        raise ValueError("No verified PayPal merchant ID mapping exists for this merchant.")
    # Require an explicit PayPal merchant identifier format; do not derive from name/token.
    if paypal_merchant_id != paypal_merchant_id.strip():
        raise ValueError("PayPal merchant ID mapping is malformed.")
    description = transaction.get("description", "Authorized transaction")
    if not isinstance(description, str):
        raise ValueError("Transaction description must be a string.")
    return CanonicalTransaction(merchant, paypal_merchant_id, amount, currency, description)


class SecurityConfigurationError(RuntimeError):
    """Raised when a security control cannot be configured safely."""


class ReplayStore:
    """Atomic replay-store interface. Implementations must reject duplicate keys."""

    def claim_once(self, namespace: str, identifier: str, expires_at: float) -> bool:
        raise NotImplementedError


class SQLiteReplayStore(ReplayStore):
    """Persistent, atomic replay store for a single host/shared local filesystem.

    Multi-host deployments must provide a distributed implementation with an
    atomic insert-if-absent operation (for example Redis SET NX with TTL).
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        if not str(path).strip():
            raise SecurityConfigurationError("A replay database path is required.")
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path, timeout=10) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS replay_entries (
                    namespace TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (namespace, identifier)
                )"""
            )

    def claim_once(self, namespace: str, identifier: str, expires_at: float) -> bool:
        if not namespace or not isinstance(identifier, str) or not identifier:
            return False
        now = time.time()
        if not isinstance(expires_at, (int, float)) or expires_at <= now:
            return False
        try:
            with sqlite3.connect(self.path, timeout=10, isolation_level=None) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM replay_entries WHERE expires_at <= ?", (now,))
                connection.execute(
                    "INSERT INTO replay_entries(namespace, identifier, expires_at) VALUES (?, ?, ?)",
                    (namespace, identifier, float(expires_at)),
                )
                connection.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            return False


@dataclass(frozen=True)
class AuthenticationResult:
    authenticated: bool
    claims: Mapping[str, Any] | None = None
    reason: str = ""


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    reason: str = ""


@dataclass(frozen=True)
class PaymentResult:
    """Backward-compatible, independent security and transaction lifecycle statuses.

    Legacy policy_status and delivery_status remain available. New callers should
    use authorization_status and order_status. ORDER_CREATED means only that PayPal
    returned an order identifier; capture remains NOT_ATTEMPTED because this
    dispatcher never captures payments.
    """
    authentication_status: str
    policy_status: str
    delivery_status: Literal["NOT_ATTEMPTED", "FAILED", "UNKNOWN", "ORDER_CREATED"]
    reason: str = ""
    dpop_status: str = "NOT_RUN"
    authorization_status: str = "NOT_RUN"
    order_status: Literal["NOT_ATTEMPTED", "FAILED", "UNKNOWN", "ORDER_CREATED"] = "NOT_ATTEMPTED"
    capture_status: Literal["NOT_ATTEMPTED"] = "NOT_ATTEMPTED"

    def __post_init__(self) -> None:
        # Keep legacy and explicit order/authorization fields coherent.
        if self.authorization_status == "NOT_RUN" and self.policy_status != "NOT_RUN":
            object.__setattr__(self, "authorization_status", self.policy_status)
        if self.order_status == "NOT_ATTEMPTED" and self.delivery_status != "NOT_ATTEMPTED":
            object.__setattr__(self, "order_status", self.delivery_status)
        if self.delivery_status != self.order_status:
            object.__setattr__(self, "delivery_status", self.order_status)


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SecurityConfigurationError(f"Required security configuration is missing: {name}")
    return value


def authenticate_kyapay_jwt(compact_token: str) -> AuthenticationResult:
    """Verify a signed KYAPay JWT using explicitly configured trust material.

    This adapter is usable only if the real KYAPay issuer confirms that its
    tokens are JWTs and supplies the issuer, audience, algorithm and verification
    key through deployment configuration. It never accepts a decoded dict as proof.
    """
    try:
        issuer = _required_env("KYAPAY_ISSUER")
        audience = _required_env("KYAPAY_AUDIENCE")
        public_key = _required_env("KYAPAY_PUBLIC_KEY_PEM").replace("\\n", "\n")
        algorithm = _required_env("KYAPAY_JWT_ALGORITHM")
        if algorithm not in {"RS256", "ES256", "EdDSA"}:
            return AuthenticationResult(False, reason="Configured JWT algorithm is not allowed.")
        if not isinstance(compact_token, str) or compact_token.count(".") != 2:
            return AuthenticationResult(False, reason="A signed compact JWT is required.")
        claims = jwt.decode(
            compact_token,
            public_key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
            options={"require": ["iss", "sub", "aud", "exp", "jti", "delegation_grant"]},
            leeway=0,
        )
        if not isinstance(claims.get("delegation_grant"), dict):
            return AuthenticationResult(False, reason="delegation_grant must be an object.")
        if not isinstance(claims.get("jti"), str) or not claims["jti"]:
            return AuthenticationResult(False, reason="A non-empty jti claim is required.")
        return AuthenticationResult(True, claims=claims, reason="Signature and registered claims verified.")
    except SecurityConfigurationError as exc:
        return AuthenticationResult(False, reason=str(exc))
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        # Do not leak token contents, keys, or detailed parser errors to callers.
        return AuthenticationResult(False, reason=f"Token authentication failed ({type(exc).__name__}).")


def _jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    kty = jwk.get("kty")
    if kty == "EC":
        names = ("crv", "kty", "x", "y")
    elif kty == "RSA":
        names = ("e", "kty", "n")
    elif kty == "OKP" and jwk.get("crv") in {"Ed25519", "Ed448"}:
        names = ("crv", "kty", "x")
    else:
        raise ValueError("Unsupported DPoP public JWK type.")
    if any(not isinstance(jwk.get(name), str) or not jwk[name] for name in names):
        raise ValueError("DPoP JWK is missing required public parameters.")
    canonical = json.dumps({name: jwk[name] for name in names}, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def verify_dpop_proof(
    compact_proof: str,
    *,
    expected_method: str,
    expected_url: str,
    replay_store: ReplayStore,
    access_token_claims: Mapping[str, Any] | None = None,
    access_token: str | None = None,
    now: float | None = None,
    max_age_seconds: int = 300,
) -> PolicyResult:
    """Verify a DPoP JWT signature and required proof bindings.

    expected_url must already be canonicalized according to RFC 9449 (htu excludes
    query and fragment). The verifier rejects symmetric/none algorithms and private
    key material in the embedded JWK.
    """
    now = time.time() if now is None else now
    try:
        if not isinstance(compact_proof, str) or compact_proof.count(".") != 2:
            return PolicyResult(False, "A signed compact DPoP JWT is required.")
        header = jwt.get_unverified_header(compact_proof)
        if header.get("typ", "").lower() != "dpop+jwt":
            return PolicyResult(False, "DPoP typ header must be dpop+jwt.")
        algorithm = header.get("alg")
        if algorithm not in {"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}:
            return PolicyResult(False, "DPoP algorithm is not allowed.")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            return PolicyResult(False, "DPoP public JWK is required.")
        if any(name in jwk for name in ("d", "p", "q", "dp", "dq", "qi", "k")):
            return PolicyResult(False, "Private or symmetric JWK material is forbidden.")
        thumbprint = _jwk_thumbprint(jwk)
        public_key = jwt.PyJWK.from_dict(jwk, algorithm=algorithm).key
        claims = jwt.decode(
            compact_proof,
            public_key,
            algorithms=[algorithm],
            options={"verify_signature": True, "verify_exp": False, "verify_aud": False},
        )
        if claims.get("htm") != expected_method.upper():
            return PolicyResult(False, "DPoP htm mismatch.")
        if not validate_canonical_url(expected_url):
            return PolicyResult(False, "Expected DPoP htu must be an HTTPS URL without query or fragment.")
        if claims.get("htu") != expected_url:
            return PolicyResult(False, "DPoP htu mismatch.")
        if access_token_claims is not None:
            if not isinstance(access_token, str) or not access_token:
                return PolicyResult(False, "The original access token is required to verify DPoP ath.")
            expected_ath = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("ascii")).digest()).decode("ascii").rstrip("=")
            if claims.get("ath") != expected_ath:
                return PolicyResult(False, "DPoP ath does not match the presented access token.")
        jti = claims.get("jti")
        iat = claims.get("iat")
        if not isinstance(jti, str) or not jti:
            return PolicyResult(False, "DPoP jti is required.")
        if not isinstance(iat, (int, float)) or abs(now - iat) > max_age_seconds:
            return PolicyResult(False, "DPoP iat is missing or outside the accepted time window.")
        if access_token_claims is not None:
            expected_jkt = access_token_claims.get("cnf", {}).get("jkt") if isinstance(access_token_claims.get("cnf"), dict) else None
            if not expected_jkt or expected_jkt != thumbprint:
                return PolicyResult(False, "DPoP key thumbprint does not match token cnf.jkt.")
        try:
            claimed = replay_store.claim_once("dpop", jti, now + max_age_seconds)
        except Exception:
            return PolicyResult(False, "DPoP replay storage failed closed.")
        if not claimed:
            return PolicyResult(False, "DPoP proof replay detected or replay storage unavailable.")
        return PolicyResult(True, "DPoP signature and proof bindings verified.")
    except (jwt.PyJWTError, TypeError, ValueError, KeyError) as exc:
        return PolicyResult(False, f"DPoP verification failed ({type(exc).__name__}).")


def authorize_delegated_transaction(
    claims: Mapping[str, Any],
    transaction: Mapping[str, Any] | CanonicalTransaction,
    replay_store: ReplayStore,
    *,
    now: float | None = None,
) -> PolicyResult:
    """Apply delegation policy to the same canonical transaction object sent onward."""
    now = time.time() if now is None else now
    try:
        grant = claims.get("delegation_grant")
        if not isinstance(grant, dict):
            return PolicyResult(False, "delegation_grant is missing or invalid.")
        if isinstance(transaction, CanonicalTransaction):
            merchant = transaction.merchant
            amount = transaction.amount
            currency = transaction.currency
        else:
            merchant = transaction.get("merchant")
            amount = Decimal(str(transaction.get("amount")))
            currency = transaction.get("currency")
        allowed_merchants = grant.get("allowed_merchants")
        max_spend = Decimal(str(grant.get("max_spend")))
        grant_currency = grant.get("currency")
        valid_until = float(grant.get("valid_until"))
        if not isinstance(merchant, str) or not merchant:
            return PolicyResult(False, "Transaction merchant is required.")
        if not isinstance(allowed_merchants, list) or merchant not in allowed_merchants:
            return PolicyResult(False, "Merchant is not permitted by the delegation grant.")
        if not amount.is_finite() or amount <= 0 or not max_spend.is_finite() or max_spend <= 0:
            return PolicyResult(False, "Transaction amount or delegation limit is invalid.")
        if amount > max_spend:
            return PolicyResult(False, "Transaction exceeds delegated spending limit.")
        if not isinstance(currency, str) or currency != grant_currency:
            return PolicyResult(False, "Transaction currency does not match delegation grant.")
        if valid_until <= now:
            return PolicyResult(False, "Delegation grant has expired.")
        token_exp = float(claims.get("exp"))
        if token_exp <= now:
            return PolicyResult(False, "Authorization token has expired.")
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            return PolicyResult(False, "Token jti is required.")
        try:
            claimed = replay_store.claim_once("kyapay", jti, token_exp)
        except Exception:
            return PolicyResult(False, "Token replay storage failed closed.")
        if not claimed:
            return PolicyResult(False, "Token replay detected or replay storage unavailable.")
        return PolicyResult(True, "Delegation policy and token replay checks passed.")
    except (InvalidOperation, TypeError, ValueError, OverflowError):
        return PolicyResult(False, "Transaction or delegation fields are malformed.")


def validate_canonical_url(url: str) -> bool:
    """Utility for callers constructing expected DPoP htu values."""
    try:
        parsed = urlsplit(url)
        return parsed.scheme == "https" and bool(parsed.netloc) and not parsed.query and not parsed.fragment
    except ValueError:
        return False
