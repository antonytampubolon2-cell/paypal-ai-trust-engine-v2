"""Skyfire KYAPay bearer-token validation. Token contents and settlement data are never logged."""
from __future__ import annotations

import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

import jwt
import requests
from jwt import InvalidTokenError

from trustguard import SecurityError

# Skyfire's official seller-verification guide publishes the Sandbox JWKS URL.
# KYAPay draft-03 specifies that the JWKS URI is built from the trusted iss origin
# plus /.well-known/jwks.json. Therefore this verifier only enables that documented pair.
DOCUMENTED_SANDBOX_ISSUER = "https://app-sandbox.skyfire.xyz"
DOCUMENTED_SANDBOX_JWKS_URL = "https://app-sandbox.skyfire.xyz/.well-known/jwks.json"
EXPECTED_SANDBOX_ENVIRONMENT = "sandbox"
ALLOWED_TYPES = {"kya+jwt", "pay+jwt", "kya-pay+jwt"}
JWKS_CACHE_TTL_SECONDS = 300
JWKS_CACHE_MAX_SECONDS = 3600


class SkyfireTokenError(SecurityError):
    """Sanitized validation/configuration failure; never includes token or claim contents."""


@dataclass(frozen=True)
class SkyfireSettings:
    issuer: str
    jwks_url: str
    expected_environment: str
    seller_agent_account_id: str
    seller_service_id: str
    database_path: str
    target_domain: str | None = None

    def __post_init__(self) -> None:
        if not all((self.issuer, self.jwks_url, self.expected_environment, self.seller_agent_account_id, self.seller_service_id, self.database_path)):
            raise SkyfireTokenError("required Skyfire service configuration is missing")
        if self.seller_service_id.startswith("LOCAL-TEST-ONLY-PAYPAL-"):
            raise SkyfireTokenError("synthetic service identities are forbidden in official Skyfire verification")
        if self.database_path == ":memory:":
            raise SkyfireTokenError("a durable TrustGuard ledger path is required")
        if self.expected_environment != EXPECTED_SANDBOX_ENVIRONMENT:
            raise SkyfireTokenError("only explicitly configured Sandbox validation is supported")
        if self.issuer != DOCUMENTED_SANDBOX_ISSUER or self.jwks_url != DOCUMENTED_SANDBOX_JWKS_URL:
            raise SkyfireTokenError("issuer and JWKS must match the documented Skyfire Sandbox pair")
        parsed = urlsplit(self.issuer)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
            raise SkyfireTokenError("trusted issuer must be an HTTPS origin")
        if self.jwks_url != self.issuer + "/.well-known/jwks.json":
            raise SkyfireTokenError("JWKS URL does not match the configured issuer")
        if self.target_domain is not None and not self.target_domain.strip():
            raise SkyfireTokenError("configured target domain is invalid")

    @classmethod
    def from_env(cls) -> "SkyfireSettings":
        values = {
            "issuer": os.environ.get("SKYFIRE_ISSUER", "").strip(),
            "jwks_url": os.environ.get("SKYFIRE_JWKS_URL", "").strip(),
            "expected_environment": os.environ.get("SKYFIRE_EXPECTED_ENVIRONMENT", "").strip(),
            "seller_agent_account_id": os.environ.get("SKYFIRE_SELLER_AGENT_ACCOUNT_ID", "").strip(),
            "seller_service_id": os.environ.get("SKYFIRE_SELLER_SERVICE_ID", "").strip(),
            "database_path": os.environ.get("TRUSTGUARD_DATABASE_PATH", "").strip(),
        }
        target_domain = os.environ.get("SKYFIRE_TARGET_DOMAIN", "").strip() or None
        try:
            return cls(**values, target_domain=target_domain)
        except TypeError as exc:
            raise SkyfireTokenError("required Skyfire service configuration is invalid") from exc


class SkyfireTokenVerifier:
    """Verify Skyfire JWTs against an explicit, bounded HTTPS JWKS configuration."""

    def __init__(self, settings: SkyfireSettings, *, jwks_fetcher: Callable[[], Mapping[str, Any]] | None = None,
                 cache_ttl_seconds: int = JWKS_CACHE_TTL_SECONDS, clock: Callable[[], float] = time.time,
                 monotonic_clock: Callable[[], float] = time.monotonic):
        if not isinstance(settings, SkyfireSettings):
            raise SkyfireTokenError("required Skyfire service configuration is missing")
        if not isinstance(cache_ttl_seconds, int) or isinstance(cache_ttl_seconds, bool) or not 1 <= cache_ttl_seconds <= JWKS_CACHE_MAX_SECONDS:
            raise SkyfireTokenError("JWKS cache duration is invalid")
        self.settings = settings
        self._fetcher = jwks_fetcher or self._fetch_jwks
        self._ttl = cache_ttl_seconds
        self._clock = clock
        self._monotonic = monotonic_clock
        self._lock = threading.Lock()
        self._keys: dict[str, dict[str, Any]] = {}
        self._expires_at = 0.0

    def _fetch_jwks(self) -> Mapping[str, Any]:
        response = requests.get(
            self.settings.jwks_url,
            headers={"Accept": "application/json"},
            timeout=(3.05, 10.0),
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise SkyfireTokenError("Skyfire signing keys are unavailable")
        try:
            data = response.json()
        except (ValueError, AttributeError) as exc:
            raise SkyfireTokenError("Skyfire signing keys are unavailable") from exc
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            raise SkyfireTokenError("Skyfire signing keys are unavailable")
        return data

    def _get_keys(self) -> dict[str, dict[str, Any]]:
        now = self._monotonic()
        with self._lock:
            if self._keys and now < self._expires_at:
                return self._keys
            try:
                document = self._fetcher()
            except SkyfireTokenError:
                raise
            except Exception as exc:
                raise SkyfireTokenError("Skyfire signing keys are unavailable") from exc
            values = document.get("keys") if isinstance(document, Mapping) else None
            if not isinstance(values, list):
                raise SkyfireTokenError("Skyfire signing keys are unavailable")
            keys: dict[str, dict[str, Any]] = {}
            for key in values:
                if not isinstance(key, dict) or not isinstance(key.get("kid"), str) or not key["kid"]:
                    continue
                if any(name in key for name in ("d", "p", "q", "dp", "dq", "qi", "k")):
                    continue
                if key.get("kty") != "EC" or key.get("crv") != "P-256":
                    continue
                if key.get("alg") not in (None, "ES256") or key.get("use") not in (None, "sig"):
                    continue
                key_ops = key.get("key_ops")
                if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
                    continue
                if key["kid"] in keys:
                    raise SkyfireTokenError("Skyfire signing-key set is invalid")
                keys[key["kid"]] = key
            if not keys:
                raise SkyfireTokenError("Skyfire signing-key set is invalid")
            self._keys = keys
            self._expires_at = now + min(self._ttl, JWKS_CACHE_MAX_SECONDS)
            return self._keys

    @staticmethod
    def _header_type(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.lower()
        if normalized.startswith("application/"):
            normalized = normalized[len("application/"):]
        return normalized if normalized in ALLOWED_TYPES else None

    @staticmethod
    def _positive_decimal(value: Any) -> Decimal | None:
        if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
            return None
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, ValueError):
            return None
        return amount if amount.is_finite() and amount > 0 else None

    def verify(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token or len(token) > 65536:
            raise SkyfireTokenError("Skyfire token is missing or malformed")
        try:
            header = jwt.get_unverified_header(token)
        except (InvalidTokenError, TypeError, ValueError) as exc:
            raise SkyfireTokenError("Skyfire token is malformed") from exc
        kid = header.get("kid")
        token_type = self._header_type(header.get("typ"))
        if not isinstance(kid, str) or not kid or header.get("alg") != "ES256" or token_type is None:
            raise SkyfireTokenError("Skyfire token header is not accepted")
        jwk = self._get_keys().get(kid)
        if jwk is None:
            raise SkyfireTokenError("Skyfire signing key is not trusted")
        try:
            key = jwt.PyJWK.from_dict(jwk, algorithm="ES256").key
            claims = jwt.decode(
                token,
                key,
                algorithms=["ES256"],
                issuer=self.settings.issuer,
                audience=self.settings.seller_agent_account_id,
                leeway=60,
                options={"require": ["iss", "sub", "aud", "iat", "exp", "jti", "env", "tsi"], "verify_signature": True, "verify_iss": True, "verify_aud": True, "verify_iat": True, "verify_exp": True, "verify_nbf": True},
            )
        except (jwt.PyJWTError, TypeError, ValueError, KeyError) as exc:
            raise SkyfireTokenError("Skyfire token validation failed") from exc
        now = self._clock()
        if claims.get("iss") != self.settings.issuer or claims.get("aud") != self.settings.seller_agent_account_id:
            raise SkyfireTokenError("Skyfire token validation failed")
        if claims.get("env") != self.settings.expected_environment:
            raise SkyfireTokenError("Skyfire token validation failed")
        if claims.get("tsi") != self.settings.seller_service_id:
            raise SkyfireTokenError("Skyfire token validation failed")
        if self.settings.target_domain is not None and claims.get("tdm") != self.settings.target_domain:
            raise SkyfireTokenError("Skyfire token target domain is invalid")
        iat, exp = claims.get("iat"), claims.get("exp")
        if isinstance(iat, bool) or not isinstance(iat, int) or iat > now + 60 or isinstance(exp, bool) or not isinstance(exp, int) or exp <= now or exp <= iat:
            raise SkyfireTokenError("Skyfire token time claims are invalid")
        jti = claims.get("jti")
        if not isinstance(jti, str):
            raise SkyfireTokenError("Skyfire token identifier is invalid")
        try:
            canonical_jti = str(uuid.UUID(jti))
        except (ValueError, AttributeError) as exc:
            raise SkyfireTokenError("Skyfire token identifier is invalid") from exc
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise SkyfireTokenError("Skyfire token subject is invalid")

        amount: Decimal | None = None
        currency: str | None = None
        if token_type in {"pay+jwt", "kya-pay+jwt"}:
            amount = self._positive_decimal(claims.get("amt"))
            raw_currency = claims.get("cur")
            if amount is None or not isinstance(raw_currency, str) or not re.fullmatch(r"[A-Z]{3}", raw_currency):
                raise SkyfireTokenError("Skyfire payment claims are invalid")
            currency = raw_currency
            if currency != "USD" or self._positive_decimal(claims.get("val")) is None:
                raise SkyfireTokenError("Skyfire settlement claims are invalid")
            settlement_type = claims.get("stp")
            if not isinstance(settlement_type, str) or settlement_type not in {"coin", "card", "bank"}:
                raise SkyfireTokenError("Skyfire settlement claims are invalid")
            settlement_info = claims.get("sti")
            if not isinstance(settlement_info, dict) or settlement_info.get("verified") is not True:
                raise SkyfireTokenError("Skyfire settlement claims are invalid")

        # jti identifies this token; it is not used to reject repeated presentations.
        # Return only a minimized projection. `sti` and the JWT are never returned.
        return {
            "token_type": token_type,
            "jti": canonical_jti,
            "exp": exp,
            "sub": claims["sub"],
            "aud": claims["aud"],
            "tsi": claims["tsi"],
            "tdm": claims.get("tdm") if self.settings.target_domain is not None else None,
            "amount": amount,
            "currency": currency,
        }


__all__ = [
    "ALLOWED_TYPES", "DOCUMENTED_SANDBOX_ISSUER",
    "DOCUMENTED_SANDBOX_JWKS_URL", "EXPECTED_SANDBOX_ENVIRONMENT", "SkyfireSettings",
    "SkyfireTokenError", "SkyfireTokenVerifier",
]
