"""Strict, explicitly selected Skyfire KYAPay protocol profiles.

No profile is inferred from an incoming token. Raw tokens and settlement claims are
never logged or returned. All generated-key tests are LOCAL TEST ONLY fixtures.
"""
from __future__ import annotations

import os
import math
import re
import threading
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

import jwt
import requests
from jwt import InvalidTokenError

from trustguard import SecurityError

PROFILE_LEGACY = "legacy-published"
PROFILE_DRAFT = "ietf-draft-2026-11"
SUPPORTED_PROFILES = frozenset({PROFILE_LEGACY, PROFILE_DRAFT})
LEGACY_HEADER = "skyfire-pay-id"
DRAFT_HEADER = "KYAPay-Token"
DOCUMENTED_SANDBOX_ISSUER = "https://app-sandbox.skyfire.xyz"
DOCUMENTED_SANDBOX_JWKS_URL = "https://app-sandbox.skyfire.xyz/.well-known/jwks.json"
EXPECTED_SANDBOX_ENVIRONMENT = "sandbox"
JWKS_CACHE_TTL_SECONDS = 300
JWKS_CACHE_MAX_SECONDS = 3600
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


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
    protocol_profile: str | None = None
    expected_audience: str | None = None
    account_configuration_confirmed: bool = False

    def __post_init__(self) -> None:
        if self.protocol_profile not in SUPPORTED_PROFILES:
            raise SkyfireTokenError("an explicit supported Skyfire protocol profile is required")
        if not all((self.issuer, self.jwks_url, self.expected_environment,
                    self.seller_agent_account_id, self.seller_service_id, self.database_path)):
            raise SkyfireTokenError("required Skyfire service configuration is missing")
        if self.seller_service_id.startswith("LOCAL-TEST-ONLY-PAYPAL-"):
            raise SkyfireTokenError("synthetic service identities are forbidden in official Skyfire verification")
        if self.database_path == ":memory:":
            raise SkyfireTokenError("a durable TrustGuard ledger path is required")
        if self.expected_environment != EXPECTED_SANDBOX_ENVIRONMENT:
            raise SkyfireTokenError("only explicitly configured Sandbox validation is supported")
        if not isinstance(self.account_configuration_confirmed, bool):
            raise SkyfireTokenError("Skyfire account-configuration confirmation is invalid")
        issuer = urlsplit(self.issuer)
        jwks = urlsplit(self.jwks_url)
        if (issuer.scheme != "https" or not issuer.hostname or issuer.path not in ("", "/")
                or issuer.query or issuer.fragment or issuer.username or issuer.password):
            raise SkyfireTokenError("trusted issuer must be a configured HTTPS origin")
        if (jwks.scheme != "https" or not jwks.hostname or jwks.username or jwks.password
                or jwks.query or jwks.fragment or jwks.netloc.lower() != issuer.netloc.lower()
                or jwks.path != "/.well-known/jwks.json"):
            raise SkyfireTokenError("JWKS URL must be the configured issuer's well-known endpoint")
        if not isinstance(self.expected_audience, str) or not self.expected_audience.strip():
            raise SkyfireTokenError("an exact trusted Skyfire audience is required")
        if self.protocol_profile == PROFILE_LEGACY and self.expected_audience != self.seller_agent_account_id:
            raise SkyfireTokenError("published-profile audience must equal the configured Seller Agent Account ID")
        if self.target_domain is not None and not self.target_domain.strip():
            raise SkyfireTokenError("configured target domain is invalid")

    @classmethod
    def from_env(cls) -> "SkyfireSettings":
        profile = os.environ.get("SKYFIRE_PROTOCOL_PROFILE", "").strip()
        if profile not in SUPPORTED_PROFILES:
            raise SkyfireTokenError("SKYFIRE_PROTOCOL_PROFILE must explicitly select a supported profile")
        confirmation = os.environ.get("SKYFIRE_ACCOUNT_CONFIGURATION_CONFIRMED", "false").strip().lower()
        if confirmation not in {"true", "false"}:
            raise SkyfireTokenError("SKYFIRE_ACCOUNT_CONFIGURATION_CONFIRMED must be true or false")
        values = {
            "issuer": os.environ.get("SKYFIRE_ISSUER", "").strip(),
            "jwks_url": os.environ.get("SKYFIRE_JWKS_URL", "").strip(),
            "expected_environment": os.environ.get("SKYFIRE_EXPECTED_ENVIRONMENT", "").strip(),
            "seller_agent_account_id": os.environ.get("SKYFIRE_SELLER_AGENT_ACCOUNT_ID", "").strip(),
            "seller_service_id": os.environ.get("SKYFIRE_SELLER_SERVICE_ID", "").strip(),
            "database_path": os.environ.get("TRUSTGUARD_DATABASE_PATH", "").strip(),
            "protocol_profile": profile,
            "expected_audience": os.environ.get("SKYFIRE_EXPECTED_AUDIENCE", "").strip() or None,
            "account_configuration_confirmed": confirmation == "true",
        }
        if values["expected_audience"] is None and profile == PROFILE_LEGACY:
            # Legacy published documentation defines aud as the Seller Agent Account ID.
            values["expected_audience"] = values["seller_agent_account_id"] or None
        target_domain = os.environ.get("SKYFIRE_TARGET_DOMAIN", "").strip() or None
        try:
            return cls(**values, target_domain=target_domain)
        except TypeError as exc:
            raise SkyfireTokenError("required Skyfire service configuration is invalid") from exc


def protocol_header(profile: str) -> str:
    if profile == PROFILE_LEGACY:
        return LEGACY_HEADER
    if profile == PROFILE_DRAFT:
        return DRAFT_HEADER
    raise SkyfireTokenError("an explicit supported Skyfire protocol profile is required")


def parse_profile_header(profile: str, selected_values: Sequence[str], other_values: Sequence[str]) -> list[str]:
    """Parse exactly the selected profile's wire representation, never fall back."""
    if profile not in SUPPORTED_PROFILES:
        raise SkyfireTokenError("Skyfire protocol profile is unavailable")
    if other_values:
        raise SkyfireTokenError("request contains a conflicting Skyfire protocol header")
    if not selected_values:
        raise SkyfireTokenError("Skyfire token header is missing")
    if any(not isinstance(value, str) or not value for value in selected_values):
        raise SkyfireTokenError("Skyfire token header is malformed")
    if sum(len(value) for value in selected_values) > 65536:
        raise SkyfireTokenError("Skyfire token header is malformed")
    if profile == PROFILE_LEGACY:
        if len(selected_values) != 1 or not _TOKEN_RE.fullmatch(selected_values[0]):
            raise SkyfireTokenError("published Skyfire token header is malformed")
        return [selected_values[0]]

    # draft-02 defines a List Structured Field whose members are bare Tokens.
    # Compact JWT characters are a strict subset of SF Token characters; parse
    # that subset and reject parameters, quoted members, empty members and junk.
    joined = ",".join(selected_values)
    if not joined.strip():
        raise SkyfireTokenError("draft KYAPay token list is malformed")
    tokens: list[str] = []
    for member in joined.split(","):
        token = member.strip(" \t")
        if not token or not _TOKEN_RE.fullmatch(token):
            raise SkyfireTokenError("draft KYAPay token list is malformed")
        tokens.append(token)
    return tokens


class _ProfileAdapter:
    name: str
    header: str
    token_types: frozenset[str]
    service_claim: str

    def normalize_type(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.lower()
        if normalized.startswith("application/"):
            normalized = normalized[len("application/"):]
        return normalized if normalized in self.token_types else None

    def validate_claims(self, claims: dict[str, Any], token_type: str,
                        settings: SkyfireSettings, now: float) -> dict[str, Any]:
        raise NotImplementedError

    @staticmethod
    def _amount(value: Any) -> Decimal | None:
        if not isinstance(value, str):
            return None
        try:
            result = Decimal(str(value))
        except (InvalidOperation, ValueError):
            return None
        return result if result.is_finite() and result > 0 else None

    @staticmethod
    def _base(claims: dict[str, Any], settings: SkyfireSettings, now: float,
              *, uuid_identifiers: bool) -> tuple[str, str, str, int, int, str]:
        required = ("iss", "sub", "aud", "iat", "exp", "jti")
        if any(name not in claims for name in required):
            raise SkyfireTokenError("Skyfire token validation failed")
        if claims.get("iss") != settings.issuer or claims.get("aud") != settings.expected_audience:
            raise SkyfireTokenError("Skyfire token validation failed")
        sub, jti = claims.get("sub"), claims.get("jti")
        if not isinstance(sub, str) or not sub or len(sub) > 2048 or not isinstance(jti, str) or not jti or len(jti) > 256:
            raise SkyfireTokenError("Skyfire token validation failed")
        if uuid_identifiers:
            try:
                sub = str(uuid.UUID(sub))
                jti = str(uuid.UUID(jti))
            except (ValueError, AttributeError) as exc:
                raise SkyfireTokenError("Skyfire token validation failed") from exc
        iat, exp = claims.get("iat"), claims.get("exp")
        if (isinstance(iat, bool) or not isinstance(iat, int) or iat >= int(now)
                or isinstance(exp, bool) or not isinstance(exp, int) or exp <= now or exp <= iat):
            raise SkyfireTokenError("Skyfire token validation failed")
        # Draft -03 permits an absent env claim; any supplied value is bound to Sandbox.
        if "env" in claims and claims["env"] != settings.expected_environment:
            raise SkyfireTokenError("Skyfire token validation failed")
        return settings.issuer, sub, claims["aud"], iat, exp, jti

    @staticmethod
    def _payment(claims: dict[str, Any], token_type: str,
                 profile: str) -> tuple[Decimal | None, str | None]:
        if token_type == "kya+jwt":
            return None, None
        amount = _ProfileAdapter._amount(claims.get("amt"))
        currency = claims.get("cur")
        settlement_value = _ProfileAdapter._amount(claims.get("val"))
        settlement_type = claims.get("stp")
        settlement_info = claims.get("sti")
        if (amount is None or settlement_value is None
                or not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency)
                or settlement_type not in {"coin", "card"}
                or not isinstance(settlement_info, dict)):
            raise SkyfireTokenError("Skyfire payment claims are invalid")
        if "verified" in settlement_info and settlement_info["verified"] is not True:
            raise SkyfireTokenError("Skyfire payment claims are invalid")
        if profile == PROFILE_DRAFT:
            settlement_names = {"coin": {"usdc"}, "card": {"visa_vic", "mastercard_scof"}}
            if settlement_info.get("type") not in settlement_names[settlement_type]:
                raise SkyfireTokenError("Skyfire payment claims are invalid")
            if "tps" in claims and claims["tps"] not in {
                "pay_per_use", "subscription", "pay_per_mb", "custom",
            }:
                raise SkyfireTokenError("Skyfire payment claims are invalid")
            if "tpr" in claims and _ProfileAdapter._amount(claims["tpr"]) is None:
                raise SkyfireTokenError("Skyfire payment claims are invalid")
            if "mnr" in claims and (
                isinstance(claims["mnr"], bool)
                or not isinstance(claims["mnr"], (int, float))
                or not math.isfinite(claims["mnr"])
                or claims["mnr"] <= 0
            ):
                raise SkyfireTokenError("Skyfire payment claims are invalid")
            if settlement_type == "card" and (
                not isinstance(settlement_info.get("payment_token"), str)
                or not re.fullmatch(r"[0-9]{12,19}", settlement_info["payment_token"])
                or not isinstance(settlement_info.get("token_expiration_month"), str)
                or not re.fullmatch(r"0[1-9]|1[0-2]", settlement_info["token_expiration_month"])
                or not isinstance(settlement_info.get("token_expiration_year"), str)
                or not re.fullmatch(r"[0-9]{4}", settlement_info["token_expiration_year"])
                or not isinstance(settlement_info.get("token_security_code"), str)
                or not re.fullmatch(r"[0-9]{3,4}", settlement_info["token_security_code"])
            ):
                raise SkyfireTokenError("Skyfire payment claims are invalid")
        return amount, currency


class LegacyPublishedProfile(_ProfileAdapter):
    """Published validation profile: skyfire-pay-id + ssi (not an account approval)."""
    name = PROFILE_LEGACY
    header = LEGACY_HEADER
    token_types = frozenset({"kya+jwt", "pay+jwt", "kya-pay+jwt"})
    service_claim = "ssi"

    def validate_claims(self, claims: dict[str, Any], token_type: str,
                        settings: SkyfireSettings, now: float) -> dict[str, Any]:
        # A valid `tsi` is never a substitute for published `ssi`.
        if ("tsi" in claims or claims.get("ssi") != settings.seller_service_id
                or claims.get("env") != settings.expected_environment):
            raise SkyfireTokenError("Skyfire token validation failed")
        _, sub, audience, iat, exp, jti = self._base(claims, settings, now, uuid_identifiers=True)
        amount, currency = self._payment(claims, token_type, self.name)
        return _normalized(self.name, token_type, settings.issuer, sub, audience,
                           settings.seller_service_id, exp, jti, amount, currency, claims)


class NovemberDraftProfile(_ProfileAdapter):
    """November 2026 working-draft profile: KYAPay-Token List + tsi."""
    name = PROFILE_DRAFT
    header = DRAFT_HEADER
    token_types = frozenset({"kya+jwt", "pay+jwt", "kya-pay+jwt"})
    service_claim = "tsi"

    def validate_claims(self, claims: dict[str, Any], token_type: str,
                        settings: SkyfireSettings, now: float) -> dict[str, Any]:
        # A valid `ssi` is never a substitute for draft `tsi`.
        if "ssi" in claims or claims.get("tsi") != settings.seller_service_id:
            raise SkyfireTokenError("Skyfire token validation failed")
        _, sub, audience, iat, exp, jti = self._base(claims, settings, now, uuid_identifiers=False)
        if settings.target_domain is not None and claims.get("tdm") != settings.target_domain:
            raise SkyfireTokenError("Skyfire token target domain is invalid")
        amount, currency = self._payment(claims, token_type, self.name)
        return _normalized(self.name, token_type, settings.issuer, sub, audience,
                           settings.seller_service_id, exp, jti, amount, currency, claims)


def _normalized(profile: str, token_type: str, issuer: str, subject: str, audience: str,
                service_id: str, exp: int, jti: str, amount: Decimal | None,
                currency: str | None, claims: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "protocol_profile": profile,
        "token_type": token_type,
        "issuer": issuer,
        "sub": subject,
        "sub_semantics": "buyer_agent_account_id" if profile == PROFILE_LEGACY else "pairwise_initiator_identity_subject",
        "aud": audience,
        "service_id": service_id,
        "exp": exp,
        "jti": jti,
        "amount": amount,
        "currency": currency,
        "tdm": claims.get("tdm") if profile == PROFILE_DRAFT else None,
    }


_PROFILES: dict[str, _ProfileAdapter] = {
    PROFILE_LEGACY: LegacyPublishedProfile(),
    PROFILE_DRAFT: NovemberDraftProfile(),
}


class SkyfireTokenVerifier:
    """Verify one explicitly selected profile against configured issuer keys."""

    def __init__(self, settings: SkyfireSettings, *, jwks_fetcher: Callable[[], Mapping[str, Any]] | None = None,
                 cache_ttl_seconds: int = JWKS_CACHE_TTL_SECONDS, clock: Callable[[], float] = time.time,
                 monotonic_clock: Callable[[], float] = time.monotonic):
        if not isinstance(settings, SkyfireSettings) or settings.protocol_profile not in _PROFILES:
            raise SkyfireTokenError("an explicit supported Skyfire protocol profile is required")
        if not isinstance(cache_ttl_seconds, int) or isinstance(cache_ttl_seconds, bool) or not 1 <= cache_ttl_seconds <= JWKS_CACHE_MAX_SECONDS:
            raise SkyfireTokenError("JWKS cache duration is invalid")
        self.settings = settings
        self.profile = _PROFILES[settings.protocol_profile]
        self._fetcher = jwks_fetcher or self._fetch_jwks
        self._ttl = cache_ttl_seconds
        self._clock = clock
        self._monotonic = monotonic_clock
        self._lock = threading.Lock()
        self._keys: dict[str, dict[str, Any]] = {}
        self._expires_at = 0.0

    def _fetch_jwks(self) -> Mapping[str, Any]:
        response = requests.get(self.settings.jwks_url, headers={"Accept": "application/json"},
                                timeout=(3.05, 10.0), allow_redirects=False)
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

    def verify(self, token: str) -> dict[str, Any]:
        if not self.settings.account_configuration_confirmed:
            raise SkyfireTokenError("Skyfire account configuration is not confirmed")
        if not isinstance(token, str) or not token or len(token) > 65536 or not _TOKEN_RE.fullmatch(token):
            raise SkyfireTokenError("Skyfire token is missing or malformed")
        try:
            header = jwt.get_unverified_header(token)
        except (InvalidTokenError, TypeError, ValueError) as exc:
            raise SkyfireTokenError("Skyfire token is malformed") from exc
        kid = header.get("kid")
        token_type = self.profile.normalize_type(header.get("typ"))
        if not isinstance(kid, str) or not kid or header.get("alg") != "ES256" or token_type is None:
            raise SkyfireTokenError("Skyfire token header is not accepted")
        jwk = self._get_keys().get(kid)
        if jwk is None:
            raise SkyfireTokenError("Skyfire signing key is not trusted")
        try:
            key = jwt.PyJWK.from_dict(jwk, algorithm="ES256").key
            claims = jwt.decode(
                token, key, algorithms=["ES256"], issuer=self.settings.issuer,
                audience=self.settings.expected_audience, leeway=0,
                options={"require": ["iss", "sub", "aud", "iat", "exp", "jti"],
                         "verify_signature": True, "verify_iss": True,
                         "verify_aud": True, "verify_iat": True,
                         "verify_exp": True, "verify_nbf": True},
            )
        except (jwt.PyJWTError, TypeError, ValueError, KeyError) as exc:
            raise SkyfireTokenError("Skyfire token validation failed") from exc
        return self.profile.validate_claims(claims, token_type, self.settings, self._clock())


__all__ = [
    "DOCUMENTED_SANDBOX_ISSUER", "DOCUMENTED_SANDBOX_JWKS_URL",
    "EXPECTED_SANDBOX_ENVIRONMENT", "LEGACY_HEADER", "DRAFT_HEADER",
    "PROFILE_LEGACY", "PROFILE_DRAFT", "SUPPORTED_PROFILES",
    "LegacyPublishedProfile", "NovemberDraftProfile", "SkyfireSettings",
    "SkyfireTokenError", "SkyfireTokenVerifier", "parse_profile_header",
    "protocol_header",
]
