"""Fail-closed TrustGuard primitives. No provider is initialized or called at import time."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit

import jwt
from jwt import InvalidTokenError

from risk_scoring import (
    ANOMALY_THRESHOLD,
    MODEL_VERSION,
    TRAINING_DATASET_ID,
    RiskAssessment,
    SyntheticIsolationForestScorer,
)

_DEFAULT_RISK_SCORER = object()


class SecurityError(Exception):
    """Request failed authentication, authorization, or transaction safety checks."""


class ConfigurationError(SecurityError):
    pass


class LedgerError(SecurityError):
    pass


class ProviderDefinitiveError(Exception):
    """Provider explicitly rejected a request before creating an order."""


class ProviderAmbiguousError(Exception):
    """Provider outcome may have happened; never retry create automatically."""

    def __init__(self, message: str = "provider outcome is ambiguous", provider_order_id: str | None = None):
        super().__init__(message)
        self.provider_order_id = provider_order_id


@dataclass(frozen=True)
class TrustConfig:
    issuer: str
    audience: str
    trusted_keys: Mapping[str, str]
    jwt_algorithms: tuple[str, ...]
    grant_id_field: str
    grant_limit_field: str
    grant_currency_field: str
    grant_payees_field: str
    token_grant_claim: str = "delegation_grant"
    max_dpop_age_seconds: int = 300
    supported_currencies: tuple[str, ...] = ("USD",)

    @classmethod
    def from_env(cls) -> "TrustConfig":
        try:
            keys = json.loads(os.environ["TRUSTGUARD_JWT_PUBLIC_KEYS_JSON"])
            algorithms = tuple(x.strip() for x in os.environ.get("TRUSTGUARD_JWT_ALGORITHMS", "ES256").split(",") if x.strip())
            issuer = os.environ["TRUSTGUARD_ISSUER"]
            audience = os.environ["TRUSTGUARD_AUDIENCE"]
            required = {
                "grant_id_field": os.environ["TRUSTGUARD_GRANT_ID_FIELD"],
                "grant_limit_field": os.environ["TRUSTGUARD_GRANT_LIMIT_FIELD"],
                "grant_currency_field": os.environ["TRUSTGUARD_GRANT_CURRENCY_FIELD"],
                "grant_payees_field": os.environ["TRUSTGUARD_GRANT_PAYEES_FIELD"],
            }
            if not isinstance(keys, dict) or not keys or not all(isinstance(k, str) and isinstance(v, str) for k, v in keys.items()):
                raise ValueError("public keys must be a non-empty JSON object")
            if not algorithms or any(a not in {"RS256", "ES256", "EdDSA"} for a in algorithms):
                raise ValueError("unsupported or empty JWT algorithm allowlist")
            if not issuer or not audience or not all(required.values()):
                raise ValueError("required trust configuration is empty")
            return cls(issuer=issuer, audience=audience, trusted_keys=keys, jwt_algorithms=algorithms, **required)
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as e:
            raise ConfigurationError("TrustGuard trust configuration is incomplete or invalid") from e

    @classmethod
    def from_values(cls, *, issuer: str, audience: str, trusted_keys: Mapping[str, str], grant_id_field: str, grant_limit_field: str, grant_currency_field: str, grant_payees_field: str, jwt_algorithms: tuple[str, ...] = ("ES256",), **kwargs: Any) -> "TrustConfig":
        if not issuer or not audience or not trusted_keys or not all((grant_id_field, grant_limit_field, grant_currency_field, grant_payees_field)):
            raise ConfigurationError("issuer, audience, trusted keys, and explicit grant field configuration are required")
        if not jwt_algorithms or any(a not in {"RS256", "ES256", "EdDSA"} for a in jwt_algorithms):
            raise ConfigurationError("unsupported or empty JWT algorithm allowlist")
        return cls(issuer, audience, dict(trusted_keys), jwt_algorithms, grant_id_field, grant_limit_field, grant_currency_field, grant_payees_field, **kwargs)


@dataclass(frozen=True)
class CanonicalTransaction:
    transaction_id: str
    idempotency_key: str
    amount_minor: int
    currency: str
    payee: str | None
    skyfire_service_id: str | None = None
    paypal_merchant_id: str | None = None

    @classmethod
    def build(cls, *, transaction_id: str, idempotency_key: str, amount: str | Decimal, currency: str, payee: str | None = None, skyfire_service_id: str | None = None, paypal_merchant_id: str | None = None, supported_currencies: tuple[str, ...] = ("USD",)) -> "CanonicalTransaction":
        if not transaction_id or not idempotency_key or not any((payee, skyfire_service_id, paypal_merchant_id)):
            raise SecurityError("transaction identity, idempotency key, and trusted payee binding are required")
        if payee is not None and paypal_merchant_id is not None and payee != paypal_merchant_id:
            raise SecurityError("legacy payee conflicts with configured PayPal merchant identity")
        merchant = paypal_merchant_id if paypal_merchant_id is not None else payee
        if currency not in supported_currencies:
            raise SecurityError("unsupported currency")
        try:
            value = Decimal(str(amount))
        except (InvalidOperation, ValueError) as e:
            raise SecurityError("invalid amount") from e
        if not value.is_finite() or value <= 0 or value.as_tuple().exponent < -2:
            raise SecurityError("amount must be positive and representable in currency minor units")
        minor = int(value * 100)
        if Decimal(minor) / 100 != value:
            raise SecurityError("amount is not an exact minor-unit value")
        return cls(transaction_id, idempotency_key, minor, currency, merchant, skyfire_service_id, merchant)

    @property
    def amount_decimal(self) -> Decimal:
        return Decimal(self.amount_minor) / 100

    @property
    def risk_payee_identity(self) -> str:
        return self.paypal_merchant_id or self.skyfire_service_id or self.payee or ""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    if jwk.get("kty") == "EC" and jwk.get("crv") in {"P-256", "P-384", "P-521"}:
        members = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif jwk.get("kty") == "RSA":
        members = {k: jwk[k] for k in ("e", "kty", "n")}
    elif jwk.get("kty") == "OKP" and jwk.get("crv") in {"Ed25519", "Ed448"}:
        members = {k: jwk[k] for k in ("crv", "kty", "x")}
    else:
        raise SecurityError("unsupported or malformed DPoP public JWK")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return _b64url(hashlib.sha256(canonical).digest())


def _normalized_htu(url: str) -> str:
    p = urlsplit(url)
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password or p.fragment:
        raise SecurityError("invalid DPoP target URI")
    host = p.hostname.lower()
    port = p.port
    netloc = host if port is None or (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80) else f"{host}:{port}"
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))


def _get_key_id(token: str) -> str:
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except (InvalidTokenError, TypeError, AttributeError) as e:
        raise SecurityError("malformed signed token") from e
    if not isinstance(kid, str) or not kid:
        raise SecurityError("token key id is missing")
    return kid


class Authenticator:
    def __init__(self, config: TrustConfig):
        self.config = config

    def verify_access_token(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token:
            raise SecurityError("serialized access token is required")
        kid = _get_key_id(token)
        key = self.config.trusted_keys.get(kid)
        if key is None:
            raise SecurityError("untrusted access-token signing key")
        try:
            claims = jwt.decode(token, key, algorithms=list(self.config.jwt_algorithms), issuer=self.config.issuer, audience=self.config.audience, options={"require": ["iss", "sub", "aud", "exp", "iat", "jti", self.config.token_grant_claim], "verify_signature": True, "verify_iss": True, "verify_aud": True, "verify_exp": True, "verify_iat": True, "verify_nbf": True})
        except (InvalidTokenError, TypeError, ValueError) as e:
            raise SecurityError("access-token verification failed") from e
        grant = claims.get(self.config.token_grant_claim)
        if not isinstance(grant, dict):
            raise SecurityError("authenticated grant claim is malformed")
        required = (self.config.grant_id_field, self.config.grant_limit_field, self.config.grant_currency_field, self.config.grant_payees_field)
        if any(field not in grant for field in required):
            raise SecurityError("configured authenticated grant fields are missing")
        gid = grant[self.config.grant_id_field]
        if not isinstance(gid, str) or not gid.strip():
            raise SecurityError("authenticated grant identity is invalid")
        grant["_canonical_grant_id"] = gid
        return claims

    def verify_dpop(self, proof: str, claims: Mapping[str, Any], method: str, url: str, access_token: str | None = None, *, now: float | None = None) -> str:
        if not isinstance(proof, str) or not proof:
            raise SecurityError("serialized DPoP proof is required")
        now = time.time() if now is None else now
        try:
            header = jwt.get_unverified_header(proof)
            if header.get("typ", "").lower() != "dpop+jwt" or header.get("alg") in (None, "none", "HS256", "HS384", "HS512"):
                raise SecurityError("invalid DPoP protected header")
            jwk = header.get("jwk")
            if not isinstance(jwk, dict) or any(k in jwk for k in ("d", "p", "q", "dp", "dq", "qi", "k")):
                raise SecurityError("DPoP header must contain a public-only JWK")
            key = jwt.PyJWK.from_dict(jwk, algorithm=header["alg"]).key
            proof_claims = jwt.decode(proof, key, algorithms=[header["alg"]], options={"verify_signature": True, "verify_exp": False, "verify_aud": False, "verify_iat": False, "verify_nbf": False})
        except SecurityError:
            raise
        except (InvalidTokenError, TypeError, ValueError, KeyError, AttributeError) as e:
            raise SecurityError("DPoP signature or structure verification failed") from e
        cnf = claims.get("cnf")
        if not isinstance(cnf, dict) or cnf.get("jkt") != jwk_thumbprint(jwk):
            raise SecurityError("DPoP key does not match authenticated token cnf.jkt")
        if proof_claims.get("htm") != method.upper() or proof_claims.get("htu") != _normalized_htu(url):
            raise SecurityError("DPoP request binding mismatch")
        iat, jti = proof_claims.get("iat"), proof_claims.get("jti")
        if not isinstance(iat, (int, float)) or abs(now - iat) > self.config.max_dpop_age_seconds:
            raise SecurityError("DPoP proof is stale or has invalid issuance time")
        if not isinstance(jti, str) or not jti or len(jti) > 256:
            raise SecurityError("DPoP jti is missing or malformed")
        if access_token is not None:
            expected_ath = _b64url(hashlib.sha256(access_token.encode()).digest())
            if proof_claims.get("ath") != expected_ath:
                raise SecurityError("DPoP access-token hash mismatch")
        return jti


class Ledger:
    """SQLite-backed spend reservations and durable token/proof replay protection."""
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path == ":memory:":
            raise ConfigurationError("TrustGuard requires a durable file-backed SQLite database")
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        db = self._connect()
        try:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
                    amount_minor INTEGER NOT NULL CHECK(amount_minor > 0), currency TEXT NOT NULL, payee TEXT,
                    skyfire_service_id TEXT, paypal_merchant_id TEXT,
                    status TEXT NOT NULL CHECK(status IN ('RESERVED','SCREENED_ALLOW','HOLD','REVIEW_RELEASED','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','FAILED','UNKNOWN')),
                    provider_order_id TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS tx_grant_status ON transactions(grant_id, status);
                CREATE TABLE IF NOT EXISTS replay_ids (kind TEXT NOT NULL, jti TEXT NOT NULL, expires_at REAL NOT NULL, PRIMARY KEY(kind,jti));
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    transaction_id TEXT PRIMARY KEY,
                    anomaly_score REAL CHECK(anomaly_score IS NULL OR (anomaly_score >= 0 AND anomaly_score <= 1)),
                    model_version TEXT NOT NULL,
                    training_dataset_id TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision IN ('ALLOW','HOLD')),
                    scored_at REAL NOT NULL,
                    features_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS transaction_reviews (
                    transaction_id TEXT PRIMARY KEY,
                    reviewer_id TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision IN ('KEEP_HOLD','RELEASE_RESERVATION')),
                    reason TEXT NOT NULL,
                    reviewed_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS capture_attempts (
                    transaction_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    started_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_evidence (
                    evidence_id INTEGER PRIMARY KEY,
                    transaction_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    recorded_at REAL NOT NULL
                );
            """)
            schema = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='transactions'").fetchone()[0]
            columns = {row[1] for row in db.execute("PRAGMA table_info(transactions)")}
            if ("'SCREENED_ALLOW'" not in schema or "'REVIEW_RELEASED'" not in schema
                    or not {"skyfire_service_id", "paypal_merchant_id"}.issubset(columns)):
                try:
                    db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE transactions_new (
                        transaction_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
                        amount_minor INTEGER NOT NULL CHECK(amount_minor > 0), currency TEXT NOT NULL, payee TEXT,
                        skyfire_service_id TEXT, paypal_merchant_id TEXT,
                        status TEXT NOT NULL CHECK(status IN ('RESERVED','SCREENED_ALLOW','HOLD','REVIEW_RELEASED','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','FAILED','UNKNOWN')),
                        provider_order_id TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
                    );
                    INSERT INTO transactions_new(transaction_id,grant_id,idempotency_key,amount_minor,currency,payee,
                      skyfire_service_id,paypal_merchant_id,status,provider_order_id,created_at,updated_at)
                    SELECT transaction_id,grant_id,idempotency_key,amount_minor,currency,
                      CASE WHEN grant_id LIKE 'skyfire:%' THEN NULL ELSE payee END,
                      CASE WHEN grant_id LIKE 'skyfire:%' THEN payee ELSE NULL END,
                      CASE WHEN grant_id LIKE 'skyfire:%' THEN NULL ELSE payee END,
                      CASE status WHEN 'ORDER_CREATED' THEN 'CREATED' ELSE status END,
                      provider_order_id,created_at,updated_at FROM transactions;
                    DROP TABLE transactions;
                    ALTER TABLE transactions_new RENAME TO transactions;
                    CREATE INDEX tx_grant_status ON transactions(grant_id,status);
                    COMMIT;
                    """)
                except Exception:
                    if db.in_transaction:
                        db.rollback()
                    raise
        finally:
            db.close()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        if self.path != ":memory:":
            db.execute("PRAGMA synchronous=FULL")
        return db

    def claim_replay_id(self, kind: str, jti: str, expires_at: float, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM replay_ids WHERE expires_at <= ?", (now,))
            db.execute("INSERT INTO replay_ids(kind,jti,expires_at) VALUES(?,?,?)", (kind, jti, expires_at))
            db.commit()
        except sqlite3.IntegrityError as e:
            db.rollback()
            raise SecurityError("replayed identifier") from e
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def reserve(self, grant_id: str, tx: CanonicalTransaction, max_spend_minor: int, grant_currency: str) -> str:
        if not grant_id or not isinstance(max_spend_minor, int) or isinstance(max_spend_minor, bool) or max_spend_minor <= 0:
            raise SecurityError("invalid authenticated grant authorization")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT transaction_id,status,grant_id,amount_minor,currency,payee,skyfire_service_id,paypal_merchant_id FROM transactions WHERE idempotency_key=?", (tx.idempotency_key,)).fetchone()
            if existing:
                if existing[0] != tx.transaction_id or existing[2:] != (grant_id, tx.amount_minor, tx.currency, tx.payee, tx.skyfire_service_id, tx.paypal_merchant_id):
                    raise SecurityError("idempotency key already belongs to a different transaction")
                db.commit()
                return existing[1]
            prior_id = db.execute("SELECT status FROM transactions WHERE transaction_id=?", (tx.transaction_id,)).fetchone()
            if prior_id:
                raise SecurityError("transaction identity already exists")
            if tx.currency != grant_currency:
                raise SecurityError("transaction currency does not match grant")
            used = db.execute("SELECT COALESCE(SUM(amount_minor),0) FROM transactions WHERE grant_id=? AND currency=? AND status IN ('RESERVED','SCREENED_ALLOW','HOLD','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','UNKNOWN')", (grant_id, tx.currency)).fetchone()[0]
            if used + tx.amount_minor > max_spend_minor:
                raise SecurityError("cumulative grant spending limit exceeded")
            now = time.time()
            db.execute(
                "INSERT INTO transactions(transaction_id,grant_id,idempotency_key,amount_minor,currency,payee,skyfire_service_id,paypal_merchant_id,status,provider_order_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?, 'RESERVED', NULL, ?,?)",
                (tx.transaction_id, grant_id, tx.idempotency_key, tx.amount_minor, tx.currency, tx.payee, tx.skyfire_service_id, tx.paypal_merchant_id, now, now),
            )
            db.commit()
            return "RESERVED"
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def risk_features(self, grant_id: str, tx: CanonicalTransaction, max_spend_minor: int, *, now: float | None = None) -> dict[str, float]:
        """Derive model inputs only from canonical transaction and durable ledger state."""
        if not grant_id or not isinstance(max_spend_minor, int) or isinstance(max_spend_minor, bool) or max_spend_minor <= 0:
            raise SecurityError("invalid authenticated grant authorization")
        now = time.time() if now is None else now
        active = ("RESERVED", "SCREENED_ALLOW", "HOLD", "DISPATCH_STARTED", "CREATED", "APPROVED", "COMPLETED", "UNKNOWN")
        placeholders = ",".join("?" for _ in active)
        db = self._connect()
        try:
            params = (grant_id, tx.currency, *active, tx.transaction_id)
            used = db.execute(
                f"SELECT COALESCE(SUM(amount_minor),0) FROM transactions WHERE grant_id=? AND currency=? AND status IN ({placeholders}) AND transaction_id<>?",
                params,
            ).fetchone()[0]
            velocity = db.execute(
                f"SELECT COUNT(*) FROM transactions WHERE grant_id=? AND currency=? AND status IN ({placeholders}) AND transaction_id<>? AND created_at>=?",
                (*params[:-1], tx.transaction_id, now - 600.0),
            ).fetchone()[0]
            prior_payee = db.execute(
                f"SELECT 1 FROM transactions WHERE grant_id=? AND currency=? AND COALESCE(paypal_merchant_id,skyfire_service_id,payee)=? AND status IN ({placeholders}) AND transaction_id<>? LIMIT 1",
                (grant_id, tx.currency, tx.risk_payee_identity, *active, tx.transaction_id),
            ).fetchone()
        finally:
            db.close()
        return {
            "amount_to_grant_ratio": min(1.0, tx.amount_minor / max_spend_minor),
            "cumulative_spending_ratio": min(1.0, (used + tx.amount_minor) / max_spend_minor),
            "recent_velocity_ratio": min(1.0, velocity / 5.0),
            "new_payee": 0.0 if prior_payee else 1.0,
        }

    def record_risk_assessment(
        self, transaction_id: str, *, anomaly_score: float | None, model_version: str,
        training_dataset_id: str, decision: str, features: Mapping[str, float], scored_at: float | None = None,
    ) -> None:
        if decision not in {"ALLOW", "HOLD"} or not model_version or not training_dataset_id:
            raise LedgerError("risk assessment is invalid")
        if anomaly_score is not None and (isinstance(anomaly_score, bool) or not isinstance(anomaly_score, (int, float)) or not math.isfinite(float(anomaly_score)) or not 0.0 <= float(anomaly_score) <= 1.0):
            raise LedgerError("risk score is invalid")
        try:
            features_json = json.dumps(dict(features), sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise LedgerError("risk features are invalid") from exc
        scored_at = time.time() if scored_at is None else scored_at
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM transactions WHERE transaction_id=?", (transaction_id,)).fetchone()
            if not row or row[0] != "RESERVED":
                raise LedgerError("risk assessment requires a reserved transaction")
            db.execute(
                "INSERT INTO risk_assessments(transaction_id,anomaly_score,model_version,training_dataset_id,decision,scored_at,features_json) VALUES(?,?,?,?,?,?,?)",
                (transaction_id, anomaly_score, model_version, training_dataset_id, decision, scored_at, features_json),
            )
            outcome_state = "SCREENED_ALLOW" if decision == "ALLOW" else "HOLD"
            updated = db.execute("UPDATE transactions SET status=?,updated_at=? WHERE transaction_id=? AND status='RESERVED'", (outcome_state, scored_at, transaction_id)).rowcount
            if updated != 1:
                raise LedgerError("could not durably persist screened transaction state")
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def review_hold(self, transaction_id: str, *, reviewer_id: str, decision: str, reason: str, reviewed_at: float | None = None) -> dict[str, Any]:
        """Atomically audit a HOLD review; RELEASE only abandons the reservation."""
        if (not transaction_id or not reviewer_id or len(reviewer_id) > 128
                or decision not in {"KEEP_HOLD", "RELEASE_RESERVATION"}
                or not isinstance(reason, str) or not reason.strip() or len(reason) > 1000):
            raise LedgerError("review request is invalid")
        reviewed_at = time.time() if reviewed_at is None else reviewed_at
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT reviewer_id,decision,reason,reviewed_at FROM transaction_reviews WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if prior:
                if prior[:3] != (reviewer_id, decision, reason):
                    raise LedgerError("transaction already has a different review decision")
                db.commit()
                return {
                    "transaction_id": transaction_id, "reviewer_id": prior[0],
                    "decision": prior[1], "reason": prior[2], "reviewed_at": prior[3],
                    "transaction_state": db.execute("SELECT status FROM transactions WHERE transaction_id=?", (transaction_id,)).fetchone()[0],
                }
            row = db.execute("SELECT status,provider_order_id FROM transactions WHERE transaction_id=?", (transaction_id,)).fetchone()
            if not row or row[0] != "HOLD" or row[1] is not None:
                raise LedgerError("only an undispatched HOLD transaction can be reviewed")
            next_state = "REVIEW_RELEASED" if decision == "RELEASE_RESERVATION" else "HOLD"
            if decision == "RELEASE_RESERVATION":
                changed = db.execute(
                    "UPDATE transactions SET status='REVIEW_RELEASED',updated_at=? WHERE transaction_id=? AND status='HOLD' AND provider_order_id IS NULL",
                    (reviewed_at, transaction_id),
                ).rowcount
                if changed != 1:
                    raise LedgerError("HOLD changed before reservation release")
            db.execute(
                "INSERT INTO transaction_reviews(transaction_id,reviewer_id,decision,reason,reviewed_at) VALUES(?,?,?,?,?)",
                (transaction_id, reviewer_id, decision, reason, reviewed_at),
            )
            db.commit()
            return {
                "transaction_id": transaction_id, "reviewer_id": reviewer_id,
                "decision": decision, "reason": reason, "reviewed_at": reviewed_at,
                "transaction_state": next_state,
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def transition(self, transaction_id: str, new_status: str, provider_order_id: str | None = None,
                   *, provider_result: Mapping[str, Any] | None = None, operation: str = "order") -> None:
        allowed = {
            "RESERVED": {"DISPATCH_STARTED", "FAILED", "HOLD", "SCREENED_ALLOW"},
            "HOLD": set(),
            "SCREENED_ALLOW": {"DISPATCH_STARTED"},
            "REVIEW_RELEASED": set(),
            "DISPATCH_STARTED": {"CREATED", "APPROVED", "COMPLETED", "FAILED", "UNKNOWN"},
            "CREATED": {"APPROVED", "COMPLETED", "FAILED", "UNKNOWN"},
            "APPROVED": {"COMPLETED", "FAILED", "UNKNOWN"},
            "UNKNOWN": {"CREATED", "APPROVED", "COMPLETED", "FAILED"},
            "COMPLETED": set(), "FAILED": set(),
        }
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM transactions WHERE transaction_id=?", (transaction_id,)).fetchone()
            if not row or new_status not in allowed.get(row[0], set()):
                raise LedgerError("invalid or missing transaction state transition")
            if new_status == "COMPLETED":
                if (not isinstance(provider_result, Mapping)
                        or provider_result.get("verified_capture") is not True
                        or provider_result.get("status") != "COMPLETED"
                        or not provider_order_id or provider_result.get("id") != provider_order_id):
                    raise LedgerError("COMPLETED requires verified provider capture evidence")
            if new_status == "COMPLETED" and row[0] == "DISPATCH_STARTED":
                if not db.execute("SELECT 1 FROM capture_attempts WHERE transaction_id=?", (transaction_id,)).fetchone():
                    raise LedgerError("order creation cannot imply completed payment")
            db.execute("UPDATE transactions SET status=?,provider_order_id=COALESCE(?,provider_order_id),updated_at=? WHERE transaction_id=?", (new_status, provider_order_id, time.time(), transaction_id))
            if provider_result is not None:
                self._insert_provider_evidence(db, transaction_id, operation, provider_result)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _insert_provider_evidence(db: sqlite3.Connection, transaction_id: str, operation: str, result: Mapping[str, Any]) -> None:
        # Never persist raw provider bodies, OAuth headers, settlement data or tokens.
        permitted = {k: result[k] for k in ("id", "status", "verified_capture", "capture_ids", "approval_url") if k in result}
        db.execute(
            "INSERT INTO provider_evidence(transaction_id,operation,result_json,recorded_at) VALUES(?,?,?,?)",
            (transaction_id, operation, json.dumps(permitted, allow_nan=False), time.time()),
        )

    def record_provider_evidence(self, transaction_id: str, result: Mapping[str, Any], *, operation: str = "reconcile") -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._insert_provider_evidence(db, transaction_id, operation, result)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def begin_capture(self, transaction_id: str, expected_order_id: str) -> str:
        """One durable capture dispatch per transaction, including after UNKNOWN/restart."""
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT t.status,t.provider_order_id,t.paypal_merchant_id,r.decision FROM transactions t LEFT JOIN risk_assessments r USING(transaction_id) WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if not row or row[0] != "APPROVED" or row[1] != expected_order_id or not row[2] or row[3] != "ALLOW":
                raise LedgerError("capture requires approved order, canonical merchant, and durable ML ALLOW")
            if db.execute("SELECT 1 FROM capture_attempts WHERE transaction_id=?", (transaction_id,)).fetchone():
                raise LedgerError("capture already started; reconciliation only")
            request_id = "cap-" + hashlib.sha256((transaction_id + ":" + expected_order_id).encode()).hexdigest()[:32]
            db.execute("INSERT INTO capture_attempts VALUES(?,?,?)", (transaction_id, request_id, time.time()))
            db.execute("UPDATE transactions SET status='DISPATCH_STARTED',updated_at=? WHERE transaction_id=? AND status='APPROVED'", (time.time(), transaction_id))
            db.commit()
            return request_id
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def get(self, transaction_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT t.transaction_id,t.grant_id,t.idempotency_key,t.amount_minor,t.currency,t.payee,t.skyfire_service_id,t.paypal_merchant_id,t.status,t.provider_order_id,t.created_at,t.updated_at,r.anomaly_score,r.model_version,r.training_dataset_id,r.decision,r.scored_at,r.features_json,v.reviewer_id,v.decision,v.reason,v.reviewed_at FROM transactions t LEFT JOIN risk_assessments r ON r.transaction_id=t.transaction_id LEFT JOIN transaction_reviews v ON v.transaction_id=t.transaction_id WHERE t.transaction_id=?", (transaction_id,)).fetchone()
        if not row:
            return None
        record = dict(zip(("transaction_id","grant_id","idempotency_key","amount_minor","currency","payee","skyfire_service_id","paypal_merchant_id","status","provider_order_id","created_at","updated_at","anomaly_score","risk_model_version","risk_training_dataset_id","risk_decision","risk_scored_at","risk_features_json","reviewer_id","review_decision","review_reason","reviewed_at"), row))
        record["risk_features"] = json.loads(record.pop("risk_features_json")) if record["risk_features_json"] is not None else None
        db = self._connect()
        try:
            attempt = db.execute("SELECT request_id,started_at FROM capture_attempts WHERE transaction_id=?", (transaction_id,)).fetchone()
            record["capture_request_id"] = attempt[0] if attempt else None
            record["capture_started_at"] = attempt[1] if attempt else None
            evidence = db.execute("SELECT operation,result_json FROM provider_evidence WHERE transaction_id=? ORDER BY evidence_id", (transaction_id,)).fetchall()
            record["provider_evidence"] = [{"operation": op, "result": json.loads(data)} for op, data in evidence]
        finally:
            db.close()
        return record


def assess_reserved_transaction(ledger: Ledger, scorer: Any, grant_id: str, tx: CanonicalTransaction, max_spend_minor: int) -> dict[str, Any]:
    """Run or retrieve one durable risk assessment for an already-reserved transaction."""
    record = ledger.get(tx.transaction_id)
    if not record:
        raise LedgerError("reserved transaction disappeared before risk assessment")
    if record["risk_decision"] is None:
        features = ledger.risk_features(grant_id, tx, max_spend_minor)
        fallback_version = getattr(scorer, "model_version", "unavailable") if scorer is not None else "unavailable"
        fallback_dataset = getattr(scorer, "training_dataset_id", "unavailable") if scorer is not None else "unavailable"
        try:
            if scorer is None:
                raise RuntimeError("risk model unavailable")
            raw = scorer.score(features)
            version = getattr(raw, "model_version", None)
            dataset_id = getattr(raw, "training_dataset_id", None)
            score = getattr(raw, "anomaly_score", None)
            decision = getattr(raw, "decision", None)
            if not isinstance(version, str) or not version or not isinstance(dataset_id, str) or not dataset_id:
                raise ValueError("risk model metadata is invalid")
            if decision not in {"ALLOW", "HOLD"}:
                raise ValueError("risk model decision is invalid")
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(float(score)) or not 0.0 <= float(score) <= 1.0:
                raise ValueError("risk model score is invalid")
            score = float(score)
            if decision == "ALLOW" and score >= ANOMALY_THRESHOLD:
                raise ValueError("risk model ALLOW conflicts with configured anomaly threshold")
        except Exception:
            # Never disclose model internals or proceed if inference is unavailable.
            version, dataset_id, score, decision = fallback_version, fallback_dataset, None, "HOLD"
        try:
            ledger.record_risk_assessment(
                tx.transaction_id, anomaly_score=score, model_version=version,
                training_dataset_id=dataset_id, decision=decision, features=features,
            )
        except LedgerError:
            # A concurrent idempotent request may have durably committed first.
            latest = ledger.get(tx.transaction_id)
            if latest is None or latest["risk_decision"] not in {"ALLOW", "HOLD"}:
                raise
        record = ledger.get(tx.transaction_id)
        if not record or record["risk_decision"] not in {"ALLOW", "HOLD"}:
            raise LedgerError("risk assessment was not durably recorded")
    return record


class RiskScreeningPipeline:
    """Provider-free API boundary for already authenticated transaction grants."""

    def __init__(self, ledger: Ledger, scorer: Any = _DEFAULT_RISK_SCORER):
        self.ledger = ledger
        self.scorer = SyntheticIsolationForestScorer() if scorer is _DEFAULT_RISK_SCORER else scorer

    def screen_authorized_transaction(
        self, tx: CanonicalTransaction, *, grant_id: str, max_spend_minor: int,
        grant_currency: str, authorized_service_id: str,
    ) -> dict[str, Any]:
        if not grant_id or not isinstance(max_spend_minor, int) or isinstance(max_spend_minor, bool) or max_spend_minor <= 0:
            raise SecurityError("authenticated transaction authorization is invalid")
        if tx.currency != grant_currency or not authorized_service_id or tx.skyfire_service_id != authorized_service_id:
            raise SecurityError("transaction currency or Skyfire service is not authorized")
        if tx.amount_minor > max_spend_minor:
            raise SecurityError("transaction exceeds authenticated amount limit")
        state = self.ledger.reserve(grant_id, tx, max_spend_minor, grant_currency)
        if state not in {"RESERVED", "SCREENED_ALLOW", "HOLD"}:
            raise SecurityError("transaction already has a non-screening terminal or dispatch state")
        if state == "HOLD":
            record = self.ledger.get(tx.transaction_id)
        else:
            record = assess_reserved_transaction(self.ledger, self.scorer, grant_id, tx, max_spend_minor)
        if not record or record["risk_decision"] not in {"ALLOW", "HOLD"}:
            raise LedgerError("screening result is unavailable")
        decision = record["risk_decision"]
        reason_code = (
            "ANOMALY_BELOW_THRESHOLD" if decision == "ALLOW"
            else "MODEL_UNAVAILABLE" if record["anomaly_score"] is None
            else "ANOMALY_THRESHOLD_EXCEEDED"
        )
        return {
            "status": decision,
            "transaction_id": tx.transaction_id,
            "transaction_state": record["status"],
            "reason_code": reason_code,
            "risk_assessment": {
                "anomaly_score": record["anomaly_score"],
                "model_version": record["risk_model_version"],
                "training_dataset_id": record["risk_training_dataset_id"],
                "scored_at": record["risk_scored_at"],
            },
        }


class Provider(Protocol):
    def create_order(self, tx: CanonicalTransaction) -> Mapping[str, Any]: ...
    def get_order_details(self, tx: CanonicalTransaction, order_id: str) -> Mapping[str, Any]: ...


class MockProvider:
    """Local-only test provider; cannot reach PayPal."""
    def __init__(self, response: Mapping[str, Any] | Exception | None = None, reconciliation_response: Mapping[str, Any] | Exception | None = None):
        self.response = response or {"status": "CREATED", "id": "MOCK-ORDER"}
        self.reconciliation_response = reconciliation_response or {"status": "CREATED", "id": "MOCK-ORDER"}
        self.calls: list[tuple[dict[str, Any], str]] = []
        self.reconciliation_calls: list[str] = []

    def create_order(self, tx: CanonicalTransaction) -> Mapping[str, Any]:
        self.calls.append((build_paypal_order_payload(tx), tx.idempotency_key))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def get_order_details(self, tx: CanonicalTransaction, order_id: str) -> Mapping[str, Any]:
        self.reconciliation_calls.append(order_id)
        if isinstance(self.reconciliation_response, Exception):
            raise self.reconciliation_response
        return self.reconciliation_response


def build_paypal_order_payload(tx: CanonicalTransaction) -> dict[str, Any]:
    merchant = tx.paypal_merchant_id or tx.payee
    if not merchant or (tx.skyfire_service_id is not None and not tx.paypal_merchant_id):
        raise SecurityError("PayPal payload requires a separate canonical merchant identity")
    return {"intent": "CAPTURE", "purchase_units": [{"reference_id": tx.transaction_id, "payee": {"merchant_id": merchant}, "amount": {"currency_code": tx.currency, "value": f"{tx.amount_decimal:.2f}"}}]}


class TrustGuard:
    """Only the local mock or explicitly enabled PayPal Sandbox provider are accepted."""
    def __init__(self, config: TrustConfig, ledger: Ledger, provider: Provider | None = None, *, risk_scorer: Any = _DEFAULT_RISK_SCORER):
        if provider is not None and not isinstance(provider, MockProvider):
            from paypal_rest import PayPalRestOrdersProvider
            if not isinstance(provider, PayPalRestOrdersProvider) or os.environ.get("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "").lower() != "true":
                raise ConfigurationError("PayPal Sandbox provider is disabled; set TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true explicitly")
        self.config, self.ledger, self.provider = config, ledger, provider
        self.risk_scorer = SyntheticIsolationForestScorer() if risk_scorer is _DEFAULT_RISK_SCORER else risk_scorer
        self.auth = Authenticator(config)

    def authorize_and_dispatch(self, access_token: str, dpop_proof: str, method: str, url: str, tx: CanonicalTransaction) -> dict[str, Any]:
        if self.provider is None:
            raise ConfigurationError("provider is not configured; dispatch is disabled")
        if not isinstance(self.provider, MockProvider):
            self.provider._check_transaction_mapping(tx)
        if tx.currency not in self.config.supported_currencies:
            raise SecurityError("unsupported transaction currency")
        claims = self.auth.verify_access_token(access_token)
        proof_jti = self.auth.verify_dpop(dpop_proof, claims, method, url, access_token)
        token_jti = claims["jti"]
        exp = float(claims["exp"])
        self.ledger.claim_replay_id("access", str(token_jti), exp)
        self.ledger.claim_replay_id("dpop", proof_jti, time.time() + self.config.max_dpop_age_seconds)
        grant = claims[self.config.token_grant_claim]
        authorized_payees = grant[self.config.grant_payees_field]
        if not isinstance(authorized_payees, list) or any(not isinstance(x, str) for x in authorized_payees):
            raise SecurityError("authenticated grant payee authorization is malformed")
        if tx.currency != grant[self.config.grant_currency_field] or tx.payee not in authorized_payees:
            raise SecurityError("transaction currency or payee is not authorized by grant")
        max_spend = grant[self.config.grant_limit_field]
        if not isinstance(max_spend, int) or isinstance(max_spend, bool) or max_spend <= 0:
            raise SecurityError("grant limit must be a positive integer in minor units")
        grant_id = grant["_canonical_grant_id"]
        status = self.ledger.reserve(grant_id, tx, max_spend, grant[self.config.grant_currency_field])
        if status in {"DISPATCH_STARTED", "UNKNOWN", "HOLD", "REVIEW_RELEASED"}:
            return {"status": status, "transaction_id": tx.transaction_id}
        if status in {"CREATED", "APPROVED", "COMPLETED", "FAILED"}:
            return {"status": status, "transaction_id": tx.transaction_id}
        # Inference runs only after authenticated request binding, grant checks,
        # and durable spending reservation, and before dispatch_started.
        assessment = assess_reserved_transaction(self.ledger, self.risk_scorer, grant_id, tx, max_spend)
        risk_summary = {
            "model_version": assessment["risk_model_version"],
            "training_dataset_id": assessment["risk_training_dataset_id"],
            "anomaly_score": assessment["anomaly_score"],
            "decision": assessment["risk_decision"],
            "scored_at": assessment["risk_scored_at"],
        }
        if assessment["risk_decision"] != "ALLOW":
            return {"status": "HOLD", "transaction_id": tx.transaction_id, "risk_assessment": risk_summary}
        # This durable transition commits before the provider can be invoked.
        self.ledger.transition(tx.transaction_id, "DISPATCH_STARTED")
        try:
            result = self.provider.create_order(tx)
        except ProviderDefinitiveError:
            self.ledger.transition(tx.transaction_id, "FAILED")
            return {"status": "FAILED", "transaction_id": tx.transaction_id}
        except Exception as e:
            self.ledger.transition(tx.transaction_id, "UNKNOWN", getattr(e, "provider_order_id", None))
            return {"status": "UNKNOWN", "transaction_id": tx.transaction_id}
        if not isinstance(result, Mapping):
            self.ledger.transition(tx.transaction_id, "UNKNOWN")
            return {"status": "UNKNOWN", "transaction_id": tx.transaction_id}
        status_code = result.get("status")
        order_id = result.get("id")
        if status_code in {"CREATED", "APPROVED"} and isinstance(order_id, str) and order_id:
            self.ledger.transition(tx.transaction_id, status_code, order_id, provider_result=result, operation="create")
            outcome = {"status": status_code, "transaction_id": tx.transaction_id, "provider_order_id": order_id, "payment_completed": False, "risk_assessment": risk_summary}
            if result.get("approval_url"):
                outcome["approval_url"] = result["approval_url"]
            return outcome
        # An order-create response alone never constitutes capture evidence.
        self.ledger.transition(tx.transaction_id, "UNKNOWN", order_id if isinstance(order_id, str) else None)
        return {"status": "UNKNOWN", "transaction_id": tx.transaction_id}

    def reconcile(self, transaction_id: str) -> dict[str, Any]:
        if self.provider is None or not hasattr(self.provider, "get_order_details"):
            raise ConfigurationError("reconciliation provider is not configured")
        record = self.ledger.get(transaction_id)
        if not record:
            raise LedgerError("transaction not found")
        if record["status"] not in {"UNKNOWN", "CREATED", "APPROVED", "COMPLETED", "DISPATCH_STARTED"}:
            raise LedgerError("transaction state is not reconcilable")
        if record["status"] == "DISPATCH_STARTED" and not record["capture_request_id"]:
            raise LedgerError("unresolved create dispatch requires manual reconciliation")
        order_id = record["provider_order_id"]
        if not order_id:
            raise LedgerError("no PayPal order ID is recorded; manual reconciliation is required")
        tx = CanonicalTransaction(transaction_id=record["transaction_id"], idempotency_key=record["idempotency_key"], amount_minor=record["amount_minor"], currency=record["currency"], payee=record["payee"], skyfire_service_id=record["skyfire_service_id"], paypal_merchant_id=record["paypal_merchant_id"])
        try:
            result = self.provider.get_order_details(tx, order_id)
        except Exception:
            if record["status"] not in {"UNKNOWN", "COMPLETED"}:
                self.ledger.transition(transaction_id, "UNKNOWN", order_id)
            return {"status": "UNKNOWN", "transaction_id": transaction_id, "provider_order_id": order_id}
        if not isinstance(result, Mapping):
            if record["status"] not in {"UNKNOWN", "COMPLETED"}:
                self.ledger.transition(transaction_id, "UNKNOWN", order_id)
            return {"status": "UNKNOWN", "transaction_id": transaction_id, "provider_order_id": order_id}
        status = result.get("status")
        if result.get("id") != order_id or status not in {"CREATED", "APPROVED", "COMPLETED", "FAILED", "UNKNOWN"}:
            status = "UNKNOWN"
        if record["status"] == "APPROVED" and status == "CREATED":
            status = "APPROVED"
        if status == "COMPLETED" and result.get("verified_capture") is not True:
            status = "UNKNOWN"
        if record["status"] == "COMPLETED" and status != "COMPLETED":
            return {"status": "UNKNOWN", "transaction_id": transaction_id, "provider_order_id": order_id, "payment_completed": False}
        if status == "UNKNOWN" and record["status"] != "UNKNOWN":
            self.ledger.transition(transaction_id, "UNKNOWN", order_id, provider_result={"id": order_id, "status": "UNKNOWN"}, operation="reconcile")
        elif status != "UNKNOWN" and status != record["status"]:
            self.ledger.transition(transaction_id, status, order_id, provider_result=result, operation="reconcile")
        else:
            self.ledger.record_provider_evidence(transaction_id, result if status != "UNKNOWN" else {"id": order_id, "status": "UNKNOWN"})
        return {"status": status, "transaction_id": transaction_id, "provider_order_id": order_id, "payment_completed": status == "COMPLETED" and result.get("verified_capture") is True, "capture_ids": result.get("capture_ids", []) if status == "COMPLETED" else []}

    def capture_approved_order(self, transaction_id: str, *, buyer_approved: bool = False) -> dict[str, Any]:
        """Explicit local approval plus verified provider APPROVED, never a callback alone.

        No transaction terms are accepted from the caller. Once a capture attempt
        exists, all future actions are reconciliation-only, even if GET says APPROVED.
        """
        if buyer_approved is not True:
            raise SecurityError("explicit buyer approval completion is required")
        if self.provider is None or not hasattr(self.provider, "capture_order"):
            raise ConfigurationError("capture provider is not configured")
        record = self.ledger.get(transaction_id)
        if not record or record["status"] not in {"CREATED", "APPROVED", "COMPLETED"} or record["risk_decision"] != "ALLOW":
            raise SecurityError("checkout requires durable ML ALLOW and a valid order state")
        if record["status"] == "COMPLETED":
            verified = [item["result"] for item in record["provider_evidence"]
                        if item["result"].get("id") == record["provider_order_id"]
                        and item["result"].get("status") == "COMPLETED"
                        and item["result"].get("verified_capture") is True]
            if not verified:
                raise SecurityError("completed state lacks durable verified capture evidence")
            return {"status": "COMPLETED", "transaction_id": transaction_id, "payment_completed": True,
                    "provider_order_id": record["provider_order_id"], "capture_ids": verified[-1].get("capture_ids", [])}
        if record["capture_request_id"]:
            raise LedgerError("capture already started; reconciliation only")
        reconciled = self.reconcile(transaction_id)
        if reconciled["status"] == "COMPLETED":
            return reconciled
        if reconciled["status"] != "APPROVED":
            raise SecurityError("PayPal has not verified buyer approval")
        record = self.ledger.get(transaction_id)
        tx = CanonicalTransaction(
            record["transaction_id"], record["idempotency_key"], record["amount_minor"], record["currency"],
            record["payee"], record["skyfire_service_id"], record["paypal_merchant_id"],
        )
        request_id = self.ledger.begin_capture(transaction_id, record["provider_order_id"])
        try:
            result = self.provider.capture_order(tx, record["provider_order_id"], request_id)
        except Exception:
            self.ledger.transition(transaction_id, "UNKNOWN", record["provider_order_id"],
                                   provider_result={"id": record["provider_order_id"], "status": "UNKNOWN"}, operation="capture")
            return {"status": "UNKNOWN", "transaction_id": transaction_id, "payment_completed": False}
        if (not isinstance(result, Mapping) or result.get("id") != record["provider_order_id"]
                or result.get("status") != "COMPLETED" or result.get("verified_capture") is not True):
            self.ledger.transition(transaction_id, "UNKNOWN", record["provider_order_id"])
            return {"status": "UNKNOWN", "transaction_id": transaction_id, "payment_completed": False}
        self.ledger.transition(transaction_id, "COMPLETED", record["provider_order_id"], provider_result=result, operation="capture")
        return {"status": "COMPLETED", "transaction_id": transaction_id, "provider_order_id": record["provider_order_id"],
                "payment_completed": True, "capture_ids": result.get("capture_ids", [])}
