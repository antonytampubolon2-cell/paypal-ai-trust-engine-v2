"""Fail-closed TrustGuard primitives. No provider is initialized or called at import time."""
from __future__ import annotations

import base64
import hashlib
import json
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
    payee: str

    @classmethod
    def build(cls, *, transaction_id: str, idempotency_key: str, amount: str | Decimal, currency: str, payee: str, supported_currencies: tuple[str, ...] = ("USD",)) -> "CanonicalTransaction":
        if not transaction_id or not idempotency_key or not payee:
            raise SecurityError("transaction identity, idempotency key, and payee are required")
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
        return cls(transaction_id, idempotency_key, minor, currency, payee)

    @property
    def amount_decimal(self) -> Decimal:
        return Decimal(self.amount_minor) / 100


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
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
                    amount_minor INTEGER NOT NULL CHECK(amount_minor > 0), currency TEXT NOT NULL, payee TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('RESERVED','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','FAILED','UNKNOWN')),
                    provider_order_id TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS tx_grant_status ON transactions(grant_id, status);
                CREATE TABLE IF NOT EXISTS replay_ids (kind TEXT NOT NULL, jti TEXT NOT NULL, expires_at REAL NOT NULL, PRIMARY KEY(kind,jti));
            """)
            schema = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='transactions'").fetchone()[0]
            if "'APPROVED'" not in schema:
                db.executescript("""
                    CREATE TABLE transactions_new (
                        transaction_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
                        amount_minor INTEGER NOT NULL CHECK(amount_minor > 0), currency TEXT NOT NULL, payee TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('RESERVED','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','FAILED','UNKNOWN')),
                        provider_order_id TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
                    );
                    INSERT INTO transactions_new SELECT transaction_id,grant_id,idempotency_key,amount_minor,currency,payee,
                      CASE status WHEN 'ORDER_CREATED' THEN 'CREATED' ELSE status END,
                      provider_order_id,created_at,updated_at FROM transactions;
                    DROP TABLE transactions;
                    ALTER TABLE transactions_new RENAME TO transactions;
                    CREATE INDEX tx_grant_status ON transactions(grant_id,status);
                """)

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
            existing = db.execute("SELECT transaction_id,status,grant_id,amount_minor,currency,payee FROM transactions WHERE idempotency_key=?", (tx.idempotency_key,)).fetchone()
            if existing:
                if existing[0] != tx.transaction_id or existing[2:] != (grant_id, tx.amount_minor, tx.currency, tx.payee):
                    raise SecurityError("idempotency key already belongs to a different transaction")
                db.commit()
                return existing[1]
            prior_id = db.execute("SELECT status FROM transactions WHERE transaction_id=?", (tx.transaction_id,)).fetchone()
            if prior_id:
                raise SecurityError("transaction identity already exists")
            if tx.currency != grant_currency:
                raise SecurityError("transaction currency does not match grant")
            used = db.execute("SELECT COALESCE(SUM(amount_minor),0) FROM transactions WHERE grant_id=? AND currency=? AND status IN ('RESERVED','DISPATCH_STARTED','CREATED','APPROVED','COMPLETED','UNKNOWN')", (grant_id, tx.currency)).fetchone()[0]
            if used + tx.amount_minor > max_spend_minor:
                raise SecurityError("cumulative grant spending limit exceeded")
            now = time.time()
            db.execute("INSERT INTO transactions VALUES(?,?,?,?,?,?, 'RESERVED', NULL, ?,?)", (tx.transaction_id, grant_id, tx.idempotency_key, tx.amount_minor, tx.currency, tx.payee, now, now))
            db.commit()
            return "RESERVED"
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def transition(self, transaction_id: str, new_status: str, provider_order_id: str | None = None) -> None:
        allowed = {
            "RESERVED": {"DISPATCH_STARTED", "FAILED"},
            "DISPATCH_STARTED": {"CREATED", "APPROVED", "FAILED", "UNKNOWN"},
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
            db.execute("UPDATE transactions SET status=?,provider_order_id=COALESCE(?,provider_order_id),updated_at=? WHERE transaction_id=?", (new_status, provider_order_id, time.time(), transaction_id))
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def get(self, transaction_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT transaction_id,grant_id,idempotency_key,amount_minor,currency,payee,status,provider_order_id,created_at,updated_at FROM transactions WHERE transaction_id=?", (transaction_id,)).fetchone()
        return dict(zip(("transaction_id","grant_id","idempotency_key","amount_minor","currency","payee","status","provider_order_id","created_at","updated_at"), row)) if row else None


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
    return {"intent": "CAPTURE", "purchase_units": [{"reference_id": tx.transaction_id, "payee": {"merchant_id": tx.payee}, "amount": {"currency_code": tx.currency, "value": f"{tx.amount_decimal:.2f}"}}]}


class TrustGuard:
    """Only the local mock or explicitly enabled PayPal Sandbox provider are accepted."""
    def __init__(self, config: TrustConfig, ledger: Ledger, provider: Provider | None = None):
        if provider is not None and not isinstance(provider, MockProvider):
            from paypal_rest import PayPalRestOrdersProvider
            if not isinstance(provider, PayPalRestOrdersProvider) or os.environ.get("TRUSTGUARD_ENABLE_PAYPAL_SANDBOX", "").lower() != "true":
                raise ConfigurationError("PayPal Sandbox provider is disabled; set TRUSTGUARD_ENABLE_PAYPAL_SANDBOX=true explicitly")
        self.config, self.ledger, self.provider = config, ledger, provider
        self.auth = Authenticator(config)

    def authorize_and_dispatch(self, access_token: str, dpop_proof: str, method: str, url: str, tx: CanonicalTransaction) -> dict[str, Any]:
        if self.provider is None:
            raise ConfigurationError("provider is not configured; dispatch is disabled")
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
        if status in {"DISPATCH_STARTED", "UNKNOWN"}:
            return {"status": status, "transaction_id": tx.transaction_id}
        if status in {"CREATED", "APPROVED", "COMPLETED", "FAILED"}:
            return {"status": status, "transaction_id": tx.transaction_id}
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
            self.ledger.transition(tx.transaction_id, status_code, order_id)
            return {"status": status_code, "transaction_id": tx.transaction_id, "provider_order_id": order_id, "payment_completed": False}
        # An order-create response alone never constitutes capture evidence.
        self.ledger.transition(tx.transaction_id, "UNKNOWN", order_id if isinstance(order_id, str) else None)
        return {"status": "UNKNOWN", "transaction_id": tx.transaction_id}

    def reconcile(self, transaction_id: str) -> dict[str, Any]:
        if self.provider is None or not hasattr(self.provider, "get_order_details"):
            raise ConfigurationError("reconciliation provider is not configured")
        record = self.ledger.get(transaction_id)
        if not record:
            raise LedgerError("transaction not found")
        if record["status"] not in {"UNKNOWN", "CREATED", "APPROVED"}:
            raise LedgerError("transaction state is not reconcilable")
        order_id = record["provider_order_id"]
        if not order_id:
            raise LedgerError("no PayPal order ID is recorded; manual reconciliation is required")
        tx = CanonicalTransaction(transaction_id=record["transaction_id"], idempotency_key=record["idempotency_key"], amount_minor=record["amount_minor"], currency=record["currency"], payee=record["payee"])
        try:
            result = self.provider.get_order_details(tx, order_id)
        except Exception:
            if record["status"] != "UNKNOWN":
                self.ledger.transition(transaction_id, "UNKNOWN", order_id)
            return {"status": "UNKNOWN", "transaction_id": transaction_id, "provider_order_id": order_id}
        if not isinstance(result, Mapping):
            if record["status"] != "UNKNOWN":
                self.ledger.transition(transaction_id, "UNKNOWN", order_id)
            return {"status": "UNKNOWN", "transaction_id": transaction_id, "provider_order_id": order_id}
        status = result.get("status")
        if result.get("id") != order_id or status not in {"CREATED", "APPROVED", "COMPLETED", "FAILED", "UNKNOWN"}:
            status = "UNKNOWN"
        if record["status"] == "APPROVED" and status == "CREATED":
            status = "APPROVED"
        if status == "COMPLETED" and result.get("verified_capture") is not True:
            status = "UNKNOWN"
        if status == "UNKNOWN" and record["status"] != "UNKNOWN":
            self.ledger.transition(transaction_id, "UNKNOWN", order_id)
        elif status != "UNKNOWN" and status != record["status"]:
            self.ledger.transition(transaction_id, status, order_id)
        return {"status": status, "transaction_id": transaction_id, "provider_order_id": order_id, "payment_completed": status == "COMPLETED" and result.get("verified_capture") is True}
