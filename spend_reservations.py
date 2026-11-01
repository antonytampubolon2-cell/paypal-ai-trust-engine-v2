"""Atomic cumulative-spend reservations for a single-host TrustGuard deployment.

SQLite provides durable, transactional coordination only for processes sharing a
single host and persistent local database with correct filesystem locking. This
module deliberately refuses to describe that as a distributed/multi-host store.
Provider calls must happen outside database transactions. A reservation whose
provider dispatch began is never freed merely because its lease expires.
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Literal

from trustguard_security import SUPPORTED_CURRENCY_MINOR_UNITS

ReservationStatus = Literal["RESERVED", "SETTLED", "RELEASED", "EXPIRED", "RECONCILIATION_REQUIRED"]
ACTIVE_STATUSES = ("RESERVED", "RECONCILIATION_REQUIRED")


class ReservationError(ValueError):
    """A reservation request or lifecycle transition violates policy."""


class ReservationStorageError(RuntimeError):
    """The reservation store failed; callers must fail closed."""


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    grant_id: str
    idempotency_key: str
    amount: Decimal
    currency: str
    status: ReservationStatus
    expires_at: float
    dispatch_started: bool
    provider_reference: str | None


class SQLiteSpendReservationStore:
    """Durable atomic spend ledger for one host; not safe for multi-host use."""

    deployment_scope = "single-host-only"

    def __init__(self, path: str | Path, *, deployment_mode: str | None = None) -> None:
        mode = deployment_mode if deployment_mode is not None else os.getenv("TRUSTGUARD_DEPLOYMENT_MODE")
        if mode != "single-host":
            raise ReservationError("SQLite spend reservations require explicit TRUSTGUARD_DEPLOYMENT_MODE=single-host; multi-host mode is unsupported.")
        if not str(path).strip() or str(path) == ":memory:":
            raise ReservationError("A persistent SQLite path is required for durable reservations.")
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with closing(sqlite3.connect(self.path, timeout=10)) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA foreign_keys=ON")
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS spend_grants (
                        grant_id TEXT PRIMARY KEY,
                        limit_amount TEXT NOT NULL,
                        currency TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS spend_reservations (
                        reservation_id TEXT PRIMARY KEY,
                        grant_id TEXT NOT NULL REFERENCES spend_grants(grant_id),
                        idempotency_key TEXT NOT NULL,
                        amount TEXT NOT NULL,
                        currency TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('RESERVED','SETTLED','RELEASED','EXPIRED','RECONCILIATION_REQUIRED')),
                        expires_at REAL NOT NULL,
                        dispatch_started INTEGER NOT NULL DEFAULT 0 CHECK(dispatch_started IN (0,1)),
                        provider_reference TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        UNIQUE(grant_id, idempotency_key)
                    );
                    CREATE INDEX IF NOT EXISTS spend_reservations_grant_status
                        ON spend_reservations(grant_id, status);
                    CREATE UNIQUE INDEX IF NOT EXISTS spend_reservations_provider_reference
                        ON spend_reservations(provider_reference) WHERE provider_reference IS NOT NULL;
                    CREATE TABLE IF NOT EXISTS spend_reservation_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        reservation_id TEXT NOT NULL REFERENCES spend_reservations(reservation_id),
                        event_type TEXT NOT NULL CHECK(event_type IN ('ORDER_CREATED','PROVIDER_UNKNOWN','SETTLED','RELEASED')),
                        external_reference TEXT,
                        created_at REAL NOT NULL,
                        UNIQUE(reservation_id, event_type, external_reference)
                    );
                    CREATE UNIQUE INDEX IF NOT EXISTS spend_reservation_order_reference
                        ON spend_reservation_events(external_reference)
                        WHERE event_type='ORDER_CREATED' AND external_reference IS NOT NULL;
                """)
                db.commit()
        except sqlite3.Error as exc:
            raise ReservationStorageError("Unable to initialize persistent spend reservation store.") from exc

    @staticmethod
    def _money(value: object, currency: str, label: str) -> Decimal:
        if currency not in SUPPORTED_CURRENCY_MINOR_UNITS:
            raise ReservationError("Unsupported reservation currency.")
        if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
            raise ReservationError(f"{label} must be a decimal string, integer, or Decimal.")
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, ValueError):
            raise ReservationError(f"{label} is malformed.") from None
        if not amount.is_finite() or amount <= 0:
            raise ReservationError(f"{label} must be finite and positive.")
        if amount.as_tuple().exponent < -SUPPORTED_CURRENCY_MINOR_UNITS[currency]:
            raise ReservationError(f"{label} has excess precision for {currency}.")
        return amount

    @staticmethod
    def _row(row: tuple) -> Reservation:
        return Reservation(
            reservation_id=row[0], grant_id=row[1], idempotency_key=row[2],
            amount=Decimal(row[3]), currency=row[4], status=row[5],
            expires_at=float(row[6]), dispatch_started=bool(row[7]),
            provider_reference=row[8],
        )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=15000")
        return db

    @contextmanager
    def _connection(self):
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    def reserve(self, *, grant_id: str, max_spend: object, amount: object,
                currency: str, idempotency_key: str, expires_at: float,
                now: float | None = None) -> Reservation:
        """Atomically reserve funds against a stable grant id and idempotency key."""
        now = time.time() if now is None else float(now)
        if not isinstance(grant_id, str) or not grant_id.strip() or len(grant_id) > 200:
            raise ReservationError("A stable authoritative grant identifier is required.")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip() or len(idempotency_key) > 200:
            raise ReservationError("A stable idempotency key is required.")
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)) or expires_at <= now:
            raise ReservationError("Reservation expiry must be a future timestamp.")
        limit = self._money(max_spend, currency, "max_spend")
        requested = self._money(amount, currency, "amount")
        if requested > limit:
            raise ReservationError("Reservation exceeds the grant's cumulative spending limit.")
        try:
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                grant = db.execute("SELECT limit_amount,currency FROM spend_grants WHERE grant_id=?", (grant_id,)).fetchone()
                if grant is None:
                    db.execute("INSERT INTO spend_grants(grant_id,limit_amount,currency,created_at) VALUES(?,?,?,?)",
                               (grant_id, str(limit), currency, now))
                elif Decimal(grant[0]) != limit or grant[1] != currency:
                    raise ReservationError("Grant limit/currency differs from its persisted authoritative definition.")
                existing = db.execute("""SELECT reservation_id,grant_id,idempotency_key,amount,currency,status,
                    expires_at,dispatch_started,provider_reference FROM spend_reservations
                    WHERE grant_id=? AND idempotency_key=?""", (grant_id, idempotency_key)).fetchone()
                if existing:
                    old = self._row(existing)
                    if old.amount != requested or old.currency != currency:
                        raise ReservationError("Idempotency key was reused with different transaction terms.")
                    db.execute("COMMIT")
                    return old
                rows = db.execute("SELECT amount,status FROM spend_reservations WHERE grant_id=?", (grant_id,)).fetchall()
                consumed = sum((Decimal(a) for a,s in rows if s in (*ACTIVE_STATUSES, "SETTLED")), Decimal("0"))
                if consumed + requested > limit:
                    raise ReservationError("Insufficient remaining cumulative grant balance.")
                rid = str(uuid.uuid4())
                db.execute("""INSERT INTO spend_reservations
                    (reservation_id,grant_id,idempotency_key,amount,currency,status,expires_at,dispatch_started,created_at,updated_at)
                    VALUES(?,?,?,?,?,'RESERVED',?,0,?,?)""",
                    (rid, grant_id, idempotency_key, str(requested), currency, float(expires_at), now, now))
                row = db.execute("""SELECT reservation_id,grant_id,idempotency_key,amount,currency,status,
                    expires_at,dispatch_started,provider_reference FROM spend_reservations WHERE reservation_id=?""", (rid,)).fetchone()
                db.execute("COMMIT")
                return self._row(row)
        except ReservationError:
            raise
        except sqlite3.Error as exc:
            raise ReservationStorageError("Atomic spend reservation failed; payment dispatch must not proceed.") from exc

    def _transition(self, reservation_id: str, *, allowed: tuple[str, ...], status: str,
                    now: float | None = None, dispatch_started: bool | None = None,
                    provider_reference: str | None = None) -> Reservation:
        now = time.time() if now is None else float(now)
        try:
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("""SELECT reservation_id,grant_id,idempotency_key,amount,currency,status,
                    expires_at,dispatch_started,provider_reference FROM spend_reservations WHERE reservation_id=?""", (reservation_id,)).fetchone()
                if row is None:
                    raise ReservationError("Reservation not found.")
                current = self._row(row)
                if current.status == status and (dispatch_started is None or current.dispatch_started == dispatch_started):
                    if provider_reference and current.provider_reference not in (None, provider_reference):
                        raise ReservationError("Provider reference conflicts with the persisted outcome.")
                    db.execute("COMMIT")
                    return current
                if current.status not in allowed:
                    raise ReservationError(f"Illegal reservation transition from {current.status} to {status}.")
                if current.provider_reference and provider_reference and current.provider_reference != provider_reference:
                    raise ReservationError("Provider reference conflicts with the persisted outcome.")
                fields = ["status=?", "updated_at=?"]
                values: list[object] = [status, now]
                if dispatch_started is not None:
                    fields.append("dispatch_started=?")
                    values.append(int(dispatch_started))
                if provider_reference is not None:
                    fields.append("provider_reference=?")
                    values.append(provider_reference)
                values.append(reservation_id)
                db.execute(f"UPDATE spend_reservations SET {','.join(fields)} WHERE reservation_id=?", values)
                updated = db.execute("""SELECT reservation_id,grant_id,idempotency_key,amount,currency,status,
                    expires_at,dispatch_started,provider_reference FROM spend_reservations WHERE reservation_id=?""", (reservation_id,)).fetchone()
                db.execute("COMMIT")
                return self._row(updated)
        except ReservationError:
            raise
        except sqlite3.Error as exc:
            raise ReservationStorageError("Reservation state update failed; reconcile before retrying.") from exc

    def mark_dispatch_started(self, reservation_id: str, *, now: float | None = None) -> Reservation:
        """Persist intent immediately before provider I/O; call before sending any request."""
        return self._transition(reservation_id, allowed=("RESERVED",), status="RESERVED",
                                dispatch_started=True, now=now)

    def mark_unknown(self, reservation_id: str, *, now: float | None = None) -> Reservation:
        """Keep funds consumed after timeout/ambiguous provider outcome."""
        return self._transition(reservation_id, allowed=("RESERVED",), status="RECONCILIATION_REQUIRED", now=now)

    def settle(self, reservation_id: str, *, provider_reference: str,
               verified_settlement: bool, now: float | None = None) -> Reservation:
        if verified_settlement is not True or not isinstance(provider_reference, str) or not provider_reference.strip():
            raise ReservationError("Settlement requires verified provider evidence and a reference.")
        return self._transition(reservation_id, allowed=("RESERVED", "RECONCILIATION_REQUIRED"),
                                status="SETTLED", provider_reference=provider_reference, now=now)

    def release(self, reservation_id: str, *, confirmed_non_payment: bool,
                now: float | None = None) -> Reservation:
        if confirmed_non_payment is not True:
            raise ReservationError("Reservation release requires confirmed non-payment evidence.")
        return self._transition(reservation_id, allowed=("RESERVED", "RECONCILIATION_REQUIRED"),
                                status="RELEASED", now=now)

    def expire_due(self, *, now: float | None = None) -> dict[str, int]:
        """Expire only pre-dispatch reservations; dispatched ones stay reserved for reconciliation."""
        now = time.time() if now is None else float(now)
        try:
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                a = db.execute("UPDATE spend_reservations SET status='EXPIRED',updated_at=? WHERE status='RESERVED' AND dispatch_started=0 AND expires_at<=?", (now,now)).rowcount
                b = db.execute("UPDATE spend_reservations SET status='RECONCILIATION_REQUIRED',updated_at=? WHERE status='RESERVED' AND dispatch_started=1 AND expires_at<=?", (now,now)).rowcount
                db.execute("COMMIT")
                return {"expired": a, "reconciliation_required": b}
        except sqlite3.Error as exc:
            raise ReservationStorageError("Reservation expiry sweep failed; do not dispatch new payments.") from exc

    def record_order_created(self, reservation_id: str, *, order_id: str,
                            now: float | None = None) -> None:
        """Persist a verified order id without treating order creation as settlement."""
        now = time.time() if now is None else float(now)
        if not isinstance(order_id, str) or not order_id.strip() or len(order_id) > 255:
            raise ReservationError("A provider order identifier is required.")
        try:
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT status,dispatch_started FROM spend_reservations WHERE reservation_id=?",
                                 (reservation_id,)).fetchone()
                if row is None or row[0] != "RESERVED" or not row[1]:
                    raise ReservationError("Order evidence requires an active dispatched reservation.")
                existing = db.execute("""SELECT external_reference FROM spend_reservation_events
                    WHERE reservation_id=? AND event_type='ORDER_CREATED'""", (reservation_id,)).fetchone()
                if existing:
                    if existing[0] != order_id:
                        raise ReservationError("Reservation already records a different provider order.")
                    db.execute("COMMIT")
                    return
                db.execute("""INSERT INTO spend_reservation_events
                    (reservation_id,event_type,external_reference,created_at)
                    VALUES(?,'ORDER_CREATED',?,?)""", (reservation_id, order_id, now))
                db.execute("COMMIT")
        except ReservationError:
            raise
        except sqlite3.Error as exc:
            raise ReservationStorageError("Unable to persist provider order evidence; reconcile before retrying.") from exc

    def events_for(self, reservation_id: str) -> list[dict[str, object]]:
        """Return persisted provider evidence events for reconciliation."""
        try:
            with self._connection() as db:
                rows = db.execute("""SELECT event_type,external_reference,created_at
                    FROM spend_reservation_events WHERE reservation_id=? ORDER BY event_id""",
                    (reservation_id,)).fetchall()
            return [{"event_type": row[0], "external_reference": row[1], "created_at": row[2]} for row in rows]
        except sqlite3.Error as exc:
            raise ReservationStorageError("Reservation event lookup failed; fail closed.") from exc

    def get(self, reservation_id: str) -> Reservation | None:
        try:
            with self._connection() as db:
                row = db.execute("""SELECT reservation_id,grant_id,idempotency_key,amount,currency,status,
                    expires_at,dispatch_started,provider_reference FROM spend_reservations WHERE reservation_id=?""", (reservation_id,)).fetchone()
            return self._row(row) if row else None
        except sqlite3.Error as exc:
            raise ReservationStorageError("Reservation lookup failed; fail closed.") from exc

    def get_by_idempotency_key(self, grant_id: str, idempotency_key: str) -> Reservation | None:
        """Recover a reservation after restart using the caller's stable request key."""
        try:
            with self._connection() as db:
                row = db.execute("""SELECT reservation_id,grant_id,idempotency_key,amount,currency,status,
                    expires_at,dispatch_started,provider_reference FROM spend_reservations
                    WHERE grant_id=? AND idempotency_key=?""", (grant_id, idempotency_key)).fetchone()
            return self._row(row) if row else None
        except sqlite3.Error as exc:
            raise ReservationStorageError("Reservation reconciliation lookup failed; fail closed.") from exc

    def committed_and_reserved_total(self, grant_id: str) -> Decimal:
        try:
            with self._connection() as db:
                rows = db.execute("SELECT amount,status FROM spend_reservations WHERE grant_id=?", (grant_id,)).fetchall()
            return sum((Decimal(a) for a,s in rows if s in (*ACTIVE_STATUSES, "SETTLED")), Decimal("0"))
        except sqlite3.Error as exc:
            raise ReservationStorageError("Spend ledger read failed; fail closed.") from exc
