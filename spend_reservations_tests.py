"""Regression tests for atomic cumulative spend reservation lifecycle."""
import concurrent.futures
import tempfile
import threading
import unittest
from decimal import Decimal
from pathlib import Path

from spend_reservations import ReservationError, SQLiteSpendReservationStore


class SpendReservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "spend.sqlite3"
        self.store = SQLiteSpendReservationStore(self.path, deployment_mode="single-host")

    def tearDown(self):
        self.tmp.cleanup()

    def reserve(self, key, amount="10.00", *, now=1000, expiry=1100):
        return self.store.reserve(grant_id="issuer-grant-1", max_spend="100.00",
                                  amount=amount, currency="USD", idempotency_key=key,
                                  expires_at=expiry, now=now)

    def test_concurrent_reservations_never_exceed_grant_limit(self):
        barrier = threading.Barrier(24)
        def one(i):
            barrier.wait(timeout=10)
            try:
                return self.reserve(f"key-{i}", "10.00").status
            except ReservationError:
                return "REJECTED"
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            outcomes = list(pool.map(one, range(24)))
        self.assertEqual(outcomes.count("RESERVED"), 10)
        self.assertEqual(outcomes.count("REJECTED"), 14)
        self.assertEqual(self.store.committed_and_reserved_total("issuer-grant-1"), Decimal("100.00"))

    def test_idempotency_returns_same_reservation_and_rejects_term_change(self):
        first = self.reserve("same", "12.00")
        self.assertEqual(self.reserve("same", "12.00").reservation_id, first.reservation_id)
        with self.assertRaises(ReservationError):
            self.reserve("same", "13.00")

    def test_dispatch_started_expiry_requires_reconciliation_and_keeps_budget(self):
        r = self.reserve("provider-call", "30.00", now=1000, expiry=1010)
        self.store.mark_dispatch_started(r.reservation_id, now=1001)
        result = self.store.expire_due(now=1011)
        self.assertEqual(result, {"expired": 0, "reconciliation_required": 1})
        self.assertEqual(self.store.get(r.reservation_id).status, "RECONCILIATION_REQUIRED")
        self.assertEqual(self.store.committed_and_reserved_total("issuer-grant-1"), Decimal("30.00"))

    def test_pre_dispatch_expiry_releases_budget(self):
        r = self.reserve("not-sent", "30.00", now=1000, expiry=1010)
        self.assertEqual(self.store.expire_due(now=1011), {"expired": 1, "reconciliation_required": 0})
        self.assertEqual(self.store.get(r.reservation_id).status, "EXPIRED")
        self.assertEqual(self.store.committed_and_reserved_total("issuer-grant-1"), Decimal("0"))

    def test_release_requires_explicit_non_payment_evidence(self):
        r = self.reserve("release", "30.00")
        with self.assertRaises(ReservationError):
            self.store.release(r.reservation_id, confirmed_non_payment=False)
        self.store.release(r.reservation_id, confirmed_non_payment=True)
        self.assertEqual(self.store.committed_and_reserved_total("issuer-grant-1"), Decimal("0"))

    def test_settlement_requires_verified_evidence_and_keeps_spend_consumed(self):
        r = self.reserve("settle", "25.00")
        with self.assertRaises(ReservationError):
            self.store.settle(r.reservation_id, provider_reference="ORDER-1", verified_settlement=False)
        self.store.settle(r.reservation_id, provider_reference="CAPTURE-1", verified_settlement=True)
        self.assertEqual(self.store.get(r.reservation_id).status, "SETTLED")
        self.assertEqual(self.store.committed_and_reserved_total("issuer-grant-1"), Decimal("25.00"))

    def test_unknown_outcome_retains_budget_after_restart(self):
        r = self.reserve("unknown", "40.00")
        self.store.mark_dispatch_started(r.reservation_id)
        self.store.mark_unknown(r.reservation_id)
        restarted = SQLiteSpendReservationStore(self.path, deployment_mode="single-host")
        self.assertEqual(restarted.get(r.reservation_id).status, "RECONCILIATION_REQUIRED")
        with self.assertRaises(ReservationError):
            restarted.reserve(grant_id="issuer-grant-1", max_spend="100.00", amount="61.00",
                              currency="USD", idempotency_key="over-limit", expires_at=9999999999)

    def test_currency_or_grant_limit_cannot_change_after_initialization(self):
        self.reserve("first", "10.00")
        with self.assertRaises(ReservationError):
            self.store.reserve(grant_id="issuer-grant-1", max_spend="200.00", amount="1.00",
                               currency="USD", idempotency_key="second", expires_at=9999999999)

    def test_order_id_is_persisted_as_reconciliation_evidence_not_settlement(self):
        r = self.reserve("order-created", "15.00")
        self.store.mark_dispatch_started(r.reservation_id)
        self.store.record_order_created(r.reservation_id, order_id="ORDER-LOCAL-TEST")
        self.store.record_order_created(r.reservation_id, order_id="ORDER-LOCAL-TEST")
        events = self.store.events_for(r.reservation_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "ORDER_CREATED")
        self.assertEqual(events[0]["external_reference"], "ORDER-LOCAL-TEST")
        self.assertEqual(self.store.get(r.reservation_id).status, "RESERVED")
        with self.assertRaises(ReservationError):
            self.store.record_order_created(r.reservation_id, order_id="DIFFERENT-ORDER")

    def test_deployment_mode_must_be_explicit_and_single_host(self):
        with self.assertRaises(ReservationError):
            SQLiteSpendReservationStore(self.path)
        with self.assertRaises(ReservationError):
            SQLiteSpendReservationStore(self.path, deployment_mode="multi-host")

    def test_storage_must_be_persistent(self):
        with self.assertRaises(ReservationError):
            SQLiteSpendReservationStore(":memory:", deployment_mode="single-host")


if __name__ == "__main__":
    unittest.main()
