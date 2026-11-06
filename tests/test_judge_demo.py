from pathlib import Path

import pytest

from scripts import run_judge_demo


def test_judge_demo_defaults_to_provider_free_offline_mode(monkeypatch):
    calls = []
    monkeypatch.setattr("scripts.run_local_demo.main", lambda: calls.append("offline") or 0)
    monkeypatch.setattr("scripts.run_paypal_sandbox_demo.main", lambda: calls.append("sandbox") or 0)

    assert run_judge_demo.main([]) == 0
    assert calls == ["offline"]


def test_sandbox_requires_separate_explicit_ack_before_runner(monkeypatch, capsys):
    monkeypatch.setattr(
        "scripts.run_paypal_sandbox_demo.main",
        lambda: pytest.fail("Sandbox runner must not be entered without acknowledgement"),
    )

    assert run_judge_demo.main(["--mode", "sandbox"]) == 2
    assert "can contact PayPal Sandbox" in capsys.readouterr().err


def test_explicitly_acknowledged_sandbox_routes_to_existing_guarded_runner(monkeypatch):
    calls = []
    monkeypatch.setattr("scripts.run_paypal_sandbox_demo.main", lambda: calls.append("sandbox") or 7)

    assert run_judge_demo.main(["--mode", "sandbox", "--confirm-sandbox"]) == 7
    assert calls == ["sandbox"]


def test_dashboard_import_displays_only_simulated_offline_rows():
    dashboard = Path(__file__).resolve().parents[1] / "dashboard_v2.html"
    source = dashboard.read_text(encoding="utf-8")

    assert "function validOfflineReport(data)" in source
    assert "item.execution_label === 'SIMULATED'" in source
    assert "item.payment_status === 'NOT_DISPATCHED'" in source
    assert "Local file (not independently verified)" in source
    assert "UNKNOWN — unresolved; not a success" in source
    assert "scenario-report" in source
    assert "target.append(card)" in source
    assert "target.innerHTML" not in source
