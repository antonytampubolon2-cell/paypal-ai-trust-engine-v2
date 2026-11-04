from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import evaluate_benchmark_v3 as runner


def test_freeze_is_persisted_before_holdout_event(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    metadata = tmp_path / "freeze.json"
    events = []

    def fake_build(*, timestamp, max_validation_fpr, freeze_callback):
        assert timestamp == "2026-11-04T19:00:00Z"
        assert max_validation_fpr == 0.01
        freeze_callback({"feature_version": "trustguard-canonical-ledger-v3-research", "selected_threshold": 0.8})
        assert json.loads(metadata.read_text())["selected_threshold"] == 0.8
        assert not output.exists()
        events.append("holdout_after_persisted_freeze")
        return {"status": "SELECTED", "timestamp": timestamp}

    monkeypatch.setattr(runner, "build_report", fake_build)
    assert runner.main(["--output", str(output), "--metadata-output", str(metadata),
                        "--timestamp", "2026-11-04T19:00:00Z"]) == 0
    assert events == ["holdout_after_persisted_freeze"]
    assert json.loads(output.read_text())["status"] == "SELECTED"


def test_historical_artifact_write_is_rejected_before_fitting(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    history = tmp_path / "evaluation" / "synthetic_v2_candidate_report.json"
    history.parent.mkdir()
    history.write_text('{"frozen":true}\n')
    monkeypatch.setattr(runner, "build_report", lambda **kwargs: pytest.fail("must not fit"))
    with pytest.raises(SystemExit):
        runner.main(["--output", str(history), "--metadata-output", str(tmp_path / "freeze.json")])
    assert history.read_text() == '{"frozen":true}\n'


@pytest.mark.parametrize("extra", [
    ["--max-validation-fpr", "nan"],
    ["--max-validation-fpr", "1.1"],
    ["--output", "unsafe.py"],
    ["--output", "same.json", "--metadata-output", "same.json"],
])
def test_invalid_options_rejected_before_fitting(extra, monkeypatch):
    monkeypatch.setattr(runner, "build_report", lambda **kwargs: pytest.fail("must not fit"))
    with pytest.raises(SystemExit):
        runner.main(extra)


def test_missing_freeze_never_writes_report(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    monkeypatch.setattr(runner, "build_report", lambda **kwargs: {"status": "SELECTED"})
    with pytest.raises(RuntimeError, match="pre-holdout freeze"):
        runner.main(["--output", str(output), "--metadata-output", str(tmp_path / "freeze.json")])
    assert not output.exists()


def test_duplicate_freeze_cannot_replace_first_artifact(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    metadata = tmp_path / "freeze.json"

    def fake_build(**kwargs):
        callback = kwargs["freeze_callback"]
        callback({"version": "first"})
        callback({"version": "replacement"})
        pytest.fail("duplicate freeze must fail")

    monkeypatch.setattr(runner, "build_report", fake_build)
    with pytest.raises(RuntimeError, match="already frozen"):
        runner.main(["--output", str(output), "--metadata-output", str(metadata)])
    assert json.loads(metadata.read_text()) == {"version": "first"}
    assert not output.exists()
