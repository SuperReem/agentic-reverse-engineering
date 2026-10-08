import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from binary_insight import tools, ui
from binary_insight.guards import fresh_tests, observation_fingerprint
from binary_insight.schemas import TestCase as Case


def test_symbol_filtering(monkeypatch, tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(b"fixture")
    monkeypatch.setattr(tools.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        tools.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, "0001 T main\n0002 t helper\n U printf\n0003 D data\n0004 T main\n", ""
        ),
    )
    assert tools.list_functions(str(path)) == ["helper", "main"]


def test_upload_validation_and_unique_storage():
    with pytest.raises(ValueError):
        ui.save_upload(b"#!/bin/sh\necho x")
    with pytest.raises(ValueError):
        ui.save_upload(b"")
    first = Path(ui.save_upload(b"\x7fELFfixture"))
    second = Path(ui.save_upload(b"\x7fELFfixture"))
    assert first != second and first.read_bytes() == b"\x7fELFfixture"
    assert first.stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group cleanup")
def test_binary_timeout_with_child_process(tmp_path):
    script = tmp_path / "trusted_fixture"
    script.write_text(f"#!{sys.executable}\nimport os,time\nprint('Started',flush=True)\nos.fork()\ntime.sleep(30)\n")
    script.chmod(0o700)
    start = time.monotonic()
    output = tools.run_binary(str(script), timeout=1)
    assert time.monotonic() - start < 4
    assert "TIMEOUT" in output and "Started" in output


def test_duplicate_arguments_and_stagnation_ignore_argument_echo():
    tests = [Case(arguments=[arg], reason="Probe") for arg in ("a", "a", "b")]
    fresh, skipped = fresh_tests(tests, [["a"]])
    assert [t.arguments for t in fresh] == [["b"]] and skipped == 2
    assert observation_fingerprint("ARGS: ['a']\nRETURN CODE: 0\nSTDOUT:\nSame") == observation_fingerprint(
        "ARGS: ['b']\nRETURN CODE: 0\nSTDOUT:\nSame"
    )
    assert observation_fingerprint("RETURN CODE: 0\nSTDOUT:\nSame") != observation_fingerprint(
        "RETURN CODE: 1\nSTDOUT:\nSame"
    )


def test_test_runner_does_not_swallow_budget_stop(monkeypatch):
    from binary_insight.schemas import DynamicTestPlan
    from binary_insight.telemetry import BudgetExceeded

    def stop(*args):
        raise BudgetExceeded("Token budget reached")

    monkeypatch.setattr(tools, "run_binary", stop)
    with pytest.raises(BudgetExceeded):
        tools.execute_test_plan("fixture", DynamicTestPlan(tests=[Case(arguments=["a"], reason="Probe")]))


def test_history_persistence_including_failed_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "HISTORY", tmp_path / "history")
    monkeypatch.setattr(ui, "ROOT", tmp_path)
    saved = {"binary_path": "/fixture/legacy", "target_function": "main"}
    (tmp_path / "analysis.json").write_text(json.dumps(saved))
    entry = ui.save_history(
        {"binary_path": "/tmp/binary", "binary_name": "CrackMe", "target_function": "sub_1000", "run_status": "error"}
    )
    entries = ui.history_entries()
    assert any(e["id"] == entry and e["binary_name"] == "CrackMe" and e["status"] == "error" for e in entries)
    assert any(e["id"] == "saved" and e["timestamp_source"] == "file_modified" for e in entries)
    assert not list(ui.HISTORY.glob("*.tmp"))
