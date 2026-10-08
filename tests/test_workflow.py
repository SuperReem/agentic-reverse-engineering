import json

import pytest

from binary_insight import agents
from binary_insight.engine import AnalysisFailure, execute_analysis
from binary_insight.graph import route_after_judge
from binary_insight.schemas import DynamicTestPlan, ExperimentRequest, TestCase as Case
from conftest import envelope, verdict


def test_parallel_workflow_is_traced_and_accounts_usage(binary, observer, offline_models):
    events = []
    result = execute_analysis(binary, "main", "fixture", observer, lambda *args: events.append(args))
    assert result["run_status"] == "complete"
    assert result["telemetry"]["model_calls"] == 4
    assert result["telemetry"]["total_tokens"] == 480
    assert result["telemetry"]["cost_usd"] == pytest.approx(0.00138)
    assert result["telemetry"]["cost_complete"]
    assert set(result["telemetry"]["per_agent"]) == {"static", "dynamic", "judge"}
    traces = [json.loads(line) for line in observer.path.read_text().splitlines()]
    judge_start = next(e["sequence"] for e in traces if e.get("name") == "judge_agent" and e["event"] == "start")
    assert all(
        next(e["sequence"] for e in traces if e.get("name") == name and e["event"] == "end") < judge_start
        for name in ("static_agent", "dynamic_agent")
    )
    assert any(e["kind"] == "tool" for e in traces)
    model_spans = {e["span_id"] for e in traces if e["kind"] == "model" and e["event"] == "start"}
    assert all(e["span_id"] in model_spans for e in traces if e["event"] == "usage")
    assert any(mode == "custom" for mode, _, _ in events)
    assert "Observed process output" not in offline_models["static"][0]
    assert "Static observation" not in offline_models["planner"][0]
    assert traces[-1]["event"] == "run_end"


def test_repeated_experiment_inputs_stop_without_reexecution(binary, observer, offline_models, monkeypatch):
    calls = []
    from binary_insight import tools

    monkeypatch.setattr(tools, "run_binary", lambda *args: calls.append(args) or "RETURN CODE: 0\nSTDOUT:\nNormal")
    monkeypatch.setattr(
        agents.judge_model,
        "invoke",
        lambda prompt: envelope(
            verdict(
                status="uncertain",
                needs_more_evidence=True,
                experiment=ExperimentRequest(description="Try another input", reason="Resolve uncertainty"),
            )
        ),
    )
    result = execute_analysis(binary, "main", observer=observer)
    assert len(calls) == 1  # Initial planned test; the duplicate experiment is skipped.
    assert "repeated previously tested inputs" in result["stop_reason"]
    assert len(result["experiment_history"]) == 1
    assert result["experiment_history"][0]["executed_arguments"] == []
    assert result["experiment_history"][0]["skipped_duplicates"] == 1
    assert len(result["verdict_history"]) == 2
    assert result["verdict"]["status"] == "uncertain"


def test_repeated_judge_request_stops(binary, observer, offline_models, monkeypatch):
    plans = iter([DynamicTestPlan(tests=[Case(arguments=[value], reason="Probe")]) for value in ("a", "b")])
    monkeypatch.setattr(agents.dynamic_planner_model, "invoke", lambda prompt: envelope(next(plans)))
    monkeypatch.setattr(
        agents.judge_model,
        "invoke",
        lambda prompt: envelope(
            verdict(
                status="uncertain",
                needs_more_evidence=True,
                experiment=ExperimentRequest(description="Try another input", reason="Resolve uncertainty"),
            )
        ),
    )
    result = execute_analysis(binary, "main", observer=observer)
    assert result["stop_reason"] == "Repeated experiment request"
    assert result["iteration"] == 1


def test_stagnation_and_complete_experiment_history(binary, observer, offline_models, monkeypatch):
    plans = iter([DynamicTestPlan(tests=[Case(arguments=[value], reason="Probe")]) for value in ("a", "b", "c")])
    monkeypatch.setattr(agents.dynamic_planner_model, "invoke", lambda prompt: envelope(next(plans)))
    judges = iter(
        [
            verdict(
                status="uncertain",
                needs_more_evidence=True,
                experiment=ExperimentRequest(description=f"Probe input {i}", reason="Resolve uncertainty"),
            )
            for i in range(3)
        ]
    )
    prompts = []
    monkeypatch.setattr(agents.judge_model, "invoke", lambda prompt: prompts.append(prompt) or envelope(next(judges)))
    result = execute_analysis(binary, "main", observer=observer)
    assert result["stagnant_rounds"] == 2
    assert "no new observations" in result["stop_reason"]
    assert len(result["experiment_history"]) == 2
    assert len(result["verdict_history"]) == 3
    assert len(result["tested_arguments"]) == 4
    assert "Normal" in prompts[-1]


def test_failed_model_call_keeps_partial_results_and_trace(binary, observer, offline_models, monkeypatch):
    def fail(prompt):
        raise TimeoutError("Provider timeout")

    monkeypatch.setattr(agents.judge_model, "invoke", fail)
    with pytest.raises(AnalysisFailure) as caught:
        execute_analysis(binary, "main", observer=observer)
    result = caught.value.result
    assert result["run_status"] == "error"
    assert "static_result" in result and "dynamic_result" in result
    assert result["telemetry"]["missing_usage_calls"] == 1
    assert result["telemetry"]["cost_complete"] is False
    traces = [json.loads(line) for line in observer.path.read_text().splitlines()]
    assert traces[-1]["event"] == "run_end" and traces[-1]["status"] == "error"
    assert any(e["kind"] == "model" and e.get("status") == "error" for e in traces)


def test_route_respects_iteration_limit_and_guard():
    v = verdict(needs_more_evidence=True)
    assert route_after_judge({"verdict": v, "iteration": 0}) == "experiment"
    assert route_after_judge({"verdict": v, "iteration": 2}) == "end"
    assert route_after_judge({"verdict": v, "iteration": 0, "stop_reason": "Repeated input"}) == "end"
