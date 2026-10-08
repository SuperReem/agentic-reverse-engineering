import pytest
from langchain_core.messages import AIMessage

from binary_insight import agents
from binary_insight.schemas import AnalysisResult, DynamicTestPlan, Evidence, FunctionSummary, TestCase, Verdict
from binary_insight.telemetry import RunObserver


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / "fixture_binary"
    path.write_bytes(b"fixture: never executed")
    return str(path)


@pytest.fixture
def observer(tmp_path):
    return RunObserver(
        directory=tmp_path / "traces",
        pricing={"models": {agents.MODEL_NAME: {"input": 2, "cached_input": 0.5, "output": 8}}},
    )


def envelope(parsed):
    return {
        "parsed": parsed,
        "parsing_error": None,
        "raw": AIMessage(
            content="Structured response",
            usage_metadata={
                "input_tokens": 100,
                "output_tokens": 20,
                "total_tokens": 120,
                "input_token_details": {"cache_read": 10},
            },
            response_metadata={"model_name": agents.MODEL_NAME},
        ),
    }


def verdict(**updates):
    return Verdict(
        status="verified",
        conclusion="Compares a command",
        confidence=0.8,
        reasoning="Static and runtime observations agree",
        supporting_evidence=["Comparison observed"],
        summary=FunctionSummary(
            purpose="Compares a command", inputs="String", behavior="Comparison", outputs="Boolean"
        ),
    ).model_copy(update=updates)


@pytest.fixture
def offline_models(monkeypatch):
    monkeypatch.setattr(agents, "research", lambda *args, **kwargs: "Offline tool observations")
    monkeypatch.setattr(agents, "get_model", lambda: object())
    prompts = {"static": [], "planner": [], "dynamic": [], "judge": []}
    for name in ("get_file_info", "get_strings", "get_symbols", "get_function_disassembly"):
        monkeypatch.setattr(agents, name, lambda *args: "Static observation " * 30)
    monkeypatch.setenv("FRIDA_ENABLED", "0")
    monkeypatch.setattr(
        agents, "run_dynamic_test", lambda *args: "ARGS: []\nRETURN CODE: 0\nSTDOUT:\nNormal\nSTDERR:\n"
    )
    from binary_insight import tools

    monkeypatch.setattr(tools, "run_binary", lambda *args: "ARGS: ['a']\nRETURN CODE: 0\nSTDOUT:\nNormal\nSTDERR:\n")
    analysis = AnalysisResult(
        target="main",
        hypothesis="Compares input",
        proposed_name="compare_input",
        confidence=0.8,
        evidence=[Evidence(source="static", description="Comparison")],
    )
    plan = DynamicTestPlan(tests=[TestCase(arguments=["a"], reason="Probe input")])

    def response(name, parsed):
        def invoke(prompt):
            prompts[name].append(prompt)
            return envelope(parsed)

        return invoke

    monkeypatch.setattr(agents.static_model, "invoke", response("static", analysis))
    monkeypatch.setattr(
        agents.dynamic_model,
        "invoke",
        response(
            "dynamic",
            analysis.model_copy(
                update={"evidence": [Evidence(source="dynamic", description="Observed process output")]}
            ),
        ),
    )
    monkeypatch.setattr(agents.dynamic_planner_model, "invoke", response("planner", plan))
    monkeypatch.setattr(agents.judge_model, "invoke", response("judge", verdict()))
    return prompts
