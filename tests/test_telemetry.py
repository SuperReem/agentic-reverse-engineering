import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from langchain_core.messages import AIMessage

from binary_insight.telemetry import (
    CURRENT,
    BudgetExceeded,
    RunObserver,
    calculate_cost,
    invoke_structured,
    traced_tool,
)


def test_cached_and_written_tokens_are_not_double_billed():
    prices = {"models": {"fixture": {"input": 2, "cached_input": 0.5, "cache_write": 2.5, "output": 8}}}
    usage = {
        "input_tokens": 1000,
        "output_tokens": 200,
        "input_token_details": {"cache_read": 300, "cache_creation": 100},
    }
    assert calculate_cost("fixture", usage, prices) == pytest.approx(0.0032)
    assert calculate_cost("unknown", usage, prices) is None
    prices["models"]["fixture"]["cache_write_required"] = True
    assert calculate_cost("fixture", {"input_tokens": 1000}, prices) is None


def test_long_context_rates():
    rates = {"input": 1, "output": 2, "long_context_threshold": 10, "long_context": {"input": 3, "output": 4}}
    assert calculate_cost(
        "fixture", {"input_tokens": 11, "output_tokens": 2}, {"models": {"fixture": rates}}
    ) == pytest.approx(0.000041)


def test_unknown_prices_are_not_reported_as_free(tmp_path):
    observer = RunObserver(tmp_path, pricing={"models": {}})
    observer.record_usage(
        AIMessage(content="x", usage_metadata={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}), "unknown"
    )
    metrics = observer.snapshot()
    assert metrics["total_tokens"] == 12 and metrics["unpriced_calls"] == 1
    assert not metrics["cost_complete"]


def test_thread_safe_trace_sequences_and_redaction(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "private-fixture-secret")
    observer = RunObserver(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(
            pool.map(
                lambda index: observer.emit(
                    "probe", "tool", inputs={"api_key": "private-fixture-secret", "text": "private-fixture-secret"}
                ),
                range(50),
            )
        )
    events = [json.loads(line) for line in observer.path.read_text().splitlines()]
    assert [e["sequence"] for e in events] == list(range(1, 52))
    assert "private-fixture-secret" not in observer.path.read_text()


@pytest.mark.parametrize("limit", ["tokens", "cost", "time"])
def test_run_budgets_stop_calls(tmp_path, limit):
    observer = RunObserver(tmp_path, max_tokens=1, max_cost=0.001, max_seconds=1)
    if limit == "tokens":
        observer.usage["total_tokens"] = 1
    elif limit == "cost":
        observer.usage["cost_usd"] = 0.001
    else:
        observer.started -= 2
    with pytest.raises(BudgetExceeded):
        observer.check()
    assert observer.events[-1]["event"] == "budget_stop"


def test_tool_errors_have_inputs_duration_and_error(tmp_path):
    observer = RunObserver(tmp_path)

    @traced_tool
    def broken_tool(argument):
        raise ValueError("Invalid fixture")

    token = CURRENT.set(observer)
    try:
        with pytest.raises(ValueError):
            broken_tool("sample")
    finally:
        CURRENT.reset(token)
    start, end = observer.events[-2:]
    assert start["inputs"] == {"argument": "sample"}
    assert end["status"] == "error" and end["duration_ms"] >= 0
    assert start["span_id"] == end["span_id"]


def test_parsing_errors_still_account_provider_usage(tmp_path):
    observer = RunObserver(tmp_path, pricing={"models": {"fixture": {"input": 1, "output": 2}}})

    class InvalidOutput:
        def invoke(self, prompt):
            return {
                "parsed": None,
                "parsing_error": ValueError("Invalid JSON"),
                "raw": AIMessage(
                    content="x", usage_metadata={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}
                ),
            }

    token = CURRENT.set(observer)
    try:
        with pytest.raises(ValueError):
            invoke_structured(InvalidOutput(), "fixture prompt", "fixture")
    finally:
        CURRENT.reset(token)
    assert observer.snapshot()["total_tokens"] == 12
    assert observer.events[-1]["status"] == "error"
