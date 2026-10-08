from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import StructuredTool

from binary_insight.react import research
from binary_insight.telemetry import CURRENT


def test_model_selects_tool_and_observes_result_before_next_action(observer):
    executed = []

    def inspect(value: str) -> str:
        """Inspect a value."""
        executed.append(value)
        return "observed " + value

    tool = StructuredTool.from_function(inspect)

    class Model:
        turns = 0

        def bind_tools(self, tools):
            assert tools == [tool]
            return self

        def invoke(self, messages):
            self.turns += 1
            if self.turns == 1:
                return AIMessage(
                    content="",
                    tool_calls=[{"name": "inspect", "args": {"value": "a"}, "id": "1"}],
                    usage_metadata={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
                )
            assert isinstance(messages[-1], ToolMessage)
            assert messages[-1].content == "observed a"
            return AIMessage(
                content="Enough evidence", usage_metadata={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}
            )

    token = CURRENT.set(observer)
    try:
        output = research(Model(), [tool], "Investigate", "fixture")
    finally:
        CURRENT.reset(token)
    assert executed == ["a"]
    assert "observed a" in output
    assert observer.snapshot()["model_calls"] == 2
    assert observer.snapshot()["total_tokens"] == 24
    assert any(event["event"] == "react_stop" for event in observer.events)


def test_repeated_requests_stop_without_reexecuting_tool():
    executed = []

    def inspect() -> str:
        """Inspect evidence."""
        executed.append(True)
        return "unchanged"

    class Model:
        turns = 0

        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            self.turns += 1
            return AIMessage(content="", tool_calls=[{"name": "inspect", "args": {}, "id": str(self.turns)}])

    model = Model()
    output = research(model, [StructuredTool.from_function(inspect)], "Investigate", "fixture")
    assert executed == [True]
    assert model.turns == 3
    assert "stagnation" in output


def test_tool_call_limit_bounds_multiple_calls_in_one_turn():
    executed = []

    def inspect(value: int) -> str:
        """Inspect a value."""
        executed.append(value)
        return str(value)

    class Model:
        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            return AIMessage(
                content="", tool_calls=[{"name": "inspect", "args": {"value": i}, "id": str(i)} for i in range(10)]
            )

    output = research(Model(), [StructuredTool.from_function(inspect)], "Investigate", "fixture", max_calls=2)
    assert executed == [0, 1]
    assert "tool-call limit" in output


def test_runtime_tools_fix_target_validate_arguments_and_skip_tested_inputs(monkeypatch):
    from binary_insight import agents

    calls = []
    additional = []
    monkeypatch.setattr(agents, "get_model", lambda: object())
    monkeypatch.setattr(agents, "run_dynamic_test", lambda *args: calls.append(args) or "trace evidence")

    def investigate(model, tools, task, name):
        tool = {tool.name: tool for tool in tools}["trace_selected_function"]
        assert "blocked" in tool.invoke({"arguments": ["old"]})
        assert tool.invoke({"arguments": ["new"]}) == "trace evidence"
        assert "blocked" in tool.invoke({"arguments": ["new"]})
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            tool.invoke({"arguments": ["bad\x00input"]})
        return "observations"

    monkeypatch.setattr(agents, "research", investigate)
    assert agents.runtime_research("/fixed/binary", "fixed_function", [], [["old"]], "Investigate", additional)
    assert calls == [("/fixed/binary", "fixed_function", ["new"])]
    assert [test.arguments for test in additional] == [["new"]]
