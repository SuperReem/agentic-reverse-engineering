"""One execution path for CLI and UI, including failed-run artifacts."""

from __future__ import annotations

from .telemetry import RunObserver, serialize


class AnalysisFailure(RuntimeError):
    def __init__(self, cause, result):
        super().__init__(str(cause))
        self.result = result
        self.cause = cause


def execute_analysis(binary, target, binary_name=None, observer=None, on_update=None, workflow=None):
    from .tools import validate_binary

    if workflow is None:
        from .graph import graph

        workflow = graph
    observer = observer or RunObserver()
    state = {"binary_path": binary, "binary_name": binary_name, "target_function": target, "iteration": 0}
    try:
        state["binary_path"] = validate_binary(binary)
        observer.emit("input", "run", inputs={"binary": binary, "target": target, "binary_name": binary_name})
        for mode, update in workflow.stream(
            state,
            config={"configurable": {"observer": observer}, "recursion_limit": 16},
            stream_mode=["updates", "custom"],
        ):
            if mode == "updates":
                for values in update.values():
                    state.update(values)
            if on_update:
                on_update(mode, update, serialize(state))
        state["run_status"] = "complete"
        observer.finish("complete", serialize(state))
    except Exception as exc:
        state.update(observer.partial_updates)
        state.update(run_status="error", error={"type": type(exc).__name__, "message": str(exc)})
        observer.finish("error", serialize(state), state["error"])
        state["telemetry"] = observer.snapshot()
        state["run_id"] = observer.run_id
        raise AnalysisFailure(exc, serialize(state)) from exc
    state["telemetry"] = observer.snapshot()
    state["run_id"] = observer.run_id
    return serialize(state)
