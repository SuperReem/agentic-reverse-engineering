from langgraph.graph import (
    StateGraph,
    START,
    END,
)

from .agents import (
    static_agent,
    dynamic_agent,
    judge_agent,
    experiment_agent,
)

from .state import REState
from .telemetry import observed_agent


MAX_EXPERIMENTS = 2


def route_after_judge(
    state: REState,
) -> str:

    verdict = state["verdict"]

    iteration = state.get(
        "iteration",
        0,
    )

    if not state.get("stop_reason") and verdict.needs_more_evidence and iteration < MAX_EXPERIMENTS:
        return "experiment"

    return "end"


builder = StateGraph(REState)


builder.add_node(
    "static",
    observed_agent(static_agent),
)

builder.add_node(
    "dynamic",
    observed_agent(dynamic_agent),
)

builder.add_node(
    "judge",
    observed_agent(judge_agent),
)

builder.add_node(
    "experiment",
    observed_agent(experiment_agent),
)


# Run static and dynamic analysis independently.
builder.add_edge(
    START,
    "static",
)

builder.add_edge(
    START,
    "dynamic",
)


# LangGraph waits for both incoming branches
# before executing the judge.
builder.add_edge(
    [
        "static",
        "dynamic",
    ],
    "judge",
)


builder.add_conditional_edges(
    "judge",
    route_after_judge,
    {
        "experiment": "experiment",
        "end": END,
    },
)


builder.add_edge(
    "experiment",
    "judge",
)


graph = builder.compile()


def export_graph_png(output_path="graph.png"):
    """Export the compiled workflow using LangGraph's built-in Mermaid renderer."""
    from pathlib import Path

    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    graph.get_graph().draw_mermaid_png(output_file_path=str(output))
    return output


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Export the agent workflow as a PNG")
    parser.add_argument("--output", default="graph.png", help="Output PNG path")
    args = parser.parse_args()
    print(f"Graph saved to {export_graph_png(args.output)}")


if __name__ == "__main__":
    main()
