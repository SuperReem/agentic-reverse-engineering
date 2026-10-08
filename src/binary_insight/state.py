from typing import TypedDict

from .schemas import (
    AnalysisResult,
    Verdict,
    DynamicTestPlan,
)


class REState(TypedDict, total=False):
    binary_path: str
    target_function: str

    static_result: AnalysisResult

    dynamic_test_plan: DynamicTestPlan
    dynamic_executed_plan: dict
    initial_observation: str
    dynamic_observations: str
    dynamic_result: AnalysisResult

    experiment_request: str
    experiment_result: str

    verdict: Verdict

    iteration: int
    tested_arguments: list[list[str]]
    observation_fingerprints: list[str]
    experiment_requests: list[str]
    experiment_history: list[dict]
    verdict_history: list[dict]
    stagnant_rounds: int
    stop_reason: str | None
