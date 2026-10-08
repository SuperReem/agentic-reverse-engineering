from __future__ import annotations

import os
from functools import lru_cache

from langchain_openai import ChatOpenAI

from .schemas import (
    AnalysisResult,
    Verdict,
    DynamicTestPlan,
    TestCase,
)

from .state import REState
from .react import research
from langchain_core.tools import StructuredTool

from .tools import (
    get_file_info,
    get_strings,
    get_symbols,
    get_disassembly,
    get_function_disassembly,
    run_dynamic_test,
    execute_test_plan,
)


from .settings import positive_float
from .telemetry import CURRENT, BudgetExceeded, invoke_structured
from .guards import fresh_tests, observation_fingerprint, normalize_request, split_observations


MODEL_NAME = os.getenv(
    "OPENAI_MODEL",
    "gpt-5.6",
)


@lru_cache(maxsize=1)
def get_model():
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("Set OPENAI_API_KEY in .env before running an analysis.")
    return ChatOpenAI(
        model=MODEL_NAME,
        # Reasoning models require Responses for function tools. This also
        # preserves reasoning items when ReAct resubmits the message history.
        use_responses_api=True,
        timeout=positive_float("OPENAI_TIMEOUT_SECONDS", 90),
        max_retries=0,
    )


class StructuredModel:
    def __init__(self, schema):
        self.schema = schema

    def invoke(self, prompt):
        return get_model().with_structured_output(self.schema, include_raw=True).invoke(prompt)


def report_progress(stage: str, message: str):
    """Emit UI progress when running inside LangGraph; CLI invocation still works."""
    from langgraph.config import get_stream_writer

    try:
        writer = get_stream_writer()
    except RuntimeError:
        return
    writer({"stage": stage, "message": message})
    observer = CURRENT.get()
    if observer:
        observer.emit("progress", "agent", message=message)


static_model = StructuredModel(AnalysisResult)
dynamic_model = StructuredModel(AnalysisResult)
dynamic_planner_model = StructuredModel(DynamicTestPlan)
judge_model = StructuredModel(Verdict)


def runtime_research(binary, target, tests, previous, task, additional_tests):
    seen = {tuple(args) for args in previous} | {tuple(test.arguments) for test in tests}

    def execute(arguments: list[str], trace: bool):
        test = TestCase(arguments=arguments, reason="ReAct follow-up investigation")
        key = tuple(test.arguments)
        if key in seen:
            return "Previously tested input blocked; use existing observations."
        seen.add(key)
        additional_tests.append(test)
        if trace:
            return run_dynamic_test(binary, target, test.arguments)
        from .tools import run_binary

        return run_binary(binary, test.arguments)

    def execute_binary(arguments: list[str]) -> str:
        """Execute the selected binary with command-line arguments and observe process output."""
        return execute(arguments, False)

    def trace_selected_function(arguments: list[str]) -> str:
        """Execute with Frida to observe selected-function calls, with explicit process fallback."""
        return execute(arguments, True)

    return research(
        get_model(),
        [StructuredTool.from_function(execute_binary), StructuredTool.from_function(trace_selected_function)],
        task,
        MODEL_NAME,
    )


def static_agent(
    state: REState,
) -> dict:
    """
    Independent static analysis.

    This agent does NOT receive the dynamic
    agent's conclusions.
    """

    binary = state["binary_path"]

    target = state["target_function"]

    static_tools = []
    for function, description in (
        (get_file_info, "Inspect binary format, architecture and metadata."),
        (get_strings, "Inspect printable strings in the selected binary."),
        (get_symbols, "Inspect symbols in the selected binary."),
        (get_function_disassembly, "Disassemble the selected target function."),
        (get_disassembly, "Inspect broader disassembly if target evidence is insufficient."),
    ):

        def inspect(function=function):
            return function(binary, target) if function is get_function_disassembly else function(binary)

        # Explicit empty schema keeps binary path and target fixed by the application.
        from pydantic import create_model

        static_tools.append(
            StructuredTool.from_function(
                inspect, name=function.__name__, description=description, args_schema=create_model("InspectionInput")
            )
        )
    static_observations = research(
        get_model(),
        static_tools,
        f"Analyze selected function {target} in {binary}. Collect static evidence; do not execute it.",
        MODEL_NAME,
    )

    prompt = f"""
    You are the STATIC ANALYSIS component of an
    autonomous reverse-engineering research system.

    Analyze only binaries that the operator is
    authorized to examine.

    You MUST reason only from the static evidence
    provided below.

    Do not claim that runtime behavior was observed.

    TARGET
    ======

    Binary:
    {binary}

    Target function:
    {target}

    A target labeled sub_<hex> is an address recovered from binary metadata,
    not an original symbol name. Do not infer its purpose from that label.


    OBJECTIVE
    =========

    Determine the most likely semantic purpose of
    the target function.

    Return:

    1. A concise hypothesis explaining what the
    function does.

    2. A meaningful proposed function name.

    3. Concrete evidence supporting the hypothesis.

    4. Confidence between 0.0 and 1.0.

    5. Limitations or uncertainty.

    Important:

    - Distinguish observations from assumptions.
    - Do not invent calls, strings, or behavior.
    - A plausible interpretation without evidence
    should receive low confidence.
    - If there is insufficient evidence, say so.


    TOOL OBSERVATIONS
    =================
    {static_observations}
    """

    result = invoke_structured(static_model, prompt, MODEL_NAME)

    return {
        "static_result": result,
    }


def dynamic_agent(
    state: REState,
) -> dict:
    """
    Autonomous black-box dynamic analysis.

    Step 1:
        Run binary once without arguments.

    Step 2:
        Let the Dynamic Agent decide what
        inputs would be informative.

    Step 3:
        Execute those inputs.

    Step 4:
        Analyze the observations.

    The Dynamic Agent does NOT receive the
    Static Agent's findings.
    """

    binary = state["binary_path"]

    target = state["target_function"]

    # ------------------------------------------------
    # Step 1: Initial runtime reconnaissance
    # ------------------------------------------------

    report_progress("dynamic", "Initial execution")
    try:
        initial_observation = run_dynamic_test(
            binary,
            target,
            [],
        )

    except BudgetExceeded:
        raise
    except Exception as exc:
        initial_observation = f"Initial execution failed: {type(exc).__name__}: {exc}"

    # ------------------------------------------------
    # Step 2: Ask agent to design tests
    # ------------------------------------------------

    planning_prompt = f"""
    You are the DYNAMIC ANALYSIS agent in an
    autonomous reverse-engineering system.

    You are investigating an unknown binary using
    black-box runtime experimentation.

    You are independent from the Static Agent.

    You have NOT seen:

    - decompiled code
    - disassembly
    - static strings
    - static call graphs
    - the Static Agent's hypothesis

    Binary:

    {binary}

    Target function label:

    {target}


    INITIAL EXECUTION
    =================

    The binary was executed without arguments.

    Observed result:

    {initial_observation}


    YOUR TASK
    =========

    Design between 1 and 10 runtime tests that would
    provide useful information about the behavior of
    this binary.

    Each test consists ONLY of command-line
    arguments.

    For every test explain why that input is useful.

    Choose tests that maximize information gained
    from runtime behavior.

    Consider, when appropriate:

    - no/empty input
    - boundary cases
    - different input classes
    - numeric vs textual inputs
    - malformed inputs
    - variations suggested by runtime output

    Do NOT invent information about the binary.

    Do NOT request shell commands.

    Do NOT request file deletion, privilege changes,
    network attacks, or other unrelated actions.

    Your output must only describe command-line
    arguments to pass to the analyzed program.
    """

    report_progress("dynamic", "Planning tests · waiting for AI")
    test_plan = invoke_structured(dynamic_planner_model, planning_prompt, MODEL_NAME)

    # ------------------------------------------------
    # Step 3: Execute agent-selected tests
    # ------------------------------------------------

    tests, skipped = fresh_tests(test_plan.tests, [[]])
    effective_plan = DynamicTestPlan.model_construct(tests=tests)
    observations = (
        execute_test_plan(
            binary,
            effective_plan,
            progress=lambda index, total: report_progress("dynamic", f"Test {index}/{total}"),
            target_function=target,
        )
        if tests
        else "No new tests; the initial no-argument run already covers this plan."
    )
    if skipped and CURRENT.get():
        CURRENT.get().emit("duplicate_tests_skipped", "guard", count=skipped)

    # ------------------------------------------------
    # Step 4: Analyze observations
    # ------------------------------------------------

    additional_tests = []
    extra = runtime_research(
        binary,
        target,
        tests,
        [[]],
        "Investigate the target independently using runtime evidence. " + initial_observation + observations,
        additional_tests,
    )
    observations += "\n" + extra
    tests.extend(additional_tests)
    effective_plan = DynamicTestPlan.model_construct(tests=tests)

    analysis_prompt = f"""
    You are the DYNAMIC ANALYSIS agent in an
    autonomous reverse-engineering system.

    You selected runtime experiments and the
    execution system performed them.

    You are independent from the Static Agent.

    TARGET
    ======

    Binary:
    {binary}

    Target function label:
    {target}


    INITIAL OBSERVATION
    ===================

    {initial_observation}


    TEST PLAN
    =========

    {test_plan.model_dump_json(indent=2)}


    RUNTIME OBSERVATIONS
    ====================

    {observations}


    YOUR TASK
    =========

    Infer what can actually be concluded from these
    runtime observations.

    Return:

    1. Your behavioral hypothesis.

    2. A proposed semantic function name only if
    runtime evidence reasonably supports one.

    3. Concrete runtime evidence.

    4. Confidence from 0.0 to 1.0.

    5. Limitations.


    IMPORTANT LIMITATION
    ====================

    Frida events, when present, directly observe the selected function's entry
    and return. Raw argument slots and return values have unknown types;
    do not infer strings, argument counts, or signed values from them alone.
    A ready hook without entry events does not prove the function is unused.
    Unavailable/failed hooks and fallback process output provide no direct
    target-level attribution. Even a successful hook does not prove the
    function caused all process output. State timeout and truncation limits.

    If target-level attribution cannot be established,
    state that explicitly and reduce confidence.
    """

    report_progress("dynamic", "Interpreting results · waiting for AI")
    result = invoke_structured(dynamic_model, analysis_prompt, MODEL_NAME)

    return {
        "dynamic_test_plan": test_plan,
        "dynamic_executed_plan": effective_plan.model_dump(),
        "initial_observation": initial_observation,
        "dynamic_observations": observations,
        "dynamic_result": result,
        "tested_arguments": [[]] + [test.arguments for test in tests],
        "observation_fingerprints": [observation_fingerprint(initial_observation)]
        + [observation_fingerprint(item) for item in split_observations(observations)],
    }


def judge_agent(
    state: REState,
) -> dict:
    """
    Compare the independent analyses.

    If necessary, request another controlled
    runtime experiment.
    """

    static = state["static_result"]

    dynamic = state["dynamic_result"]

    experiment_result = state.get("experiment_history", []) or state.get("experiment_result")

    prompt = f"""
    You are the evidence JUDGE for an autonomous
    reverse-engineering research system.

    Two independent analysts investigated the same
    binary target.

    Your job is to determine what conclusion is
    actually justified by the available evidence.

    Do NOT:

    - automatically trust the higher-confidence agent,
    - assume agreement means correctness,
    - invent missing evidence.

    Evaluate the provenance and strength of every
    claim.


    STATIC ANALYSIS
    ===============

    {static.model_dump_json(indent=2)}


    DYNAMIC ANALYSIS
    ================

    {dynamic.model_dump_json(indent=2)}


    ADDITIONAL EXPERIMENT
    =====================

    {experiment_result or "No additional experiment has been run."}


    DECISION
    ========

    PRESENTATION STRUCTURE
    ======================

    Populate summary for every verdict:
    - purpose: one short sentence about the supported function purpose.
    - inputs: a brief input description.
    - behavior: the key operation justified by evidence.
    - outputs: return values or side effects justified by evidence.
    Keep each field under 25 words. Say "Unknown" when not established.
    Do not describe a rejected hypothesis as an established function fact.
    Do not attribute process-wide observations to the target without evidence.
    Keep conclusion to a single short sentence.
    Provide at most three concise supporting_evidence items and at most
    three concise contradictions. Populate unresolved_points with up to
    three material uncertainties, using one short sentence each.

    Return one of:

    verified
        Evidence is sufficiently strong and
        consistent.

    rejected
        The proposed interpretation is contradicted
        by stronger evidence.

    uncertain
        Available evidence cannot establish a
        reliable conclusion.


    If uncertainty could reasonably be reduced with
    one additional runtime experiment:

    needs_more_evidence = true

    and provide exactly ONE concrete experiment.

    The experiment description should specify what
    observation would help distinguish the competing
    interpretations.

    If the existing evidence is sufficient:

    needs_more_evidence = false
    experiment = null
    """

    report_progress("judge", "Reviewing evidence · waiting for AI")
    verdict = invoke_structured(judge_model, prompt, MODEL_NAME)

    history = state.get("verdict_history", []) + [verdict.model_dump()]
    stop_reason = state.get("stop_reason")
    request = normalize_request(verdict.experiment.description) if verdict.experiment else None
    if verdict.needs_more_evidence and not stop_reason:
        if not verdict.experiment:
            stop_reason = "Judge requested more evidence without an executable experiment"
        elif request in state.get("experiment_requests", []):
            stop_reason = "Repeated experiment request"
        elif state.get("stagnant_rounds", 0) >= 2:
            stop_reason = "Experiments produced no new observations for two rounds"
        elif state.get("iteration", 0) >= 2:
            stop_reason = "Experiment limit reached"
    if stop_reason and verdict.needs_more_evidence:
        verdict = verdict.model_copy(
            update={"status": "uncertain", "unresolved_points": (verdict.unresolved_points + [stop_reason])[-3:]}
        )
        observer = CURRENT.get()
        if observer:
            observer.emit("loop_stop", "guard", reason=stop_reason)
    return {"verdict": verdict, "verdict_history": history, "stop_reason": stop_reason}


def experiment_agent(
    state: REState,
) -> dict:

    verdict = state["verdict"]

    binary = state["binary_path"]

    iteration = state.get(
        "iteration",
        0,
    )

    if not verdict.experiment:
        return {
            "experiment_request": "No experiment requested.",
            "experiment_result": "No experiment executed.",
            "iteration": iteration + 1,
            "stop_reason": "No experiment supplied",
        }

    requested_experiment = verdict.experiment.description

    reason = verdict.experiment.reason

    planning_prompt = f"""
    Previously tested arguments (do not repeat): {state.get("tested_arguments", [])}

    You are an Experiment Agent in an autonomous
    reverse-engineering system.

    The Judge found uncertainty between available
    reverse-engineering evidence.

    The Judge requested this experiment:

    {requested_experiment}

    Reason:

    {reason}


    YOUR TASK
    =========

    Design command-line input tests that can help
    resolve this specific uncertainty.

    Return between 1 and 10 tests.

    Each test may contain ONLY command-line
    arguments for the analyzed binary.

    The tests should discriminate between competing
    interpretations rather than simply produce more
    random observations.

    Do not generate shell commands.
    """

    report_progress("experiment", "Planning experiment · waiting for AI")
    test_plan = invoke_structured(dynamic_planner_model, planning_prompt, MODEL_NAME)

    tests, skipped = fresh_tests(test_plan.tests, state.get("tested_arguments", []))
    if not tests:
        stop_reason = "Experiment repeated previously tested inputs"
        observations = "No execution: all proposed tests were duplicates."
    else:
        stop_reason = None
        observations = execute_test_plan(
            binary,
            DynamicTestPlan.model_construct(tests=tests),
            progress=lambda index, total: report_progress("experiment", f"Test {index}/{total}"),
            target_function=state["target_function"],
        )
    additional_tests = []
    if tests:
        observations += "\n" + runtime_research(
            binary,
            state["target_function"],
            tests,
            state.get("tested_arguments", []),
            f"Resolve this judge request: {requested_experiment}. Current observations: {observations}",
            additional_tests,
        )
        tests.extend(additional_tests)

    fingerprints = [observation_fingerprint(item) for item in split_observations(observations)] if tests else []
    previous = state.get("observation_fingerprints", [])
    new_evidence = bool(set(fingerprints) - set(previous))
    stagnant = 0 if new_evidence else state.get("stagnant_rounds", 0) + 1
    if skipped and CURRENT.get():
        CURRENT.get().emit("duplicate_tests_skipped", "guard", count=skipped)

    result = f"""
    JUDGE REQUEST
    =============

    {requested_experiment}


    REASON
    ======

    {reason}


    EXPERIMENT PLAN
    ===============

    {test_plan.model_dump_json(indent=2)}


    OBSERVATIONS
    ============

    {observations}
    """

    return {
        "experiment_request": requested_experiment,
        "experiment_result": result,
        "iteration": iteration + 1,
        "stop_reason": stop_reason,
        "stagnant_rounds": stagnant,
        "tested_arguments": state.get("tested_arguments", []) + [test.arguments for test in tests],
        "observation_fingerprints": previous + fingerprints,
        "experiment_requests": state.get("experiment_requests", []) + [normalize_request(requested_experiment)],
        "experiment_history": state.get("experiment_history", [])
        + [
            {
                "round": iteration + 1,
                "request": requested_experiment,
                "reason": reason,
                "plan": test_plan.model_dump(),
                "executed_arguments": [test.arguments for test in tests],
                "skipped_duplicates": skipped,
                "observations": observations,
                "new_observations": new_evidence,
                "stop_reason": stop_reason,
            }
        ],
    }
