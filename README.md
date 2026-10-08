# Binary Analysis Agents

A multi-agent reverse-engineering project: independent static and dynamic analysts, an evidence judge, and bounded follow-up experiments.

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/getting-started/installation/). Install the locked dependencies:

```sh
uv sync --locked
cp .env.example .env
```

Set `OPENAI_API_KEY` and a model available to your account in `.env`. Model clients initialize only when analysis starts, so graph inspection and tests do not require an API key.

The system inspection commands `file`, `strings`, `nm`, and `objdump` must be available. On macOS these are provided by developer tools; on Linux install the corresponding system utilities. Executables must match the host OS and architecture. Dynamic tests execute locally and are designed for trusted command-line binaries; this is not a VM sandbox or a GUI automation backend.

## Run

```sh
uv run --locked binary-insight
```

Open **http://127.0.0.1:8080**. Upload a binary (up to 50 MB), select a detected function, and click **Analyze**. Uploads use a private temporary directory for the server session. Symbol discovery does not execute the binary. Stripped Mach-O binaries use address-based function choices when function-start metadata is available.

Progress shows parallel agent states, test counts, AI waits, and elapsed time. The structured verdict separates the decision, confidence, purpose, inputs, operation, outputs, evidence, and unresolved points. The suggested function name is labeled explicitly.

**Analysis history** lists completed and failed runs by original filename, function, and completion timestamp in Riyadh time. Click an entry to reopen it. The sidebar folds and remembers its state. Existing `analysis.json` also appears using its modification time. History stores results, not executable copies; re-upload to rerun after restarting the server.

The **Trace** control shows step timing and outcomes. Token counts, call counts, and estimated costs are recorded under `result.telemetry` in analysis-history JSON, including per-agent totals; they are not displayed in the UI. Download the full trace as JSONL. **Export JSON** downloads results, including all experiments, verdict revisions, stop reasons, and usage totals.

Command-line analysis:

```sh
uv run --locked binary-analyze ./samples/test_program check_command --output analysis.json
uv run --locked binary-graph --output docs/graph.png
```

PNG export uses `graph.get_graph().draw_mermaid_png(...)`; its default renderer contacts Mermaid's rendering service. Use the installed package commands above.

The exported workflow image is in [docs/graph.png](docs/graph.png).

## Tracing and usage

Every agent, model call, and analysis tool has a structured span: run/span/parent IDs, timestamp, inputs, outputs, duration, outcome, and errors. JSONL events are written as they happen under `traces/<run_id>.jsonl`; failed runs preserve partial findings. Credentials are redacted and large trace fields are truncated at 64,000 characters with an explicit marker. Traces contain submitted evidence and generated results, not private model reasoning.

Token totals come from provider responses, including cache-read counts. Usage updates after each response, with per-agent and whole-run totals. Missing usage and missing pricing are flagged rather than counted as free. Estimated costs are not an invoice; failed requests without returned usage may incur unobservable charges.

Configure exact model prices in `config/pricing.json`. Included rates are a dated snapshot from [official OpenAI pricing](https://developers.openai.com/api/docs/pricing), for standard text-token processing. The configured `gpt-5.6` alias uses GPT-5.6 Sol rates, as explicitly documented on the [official model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol). A model absent from this file is flagged unpriced in the saved JSON; add its verified rates before demonstrating real-time costs. No rates are inferred from similar model names.

Each model entry uses USD per million tokens:

```json
{
  "input": 2.0,
  "cached_input": 0.5,
  "output": 8.0
}
```

Those numbers are an **illustrative configuration, not model prices**. Models with cache-write billing also need `cache_write`, `cache_write_required: true`, and provider cache-write usage. Long-context pricing can use `long_context_threshold` and a `long_context` rate object. Cached input is subtracted from ordinary input to avoid double billing. Nonstandard service tiers are flagged unpriced; regional uplifts are excluded. Recheck rates when configuring your model.

## Reliability

- Independent analysts have separate inputs; dynamic analysis never receives static findings.
- Pydantic validates plans and results; runtime plans contain argument arrays, never shell commands.
- Duplicate arguments are skipped across the initial run and all experiment rounds.
- Repeated normalized experiment requests stop the loop.
- Two rounds without new observed behavior stop further experiments.
- Two experiment rounds and a graph recursion limit provide additional hard step bounds.
- Every experiment and judge revision is retained; the judge reviews all experiment records.
- Remaining uncertainty and the reason for stopping remain visible in the final verdict.
- Binary runs have a five-second timeout, closed stdin, file-backed output, and POSIX process-group cleanup. This is process management, not security isolation.
- AI calls have a 90-second timeout with no automatic retries.
- Time, token, and known-cost budgets stop subsequent work at call boundaries and immediately after model responses. In-flight parallel requests can overshoot a budget; this is not cancellation of already-issued API requests. A cost budget cannot enforce an unknown model price.

Configuration defaults are listed in `.env.example`. `BINARY_STUDIO_HOME` optionally selects the directory for `.env`, history, pricing, and traces; otherwise the current working directory is used.

## Project structure

```text
src/binary_insight/
  agents.py       Specialized reasoning and plan/execute steps
  graph.py        Parallel fan-out, judge, and guarded experiment loop
  tools.py        Binary inspection and bounded execution
  schemas.py      Validated plans, evidence, and structured verdicts
  state.py        Shared graph state and complete experiment history
  guards.py       Repetition and stagnation detection
  telemetry.py    Spans, usage, estimated costs, and budgets
  engine.py       Shared CLI/UI runner and failure preservation
  ui.py          Local API, uploads, history, and trace downloads
  main.py        CLI
  settings.py    Configuration and resource locations
web/             Dashboard
samples/         Example C program, test binary, and CrackMe reference
config/          Versioned pricing configuration
tests/          Offline regression suite
```

All Python implementation files live in `src/binary_insight/`. Run them through the installed commands or `python -m binary_insight.ui`, `python -m binary_insight.main`, and `python -m binary_insight.graph`.

## Verify

```sh
uv run --locked pytest -q
uv run --locked ruff check src tests
uv run --locked ruff format --check src tests
node --check web/app.js
```

Tests use deterministic model responses with provider-shaped usage metadata. They do not call paid APIs or execute supplied unknown binaries. A generated, trusted subprocess fixture tests child-process timeout cleanup. Node.js enables frontend-state tests; those tests are skipped when Node is unavailable. An actual provider/binary integration run still depends on your model access and host compatibility.


## Optional function tracing with Frida

Install with `uv sync --locked --extra instrumentation`. When installed, dynamic
analysis and follow-up experiments automatically hook the selected function before
executing the binary. Set `FRIDA_ENABLED=0` to disable instrumentation.

The `trace_function` tool records up to 50 calls: entry, thread ID, four raw
argument slots, and raw return values. These are untyped machine values, not
inferred strings or function signatures. Named functions are resolved in the main
executable; stripped Mach-O `sub_...` selections use module-relative offsets to
account for ASLR. Other stripped formats are not supported by address tracing.

Each execution has a five-second runtime limit and a ten-second hard worker
deadline including setup/cleanup. Missing Frida or hook/permission failures fall
back to ordinary execution, explicitly marked as a separate run without target
attribution. A successful hook with no calls is recorded as `not_observed`.
Trace evidence is included in saved analysis/history and structured tool spans.
Frida needs host instrumentation permissions; this remains local execution of
trusted binaries, not a sandbox. Instrumentation can affect timing and behavior.

## Tool-calling ReAct

The static, dynamic, and experiment agents bind scoped tools to the model with
`bind_tools()`. Each research turn lets the model choose tools, executes validated
calls, and returns `ToolMessage` observations for the next decision. Static tools
inspect metadata, strings, symbols, and disassembly. Runtime tools execute the
selected binary or trace its selected function using Frida. Binary paths and
function targets are fixed by the application; runtime arguments use the existing
validation rules. The judge reviews evidence and requests experiments.

Each research loop is limited to six model turns and eight tool calls. Duplicate
requests and previously tested inputs are blocked, and two turns without new
observations stop the loop. Existing run budgets still apply. Final reports use
structured output after research, and every research model call contributes to
saved token/cost telemetry. Model completion text is not treated as tool evidence.
