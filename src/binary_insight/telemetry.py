"""Thread-safe JSONL tracing and provider-reported token accounting."""

from __future__ import annotations

import contextvars
import functools
import inspect
import json
import os
import re
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from langchain_core.runnables import RunnableConfig

from .settings import PRICING, ROOT, positive_float

CURRENT = contextvars.ContextVar("analysis_observer", default=None)
PARENT = contextvars.ContextVar("analysis_span", default=None)
STAGE = contextvars.ContextVar("analysis_stage", default="system")


class BudgetExceeded(RuntimeError):
    pass


def serialize(value):
    return json.loads(
        json.dumps(value, default=lambda item: item.model_dump() if hasattr(item, "model_dump") else str(item))
    )


def redact(value):
    """Keep traces bounded and avoid accidentally logging credential values."""
    if isinstance(value, dict):
        return {
            str(k): "[REDACTED]"
            if any(term in str(k).lower() for term in ("api_key", "authorization", "access_token"))
            else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"sk-[A-Za-z0-9_-]{12,}", "[REDACTED]", value)
        for key in ("OPENAI_API_KEY",):
            secret = os.getenv(key)
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value[:64000] + ("\n[TRACE TRUNCATED]" if len(value) > 64000 else "")
    return value


def calculate_cost(model, usage, prices):
    """USD estimate for text tokens, honoring cache read/write categories."""
    rates = prices.get("models", {}).get(model)
    if not rates or not usage:
        return None
    if any(key.startswith(("priority_", "flex_", "fast_")) for key in usage.get("input_token_details", {})):
        return None
    tier = (
        rates.get("long_context")
        if usage.get("input_tokens", 0) > rates.get("long_context_threshold", float("inf"))
        else rates
    )
    if not tier:
        return None
    details = usage.get("input_token_details", {})
    cached = details.get("cache_read", 0)
    writes = details.get("cache_creation", details.get("cache_write", 0))
    if rates.get("cache_write_required") and not any(k in details for k in ("cache_creation", "cache_write")):
        return None
    if writes and "cache_write" not in tier:
        return None
    regular = max(0, usage.get("input_tokens", 0) - cached - writes)
    return (
        regular * tier["input"]
        + cached * tier.get("cached_input", tier["input"])
        + writes * tier.get("cache_write", tier["input"])
        + usage.get("output_tokens", 0) * tier["output"]
    ) / 1_000_000


class RunObserver:
    def __init__(self, directory=None, on_update=None, max_seconds=None, max_tokens=None, max_cost=None, pricing=None):
        self.run_id = uuid.uuid4().hex
        directory = Path(directory or ROOT / "traces")
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / f"{self.run_id}.jsonl"
        self.path.touch(mode=0o600)
        self.lock = threading.RLock()
        self.on_update = on_update
        self.started = time.monotonic()
        self.finished = None
        self.max_seconds = max_seconds or positive_float("RUN_TIMEOUT_SECONDS", 600)
        self.max_tokens = max_tokens or int(positive_float("RUN_MAX_TOKENS", 100000))
        self.max_cost = max_cost or positive_float("RUN_MAX_COST_USD", 5)
        if pricing is not None:
            self.pricing = pricing
        else:
            try:
                self.pricing = json.loads(PRICING.read_text())
            except (OSError, ValueError):
                self.pricing = {"models": {}}
        self.usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cached_tokens": 0,
            "model_calls": 0,
            "cost_usd": 0.0,
            "unpriced_calls": 0,
            "missing_usage_calls": 0,
        }
        self.per_agent = {}
        self.partial_updates = {}
        self.events = []
        self.emit("run_start", "run", inputs={"limits": self.limits()})

    def limits(self):
        return {"seconds": self.max_seconds, "tokens": self.max_tokens, "cost_usd": self.max_cost}

    def snapshot(self):
        with self.lock:
            return {
                "run_id": self.run_id,
                "elapsed_seconds": round((self.finished or time.monotonic()) - self.started, 2),
                **self.usage,
                "cost_complete": not (self.usage["unpriced_calls"] or self.usage["missing_usage_calls"]),
                "per_agent": serialize(self.per_agent),
                "limits": self.limits(),
            }

    def emit(self, event, kind, **fields):
        with self.lock:
            entry = redact(
                serialize(
                    {
                        "sequence": len(self.events) + 1,
                        "run_id": self.run_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event": event,
                        "kind": kind,
                        "stage": STAGE.get(),
                        "span_id": PARENT.get(),
                        **fields,
                    }
                )
            )
            with self.path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.events.append(entry)
        if self.on_update:
            self.on_update(entry, self.snapshot())
        return entry

    def check(self):
        summary = self.snapshot()
        reason = None
        if summary["elapsed_seconds"] >= self.max_seconds:
            reason = "Run time budget reached"
        elif summary["total_tokens"] >= self.max_tokens:
            reason = "Run token budget reached"
        elif summary["cost_usd"] >= self.max_cost:
            reason = "Run cost budget reached"
        if reason:
            self.emit("budget_stop", "guard", reason=reason)
            raise BudgetExceeded(reason)

    def record_usage(self, raw, fallback_model):
        usage = getattr(raw, "usage_metadata", None)
        model = getattr(raw, "response_metadata", {}).get("model_name") or fallback_model
        rates_model = model if model in self.pricing.get("models", {}) else fallback_model
        cost = calculate_cost(rates_model, usage, self.pricing)
        if getattr(raw, "response_metadata", {}).get("service_tier") not in (None, "default", "standard"):
            cost = None
        with self.lock:
            agent = self.per_agent.setdefault(
                STAGE.get(),
                {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "cached_tokens": 0,
                    "model_calls": 0,
                    "cost_usd": 0.0,
                    "unpriced_calls": 0,
                    "missing_usage_calls": 0,
                },
            )
            for totals in (self.usage, agent):
                totals["model_calls"] += 1
                if not usage:
                    totals["missing_usage_calls"] += 1
                    continue
                for key in ("input_tokens", "output_tokens", "total_tokens"):
                    totals[key] += usage.get(
                        key,
                        usage.get("input_tokens", 0) + usage.get("output_tokens", 0) if key == "total_tokens" else 0,
                    )
                totals["cached_tokens"] += usage.get("input_token_details", {}).get("cache_read", 0)
                if cost is None:
                    totals["unpriced_calls"] += 1
                else:
                    totals["cost_usd"] += cost
        self.emit(
            "usage",
            "model",
            model=model,
            pricing_model=rates_model,
            usage=usage,
            estimated_cost_usd=cost,
            pricing_version=self.pricing.get("updated_at"),
        )

    def finish(self, status, result=None, error=None):
        self.finished = time.monotonic()
        self.emit("run_end", "run", status=status, outputs=result, error=error, metrics=self.snapshot())


@contextmanager
def span(kind, name, inputs=None):
    observer = CURRENT.get()
    if not observer:
        yield
        return
    observer.check()
    span_id = uuid.uuid4().hex
    parent = PARENT.get()
    token = PARENT.set(span_id)
    started = time.monotonic()
    observer.emit("start", kind, name=name, span_id=span_id, parent_span_id=parent, inputs=inputs)
    try:
        yield
    except Exception as exc:
        observer.emit(
            "end",
            kind,
            name=name,
            span_id=span_id,
            parent_span_id=parent,
            status="error",
            duration_ms=round((time.monotonic() - started) * 1000, 2),
            error={"type": type(exc).__name__, "message": str(exc)},
        )
        raise
    else:
        observer.emit(
            "end",
            kind,
            name=name,
            span_id=span_id,
            parent_span_id=parent,
            status="ok",
            duration_ms=round((time.monotonic() - started) * 1000, 2),
        )
    finally:
        PARENT.reset(token)


def traced_tool(function):
    signature = inspect.signature(function)

    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        inputs = dict(signature.bind(*args, **kwargs).arguments)
        inputs.pop("progress", None)
        with span("tool", function.__name__, inputs):
            result = function(*args, **kwargs)
            observer = CURRENT.get()
            if observer:
                observer.emit("output", "tool", name=function.__name__, span_id=PARENT.get(), outputs=result)
            return result

    return wrapped


def observed_agent(function):
    def node(state, config: RunnableConfig):
        observer = config.get("configurable", {}).get("observer")
        token = CURRENT.set(observer)
        stage = STAGE.set(function.__name__.removesuffix("_agent"))
        try:
            with span("agent", function.__name__, state):
                result = function(state)
                if observer:
                    with observer.lock:
                        observer.partial_updates.update(result)
                    observer.emit("output", "agent", name=function.__name__, span_id=PARENT.get(), outputs=result)
                return result
        finally:
            STAGE.reset(stage)
            CURRENT.reset(token)

    return node


def invoke_structured(runnable, prompt, model_name):
    with span("model", model_name, {"prompt": prompt}):
        observer = CURRENT.get()
        try:
            envelope = runnable.invoke(prompt)
        except Exception:
            if observer:
                observer.record_usage(None, model_name)
            raise
        if observer:
            observer.record_usage(envelope.get("raw"), model_name)
        if envelope.get("parsing_error"):
            raise ValueError(f"Invalid structured model output: {envelope['parsing_error']}")
        result = envelope.get("parsed")
        if result is None:
            raise ValueError("Model returned no structured result")
        if observer:
            observer.emit("output", "model", name=model_name, span_id=PARENT.get(), outputs=result)
            observer.check()
        return result
