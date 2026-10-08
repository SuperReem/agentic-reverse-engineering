from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import execute_analysis, AnalysisFailure
from .tools import validate_binary


def parse_args():

    parser = argparse.ArgumentParser(description=("Static/Dynamic agentic reverse-engineering prototype"))

    parser.add_argument(
        "binary",
        help="Path to the test binary",
    )

    parser.add_argument(
        "target",
        help=("Target function name, for example main or check_password"),
    )

    parser.add_argument(
        "--output",
        default="analysis.json",
        help=("Output JSON file (default: analysis.json)"),
    )

    return parser.parse_args()


def serialize_result(
    result: dict,
) -> dict:

    output = {}

    for key, value in result.items():
        if hasattr(
            value,
            "model_dump",
        ):
            output[key] = value.model_dump()

        else:
            output[key] = value

    return output


def print_section(
    title: str,
    content,
):

    print()
    print("=" * 72)
    print(title)
    print("=" * 72)

    if content is None:
        print("None")
        return

    if hasattr(
        content,
        "model_dump_json",
    ):
        print(content.model_dump_json(indent=2))

    else:
        print(content)


def main():

    args = parse_args()

    binary = validate_binary(args.binary)

    print(f"[+] Binary: {binary}")

    print(f"[+] Target: {args.target}")

    print("[+] Starting independent static/dynamic analysis...")

    failed = False
    try:
        result = execute_analysis(binary, args.target, Path(binary).name)
    except AnalysisFailure as exc:
        result = exc.result
        failed = True
        print(f"[!] Analysis stopped: {exc}")

    print_section(
        "STATIC ANALYSIS",
        result.get("static_result"),
    )

    print_section(
        "DYNAMIC ANALYSIS",
        result.get("dynamic_result"),
    )

    if result.get("experiment_result"):
        print_section(
            "EXPERIMENT",
            result["experiment_result"],
        )

    print_section(
        "FINAL VERDICT",
        result.get("verdict"),
    )

    serialized = serialize_result(result)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            serialized,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print(f"[+] Full analysis saved to {output_path}")

    print(f"[+] Trace: traces/{result['run_id']}.jsonl")
    print(f"[+] Tokens: {result['telemetry']['total_tokens']}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
