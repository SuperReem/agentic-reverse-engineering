from __future__ import annotations

import os
import subprocess
from pathlib import Path
import platform
import re
import signal
import tempfile
import json
import sys
import struct
import importlib.util

from .telemetry import BudgetExceeded, traced_tool

MAX_STATIC_OUTPUT = 40_000
MAX_DYNAMIC_OUTPUT = 20_000


class ToolError(RuntimeError):
    pass


def validate_binary(binary_path: str) -> str:
    """
    Resolve and validate a binary path.
    """

    path = Path(binary_path).expanduser().resolve()

    if not path.exists():
        raise ToolError(f"Binary does not exist: {path}")

    if not path.is_file():
        raise ToolError(f"Not a file: {path}")

    return str(path)


@traced_tool
def run_command(
    args: list[str],
    timeout: int = 30,
    max_output: int = MAX_STATIC_OUTPUT,
) -> str:
    """
    Execute a fixed command without invoking a shell.
    """

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )

    except FileNotFoundError as exc:
        raise ToolError(f"Required command not found: {args[0]}") from exc

    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Command timed out: {' '.join(args)}") from exc

    output = (
        f"COMMAND: {' '.join(args)}\n"
        f"RETURN CODE: {result.returncode}\n\n"
        f"STDOUT:\n{result.stdout}\n\n"
        f"STDERR:\n{result.stderr}"
    )

    if len(output) > max_output:
        output = output[:max_output] + "\n\n[OUTPUT TRUNCATED]"

    return output


@traced_tool
def get_file_info(
    binary_path: str,
) -> str:

    binary_path = validate_binary(binary_path)

    return run_command(
        [
            "file",
            binary_path,
        ],
        max_output=5_000,
    )


@traced_tool
def get_strings(
    binary_path: str,
) -> str:

    binary_path = validate_binary(binary_path)

    return run_command(
        [
            "strings",
            "-n",
            "4",
            binary_path,
        ],
        max_output=20_000,
    )


@traced_tool
def get_symbols(
    binary_path: str,
) -> str:

    binary_path = validate_binary(binary_path)

    return run_command(
        [
            "nm",
            "-C",
            binary_path,
        ],
        max_output=20_000,
    )


@traced_tool
def list_functions(binary_path: str) -> list[str]:
    """List defined text symbols without executing the binary."""
    binary_path = validate_binary(binary_path)
    try:
        result = subprocess.run(
            ["nm", "--defined-only", binary_path] if platform.system() != "Darwin" else ["nm", binary_path],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"Cannot read function symbols: {exc}") from exc
    if result.returncode:
        raise ToolError(result.stderr.strip() or "Could not read binary symbols.")
    functions = set()
    for line in result.stdout.splitlines():
        parts = line.strip().split(maxsplit=2)
        if len(parts) != 3 or parts[1] not in ("T", "t", "W", "w"):
            continue
        name = parts[2]
        if name == "__mh_execute_header":
            continue
        if platform.system() == "Darwin" and name.startswith("_"):
            name = name[1:]
        functions.add(name)
    if functions:
        return sorted(functions)
    starts = get_macho_function_starts(binary_path)
    return [f"sub_{address:x}" for address in starts]


@traced_tool
def get_macho_function_starts(binary_path: str) -> list[int]:
    """Recover Mach-O function boundaries from metadata, without guessing names."""
    with open(binary_path, "rb") as file:
        magic = file.read(4)
    if magic not in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return []
    output = run_command(["objdump", "--macho", "--function-starts", binary_path])
    return sorted(
        {int(line.strip(), 16) for line in output.splitlines() if re.fullmatch(r"[0-9a-fA-F]{8,16}", line.strip())}
    )


@traced_tool
def get_disassembly(
    binary_path: str,
) -> str:

    binary_path = validate_binary(binary_path)

    return run_command(
        [
            "objdump",
            "-d",
            "-M",
            "intel",
            binary_path,
        ],
        timeout=60,
        max_output=MAX_STATIC_OUTPUT,
    )


@traced_tool
def get_function_disassembly(
    binary_path: str,
    function_name: str,
) -> str:

    binary_path = validate_binary(binary_path)

    if re.fullmatch(r"sub_[0-9a-fA-F]+", function_name):
        start = int(function_name[4:], 16)
        starts = get_macho_function_starts(binary_path)
        if start not in starts:
            raise ToolError("Selected address is not a known function start.")
        index = starts.index(start)
        if index + 1 < len(starts):
            stop = starts[index + 1]
        else:
            sections = run_command(["objdump", "-h", binary_path])
            match = re.search(r"^\s*\d+\s+__text\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", sections, re.MULTILINE)
            if not match:
                raise ToolError("Could not determine the final function boundary.")
            stop = int(match[1], 16) + int(match[2], 16)
        return run_command(
            ["objdump", "-d", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}", binary_path],
            max_output=20_000,
        )

    if platform.system() == "Darwin":
        # Mach-O C symbols normally have a leading "_".
        symbol = function_name

        if not symbol.startswith("_"):
            symbol = "_" + symbol

        return run_command(
            [
                "objdump",
                f"--disassemble-symbols={symbol}",
                binary_path,
            ],
            timeout=30,
            max_output=20_000,
        )

    # Linux / GNU objdump
    return run_command(
        [
            "objdump",
            "-d",
            "-M",
            "intel",
            f"--disassemble={function_name}",
            binary_path,
        ],
        timeout=30,
        max_output=20_000,
    )


@traced_tool
def run_binary(
    binary_path: str,
    arguments: list[str] | None = None,
    timeout: int = 5,
) -> str:
    """
    Execute a test binary.

    IMPORTANT:
    Use this only for binaries you trust in V0.

    For unknown/untrusted binaries, replace this
    function with a VM/container/sandbox backend.
    """

    binary_path = validate_binary(binary_path)

    arguments = arguments or []

    if not os.access(
        binary_path,
        os.X_OK,
    ):
        raise ToolError(f"Binary is not executable: {binary_path}")

    try:
        # File-backed output prevents inherited pipes in child processes from
        # keeping communicate() blocked after the parent has been killed.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                [binary_path, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=os.name == "posix",
            )
            timed_out = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                # Clean up descendants too, even if the original process exited.
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    elif process.poll() is None:
                        process.kill()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired as exc:
                    raise ToolError("Binary could not be reaped after termination.") from exc
            stdout.seek(0)
            stderr.seek(0)
            out = stdout.read(MAX_DYNAMIC_OUTPUT).decode(errors="replace")
            err = stderr.read(MAX_DYNAMIC_OUTPUT).decode(errors="replace")
            status = f"RESULT: TIMEOUT after {timeout} seconds" if timed_out else f"RETURN CODE: {process.returncode}"
            return (f"ARGS: {arguments}\n{status}\nSTDOUT:\n{out}\nSTDERR:\n{err}")[:MAX_DYNAMIC_OUTPUT]

    except PermissionError as exc:
        raise ToolError(f"Permission denied executing {binary_path}") from exc


@traced_tool
def trace_function(
    binary_path: str, target_function: str, arguments: list[str] | None = None, timeout: int = 5
) -> dict:
    """Trace a selected function using a fixed Frida hook, never model-supplied code."""
    binary_path = validate_binary(binary_path)
    if os.getenv("FRIDA_ENABLED", "1") == "0" or importlib.util.find_spec("frida") is None:
        return {"status": "unavailable", "error": "Frida disabled or not installed"}
    target = {"name": target_function}
    if re.fullmatch(r"sub_[0-9a-fA-F]+", target_function):
        # UI-generated stripped Mach-O labels are preferred virtual addresses;
        # convert to a module-relative offset before Frida applies ASLR.
        try:
            address = int(target_function[4:], 16)
            if address not in get_macho_function_starts(binary_path):
                raise ValueError("Unknown function address")
            with open(binary_path, "rb") as file:
                header = file.read(32)
                magic = header[:4]
                endian = "<" if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else ">"
                is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
                file.seek(32 if is64 else 28)
                for _ in range(struct.unpack_from(endian + "I", header, 16)[0]):
                    command = file.read(8)
                    kind, size = struct.unpack(endian + "II", command)
                    if size < 8:
                        raise ValueError("Invalid Mach-O load command")
                    payload = file.read(size - 8)
                    if kind in (1, 25) and payload[:16].rstrip(b"\0") == b"__TEXT":
                        base = struct.unpack_from(endian + ("Q" if kind == 25 else "I"), payload, 16)[0]
                        target = {"offset": hex(address - base)}
                        break
                else:
                    raise ValueError("No __TEXT segment")
        except (OSError, ValueError, struct.error) as exc:
            return {"status": "error", "error": str(exc)}
    with tempfile.TemporaryDirectory(prefix="binary-frida-") as directory:
        pid_file = Path(directory) / "pid"
        request = {
            "binary": binary_path,
            "target": target,
            "arguments": arguments or [],
            "timeout": timeout,
            "pid_file": str(pid_file),
        }
        process = subprocess.Popen(
            [sys.executable, "-m", "binary_insight.frida_worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
        )
        try:
            out, err = process.communicate(json.dumps(request).encode(), timeout=timeout + 5)
            if process.returncode:
                return {"status": "error", "error": err.decode(errors="replace")[:2000]}
            return json.loads(out)
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Frida exceeded hard deadline"}
        except (ValueError, OSError) as exc:
            return {"status": "error", "error": str(exc)}
        finally:
            if process.poll() is None:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=1)
                # Frida's target may live outside the worker's process group.
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text()), signal.SIGKILL)
                    except (ProcessLookupError, ValueError):
                        pass


@traced_tool
def run_dynamic_test(binary_path: str, target_function: str, arguments: list[str] | None = None) -> str:
    trace = trace_function(binary_path, target_function, arguments)
    evidence = "FRIDA TRACE: " + json.dumps(trace)
    if trace["status"] in ("observed", "not_observed"):
        return f"ARGS: {arguments or []}\n{evidence}"
    return evidence + "\nFALLBACK PROCESS EXECUTION (separate run):\n" + run_binary(binary_path, arguments)


@traced_tool
def execute_test_plan(
    binary_path: str,
    test_plan,
    progress=None,
    target_function: str | None = None,
) -> str:
    """
    Execute tests selected by the Dynamic Agent.

    The agent chooses arguments, but it cannot
    choose arbitrary shell commands.
    """

    observations = []

    for index, test in enumerate(
        test_plan.tests,
        start=1,
    ):
        if progress:
            progress(index, len(test_plan.tests))

        try:
            result = (
                run_dynamic_test(binary_path, target_function, test.arguments)
                if target_function
                else run_binary(binary_path, test.arguments)
            )

        except BudgetExceeded:
            raise

        except Exception as exc:
            result = f"ERROR: {type(exc).__name__}: {exc}"

        observation = f"""
            TEST {index}
            ======

            Reason:
            {test.reason}

            Arguments:
            {test.arguments}

            Result:
            {result}
            """

        observations.append(observation)

    return "\n\n".join(observations)
