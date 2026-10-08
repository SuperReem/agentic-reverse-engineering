import json
import sys
from types import SimpleNamespace

from binary_insight import frida_worker, tools


def test_unavailable_frida_falls_back_once(monkeypatch, binary):
    monkeypatch.setenv("FRIDA_ENABLED", "0")
    calls = []
    monkeypatch.setattr(tools, "run_binary", lambda *args: calls.append(args) or "PROCESS OUTPUT")
    output = tools.run_dynamic_test(binary, "main", ["hello"])
    assert '"status": "unavailable"' in output
    assert "PROCESS OUTPUT" in output
    assert calls == [(binary, ["hello"])]


def test_successful_trace_does_not_execute_twice(monkeypatch, binary):
    monkeypatch.setattr(tools, "trace_function", lambda *args: {"status": "observed", "events": [{"kind": "enter"}]})
    monkeypatch.setattr(tools, "run_binary", lambda *args: (_ for _ in ()).throw(AssertionError("Duplicate execution")))
    assert '"status": "observed"' in tools.run_dynamic_test(binary, "main", [])


def test_worker_hooks_before_resume_and_cleans_up(monkeypatch, tmp_path):
    actions = []

    class Script:
        def on(self, event, callback):
            self.message = callback

        def load(self):
            actions.append("hook")
            self.message({"type": "send", "payload": {"kind": "ready"}}, None)
            self.message({"type": "send", "payload": {"kind": "enter", "call_id": 1}}, None)

    class Session:
        def on(self, event, callback):
            self.detached = callback

        def create_script(self, source):
            assert '"offset": "0x123"' in source
            return Script()

        def detach(self):
            actions.append("detach")

    session = Session()

    class Device:
        def on(self, *args):
            pass

        def spawn(self, argv, stdio):
            assert argv == ["/sample", "a"] and stdio == "pipe"
            return 123

        def input(self, *args):
            pass

        def attach(self, pid):
            return session

        def resume(self, pid):
            actions.append("resume")
            session.detached("process-terminated")

        def kill(self, pid):
            actions.append("kill")

    monkeypatch.setitem(sys.modules, "frida", SimpleNamespace(get_local_device=lambda: Device()))
    result = frida_worker.trace(
        {
            "binary": "/sample",
            "arguments": ["a"],
            "target": {"offset": "0x123"},
            "timeout": 1,
            "pid_file": str(tmp_path / "pid"),
        }
    )
    assert result["status"] == "observed"
    assert not result["timed_out"]
    assert actions == ["hook", "resume", "kill", "detach"]
    assert json.loads(json.dumps(result))["events"][1]["call_id"] == 1


def test_hard_deadline_kills_worker_and_spawned_target(monkeypatch, binary):
    import subprocess

    monkeypatch.setenv("FRIDA_ENABLED", "1")
    monkeypatch.setattr(tools.importlib.util, "find_spec", lambda name: object())
    killed = []

    class Worker:
        pid = 555
        returncode = None

        def communicate(self, payload, timeout):
            request = json.loads(payload)
            assert timeout == 6
            from pathlib import Path

            Path(request["pid_file"]).write_text("777")
            raise subprocess.TimeoutExpired("frida", timeout)

        def poll(self):
            return None

        def wait(self, timeout):
            killed.append("reaped")

    monkeypatch.setattr(tools.subprocess, "Popen", lambda *args, **kwargs: Worker())
    monkeypatch.setattr(tools.os, "killpg", lambda pid, sig: killed.append(pid))
    monkeypatch.setattr(tools.os, "kill", lambda pid, sig: killed.append(pid))
    result = tools.trace_function(binary, "main", timeout=1)
    assert result["status"] == "error" and "deadline" in result["error"]
    assert killed == [555, "reaped", 777]
