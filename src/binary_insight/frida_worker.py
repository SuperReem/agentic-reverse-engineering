"""Isolated Frida runner; the parent enforces a hard wall-clock deadline."""

import json
import sys
import threading
from pathlib import Path

HOOK = r"""
const target = TARGET;
const module = Process.mainModule;
let address;
if (target.offset !== undefined) {
  address = module.base.add(target.offset);
} else {
  const symbol = module.enumerateSymbols().find(s =>
    s.type === 'function' && (s.name === target.name || s.name === '_' + target.name));
  if (!symbol) throw new Error('Selected function symbol not found in main executable');
  address = symbol.address;
}
const range = Process.findRangeByAddress(address);
if (address.compare(module.base) < 0 || address.compare(module.base.add(module.size)) >= 0 ||
    !range || !range.protection.includes('x')) throw new Error('Target is not executable main-module code');
let calls = 0;
Interceptor.attach(address, {
  onEnter(args) {
    this.id = ++calls;
    if (this.id <= 50) send({kind:'enter', call_id:this.id, thread_id:this.threadId,
      raw_argument_slots:[args[0].toString(), args[1].toString(), args[2].toString(), args[3].toString()]});
    if (this.id === 51) send({kind:'truncated', message:'Only first 50 calls recorded'});
  },
  onLeave(value) {
    if (this.id <= 50) send({kind:'leave', call_id:this.id, raw_return:value.toString()});
  }
});
Interceptor.flush();
send({kind:'ready', address:address.toString(), module:module.name});
"""


def trace(request):
    import frida

    result = {"status": "error", "events": [], "stdout": "", "stderr": ""}
    device = frida.get_local_device()
    pid = None
    session = None
    ready = threading.Event()
    finished = threading.Event()

    def output(process_id, fd, data):
        if process_id == pid:
            key = "stdout" if fd == 1 else "stderr"
            result[key] = (result[key] + data.decode(errors="replace"))[:8000]

    def message(msg, data):
        if msg["type"] == "send":
            event = msg["payload"]
            if len(result["events"]) < 102:
                result["events"].append(event)
            if event.get("kind") == "ready":
                ready.set()
        elif msg["type"] == "error":
            result["error"] = msg.get("description", "Hook script failed")
            ready.set()

    def detached(reason, crash=None):
        result["termination"] = reason
        finished.set()

    try:
        device.on("output", output)
        pid = device.spawn([request["binary"], *request["arguments"]], stdio="pipe")
        Path(request["pid_file"]).write_text(str(pid))
        # Close stdin so command-line programs cannot wait indefinitely for input.
        device.input(pid, b"")
        session = device.attach(pid)
        session.on("detached", detached)
        script = session.create_script(HOOK.replace("TARGET", json.dumps(request["target"]), 1))
        script.on("message", message)
        script.load()
        if not ready.wait(2) or "error" in result:
            raise RuntimeError(result.get("error", "Hook did not become ready"))
        device.resume(pid)
        result["timed_out"] = not finished.wait(request["timeout"])
        result["status"] = "observed" if any(e["kind"] == "enter" for e in result["events"]) else "not_observed"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if pid is not None:
            try:
                device.kill(pid)
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
    return result


if __name__ == "__main__":
    print(json.dumps(trace(json.load(sys.stdin))))
