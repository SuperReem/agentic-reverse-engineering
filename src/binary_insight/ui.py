"""Local dashboard: binary-insight, then open http://127.0.0.1:8080."""

from __future__ import annotations

import argparse
import json
import threading
import tempfile
import uuid
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .settings import ROOT, WEB
from .engine import execute_analysis, AnalysisFailure
from .telemetry import RunObserver

lock = threading.Lock()
job = {
    "status": "idle",
    "stages": [],
    "result": None,
    "error": None,
    "progress": {},
    "started_at": None,
    "telemetry": None,
    "run_id": None,
    "trace": [],
}
uploads = tempfile.TemporaryDirectory(prefix="binary-insight-")
MAX_UPLOAD = 50 * 1024 * 1024
HISTORY = ROOT / "analysis_history"


def save_history(result: dict) -> str:
    HISTORY.mkdir(exist_ok=True)
    entry_id = uuid.uuid4().hex
    entry = {
        "id": entry_id,
        "binary_name": result.get("binary_name") or Path(result["binary_path"]).name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": result,
    }
    temporary = HISTORY / f"{entry_id}.tmp"
    temporary.write_text(json.dumps(entry, indent=2, ensure_ascii=False))
    temporary.replace(HISTORY / f"{entry_id}.json")
    return entry_id


def history_entries() -> list[dict]:
    entries = []
    for path in HISTORY.glob("*.json"):
        try:
            entry = json.loads(path.read_text())
            entries.append({key: entry[key] for key in ("id", "binary_name", "timestamp")})
            entries[-1]["target"] = entry["result"].get("target_function", "")
            entries[-1]["status"] = entry["result"].get("run_status", "complete")
        except (OSError, ValueError, KeyError, TypeError):
            continue
    saved = ROOT / "analysis.json"
    try:
        result = json.loads(saved.read_text())
        entries.append(
            {
                "id": "saved",
                "binary_name": Path(result.get("binary_path", "binary")).name,
                "target": result.get("target_function", ""),
                "timestamp": datetime.fromtimestamp(saved.stat().st_mtime, timezone.utc).isoformat(),
                "timestamp_source": "file_modified",
            }
        )
    except (OSError, ValueError, TypeError):
        pass
    return sorted(entries, key=lambda entry: entry["timestamp"], reverse=True)


def save_upload(content: bytes) -> str:
    if not content or len(content) > MAX_UPLOAD:
        raise ValueError("Choose a binary smaller than 50 MB.")
    signatures = (
        b"\x7fELF",
        b"MZ",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    )
    if not content.startswith(signatures):
        raise ValueError("Choose a compiled executable (ELF, Mach-O, or PE).")
    path = Path(uploads.name) / uuid.uuid4().hex / "binary"
    path.parent.mkdir(mode=0o700)
    path.write_bytes(content)
    path.chmod(0o700)
    return str(path)


def analyze(binary: str, target: str, binary_name: str):
    def telemetry_update(entry, metrics):
        with lock:
            job["telemetry"] = metrics
            job["run_id"] = metrics["run_id"]
            job["trace"].append(
                {
                    key: entry.get(key)
                    for key in (
                        "sequence",
                        "timestamp",
                        "event",
                        "kind",
                        "stage",
                        "name",
                        "status",
                        "duration_ms",
                        "reason",
                        "error",
                    )
                }
            )

    def update(mode, event, state):
        with lock:
            if mode == "custom":
                job["progress"][event["stage"]] = event["message"]
            else:
                job["stages"].extend(event.keys())
                job["result"] = state

    try:
        observer = RunObserver(on_update=telemetry_update)
        result = execute_analysis(binary, target, binary_name, observer, update)
        save_history(result)
        with lock:
            job.update(status="complete", result=result)
    except AnalysisFailure as exc:
        result = exc.result
        try:
            save_history(result)
        except OSError:
            pass
        with lock:
            job.update(status="error", result=result, error=f"{type(exc.cause).__name__}: {exc}")
    except Exception as exc:
        with lock:
            job.update(status="error", error=f"{type(exc).__name__}: {exc}")


class Handler(BaseHTTPRequestHandler):
    def send(self, status, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/traces/"):
            run_id = self.path.removeprefix("/api/traces/")
            if len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
                self.send(404, {"error": "Trace not found"})
                return
            try:
                self.send(200, (ROOT / "traces" / f"{run_id}.jsonl").read_bytes(), "application/x-ndjson")
            except OSError:
                self.send(404, {"error": "Trace not found"})
        elif self.path == "/api/history":
            self.send(200, {"entries": history_entries()})
        elif self.path.startswith("/api/history/"):
            entry_id = self.path.removeprefix("/api/history/")
            if len(entry_id) != 32 or any(c not in "0123456789abcdef" for c in entry_id):
                self.send(404, {"error": "Analysis not found"})
                return
            try:
                self.send(200, json.loads((HISTORY / f"{entry_id}.json").read_text())["result"])
            except (OSError, ValueError, KeyError):
                self.send(404, {"error": "Analysis not found"})
        elif self.path == "/api/status":
            with lock:
                self.send(200, job)
        elif self.path == "/api/saved":
            try:
                self.send(200, json.loads((ROOT / "analysis.json").read_text()))
            except (OSError, ValueError):
                self.send(404, {"error": "No saved analysis available."})
        elif self.path in ("/", "/app.js", "/style.css"):
            name, mime = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript"),
                "/style.css": ("style.css", "text/css"),
            }[self.path]
            self.send(200, (WEB / name).read_bytes(), mime)
        else:
            self.send(404, {"error": "Not found"})

    def do_POST(self):
        # Only same-origin local browser requests may start binary execution.
        if self.headers.get("Origin") not in (None, f"http://{self.headers.get('Host')}"):
            self.send(403, {"error": "Invalid origin"})
            return
        if self.path == "/api/upload":
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 < length <= MAX_UPLOAD:
                    self.send(413, {"error": "Choose a binary smaller than 50 MB."})
                    return
                content = self.rfile.read(length)
                if len(content) != length:
                    raise ValueError("Upload was incomplete. Try again.")
                self.send(201, {"binary": save_upload(content)})
            except (ValueError, OSError) as exc:
                self.send(400, {"error": str(exc)})
            return
        if self.path not in ("/api/analyze", "/api/functions"):
            self.send(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            if not 0 < length <= 8192:
                raise ValueError("Invalid request size")
            data = json.loads(self.rfile.read(length))
            binary = data["binary"].strip()
            target = data.get("target", "").strip()
            binary_name = Path(data.get("binary_name", "binary").strip()).name[:255] or "binary"
            if not binary or (self.path == "/api/analyze" and not target):
                raise ValueError("Enter a binary path and target function.")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            self.send(400, {"error": str(exc)})
            return
        if self.path == "/api/functions":
            from .tools import list_functions, ToolError

            try:
                self.send(200, {"functions": list_functions(binary)})
            except ToolError as exc:
                self.send(400, {"error": str(exc)})
            return
        with lock:
            if job["status"] == "running":
                self.send(409, {"error": "An analysis is already running."})
                return
            job.update(
                status="running",
                stages=[],
                result=None,
                error=None,
                progress={},
                started_at=time.time(),
                telemetry=None,
                run_id=None,
                trace=[],
            )
        threading.Thread(target=analyze, args=(binary, target, binary_name), daemon=True).start()
        self.send(202, {"status": "running"})


def main():
    parser = argparse.ArgumentParser(description="Binary analysis dashboard")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    print(f"Dashboard: http://127.0.0.1:{args.port}")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
