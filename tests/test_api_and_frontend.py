import io
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_insight import ui


def handler(path, body=b"", **headers):
    request = ui.Handler.__new__(ui.Handler)
    request.path = path
    request.headers = {"Host": "127.0.0.1:8080", "Content-Length": str(len(body)), **headers}
    request.rfile = io.BytesIO(body)
    responses = []
    request.send = lambda *args: responses.append(args)
    return request, responses


def test_api_upload_and_function_discovery_without_execution(monkeypatch):
    request, responses = handler("/api/upload", b"\x7fELFfixture", Origin="http://127.0.0.1:8080")
    request.do_POST()
    assert responses[0][0] == 201
    binary = responses[0][1]["binary"]
    from binary_insight import tools

    monkeypatch.setattr(tools, "list_functions", lambda path: ["main"] if path == binary else [])
    request, responses = handler("/api/functions", json.dumps({"binary": binary}).encode())
    request.do_POST()
    assert responses[0] == (200, {"functions": ["main"]})


def test_cross_origin_upload_rejected():
    request, responses = handler("/api/upload", b"\x7fELFfixture", Origin="https://unrelated.example")
    request.do_POST()
    assert responses[0][0] == 403


def test_oversized_upload_rejected_without_reading_body():
    request, responses = handler("/api/upload", **{"Content-Length": str(ui.MAX_UPLOAD + 1)})
    request.do_POST()
    assert responses[0][0] == 413


@pytest.mark.parametrize("path", ["/api/history/../../.env", "/api/traces/../../.env"])
def test_artifact_paths_cannot_escape_directory(path):
    request, responses = handler(path)
    request.do_GET()
    assert responses[0][0] == 404


def test_history_and_trace_download(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "ROOT", tmp_path)
    monkeypatch.setattr(ui, "HISTORY", tmp_path / "analysis_history")
    result = {"binary_path": "/tmp/binary", "binary_name": "fixture", "target_function": "main", "run_id": "a" * 32}
    entry_id = ui.save_history(result)
    request, responses = handler(f"/api/history/{entry_id}")
    request.do_GET()
    assert responses[0] == (200, result)
    (tmp_path / "traces").mkdir()
    content = b'{"event":"run_start"}\n'
    (tmp_path / "traces" / f"{result['run_id']}.jsonl").write_bytes(content)
    request, responses = handler(f"/api/traces/{result['run_id']}")
    request.do_GET()
    assert responses[0] == (200, content, "application/x-ndjson")


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js required for browser-script checks")
def test_frontend_progress_trace_and_safe_verdict_rendering():
    root = Path(__file__).resolve().parents[1]
    subprocess.run(["node", "--check", str(root / "web/app.js")], check=True)
    script = r"""
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const nodes={};const make=()=>({hidden:false,innerHTML:'',textContent:'',attrs:{},addEventListener(){},setAttribute(k,v){this.attrs[k]=v},getAttribute(k){return this.attrs[k]},classList:{toggle(){}}});
const cards=['static','dynamic','judge','experiment'].map(name=>{const state=make();return {...make(),dataset:{stage:name},querySelector:()=>state,state}});
const document={getElementById:id=>nodes[id] ||= make(),querySelectorAll:()=>cards};
const context=vm.createContext({document,localStorage:{getItem:()=>null,setItem(){}},console});
vm.runInContext(fs.readFileSync('web/app.js','utf8').replace(/^loadHistory();$/m,''),context);
context.stages([],'running');assert.equal(cards[0].state.textContent,'Running');assert.equal(cards[2].state.textContent,'Waiting');
context.stages(['static','dynamic'],'running');assert.equal(cards[2].state.textContent,'Running');
context.renderTrace({run_id:'a'.repeat(32),total_tokens:250,model_calls:2,cost_usd:.005,cost_complete:true,per_agent:{}});
assert.equal(nodes['trace-controls'].hidden,false);
assert.equal(nodes['trace-download'].href,'/api/traces/'+ 'a'.repeat(32));
assert(!nodes['usage-cost'] && !nodes['usage-tokens'] && !nodes['usage-calls'] && !nodes['agent-usage']);
context.renderVerdict({status:'uncertain',confidence:.4,summary:{purpose:'<script>alert(1)</script>',inputs:'Unknown',behavior:'Comparison',outputs:'Unknown'},supporting_evidence:[],unresolved_points:['Attribution']},{target_function:'main'});
assert(!nodes['verdict-content'].innerHTML.includes('<script>'));assert(nodes['verdict-content'].innerHTML.includes('verdict-tiles'));
"""
    subprocess.run(["node", "-e", script], cwd=root, check=True)
