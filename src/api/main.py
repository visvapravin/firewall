from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from firewall.logging_config import configure_logging
from firewall.models import FirewallRule, PacketContext, RuleAction
from firewall.policy import FirewallPolicy
from firewall.rule_engine import FirewallEngine

configure_logging()
app = FastAPI(title="Virtualized Firewall Appliance", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _default_config_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "firewall.sample.yaml"


def _build_engine(config_path: Optional[Path] = None) -> FirewallEngine:
    path = config_path or _default_config_path()
    policy = FirewallPolicy.from_file(path)
    return FirewallEngine(policy)


CONFIG_PATH = _default_config_path()
engine = _build_engine(CONFIG_PATH)


class EvaluateRequest(BaseModel):
    source_ip: str
    destination: str
    protocol: str
    destination_port: int


class RuleRequest(BaseModel):
        id: str = Field(min_length=1)
        source_cidr: str
        destination: str
        protocol: str
        destination_port: int
        action: RuleAction
        description: str = ""


class DefaultActionRequest(BaseModel):
        action: RuleAction


def _persist_policy() -> None:
        engine.policy.save_to_file(CONFIG_PATH)


def _build_rule(payload: RuleRequest) -> FirewallRule:
        return FirewallRule(
                id=payload.id,
                source_cidr=payload.source_cidr,
                destination=payload.destination,
                protocol=payload.protocol.lower(),
                destination_port=payload.destination_port,
                action=payload.action,
                description=payload.description,
        )


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
        return """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Virtual Firewall Dashboard</title>
    <style>
        :root { --bg:#f4f7f8; --card:#ffffff; --ink:#1d2a34; --accent:#0d6e6e; --line:#d8e0e3; }
        body { margin:0; background:radial-gradient(circle at top right,#d9efef,#f4f7f8); font-family:"Segoe UI",Tahoma,sans-serif; color:var(--ink); }
        .wrap { max-width:980px; margin:24px auto; padding:0 16px; }
        .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; margin-bottom:14px; box-shadow:0 8px 20px rgba(0,0,0,.05); }
        h1 { margin:0 0 8px; }
        .grid { display:grid; gap:10px; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); }
        label { display:block; font-size:12px; font-weight:600; margin-bottom:4px; }
        input, select, button, textarea { width:100%; box-sizing:border-box; border:1px solid var(--line); border-radius:8px; padding:9px; font-size:14px; }
        button { background:var(--accent); color:#fff; border:none; cursor:pointer; }
        button:hover { filter:brightness(.95); }
        pre { margin:0; overflow:auto; background:#0f1720; color:#cfe4ff; padding:12px; border-radius:8px; }
    </style>
</head>
<body>
<div class="wrap">
    <div class="card"><h1>Virtual Firewall Dashboard</h1><div id="status">Loading...</div></div>
    <div class="card">
        <h3>Evaluate Packet</h3>
        <div class="grid">
            <div><label>Source IP</label><input id="eSource" value="10.10.20.15" /></div>
            <div><label>Destination</label><input id="eDest" value="203.0.113.10" /></div>
            <div><label>Protocol</label><input id="eProto" value="tcp" /></div>
            <div><label>Port</label><input id="ePort" type="number" value="443" /></div>
        </div>
        <p><button onclick="evaluatePacket()">Evaluate</button></p>
        <pre id="evalOut"></pre>
    </div>
    <div class="card">
        <h3>Create or Update Rule</h3>
        <div class="grid">
            <div><label>Rule ID</label><input id="rId" placeholder="allow-demo" /></div>
            <div><label>Source CIDR</label><input id="rSrc" value="10.10.0.0/16" /></div>
            <div><label>Destination</label><input id="rDst" value="web-1.internal" /></div>
            <div><label>Protocol</label><input id="rPr" value="tcp" /></div>
            <div><label>Port</label><input id="rPo" type="number" value="443" /></div>
            <div><label>Action</label><select id="rAc"><option value="allow">allow</option><option value="deny">deny</option></select></div>
            <div style="grid-column:1/-1"><label>Description</label><textarea id="rDe">Live rule from dashboard</textarea></div>
        </div>
        <p><button onclick="saveRule()">Save Rule</button></p>
    </div>
    <div class="card">
        <h3>Delete Rule</h3>
        <div class="grid"><div><label>Rule ID</label><input id="dId" placeholder="allow-demo" /></div></div>
        <p><button onclick="deleteRule()">Delete Rule</button></p>
    </div>
    <div class="card">
        <h3>Current Policy</h3>
        <p><button onclick="loadPolicy()">Refresh Policy</button></p>
        <pre id="policyOut"></pre>
    </div>
</div>
<script>
    async function api(path, method='GET', body=null) {
        const options = { method, headers: { 'Content-Type': 'application/json' } };
        if (body) options.body = JSON.stringify(body);
        const r = await fetch(path, options);
        const data = await r.json();
        if (!r.ok) throw new Error(JSON.stringify(data));
        return data;
    }
    function print(id, data) { document.getElementById(id).textContent = JSON.stringify(data, null, 2); }
    async function loadHealth() { const health = await api('/health'); document.getElementById('status').textContent = 'API: ' + health.status; }
    async function loadPolicy() { print('policyOut', await api('/policy')); }
    async function evaluatePacket() {
        const body = {
            source_ip: document.getElementById('eSource').value,
            destination: document.getElementById('eDest').value,
            protocol: document.getElementById('eProto').value,
            destination_port: Number(document.getElementById('ePort').value)
        };
        print('evalOut', await api('/rules/evaluate', 'POST', body));
    }
    async function saveRule() {
        const body = {
            id: document.getElementById('rId').value,
            source_cidr: document.getElementById('rSrc').value,
            destination: document.getElementById('rDst').value,
            protocol: document.getElementById('rPr').value,
            destination_port: Number(document.getElementById('rPo').value),
            action: document.getElementById('rAc').value,
            description: document.getElementById('rDe').value
        };
        await api('/rules', 'POST', body);
        await loadPolicy();
    }
    async function deleteRule() {
        const ruleId = document.getElementById('dId').value;
        await api('/rules/' + encodeURIComponent(ruleId), 'DELETE');
        await loadPolicy();
    }
    loadHealth().then(loadPolicy).catch(err => { document.getElementById('status').textContent = err.message; });
</script>
</body>
</html>
"""


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "virtual-firewall"}


@app.get("/rules")
def list_rules() -> dict[str, object]:
    return {"count": len(engine.list_rules()), "rules": engine.list_rules()}


@app.get("/policy")
def get_policy() -> dict[str, object]:
    data = engine.policy.to_dict()
    data["rule_count"] = len(engine.policy.rules)
    return data


@app.put("/policy/default-action")
def update_default_action(request: DefaultActionRequest) -> dict[str, str]:
    engine.policy.set_default_action(request.action)
    _persist_policy()
    return {"status": "updated", "default_action": request.action.value}


@app.post("/rules")
def create_or_update_rule(request: RuleRequest) -> dict[str, object]:
    status = engine.policy.upsert_rule(_build_rule(request))
    _persist_policy()
    return {"status": status, "rule": engine.policy.rule_to_dict(_build_rule(request))}


@app.put("/rules/{rule_id}")
def replace_rule(rule_id: str, request: RuleRequest) -> dict[str, object]:
    if rule_id != request.id:
        raise HTTPException(status_code=400, detail="Path rule_id must match request id")

    status = engine.policy.upsert_rule(_build_rule(request))
    _persist_policy()
    return {"status": status, "rule": engine.policy.rule_to_dict(_build_rule(request))}


@app.delete("/rules/{rule_id}")
def remove_rule(rule_id: str) -> dict[str, str]:
    deleted = engine.policy.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")

    _persist_policy()
    return {"status": "deleted", "rule_id": rule_id}


@app.post("/policy/reload")
def reload_policy() -> dict[str, str]:
    global engine
    engine = _build_engine(CONFIG_PATH)
    return {"status": "reloaded"}


@app.post("/rules/evaluate")
def evaluate_packet(request: EvaluateRequest) -> dict[str, object]:
    packet = PacketContext(
        source_ip=request.source_ip,
        destination=request.destination,
        protocol=request.protocol,
        destination_port=request.destination_port,
    )
    return engine.evaluate(packet)
