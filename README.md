# Virtualized Firewall Appliance

This project provides a starter implementation of a virtualized firewall appliance focused on securing internal web application servers.

## Objectives

- Enforce network segmentation between external traffic and internal tiers.
- Apply rule-based packet filtering with default deny.
- Simulate destination NAT from public IP/ports to internal services.
- Expose a management API for rule inspection and packet decision simulation.

## Architecture

- `src/firewall`: Policy model and packet decision engine.
- `src/api`: FastAPI service for health checks, rule listing, and packet evaluation.
- `config/firewall.sample.yaml`: Declarative firewall rules, segments, and NAT map.
- `docker-compose.yml`: Simulation stack for firewall and internal web servers.

## Threat Model (Baseline)

- Unauthorized external access to internal web and data services.
- Lateral movement attempts from untrusted source ranges.
- Overly permissive ingress policy due to missing deny-first controls.

## Quick Start

1. Create and activate a Python 3.12+ virtual environment.
2. Install dependencies:
   - `pip install -r requirements.txt`
3. Set path for imports:
   - PowerShell: `$env:PYTHONPATH = "src"`
4. Run API:
   - `uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload`
5. Open health endpoint:
   - `http://127.0.0.1:8000/health`

## API Endpoints

- `GET /health`: Service status.
- `GET /rules`: Active firewall rules from policy.
- `POST /rules/evaluate`: Evaluate a simulated packet decision.
- `GET /policy`: Full editable policy snapshot.
- `POST /rules`: Create or update a rule by id and persist to YAML.
- `DELETE /rules/{rule_id}`: Delete a rule and persist to YAML.
- `PUT /policy/default-action`: Change default action (allow/deny).
- `POST /policy/reload`: Reload policy from disk.
- `GET /`: Browser dashboard for live testing and edits.

Sample request body:

```json
{
  "source_ip": "10.10.20.15",
  "destination": "203.0.113.10",
  "protocol": "tcp",
  "destination_port": 443
}
```

## Validation

- Syntax compile: `python -m compileall src tests`
- Unit tests: `pytest -q`
- Container simulation: `docker compose up --build`

## Live Demo with Mobile Phones

1. Start API with host binding for LAN:
   - `py -3 -m uvicorn --app-dir src api.main:app --host 0.0.0.0 --port 8000 --reload`
2. Find your laptop IPv4 (PowerShell):
   - `ipconfig`
3. Ensure phone and laptop are on same Wi-Fi.
4. Open on phone browser:
   - `http://<laptop-ip>:8000/`
5. From dashboard, create or edit rules live, then run Evaluate.

If phone cannot reach API, allow inbound port 8000 in Windows Firewall and retry.

## Deploy on Render

1. Push this project to a GitHub repository.
2. Sign in to Render and choose New +, then Blueprint.
3. Select your GitHub repo. Render will detect `render.yaml`.
4. Click Apply to create the service.
5. Wait for build and deploy to finish.
6. Open the generated Render URL.

Expected URL examples:

- `https://virtual-firewall.onrender.com/`
- `https://virtual-firewall.onrender.com/docs`

Important notes for viva/demo:

- Rule edits are saved to the service filesystem.
- On free tier, the filesystem is ephemeral, so policy edits may reset after service restart.
- For persistent edits, attach a persistent disk or store policy in a database.

## Notes

This is a development baseline that simulates policy decisions. To evolve into a production-grade virtual appliance, integrate with host-level packet filters (for example nftables), hardened base images, authenticated control plane endpoints, and centralized telemetry.
