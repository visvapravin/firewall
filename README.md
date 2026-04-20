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

## Dashboard Walkthrough

Open the dashboard in a browser at `http://127.0.0.1:8000/` on your laptop, or `http://<laptop-ip>:8000/` from a phone on the same Wi-Fi.

### 1. Check the API status

At the top of the page you will see the API status.

- If it shows `API: ok`, the backend is running.
- If it shows an error, start the server again with:
   - `py -3 -m uvicorn --app-dir src api.main:app --host 0.0.0.0 --port 8000 --reload`

### 2. Evaluate a packet

Use this section to test whether traffic is allowed or denied.

Enter the following values:

- Source IP: the client IP that is trying to connect, for example `10.10.20.15`
- Destination: the public IP before NAT, for example `203.0.113.10`
- Protocol: usually `tcp`
- Port: the service port, for example `443`

Click `Evaluate`.

The result shows:

- `decision`: `allow` or `deny`
- `matched_rule`: the rule that matched, if any
- `translated_destination`: the internal host after NAT
- `segment`: the internal network segment

Example to show in class:

- Source IP: `10.10.20.15`
- Destination: `203.0.113.10`
- Protocol: `tcp`
- Port: `443`

Expected result: `allow`

### 3. Create or update a rule

Use this section when you want to change firewall behavior live.

Enter the following fields:

- Rule ID: a unique name such as `allow-staff-wifi-https`
- Source CIDR: the allowed network range, for example `192.168.1.0/24`
- Destination: the internal destination name, for example `web-1.internal`
- Protocol: `tcp` or `udp`
- Port: the port to allow or block, for example `443`
- Action: `allow` or `deny`
- Description: a short note explaining the rule

Click `Save Rule`.

If the Rule ID already exists, the rule is updated. If it does not exist, a new rule is created.

### 4. Delete a rule

Use this section to remove a rule that is no longer needed.

- Enter the Rule ID exactly as it was created.
- Click `Delete Rule`.

### 5. Refresh and review the policy

Click `Refresh Policy` to see the latest rules currently loaded in the firewall.

This is useful after:

- Creating a new rule
- Updating an existing rule
- Deleting a rule
- Reloading policy from disk

### 6. Simple live demo flow

Use this sequence when presenting to staff or in class:

1. Open the dashboard.
2. Show the API status is healthy.
3. Evaluate a trusted client IP and show `allow`.
4. Evaluate an untrusted IP and show `deny`.
5. Add a new rule live.
6. Re-run the same packet and show the result changed.
7. Refresh the policy so everyone can see the change is saved.

### 7. Good example values to type

For a staff Wi-Fi rule:

- Rule ID: `allow-staff-wifi-https`
- Source CIDR: `192.168.1.0/24`
- Destination: `web-1.internal`
- Protocol: `tcp`
- Port: `443`
- Action: `allow`
- Description: `Allow staff Wi-Fi clients to web app over HTTPS`

For a single-IP allow rule:

- Rule ID: `allow-only-my-ip`
- Source CIDR: `192.168.1.39/32`
- Destination: `web-1.internal`
- Protocol: `tcp`
- Port: `443`
- Action: `allow`
- Description: `Allow only one laptop IP`

### 8. What the dashboard is demonstrating

The dashboard is not just a form. It shows a real firewall workflow:

- Policy is loaded from YAML
- NAT translates public destinations to internal services
- Source CIDR is matched against the client IP
- Protocol and port are checked
- The first matching rule decides the result
- If no rule matches, the default action is applied

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
