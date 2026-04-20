from pathlib import Path

from fastapi.testclient import TestClient

import api.main as api_main


def _reset_engine_to_temp_policy(tmp_path: Path) -> None:
    source = Path("config/firewall.sample.yaml")
    target = tmp_path / "firewall.test.yaml"
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    api_main.CONFIG_PATH = target
    api_main.engine = api_main._build_engine(target)


def test_dashboard_page_renders() -> None:
    client = TestClient(api_main.app)
    response = client.get("/")

    assert response.status_code == 200
    assert "Virtual Firewall Dashboard" in response.text


def test_create_and_delete_rule_persists(tmp_path: Path) -> None:
    _reset_engine_to_temp_policy(tmp_path)
    client = TestClient(api_main.app)

    create_response = client.post(
        "/rules",
        json={
            "id": "allow-lab-demo",
            "source_cidr": "172.16.0.0/16",
            "destination": "web-1.internal",
            "protocol": "tcp",
            "destination_port": 443,
            "action": "allow",
            "description": "Temporary lab access",
        },
    )

    assert create_response.status_code == 200
    assert create_response.json()["status"] == "created"

    policy_response = client.get("/policy")
    assert policy_response.status_code == 200
    assert any(rule["id"] == "allow-lab-demo" for rule in policy_response.json()["rules"])

    delete_response = client.delete("/rules/allow-lab-demo")
    assert delete_response.status_code == 200

    policy_after_delete = client.get("/policy").json()
    assert not any(rule["id"] == "allow-lab-demo" for rule in policy_after_delete["rules"])
