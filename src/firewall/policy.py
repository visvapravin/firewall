from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .models import FirewallRule, RuleAction


@dataclass
class FirewallPolicy:
    default_action: RuleAction = RuleAction.DENY
    rules: List[FirewallRule] = field(default_factory=list)
    nat_table: Dict[str, str] = field(default_factory=dict)
    segments: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_file(cls, file_path: str | Path) -> "FirewallPolicy":
        path = Path(file_path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        raw_rules = data.get("rules", [])
        rules = [
            FirewallRule(
                id=str(item["id"]),
                source_cidr=str(item["source_cidr"]),
                destination=str(item["destination"]),
                protocol=str(item["protocol"]).lower(),
                destination_port=int(item["destination_port"]),
                action=RuleAction(str(item.get("action", "deny")).lower()),
                description=str(item.get("description", "")),
            )
            for item in raw_rules
        ]

        return cls(
            default_action=RuleAction(str(data.get("default_action", "deny")).lower()),
            rules=rules,
            nat_table={str(k): str(v) for k, v in data.get("nat_table", {}).items()},
            segments={str(k): str(v) for k, v in data.get("segments", {}).items()},
        )

    @staticmethod
    def rule_to_dict(rule: FirewallRule) -> Dict[str, Any]:
        return {
            "id": rule.id,
            "source_cidr": rule.source_cidr,
            "destination": rule.destination,
            "protocol": rule.protocol,
            "destination_port": rule.destination_port,
            "action": rule.action.value,
            "description": rule.description,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "default_action": self.default_action.value,
            "segments": self.segments,
            "nat_table": self.nat_table,
            "rules": [self.rule_to_dict(rule) for rule in self.rules],
        }

    def save_to_file(self, file_path: str | Path) -> None:
        path = Path(file_path)
        path.write_text(
            yaml.safe_dump(self.to_dict(), sort_keys=False),
            encoding="utf-8",
        )

    def set_default_action(self, action: RuleAction) -> None:
        self.default_action = action

    def upsert_rule(self, rule: FirewallRule) -> str:
        for idx, existing in enumerate(self.rules):
            if existing.id == rule.id:
                self.rules[idx] = rule
                return "updated"

        self.rules.append(rule)
        return "created"

    def delete_rule(self, rule_id: str) -> bool:
        for idx, existing in enumerate(self.rules):
            if existing.id == rule_id:
                del self.rules[idx]
                return True

        return False
