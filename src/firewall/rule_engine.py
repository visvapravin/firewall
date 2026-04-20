from __future__ import annotations

import ipaddress
from typing import Dict, List

from .models import FirewallRule, PacketContext
from .policy import FirewallPolicy


class FirewallEngine:
    """Evaluates packet context against firewall policy with default deny."""

    def __init__(self, policy: FirewallPolicy) -> None:
        self.policy = policy

    def evaluate(self, packet: PacketContext) -> Dict[str, object]:
        translated_destination = self._apply_nat(packet.destination, packet.destination_port)
        segment = self.policy.segments.get(translated_destination, "unknown")

        for rule in self.policy.rules:
            if self._matches(rule, packet, translated_destination):
                return {
                    "decision": rule.action.value,
                    "matched_rule": self.policy.rule_to_dict(rule),
                    "translated_destination": translated_destination,
                    "segment": segment,
                }

        return {
            "decision": self.policy.default_action.value,
            "matched_rule": None,
            "translated_destination": translated_destination,
            "segment": segment,
        }

    def list_rules(self) -> List[Dict[str, object]]:
        return [self.policy.rule_to_dict(rule) for rule in self.policy.rules]

    def _apply_nat(self, destination: str, destination_port: int) -> str:
        key = f"{destination}:{destination_port}"
        return self.policy.nat_table.get(key, destination)

    @staticmethod
    def _matches(rule: FirewallRule, packet: PacketContext, translated_destination: str) -> bool:
        if rule.destination != translated_destination:
            return False
        if rule.protocol.lower() != packet.protocol.lower():
            return False
        if rule.destination_port != packet.destination_port:
            return False

        network = ipaddress.ip_network(rule.source_cidr, strict=False)
        source_ip = ipaddress.ip_address(packet.source_ip)
        return source_ip in network
