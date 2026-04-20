from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class RuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class FirewallRule:
    id: str
    source_cidr: str
    destination: str
    protocol: str
    destination_port: int
    action: RuleAction
    description: str = ""


@dataclass(frozen=True)
class PacketContext:
    source_ip: str
    destination: str
    protocol: str
    destination_port: int
    metadata: Dict[str, str] = field(default_factory=dict)
    ingress_interface: Optional[str] = None
