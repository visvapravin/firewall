from firewall.models import PacketContext
from firewall.policy import FirewallPolicy
from firewall.rule_engine import FirewallEngine


def test_allows_corporate_https_to_web1() -> None:
    policy = FirewallPolicy.from_file("config/firewall.sample.yaml")
    engine = FirewallEngine(policy)

    packet = PacketContext(
        source_ip="10.10.1.25",
        destination="203.0.113.10",
        protocol="tcp",
        destination_port=443,
    )
    result = engine.evaluate(packet)

    assert result["decision"] == "allow"
    assert result["translated_destination"] == "web-1.internal"


def test_denies_non_corporate_https_to_web1() -> None:
    policy = FirewallPolicy.from_file("config/firewall.sample.yaml")
    engine = FirewallEngine(policy)

    packet = PacketContext(
        source_ip="198.51.100.99",
        destination="203.0.113.10",
        protocol="tcp",
        destination_port=443,
    )
    result = engine.evaluate(packet)

    assert result["decision"] == "deny"
