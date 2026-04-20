from firewall.models import PacketContext
from firewall.policy import FirewallPolicy
from firewall.rule_engine import FirewallEngine


if __name__ == "__main__":
    policy = FirewallPolicy.from_file("config/firewall.sample.yaml")
    engine = FirewallEngine(policy)

    sample = PacketContext(
        source_ip="10.10.20.15",
        destination="203.0.113.10",
        protocol="tcp",
        destination_port=443,
    )
    decision = engine.evaluate(sample)
    print(decision)
