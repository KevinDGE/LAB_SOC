import ipaddress
import json

from soc_lab import pipeline
from soc_lab.simulator.generator import generate

INTERNAL = ipaddress.ip_network("10.10.0.0/16")
DOCUMENTATION = [ipaddress.ip_network(c) for c in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_all_ips_are_internal_or_documentation(lab):
    """Ningún dato apunta a infraestructura real: solo 10.10/16, loopback y RFC 5737."""
    for e in lab["events"]:
        for value in (e.src_ip, e.dst_ip):
            if value is None:
                continue
            ip = ipaddress.ip_address(value)
            assert ip in INTERNAL or ip.is_loopback or any(ip in net for net in DOCUMENTATION), value


def test_generation_is_deterministic(lab, tmp_path):
    generate(tmp_path / "raw", seed=lab["manifest"]["seed"])
    for name in ("sshd.log", "windows.jsonl", "firewall.log", "scenarios.json"):
        original = (pipeline.raw_dir(lab["data_dir"]) / name).read_bytes()
        assert (tmp_path / "raw" / name).read_bytes() == original, name


def test_different_seed_changes_background(lab, tmp_path):
    generate(tmp_path / "raw", seed=42)
    assert (tmp_path / "raw" / "firewall.log").read_bytes() != \
        (pipeline.raw_dir(lab["data_dir"]) / "firewall.log").read_bytes()


def test_every_raw_line_is_parsed(lab):
    raw = pipeline.raw_dir(lab["data_dir"])
    total = sum(len(p.read_text().splitlines()) for p in raw.glob("*.log")) + \
        len((raw / "windows.jsonl").read_text().splitlines())
    assert total == len(lab["events"])


def test_events_cover_one_day_and_all_sources(lab):
    events = lab["events"]
    assert {e.source for e in events} == {"sshd", "windows", "firewall"}
    assert all(e.timestamp.date().isoformat() == lab["manifest"]["day"] for e in events)
    assert events == sorted(events, key=lambda e: (e.timestamp, e.source, e.raw))


def test_manifest_describes_three_scenarios(lab):
    manifest = json.loads(pipeline.scenarios_path(lab["data_dir"]).read_text())
    assert [s["scenario_id"] for s in manifest["scenarios"]] == ["CASE-001", "CASE-002", "CASE-003"]
    assert all(s["expected_rules"] and s["techniques"] for s in manifest["scenarios"])
