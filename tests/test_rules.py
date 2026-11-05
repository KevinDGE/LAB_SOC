"""Pruebas de las reglas reales contra el dataset simulado."""

import re

import pytest

from soc_lab.detection.docs import render
from soc_lab.detection.engine import load_rules
from tests.conftest import REPO_ROOT

RULES = load_rules()
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTICS = {"Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
           "Collection", "Command and Control", "Exfiltration", "Impact"}


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_is_documented_and_mapped(rule):
    assert re.fullmatch(r"SOC-\d{3}", rule.id)
    assert rule.path.endswith(".yml") and rule.id in rule.path
    assert len(rule.description.split()) >= 15
    assert rule.false_positives and rule.triage and rule.response
    assert set(rule.tactics) <= TACTICS
    for t in rule.techniques:
        assert TECHNIQUE_RE.match(t["id"]) and t["name"] and t["tactic"] in TACTICS
        assert any(t["id"].replace(".", "/") in ref for ref in rule.references), t["id"]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_rule_fires_on_dataset(rule, lab):
    assert any(a.rule_id == rule.id for a in lab["alerts"])


def test_all_scenarios_fully_detected(lab):
    for scenario in lab["metrics"]["scenarios"]:
        assert scenario["missed_rules"] == [], scenario


def test_only_known_false_positive(lab):
    """La única alerta no atribuible es la cuenta de servicio con contraseña expirada."""
    by_id = {a.alert_id: a for a in lab["alerts"]}
    fps = [by_id[i] for i in lab["metrics"]["unattributed_alerts"]]
    assert [(a.rule_id, a.group["user"]) for a in fps] == [("SOC-002", "svc_backup")]
    assert all(e.extra["sub_status"] == "0xC0000071" for e in fps[0].evidence)


def test_authorized_activity_is_suppressed(lab):
    sources = {ip for a in lab["alerts"] for ip in a.entities.get("src_ips", [])}
    assert "10.10.5.5" not in sources   # SCAN01, escáner autorizado
    assert "10.10.5.10" not in sources  # JUMP01, administración legítima


def test_password_spraying_not_seen_as_single_account_bruteforce(lab):
    spray_users = {a.group.get("user") for a in lab["alerts"] if a.rule_id == "SOC-002"}
    assert spray_users == {"svc_backup"}


def test_internal_scan_is_escalated(lab):
    scans = {a.entities["src_ips"][0]: a.severity for a in lab["alerts"] if a.rule_id == "SOC-005"}
    assert scans == {"203.0.113.77": "medium", "10.10.20.17": "high"}


def test_rule_docs_are_in_sync():
    committed = (REPO_ROOT / "docs" / "detection-rules.md").read_text(encoding="utf-8")
    assert committed == render(RULES), "ejecuta `python -m soc_lab docs` y commitea el resultado"
