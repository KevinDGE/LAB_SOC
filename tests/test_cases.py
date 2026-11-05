import ipaddress

import pytest

from tests.conftest import REPO_ROOT


def _case(lab, case_id):
    return next(c for c in lab["cases"] if c["case_id"] == case_id)


def test_three_cases_with_expected_rules(lab):
    rules = {c["case_id"]: c["alert_rules"] for c in lab["cases"]}
    assert rules == {
        "CASE-001": ["SOC-001", "SOC-004", "SOC-005"],
        "CASE-002": ["SOC-003", "SOC-004"],
        "CASE-003": ["SOC-005", "SOC-006", "SOC-007", "SOC-008", "SOC-009"],
    }


@pytest.mark.parametrize("case_id", ["CASE-001", "CASE-002", "CASE-003"])
def test_timeline_is_ordered_and_complete(lab, case_id):
    case = _case(lab, case_id)
    timestamps = [t["ts"] for t in case["timeline"]]
    assert timestamps == sorted(timestamps)
    kinds = {t["kind"] for t in case["timeline"]}
    assert "alert" in kinds and kinds & {"event", "activity"}
    assert all(t["detail"] and "{" not in t["detail"] for t in case["timeline"])  # plantillas resueltas
    assert case["iocs"] and case["attack"] and case["evidence_samples"]
    m = case["metrics"]
    assert m["first_malicious"] <= m["first_alert"] <= m["last_activity"]


def test_case_alerts_do_not_overlap(lab):
    ids = [a for c in lab["cases"] for a in c["alert_ids"]]
    assert len(ids) == len(set(ids))


def test_detection_gaps_are_documented(lab):
    case = _case(lab, "CASE-003")
    no_alert = {r["id"] for r in case["attack"] if r["evidence"] == ["contexto (sin alerta)"]}
    assert no_alert == {"T1071.001", "T1041"}


def test_compromised_accounts(lab):
    accounts = {c["case_id"]: sorted(i["value"] for i in c["iocs"] if i["type"] == "Cuenta") for c in lab["cases"]}
    assert accounts == {"CASE-001": ["deploy"], "CASE-002": ["e.vega", "r.medina"], "CASE-003": ["adm.m.fuentes"]}


def test_external_iocs_are_documentation_ranges(lab):
    nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for case in lab["cases"]:
        for ioc in case["iocs"]:
            if ioc["type"].startswith("IPv4"):
                assert any(ipaddress.ip_address(ioc["value"]) in n for n in nets)


def test_committed_reports_are_in_sync(lab):
    for path in lab["reports"]:
        committed = REPO_ROOT / "reports" / path.name
        assert committed.read_text(encoding="utf-8") == path.read_text(encoding="utf-8"), \
            f"{path.name} desactualizado: ejecuta `python -m soc_lab all`"
    assert (REPO_ROOT / "reports" / "README.md").exists()
