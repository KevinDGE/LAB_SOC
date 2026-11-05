"""Pruebas unitarias del motor con eventos sintéticos."""

from datetime import datetime, timedelta, timezone

import pytest

from soc_lab.detection.engine import Filter, Rule, parse_duration, run_rule
from soc_lab.schema import Event

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
LISTS = {"scanners": ["10.0.0.5"], "internal": ["10.0.0.0/8"], "prefixes": ["svc_"]}


def ev(sec, **kw):
    base = dict(timestamp=T0 + timedelta(seconds=sec), source="test", event_code="x",
                category="authentication", action="a", outcome="failure")
    base.update(kw)
    return Event(**base)


def rule(logic, **kw):
    spec = dict(id="T-1", name="test", description="d", severity="medium", tactics=["Discovery"],
                techniques=[{"id": "T1046", "name": "x"}], logic=logic, summary="{count}")
    spec.update(kw)
    return Rule(**spec).compile(LISTS)


@pytest.mark.parametrize("text,expected", [("90s", 90), ("5m", 300), ("2h", 7200)])
def test_parse_duration(text, expected):
    assert parse_duration(text).total_seconds() == expected


def test_parse_duration_invalid():
    with pytest.raises(ValueError):
        parse_duration("5 minutes")


def test_filter_operators_and_lists():
    e = ev(0, src_ip="10.0.0.5", user="svc_backup", extra={"path": r"C:\Windows\Temp\x.exe"}, dst_port=445)
    assert Filter({"src_ip": {"in": "$scanners"}}, LISTS).matches(e)
    assert Filter({"src_ip": {"cidr": "$internal"}}, LISTS).matches(e)
    assert not Filter({"src_ip": {"not_cidr": "$internal"}}, LISTS).matches(e)
    assert Filter({"user": {"startswith": "$prefixes"}}, LISTS).matches(e)
    assert Filter({"extra.path": {"contains_any": ["\\temp\\"]}}, LISTS).matches(e)
    assert Filter({"dst_port": [22, 445], "outcome": "failure"}, LISTS).matches(e)
    assert not Filter({"dst_port": {"gte": 1000}}, LISTS).matches(e)
    assert Filter({"host": {"exists": False}}, LISTS).matches(e)
    with pytest.raises(ValueError):
        Filter({"x": {"regex": "."}}, LISTS)
    with pytest.raises(KeyError):
        Filter({"x": "$missing"}, LISTS)


def test_threshold_fires_once_per_burst():
    r = rule({"type": "threshold", "group_by": ["src_ip"], "window": "1m", "threshold": 5})
    burst = [ev(i * 5, src_ip="1.1.1.1") for i in range(20)]          # 20 eventos, uno cada 5 s
    later = [ev(3600 + i * 5, src_ip="1.1.1.1") for i in range(5)]    # segunda ráfaga una hora después
    alerts = run_rule(r, burst + later)
    assert [a.event_count for a in alerts] == [20, 5]


def test_threshold_below_limit_and_slow_events():
    r = rule({"type": "threshold", "group_by": ["src_ip"], "window": "1m", "threshold": 5})
    assert run_rule(r, [ev(i * 5, src_ip="1.1.1.1") for i in range(4)]) == []
    assert run_rule(r, [ev(i * 120, src_ip="1.1.1.1") for i in range(10)]) == []  # demasiado espaciados


def test_group_by_separates_entities_and_skips_missing_keys():
    r = rule({"type": "threshold", "group_by": ["src_ip"], "window": "1m", "threshold": 3})
    events = [ev(i, src_ip="1.1.1.1" if i % 2 else "2.2.2.2") for i in range(5)] + [ev(1) for _ in range(9)]
    alerts = run_rule(r, events)
    assert [a.group["src_ip"] for a in alerts] == ["2.2.2.2"]


def test_distinct_counts_unique_values():
    r = rule({"type": "distinct", "group_by": ["src_ip"], "distinct_field": "user", "window": "10m", "threshold": 3})
    same_user = [ev(i, src_ip="1.1.1.1", user="a") for i in range(10)]
    assert run_rule(r, same_user) == []
    spray = [ev(i * 10, src_ip="1.1.1.1", user=f"u{i}") for i in range(4)]
    (alert,) = run_rule(r, spray)
    assert alert.entities["users"] == ["u0", "u1", "u2", "u3"]


def test_exceptions_suppress_events():
    r = rule({"type": "threshold", "group_by": ["src_ip"], "window": "1m", "threshold": 2},
             exceptions=[{"src_ip": {"in": "$scanners"}}])
    assert run_rule(r, [ev(i, src_ip="10.0.0.5") for i in range(10)]) == []
    assert len(run_rule(r, [ev(i, src_ip="10.0.0.6") for i in range(10)])) == 1


def test_severity_override_only_escalates():
    r = rule({"type": "threshold", "group_by": ["src_ip"], "window": "1m", "threshold": 1},
             severity_overrides=[{"when": {"src_ip": {"cidr": "$internal"}}, "severity": "high"},
                                 {"when": {"src_ip": {"cidr": "$internal"}}, "severity": "low"}])
    assert run_rule(r, [ev(0, src_ip="10.1.1.1")])[0].severity == "high"
    assert run_rule(r, [ev(0, src_ip="8.8.8.8")])[0].severity == "medium"


def test_sequence_requires_failures_before_success():
    r = rule({"type": "sequence", "group_by": ["src_ip"], "window": "10m",
              "steps": [{"name": "f", "filter": {"outcome": "failure"}, "min_count": 3},
                        {"name": "s", "filter": {"outcome": "success"}}]},
             summary="{failures}/{successes}/{success_users}")
    ok_first = [ev(0, src_ip="1.1.1.1", outcome="success")] + [ev(i + 1, src_ip="1.1.1.1") for i in range(5)]
    assert run_rule(r, ok_first) == []
    attack = [ev(i, src_ip="1.1.1.1") for i in range(5)] + [ev(10, src_ip="1.1.1.1", outcome="success", user="bob")]
    (alert,) = run_rule(r, attack)
    assert alert.summary == "5/1/bob"
    # Un éxito posterior dentro del mismo ataque se agrega a la misma alerta.
    attack.append(ev(300, src_ip="1.1.1.1", outcome="success", user="bob"))
    assert [a.event_count for a in run_rule(r, attack)] == [7]


def test_sequence_respects_window():
    r = rule({"type": "sequence", "group_by": ["src_ip"], "window": "1m",
              "steps": [{"name": "f", "filter": {"outcome": "failure"}, "min_count": 3},
                        {"name": "s", "filter": {"outcome": "success"}}]})
    events = [ev(i, src_ip="1.1.1.1") for i in range(5)] + [ev(600, src_ip="1.1.1.1", outcome="success")]
    assert run_rule(r, events) == []


def test_alert_ids_are_stable():
    r = rule({"type": "threshold", "group_by": ["src_ip"], "window": "1m", "threshold": 1})
    a1 = run_rule(r, [ev(0, src_ip="1.1.1.1")])[0]
    a2 = run_rule(r, [ev(0, src_ip="1.1.1.1")])[0]
    assert a1.alert_id == a2.alert_id and a1.alert_id.startswith("T-1-")


VALID_LOGIC = {"type": "threshold", "group_by": ["src_ip"], "window": "1m", "threshold": 1}


@pytest.mark.parametrize("logic,override,error", [
    (VALID_LOGIC, {"severity": "urgent"}, "severidad"),
    (VALID_LOGIC, {"techniques": []}, "ATT&CK"),
    ({"type": "magic", "window": "1m"}, {}, "tipo"),
    ({**VALID_LOGIC, "window": "1 hora"}, {}, "duración"),
])
def test_invalid_rules_are_rejected(logic, override, error):
    with pytest.raises(ValueError, match=error):
        rule(logic, **override)
