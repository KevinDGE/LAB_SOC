"""Evaluación de la detección contra el ground truth del simulador.

Una alerta se atribuye a un escenario si se solapa con su ventana temporal y
comparte alguna entidad (IP atacante, host o cuenta afectados). Las alertas no
atribuibles se consideran falsos positivos y deben quedar explicadas.
"""

from __future__ import annotations

from typing import Any

from soc_lab.schema import Alert, parse_ts


def _entities(alert: Alert) -> set[str]:
    return {v for values in alert.entities.values() for v in values}


def attribute(alert: Alert, scenarios: list[dict[str, Any]]) -> str | None:
    for sc in scenarios:
        start, end = parse_ts(sc["start"]), parse_ts(sc["end"])
        overlaps = alert.first_seen <= end and alert.last_seen >= start
        if overlaps and _entities(alert) & set(sc["attacker"] + sc.get("assets", [])):
            return sc["scenario_id"]
    return None


def evaluate(alerts: list[Alert], scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    by_scenario: dict[str, list[str]] = {sc["scenario_id"]: [] for sc in scenarios}
    unattributed = []
    for alert in alerts:
        sid = attribute(alert, scenarios)
        if sid:
            by_scenario[sid].append(alert.rule_id)
        else:
            unattributed.append(alert.alert_id)

    results = []
    for sc in scenarios:
        fired = set(by_scenario[sc["scenario_id"]])
        expected = set(sc["expected_rules"])
        results.append({
            "scenario_id": sc["scenario_id"],
            "title": sc["title"],
            "expected_rules": sorted(expected),
            "fired_rules": sorted(fired),
            "missed_rules": sorted(expected - fired),
            "detected": bool(fired),
        })
    total = len(alerts)
    return {
        "scenarios": results,
        "alerts_total": total,
        "alerts_attributed": total - len(unattributed),
        "unattributed_alerts": unattributed,
        "precision": round((total - len(unattributed)) / total, 3) if total else 1.0,
        "scenario_recall": round(sum(r["detected"] for r in results) / len(results), 3) if results else 1.0,
    }
