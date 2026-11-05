"""Genera ``docs/detection-rules.md`` a partir de los YAML de reglas.

La documentación nunca se edita a mano: se regenera con
``python -m soc_lab docs`` para que no diverja de la lógica real.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from soc_lab.detection.engine import Rule, load_rules


def _logic_text(rule: Rule) -> str:
    logic = rule.logic
    group = ", ".join(f"`{g}`" for g in rule.group_by)
    if rule.type == "threshold":
        return f"≥ {logic['threshold']} eventos por {group} en {logic['window']}"
    if rule.type == "distinct":
        return f"≥ {logic['threshold']} valores distintos de `{logic['distinct_field']}` por {group} en {logic['window']}"
    steps = logic["steps"]
    return (f"≥ {steps[0].get('min_count', 1)} × `{steps[0]['name']}` seguido de `{steps[1]['name']}` "
            f"por {group} en {logic['window']}")


def _techniques(rule: Rule) -> str:
    return ", ".join(
        f"[{t['id']}](https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/) {t['name']}"
        for t in rule.techniques
    )


def render(rules: list[Rule]) -> str:
    out = [
        "# Reglas de detección",
        "",
        "> Documento generado automáticamente desde `soc_lab/detection/rules/*.yml` "
        "con `python -m soc_lab docs`. No editar a mano.",
        "",
        "## Resumen",
        "",
        "| ID | Regla | Severidad base | Táctica | Técnicas ATT&CK | Lógica |",
        "|----|-------|----------------|---------|-----------------|--------|",
    ]
    for r in rules:
        out.append(f"| {r.id} | {r.name} | {r.severity} | {', '.join(r.tactics)} | {_techniques(r)} | {_logic_text(r)} |")

    coverage: dict[str, list[str]] = defaultdict(list)
    for r in rules:
        for t in r.techniques:
            coverage[f"{t.get('tactic', r.tactics[0])}|{t['id']}|{t['name']}"].append(r.id)
    out += ["", "## Cobertura MITRE ATT&CK", "", "| Táctica | Técnica | Reglas |", "|---------|---------|--------|"]
    for key in sorted(coverage):
        tactic, tid, name = key.split("|")
        out.append(f"| {tactic} | {tid} {name} | {', '.join(coverage[key])} |")

    for r in rules:
        out += ["", f"## {r.id} — {r.name}", "",
                f"**Severidad:** {r.severity} · **Estado:** {r.status} · "
                f"**Fuentes:** {', '.join(r.data_sources)} · **Archivo:** `{r.path}`", "",
                r.description.strip(), "", f"**ATT&CK:** {_techniques(r)}", "",
                "**Lógica:**", "", "```yaml",
                yaml.safe_dump({"logic": r.logic}, allow_unicode=True, sort_keys=False).strip(), "```"]
        if r.exceptions:
            out += ["", "**Excepciones:**", "", "```yaml",
                    yaml.safe_dump(r.exceptions, allow_unicode=True, sort_keys=False).strip(), "```"]
        if r.severity_overrides:
            out += ["", "**Ajustes de severidad:** " + "; ".join(
                f"`{o['when']}` → {o['severity']}" for o in r.severity_overrides)]
        for title, items in (("Falsos positivos conocidos", r.false_positives),
                             ("Triage", r.triage), ("Respuesta", r.response)):
            if items:
                out += ["", f"**{title}:**", ""] + [f"- {i}" for i in items]
        if r.references:
            out += ["", "**Referencias:** " + " · ".join(r.references)]
    return "\n".join(out) + "\n"


def write_docs(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(load_rules()), encoding="utf-8")
    return path
