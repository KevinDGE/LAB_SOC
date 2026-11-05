"""CLI del laboratorio: ``python -m soc_lab <comando>``."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from soc_lab import pipeline
from soc_lab.simulator.generator import DEFAULT_SEED, generate


def cmd_generate(args: argparse.Namespace) -> None:
    manifest = generate(pipeline.raw_dir(args.data), seed=args.seed)
    print(f"[generate] semilla={manifest['seed']} día={manifest['day']}")
    for name, count in manifest["files"].items():
        print(f"  {name:<15} {count:>6} registros")
    events = pipeline.normalize(args.data)
    by_source = Counter(e.source for e in events)
    print(f"[normalize] {len(events)} eventos → {pipeline.events_path(args.data)}  {dict(by_source)}")


def cmd_detect(args: argparse.Namespace) -> None:
    alerts, metrics = pipeline.detect(args.data)
    print(f"[detect] {len(alerts)} alertas → {pipeline.alerts_path(args.data)}")
    for alert in alerts:
        print(f"  {alert.first_seen:%H:%M:%S}  {alert.severity:<8} {alert.rule_id}  {alert.summary}")
    print("[evaluate]")
    for sc in metrics["scenarios"]:
        status = "OK " if not sc["missed_rules"] else "GAP"
        print(f"  {status} {sc['scenario_id']}  disparadas={sc['fired_rules']}  faltantes={sc['missed_rules']}")
    print(f"  alertas atribuidas a escenarios: {metrics['alerts_attributed']}/{metrics['alerts_total']}"
          f"  no atribuidas: {metrics['unattributed_alerts']}")


def cmd_docs(args: argparse.Namespace) -> None:
    from soc_lab.detection.docs import write_docs

    print(f"[docs] {write_docs(Path('docs/detection-rules.md'))}")


def cmd_cases(args: argparse.Namespace) -> None:
    cases, reports = pipeline.build_cases(args.data, args.reports)
    print(f"[cases] {len(cases)} casos → {pipeline.cases_path(args.data)}")
    for case, path in zip(cases, reports):
        m = case["metrics"]
        print(f"  {case['case_id']}  {m['alerts']} alertas, {len(case['timeline'])} hitos, "
              f"{m['duration_min']} min  → {path}")


def cmd_all(args: argparse.Namespace) -> None:
    """Pipeline completo: generar → normalizar → detectar → casos (→ servir)."""
    cmd_generate(args)
    cmd_detect(args)
    cmd_cases(args)
    if args.serve:
        cmd_serve(args)


def cmd_serve(args: argparse.Namespace) -> None:
    from soc_lab.dashboard.app import create_app

    create_app(args.data).run(host=args.host, port=args.port, debug=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc_lab", description="Laboratorio SOC con datos simulados")
    parser.add_argument("--data", type=Path, default=Path("data"), help="directorio de datos (default: data)")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="genera logs crudos simulados y los normaliza")
    gen.add_argument("--seed", type=int, default=DEFAULT_SEED)
    gen.set_defaults(func=cmd_generate)

    det = sub.add_parser("detect", help="ejecuta las reglas sobre los eventos normalizados")
    det.set_defaults(func=cmd_detect)

    docs = sub.add_parser("docs", help="regenera docs/detection-rules.md desde los YAML")
    docs.set_defaults(func=cmd_docs)

    cases = sub.add_parser("cases", help="construye los casos y sus reportes de incidente")
    cases.add_argument("--reports", type=Path, default=Path("reports"))
    cases.set_defaults(func=cmd_cases)

    serve = sub.add_parser("serve", help="levanta el dashboard web")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=cmd_serve)

    run_all = sub.add_parser("all", help="ejecuta todo el pipeline y opcionalmente el dashboard")
    run_all.add_argument("--seed", type=int, default=DEFAULT_SEED)
    run_all.add_argument("--reports", type=Path, default=Path("reports"))
    run_all.add_argument("--serve", action="store_true", help="levanta el dashboard al terminar")
    run_all.add_argument("--host", default="127.0.0.1")
    run_all.add_argument("--port", type=int, default=8000)
    run_all.set_defaults(func=cmd_all)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
