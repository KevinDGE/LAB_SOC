"""Fixtures compartidas: ejecuta el pipeline completo una vez por sesión."""

from __future__ import annotations

from pathlib import Path

import pytest

from soc_lab import pipeline
from soc_lab.simulator.generator import DEFAULT_SEED, generate

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    """Datos generados con la semilla por defecto en un directorio temporal."""
    data_dir = tmp_path_factory.mktemp("data")
    reports_dir = tmp_path_factory.mktemp("reports")
    manifest = generate(pipeline.raw_dir(data_dir), seed=DEFAULT_SEED)
    events = pipeline.normalize(data_dir)
    alerts, metrics = pipeline.detect(data_dir)
    cases, reports = pipeline.build_cases(data_dir, reports_dir)
    return {
        "data_dir": data_dir, "reports_dir": reports_dir, "manifest": manifest,
        "events": events, "alerts": alerts, "metrics": metrics, "cases": cases, "reports": reports,
    }
