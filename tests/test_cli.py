from soc_lab.__main__ import main


def test_cli_full_pipeline(tmp_path, capsys):
    assert main(["--data", str(tmp_path / "data"), "all", "--reports", str(tmp_path / "reports")]) == 0
    out = capsys.readouterr().out
    assert "[generate]" in out and "[detect]" in out and "[cases] 3 casos" in out
    assert (tmp_path / "data" / "alerts.json").exists()
    assert sorted(p.name for p in (tmp_path / "reports").iterdir()) == \
        ["CASE-001.md", "CASE-002.md", "CASE-003.md", "README.md"]
