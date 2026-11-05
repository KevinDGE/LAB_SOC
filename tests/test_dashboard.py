import pytest

from soc_lab.dashboard.app import create_app


@pytest.fixture(scope="module")
def client(lab):
    app = create_app(lab["data_dir"])
    app.config["TESTING"] = True
    return app.test_client()


@pytest.mark.parametrize("url", ["/", "/alerts", "/rules", "/cases", "/rules/SOC-001",
                                 "/cases/CASE-001", "/cases/CASE-002", "/cases/CASE-003", "/healthz"])
def test_pages_render(client, url):
    assert client.get(url).status_code == 200


def test_every_alert_detail_renders(client, lab):
    for alert in lab["alerts"]:
        response = client.get(f"/alerts/{alert.alert_id}")
        assert response.status_code == 200
        assert alert.rule_name.encode() in response.data


@pytest.mark.parametrize("url", ["/alerts/NOPE", "/rules/SOC-999", "/cases/CASE-999", "/api/alerts/NOPE"])
def test_not_found(client, url):
    assert client.get(url).status_code == 404


def test_alert_filters(client, lab):
    critical = client.get("/api/alerts?severity=critical").get_json()
    assert critical and all(a["severity"] == "critical" for a in critical)
    by_ip = client.get("/api/alerts?q=10.10.20.17").get_json()
    assert {a["rule_id"] for a in by_ip} >= {"SOC-005", "SOC-006", "SOC-007", "SOC-009"}
    discovery = client.get("/api/alerts?tactic=Discovery").get_json()
    assert all("Discovery" in a["tactic"] for a in discovery)
    assert client.get("/api/alerts?rule=SOC-003").get_json()[0]["rule_id"] == "SOC-003"
    assert b"Sin alertas" in client.get("/alerts?q=no-existe").data


def test_api_stats(client, lab):
    stats = client.get("/api/stats").get_json()
    assert stats["events"] == len(lab["events"])
    assert stats["alerts"] == len(lab["alerts"]) and stats["cases"] == 3
    assert sum(stats["alerts_by_severity"].values()) == stats["alerts"]


def test_api_alert_includes_evidence(client, lab):
    alert = lab["alerts"][0]
    data = client.get(f"/api/alerts/{alert.alert_id}").get_json()
    assert len(data["evidence"]) == alert.event_count


def test_user_input_is_escaped(client):
    html = client.get("/alerts?q=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_inline_markdown_filter_escapes_html(lab):
    app = create_app(lab["data_dir"])
    md = app.jinja_env.filters["md_inline"]
    assert str(md("**hola** `x` <b>")) == "<strong>hola</strong> <code>x</code> &lt;b&gt;"
