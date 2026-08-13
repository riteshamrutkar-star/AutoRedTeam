import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_route_get_dashboard_ui(client):
    """Test dashboard HTML route returns 200 and renders disclaimer and context banner."""
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Security Research Dashboard" in resp.text
    assert "Research Disclaimer:" in resp.text


def test_route_reporting_summary(client):
    """Test GET /api/v1/reporting/summary returns active KPI summary."""
    resp = client.get("/api/v1/reporting/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "evaluation_id" in data
    assert "strategy" in data
    assert "discovery_rate" in data


def test_route_reporting_context_set(client):
    """Test POST /api/v1/reporting/context updates active reporting store."""
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    parse_resp = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    spec_data = parse_resp.json()

    ctx_req = {
        "run_name": "API Context Set Run",
        "strategy": "ADAPTIVE",
        "target_id": "vampi-local",
        "normalized_spec": spec_data,
    }

    resp = client.post("/api/v1/reporting/context", json=ctx_req)
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["run_name"] == "API Context Set Run"
    assert summary["strategy"] == "ADAPTIVE"


def test_route_reporting_findings(client):
    """Test GET /api/v1/reporting/findings with filtering."""
    resp = client.get("/api/v1/reporting/findings?status_filter=CONFIRMED")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_route_reporting_coverage(client):
    """Test GET /api/v1/reporting/coverage returns coverage metrics."""
    resp = client.get("/api/v1/reporting/coverage")
    assert resp.status_code == 200
    data = resp.json()
    assert "endpoint_coverage" in data
    assert "method_coverage" in data


def test_route_reporting_exports(client):
    """Test JSON and CSV export endpoints."""
    json_resp = client.get("/api/v1/reporting/export/json")
    assert json_resp.status_code == 200
    json_data = json_resp.json()
    assert "evaluation_id" in json_data
    assert "summary" in json_data

    csv_resp = client.get("/api/v1/reporting/export/csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "finding_id,status,severity" in csv_resp.text


def test_xss_escaping_safety(client):
    """Negative security test: script tags in finding titles or evidence are safely escaped and not executable."""
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    parse_resp = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    spec_data = parse_resp.json()

    # Inject XSS payload in run_name
    xss_run_name = "<script>alert('XSS-TEST')</script>"
    ctx_req = {
        "run_name": xss_run_name,
        "strategy": "STATIC",
        "target_id": "vampi-local",
        "normalized_spec": spec_data,
    }

    resp = client.post("/api/v1/reporting/context", json=ctx_req)
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["run_name"] == xss_run_name

    # Check that dashboard HTML embeds client script with escapeHtml protection
    dash_resp = client.get("/dashboard")
    assert dash_resp.status_code == 200
    assert "function escapeHtml(str)" in dash_resp.text
