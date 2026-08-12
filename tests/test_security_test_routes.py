from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_route_get_catalogue(client):
    response = client.get("/api/v1/security-tests/catalogue")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    # Check structure of a returned template
    template = data[0]
    assert "template_id" in template
    assert "category" in template
    assert "strategy" in template


def test_route_post_applicable(client):
    # Parse spec first using /specifications/parse
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    parse_resp = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    assert parse_resp.status_code == 200
    spec_data = parse_resp.json()

    # Pass normalized spec to /security-tests/applicable
    applicable_resp = client.post(
        "/api/v1/security-tests/applicable",
        json=spec_data,
    )
    assert applicable_resp.status_code == 200
    results = applicable_resp.json()
    assert isinstance(results, list)
    assert len(results) > 0

    # Verify instance_id and applicability_reasons are present
    first_result = results[0]
    assert "instance_id" in first_result
    assert "applicability_reasons" in first_result
    assert len(first_result["applicability_reasons"]) > 0
