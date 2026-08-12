from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_route_llm_health(client):
    response = client.get("/api/v1/llm/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["provider"] == "mock"
    assert data["model"] == "mock-v1"


def test_route_generate_security_tests(client):
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()

    # 1. Parse spec
    parse_resp = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    assert parse_resp.status_code == 200
    spec_data = parse_resp.json()

    # 2. Get applicable tests
    applicable_resp = client.post(
        "/api/v1/security-tests/applicable",
        json=spec_data,
    )
    assert applicable_resp.status_code == 200
    applicable_tests = applicable_resp.json()

    # 3. Generate tests
    gen_req = {
        "spec": spec_data,
        "applicable_tests": applicable_tests[:2],
    }
    gen_resp = client.post(
        "/api/v1/security-tests/generate",
        json=gen_req,
    )
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()

    assert gen_data["total_requested"] == 2
    assert gen_data["total_generated"] == 2
    assert len(gen_data["generated_tests"]) == 2
    assert gen_data["generated_tests"][0]["generation_metadata"]["provider"] == "mock"
