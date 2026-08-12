from tests.test_execution_safety import create_sample_generated_test
from tests.test_security_analyzer import create_sample_execution_result


def test_route_get_owasp_taxonomy(client):
    response = client.get("/api/v1/security-analysis/owasp")
    assert response.status_code == 200
    data = response.json()
    assert "API1:2023" in data
    assert "API2:2023" in data
    assert data["API1:2023"]["name"] == "Broken Object Level Authorization"


def test_route_analyze_execution(client):
    test = create_sample_generated_test()
    result = create_sample_execution_result(status_code=401, template_id="AUTH-001")

    req = {
        "generated_test": test.model_dump(mode="json"),
        "execution_result": result.model_dump(mode="json"),
    }

    response = client.post("/api/v1/security-analysis/analyze", json=req)
    assert response.status_code == 200
    finding = response.json()

    assert finding["status"] == "NEGATIVE"
    assert finding["owasp"]["category_id"] == "API2:2023"
    assert finding["severity"] == "INFO"
    assert "confidence" in finding
