import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_route_get_evaluation_metrics_info(client):
    resp = client.get("/api/v1/evaluation/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "evaluation_version" in data
    assert "supported_strategies" in data
    assert "STATIC" in data["supported_strategies"]


def test_route_compute_evaluation(client):
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    parse_resp = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    spec_data = parse_resp.json()

    gt_data = json.loads((FIXTURES_DIR / "evaluation_ground_truth.json").read_text())

    eval_req = {
        "run_name": "API Route Test Run",
        "strategy": "STATIC",
        "target_id": "vampi-local",
        "normalized_spec": spec_data,
        "ground_truth": gt_data,
    }

    resp = client.post("/api/v1/evaluation/compute", json=eval_req)
    assert resp.status_code == 200
    result = resp.json()

    assert result["evaluation_id"].startswith("eval_")
    assert result["target_id"] == "vampi-local"
    assert "coverage" in result
    assert "discovery" in result


def test_route_compare_evaluations(client):
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    parse_resp = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    spec_data = parse_resp.json()

    eval_req_a = {
        "run_name": "Static Run",
        "strategy": "STATIC",
        "target_id": "vampi-local",
        "normalized_spec": spec_data,
    }
    eval_req_b = {
        "run_name": "Adaptive Run",
        "strategy": "ADAPTIVE",
        "target_id": "vampi-local",
        "normalized_spec": spec_data,
    }

    resp_a = client.post("/api/v1/evaluation/compute", json=eval_req_a).json()
    resp_b = client.post("/api/v1/evaluation/compute", json=eval_req_b).json()

    compare_req = {
        "run_a": resp_a,
        "run_b": resp_b,
    }

    resp = client.post("/api/v1/evaluation/compare", json=compare_req)
    assert resp.status_code == 200
    comp_result = resp.json()

    assert "run_a_name" in comp_result
    assert "metrics_comparison" in comp_result
    assert len(comp_result["metrics_comparison"]) > 0
