from tests.test_execution_safety import create_sample_generated_test


def test_route_list_targets(client):
    response = client.get("/api/v1/targets")
    assert response.status_code == 200
    targets = response.json()
    assert isinstance(targets, list)
    target_ids = [t["target_id"] for t in targets]
    assert "vampi-local" in target_ids
    assert "juice-shop-local" in target_ids


def test_route_execute_blocked_target(client):
    test = create_sample_generated_test()
    req = {
        "target_id": "unregistered-target-123",
        "generated_test": test.model_dump(mode="json"),
    }
    response = client.post("/api/v1/executions", json=req)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert data["policy_decision"]["allowed"] is False
    assert data["policy_decision"]["rule_violated"] == "UNREGISTERED_TARGET"
