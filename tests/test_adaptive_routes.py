from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_route_create_adaptive_session(client):
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()

    parse_resp = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    assert parse_resp.status_code == 200
    spec_data = parse_resp.json()

    session_req = {
        "target_id": "vampi-local",
        "spec": spec_data,
        "budget": {
            "max_iterations": 5,
            "max_executions": 5,
        },
    }

    create_resp = client.post("/api/v1/adaptive/sessions", json=session_req)
    assert create_resp.status_code == 201
    session_data = create_resp.json()

    assert session_data["session_id"].startswith("sess_")
    assert session_data["target_id"] == "vampi-local"
    assert session_data["status"] == "CREATED"
    assert session_data["budget"]["max_iterations"] == 5

    # GET session by ID
    get_resp = client.get(f"/api/v1/adaptive/sessions/{session_data['session_id']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["session_id"] == session_data["session_id"]


def test_route_run_session_bounded_max_steps_this_call(client):
    """Test that POST /run endpoint respects max_steps_this_call independently of session budget."""
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()

    parse_resp = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    assert parse_resp.status_code == 200
    spec_data = parse_resp.json()

    session_req = {
        "target_id": "vampi-local",
        "spec": spec_data,
        "budget": {
            "max_iterations": 10,
            "max_executions": 10,
        },
    }

    create_resp = client.post("/api/v1/adaptive/sessions", json=session_req)
    session_data = create_resp.json()
    session_id = session_data["session_id"]

    # Request run with max_steps_this_call = 2
    run_resp = client.post(
        f"/api/v1/adaptive/sessions/{session_id}/run",
        json={"max_steps_this_call": 2},
    )
    assert run_resp.status_code == 200
    updated_data = run_resp.json()

    # Session budget had max_iterations=10, but max_steps_this_call=2 limited this call to 2 iterations
    assert updated_data["current_iteration"] == 2
    assert updated_data["status"] == "RUNNING"
