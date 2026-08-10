def test_health_endpoint(client):
    """Verify that GET /health returns status 200 and expected metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["service_name"] == "AutoRedTeam"
    assert data["status"] == "ok"
    assert "environment" in data
