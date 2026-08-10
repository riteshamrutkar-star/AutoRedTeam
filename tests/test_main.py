def test_root_endpoint(client):
    """Verify that GET / returns HTTP 200 and the welcome message."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "AutoRedTeam" in data["message"]
