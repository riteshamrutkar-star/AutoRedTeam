from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_route_parse_yaml_spec(client):
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    response = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["metadata"]["title"] == "PetStore Test API"
    assert len(data["endpoints"]) > 0


def test_route_validate_yaml_spec(client):
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    response = client.post(
        "/api/v1/specifications/validate",
        files={"file": ("petstore.yaml", yaml_bytes, "application/x-yaml")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["title"] == "PetStore Test API"
    assert data["endpoint_count"] == 3  # /users, /users/{id}, /auth/login


def test_route_parse_invalid_file(client):
    response = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("invalid.txt", b"not a json or yaml", "text/plain")},
    )
    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "InvalidFileFormatError"


def test_route_parse_unsupported_version(client):
    swagger2_bytes = (FIXTURES_DIR / "swagger2_spec.json").read_bytes()
    response = client.post(
        "/api/v1/specifications/parse",
        files={"file": ("swagger2.json", swagger2_bytes, "application/json")},
    )
    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "UnsupportedSpecVersionError"
