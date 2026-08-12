from pathlib import Path
import pytest

from app.core.exceptions import UnsupportedSpecVersionError
from app.services.openapi.loader import load_spec_from_bytes
from app.services.openapi.normalizer import normalize_openapi_spec, process_spec_bytes

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_normalize_petstore_spec():
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    norm_spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")

    # Metadata
    assert norm_spec.metadata.title == "PetStore Test API"
    assert norm_spec.metadata.version == "1.2.0"

    # Servers
    assert len(norm_spec.servers) == 1
    assert norm_spec.servers[0].url == "https://api.petstore.example.com/v1"

    # Security schemes
    assert "BearerAuth" in norm_spec.security_schemes
    assert norm_spec.security_schemes["BearerAuth"].type == "http"
    assert norm_spec.security_schemes["BearerAuth"].scheme == "bearer"

    # Endpoints count
    endpoint_paths = [e.path for e in norm_spec.endpoints]
    assert "/users" in endpoint_paths
    assert "/users/{id}" in endpoint_paths
    assert "/auth/login" in endpoint_paths


def test_security_override_semantics():
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    norm_spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")

    endpoints_by_id = {e.operation_id: e for e in norm_spec.endpoints if e.operation_id}

    # /users GET inherits global security (BearerAuth)
    list_users_op = endpoints_by_id["listUsers"]
    assert list_users_op.security == [{"BearerAuth": []}]

    # /auth/login POST explicitly overrides security with [] (unauthenticated)
    login_op = endpoints_by_id["loginUser"]
    assert login_op.security == []


def test_rich_schema_preservation():
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    norm_spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")

    create_user_op = next(e for e in norm_spec.endpoints if e.operation_id == "createUser")
    assert create_user_op.request_body is not None
    assert "application/json" in create_user_op.request_body.content

    json_content = create_user_op.request_body.content["application/json"]
    schema = json_content.schema_def
    assert schema is not None
    assert schema.type == "object"
    assert "username" in schema.properties
    assert "email" in schema.properties
    assert "password" in schema.properties
    assert schema.properties["email"].format == "email"


def test_reject_swagger_2_spec():
    swagger2_bytes = (FIXTURES_DIR / "swagger2_spec.json").read_bytes()
    doc = load_spec_from_bytes(swagger2_bytes, filename="swagger2_spec.json")
    with pytest.raises(UnsupportedSpecVersionError) as exc_info:
        normalize_openapi_spec(doc)
    assert "Swagger 2.0 is not supported" in str(exc_info.value)
