from pathlib import Path

from app.services.openapi.normalizer import process_spec_bytes
from app.services.security_tests.applicability import ApplicabilityEngine

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_applicability_petstore_spec():
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")

    engine = ApplicabilityEngine()
    results = engine.evaluate_spec(spec)

    assert len(results) > 0

    # Verify GET /users/{id} receives identifier/authorization test (AUTHZ-001)
    get_user_by_id_results = [
        r for r in results if r.target.path == "/users/{id}" and r.target.http_method == "GET"
    ]
    template_ids_get_user = {r.template_id for r in get_user_by_id_results}
    assert "AUTHZ-001" in template_ids_get_user
    assert "AUTH-001" in template_ids_get_user

    # Verify POST /users receives request body tests
    post_users_results = [
        r for r in results if r.target.path == "/users" and r.target.http_method == "POST"
    ]
    template_ids_post_users = {r.template_id for r in post_users_results}
    assert "BODY-001" in template_ids_post_users
    assert "BODY-002" in template_ids_post_users
    assert "BODY-003" in template_ids_post_users


def test_negative_applicability():
    """Verify irrelevant test templates are NOT returned for endpoints that do not meet prerequisites."""
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")

    engine = ApplicabilityEngine()
    results = engine.evaluate_spec(spec)

    # 1. Unauthenticated endpoint (POST /auth/login with security: []) must NOT receive AUTH-001 or AUTH-002
    login_results = [
        r for r in results if r.target.path == "/auth/login" and r.target.http_method == "POST"
    ]
    login_template_ids = {r.template_id for r in login_results}
    assert "AUTH-001" not in login_template_ids
    assert "AUTH-002" not in login_template_ids

    # 2. Endpoint without request body (GET /users) must NOT receive body tests (BODY-001, BODY-002)
    get_users_results = [
        r for r in results if r.target.path == "/users" and r.target.http_method == "GET"
    ]
    get_users_template_ids = {r.template_id for r in get_users_results}
    assert "BODY-001" not in get_users_template_ids
    assert "BODY-002" not in get_users_template_ids


def test_boundary_case_schema_constraints():
    """Verify rich schema constraint information from Phase 2 triggers boundary mutation tests (INP-003)."""
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")

    engine = ApplicabilityEngine()
    results = engine.evaluate_spec(spec)

    # GET /users has page parameter with minimum: 1 and limit parameter with maximum: 100
    get_users_results = [
        r for r in results if r.target.path == "/users" and r.target.http_method == "GET"
    ]
    get_users_template_ids = {r.template_id for r in get_users_results}
    assert "INP-003" in get_users_template_ids  # Boundary Value Mutation


def test_deterministic_reproducible_ordering():
    """Verify evaluating identical spec multiple times produces identical, deterministically ordered results."""
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")

    engine = ApplicabilityEngine()
    run1 = engine.evaluate_spec(spec)
    run2 = engine.evaluate_spec(spec)

    assert len(run1) == len(run2)
    for res1, res2 in zip(run1, run2):
        assert res1.instance_id == res2.instance_id
        assert res1.template_id == res2.template_id
        assert res1.target.path == res2.target.path
        assert res1.target.http_method == res2.target.http_method
