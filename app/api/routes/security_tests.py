from fastapi import APIRouter

from app.schemas.security_test import ApplicableTestResult, TestTemplate
from app.schemas.spec import NormalizedApiSpec
from app.services.security_tests.applicability import applicability_engine
from app.services.security_tests.catalogue import catalogue_registry

router = APIRouter(prefix="/api/v1/security-tests", tags=["Security Tests"])


@router.get(
    "/catalogue",
    response_model=list[TestTemplate],
    summary="Get security test catalogue templates",
    description="Retrieve all immutable security test templates registered in AutoRedTeam's test catalogue.",
)
def get_catalogue() -> list[TestTemplate]:
    """Return all catalogue test templates."""
    return catalogue_registry.get_all_templates()


@router.post(
    "/applicable",
    response_model=list[ApplicableTestResult],
    summary="Evaluate applicable security tests for a normalized API spec",
    description="Thin API wrapper that runs the ApplicabilityEngine against a NormalizedApiSpec to determine applicable security test instances with structured reasons.",
)
def evaluate_applicable_tests(spec: NormalizedApiSpec) -> list[ApplicableTestResult]:
    """Evaluate applicable security test instances for an API specification."""
    return applicability_engine.evaluate_spec(spec)
