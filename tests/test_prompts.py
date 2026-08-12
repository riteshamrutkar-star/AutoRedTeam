from app.schemas.security_test import (
    ApplicableTestResult,
    EvidenceRequirements,
    ExpectedBehavior,
    InputSpecification,
    MutationType,
    Priority,
    RiskLevel,
    SecurityTestCategory,
    StrategyType,
    TargetLocation,
    TestStrategy,
    TestTarget,
)
from app.schemas.spec import NormalizedEndpoint, NormalizedParameter, SchemaDefinition
from app.services.llm.prompts import PROMPT_VERSION, build_test_generation_prompt


def test_prompt_building():
    endpoint = NormalizedEndpoint(
        path="/users/{id}",
        method="GET",
        parameters=[
            NormalizedParameter(
                name="id",
                location="path",
                required=True,
                schema_def=SchemaDefinition(type="string", format="uuid"),
            )
        ],
        security=[{"BearerAuth": []}],
    )

    candidate = ApplicableTestResult(
        instance_id="users_id_GET_AUTHZ-001_id",
        template_id="AUTHZ-001",
        name="Object Identifier Substitution (id)",
        category=SecurityTestCategory.AUTHORIZATION,
        subcategory="Object Level Authorization",
        target=TestTarget(
            path="/users/{id}",
            http_method="GET",
            target_location=TargetLocation.PATH,
            parameter_name="id",
        ),
        strategy=TestStrategy(
            strategy_type=StrategyType.IDENTIFIER_SUBSTITUTION,
            mutation_type=MutationType.OTHER_USER_ID,
            rationale="Rationale text",
            expected_observation="Observation text",
        ),
        input_spec=InputSpecification(
            target_element="Parameter 'id'",
            mutation_description="Mutation desc",
            purpose="Testing BOLA",
        ),
        expected_behavior=ExpectedBehavior(
            description="Rejection expected",
            expected_status_codes=[403, 404],
            should_reject=True,
            security_goal="Enforce BOLA",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True),
        priority=Priority.HIGH,
        risk_level=RiskLevel.HIGH,
        applicability_reasons=["Endpoint contains identifier parameter 'id'"],
    )

    user_prompt, system_prompt = build_test_generation_prompt(endpoint, candidate)

    assert "TEMPLATE_ID: AUTHZ-001" in user_prompt
    assert "ENDPOINT_PATH: /users/{id}" in user_prompt
    assert "HTTP_METHOD: GET" in user_prompt
    assert "TARGET_PARAMETER: id" in user_prompt
    assert PROMPT_VERSION in user_prompt
    assert "NO HALLUCINATION" in system_prompt
