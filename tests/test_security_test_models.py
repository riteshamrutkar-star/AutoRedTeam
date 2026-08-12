import pytest
from pydantic import ValidationError

from app.schemas.security_test import (
    EvidenceRequirements,
    ExpectedBehavior,
    InputSpecification,
    MutationType,
    PrerequisiteRequirement,
    Priority,
    RiskLevel,
    SecurityTestCategory,
    StrategyType,
    TestStrategy,
    TestTarget,
    TestTemplate,
    TargetLocation,
)


def test_create_valid_test_template():
    template = TestTemplate(
        template_id="TEST-001",
        name="Sample Test",
        description="Sample test template",
        category=SecurityTestCategory.AUTHENTICATION,
        subcategory="Sample Subcategory",
        prerequisites=PrerequisiteRequirement(requires_auth_declared=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.AUTH_STATE_CHANGE,
            mutation_type=MutationType.OMIT,
            rationale="Rationale text",
            expected_observation="Expected observation text",
        ),
        input_spec_template=InputSpecification(
            target_element="Auth Header",
            mutation_description="Omit auth header",
            purpose="Testing auth enforcement",
        ),
        expected_behavior=ExpectedBehavior(
            description="Rejection",
            expected_status_codes=[401],
            should_reject=True,
            security_goal="Enforce auth",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True),
        baseline_priority=Priority.HIGH,
        baseline_risk_level=RiskLevel.HIGH,
    )

    assert template.template_id == "TEST-001"
    assert template.category == SecurityTestCategory.AUTHENTICATION
    assert template.baseline_priority == Priority.HIGH
    
    # Test JSON serialization
    serialized = template.model_dump_json()
    assert "TEST-001" in serialized


def test_invalid_enum_validation():
    with pytest.raises(ValidationError):
        TestTemplate(
            template_id="TEST-002",
            name="Invalid Enum Test",
            description="Testing invalid enum",
            category="INVALID_CATEGORY",  # Invalid enum value
            subcategory="Sub",
            prerequisites=PrerequisiteRequirement(),
            strategy=TestStrategy(
                strategy_type=StrategyType.VALUE_OMISSION,
                mutation_type=MutationType.OMIT,
                rationale="Rationale",
                expected_observation="Observation",
            ),
            input_spec_template=InputSpecification(
                target_element="Param",
                mutation_description="Desc",
                purpose="Purpose",
            ),
            expected_behavior=ExpectedBehavior(
                description="Desc",
                expected_status_codes=[400],
                security_goal="Goal",
            ),
            evidence_requirements=EvidenceRequirements(),
            baseline_priority=Priority.LOW,
            baseline_risk_level=RiskLevel.LOW,
        )
