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
    TestTemplate,
)

CATALOGUE_TEMPLATES: list[TestTemplate] = [
    # --- AUTHENTICATION ---
    TestTemplate(
        template_id="AUTH-001",
        name="Missing Authentication Requirement",
        description="Verify endpoint rejects requests sent without declared authentication credentials.",
        category=SecurityTestCategory.AUTHENTICATION,
        subcategory="Missing Credentials",
        prerequisites=PrerequisiteRequirement(requires_auth_declared=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.AUTH_STATE_CHANGE,
            mutation_type=MutationType.OMIT,
            rationale="Endpoints declaring security requirements must reject unauthenticated traffic.",
            expected_observation="HTTP 401 Unauthorized or 403 Forbidden response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Authorization Header / API Key",
            mutation_description="Omit all declared authentication headers, tokens, and cookies.",
            purpose="Ensure authentication enforcement is active.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must reject unauthenticated requests.",
            expected_status_codes=[401, 403],
            should_reject=True,
            security_goal="Enforce mandatory authentication for protected routes.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_headers=True, response_body=True),
        baseline_priority=Priority.HIGH,
        baseline_risk_level=RiskLevel.HIGH,
        tags=["authentication", "access-control"],
    ),
    TestTemplate(
        template_id="AUTH-002",
        name="Invalid Authentication Token",
        description="Verify endpoint rejects requests containing invalid authentication tokens.",
        category=SecurityTestCategory.AUTHENTICATION,
        subcategory="Invalid Credentials",
        prerequisites=PrerequisiteRequirement(requires_auth_declared=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.AUTH_STATE_CHANGE,
            mutation_type=MutationType.INVALID_TOKEN,
            rationale="Endpoints must validate token signature and validity before processing requests.",
            expected_observation="HTTP 401 Unauthorized response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Authorization Header",
            mutation_description="Substitute active authentication token with a syntactically invalid string.",
            purpose="Verify token signature validation.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must reject requests with invalid credentials.",
            expected_status_codes=[401],
            should_reject=True,
            security_goal="Prevent unauthorized access via forged or invalid tokens.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_headers=True, response_body=True),
        baseline_priority=Priority.HIGH,
        baseline_risk_level=RiskLevel.HIGH,
        tags=["authentication", "token-validation"],
    ),
    TestTemplate(
        template_id="AUTH-003",
        name="Malformed Authentication Header",
        description="Verify endpoint handles malformed authentication header syntax gracefully.",
        category=SecurityTestCategory.AUTHENTICATION,
        subcategory="Malformed Credentials",
        prerequisites=PrerequisiteRequirement(requires_auth_declared=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.MALFORMED_INPUT,
            mutation_type=MutationType.MUTATE_TYPE,
            rationale="Malformed security headers should be rejected without internal server errors.",
            expected_observation="HTTP 400 Bad Request or 401 Unauthorized response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Authorization Header",
            mutation_description="Send malformed authentication scheme or header prefix.",
            purpose="Ensure robust header parsing.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must handle header syntax errors gracefully.",
            expected_status_codes=[400, 401],
            should_reject=True,
            security_goal="Prevent error leakage from header parsing failure.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_headers=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["authentication", "syntax-validation"],
    ),

    # --- AUTHORIZATION ---
    TestTemplate(
        template_id="AUTHZ-001",
        name="Object Identifier Substitution",
        description="Verify endpoint enforces authorization when accessing resources via path/query identifiers.",
        category=SecurityTestCategory.AUTHORIZATION,
        subcategory="Object Level Authorization",
        prerequisites=PrerequisiteRequirement(requires_identifier_candidate=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.IDENTIFIER_SUBSTITUTION,
            mutation_type=MutationType.OTHER_USER_ID,
            rationale="Accessing resources using another entity's identifier must be checked against user permissions.",
            expected_observation="HTTP 403 Forbidden or 404 Not Found response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Identifier Parameter",
            mutation_description="Substitute resource identifier with another valid identifier format.",
            purpose="Determine whether object-level authorization is enforced.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API should reject unauthorized access to resource identifiers.",
            expected_status_codes=[403, 404],
            should_reject=True,
            security_goal="Enforce object-level access control.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True, comparison_context="authorized_vs_unauthorized_access"),
        baseline_priority=Priority.HIGH,
        baseline_risk_level=RiskLevel.HIGH,
        tags=["authorization", "bola", "idor"],
    ),
    TestTemplate(
        template_id="AUTHZ-002",
        name="Cross-Resource Identifier Access",
        description="Verify resource identifier substitution across different scopes.",
        category=SecurityTestCategory.AUTHORIZATION,
        subcategory="Resource Isolation",
        prerequisites=PrerequisiteRequirement(requires_identifier_candidate=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.IDENTIFIER_SUBSTITUTION,
            mutation_type=MutationType.SUBSTITUTE,
            rationale="Identifier scope isolation prevents horizontal privilege escalation.",
            expected_observation="HTTP 403 Forbidden or 404 Not Found response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Resource Identifier",
            mutation_description="Substitute resource ID with an out-of-scope resource ID.",
            purpose="Verify cross-tenant resource boundary isolation.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must isolate resource access between tenants.",
            expected_status_codes=[403, 404],
            should_reject=True,
            security_goal="Prevent cross-tenant data access.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.HIGH,
        baseline_risk_level=RiskLevel.HIGH,
        tags=["authorization", "tenant-isolation"],
    ),
    TestTemplate(
        template_id="AUTHZ-003",
        name="Privilege Context Variation",
        description="Verify endpoint authorization checks against lower-privileged user context.",
        category=SecurityTestCategory.AUTHORIZATION,
        subcategory="Function Level Authorization",
        prerequisites=PrerequisiteRequirement(requires_auth_declared=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.AUTH_STATE_CHANGE,
            mutation_type=MutationType.SUBSTITUTE,
            rationale="Restricted administrative or write operations must reject lower-privileged accounts.",
            expected_observation="HTTP 403 Forbidden response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Authorization Context",
            mutation_description="Execute request using a valid token belonging to a lower-privileged role.",
            purpose="Ensure function-level authorization enforcement.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must restrict administrative functions to authorized roles.",
            expected_status_codes=[403],
            should_reject=True,
            security_goal="Enforce function-level access control.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.HIGH,
        baseline_risk_level=RiskLevel.HIGH,
        tags=["authorization", "bfla", "privilege-escalation"],
    ),

    # --- INPUT VALIDATION ---
    TestTemplate(
        template_id="INP-001",
        name="Missing Required Parameter",
        description="Verify endpoint handles missing required parameters with appropriate validation errors.",
        category=SecurityTestCategory.INPUT_VALIDATION,
        subcategory="Parameter Omission",
        prerequisites=PrerequisiteRequirement(requires_path_params=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.VALUE_OMISSION,
            mutation_type=MutationType.OMIT,
            rationale="Required parameters must be validated prior to business logic processing.",
            expected_observation="HTTP 400 Bad Request or 422 Unprocessable Entity response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Required Parameter",
            mutation_description="Omit a parameter designated as required in specification.",
            purpose="Verify parameter presence validation.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must reject requests omitting required parameters.",
            expected_status_codes=[400, 422],
            should_reject=True,
            security_goal="Prevent unhandled exceptions from missing inputs.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["input-validation", "parameter-check"],
    ),
    TestTemplate(
        template_id="INP-002",
        name="Unexpected Parameter Type",
        description="Verify endpoint validates parameter data types against schema definitions.",
        category=SecurityTestCategory.INPUT_VALIDATION,
        subcategory="Type Validation",
        prerequisites=PrerequisiteRequirement(requires_query_params=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.TYPE_MUTATION,
            mutation_type=MutationType.MUTATE_TYPE,
            rationale="Passing mismatched data types (e.g. string for integer) should be caught by validation.",
            expected_observation="HTTP 400 Bad Request or 422 Unprocessable Entity response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Query Parameter",
            mutation_description="Substitute integer/boolean parameter with an incompatible string payload.",
            purpose="Verify strict parameter type checking.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must reject mismatched input types.",
            expected_status_codes=[400, 422],
            should_reject=True,
            security_goal="Prevent type confusion errors.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["input-validation", "type-safety"],
    ),
    TestTemplate(
        template_id="INP-003",
        name="Boundary Value Mutation",
        description="Verify endpoint enforces schema boundary constraints (minimum, maximum, minLength, maxLength).",
        category=SecurityTestCategory.INPUT_VALIDATION,
        subcategory="Boundary Testing",
        prerequisites=PrerequisiteRequirement(requires_schema_constraints=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.BOUNDARY_MUTATION,
            mutation_type=MutationType.BOUNDARY_MIN,
            rationale="Values exceeding declared minimum/maximum bounds should be rejected by schema validators.",
            expected_observation="HTTP 400 Bad Request or 422 Unprocessable Entity response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Constrained Schema Parameter",
            mutation_description="Supply values violating declared numeric range or string length limits.",
            purpose="Verify boundary constraint enforcement.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must enforce schema boundary limits.",
            expected_status_codes=[400, 422],
            should_reject=True,
            security_goal="Prevent out-of-bounds input processing.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["input-validation", "boundary-check"],
    ),
    TestTemplate(
        template_id="INP-004",
        name="Oversized Parameter Value",
        description="Verify endpoint rejects excessively large parameter values.",
        category=SecurityTestCategory.INPUT_VALIDATION,
        subcategory="Length Limits",
        prerequisites=PrerequisiteRequirement(requires_query_params=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.BOUNDARY_MUTATION,
            mutation_type=MutationType.OVERSIZED,
            rationale="Unbounded parameter sizes can lead to memory exhaustion or buffer issues.",
            expected_observation="HTTP 400 Bad Request or 413 Payload Too Large response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Query Parameter",
            mutation_description="Provide an oversized string value exceeding typical length bounds.",
            purpose="Verify input length caps.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must reject oversized input values.",
            expected_status_codes=[400, 413, 422],
            should_reject=True,
            security_goal="Prevent resource exhaustion from oversized parameters.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_size=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["input-validation", "size-limit"],
    ),

    # --- HTTP METHOD / BEHAVIOR ---
    TestTemplate(
        template_id="HTTP-001",
        name="Unsupported HTTP Method Check",
        description="Verify API rejects unhandled HTTP methods on endpoint routes.",
        category=SecurityTestCategory.HTTP_METHOD,
        subcategory="Method Handling",
        prerequisites=PrerequisiteRequirement(),  # Always applicable
        strategy=TestStrategy(
            strategy_type=StrategyType.METHOD_CHANGE,
            mutation_type=MutationType.UNSUPPORTED_METHOD,
            rationale="Endpoints should explicitly reject undeclared HTTP methods with HTTP 405 Method Not Allowed.",
            expected_observation="HTTP 405 Method Not Allowed response.",
        ),
        input_spec_template=InputSpecification(
            target_element="HTTP Verb",
            mutation_description="Send request using an unhandled verb (e.g. TRACE or HEAD).",
            purpose="Verify strict HTTP verb filtering.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must return HTTP 405 for unsupported HTTP verbs.",
            expected_status_codes=[405],
            should_reject=True,
            security_goal="Enforce route method restrictions.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_headers=True),
        baseline_priority=Priority.LOW,
        baseline_risk_level=RiskLevel.LOW,
        tags=["http-method", "verb-tampering"],
    ),
    TestTemplate(
        template_id="HTTP-002",
        name="Duplicate Parameter Injection",
        description="Verify API behavior when query parameters are duplicated in a single request.",
        category=SecurityTestCategory.API_BEHAVIOR,
        subcategory="Parameter Pollution",
        prerequisites=PrerequisiteRequirement(requires_query_params=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.REPETITION,
            mutation_type=MutationType.DUPLICATE_KEY,
            rationale="HTTP Parameter Pollution occurs when duplicate parameters cause inconsistent server parsing.",
            expected_observation="Consistent parameter handling without error.",
        ),
        input_spec_template=InputSpecification(
            target_element="Query Parameter",
            mutation_description="Supply duplicate instances of the same query parameter key with conflicting values.",
            purpose="Identify HTTP parameter pollution parsing behavior.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API should handle parameter repetition deterministically.",
            expected_status_codes=[200, 400, 422],
            should_reject=False,
            security_goal="Ensure deterministic query parameter handling.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.LOW,
        baseline_risk_level=RiskLevel.LOW,
        tags=["api-behavior", "hpp"],
    ),

    # --- REQUEST BODY ---
    TestTemplate(
        template_id="BODY-001",
        name="Request Body Field Omission",
        description="Verify API handles missing required request body properties cleanly.",
        category=SecurityTestCategory.INPUT_VALIDATION,
        subcategory="Body Schema Omission",
        prerequisites=PrerequisiteRequirement(requires_request_body=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.FIELD_REMOVAL,
            mutation_type=MutationType.OMIT,
            rationale="Omitted required JSON body fields should trigger schema validation rejection.",
            expected_observation="HTTP 400 Bad Request or 422 Unprocessable Entity response.",
        ),
        input_spec_template=InputSpecification(
            target_element="JSON Request Body",
            mutation_description="Remove required top-level property from request payload.",
            purpose="Verify JSON schema property enforcement.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must reject body payloads missing required properties.",
            expected_status_codes=[400, 422],
            should_reject=True,
            security_goal="Enforce request body schema validation.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["request-body", "schema-validation"],
    ),
    TestTemplate(
        template_id="BODY-002",
        name="Request Body Field Addition",
        description="Verify API behavior when undeclared additional fields are injected into JSON request bodies.",
        category=SecurityTestCategory.API_BEHAVIOR,
        subcategory="Mass Assignment",
        prerequisites=PrerequisiteRequirement(requires_request_body=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.FIELD_ADDITION,
            mutation_type=MutationType.UNEXPECTED_FIELD,
            rationale="Injecting extra fields (e.g. role, isAdmin) tests for mass assignment vulnerabilities.",
            expected_observation="Undeclared fields are ignored or rejected.",
        ),
        input_spec_template=InputSpecification(
            target_element="JSON Request Body",
            mutation_description="Inject unexpected properties into payload.",
            purpose="Detect unhandled mass assignment.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must not process or persist undeclared sensitive properties.",
            expected_status_codes=[200, 201, 400, 422],
            should_reject=False,
            security_goal="Prevent mass assignment vulnerabilities.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.HIGH,
        baseline_risk_level=RiskLevel.HIGH,
        tags=["request-body", "mass-assignment"],
    ),
    TestTemplate(
        template_id="BODY-003",
        name="Request Body Type Mutation",
        description="Verify API validates request body property data types.",
        category=SecurityTestCategory.INPUT_VALIDATION,
        subcategory="Body Type Validation",
        prerequisites=PrerequisiteRequirement(requires_request_body=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.TYPE_MUTATION,
            mutation_type=MutationType.MUTATE_TYPE,
            rationale="Mutating JSON property types (e.g. array for string) should trigger validation errors.",
            expected_observation="HTTP 400 Bad Request or 422 Unprocessable Entity response.",
        ),
        input_spec_template=InputSpecification(
            target_element="JSON Property",
            mutation_description="Substitute string property value with array or object.",
            purpose="Verify strict JSON property type checks.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must reject body payloads with invalid field types.",
            expected_status_codes=[400, 422],
            should_reject=True,
            security_goal="Prevent type confusion errors in request bodies.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["request-body", "type-safety"],
    ),
    TestTemplate(
        template_id="BODY-004",
        name="Request Body Enum Violation",
        description="Verify API rejects enum property values outside declared permitted sets.",
        category=SecurityTestCategory.INPUT_VALIDATION,
        subcategory="Enum Constraints",
        prerequisites=PrerequisiteRequirement(requires_request_body=True, requires_schema_constraints=True),
        strategy=TestStrategy(
            strategy_type=StrategyType.VALUE_SUBSTITUTION,
            mutation_type=MutationType.SUBSTITUTE,
            rationale="Enum fields must only accept values defined in schema specifications.",
            expected_observation="HTTP 400 Bad Request or 422 Unprocessable Entity response.",
        ),
        input_spec_template=InputSpecification(
            target_element="Enum Field",
            mutation_description="Supply an arbitrary string value not present in declared enum list.",
            purpose="Verify enum validation.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API must reject enum values outside the permitted list.",
            expected_status_codes=[400, 422],
            should_reject=True,
            security_goal="Enforce enum value constraints.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["request-body", "enum-validation"],
    ),

    # --- DATA EXPOSURE ---
    TestTemplate(
        template_id="DATA-001",
        name="Excessive Response Field Exposure Check",
        description="Verify endpoint responses do not expose excessive or sensitive data fields.",
        category=SecurityTestCategory.DATA_EXPOSURE,
        subcategory="Sensitive Data Exposure",
        prerequisites=PrerequisiteRequirement(),  # Always applicable
        strategy=TestStrategy(
            strategy_type=StrategyType.VALUE_SUBSTITUTION,
            mutation_type=MutationType.SUBSTITUTE,
            rationale="Responses should return only necessary fields and avoid exposing internal keys or hashes.",
            expected_observation="Response body contains only expected public fields.",
        ),
        input_spec_template=InputSpecification(
            target_element="Response Schema",
            mutation_description="Inspect successful response payloads for sensitive field names.",
            purpose="Identify potential excessive data exposure.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API response payload must not contain sensitive internal fields.",
            expected_status_codes=[200],
            should_reject=False,
            security_goal="Prevent sensitive data disclosure in responses.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_body=True),
        baseline_priority=Priority.MEDIUM,
        baseline_risk_level=RiskLevel.MEDIUM,
        tags=["data-exposure", "privacy"],
    ),

    # --- RATE / ABUSE CONTROL (Declarative Only) ---
    TestTemplate(
        template_id="RATE-001",
        name="Declarative Request Burst Strategy",
        description="Declarative test specification for evaluating rate limiting policy.",
        category=SecurityTestCategory.RATE_LIMITING,
        subcategory="Rate Control",
        prerequisites=PrerequisiteRequirement(),  # Always applicable
        strategy=TestStrategy(
            strategy_type=StrategyType.REPETITION,
            mutation_type=MutationType.BURST_SEQUENCE,
            rationale="Endpoints should enforce rate limits against rapid automated request bursts.",
            expected_observation="HTTP 429 Too Many Requests response after burst threshold.",
        ),
        input_spec_template=InputSpecification(
            target_element="Endpoint Route",
            mutation_description="Declarative template describing rapid sequential request execution.",
            purpose="Define rate limit evaluation criteria.",
        ),
        expected_behavior=ExpectedBehavior(
            description="The API should enforce rate limiting headers and status codes on bursts.",
            expected_status_codes=[429],
            should_reject=True,
            security_goal="Protect API availability against request bursts.",
        ),
        evidence_requirements=EvidenceRequirements(status_code=True, response_headers=True, response_time=True),
        baseline_priority=Priority.LOW,
        baseline_risk_level=RiskLevel.LOW,
        tags=["rate-limiting", "abuse-prevention"],
    ),
]


class TestCatalogue:
    """Immutable registry holding security test templates."""

    __test__ = False

    def __init__(self, templates: list[TestTemplate] | None = None) -> None:
        self._templates: dict[str, TestTemplate] = {}
        for t in templates or CATALOGUE_TEMPLATES:
            self._templates[t.template_id] = t

    def get_template(self, template_id: str) -> TestTemplate | None:
        """Retrieves a single template by ID."""
        return self._templates.get(template_id)

    def get_all_templates(self) -> list[TestTemplate]:
        """Returns all registered test templates, deterministically sorted by ID."""
        return sorted(list(self._templates.values()), key=lambda t: t.template_id)

    def get_templates_by_category(self, category: SecurityTestCategory) -> list[TestTemplate]:
        """Returns templates matching a given category."""
        return [t for t in self.get_all_templates() if t.category == category]


# Default global catalogue instance
catalogue_registry = TestCatalogue()
