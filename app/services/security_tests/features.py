from pydantic import BaseModel, Field

from app.schemas.spec import NormalizedEndpoint, NormalizedParameter, SchemaDefinition

IDENTIFIER_NAME_KEYWORDS = {"id", "uuid", "guid", "pk", "key"}


def is_identifier_candidate(param: NormalizedParameter) -> bool:
    """Determines if a parameter is a candidate for object identifier tests.

    Uses parameter location and schema format/type as primary signals,
    and parameter name as a secondary heuristic.
    """
    schema = param.schema_def
    schema_format = (schema.format or "").lower() if schema else ""
    schema_type = (schema.type or "") if schema else ""
    param_name = param.name.lower()

    # Primary signals: UUID/int64 format or path parameter with integer/string schema
    if schema_format in ("uuid", "int64", "guid"):
        return True

    if param.location == "path" and schema_type in ("string", "integer"):
        return True

    # Secondary heuristic: Name ends with or equals identifier keywords
    if any(param_name == kw or param_name.endswith(f"_{kw}") or param_name.endswith(f"-{kw}") for kw in IDENTIFIER_NAME_KEYWORDS):
        return True

    return False


def schema_has_constraints(schema: SchemaDefinition | None) -> bool:
    """Checks if a schema definition contains numeric, string, or enum constraints."""
    if not schema:
        return False

    if schema.minimum is not None or schema.maximum is not None:
        return True
    if schema.min_length is not None or schema.max_length is not None:
        return True
    if schema.pattern is not None or schema.enum is not None:
        return True

    # Check child properties recursively
    if schema.properties:
        return any(schema_has_constraints(prop) for prop in schema.properties.values())
    if schema.items:
        return schema_has_constraints(schema.items)

    return False


class EndpointFeatures(BaseModel):
    """Extracted feature metadata for an API endpoint operation."""

    has_declared_security: bool = False
    security_schemes: list[str] = Field(default_factory=list)
    has_path_params: bool = False
    has_query_params: bool = False
    has_header_params: bool = False
    has_request_body: bool = False
    has_schema_constraints: bool = False
    path_parameters: list[NormalizedParameter] = Field(default_factory=list)
    query_parameters: list[NormalizedParameter] = Field(default_factory=list)
    header_parameters: list[NormalizedParameter] = Field(default_factory=list)
    identifier_parameters: list[NormalizedParameter] = Field(default_factory=list)
    constrained_parameters: list[NormalizedParameter] = Field(default_factory=list)


def extract_endpoint_features(endpoint: NormalizedEndpoint) -> EndpointFeatures:
    """Extracts centralized structural and semantic features from a NormalizedEndpoint."""
    path_params: list[NormalizedParameter] = []
    query_params: list[NormalizedParameter] = []
    header_params: list[NormalizedParameter] = []
    id_params: list[NormalizedParameter] = []
    constrained_params: list[NormalizedParameter] = []
    has_constraints = False

    for param in endpoint.parameters:
        if param.location == "path":
            path_params.append(param)
        elif param.location == "query":
            query_params.append(param)
        elif param.location == "header":
            header_params.append(param)

        if is_identifier_candidate(param):
            id_params.append(param)

        if schema_has_constraints(param.schema_def):
            constrained_params.append(param)
            has_constraints = True

    # Check request body schema constraints
    req_body = endpoint.request_body
    has_body = req_body is not None and len(req_body.content) > 0
    if has_body and req_body:
        for media_type_content in req_body.content.values():
            if schema_has_constraints(media_type_content.schema_def):
                has_constraints = True

    # Check declared security requirements
    # Security is declared if endpoint.security is a non-empty list of dicts
    has_security = len(endpoint.security) > 0
    sec_schemes: list[str] = []
    for sec_dict in endpoint.security:
        sec_schemes.extend(sec_dict.keys())

    return EndpointFeatures(
        has_declared_security=has_security,
        security_schemes=sec_schemes,
        has_path_params=len(path_params) > 0,
        has_query_params=len(query_params) > 0,
        has_header_params=len(header_params) > 0,
        has_request_body=has_body,
        has_schema_constraints=has_constraints,
        path_parameters=path_params,
        query_parameters=query_params,
        header_parameters=header_params,
        identifier_parameters=id_params,
        constrained_parameters=constrained_params,
    )
