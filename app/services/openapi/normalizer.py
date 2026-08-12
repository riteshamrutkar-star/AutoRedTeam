from typing import Any

from app.schemas.spec import (
    ApiMetadata,
    MediaTypeContent,
    NormalizedApiSpec,
    NormalizedEndpoint,
    NormalizedParameter,
    NormalizedRequestBody,
    NormalizedResponse,
    SchemaDefinition,
    SecurityScheme,
    ServerInfo,
    ServerVariable,
)
from app.services.openapi.loader import load_spec_from_bytes
from app.services.openapi.resolver import resolve_local_references
from app.services.openapi.validator import validate_openapi_spec

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


def parse_schema_def(schema: dict[str, Any] | None) -> SchemaDefinition | None:
    """Parses an OpenAPI schema dict into a rich, structured SchemaDefinition."""
    if not isinstance(schema, dict) or not schema:
        return None

    # Handle properties
    props: dict[str, SchemaDefinition] = {}
    raw_props = schema.get("properties")
    if isinstance(raw_props, dict):
        for prop_name, prop_schema in raw_props.items():
            parsed_prop = parse_schema_def(prop_schema)
            if parsed_prop:
                props[prop_name] = parsed_prop

    # Handle items (for arrays)
    items_def: SchemaDefinition | None = None
    raw_items = schema.get("items")
    if isinstance(raw_items, dict):
        items_def = parse_schema_def(raw_items)

    required_list = schema.get("required", [])
    if not isinstance(required_list, list):
        required_list = []

    return SchemaDefinition(
        type=schema.get("type"),
        format=schema.get("format"),
        title=schema.get("title"),
        description=schema.get("description"),
        default=schema.get("default"),
        enum=schema.get("enum") if isinstance(schema.get("enum"), list) else None,
        example=schema.get("example"),
        properties=props,
        items=items_def,
        required=required_list,
        additional_properties=schema.get("additionalProperties"),
        nullable=schema.get("nullable"),
        minimum=schema.get("minimum"),
        maximum=schema.get("maximum"),
        min_length=schema.get("minLength"),
        max_length=schema.get("maxLength"),
        pattern=schema.get("pattern"),
        raw_schema=schema,
    )


def normalize_openapi_spec(doc: dict[str, Any]) -> NormalizedApiSpec:
    """Validates, dereferences, and converts an OpenAPI dictionary into NormalizedApiSpec."""
    # 1. Structural Validation
    validate_openapi_spec(doc)

    # 2. Local Pointer Dereferencing
    resolved_doc = resolve_local_references(doc)

    # 3. Metadata Extraction
    info_dict = resolved_doc.get("info", {})
    metadata = ApiMetadata(
        title=info_dict.get("title", "Untitled API"),
        version=str(info_dict.get("version", "1.0.0")),
        description=info_dict.get("description"),
        terms_of_service=info_dict.get("termsOfService"),
        contact=info_dict.get("contact") if isinstance(info_dict.get("contact"), dict) else None,
        license=info_dict.get("license") if isinstance(info_dict.get("license"), dict) else None,
    )

    # 4. Server Info Extraction
    servers: list[ServerInfo] = []
    for srv in resolved_doc.get("servers", []):
        if isinstance(srv, dict) and "url" in srv:
            vars_dict: dict[str, ServerVariable] = {}
            if isinstance(srv.get("variables"), dict):
                for var_name, var_info in srv["variables"].items():
                    if isinstance(var_info, dict) and "default" in var_info:
                        vars_dict[var_name] = ServerVariable(
                            default=str(var_info["default"]),
                            enum=var_info.get("enum", []),
                            description=var_info.get("description"),
                        )
            servers.append(
                ServerInfo(
                    url=srv["url"],
                    description=srv.get("description"),
                    variables=vars_dict,
                )
            )

    # 5. Security Schemes Extraction
    security_schemes: dict[str, SecurityScheme] = {}
    components = resolved_doc.get("components", {})
    if isinstance(components, dict):
        raw_schemes = components.get("securitySchemes", {})
        if isinstance(raw_schemes, dict):
            for name, scheme_data in raw_schemes.items():
                if isinstance(scheme_data, dict) and "type" in scheme_data:
                    security_schemes[name] = SecurityScheme(
                        type=scheme_data["type"],
                        description=scheme_data.get("description"),
                        name=scheme_data.get("name"),
                        in_loc=scheme_data.get("in"),
                        scheme=scheme_data.get("scheme"),
                        bearer_format=scheme_data.get("bearerFormat"),
                        flows=scheme_data.get("flows") if isinstance(scheme_data.get("flows"), dict) else None,
                        open_id_connect_url=scheme_data.get("openIdConnectUrl"),
                    )

    # Global Security Requirements
    global_security = resolved_doc.get("security", [])
    if not isinstance(global_security, list):
        global_security = []

    # 6. Endpoints & Operations Normalization
    endpoints: list[NormalizedEndpoint] = []
    paths_dict = resolved_doc.get("paths", {})

    if isinstance(paths_dict, dict):
        for path_str, path_item in paths_dict.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters
            path_level_params = path_item.get("parameters", [])
            if not isinstance(path_level_params, list):
                path_level_params = []

            for method_str, op_dict in path_item.items():
                if method_str.lower() not in HTTP_METHODS or not isinstance(op_dict, dict):
                    continue

                # Merge path-level and operation-level parameters
                op_level_params = op_dict.get("parameters", [])
                if not isinstance(op_level_params, list):
                    op_level_params = []

                merged_param_map: dict[tuple[str, str], dict[str, Any]] = {}
                for p in path_level_params:
                    if isinstance(p, dict) and "name" in p and "in" in p:
                        merged_param_map[(p["name"], p["in"])] = p
                for p in op_level_params:
                    if isinstance(p, dict) and "name" in p and "in" in p:
                        # Operation parameter overrides path parameter
                        merged_param_map[(p["name"], p["in"])] = p

                norm_params: list[NormalizedParameter] = []
                for p_dict in merged_param_map.values():
                    schema_obj = parse_schema_def(p_dict.get("schema"))
                    norm_params.append(
                        NormalizedParameter(
                            name=p_dict["name"],
                            location=p_dict["in"],
                            required=bool(p_dict.get("required", p_dict["in"] == "path")),
                            description=p_dict.get("description"),
                            schema_def=schema_obj,
                            example=p_dict.get("example"),
                            default=p_dict.get("default"),
                            deprecated=bool(p_dict.get("deprecated", False)),
                        )
                    )

                # Request Body Normalization
                norm_req_body: NormalizedRequestBody | None = None
                raw_req_body = op_dict.get("requestBody")
                if isinstance(raw_req_body, dict):
                    body_content_map: dict[str, MediaTypeContent] = {}
                    raw_content = raw_req_body.get("content", {})
                    if isinstance(raw_content, dict):
                        for m_type, m_data in raw_content.items():
                            if isinstance(m_data, dict):
                                body_content_map[m_type] = MediaTypeContent(
                                    media_type=m_type,
                                    schema_def=parse_schema_def(m_data.get("schema")),
                                    example=m_data.get("example"),
                                    examples=m_data.get("examples") if isinstance(m_data.get("examples"), dict) else {},
                                )
                    norm_req_body = NormalizedRequestBody(
                        description=raw_req_body.get("description"),
                        required=bool(raw_req_body.get("required", False)),
                        content=body_content_map,
                    )

                # Response Definitions Normalization
                norm_responses: list[NormalizedResponse] = []
                raw_responses = op_dict.get("responses", {})
                if isinstance(raw_responses, dict):
                    for status_code, resp_data in raw_responses.items():
                        if isinstance(resp_data, dict):
                            resp_content_map: dict[str, MediaTypeContent] = {}
                            raw_resp_content = resp_data.get("content", {})
                            if isinstance(raw_resp_content, dict):
                                for m_type, m_data in raw_resp_content.items():
                                    if isinstance(m_data, dict):
                                        resp_content_map[m_type] = MediaTypeContent(
                                            media_type=m_type,
                                            schema_def=parse_schema_def(m_data.get("schema")),
                                            example=m_data.get("example"),
                                            examples=m_data.get("examples") if isinstance(m_data.get("examples"), dict) else {},
                                        )
                            norm_responses.append(
                                NormalizedResponse(
                                    status_code=str(status_code),
                                    description=str(resp_data.get("description", "")),
                                    headers=resp_data.get("headers") if isinstance(resp_data.get("headers"), dict) else {},
                                    content=resp_content_map,
                                )
                            )

                # Security Semantics: Global vs Operation Override
                if "security" in op_dict and isinstance(op_dict["security"], list):
                    effective_security = op_dict["security"]
                else:
                    effective_security = global_security

                endpoints.append(
                    NormalizedEndpoint(
                        path=path_str,
                        method=method_str.upper(),
                        operation_id=op_dict.get("operationId"),
                        summary=op_dict.get("summary"),
                        description=op_dict.get("description"),
                        tags=op_dict.get("tags") if isinstance(op_dict.get("tags"), list) else [],
                        parameters=norm_params,
                        request_body=norm_req_body,
                        responses=norm_responses,
                        security=effective_security,
                        deprecated=bool(op_dict.get("deprecated", False)),
                    )
                )

    return NormalizedApiSpec(
        metadata=metadata,
        servers=servers,
        security_schemes=security_schemes,
        endpoints=endpoints,
    )


def process_spec_bytes(content: bytes, filename: str | None = None) -> NormalizedApiSpec:
    """Convenience pipeline function: load bytes -> normalize -> return NormalizedApiSpec."""
    doc = load_spec_from_bytes(content, filename)
    return normalize_openapi_spec(doc)
