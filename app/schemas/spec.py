from typing import Any
from pydantic import BaseModel, Field


class ApiMetadata(BaseModel):
    """General metadata for the API specification."""

    title: str
    version: str
    description: str | None = None
    terms_of_service: str | None = None
    contact: dict[str, Any] | None = None
    license: dict[str, Any] | None = None


class ServerVariable(BaseModel):
    """Server variable definition."""

    default: str
    enum: list[str] = Field(default_factory=list)
    description: str | None = None


class ServerInfo(BaseModel):
    """Server URL and environment info."""

    url: str
    description: str | None = None
    variables: dict[str, ServerVariable] = Field(default_factory=dict)


class SecurityScheme(BaseModel):
    """Declared OpenAPI security scheme."""

    type: str
    description: str | None = None
    name: str | None = None
    in_loc: str | None = Field(default=None, alias="in")
    scheme: str | None = None
    bearer_format: str | None = None
    flows: dict[str, Any] | None = None
    open_id_connect_url: str | None = None


class SchemaDefinition(BaseModel):
    """Rich normalized JSON/OpenAPI schema representation preserving full structure."""

    type: str | list[str] | None = None
    format: str | None = None
    title: str | None = None
    description: str | None = None
    default: Any | None = None
    enum: list[Any] | None = None
    example: Any | None = None
    properties: dict[str, "SchemaDefinition"] = Field(default_factory=dict)
    items: "SchemaDefinition | None" = None
    required: list[str] = Field(default_factory=list)
    additional_properties: Any | None = None
    nullable: bool | None = None
    minimum: float | None = None
    maximum: float | None = None
    min_length: int | None = None
    max_length: int | None = None
    pattern: str | None = None
    raw_schema: dict[str, Any] = Field(default_factory=dict)


SchemaDefinition.model_rebuild()


class NormalizedParameter(BaseModel):
    """Normalized endpoint parameter (path, query, header, cookie)."""

    name: str
    location: str  # path, query, header, cookie
    required: bool = False
    description: str | None = None
    schema_def: SchemaDefinition | None = None
    example: Any | None = None
    default: Any | None = None
    deprecated: bool = False


class MediaTypeContent(BaseModel):
    """Media type payload description."""

    media_type: str
    schema_def: SchemaDefinition | None = None
    example: Any | None = None
    examples: dict[str, Any] = Field(default_factory=dict)


class NormalizedRequestBody(BaseModel):
    """Normalized endpoint request body."""

    description: str | None = None
    required: bool = False
    content: dict[str, MediaTypeContent] = Field(default_factory=dict)


class NormalizedResponse(BaseModel):
    """Normalized response specification."""

    status_code: str
    description: str
    headers: dict[str, Any] = Field(default_factory=dict)
    content: dict[str, MediaTypeContent] = Field(default_factory=dict)


class NormalizedEndpoint(BaseModel):
    """Normalized API endpoint operation."""

    path: str
    method: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[NormalizedParameter] = Field(default_factory=list)
    request_body: NormalizedRequestBody | None = None
    responses: list[NormalizedResponse] = Field(default_factory=list)
    security: list[dict[str, list[str]]] = Field(default_factory=list)
    deprecated: bool = False


class NormalizedApiSpec(BaseModel):
    """Complete AutoRedTeam normalized API domain model."""

    metadata: ApiMetadata
    servers: list[ServerInfo] = Field(default_factory=list)
    security_schemes: dict[str, SecurityScheme] = Field(default_factory=dict)
    endpoints: list[NormalizedEndpoint] = Field(default_factory=list)
