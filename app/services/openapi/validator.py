from typing import Any
from openapi_spec_validator import validate
from openapi_spec_validator.validation.exceptions import OpenAPIValidationError as SpecValidatorError

from app.core.exceptions import OpenAPIValidationError, UnsupportedSpecVersionError


def validate_openapi_spec(doc: dict[str, Any]) -> None:
    """Validates that doc is a structurally valid OpenAPI 3.x specification.

    Rejects Swagger 2.0 and non-OpenAPI 3.x specifications.
    """
    if "swagger" in doc:
        raise UnsupportedSpecVersionError(
            f"Swagger {doc['swagger']} is not supported. AutoRedTeam requires OpenAPI 3.x specifications."
        )

    openapi_version = doc.get("openapi")
    if not openapi_version or not str(openapi_version).startswith("3."):
        raise UnsupportedSpecVersionError(
            f"Unsupported specification version: '{openapi_version}'. Only OpenAPI 3.x specifications are supported."
        )

    if "info" not in doc or not isinstance(doc["info"], dict):
        raise OpenAPIValidationError("Missing required root field 'info' in OpenAPI specification.")

    if "title" not in doc["info"] or "version" not in doc["info"]:
        raise OpenAPIValidationError("OpenAPI 'info' object must contain 'title' and 'version'.")

    if "paths" not in doc or not isinstance(doc["paths"], dict):
        raise OpenAPIValidationError("Missing required root field 'paths' in OpenAPI specification.")

    # Validate against standard OpenAPI schema validator
    try:
        validate(doc)
    except SpecValidatorError as exc:
        raise OpenAPIValidationError(
            f"OpenAPI validation failed: {exc}",
            details={"path": list(exc.path) if hasattr(exc, "path") and exc.path else []},
        ) from exc
    except Exception as exc:
        # Fallback if spec validator encounters unhandled structural issue
        raise OpenAPIValidationError(f"OpenAPI schema validation error: {exc}") from exc
