import json
from typing import Any
from urllib.parse import urljoin

from app.core.config import settings
from app.core.exceptions import OpenAPIException
from app.schemas.execution import RegisteredTarget, RequestEvidence
from app.schemas.generated_test import GeneratedSecurityTest

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key"}


class RequestBuilderError(OpenAPIException):
    """Exception raised when HTTP request building or body sizing fails."""

    pass


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Returns a copy of headers with sensitive header values redacted."""
    redacted = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def redact_body(body: Any) -> Any:
    """Redacts obvious credential keys inside body objects if present."""
    if isinstance(body, dict):
        redacted_dict = {}
        for k, v in body.items():
            if k.lower() in ("password", "secret", "token", "access_token", "api_key"):
                redacted_dict[k] = "[REDACTED]"
            else:
                redacted_dict[k] = redact_body(v)
        return redacted_dict
    return body


def build_http_request_data(
    target: RegisteredTarget, test: GeneratedSecurityTest
) -> tuple[str, str, dict[str, Any], dict[str, str], Any, RequestEvidence]:
    """Converts a GeneratedSecurityTest's RequestPlan into concrete HTTP client request arguments.

    Enforces request body size limits before sending and resolves symbolic authentication references.
    """
    plan = test.request_plan
    path_relative = (plan.path or "/").lstrip("/")
    full_url = urljoin(target.base_url + "/", path_relative)

    # 1. Resolve Query Parameters
    query_params = plan.query_parameters or {}

    # 2. Resolve Headers
    headers = dict(plan.headers or {})

    # 3. Resolve Symbolic Authentication State
    auth_state = plan.auth_state or test.authentication_context
    if auth_state:
        mapped_auth = target.auth_symbolic_map.get(auth_state)
        if mapped_auth:
            headers["Authorization"] = mapped_auth

    # 4. Process Request Body & Enforce Pre-flight Size Limits
    body_data = plan.request_body
    body_bytes_len = 0
    formatted_body_payload: Any = None

    if body_data is not None:
        if isinstance(body_data, (dict, list)):
            body_bytes = json.dumps(body_data).encode("utf-8")
            formatted_body_payload = body_data
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
        elif isinstance(body_data, str):
            body_bytes = body_data.encode("utf-8")
            formatted_body_payload = body_data
        else:
            body_bytes = str(body_data).encode("utf-8")
            formatted_body_payload = str(body_data)

        body_bytes_len = len(body_bytes)
        if body_bytes_len > settings.MAX_REQUEST_BODY_BYTES:
            raise RequestBuilderError(
                f"Request body size ({body_bytes_len} bytes) exceeds configured MAX_REQUEST_BODY_BYTES limit ({settings.MAX_REQUEST_BODY_BYTES} bytes)."
            )

    # 5. Build Clean Request Evidence (without full_url or un-redacted credentials)
    request_evidence = RequestEvidence(
        method=plan.http_method.upper(),
        target_id=target.target_id,
        path=f"/{path_relative}",
        query_parameters=query_params,
        headers=redact_headers(headers),
        body=redact_body(formatted_body_payload),
        auth_state=auth_state,
    )

    return plan.http_method.upper(), full_url, query_params, headers, formatted_body_payload, request_evidence
