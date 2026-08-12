from datetime import datetime, timezone
import time
from urllib.parse import urlparse
import uuid
import httpx

from app.core.config import settings
from app.schemas.execution import (
    ExecutionOptions,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    PolicyDecision,
    ResponseEvidence,
)
from app.services.execution.policy import ExecutionPolicy
from app.services.execution.request_builder import build_http_request_data, redact_headers
from app.services.execution.target_registry import TargetRegistry, target_registry


class ExecutionEngine:
    """Synchronous single-test execution engine enforcing controlled safety policies and bounded response streaming."""

    def __init__(
        self,
        registry: TargetRegistry | None = None,
        policy: ExecutionPolicy | None = None,
    ) -> None:
        self.registry = registry or target_registry
        self.policy = policy or ExecutionPolicy(allowed_hosts=self.registry.allowed_hosts)

    async def execute_test(
        self,
        request: ExecutionRequest,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> ExecutionResult:
        """Executes a single GeneratedSecurityTest against a registered controlled target."""
        execution_id = f"exec_{uuid.uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()

        options = request.options or ExecutionOptions(
            timeout_seconds=settings.EXECUTION_TIMEOUT_SECONDS,
            max_response_bytes=settings.MAX_RESPONSE_BYTES,
            follow_redirects=settings.FOLLOW_REDIRECTS,
        )

        target = self.registry.get_target(request.target_id)
        test = request.generated_test

        # 1. Evaluate Safety Policy
        decision = self.policy.evaluate_execution_request(target, test)
        if not decision.allowed:
            completed_at = datetime.now(timezone.utc).isoformat()
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ExecutionResult(
                execution_id=execution_id,
                target_id=request.target_id,
                generated_test_id=test.generated_test_id,
                status=ExecutionStatus.BLOCKED,
                started_at=now_utc,
                completed_at=completed_at,
                duration_ms=duration_ms,
                policy_decision=decision,
                error=decision.reason,
            )

        assert target is not None

        # 2. Build Request Data
        try:
            method, full_url, query_params, headers, body_payload, request_evidence = build_http_request_data(target, test)
        except Exception as exc:
            completed_at = datetime.now(timezone.utc).isoformat()
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ExecutionResult(
                execution_id=execution_id,
                target_id=request.target_id,
                generated_test_id=test.generated_test_id,
                status=ExecutionStatus.FAILED,
                started_at=now_utc,
                completed_at=completed_at,
                duration_ms=duration_ms,
                policy_decision=decision,
                error=f"Request building failed: {exc}",
            )

        # 3. Streamed HTTP Execution with Bounded Response Byte Caps
        status = ExecutionStatus.COMPLETED
        error_msg: str | None = None
        response_evidence: ResponseEvidence | None = None

        client_kwargs: dict = {
            "timeout": float(options.timeout_seconds),
            "follow_redirects": options.follow_redirects,
        }
        if transport:
            client_kwargs["transport"] = transport

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                req = client.build_request(
                    method=method,
                    url=full_url,
                    params=query_params,
                    headers=headers,
                    json=body_payload if isinstance(body_payload, (dict, list)) else None,
                    content=body_payload if isinstance(body_payload, (str, bytes)) else None,
                )

                resp = await client.send(req, stream=True)

                # Bounded streamed chunk reading
                accumulated_bytes = bytearray()
                truncated = False
                total_bytes_read = 0

                async for chunk in resp.aiter_bytes():
                    chunk_len = len(chunk)
                    total_bytes_read += chunk_len
                    if len(accumulated_bytes) + chunk_len > options.max_response_bytes:
                        remaining_allowed = options.max_response_bytes - len(accumulated_bytes)
                        if remaining_allowed > 0:
                            accumulated_bytes.extend(chunk[:remaining_allowed])
                        truncated = True
                        break
                    else:
                        accumulated_bytes.extend(chunk)

                await resp.aclose()

                resp_duration = round((time.perf_counter() - start_time) * 1000, 2)
                resp_text = accumulated_bytes.decode("utf-8", errors="replace")
                final_host = (urlparse(str(resp.url)).hostname or "").lower()

                response_evidence = ResponseEvidence(
                    status_code=resp.status_code,
                    headers=redact_headers(dict(resp.headers)),
                    body=resp_text,
                    body_size=total_bytes_read,
                    duration_ms=resp_duration,
                    final_url_host=final_host,
                    truncated=truncated,
                )

        except httpx.TimeoutException as exc:
            status = ExecutionStatus.TIMEOUT
            error_msg = f"HTTP execution timed out after {options.timeout_seconds} seconds."
        except httpx.ConnectError as exc:
            status = ExecutionStatus.FAILED
            error_msg = f"Could not connect to target '{target.target_id}' at base URL '{target.base_url}': {exc}"
        except Exception as exc:
            status = ExecutionStatus.FAILED
            error_msg = f"HTTP execution error: {exc}"

        completed_at = datetime.now(timezone.utc).isoformat()
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ExecutionResult(
            execution_id=execution_id,
            target_id=target.target_id,
            generated_test_id=test.generated_test_id,
            status=status,
            started_at=now_utc,
            completed_at=completed_at,
            duration_ms=duration_ms,
            request_evidence=request_evidence,
            response_evidence=response_evidence,
            policy_decision=decision,
            error=error_msg,
        )
