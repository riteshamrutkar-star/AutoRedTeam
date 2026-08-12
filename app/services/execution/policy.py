from urllib.parse import urljoin, urlparse

from app.schemas.execution import PolicyDecision, RegisteredTarget
from app.schemas.generated_test import GeneratedSecurityTest
from app.services.execution.target_registry import validate_target_base_url


class ExecutionPolicy:
    """Centralized safety policy enforcing execution boundaries and SSRF protection."""

    def __init__(self, allowed_hosts: list[str] | None = None) -> None:
        self.allowed_hosts = allowed_hosts

    def evaluate_execution_request(
        self, target: RegisteredTarget | None, test: GeneratedSecurityTest
    ) -> PolicyDecision:
        """Evaluates whether an execution request is permitted by safety rules."""
        # 1. Target registration & availability check
        if not target:
            return PolicyDecision(
                allowed=False,
                reason="Target ID is not registered in target allowlist.",
                rule_violated="UNREGISTERED_TARGET",
            )

        if not target.enabled:
            return PolicyDecision(
                allowed=False,
                reason=f"Registered target '{target.target_id}' is currently disabled.",
                rule_violated="TARGET_DISABLED",
            )

        # 2. Re-validate target base URL
        try:
            validate_target_base_url(target.base_url, self.allowed_hosts or [])
        except Exception as exc:
            return PolicyDecision(
                allowed=False,
                reason=f"Target base URL validation failed: {exc}",
                rule_violated="INVALID_TARGET_BASE_URL",
            )

        # 3. Request Plan Method Check
        method = test.request_plan.http_method.upper()
        if method not in target.allowed_methods:
            return PolicyDecision(
                allowed=False,
                reason=f"HTTP method '{method}' is not in allowed target methods ({', '.join(target.allowed_methods)}).",
                rule_violated="DISALLOWED_HTTP_METHOD",
            )

        # 4. SSRF & URL-Escape Checks on Relative Path
        raw_path = test.request_plan.path or ""

        # Reject absolute URLs supplied in path
        if raw_path.startswith("http://") or raw_path.startswith("https://"):
            return PolicyDecision(
                allowed=False,
                reason="Absolute URLs in request plan path are strictly forbidden.",
                rule_violated="ABSOLUTE_URL_FORBIDDEN",
            )

        # Reject scheme-relative URLs (e.g. "//evil.com")
        if raw_path.startswith("//"):
            return PolicyDecision(
                allowed=False,
                reason="Scheme-relative URLs ('//...') are strictly forbidden.",
                rule_violated="SCHEME_RELATIVE_URL_FORBIDDEN",
            )

        # Reject authority changes / userinfo (@)
        if "@" in raw_path:
            return PolicyDecision(
                allowed=False,
                reason="Path containing userinfo or authority change ('@') is strictly forbidden.",
                rule_violated="AUTHORITY_CHANGE_FORBIDDEN",
            )

        # Reject path traversal (.. path segments)
        parts = [p for p in raw_path.split("/") if p]
        if ".." in parts:
            return PolicyDecision(
                allowed=False,
                reason="Path traversal segments ('..') are strictly forbidden.",
                rule_violated="PATH_TRAVERSAL_FORBIDDEN",
            )

        # 5. Re-validate Resolved Final Destination URL
        resolved_url = urljoin(target.base_url + "/", raw_path.lstrip("/"))
        parsed_final = urlparse(resolved_url)

        final_host = (parsed_final.hostname or "").lower()
        target_host = (urlparse(target.base_url).hostname or "").lower()

        if final_host != target_host:
            return PolicyDecision(
                allowed=False,
                reason=f"Resolved destination host '{final_host}' differs from registered target host '{target_host}'.",
                rule_violated="HOST_MISMATCH",
            )

        return PolicyDecision(allowed=True, reason="Execution request satisfies all safety policy rules.")
