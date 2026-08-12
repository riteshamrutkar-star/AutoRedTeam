from urllib.parse import urlparse

from app.core.config import settings
from app.core.exceptions import OpenAPIException
from app.schemas.execution import RegisteredTarget


class TargetRegistryError(OpenAPIException):
    """Exception raised when target registry fails validation or target lookup."""

    pass


def validate_target_base_url(url: str, allowed_hosts: list[str]) -> str:
    """Validates base URL scheme, host scope, and absence of embedded credentials."""
    if not url or not url.strip():
        raise TargetRegistryError("Target base URL cannot be empty.")

    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise TargetRegistryError(
            f"Invalid target URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed."
        )

    if parsed.username or parsed.password:
        raise TargetRegistryError(
            "Embedded credentials (user:pass@host) are strictly forbidden in target base URLs."
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise TargetRegistryError("Target base URL must contain a valid hostname.")

    # Validate host against allowed network scope
    if allowed_hosts and hostname not in allowed_hosts:
        raise TargetRegistryError(
            f"Target host '{hostname}' is outside the explicitly allowed network scope ({', '.join(allowed_hosts)})."
        )

    return url.strip().rstrip("/")


class TargetRegistry:
    """Registry maintaining explicitly allowed, controlled targets."""

    def __init__(self, allowed_hosts: list[str] | None = None) -> None:
        raw_hosts = (settings.ALLOWED_TARGET_HOSTS or "").split(",")
        self.allowed_hosts = [h.strip().lower() for h in (allowed_hosts or raw_hosts) if h.strip()]
        self._targets: dict[str, RegisteredTarget] = {}
        self._initialize_default_targets()

    def _initialize_default_targets(self) -> None:
        default_defs = [
            RegisteredTarget(
                target_id="vampi-local",
                name="VAmPI Vulnerable API",
                description="Controlled local VAmPI vulnerability test target.",
                target_type="vampi",
                base_url=settings.TARGET_VAMPI_URL,
                environment="local",
                auth_symbolic_map={"TEST_TOKEN_USER": "Bearer mock_user_token", "TEST_TOKEN_ADMIN": "Bearer mock_admin_token"},
            ),
            RegisteredTarget(
                target_id="juice-shop-local",
                name="OWASP Juice Shop API",
                description="Controlled local Juice Shop test target.",
                target_type="juice-shop",
                base_url=settings.TARGET_JUICE_SHOP_URL,
                environment="local",
                auth_symbolic_map={"TEST_TOKEN_USER": "Bearer mock_juice_token"},
            ),
            RegisteredTarget(
                target_id="dvwa-local",
                name="DVWA Local Target",
                description="Controlled local DVWA test target.",
                target_type="dvwa",
                base_url=settings.TARGET_DVWA_URL,
                environment="local",
                auth_symbolic_map={"TEST_TOKEN_USER": "Bearer mock_dvwa_token"},
            ),
        ]

        for target in default_defs:
            try:
                # Startup validation
                target.base_url = validate_target_base_url(target.base_url, self.allowed_hosts)
                self._targets[target.target_id] = target
            except Exception:
                # If target base URL points to un-configured host during startup, register as disabled
                target.enabled = False
                self._targets[target.target_id] = target

    def register_target(self, target: RegisteredTarget) -> None:
        """Registers a new controlled target after validating its base URL."""
        target.base_url = validate_target_base_url(target.base_url, self.allowed_hosts)
        self._targets[target.target_id] = target

    def get_target(self, target_id: str) -> RegisteredTarget | None:
        """Retrieves a registered target by ID."""
        return self._targets.get(target_id)

    def list_targets(self) -> list[RegisteredTarget]:
        """Returns all registered targets sorted by target_id."""
        return sorted(list(self._targets.values()), key=lambda t: t.target_id)


# Default global target registry instance
target_registry = TargetRegistry()
