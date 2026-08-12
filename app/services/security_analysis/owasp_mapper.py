from typing import Any

from app.core.config import settings
from app.schemas.finding import OWASPMapping

# Active positive detection rules exist for API1, API2, API3, API5 in Phase 6
ACTIVE_DETECTION_CATEGORIES = {"API1:2023", "API2:2023", "API3:2023", "API5:2023"}

OWASP_API_TOP_10_2023: dict[str, dict[str, Any]] = {
    "API1:2023": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "description": "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface for Object Level Access Control issues.",
        "has_active_detection_rule": True,
    },
    "API2:2023": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.",
        "has_active_detection_rule": True,
    },
    "API3:2023": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "description": "Lacking or improper authorization validation at the object property level leads to information exposure or unauthorized manipulation of object properties.",
        "has_active_detection_rule": True,
    },
    "API4:2023": {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "description": "Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage.",
        "has_active_detection_rule": False,
    },
    "API5:2023": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "description": "Complex access control policies with different roles, groups, and hierarchy levels make it difficult to manage function-level access control.",
        "has_active_detection_rule": True,
    },
    "API6:2023": {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": "APIs exposing business flows can harm the business if accessed automatically in an excessive or malicious manner.",
        "has_active_detection_rule": False,
    },
    "API7:2023": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
        "description": "Server-Side Request Forgery (SSRF) flaws occur when an API fetches a remote resource without validating user-supplied URI.",
        "has_active_detection_rule": False,
    },
    "API8:2023": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "description": "APIs and systems supporting them often have complex configurations. Misconfigurations include unpatched systems, verbose error messages, or improper CORS policies.",
        "has_active_detection_rule": False,
    },
    "API9:2023": {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "description": "APIs expose more endpoints than traditional web apps. Deprecated API versions often lack modern security controls.",
        "has_active_detection_rule": False,
    },
    "API10:2023": {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "description": "Developers tend to trust data received from third-party APIs more than user input.",
        "has_active_detection_rule": False,
    },
}


class OWASPMapper:
    """Registry and evidence-driven mapper for OWASP API Security Top 10 — 2023."""

    def __init__(self) -> None:
        self.taxonomy_version = settings.OWASP_API_TOP_10_VERSION

    def get_supported_taxonomy(self) -> dict[str, dict[str, Any]]:
        """Returns complete dictionary of OWASP API Security Top 10 2023 categories."""
        return OWASP_API_TOP_10_2023

    def map_category(
        self,
        category_id: str | None,
        rationale: str,
        secondary_categories: list[str] | None = None,
    ) -> OWASPMapping:
        """Constructs an OWASPMapping object for a verified category ID."""
        if not category_id or category_id not in OWASP_API_TOP_10_2023:
            return OWASPMapping(
                taxonomy=f"OWASP_API_TOP_10_{self.taxonomy_version}",
                category_id="NONE",
                category_name="None / Not Vulnerable",
                rationale=rationale,
                secondary_categories=secondary_categories or [],
            )

        cat_def = OWASP_API_TOP_10_2023[category_id]
        return OWASPMapping(
            taxonomy=f"OWASP_API_TOP_10_{self.taxonomy_version}",
            category_id=cat_def["id"],
            category_name=cat_def["name"],
            rationale=rationale,
            secondary_categories=secondary_categories or [],
        )
