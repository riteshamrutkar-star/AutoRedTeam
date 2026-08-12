import re
from app.schemas.security_test import (
    ApplicableTestResult,
    InputSpecification,
    TargetLocation,
    TestTarget,
    TestTemplate,
)
from app.schemas.spec import NormalizedApiSpec, NormalizedEndpoint
from app.services.security_tests.catalogue import TestCatalogue, catalogue_registry
from app.services.security_tests.features import EndpointFeatures, extract_endpoint_features


def sanitize_id_part(text: str) -> str:
    """Sanitizes strings for clean, deterministic instance ID formatting."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", text).strip("_")


class ApplicabilityEngine:
    """Evaluates OpenAPI specification endpoints against test catalogue prerequisites.

    Produces deterministic, endpoint-specific ApplicableTestResult instances
    without mutating underlying catalogue templates.
    """

    def __init__(self, catalogue: TestCatalogue | None = None) -> None:
        self.catalogue = catalogue or catalogue_registry

    def evaluate_endpoint(self, endpoint: NormalizedEndpoint) -> list[ApplicableTestResult]:
        """Evaluates a single endpoint and returns all applicable test instances."""
        features = extract_endpoint_features(endpoint)
        results: list[ApplicableTestResult] = []

        for template in self.catalogue.get_all_templates():
            reasons = self._check_prerequisites(template, features)
            if reasons is None:
                # Prerequisites not satisfied
                continue

            # Instantiate test instances for this template on this endpoint
            instances = self._instantiate_test_results(template, endpoint, features, reasons)
            results.extend(instances)

        return results

    def evaluate_spec(self, spec: NormalizedApiSpec) -> list[ApplicableTestResult]:
        """Evaluates a complete NormalizedApiSpec deterministically."""
        all_results: list[ApplicableTestResult] = []

        # Sort endpoints deterministically by path then method
        sorted_endpoints = sorted(spec.endpoints, key=lambda e: (e.path, e.method))

        for endpoint in sorted_endpoints:
            endpoint_results = self.evaluate_endpoint(endpoint)
            all_results.extend(endpoint_results)

        # Final deterministic sort across all results
        all_results.sort(
            key=lambda r: (
                r.target.path,
                r.target.http_method,
                r.template_id,
                r.target.parameter_name or "",
                r.target.field_path or "",
            )
        )
        return all_results

    def _check_prerequisites(
        self, template: TestTemplate, features: EndpointFeatures
    ) -> list[str] | None:
        """Checks template prerequisites against endpoint features.

        Returns a list of reasons if applicable, or None if not applicable.
        """
        prereqs = template.prerequisites
        reasons: list[str] = []

        if prereqs.requires_auth_declared:
            if not features.has_declared_security:
                return None
            sec_names = ", ".join(features.security_schemes) if features.security_schemes else "declared security"
            reasons.append(f"Endpoint declares security requirements ({sec_names})")

        if prereqs.requires_path_params:
            if not features.has_path_params:
                return None
            reasons.append("Endpoint contains path parameters")

        if prereqs.requires_query_params:
            if not features.has_query_params:
                return None
            reasons.append("Endpoint contains query parameters")

        if prereqs.requires_request_body:
            if not features.has_request_body:
                return None
            reasons.append("Endpoint accepts a request body payload")

        if prereqs.requires_schema_constraints:
            if not features.has_schema_constraints:
                return None
            reasons.append("Endpoint schema defines numerical, string, or enum constraints")

        if prereqs.requires_identifier_candidate:
            if len(features.identifier_parameters) == 0:
                return None
            id_names = ", ".join(p.name for p in features.identifier_parameters)
            reasons.append(f"Endpoint defines identifier candidate parameter(s): [{id_names}]")

        # If no specific prerequisites were set or all passed
        if not reasons:
            reasons.append("Test template is generally applicable to all API endpoints")

        return reasons

    def _instantiate_test_results(
        self,
        template: TestTemplate,
        endpoint: NormalizedEndpoint,
        features: EndpointFeatures,
        reasons: list[str],
    ) -> list[ApplicableTestResult]:
        """Instantiates endpoint-specific ApplicableTestResult instances."""
        results: list[ApplicableTestResult] = []
        path_clean = sanitize_id_part(endpoint.path)
        method = endpoint.method.upper()

        prereqs = template.prerequisites

        # Parameter-specific tests
        if prereqs.requires_identifier_candidate:
            for param in features.identifier_parameters:
                instance_id = f"{path_clean}_{method}_{template.template_id}_{sanitize_id_part(param.name)}"
                loc = TargetLocation.PATH if param.location == "path" else TargetLocation.QUERY
                results.append(
                    ApplicableTestResult(
                        instance_id=instance_id,
                        template_id=template.template_id,
                        name=f"{template.name} ({param.name})",
                        category=template.category,
                        subcategory=template.subcategory,
                        target=TestTarget(
                            path=endpoint.path,
                            http_method=method,
                            target_location=loc,
                            parameter_name=param.name,
                        ),
                        strategy=template.strategy,
                        input_spec=InputSpecification(
                            target_element=f"Parameter '{param.name}' ({param.location})",
                            mutation_description=template.input_spec_template.mutation_description,
                            source_description=template.input_spec_template.source_description,
                            purpose=template.input_spec_template.purpose,
                        ),
                        expected_behavior=template.expected_behavior,
                        evidence_requirements=template.evidence_requirements,
                        priority=template.baseline_priority,
                        risk_level=template.baseline_risk_level,
                        applicability_reasons=reasons,
                        tags=template.tags,
                    )
                )
        elif prereqs.requires_query_params and not prereqs.requires_request_body:
            for param in features.query_parameters:
                instance_id = f"{path_clean}_{method}_{template.template_id}_{sanitize_id_part(param.name)}"
                results.append(
                    ApplicableTestResult(
                        instance_id=instance_id,
                        template_id=template.template_id,
                        name=f"{template.name} ({param.name})",
                        category=template.category,
                        subcategory=template.subcategory,
                        target=TestTarget(
                            path=endpoint.path,
                            http_method=method,
                            target_location=TargetLocation.QUERY,
                            parameter_name=param.name,
                        ),
                        strategy=template.strategy,
                        input_spec=InputSpecification(
                            target_element=f"Query parameter '{param.name}'",
                            mutation_description=template.input_spec_template.mutation_description,
                            source_description=template.input_spec_template.source_description,
                            purpose=template.input_spec_template.purpose,
                        ),
                        expected_behavior=template.expected_behavior,
                        evidence_requirements=template.evidence_requirements,
                        priority=template.baseline_priority,
                        risk_level=template.baseline_risk_level,
                        applicability_reasons=reasons,
                        tags=template.tags,
                    )
                )
        elif prereqs.requires_request_body:
            instance_id = f"{path_clean}_{method}_{template.template_id}_body"
            results.append(
                ApplicableTestResult(
                    instance_id=instance_id,
                    template_id=template.template_id,
                    name=f"{template.name} (Request Body)",
                    category=template.category,
                    subcategory=template.subcategory,
                    target=TestTarget(
                        path=endpoint.path,
                        http_method=method,
                        target_location=TargetLocation.REQUEST_BODY,
                    ),
                    strategy=template.strategy,
                    input_spec=template.input_spec_template,
                    expected_behavior=template.expected_behavior,
                    evidence_requirements=template.evidence_requirements,
                    priority=template.baseline_priority,
                    risk_level=template.baseline_risk_level,
                    applicability_reasons=reasons,
                    tags=template.tags,
                )
            )
        else:
            # Endpoint-level test (Authentication, Rate Limiting, HTTP Method, Data Exposure)
            instance_id = f"{path_clean}_{method}_{template.template_id}"
            target_loc = TargetLocation.AUTHENTICATION if template.category == "AUTHENTICATION" else TargetLocation.ENDPOINT
            results.append(
                ApplicableTestResult(
                    instance_id=instance_id,
                    template_id=template.template_id,
                    name=template.name,
                    category=template.category,
                    subcategory=template.subcategory,
                    target=TestTarget(
                        path=endpoint.path,
                        http_method=method,
                        target_location=target_loc,
                    ),
                    strategy=template.strategy,
                    input_spec=template.input_spec_template,
                    expected_behavior=template.expected_behavior,
                    evidence_requirements=template.evidence_requirements,
                    priority=template.baseline_priority,
                    risk_level=template.baseline_risk_level,
                    applicability_reasons=reasons,
                    tags=template.tags,
                )
            )

        return results


# Default global applicability engine instance
applicability_engine = ApplicabilityEngine()
