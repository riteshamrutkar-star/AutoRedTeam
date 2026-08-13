from app.schemas.evaluation import CoverageItem, CoverageMetrics, MetricStatus
from app.schemas.execution import ExecutionResult
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec
from app.services.security_tests.applicability import ApplicabilityEngine
from app.services.security_tests.catalogue import catalogue_registry


def compute_coverage(
    spec: NormalizedApiSpec,
    generated_tests: list[GeneratedSecurityTest],
    execution_results: list[ExecutionResult],
) -> CoverageMetrics:
    """Computes spec-relative coverage metrics over unique set identities."""

    # Map executed test IDs to generated tests
    executed_gen_test_ids = {
        r.generated_test_id for r in execution_results if r.generated_test_id
    }
    executed_tests = [
        t for t in generated_tests if t.generated_test_id in executed_gen_test_ids
    ]
    if not executed_tests and generated_tests:
        executed_tests = generated_tests

    # 1. Endpoint Coverage (unique paths)
    total_endpoints = {ep.path for ep in spec.endpoints}
    tested_endpoints = {t.endpoint_target for t in executed_tests}
    denom_ep = len(total_endpoints)
    num_ep = len(tested_endpoints.intersection(total_endpoints))
    ep_cov = CoverageItem(
        numerator=num_ep,
        denominator=denom_ep,
        percentage=round((num_ep / denom_ep) * 100.0, 2) if denom_ep > 0 else None,
        status=MetricStatus.COMPUTED if denom_ep > 0 else MetricStatus.UNDEFINED,
        reason=None if denom_ep > 0 else "Specification has 0 endpoints.",
    )

    # 2. Method Coverage (unique path + method pairs)
    total_methods = {(ep.path, ep.method.upper()) for ep in spec.endpoints}
    tested_methods = {(t.endpoint_target, t.http_method.upper()) for t in executed_tests}
    denom_m = len(total_methods)
    num_m = len(tested_methods.intersection(total_methods))
    m_cov = CoverageItem(
        numerator=num_m,
        denominator=denom_m,
        percentage=round((num_m / denom_m) * 100.0, 2) if denom_m > 0 else None,
        status=MetricStatus.COMPUTED if denom_m > 0 else MetricStatus.UNDEFINED,
    )

    # 3. Parameter Coverage (unique parameters declared in spec)
    spec_params = set()
    for ep in spec.endpoints:
        for p in ep.parameters:
            spec_params.add((ep.path, ep.method.upper(), p.name, p.location.upper()))

    tested_params = set()
    for t in executed_tests:
        if t.input_mutations:
            for mut in t.input_mutations:
                loc = mut.location.value if hasattr(mut.location, "value") else str(mut.location)
                if loc.upper() in ("QUERY", "PATH", "HEADER", "COOKIE"):
                    tested_params.add((t.endpoint_target, t.http_method.upper(), mut.target, loc.upper()))

    denom_p = len(spec_params)
    num_p = len(tested_params.intersection(spec_params))
    p_cov = CoverageItem(
        numerator=num_p,
        denominator=denom_p,
        percentage=round((num_p / denom_p) * 100.0, 2) if denom_p > 0 else None,
        status=MetricStatus.COMPUTED if denom_p > 0 else MetricStatus.NOT_APPLICABLE,
        reason=None if denom_p > 0 else "No parameters declared in API specification.",
    )

    # 4. Body Field Coverage
    spec_fields = set()
    for ep in spec.endpoints:
        if ep.request_body and ep.request_body.content:
            for mt, media in ep.request_body.content.items():
                if media.schema_def and media.schema_def.properties:
                    for prop_name in media.schema_def.properties.keys():
                        spec_fields.add((ep.path, ep.method.upper(), prop_name))

    tested_fields = set()
    for t in executed_tests:
        if t.input_mutations:
            for mut in t.input_mutations:
                loc = mut.location.value if hasattr(mut.location, "value") else str(mut.location)
                if loc.upper() == "BODY":
                    tested_fields.add((t.endpoint_target, t.http_method.upper(), mut.target))

    denom_f = len(spec_fields)
    num_f = len(tested_fields.intersection(spec_fields))
    f_cov = CoverageItem(
        numerator=num_f,
        denominator=denom_f,
        percentage=round((num_f / denom_f) * 100.0, 2) if denom_f > 0 else None,
        status=MetricStatus.COMPUTED if denom_f > 0 else MetricStatus.NOT_APPLICABLE,
        reason=None if denom_f > 0 else "No request body fields declared in API specification.",
    )

    # 5. Test Template Coverage (relative to applicable templates for spec)
    app_engine = ApplicabilityEngine()
    app_results = app_engine.evaluate_spec(spec)
    applicable_templates = {r.template_id for r in app_results}
    executed_templates = {t.template_id for t in executed_tests}

    denom_t = len(applicable_templates)
    num_t = len(executed_templates.intersection(applicable_templates))
    t_cov = CoverageItem(
        numerator=num_t,
        denominator=denom_t,
        percentage=round((num_t / denom_t) * 100.0, 2) if denom_t > 0 else None,
        status=MetricStatus.COMPUTED if denom_t > 0 else MetricStatus.UNDEFINED,
    )

    # 6. Security Category Coverage (Phase 3 category taxonomy)
    applicable_categories = set()
    for t_id in applicable_templates:
        tmpl = catalogue_registry.get_template(t_id)
        if tmpl:
            applicable_categories.add(tmpl.category.value if hasattr(tmpl.category, "value") else str(tmpl.category))

    executed_categories = set()
    for t in executed_tests:
        tmpl = catalogue_registry.get_template(t.template_id)
        if tmpl:
            executed_categories.add(tmpl.category.value if hasattr(tmpl.category, "value") else str(tmpl.category))

    denom_c = len(applicable_categories)
    num_c = len(executed_categories.intersection(applicable_categories))
    c_cov = CoverageItem(
        numerator=num_c,
        denominator=denom_c,
        percentage=round((num_c / denom_c) * 100.0, 2) if denom_c > 0 else None,
        status=MetricStatus.COMPUTED if denom_c > 0 else MetricStatus.UNDEFINED,
    )

    return CoverageMetrics(
        endpoint_coverage=ep_cov,
        method_coverage=m_cov,
        parameter_coverage=p_cov,
        body_field_coverage=f_cov,
        template_coverage=t_cov,
        category_coverage=c_cov,
    )
