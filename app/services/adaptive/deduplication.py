import hashlib
import json
from typing import Any

from app.schemas.generated_test import GeneratedSecurityTest


def compute_test_signature(
    target_id: str,
    template_id: str,
    path: str,
    method: str,
    target_location: str | None = None,
    target_param: str | None = None,
    mutation_type: str | None = None,
    input_data: Any | None = None,
) -> str:
    """Computes a strengthened deterministic test signature.

    Includes target, template, path, method, target_location, target_parameter, mutation_type, and input hash.
    """
    clean_target = (target_id or "").strip().lower()
    clean_template = (template_id or "").strip().upper()
    clean_path = (path or "").strip()
    clean_method = (method or "").strip().upper()
    clean_loc = (target_location or "").strip().upper()
    clean_param = (target_param or "").strip()
    clean_mut = (mutation_type or "").strip().upper()

    input_str = ""
    if input_data is not None:
        try:
            input_str = json.dumps(input_data, sort_keys=True)
        except Exception:
            input_str = str(input_data)

    input_hash = hashlib.sha256(input_str.encode("utf-8")).hexdigest()[:8]

    raw_sig = f"{clean_target}:{clean_template}:{clean_path}:{clean_method}:{clean_loc}:{clean_param}:{clean_mut}:{input_hash}"
    return hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()


def compute_generated_test_signature(target_id: str, test: GeneratedSecurityTest) -> str:
    """Computes a deduplication signature from a GeneratedSecurityTest instance."""
    target_loc = None
    target_param = None
    mutation_type = None
    input_data = None

    if test.input_mutations:
        mut = test.input_mutations[0]
        target_loc = mut.location.value if hasattr(mut.location, "value") else str(mut.location)
        target_param = mut.target
        mutation_type = mut.mutation_type
        input_data = mut.generated_value

    return compute_test_signature(
        target_id=target_id,
        template_id=test.template_id,
        path=test.endpoint_target,
        method=test.http_method,
        target_location=target_loc,
        target_param=target_param,
        mutation_type=mutation_type,
        input_data=input_data,
    )
