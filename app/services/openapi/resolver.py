import copy
from typing import Any

from app.core.exceptions import ReferenceResolutionError


def resolve_pointer(doc: dict[str, Any], pointer: str) -> Any:
    """Resolves a local JSON pointer (e.g. '#/components/schemas/Pet') within doc."""
    if not pointer.startswith("#/"):
        raise ReferenceResolutionError(
            f"External or non-local $ref pointer '{pointer}' is not supported. Only local '#/...' references are supported."
        )

    parts = pointer[2:].split("/")
    curr: Any = doc
    for part in parts:
        part_unescaped = part.replace("~1", "/").replace("~0", "~")
        if isinstance(curr, dict) and part_unescaped in curr:
            curr = curr[part_unescaped]
        elif isinstance(curr, list) and part_unescaped.isdigit():
            idx = int(part_unescaped)
            if 0 <= idx < len(curr):
                curr = curr[idx]
            else:
                raise ReferenceResolutionError(f"Index {idx} out of range in pointer '{pointer}'.")
        else:
            raise ReferenceResolutionError(f"Could not resolve JSON pointer '{pointer}'. Part '{part_unescaped}' not found.")
    return curr


def resolve_local_references(doc: dict[str, Any]) -> dict[str, Any]:
    """Recursively resolves local $ref pointers in doc while preventing infinite circular loops."""
    
    def _resolve(obj: Any, visited: set[str]) -> Any:
        if isinstance(obj, dict):
            if "$ref" in obj and isinstance(obj["$ref"], str):
                ref_path = obj["$ref"]
                if ref_path in visited:
                    # Circular reference detected: preserve reference without recursing further
                    return {"$ref": ref_path, "circular": True}
                
                target = resolve_pointer(doc, ref_path)
                # Combine extra properties if present alongside $ref in OpenAPI 3.1
                new_visited = visited | {ref_path}
                resolved_target = _resolve(target, new_visited)
                if isinstance(resolved_target, dict):
                    combined = copy.deepcopy(resolved_target)
                    for k, v in obj.items():
                        if k != "$ref":
                            combined[k] = _resolve(v, visited)
                    return combined
                return resolved_target
            else:
                return {k: _resolve(v, visited) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_resolve(item, visited) for item in obj]
        return obj

    # Work on a copy of the document
    doc_copy = copy.deepcopy(doc)
    return _resolve(doc_copy, set())
