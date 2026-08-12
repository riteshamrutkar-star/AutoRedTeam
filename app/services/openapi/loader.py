import json
from typing import Any
import yaml

from app.core.exceptions import InvalidFileFormatError


def load_spec_from_bytes(content: bytes, filename: str | None = None) -> dict[str, Any]:
    """Parses raw specification bytes into a Python dictionary.

    Supports JSON (.json) and YAML (.yaml, .yml) specifications.
    """
    if not content or not content.strip():
        raise InvalidFileFormatError("The submitted specification file is empty.")

    text_content = content.decode("utf-8", errors="replace").strip()
    parsed_doc: Any = None
    ext = filename.lower().rsplit(".", 1)[-1] if filename and "." in filename else ""

    if ext == "json":
        try:
            parsed_doc = json.loads(text_content)
        except json.JSONDecodeError as exc:
            raise InvalidFileFormatError(
                f"Failed to parse JSON specification: {exc.msg}",
                details={"line": exc.lineno, "col": exc.colno},
            ) from exc
    elif ext in ("yaml", "yml"):
        try:
            parsed_doc = yaml.safe_load(text_content)
        except yaml.YAMLError as exc:
            raise InvalidFileFormatError(
                f"Failed to parse YAML specification: {exc}"
            ) from exc
    else:
        # Fallback: try parsing JSON first, then YAML
        try:
            parsed_doc = json.loads(text_content)
        except Exception:
            try:
                parsed_doc = yaml.safe_load(text_content)
            except Exception as exc:
                raise InvalidFileFormatError(
                    "Unable to parse specification. File must be valid JSON or YAML."
                ) from exc

    if not isinstance(parsed_doc, dict):
        raise InvalidFileFormatError(
            f"Invalid OpenAPI root structure. Expected a JSON object / YAML dictionary, got {type(parsed_doc).__name__}."
        )

    return parsed_doc
