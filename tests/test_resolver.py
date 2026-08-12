import pytest

from app.core.exceptions import ReferenceResolutionError
from app.services.openapi.resolver import resolve_local_references, resolve_pointer


def test_resolve_pointer():
    doc = {
        "components": {
            "schemas": {
                "User": {"type": "object", "properties": {"name": {"type": "string"}}}
            }
        }
    }
    target = resolve_pointer(doc, "#/components/schemas/User")
    assert target == {"type": "object", "properties": {"name": {"type": "string"}}}


def test_resolve_invalid_pointer():
    doc = {"components": {}}
    with pytest.raises(ReferenceResolutionError):
        resolve_pointer(doc, "#/components/schemas/Missing")


def test_resolve_external_pointer_error():
    doc = {}
    with pytest.raises(ReferenceResolutionError) as exc_info:
        resolve_pointer(doc, "https://example.com/schema.json#/User")
    assert "non-local" in str(exc_info.value)


def test_resolve_circular_references():
    doc = {
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"},
                        "next": {"$ref": "#/components/schemas/Node"},
                    },
                }
            }
        }
    }
    resolved = resolve_local_references(doc)
    node_schema = resolved["components"]["schemas"]["Node"]
    assert node_schema["properties"]["value"]["type"] == "string"
    assert node_schema["properties"]["next"]["properties"]["value"]["type"] == "string"
    assert node_schema["properties"]["next"]["properties"]["next"]["$ref"] == "#/components/schemas/Node"
    assert node_schema["properties"]["next"]["properties"]["next"]["circular"] is True
