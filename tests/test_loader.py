from pathlib import Path
import pytest

from app.core.exceptions import InvalidFileFormatError
from app.services.openapi.loader import load_spec_from_bytes

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_load_valid_yaml():
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    doc = load_spec_from_bytes(yaml_bytes, filename="petstore.yaml")
    assert isinstance(doc, dict)
    assert doc.get("openapi") == "3.0.3"
    assert doc.get("info", {}).get("title") == "PetStore Test API"


def test_load_valid_json():
    json_bytes = b'{"openapi": "3.0.0", "info": {"title": "Test JSON API", "version": "1.0"}, "paths": {}}'
    doc = load_spec_from_bytes(json_bytes, filename="spec.json")
    assert isinstance(doc, dict)
    assert doc["info"]["title"] == "Test JSON API"


def test_load_empty_file():
    with pytest.raises(InvalidFileFormatError) as exc_info:
        load_spec_from_bytes(b"   ", filename="empty.json")
    assert "empty" in str(exc_info.value).lower()


def test_load_malformed_yaml():
    malformed_bytes = (FIXTURES_DIR / "invalid_yaml.yaml").read_bytes()
    with pytest.raises(InvalidFileFormatError):
        load_spec_from_bytes(malformed_bytes, filename="invalid_yaml.yaml")


def test_load_non_dict_json():
    json_array_bytes = b'["item1", "item2"]'
    with pytest.raises(InvalidFileFormatError) as exc_info:
        load_spec_from_bytes(json_array_bytes, filename="array.json")
    assert "Expected a JSON object" in str(exc_info.value)
