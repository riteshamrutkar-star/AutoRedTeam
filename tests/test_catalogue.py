from app.schemas.security_test import SecurityTestCategory
from app.services.security_tests.catalogue import TestCatalogue, catalogue_registry


def test_catalogue_initialization():
    templates = catalogue_registry.get_all_templates()
    assert len(templates) > 0


def test_catalogue_unique_ids():
    templates = catalogue_registry.get_all_templates()
    ids = [t.template_id for t in templates]
    assert len(ids) == len(set(ids)), "Catalogue template IDs must be unique"


def test_catalogue_category_lookup():
    auth_templates = catalogue_registry.get_templates_by_category(SecurityTestCategory.AUTHENTICATION)
    assert len(auth_templates) >= 3
    assert all(t.category == SecurityTestCategory.AUTHENTICATION for t in auth_templates)


def test_catalogue_single_lookup():
    template = catalogue_registry.get_template("AUTH-001")
    assert template is not None
    assert template.name == "Missing Authentication Requirement"

    missing = catalogue_registry.get_template("NON-EXISTENT")
    assert missing is None
