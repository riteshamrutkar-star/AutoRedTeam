from app.services.security_analysis.owasp_mapper import OWASPMapper


def test_owasp_taxonomy_completeness():
    mapper = OWASPMapper()
    taxonomy = mapper.get_supported_taxonomy()

    assert len(taxonomy) == 10
    assert "API1:2023" in taxonomy
    assert taxonomy["API1:2023"]["name"] == "Broken Object Level Authorization"
    assert "API2:2023" in taxonomy
    assert taxonomy["API2:2023"]["name"] == "Broken Authentication"
    assert "API10:2023" in taxonomy
    assert taxonomy["API10:2023"]["name"] == "Unsafe Consumption of APIs"


def test_map_valid_category():
    mapper = OWASPMapper()
    mapping = mapper.map_category("API1:2023", "BOLA detected on user ID substitution.")
    assert mapping.category_id == "API1:2023"
    assert mapping.category_name == "Broken Object Level Authorization"
    assert mapping.taxonomy == "OWASP_API_TOP_10_2023"
    assert "BOLA detected" in mapping.rationale
