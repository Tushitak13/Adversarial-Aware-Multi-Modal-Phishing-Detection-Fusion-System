from detectors.url.features import (
    extract_domain,
    check_typosquatting
)
from detectors.url.features import check_homoglyph

def test_extract_domain():
    result = extract_domain(
        "https://www.paypal.com/login"
    )

    assert result == "www.paypal.com"


def test_typosquatting_detected():
    result = check_typosquatting("paypa1.com")

    assert result["suspicious"] is True
    assert result["closest_brand"] == "paypal.com"
    assert result["distance"] == 1


def test_legitimate_domain_not_flagged():
    result = check_typosquatting("paypal.com")

    assert result["suspicious"] is False
    assert result["distance"] == 0

def test_homoglyph_detected():
    result = check_homoglyph("paypаl.com")

    assert result["suspicious"] is True
    assert result["risk_score"] > 0
    assert len(result["detected_characters"]) > 0


def test_normal_ascii_domain_has_no_homoglyph():
    result = check_homoglyph("paypal.com")

    assert result["suspicious"] is False
    assert result["detected_characters"] == []