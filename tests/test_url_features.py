from detectors.url.features import extract_domain
from detectors.url.features import check_typosquatting
from detectors.url.features import check_homoglyph
from detectors.url.features import check_ssl

def test_extract_domain():
    url = "https://www.paypal.com/login"

    result = extract_domain(url)

    assert result == "www.paypal.com"


def test_typosquatting_detects_suspicious_domain():
    result = check_typosquatting("paypa1.com")

    assert result["suspicious"] is True
    assert result["closest_brand"] == "paypal.com"
    assert result["distance"] == 1


def test_typosquatting_accepts_legitimate_domain():
    result = check_typosquatting("paypal.com")

    assert result["suspicious"] is False
    assert result["distance"] == 0


def test_homoglyph_detects_suspicious_unicode():
    # The 'а' here is Cyrillic, not normal Latin 'a'.
    domain = "paypаl.com"

    result = check_homoglyph(domain)

    assert result["suspicious"] is True
    assert len(result["detected_characters"]) > 0


def test_homoglyph_accepts_normal_domain():
    result = check_homoglyph("paypal.com")

    assert result["suspicious"] is False
    assert result["detected_characters"] == []


def test_ssl_https_connection():
    result = check_ssl("https://example.com")

    assert result["https"] is True


def test_ssl_detects_non_https():
    result = check_ssl("http://example.com")

    assert result["https"] is False