from detectors.url.features import extract_domain
from detectors.url.features import check_typosquatting
from detectors.url.features import check_homoglyph
from detectors.url.features import check_ssl
from detectors.url.features import check_redirects
from detectors.url.features import check_domain_age
from detectors.url.detector import analyze_url


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


def test_redirect_detection():
    result = check_redirects("https://example.com")

    assert result["redirect_count"] is not None
    assert result["final_url"] is not None
    assert isinstance(result["redirect_chain"], list)


def test_domain_age_success():
    result = check_domain_age("google.com")

    assert "lookup_success" in result
    assert "risk_score" in result

    if result["lookup_success"]:
        assert result["age_days"] is not None
        assert result["age_days"] >= 0


def test_domain_age_failure_is_graceful():
    result = check_domain_age(
        "this-domain-definitely-does-not-exist-123456789.com"
    )

    assert "lookup_success" in result
    assert "risk_score" in result


def test_analyze_url_returns_standard_contract():
    result = analyze_url("https://example.com")

    assert result["detector_name"] == "url"
    assert 0.0 <= result["score"] <= 1.0
    assert 0.0 <= result["confidence"] <= 1.0
    assert isinstance(result["raw_features"], dict)
    assert isinstance(result["latency_ms"], int)


def test_analyze_url_detects_typosquatting():
    result = analyze_url("https://paypa1.com")

    assert result["detector_name"] == "url"

    # The URL should receive some phishing risk
    # because of the typosquatting signal.
    assert result["score"] > 0.0