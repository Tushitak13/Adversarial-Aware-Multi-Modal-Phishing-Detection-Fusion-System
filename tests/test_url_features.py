from detectors.url.features import (
    extract_domain,
    check_typosquatting
)
from detectors.url.features import check_homoglyph
from detectors.url.features import check_ssl
from detectors.url.features import check_redirects
from detectors.url.features import check_domain_age
from detectors.url.detector import analyze_url
from detectors.url.features import analyze_url_structure



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

def test_ssl_https():
    result = check_ssl("https://example.com")

    assert result["https"] is True


def test_ssl_http():
    result = check_ssl("http://example.com")

    assert result["https"] is False

def test_redirect_detection():
    result = check_redirects("https://example.com")

    assert result["redirect_count"] is not None
    assert result["final_url"] is not None
    assert isinstance(result["redirect_chain"], list)
    assert 0.0 <= result["risk_score"] <= 1.0

def test_domain_age():
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
    assert 0.0 <= result["risk_score"] <= 1.0

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
    assert result["score"] > 0.0

def test_url_structure():
    result = analyze_url_structure(
        "https://login.paypal.com:8080/account/login?user=test"
    )

    assert result["scheme"] == "https"
    assert result["hostname"] == "login.paypal.com"
    assert result["registered_domain"] == "paypal.com"
    assert result["subdomain"] == "login"
    assert result["port"] == 8080
    assert result["path"] == "/account/login"
    assert result["query"] == "user=test"


def test_registered_domain_prevents_subdomain_confusion():
    result = analyze_url_structure(
        "https://paypal.com.evil.com/login"
    )

    assert result["registered_domain"] == "evil.com"
    assert "paypal.com" in result["subdomain"]