from detectors.url.features import extract_domain
from detectors.url.features import check_typosquatting


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