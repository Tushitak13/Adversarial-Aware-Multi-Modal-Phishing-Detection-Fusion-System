from urllib.parse import urlparse


def extract_domain(url: str) -> str:
    """
    Extract the hostname/domain from a URL.

    Example:
        https://www.paypal.com/login
        -> www.paypal.com
    """

    parsed = urlparse(url)

    domain = parsed.hostname

    if domain is None:
        raise ValueError("Invalid URL: could not extract domain")

    return domain.lower()



import json
from pathlib import Path
import Levenshtein


def load_brand_list():
    """
    Load legitimate brand domains from brand_list.json.
    """

    brand_file = Path(__file__).parent / "brand_list.json"

    with open(brand_file, "r", encoding="utf-8") as file:
        return json.load(file)


def check_typosquatting(domain: str):
    """
    Compare a domain against known legitimate brand domains.

    Returns:
        suspicious: True/False
        closest_brand: most similar legitimate domain
        distance: Levenshtein distance
        risk_score: normalized risk score between 0 and 1
    """

    brands = load_brand_list()

    best_brand = None
    best_distance = float("inf")

    for brand in brands:
        distance = Levenshtein.distance(domain, brand)

        if distance < best_distance:
            best_distance = distance
            best_brand = brand

    # A small edit distance means the domain is suspiciously
    # similar to a legitimate brand.
    if best_distance == 0:
        risk_score = 0.0
        suspicious = False

    elif best_distance <= 2:
        risk_score = 0.9
        suspicious = True

    elif best_distance <= 4:
        risk_score = 0.6
        suspicious = True

    else:
        risk_score = 0.1
        suspicious = False

    return {
        "suspicious": suspicious,
        "closest_brand": best_brand,
        "distance": best_distance,
        "risk_score": risk_score
    }



from detectors.url.features import check_typosquatting


def test_typosquatting_detects_suspicious_domain():
    result = check_typosquatting("paypa1.com")

    assert result["suspicious"] is True
    assert result["closest_brand"] == "paypal.com"
    assert result["distance"] == 1


def test_typosquatting_accepts_legitimate_domain():
    result = check_typosquatting("paypal.com")

    assert result["suspicious"] is False
    assert result["distance"] == 0