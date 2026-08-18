import time

from detectors.url.features import (
    extract_domain,
    check_domain_age,
    check_typosquatting,
    check_homoglyph,
    check_ssl,
    check_redirects
)

def analyze_url(url: str) -> dict:
    """
    Analyze a URL using multiple URL-based phishing signals.

    Returns the standard detector contract:

    {
        "detector_name": "url",
        "score": 0.0,
        "confidence": 0.0,
        "raw_features": {},
        "latency_ms": 0
    }
    """

    start_time = time.perf_counter()

    # ---------------------------------------------------------
    # 1. Extract domain
    # ---------------------------------------------------------

    try:
        domain = extract_domain(url)
    except ValueError:
        return {
            "detector_name": "url",
            "score": 1.0,
            "confidence": 0.0,
            "raw_features": {
                "error": "Invalid URL"
            },
            "latency_ms": 0
        }

    # ---------------------------------------------------------
    # 2. Run individual URL features
    # ---------------------------------------------------------

    domain_age = check_domain_age(domain)

    typosquatting = check_typosquatting(domain)

    homoglyph = check_homoglyph(domain)

    ssl_result = check_ssl(url)

    redirects = check_redirects(url)

    # ---------------------------------------------------------
    # 3. Collect all feature scores
    # ---------------------------------------------------------

    feature_scores = {
        "domain_age": domain_age["risk_score"],
        "typosquatting": typosquatting["risk_score"],
        "homoglyph": homoglyph["risk_score"],
        "ssl": ssl_result["risk_score"],
        "redirects": redirects["risk_score"]
    }

    # ---------------------------------------------------------
    # 4. Weighted rule-based scoring
    # ---------------------------------------------------------

    weights = {
        "domain_age": 0.25,
        "typosquatting": 0.25,
        "homoglyph": 0.20,
        "ssl": 0.15,
        "redirects": 0.15
    }

    score = sum(
        feature_scores[name] * weights[name]
        for name in feature_scores
    )

    # ---------------------------------------------------------
    # 5. Calculate confidence
    # ---------------------------------------------------------

    successful_checks = 0
    total_checks = len(feature_scores)

    if domain_age["lookup_success"]:
        successful_checks += 1

    # These checks successfully produce a result even when
    # the result indicates no suspicious signal.
    successful_checks += 1  # typosquatting
    successful_checks += 1  # homoglyph
    successful_checks += 1  # SSL
    successful_checks += 1  # redirects

    confidence = successful_checks / total_checks

    # ---------------------------------------------------------
    # 6. Calculate latency
    # ---------------------------------------------------------

    latency_ms = int(
        (time.perf_counter() - start_time) * 1000
    )

    # ---------------------------------------------------------
    # 7. Return standard detector contract
    # ---------------------------------------------------------

    return {
        "detector_name": "url",
        "score": round(score, 4),
        "confidence": round(confidence, 4),
        "raw_features": {
            "domain": domain,
            "domain_age": domain_age,
            "typosquatting": typosquatting,
            "homoglyph": homoglyph,
            "ssl": ssl_result,
            "redirects": redirects,
            "feature_scores": feature_scores,
            "weights": weights
        },
        "latency_ms": latency_ms
    }