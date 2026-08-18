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



import unicodedata


def check_homoglyph(domain: str):
    """
    Detect potentially suspicious Unicode characters in a domain.

    ASCII domain characters are treated as normal.
    Non-ASCII characters are inspected to determine whether
    they may be visually similar to common Latin characters.
    """

    suspicious_characters = []

    for char in domain:
        # Normal ASCII characters are not homoglyphs.
        if ord(char) < 128:
            continue

        character_name = unicodedata.name(char, "")

        # Look for Unicode characters from scripts commonly
        # involved in visually deceptive domain names.
        suspicious_scripts = [
            "CYRILLIC",
            "GREEK",
            "ARMENIAN",
            "HEBREW"
        ]

        if any(script in character_name for script in suspicious_scripts):
            suspicious_characters.append({
                "character": char,
                "unicode_name": character_name,
                "codepoint": f"U+{ord(char):04X}"
            })

    suspicious = len(suspicious_characters) > 0

    if suspicious:
        risk_score = 0.9
    else:
        risk_score = 0.0

    return {
        "suspicious": suspicious,
        "detected_characters": suspicious_characters,
        "risk_score": risk_score
    }


import socket
import ssl
from datetime import datetime, timezone


def check_ssl(url: str):
    """
    Check basic SSL/TLS certificate information for a URL.

    Returns:
        HTTPS status
        certificate validity
        certificate expiry information
        certificate issuer/subject
        risk score
    """

    parsed = urlparse(url)

    # SSL/TLS only applies to HTTPS URLs.
    if parsed.scheme.lower() != "https":
        return {
            "https": False,
            "certificate_valid": False,
            "certificate_expired": False,
            "issuer": None,
            "subject": None,
            "risk_score": 0.8
        }

    hostname = parsed.hostname

    if hostname is None:
        return {
            "https": True,
            "certificate_valid": False,
            "certificate_expired": False,
            "issuer": None,
            "subject": None,
            "risk_score": 0.8
        }

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

        # If we successfully reached this point,
        # Python's default SSL verification succeeded.
        certificate_valid = True

        expiry_string = certificate.get("notAfter")

        certificate_expired = False

        if expiry_string:
            expiry_date = datetime.strptime(
                expiry_string,
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            certificate_expired = (
                expiry_date < datetime.now(timezone.utc)
            )

        issuer = certificate.get("issuer")
        subject = certificate.get("subject")

        if certificate_expired:
            risk_score = 0.8
        else:
            risk_score = 0.0

        return {
            "https": True,
            "certificate_valid": certificate_valid,
            "certificate_expired": certificate_expired,
            "issuer": issuer,
            "subject": subject,
            "risk_score": risk_score
        }

    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError):
        return {
            "https": True,
            "certificate_valid": False,
            "certificate_expired": False,
            "issuer": None,
            "subject": None,
            "risk_score": 0.7
        }



import requests


def check_redirects(url: str):
    """
    Follow HTTP redirects and measure the redirect chain depth.

    Returns:
        redirect_count: number of redirects encountered
        final_url: final destination after redirects
        redirect_chain: URLs visited during the process
        risk_score: normalized risk score
    """

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        redirect_chain = [
            history.url for history in response.history
        ]

        redirect_chain.append(response.url)

        redirect_count = len(response.history)

        # Simple initial scoring.
        if redirect_count == 0:
            risk_score = 0.0

        elif redirect_count <= 2:
            risk_score = 0.2

        elif redirect_count <= 4:
            risk_score = 0.5

        else:
            risk_score = 0.8

        return {
            "redirect_count": redirect_count,
            "final_url": response.url,
            "redirect_chain": redirect_chain,
            "risk_score": risk_score
        }

    except requests.RequestException as error:
        return {
            "redirect_count": None,
            "final_url": None,
            "redirect_chain": [],
            "risk_score": 0.5,
            "error": str(error)
        }


import whois
from datetime import datetime, timezone


def check_domain_age(domain: str):
    """
    Look up the domain registration date using WHOIS.

    Returns:
        registration_date
        age_days
        risk_score
        lookup_success
    """

    try:
        whois_data = whois.whois(domain)

        creation_date = whois_data.creation_date

        # Some WHOIS servers return multiple creation dates.
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {
                "registration_date": None,
                "age_days": None,
                "risk_score": 0.5,
                "lookup_success": False
            }

        # Convert naive datetime to UTC.
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(timezone.utc)

        age_days = (now - creation_date).days

        # Initial simple scoring:
        #
        # Very new domains are more suspicious.
        # Older domains receive lower risk.

        if age_days < 7:
            risk_score = 0.9

        elif age_days < 30:
            risk_score = 0.7

        elif age_days < 180:
            risk_score = 0.4

        elif age_days < 365:
            risk_score = 0.2

        else:
            risk_score = 0.0

        return {
            "registration_date": creation_date.isoformat(),
            "age_days": age_days,
            "risk_score": risk_score,
            "lookup_success": True
        }

    except Exception as error:
        # WHOIS lookup failures should NOT crash the detector.
        return {
            "registration_date": None,
            "age_days": None,
            "risk_score": 0.5,
            "lookup_success": False,
            "error": str(error)
        }