import json
from pathlib import Path
from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime, timezone
import requests
import whois
import tldextract

# Load legitimate brand domains
BRAND_LIST_PATH = Path(__file__).parent / "brand_list.json"

with open(BRAND_LIST_PATH, "r", encoding="utf-8") as file:
    BRANDS = json.load(file)


def extract_domain(url: str) -> str:
    """
    Extract the hostname/domain from a URL.
    """

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("Invalid URL")

    return parsed.hostname.lower()


def levenshtein_distance(a: str, b: str) -> int:
    """
    Calculate the Levenshtein edit distance between two strings.
    """

    previous_row = list(range(len(b) + 1))

    for i, char_a in enumerate(a, start=1):

        current_row = [i]

        for j, char_b in enumerate(b, start=1):

            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            replace_cost = previous_row[j - 1] + (char_a != char_b)

            current_row.append(
                min(insert_cost, delete_cost, replace_cost)
            )

        previous_row = current_row

    return previous_row[-1]


def check_typosquatting(domain: str) -> dict:
    """
    Compare a domain against known legitimate brand domains.
    """

    domain = domain.lower()

    # Remove common www prefix
    if domain.startswith("www."):
        domain = domain[4:]

    best_brand = None
    best_distance = float("inf")

    for brand_name, legitimate_domain in BRANDS.items():

        distance = levenshtein_distance(
            domain,
            legitimate_domain
        )

        if distance < best_distance:
            best_distance = distance
            best_brand = legitimate_domain

    # Initial suspiciousness rule
    suspicious = (
        best_distance <= 2
        and domain != best_brand
    )

    if suspicious:
        risk_score = 0.9
    else:
        risk_score = 0.0

    return {
        "suspicious": suspicious,
        "closest_brand": best_brand,
        "distance": best_distance,
        "risk_score": risk_score
    }

def check_homoglyph(domain: str) -> dict:
    """
    Detect suspicious Unicode characters that can visually
    resemble normal Latin characters.
    """

    suspicious_characters = []

    for char in domain:

        # ASCII characters are not homoglyphs.
        if ord(char) < 128:
            continue

        suspicious_characters.append({
            "character": char,
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


def check_ssl(url: str) -> dict:
    """
    Check basic SSL/TLS certificate information.
    """

    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        return {
            "https": False,
            "certificate_valid": False,
            "certificate_expired": False,
            "issuer": None,
            "risk_score": 0.8
        }

    hostname = parsed.hostname

    if hostname is None:
        return {
            "https": True,
            "certificate_valid": False,
            "certificate_expired": False,
            "issuer": None,
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

        if certificate_expired:
            risk_score = 0.8
        else:
            risk_score = 0.0

        return {
            "https": True,
            "certificate_valid": True,
            "certificate_expired": certificate_expired,
            "issuer": issuer,
            "risk_score": risk_score
        }

    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError):
        return {
            "https": True,
            "certificate_valid": False,
            "certificate_expired": False,
            "issuer": None,
            "risk_score": 0.7
        }

def check_redirects(url: str) -> dict:
    """
    Follow redirects and measure the redirect chain depth.
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

        redirect_count = len(response.history)

        redirect_chain = [
            history.url
            for history in response.history
        ]

        redirect_chain.append(response.url)

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

def check_domain_age(domain: str) -> dict:
    """
    Look up the domain registration date using WHOIS.

    If WHOIS information is unavailable, return a safe
    fallback instead of crashing the detector.
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

        # Convert a timezone-naive datetime to UTC.
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(timezone.utc)

        age_days = (now - creation_date).days

        # New domains are generally more suspicious.
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
        # WHOIS failure must not crash the detector.
        return {
            "registration_date": None,
            "age_days": None,
            "risk_score": 0.5,
            "lookup_success": False,
            "error": str(error)
        }

def analyze_url_structure(url: str) -> dict:
    """
    Extract the structural components of a URL.

    Returns:
        scheme
        hostname
        registered_domain
        subdomain
        port
        path
        query
    """

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("Invalid URL")

    extracted = tldextract.extract(parsed.hostname)

    registered_domain = extracted.registered_domain
    subdomain = extracted.subdomain

    return {
        "scheme": parsed.scheme.lower(),
        "hostname": parsed.hostname.lower(),
        "registered_domain": registered_domain.lower(),
        "subdomain": subdomain.lower(),
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query
    }

import ipaddress


def check_ip_address(domain: str) -> dict:
    """
    Check whether the hostname is an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(domain)

        return {
            "is_ip": True,
            "version": ipaddress.ip_address(domain).version,
            "risk_score": 0.7
        }

    except ValueError:
        return {
            "is_ip": False,
            "version": None,
            "risk_score": 0.0
        }

def check_at_symbol(url: str) -> dict:
    """
    Detect the use of '@' in a URL.

    In URLs such as:
        https://paypal.com@evil.com/login

    the actual destination is evil.com.
    """

    parsed = urlparse(url)

    has_at_symbol = "@" in url

    if has_at_symbol:
        risk_score = 0.8
    else:
        risk_score = 0.0

    return {
        "has_at_symbol": has_at_symbol,
        "userinfo": parsed.username,
        "risk_score": risk_score
    }


