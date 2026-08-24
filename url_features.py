# -*- coding: utf-8 -*-
"""
Lexical URL feature extraction.

These 8 features are computed purely from the URL string itself (no network
calls), so the exact same function can be used both to build the training
set and to score a brand-new URL live. Logic follows the well-established
UCI "Phishing Websites" feature set (Have_IP, Have_At, URL_Length, URL_Depth,
Redirection, https_Domain, TinyURL, Prefix/Suffix).
"""

import re
import ipaddress
from urllib.parse import urlparse

FEATURE_NAMES = [
    "Have_IP", "Have_At", "URL_Length", "URL_Depth",
    "Redirection", "https_Domain", "TinyURL", "Prefix/Suffix",
    "Domain_Length", "Num_Dots", "Num_Digits", "Sensitive_Words",
]

_SENSITIVE_WORDS = (
    "secure", "login", "verify", "account", "update", "confirm",
    "signin", "banking", "password", "wallet", "security", "authenticate",
)

_SHORTENERS = (
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|"
    r"buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|"
    r"vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net"
)


def _having_ip(url: str) -> int:
    netloc = urlparse(url).netloc.split(":")[0]
    try:
        ipaddress.ip_address(netloc)
        return 1
    except ValueError:
        return 0


def _have_at_sign(url: str) -> int:
    return 1 if "@" in url else 0


def _get_length(url: str) -> int:
    return 1 if len(url) >= 54 else 0


def _get_depth(url: str) -> int:
    segments = urlparse(url).path.split("/")
    return sum(1 for s in segments if len(s) != 0)


def _redirection(url: str) -> int:
    pos = url.rfind("//")
    return 1 if pos > 7 else 0


def _http_in_domain(url: str) -> int:
    return 1 if "https" in urlparse(url).netloc else 0


def _tiny_url(url: str) -> int:
    return 1 if re.search(_SHORTENERS, url, re.IGNORECASE) else 0


def _prefix_suffix(url: str) -> int:
    return 1 if "-" in urlparse(url).netloc else 0


def _domain_of(url: str) -> str:
    domain = urlparse(url).netloc.split(":")[0]
    return re.sub(r"^www\.", "", domain)


def _domain_length(url: str) -> int:
    return len(_domain_of(url))


def _num_dots(url: str) -> int:
    return _domain_of(url).count(".")


def _num_digits(url: str) -> int:
    return sum(c.isdigit() for c in _domain_of(url))


def _sensitive_words(url: str) -> int:
    domain = _domain_of(url).lower()
    return sum(1 for w in _SENSITIVE_WORDS if w in domain)


def extract_features(url: str) -> list:
    """Return the lexical features for `url`, in FEATURE_NAMES order."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return [
        _having_ip(url),
        _have_at_sign(url),
        _get_length(url),
        _get_depth(url),
        _redirection(url),
        _http_in_domain(url),
        _tiny_url(url),
        _prefix_suffix(url),
        _domain_length(url),
        _num_dots(url),
        _num_digits(url),
        _sensitive_words(url),
    ]
