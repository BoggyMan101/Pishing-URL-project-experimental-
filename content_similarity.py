# -*- coding: utf-8 -*-
"""
Brand-impersonation check via favicon similarity.

Fetches the target site's favicon and compares it (via perceptual hash) to a
small set of well-known brands' real favicons. A close visual match on a
domain that ISN'T that brand's real domain is a strong phishing signal --
this is exactly the "looks like PayPal, isn't PayPal" attack pattern.

This makes live HTTP requests to the target URL (and, the first time a given
brand is checked, to that brand's real site too -- results are cached locally
in favicon_hash_cache.json after that). It's slower and network-dependent,
so treat it as a supplementary signal.
"""

import io
import json
import os
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from PIL import Image
import imagehash

TRUSTED_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "github": "github.com",
    "coinbase": "coinbase.com",
    "adobe": "adobe.com",
}

HAMMING_THRESHOLD = 6  # phash bits differing or fewer = treated as a visual match
_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "favicon_hash_cache.json")
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; AntiPhishingChecker/1.0)"}


def _load_cache() -> dict:
    if os.path.exists(_CACHE_PATH):
        try:
            with open(_CACHE_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    try:
        with open(_CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
    except OSError:
        pass


def _fetch_favicon_bytes(url: str, timeout: int = 6):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException:
        return None

    icon_url = None
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup.find_all("link"):
            rel = (tag.get("rel") or [])
            rel = " ".join(rel) if isinstance(rel, list) else str(rel)
            if "icon" in rel.lower() and tag.get("href"):
                icon_url = urljoin(resp.url, tag["href"])
                break
    except Exception:
        pass
    if not icon_url:
        icon_url = urljoin(resp.url, "/favicon.ico")

    try:
        icon_resp = requests.get(icon_url, headers=_HEADERS, timeout=timeout)
        icon_resp.raise_for_status()
        if not icon_resp.content:
            return None
        return icon_resp.content
    except requests.RequestException:
        return None


def _phash_of(image_bytes: bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes))
        return imagehash.phash(img)
    except Exception:
        return None


def _get_reference_hash(brand: str, brand_domain: str, cache: dict):
    if brand in cache:
        try:
            return imagehash.hex_to_hash(cache[brand])
        except ValueError:
            pass
    icon_bytes = _fetch_favicon_bytes(f"https://{brand_domain}")
    if icon_bytes is None:
        return None
    h = _phash_of(icon_bytes)
    if h is not None:
        cache[brand] = str(h)
    return h


def check_brand_impersonation(url: str, timeout: int = 6):
    """
    Returns (matched_brand, hamming_distance) if the target's favicon closely
    matches a known brand's favicon while NOT being hosted on that brand's
    real domain. Returns (None, best_distance_or_None) otherwise.
    """
    domain = urlparse(url if "//" in url else "http://" + url).netloc.split(":")[0].lower()
    domain = domain[4:] if domain.startswith("www.") else domain

    icon_bytes = _fetch_favicon_bytes(url, timeout=timeout)
    if icon_bytes is None:
        return None, None
    target_hash = _phash_of(icon_bytes)
    if target_hash is None:
        return None, None

    cache = _load_cache()
    best_brand, best_dist = None, None
    for brand, brand_domain in TRUSTED_BRANDS.items():
        if domain == brand_domain or domain.endswith("." + brand_domain):
            continue  # this IS the brand's own real domain -- not impersonation
        ref_hash = _get_reference_hash(brand, brand_domain, cache)
        if ref_hash is None:
            continue
        dist = target_hash - ref_hash
        if best_dist is None or dist < best_dist:
            best_brand, best_dist = brand, dist
    _save_cache(cache)

    if best_dist is not None and best_dist <= HAMMING_THRESHOLD:
        return best_brand, best_dist
    return None, best_dist
