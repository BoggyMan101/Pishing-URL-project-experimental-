# -*- coding: utf-8 -*-
"""
WHOIS-based domain age check.

Most phishing domains are registered shortly before use and abandoned soon
after (often within days). A domain that's decades old and not expiring
anytime soon is far more likely to be legitimate. This makes a live WHOIS
query per domain, so it's slower and network-dependent -- use it as a
supplementary signal, not the sole check.
"""

from datetime import datetime, timezone

import whois

NEW_DOMAIN_THRESHOLD_DAYS = 180   # registered more recently than this = suspicious
EXPIRES_SOON_THRESHOLD_DAYS = 90  # phishing domains are rarely renewed far in advance


def _first(value):
    """WHOIS libraries sometimes return a list of dates (multiple records); take the earliest/first."""
    if isinstance(value, list):
        value = value[0] if value else None
    return value


def _as_aware_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def get_domain_age_info(domain: str, timeout: int = 8) -> dict:
    """
    Returns:
      {
        "lookup_ok": bool,           # False if WHOIS failed/was blocked/rate-limited
        "domain_age_days": int|None,
        "is_new_domain": bool|None,  # True if registered < NEW_DOMAIN_THRESHOLD_DAYS ago
        "expires_soon": bool|None,   # True if expiring < EXPIRES_SOON_THRESHOLD_DAYS from now
      }
    A failed/empty lookup is itself a weak signal (many phishing domains use
    privacy-shielded or low-quality registrars that don't respond cleanly),
    but it's reported separately rather than silently treated as "suspicious"
    since plenty of legitimate ccTLDs also return sparse WHOIS data.
    """
    result = {"lookup_ok": False, "domain_age_days": None, "is_new_domain": None, "expires_soon": None}
    try:
        w = whois.whois(domain, timeout=timeout)
    except Exception:
        return result

    created = _as_aware_utc(_first(getattr(w, "creation_date", None)))
    expires = _as_aware_utc(_first(getattr(w, "expiration_date", None)))

    if created is None:
        return result

    now = datetime.now(timezone.utc)
    age_days = (now - created).days
    result.update(
        lookup_ok=True,
        domain_age_days=age_days,
        is_new_domain=age_days < NEW_DOMAIN_THRESHOLD_DAYS,
    )
    if expires is not None:
        result["expires_soon"] = (expires - now).days < EXPIRES_SOON_THRESHOLD_DAYS
    return result
