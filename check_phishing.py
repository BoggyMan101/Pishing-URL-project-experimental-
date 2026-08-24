#!/usr/bin/env python3
"""
Anti-Phishing URL Checker
--------------------------
Checks one or more URLs against Google's Safe Browsing API (v4) to detect
phishing, malware, and other unwanted-software threats.

Setup:
  1. Get a free API key:
     https://developers.google.com/safe-browsing/v4/get-started
     (Enable the "Safe Browsing API" in Google Cloud Console, create an API key.)
  2. Set it as an environment variable:
       export SAFE_BROWSING_API_KEY="your_key_here"
     ...or pass it with --api-key.
  3. Install dependencies:
       pip install requests joblib scikit-learn pandas python-whois pillow imagehash beautifulsoup4 lxml --break-system-packages

Usage:
  python check_phishing.py https://example.com
  python check_phishing.py https://a.com https://b.com --api-key YOUR_KEY
  python check_phishing.py --file urls.txt
  python check_phishing.py --no-safe-browsing https://example.com        # offline ML only
  python check_phishing.py --deep https://example.com --api-key YOUR_KEY # + WHOIS + favicon checks
"""

import argparse
import os
import sys
import json
from urllib.parse import urlparse

import requests
import joblib

from url_features import extract_features, FEATURE_NAMES
from whois_check import get_domain_age_info
from content_similarity import check_brand_impersonation

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_model.joblib")

_model = None


def get_model():
    """Lazy-load the trained scikit-learn model (see train_model.py)."""
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


def predict_phishing_probability(url):
    """Local ML prediction (0.0-1.0) that `url` is phishing, based purely on
    lexical URL features -- works fully offline, no API calls needed."""
    feats = extract_features(url)
    model = get_model()
    proba = model.predict_proba([feats])[0]
    # class 1 = phishing (see Label column in training data)
    classes = list(model.classes_)
    phishing_idx = classes.index(1)
    return proba[phishing_idx], dict(zip(FEATURE_NAMES, feats))

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",   # phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def check_urls(urls, api_key):
    """Send a batch of URLs to Google Safe Browsing and return the raw matches."""
    body = {
        "client": {
            "clientId": "anti-phishing-checker",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }

    resp = requests.post(
        SAFE_BROWSING_URL,
        params={"key": api_key},
        json=body,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("matches", [])


def load_urls_from_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Check URLs against Google Safe Browsing for phishing/malware.")
    parser.add_argument("urls", nargs="*", help="One or more URLs to check")
    parser.add_argument("--file", help="Path to a text file with one URL per line")
    parser.add_argument("--api-key", default=os.environ.get("SAFE_BROWSING_API_KEY"),
                         help="Google Safe Browsing API key (or set SAFE_BROWSING_API_KEY env var)")
    parser.add_argument("--ml-threshold", type=float, default=0.75,
                         help="Probability above which the local ML model flags a URL as phishing (default 0.75; "
                              "the lexical-only model runs 'warm' on URLs with paths, so a higher bar cuts false positives)")
    parser.add_argument("--no-safe-browsing", action="store_true",
                         help="Skip the Google Safe Browsing lookup and use only the local ML model (no API key/network needed)")
    parser.add_argument("--deep", action="store_true",
                         help="Also run a live WHOIS domain-age check and a favicon brand-impersonation check. "
                              "Slower (one WHOIS + one/two HTTP fetches per URL) and more network-dependent, "
                              "but catches things Safe Browsing and the ML model alone miss (brand-new domains, "
                              "visual clones of known brands).")
    args = parser.parse_args()

    if not args.no_safe_browsing and not args.api_key:
        print("Error: no API key provided. Use --api-key, set SAFE_BROWSING_API_KEY, "
              "or pass --no-safe-browsing to use only the offline ML model.", file=sys.stderr)
        sys.exit(1)

    urls = list(args.urls)
    if args.file:
        urls.extend(load_urls_from_file(args.file))

    if not urls:
        print("Error: no URLs given. Pass them as arguments or via --file.", file=sys.stderr)
        sys.exit(1)

    # --- 1. Google Safe Browsing: known-bad blocklist lookup ---
    flagged_by_google = {}
    all_matches = []
    if not args.no_safe_browsing:
        CHUNK = 500  # Safe Browsing allows up to 500 URLs per request
        for i in range(0, len(urls), CHUNK):
            chunk = urls[i:i + CHUNK]
            try:
                matches = check_urls(chunk, args.api_key)
                all_matches.extend(matches)
            except requests.exceptions.HTTPError as e:
                print(f"API error: {e}\n{resp_text_safe(e)}", file=sys.stderr)
                sys.exit(1)
            except requests.exceptions.RequestException as e:
                print(f"Network error: {e}", file=sys.stderr)
                sys.exit(1)
        for m in all_matches:
            flagged_by_google.setdefault(m["threat"]["url"], set()).add(m["threatType"])

    # --- 2. Local ML model: predictive score from URL structure alone ---
    ml_results = {}
    for u in urls:
        try:
            prob, feats = predict_phishing_probability(u)
            ml_results[u] = prob
        except Exception as e:
            print(f"Warning: ML prediction failed for {u}: {e}", file=sys.stderr)
            ml_results[u] = None

    # --- 3. Deep checks (opt-in): live WHOIS domain-age + favicon brand-impersonation ---
    whois_results = {}
    brand_results = {}
    if args.deep:
        print("Running deep checks (WHOIS + favicon comparison) -- this makes live "
              "network requests per URL and may take a while...", file=sys.stderr)
        for u in urls:
            domain = urlparse(u if "//" in u else "http://" + u).netloc.split(":")[0]
            try:
                whois_results[u] = get_domain_age_info(domain)
            except Exception as e:
                print(f"Warning: WHOIS lookup failed for {u}: {e}", file=sys.stderr)
                whois_results[u] = {"lookup_ok": False, "is_new_domain": None}
            try:
                brand_results[u] = check_brand_impersonation(u)
            except Exception as e:
                print(f"Warning: favicon check failed for {u}: {e}", file=sys.stderr)
                brand_results[u] = (None, None)

    # --- 4. Combine all signals: unsafe if ANY of them trips ---
    n_flagged = 0
    print(f"\nChecked {len(urls)} URL(s)\n")
    for u in urls:
        google_hit = u in flagged_by_google
        ml_prob = ml_results.get(u)
        ml_hit = (ml_prob is not None) and (ml_prob >= args.ml_threshold)

        whois_info = whois_results.get(u, {})
        new_domain_hit = bool(whois_info.get("is_new_domain"))

        brand, dist = brand_results.get(u, (None, None))
        brand_hit = brand is not None

        if google_hit or ml_hit or new_domain_hit or brand_hit:
            n_flagged += 1
            parts = []
            if google_hit:
                parts.append("Google: " + ", ".join(sorted(flagged_by_google[u])))
            if ml_hit:
                parts.append(f"ML model: {ml_prob:.0%} phishing likelihood")
            if new_domain_hit:
                parts.append(f"WHOIS: domain registered only {whois_info['domain_age_days']} days ago")
            if brand_hit:
                parts.append(f"Favicon: closely matches {brand}'s icon (distance {dist}) but isn't {brand}'s domain")
            print(f"  [!] UNSAFE  {u}")
            for p in parts:
                print(f"        - {p}")
        else:
            notes = []
            if ml_prob is not None:
                notes.append(f"ML: {ml_prob:.0%}")
            if whois_info.get("lookup_ok"):
                notes.append(f"domain age: {whois_info['domain_age_days']}d")
            note_str = f"({', '.join(notes)})" if notes else ""
            print(f"  [ok] SAFE   {u}  {note_str}")

    print(f"\n{n_flagged} of {len(urls)} URL(s) flagged.")
    print("Note: the ML score is a heuristic prediction based on URL structure only "
          "(~88% test accuracy) -- it is not a certainty, and is weaker on URLs with "
          "long paths on unfamiliar domains. Google Safe Browsing hits are confirmed "
          "known-bad URLs; treat those as the higher-confidence signal.")
    if args.deep:
        print("WHOIS/favicon checks are heuristics too: privacy-shielded WHOIS records "
              "and sites with no fetchable favicon will simply be skipped for those signals, "
              "not counted as safe.")

    if all_matches:
        print("\nRaw Safe Browsing match details:")
        print(json.dumps(all_matches, indent=2))


def resp_text_safe(err):
    try:
        return err.response.text
    except Exception:
        return ""


if __name__ == "__main__":
    main()
