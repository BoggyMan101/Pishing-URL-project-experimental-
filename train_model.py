"""
Trains a phishing-URL classifier on the labeled dataset (10,000 URLs,
5,000 phishing / 5,000 legitimate; source: PhishTank + UNB benign URL list,
via the UCI 'Phishing Websites' feature set) using only the 8 lexical
features that can be computed offline from the URL string alone.
"""

import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

from url_features import FEATURE_NAMES, extract_features, _sensitive_words

df = pd.read_csv("urldata.csv")

# The CSV already has the 8 URL-string features pre-extracted; derive the
# extra Domain-based features (added to fix false positives on short,
# trick-free legitimate domains) from the Domain column itself so training
# and live inference use identical logic.
df["Domain_Length"] = df["Domain"].apply(lambda d: len(str(d)))
df["Num_Dots"] = df["Domain"].apply(lambda d: str(d).count("."))
df["Num_Digits"] = df["Domain"].apply(lambda d: sum(c.isdigit() for c in str(d)))
df["Sensitive_Words"] = df["Domain"].apply(lambda d: _sensitive_words("http://" + str(d)))

rows = [df[FEATURE_NAMES + ["Label"]]]

# --- Augment with known-legitimate top domains (Moz Top 500, via Kikobeats/top-sites) ---
# The original dataset has almost no "bare domain, no path" examples, and the
# handful it does have skew phishing -- causing false positives on ordinary
# root-domain lookups like "google.com". Adding real top-ranked domains,
# queried the same way a user actually would (bare domain, no path), fixes
# that blind spot instead of just special-casing it.
with open("top_sites.json") as f:
    top_domains = [entry["rootDomain"] for entry in json.load(f)]

synthetic_paths = ["", "/about", "/blog/2024/how-it-works", "/user/settings/profile", "/search?q=example"]
aug_rows = []
for d in top_domains:
    for path in synthetic_paths:
        feats = extract_features("https://" + d + path)
        aug_rows.append(dict(zip(FEATURE_NAMES, feats), Label=0))
aug_df = pd.DataFrame(aug_rows)
rows.append(aug_df)

full = pd.concat(rows, ignore_index=True)

X = full[FEATURE_NAMES]
y = full["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(n_estimators=300, max_depth=12, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

preds = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, preds):.4f}\n")
print(classification_report(y_test, preds, target_names=["legitimate", "phishing"]))

print("Feature importances:")
for name, imp in sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1]):
    print(f"  {name:15s} {imp:.3f}")

joblib.dump(model, "phishing_model.joblib")
print("\nSaved model to phishing_model.joblib")
