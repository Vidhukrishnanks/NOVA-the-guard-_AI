"""
Combines the ML prediction, rule-based checks and (optional, consented)
threat intelligence into one analysis result.

The three sources are kept clearly separate in the output:
  * result["ml"]            -> machine-learning prediction (estimate)
  * result["rules"]         -> transparent rule-based checks
  * result["threat_intel"]  -> independent verification (only if configured + consented)
"""
from __future__ import annotations

from datetime import datetime, timezone

from brand_check import check_brand_impersonation
from feature_extraction import informational_signals, mask_url, validate_url

CATEGORY_LABELS = {
    "legitimate": "Likely Legitimate",
    "suspicious": "Suspicious",
    "malicious": "Likely Malicious",
}

DISCLAIMER = ("This is an automated machine-learning estimate based only on the text of the URL. "
              "It can produce false positives (safe sites flagged) and false negatives (dangerous "
              "sites missed). It is not an official finding. The URL was not visited.")


def _reasons(ml: dict, findings: list[dict]) -> list[str]:
    reasons = []
    for c in ml.get("contributions", []):
        if c["direction"] != "increases":
            continue
        if c["kind"] == "feature":
            if not c.get("value"):
                continue  # a zero-valued feature is not a "reason" a person would recognise
            if c.get("vs_typical") in ("lower", "similar"):
                continue
            typ = f" (typical ≈ {c['typical']})" if "typical" in c else ""
            reasons.append(f"{c['label']}: {c['value']}{typ}")
    ngrams = [c["name"] for c in ml.get("contributions", [])
              if c["kind"] == "ngram" and c["direction"] == "increases"][:3]
    if ngrams:
        reasons.append("Contains character patterns the model links to malicious URLs: "
                       + ", ".join(f"“{n}”" for n in ngrams))
    for f in findings:
        if f["severity"] == "high":
            reasons.append(f["message"])
    return reasons[:8]


def _recommendations(category: str, uses_https: bool, money_risk: bool) -> list[str]:
    recs = []
    if category == "malicious":
        recs += [
            "Do not open this link, and do not download anything from it.",
            "Never enter passwords, card numbers, UPI PIN or OTPs on this site.",
            "If you already shared bank or card details, call 1930 (India cyber fraud helpline) and your bank immediately.",
            "Report the URL on the official National Cyber Crime Reporting Portal (see Report This URL).",
            "Block and report the sender on WhatsApp/SMS/email.",
        ]
    elif category == "suspicious":
        recs += [
            "Do not log in through this link. Open the official app, or type the official website address yourself.",
            "Check the domain name carefully, letter by letter, for look-alike spellings.",
            "Never share OTPs or your UPI PIN. Banks and government offices never ask for them.",
            "If unsure, verify with the organisation through its official customer-care number.",
        ]
    else:
        recs += [
            "No strong risk indicators were found, but stay careful: the model can be wrong.",
            "Confirm the domain is exactly the one you expect before entering any details.",
        ]
    if uses_https:
        recs.append("HTTPS only means the connection is encrypted. Phishing sites use HTTPS too, so it is not proof of safety.")
    else:
        recs.append("This URL does not use HTTPS, so data sent to it may not be encrypted.")
    if money_risk and category != "legitimate":
        recs.append("Treat payment, reward, refund or KYC requests from links as scams until verified.")
    return recs


def analyze_url(raw_url: str, model_service, threat_result: dict | None = None) -> dict:
    """Validate + analyse a URL string. Raises URLValidationError for bad input."""
    url = validate_url(raw_url)
    ml = model_service.predict(url, explain=True)
    findings = check_brand_impersonation(url)
    info = informational_signals(url)

    final = ml["category"]
    escalated = False
    if final == "legitimate" and any(f["severity"] == "high" for f in findings):
        final, escalated = "suspicious", True

    verified = None
    if threat_result and threat_result.get("status") == "match":
        final = "malicious"
        verified = "Listed as unsafe by Google Safe Browsing"

    feats = ml["features"]
    money_risk = feats.get("suspicious_keyword_count", 0) > 0
    return {
        "url": url,
        "url_masked": mask_url(url),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ml": ml,
        "rules": findings,
        "info": info,
        "final_category": final,
        "final_label": CATEGORY_LABELS[final],
        "escalated_by_rules": escalated,
        "verified": verified,
        "threat_intel": threat_result or {"status": "not_checked"},
        "reasons": _reasons(ml, findings),
        "recommendations": _recommendations(final, info["uses_https"], money_risk),
        "disclaimer": DISCLAIMER,
    }
