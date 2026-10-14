"""
Rule-based Indian brand look-alike detection.

This is NOT machine learning. It is a transparent set of rules that flags
URLs which *mention* a well-known Indian brand but are not hosted on that
brand's official domain, or whose domain is a near-miss spelling of it
(typosquatting / homoglyphs). Results are shown separately from the ML
prediction so users can tell the two apart.

The URL is never visited.
"""
from __future__ import annotations

import re

from feature_extraction import parse_parts, registered_domain

# brand key -> (display name, official registered domains, extra trigger tokens)
BRANDS = {
    "sbi": ("State Bank of India", {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "sbilife.co.in", "onlinesbi.com", "sbimf.com", "sbigeneral.in", "sbisecurities.in"}, {"onlinesbi", "yonosbi", "yono"}),
    "hdfc": ("HDFC Bank", {"hdfcbank.com", "hdfc.com", "hdfcbank.bank.in", "hdfclife.com", "hdfcergo.com", "hdfcsec.com", "hdfcfund.com", "hdfcsky.com"}, {"hdfcbank"}),
    "icici": ("ICICI Bank", {"icicibank.com", "icicidirect.com", "icicibank.bank.in", "iciciprulife.com", "icicilombard.com", "icicipru.com", "icicipruamc.com", "icicisecurities.com"}, {"icicibank"}),
    "axis": ("Axis Bank", {"axisbank.com", "axisbank.bank.in", "axisdirect.in", "axismf.com", "axismaxlife.com"}, {"axisbank"}),
    "kotak": ("Kotak Mahindra Bank", {"kotak.com", "kotak.bank.in", "kotaksecurities.com", "kotaklife.com", "kotakmf.com"}, {"kotakbank"}),
    "pnb": ("Punjab National Bank", {"pnbindia.in", "pnb.bank.in", "netpnb.com"}, {"pnbindia"}),
    "canarabank": ("Canara Bank", {"canarabank.com", "canarabank.bank.in"}, set()),
    "federalbank": ("Federal Bank", {"federalbank.co.in", "federalbank.bank.in"}, set()),
    "paytm": ("Paytm", {"paytm.com", "paytm.in", "paytmbank.com", "paytmmoney.com", "paytmmall.com", "paytmpayments.com"}, set()),
    "phonepe": ("PhonePe", {"phonepe.com"}, set()),
    "gpay": ("Google Pay", {"google.com", "gpay.app"}, {"googlepay"}),
    "bhim": ("BHIM / NPCI", {"npci.org.in", "bhimupi.org.in"}, {"npci", "bhimupi"}),
    "irctc": ("IRCTC", {"irctc.co.in", "irctc.com", "irctctourism.com", "irctcipay.com"}, set()),
    "uidai": ("UIDAI (Aadhaar)", {"uidai.gov.in", "gov.in"}, {"aadhaar", "aadhar", "myaadhaar"}),
    "incometax": ("Income Tax Department", {"incometax.gov.in", "incometaxindia.gov.in", "gov.in"}, {"incometaxindia", "itrefund"}),
    "epfo": ("EPFO", {"epfindia.gov.in", "gov.in"}, {"epfindia"}),
    "indiapost": ("India Post", {"indiapost.gov.in", "gov.in", "ippbonline.com"}, {"ippb"}),
    "amazon": ("Amazon", {"amazon.in", "amazon.com", "amazon.de", "amazon.ae", "amazon.sg", "amazon.co.jp", "amazon.ca", "amazon.fr", "amazon.com.au", "amazonpay.in", "amazon.co.uk", "amazon.co.in", "amazonaws.com", "media-amazon.com", "ssl-images-amazon.com", "amazon.jobs"}, {"amazonpay"}),
    "flipkart": ("Flipkart", {"flipkart.com"}, set()),
    "airtel": ("Airtel", {"airtel.in", "airtel.com", "airtelxstream.in", "airtelthanks.com"}, set()),
    "jio": ("Jio", {"jio.com", "jiomart.com", "ril.com", "jiosaavn.com", "jiocinema.com", "jiohotstar.com", "jiofinance.com"}, {"myjio"}),
    "kseb": ("KSEB (Kerala electricity)", {"kseb.in"}, set()),
    "whatsapp": ("WhatsApp", {"whatsapp.com", "whatsapp.net", "wa.me"}, set()),
}

# Real, unrelated domains that happen to look like a brand name (avoid false alarms).
KNOWN_LEGIT_LOOKALIKES = {"kodak.com", "axios.com", "paypal.com", "jira.com", "amazona.com"}

# Brands that own a dedicated top-level domain (e.g. anything.sbi belongs to SBI).
BRAND_TLDS = {"sbi": "sbi"}

# Common digit/letter substitutions used in look-alike domains.
_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


def _levenshtein(a: str, b: str) -> int:
    """Edit distance counting a swap of two neighbouring letters as one edit
    (Damerau / optimal string alignment), e.g. 'flipkrat' vs 'flipkart' = 1."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _is_official(reg: str, host: str, officials: set[str]) -> bool:
    return reg in officials or any(host == o or host.endswith("." + o) for o in officials)


def check_brand_impersonation(url: str) -> list[dict]:
    """Return a list of findings. Each finding has severity 'high' or 'low'."""
    parts = parse_parts(url)
    host = parts["host"]
    if not host:
        return []
    reg = registered_domain(host)
    host_tokens = set(t for t in re.split(r"[^a-z0-9]", host) if t)
    reg_label = reg.split(".")[0] if reg else ""
    path_tokens = set(t for t in re.split(r"[^a-z0-9]", (parts["path"] + " " + parts["query"]).lower()) if t)
    findings: list[dict] = []

    tld = host.rsplit(".", 1)[-1]
    if reg in KNOWN_LEGIT_LOOKALIKES:
        return []
    for key, (name, officials, extra) in BRANDS.items():
        if _is_official(reg, host, officials) or BRAND_TLDS.get(key) == tld:
            continue
        triggers = {key} | extra
        # 1) Brand name used inside the hostname of a non-official domain
        hit = sorted(t for t in host_tokens if t in triggers or any(
            t.startswith(trig) and len(trig) >= 4 for trig in triggers))
        if hit:
            findings.append({
                "rule": "brand_in_unofficial_host",
                "severity": "high",
                "brand": name,
                "message": f"Hostname mentions '{hit[0]}' ({name}) but '{reg}' is not on URLGuard's list of its official domains.",
            })
            continue
        # 2) Typosquatting / homoglyph near-miss of the brand label
        cand = reg_label.translate(_CONFUSABLES)
        if len(key) >= 4 and reg_label and reg_label != key:
            near = len(key) >= 5 and (_levenshtein(cand, key) == 1 or _levenshtein(cand, key + "bank") == 1)
            if cand == key or near:
                findings.append({
                    "rule": "lookalike_domain",
                    "severity": "high",
                    "brand": name,
                    "message": f"Domain '{reg}' looks like a misspelling or look-alike of {name}.",
                })
                continue
        # 3) Brand mentioned only in path/query (weak signal: could be a news article)
        if path_tokens & triggers:
            findings.append({
                "rule": "brand_in_path",
                "severity": "low",
                "brand": name,
                "message": f"Path mentions {name}, but the site is not an official {name} domain (weak signal).",
            })

    if "xn--" in host:
        findings.append({
            "rule": "punycode_host",
            "severity": "high",
            "brand": None,
            "message": "Hostname uses punycode (xn--), which can hide look-alike characters from other alphabets.",
        })
    return findings
