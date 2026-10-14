"""
Generate a SYNTHETIC demo dataset so the app works before you download a
real dataset.

    python generate_demo_data.py

Output: data/demo_synthetic_urls.csv  (columns: url, type)

WARNING: These URLs are machine-generated from templates. A model trained on
them only demonstrates the workflow. Its metrics say NOTHING about real-world
detection performance. Use the Kaggle "malicious_phish" dataset (see
README.md) for meaningful results.
"""
from __future__ import annotations

import argparse
import csv
import random
import string
from pathlib import Path

BENIGN_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.in", "flipkart.com",
    "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "irctc.co.in", "incometax.gov.in",
    "uidai.gov.in", "thehindu.com", "manoramaonline.com", "mathrubhumi.com",
    "ndtv.com", "timesofindia.indiatimes.com", "github.com", "stackoverflow.com",
    "microsoft.com", "apple.com", "linkedin.com", "zomato.com", "swiggy.com",
    "paytm.com", "phonepe.com", "kerala.gov.in", "keralatourism.org", "cusat.ac.in",
    "iitm.ac.in", "nptel.ac.in", "python.org", "w3schools.com", "medium.com",
    "bbc.co.uk", "reddit.com", "instagram.com", "netflix.com", "hotstar.com",
    "myntra.com", "bigbasket.com", "makemytrip.com", "kseb.in", "airtel.in",
    "jio.com", "india.gov.in", "digilocker.gov.in", "rbi.org.in", "npci.org.in",
    "coursera.org", "khanacademy.org", "bookmyshow.com", "olx.in", "justdial.com",
]
BENIGN_SUBS = ["", "", "", "www.", "www.", "m.", "docs.", "blog.", "support.", "news."]
BENIGN_PATHS = [
    "", "about", "contact", "news/{w}-{w}", "products/{w}", "search?q={w}",
    "{w}/{w}", "help/{w}", "articles/{n}/{w}-{w}-{w}", "watch?v={id}",
    "wiki/{W}_{W}", "in/{w}", "category/{w}/{n}", "{w}.html", "user/{w}",
    "courses/{w}-{w}", "careers", "privacy-policy", "en/{w}/{w}",
]
WORDS = [
    "india", "kerala", "travel", "food", "cricket", "python", "learning", "music",
    "movies", "health", "science", "market", "weather", "budget", "election",
    "festival", "onam", "kochi", "school", "college", "results", "jobs", "phone",
    "laptop", "shoes", "books", "recipe", "temple", "beach", "history", "data",
    "machine", "model", "research", "sports", "football", "startup", "finance",
]
BRANDS = ["sbi", "hdfc", "icici", "paytm", "phonepe", "irctc", "amazon", "flipkart",
          "axisbank", "kotak", "airtel", "jio", "uidai", "aadhaar", "incometax", "kseb", "epfo"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "online", "site", "info", "club", "icu", "buzz", "live", "in", "com"]
BAD_WORDS = ["login", "verify", "update", "secure", "account", "kyc", "otp", "reward",
             "bonus", "refund", "claim", "support", "alert", "confirm", "unlock", "wallet", "gift"]
SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.ly"]


def _rid(rng, k=8, chars=string.ascii_lowercase + string.digits):
    return "".join(rng.choice(chars) for _ in range(k))


def _fill(rng, template: str) -> str:
    out = template
    while "{w}" in out:
        out = out.replace("{w}", rng.choice(WORDS), 1)
    while "{W}" in out:
        out = out.replace("{W}", rng.choice(WORDS).capitalize(), 1)
    while "{n}" in out:
        out = out.replace("{n}", str(rng.randint(1, 99999)), 1)
    while "{id}" in out:
        out = out.replace("{id}", _rid(rng, 11, string.ascii_letters + string.digits + "-_"), 1)
    return out


def benign(rng) -> str:
    dom = rng.choice(BENIGN_DOMAINS)
    sub = rng.choice(BENIGN_SUBS)
    path = _fill(rng, rng.choice(BENIGN_PATHS))
    scheme = rng.choice(["", "", "https://", "http://"])
    url = f"{scheme}{sub}{dom}"
    return url + ("/" + path if path else "")


def malicious(rng) -> tuple[str, str]:
    kind = rng.random()
    brand = rng.choice(BRANDS)
    bw = rng.choice(BAD_WORDS)
    tld = rng.choice(BAD_TLDS)
    scheme = rng.choice(["", "http://", "https://"])
    if kind < 0.18:  # brand in subdomain of random domain
        url = f"{scheme}{brand}.{bw}-{_rid(rng, 5)}.{tld}/{bw}/index.php?id={_rid(rng, 12)}"
        t = "phishing"
    elif kind < 0.34:  # brand-keyword hyphen combo
        url = f"{scheme}{brand}-{bw}-{rng.choice(BAD_WORDS)}.{tld}/{rng.choice(['', 'login', 'verify.html', 'kyc/update'])}"
        t = "phishing"
    elif kind < 0.46:  # IP based host
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        port = rng.choice(["", "", ":8080", ":8443"])
        url = f"http://{ip}{port}/{brand}/{bw}.php?session={_rid(rng, 16)}"
        t = "phishing"
    elif kind < 0.56:  # malware downloads
        url = f"{scheme}{_rid(rng, rng.randint(6, 14))}.{tld}/{rng.choice(['download', 'files', 'app', 'apk'])}/{rng.choice(WORDS)}_{_rid(rng, 4)}.{rng.choice(['apk', 'exe', 'zip', 'scr'])}"
        t = "malware"
    elif kind < 0.64:  # typosquats
        typo = brand.replace("a", "4", 1) if "a" in brand else brand + "s"
        if rng.random() < 0.5 and len(brand) > 3:
            i = rng.randint(1, len(brand) - 2)
            typo = brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:]
        url = f"{scheme}{typo}.{rng.choice(['com', 'in', 'net', 'co', 'xyz'])}/{bw}"
        t = "phishing"
    elif kind < 0.72:  # @ trick and redirects
        url = f"http://{brand}.com@{_rid(rng, 9)}.{tld}/{bw}?redirect=http://{_rid(rng, 6)}.{tld}/{bw}"
        t = "phishing"
    elif kind < 0.80:  # defacement-like long query strings on hacked CMS sites
        url = f"http://{_rid(rng, 7)}.{rng.choice(['com', 'org', 'in', 'net'])}/index.php?option=com_{rng.choice(['content', 'user', 'k2'])}&view={rng.choice(['article', 'item'])}&id={rng.randint(1, 999)}:{_rid(rng, 10)}&Itemid={rng.randint(1, 99)}"
        t = "defacement"
    elif kind < 0.86:  # shortener
        url = f"{scheme}{rng.choice(SHORTENERS)}/{_rid(rng, rng.randint(5, 8), string.ascii_letters + string.digits)}"
        t = "phishing"
    elif kind < 0.93:  # random high-entropy hosts with many subdomains
        url = f"{scheme}{_rid(rng, 4)}.{_rid(rng, 6)}.{_rid(rng, 12)}.{tld}/{_rid(rng, 20)}/{bw}"
        t = "malware"
    else:  # free hosting abuse
        host = rng.choice(["000webhostapp.com", "weebly.com", "web.app", "firebaseapp.com", "blogspot.com", "netlify.app"])
        url = f"{scheme}{brand}-{bw}-{_rid(rng, 4)}.{host}/{rng.choice(['', 'index.html', 'login.html'])}"
        t = "phishing"
    return url.rstrip("/"), t


def generate(n: int, seed: int = 42, malicious_share: float = 0.4, noise: float = 0.02) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    rows = []
    for _ in range(n):
        if rng.random() < malicious_share:
            url, t = malicious(rng)
        else:
            url, t = benign(rng), "benign"
        # small label noise so demo metrics are not a perfect 100%
        if rng.random() < noise:
            t = "benign" if t != "benign" else "phishing"
        rows.append((url, t))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rows", type=int, default=15000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(Path(__file__).parent / "data" / "demo_synthetic_urls.csv"))
    args = ap.parse_args()
    rows = generate(args.rows, args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "type"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} SYNTHETIC rows to {out}")
    print("Reminder: synthetic data demonstrates the workflow only - not real-world performance.")


if __name__ == "__main__":
    main()
