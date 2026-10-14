"""
URL feature extraction for URLGuard AI.

IMPORTANT SECURITY NOTE
-----------------------
Everything in this module works on the URL *string* only. Nothing here
opens, visits, resolves (DNS) or fetches the URL. This prevents
server-side request forgery (SSRF) and keeps users safe.

LEAKAGE NOTE
------------
Public datasets (e.g. Kaggle "malicious_phish") store most legitimate URLs
WITHOUT a scheme ("google.com/...") while many malicious ones include
"http://". A model trained on raw strings learns "has a scheme => malicious",
which is a dataset artefact, not real security knowledge. We therefore
normalise every URL (strip scheme + leading "www.") BEFORE computing model
features. HTTPS usage is still reported to the user, but only as
information - it is never a model input, and never proof of safety.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit, parse_qsl

MAX_URL_LENGTH = 2048

# Known URL shortening services (string match on the hostname only).
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink",
    "t.ly", "s.id", "v.gd", "shorte.st", "adf.ly", "bitly.com", "lnkd.in",
    "surl.li", "qr.ae", "tr.im", "x.co", "short.io", "soo.gd", "clck.ru",
}

# Words frequently abused in phishing / fraud URLs (incl. India-specific).
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "update", "secure",
    "account", "banking", "confirm", "password", "passwd", "suspend", "locked",
    "unlock", "webscr", "ebayisapi", "wallet", "bonus", "free", "gift",
    "reward", "prize", "lucky", "winner", "refund", "claim", "kyc", "otp",
    "aadhaar", "aadhar", "pancard", "pan-card", "upi", "cashback", "loan",
    "lottery", "recharge", "blocked", "urgent", "payment", "invoice",
]

# TLDs that are cheap/free and frequently abused. Informational risk signal.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "buzz", "rest",
    "fit", "icu", "cyou", "sbs", "cfd", "click", "link", "work", "support",
    "country", "kim", "loan", "men", "date", "racing", "win", "review",
}

RISKY_EXTENSIONS = (".exe", ".apk", ".scr", ".bat", ".msi", ".jar", ".vbs", ".zip", ".rar")

# Two-level public suffixes common in India and elsewhere (offline heuristic,
# so we don't need to download the Public Suffix List at runtime).
MULTI_PART_SUFFIXES = {
    "co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in", "res.in",
    "nic.in", "firm.in", "gen.in", "ind.in", "mil.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "com.br", "com.cn", "com.sg", "com.my", "co.za", "co.nz",
    "com.pk", "com.bd", "com.np", "com.lk",
}

SPECIAL_CHARS = set("@?=&%~!*,;:+$#_|")

# Ordered list of features fed to the model. Keep in sync with extract_features().
MODEL_FEATURES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_subdomains",
    "num_hyphens",
    "num_hyphens_host",
    "num_underscores",
    "num_slashes",
    "num_query_params",
    "num_digits",
    "digit_ratio",
    "num_digits_host",
    "num_special_chars",
    "num_percent_encoded",
    "has_at_symbol",
    "has_ip_host",
    "has_port",
    "is_shortener",
    "suspicious_keyword_count",
    "has_punycode",
    "suspicious_tld",
    "path_depth",
    "has_double_slash_in_path",
    "has_http_in_path",
    "hostname_entropy",
    "longest_token_length",
    "has_risky_extension",
]

# Human-friendly descriptions used in explanations / UI.
FEATURE_DESCRIPTIONS = {
    "url_length": "Total URL length (characters)",
    "hostname_length": "Hostname length (characters)",
    "path_length": "Path length (characters)",
    "query_length": "Query-string length (characters)",
    "num_dots": "Number of dots",
    "num_subdomains": "Number of subdomains",
    "num_hyphens": "Number of hyphens in URL",
    "num_hyphens_host": "Number of hyphens in hostname",
    "num_underscores": "Number of underscores",
    "num_slashes": "Number of slashes in path",
    "num_query_params": "Number of query parameters",
    "num_digits": "Number of digits",
    "digit_ratio": "Share of characters that are digits",
    "num_digits_host": "Digits in hostname",
    "num_special_chars": "Special characters (@ ? = & % ~ ! * etc.)",
    "num_percent_encoded": "Percent-encoded sequences (%xx)",
    "has_at_symbol": "Contains '@' symbol",
    "has_ip_host": "Uses an IP address instead of a domain name",
    "has_port": "Specifies an explicit port",
    "is_shortener": "Uses a URL-shortening service",
    "suspicious_keyword_count": "Suspicious keywords (login, verify, kyc, otp...)",
    "has_punycode": "Internationalised (punycode / xn--) hostname",
    "suspicious_tld": "Top-level domain frequently abused",
    "path_depth": "Path depth (number of folders)",
    "has_double_slash_in_path": "'//' inside the path (possible redirect)",
    "has_http_in_path": "'http' text inside path or query (possible redirect)",
    "hostname_entropy": "Hostname randomness (Shannon entropy)",
    "longest_token_length": "Longest word/token length",
    "has_risky_extension": "Links to a risky file type (.apk, .exe, ...)",
}

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_HOST_ALLOWED = re.compile(r"^[a-z0-9.\-\[\]:_]+$")


class URLValidationError(ValueError):
    """Raised when user input is not an acceptable http(s) URL string."""


def validate_url(raw: str) -> str:
    """Validate and lightly clean a user-supplied URL string.

    Returns the cleaned URL (with a scheme added if it was missing).
    Raises URLValidationError with a user-friendly message otherwise.
    The URL is NEVER fetched.
    """
    if raw is None:
        raise URLValidationError("Please enter a URL.")
    url = str(raw).strip()
    if not url:
        raise URLValidationError("Please enter a URL.")
    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if _CONTROL_CHARS.search(url):
        raise URLValidationError("URL contains invalid control characters.")
    if " " in url:
        raise URLValidationError("URL must not contain spaces.")

    lowered = url.lower()
    if _SCHEME_RE.match(url):
        scheme = lowered.split("://", 1)[0]
        if scheme not in ("http", "https"):
            raise URLValidationError("Only http:// and https:// URLs can be analysed.")
    elif re.match(r"^(javascript|data|file|vbscript|mailto|ftp):", lowered):
        raise URLValidationError("Only http:// and https:// URLs can be analysed.")
    else:
        url = "http://" + url  # assume web URL; only used for parsing

    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port  # raises ValueError on an invalid port
    except ValueError as exc:
        raise URLValidationError("That does not look like a valid URL.") from exc

    if not host:
        raise URLValidationError("URL must include a domain name or IP address.")
    try:
        host_ascii = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError as exc:
        raise URLValidationError("URL has an invalid international domain name.") from exc
    if not _HOST_ALLOWED.match(host_ascii.lower()):
        raise URLValidationError("URL hostname contains invalid characters.")
    if "." not in host_ascii and not _is_ip(host_ascii) and host_ascii != "localhost":
        raise URLValidationError("URL hostname must contain a dot (e.g. example.com).")
    return url


def _is_ip(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Decimal / hex encoded IPv4 tricks such as http://3232235777/ or 0x7f.1
    if re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"(0x[0-9a-f]+\.?){1,4}", host):
        return True
    return False


def normalize_url(url: str) -> str:
    """Remove scheme and leading 'www.', lower-case the host, drop trailing '/'.

    This is the text representation the model sees (see LEAKAGE NOTE).
    """
    u = str(url).strip()
    u = _SCHEME_RE.sub("", u)
    if u.lower().startswith("www."):
        u = u[4:]
    # lower-case the host part only
    slash = re.search(r"[/?#]", u)
    if slash:
        u = u[: slash.start()].lower() + u[slash.start():]
    else:
        u = u.lower()
    u = u.split("#", 1)[0]  # fragments never reach servers; ignore them
    if u.endswith("/"):
        u = u.rstrip("/")
    return u


def registered_domain(host: str) -> str:
    """Approximate registrable domain, e.g. 'login.sbi.co.in' -> 'sbi.co.in'."""
    host = (host or "").lower().strip(".")
    if not host or _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parse_parts(url: str) -> dict:
    """Split a URL string into components without any network access."""
    work = url if _SCHEME_RE.match(url) else "http://" + url
    try:
        parts = urlsplit(work)
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = None
    except ValueError:
        return {"scheme": "", "host": "", "port": None, "path": "", "query": "", "had_scheme": False}
    if host and not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return {
        "scheme": parts.scheme.lower() if _SCHEME_RE.match(url) else "",
        "host": host,
        "port": port,
        "path": parts.path or "",
        "query": parts.query or "",
        "had_scheme": bool(_SCHEME_RE.match(url)),
    }


def extract_features(url: str) -> dict:
    """Compute the numeric model features for one URL string.

    Works on dataset rows (which may lack a scheme) and on validated user input.
    """
    parts = parse_parts(str(url))
    host = parts["host"]
    if host.startswith("www."):
        host = host[4:]
    path, query = parts["path"], parts["query"]
    norm = normalize_url(url)
    lower = norm.lower()

    reg = registered_domain(host)
    is_ip = _is_ip(host)
    host_labels = [l for l in host.split(".") if l]
    reg_labels = reg.split(".") if reg else []
    num_subdomains = 0 if is_ip else max(0, len(host_labels) - len(reg_labels))
    tld = host_labels[-1] if host_labels and not is_ip else ""

    digits = sum(ch.isdigit() for ch in norm)
    tokens = [t for t in re.split(r"[^a-zA-Z0-9]", norm) if t]
    after_host = norm[len(host):] if norm.startswith(host) else norm

    feats = {
        "url_length": len(norm),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": norm.count("."),
        "num_subdomains": num_subdomains,
        "num_hyphens": norm.count("-"),
        "num_hyphens_host": host.count("-"),
        "num_underscores": norm.count("_"),
        "num_slashes": path.count("/"),
        "num_query_params": len(parse_qsl(query, keep_blank_values=True)),
        "num_digits": digits,
        "digit_ratio": round(digits / len(norm), 4) if norm else 0.0,
        "num_digits_host": sum(ch.isdigit() for ch in host),
        "num_special_chars": sum(ch in SPECIAL_CHARS for ch in norm),
        "num_percent_encoded": len(re.findall(r"%[0-9a-fA-F]{2}", norm)),
        "has_at_symbol": int("@" in norm),
        "has_ip_host": int(is_ip),
        "has_port": int(parts["port"] is not None),
        "is_shortener": int(host in SHORTENERS or reg in SHORTENERS),
        "suspicious_keyword_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower),
        "has_punycode": int("xn--" in host),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "path_depth": len([p for p in path.split("/") if p]),
        "has_double_slash_in_path": int("//" in path),
        "has_http_in_path": int("http" in after_host.lower()),
        "hostname_entropy": round(_entropy(host), 4),
        "longest_token_length": max((len(t) for t in tokens), default=0),
        "has_risky_extension": int(path.lower().endswith(RISKY_EXTENSIONS)),
    }
    return feats


def informational_signals(url: str) -> dict:
    """Facts shown to the user that are NOT model inputs (e.g. HTTPS)."""
    parts = parse_parts(url)
    return {
        "scheme": parts["scheme"] or "(none given)",
        "uses_https": parts["scheme"] == "https",
        "hostname": parts["host"],
        "registered_domain": registered_domain(parts["host"]),
    }


def mask_url(url: str) -> str:
    """Privacy-preserving version for storage: keep parameter NAMES, hide values.

    'https://x.com/a?token=abc&id=5#frag' -> 'https://x.com/a?token=***&id=***'
    """
    try:
        parts = urlsplit(url if _SCHEME_RE.match(url) else "http://" + url)
    except ValueError:
        return "(unparseable URL)"
    base = f"{parts.scheme}://{parts.netloc.rsplit('@', 1)[-1]}{parts.path}"
    if parts.query:
        names = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
        if names:
            base += "?" + "&".join(f"{k}=***" for k in names[:20])
        else:
            base += "?***"
    return base[:500]
