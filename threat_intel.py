"""
Optional threat-intelligence lookup (Google Safe Browsing Lookup API v4).

Privacy & safety rules enforced here:
  * Disabled unless SAFE_BROWSING_API_KEY is set in the environment.
  * Called only when the user explicitly ticks the consent box for that scan.
  * We send the URL string to Google's fixed API endpoint only. We never
    request the submitted URL itself (no SSRF possible).
  * Every outcome is reported honestly: 'unavailable', 'no_match', 'match' or 'error'.
    'no_match' is NOT proof of safety - it only means the URL is not on Google's lists.
"""
from __future__ import annotations

from datetime import datetime, timezone

import requests

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PROVIDER_NAME = "Google Safe Browsing (Lookup API v4)"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ThreatIntel:
    def __init__(self, api_key: str | None, timeout: float = 5.0, client_version: str = "1.0"):
        self.api_key = (api_key or "").strip() or None
        self.timeout = timeout
        self.client_version = client_version

    @property
    def configured(self) -> bool:
        return self.api_key is not None

    def status(self) -> dict:
        return {
            "provider": PROVIDER_NAME,
            "configured": self.configured,
            "message": ("Configured. Lookups run only when you tick the consent box."
                        if self.configured else
                        "Unavailable: no SAFE_BROWSING_API_KEY is configured. See README to enable it."),
        }

    def check(self, url: str, consent: bool) -> dict:
        base = {"provider": PROVIDER_NAME, "checked_at": _now()}
        if not self.configured:
            return {**base, "status": "unavailable",
                    "message": "Reputation check unavailable: no provider configured."}
        if not consent:
            return {**base, "status": "not_checked",
                    "message": "Not checked: you did not consent to sending this URL to Google Safe Browsing."}
        payload = {
            "client": {"clientId": "urlguard-ai", "clientVersion": self.client_version},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            resp = requests.post(SAFE_BROWSING_ENDPOINT, params={"key": self.api_key},
                                 json=payload, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            return {**base, "status": "error", "message": f"Lookup failed ({type(exc).__name__}). No result."}
        if resp.status_code != 200:
            return {**base, "status": "error",
                    "message": f"Provider returned HTTP {resp.status_code}. Check your API key. No result."}
        try:
            data = resp.json()
        except ValueError:
            return {**base, "status": "error", "message": "Provider returned an unreadable response."}
        matches = data.get("matches", [])
        if matches:
            types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return {**base, "status": "match", "threats": types,
                    "message": "Listed by Google Safe Browsing as: " + ", ".join(types)}
        return {**base, "status": "no_match", "threats": [],
                "message": "Not found on Google Safe Browsing lists. This is not proof the site is safe."}
