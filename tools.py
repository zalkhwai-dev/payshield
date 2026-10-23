"""
Investigation tools the AI agent can call on its own.

  check_link         - lookalike / risky-ending / shortener / IP checks (offline)
  expand_short_link  - follow redirects to see where a short link really goes
  domain_age         - how many days ago the domain was registered (RDAP, free, no key)
  safe_browsing      - Google Safe Browsing threat lookup (needs GOOGLE_SAFE_BROWSING_KEY)
  scan_text_rules    - run PayShield's rule engine on any text
"""

import ipaddress
import os
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 5
UA = {"User-Agent": "PayShield/1.0 (scam check)"}


def _host(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def _is_public(host: str) -> bool:
    """Refuse to fetch internal/private addresses (basic SSRF protection)."""
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return True
    except (socket.gaierror, ValueError):
        return False


def check_link(url: str) -> dict:
    from analyzer import check_links  # local import avoids a circular import
    score, findings, hosts = check_links(url)
    return {"host": hosts[0] if hosts else _host(url), "risk_points": score,
            "findings": [f[2] for f in findings] or ["No offline warning signs for this link."]}


def expand_short_link(url: str) -> dict:
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    hops = [url]
    try:
        for _ in range(6):
            host = _host(hops[-1])
            if not host or not _is_public(host):
                return {"chain": hops, "final_url": hops[-1], "note": "Stopped: address is not public."}
            r = requests.head(hops[-1], allow_redirects=False, timeout=TIMEOUT, headers=UA)
            loc = r.headers.get("Location")
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                hops.append(urljoin(hops[-1], loc))
            else:
                break
        return {"chain": hops, "final_url": hops[-1], "final_host": _host(hops[-1])}
    except requests.RequestException as exc:
        return {"chain": hops, "error": f"Could not open link: {type(exc).__name__}"}


def domain_age(domain: str) -> dict:
    from analyzer import _registered_domain
    host = _host(domain)
    reg = _registered_domain(host)
    try:
        r = requests.get(f"https://rdap.org/domain/{reg}", timeout=(3, 4), headers=UA)
    except requests.RequestException:
        return {"domain": reg, "age_days": None, "note": "Registry lookup timed out."}
    if r.status_code == 404:
        return {"domain": reg, "age_days": None, "registered": False,
                "warning": "Domain is not registered (or was just taken down) - the link cannot be legitimate."}
    if r.status_code != 200:
        return {"domain": reg, "age_days": None, "note": f"Registry lookup returned HTTP {r.status_code}."}
    try:
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                days = (datetime.now(timezone.utc) - created).days
                return {"domain": reg, "registered": created.date().isoformat(), "age_days": days,
                        "warning": "Very new domain - typical for scam sites." if days < 90 else None}
    except (ValueError, KeyError):
        pass
    return {"domain": reg, "age_days": None, "note": "Registration date not available."}


def safe_browsing(url: str) -> dict:
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return {"available": False, "note": "Safe Browsing key not configured."}
    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": key},
            json={"client": {"clientId": "payshield", "clientVersion": "1.0"},
                  "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                                 "POTENTIALLY_HARMFUL_APPLICATION"],
                                 "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                 "threatEntries": [{"url": url}]}},
            timeout=TIMEOUT)
        r.raise_for_status()
        matches = r.json().get("matches", [])
        return {"available": True, "listed_as_dangerous": bool(matches),
                "threats": sorted({m["threatType"] for m in matches})}
    except requests.RequestException as exc:
        return {"available": False, "error": type(exc).__name__}


def scan_text_rules(text: str) -> dict:
    from analyzer import rule_engine
    score, reasons, _, _ = rule_engine(text, "goods_services", 0, "")
    return {"risk_points": score, "signals": [r["en"] for r in reasons]}


TOOLS = {
    "check_link": (check_link, "Offline check of a URL or domain for lookalike brands, risky endings, shorteners and IP links.",
                   {"url": "The URL or domain to check"}),
    "expand_short_link": (expand_short_link, "Follow redirects of a (shortened) link and return the real final destination.",
                          {"url": "The link to expand"}),
    "domain_age": (domain_age, "Look up when a domain was registered. Scam sites are usually only days or weeks old.",
                   {"domain": "Domain name, e.g. example.com"}),
    "safe_browsing": (safe_browsing, "Ask Google Safe Browsing whether a URL is a known phishing or malware site.",
                      {"url": "Full URL to check"}),
    "scan_text_rules": (scan_text_rules, "Run PayShield's Arabic/English scam rule engine on a piece of text.",
                        {"text": "Text to scan"}),
}


def run_tool(name: str, args: dict) -> dict:
    if name not in TOOLS:
        return {"error": f"Unknown tool {name}"}
    fn, _, params = TOOLS[name]
    try:
        return fn(**{k: str(args.get(k, "")) for k in params})
    except Exception as exc:  # a broken tool must never crash the payment check
        return {"error": f"{type(exc).__name__}: {exc}"}
