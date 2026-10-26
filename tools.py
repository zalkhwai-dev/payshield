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
            "findings": [f[2] for f in findings] or ["No offline warning signs for this link."],
            "findings_ar": [f[3] for f in findings] or ["لا توجد علامات تحذيرية في هذا الرابط."]}


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
    return {"risk_points": score, "signals": [r["en"] for r in reasons],
            "signals_ar": [r["ar"] for r in reasons]}


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


def available_tools() -> dict:
    """Tools offered to the agent. Safe Browsing only when a key is configured,
    so the agent never wastes a step on a tool that cannot answer."""
    return {n: v for n, v in TOOLS.items() if n != "safe_browsing" or os.getenv("GOOGLE_SAFE_BROWSING_KEY")}


def _ar_count(n: int, one: str, two: str, few: str, many: str) -> str:
    """Arabic number + noun: 1 يوم واحد, 2 يومين, 3-10 أيام, 11+ يوماً."""
    if n == 1:
        return one
    if n == 2:
        return two
    return f"{n} {few if 3 <= n % 100 <= 10 else many}"


def describe(name: str, r: dict) -> tuple[str, str]:
    """One plain sentence (English, Arabic) saying what a tool found, for the user."""
    if r.get("error") and name != "expand_short_link":
        return "Could not complete this check.", "تعذّر إكمال هذا الفحص."
    if name == "check_link":
        return " ".join(r.get("findings", [])), " ".join(r.get("findings_ar", []))
    if name == "domain_age":
        if r.get("registered") is False:
            return ("This website is not registered (or was just taken down), so the link cannot be real.",
                    "هذا الموقع غير مسجّل (أو حُذف للتو)، لذلك لا يمكن أن يكون الرابط حقيقياً.")
        days = r.get("age_days")
        if days is not None:
            if days < 90:
                return (f"This website was created only {days} day{'s' if days != 1 else ''} ago. "
                        "Scam sites are usually brand new.",
                        f"أُنشئ هذا الموقع قبل {_ar_count(days, 'يوم واحد', 'يومين', 'أيام', 'يوماً')} فقط. "
                        "مواقع الاحتيال عادةً جديدة جداً.")
            years = days // 365
            age_en = f"{years} year{'s' if years != 1 else ''}" if years >= 1 else f"{days} days"
            age_ar = _ar_count(years, "سنة واحدة", "سنتين", "سنوات", "سنة") if years >= 1 else \
                _ar_count(days, "يوم واحد", "يومين", "أيام", "يوماً")
            return (f"This website has existed for {age_en}.", f"هذا الموقع موجود منذ {age_ar}.")
        return "The registration date could not be found.", "تعذّر معرفة تاريخ تسجيل الموقع."
    if name == "expand_short_link":
        if r.get("final_host"):
            return (f"This link really goes to {r['final_host']}.", f"هذا الرابط يذهب فعلياً إلى {r['final_host']}.")
        return "The real destination of this link could not be opened.", "تعذّر فتح الوجهة الحقيقية لهذا الرابط."
    if name == "safe_browsing":
        if not r.get("available"):
            return "Google Safe Browsing was not available.", "خدمة Google Safe Browsing غير متاحة."
        if r.get("listed_as_dangerous"):
            return ("Google lists this link as dangerous.", "تصنّف Google هذا الرابط كرابط خطير.")
        return "Google has no reports about this link.", "لا توجد بلاغات لدى Google عن هذا الرابط."
    if name == "scan_text_rules":
        n = len(r.get("signals", []))
        if not n:
            return "No scam phrases found in the text.", "لم توجد عبارات احتيال في النص."
        return (f"Found {n} warning sign{'s' if n != 1 else ''} in the text.", f"وُجدت {_ar_count(n, 'علامة تحذيرية واحدة', 'علامتان تحذيريتان', 'علامات تحذيرية', 'علامة تحذيرية')} في النص.")
    return "", ""


def run_tool(name: str, args: dict) -> dict:
    if name not in TOOLS:
        return {"error": f"Unknown tool {name}"}
    fn, _, params = TOOLS[name]
    try:
        return fn(**{k: str(args.get(k, "")) for k in params})
    except Exception as exc:  # a broken tool must never crash the payment check
        return {"error": f"{type(exc).__name__}: {exc}"}
