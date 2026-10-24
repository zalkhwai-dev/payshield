"""
Generate a SEPARATE validation set (synthetic) to check PayShield changes
before running the final test on the real 159-message dataset.

    python make_validation.py ~/Downloads/training_data/validation.csv

Uses ~8 Gemini requests. Every message is clearly marked synthetic.
Review it after: fix anything unrealistic, delete anything mislabeled.
"""

import csv
import json
import os
import re
import sys
import time
from pathlib import Path

_env = Path(__file__).with_name(".env")
if _env.exists():
    for line in _env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

import requests  # noqa: E402

import agent  # noqa: E402

# Each batch: (label, count, description). Written from general scam knowledge,
# NOT from the real test messages.
BATCHES = [
    ("scam", 20, "fake delivery / customs / parcel-fee messages (Aramex, SMSA, SPL, DHL, Naqel, Qatar Post) with links"),
    ("scam", 20, "fake bank, Absher, Nafath, government, traffic-fine, travel-ban or police-summons messages asking to click, pay or share a code"),
    ("scam", 20, "WhatsApp/X/TikTok conversations: fake jobs with fees, crypto or forex 'investment', fake jam'iya (جمعية) savings circles, fake charity or royal aid (e.g. using names of foundations), inheritance letters, prize/lottery winners"),
    ("scam", 15, "account-takeover tricks: 'I sent you a code by mistake, send it back', 'this was my old number, send me the code', 'save my new number', wrong-transfer refund requests, fake marketplace sellers asking Friends & Family"),
    ("legit", 20, "REAL-looking OTP / verification code SMS from banks, telecoms (STC, Mobily, Zain), apps (TikTok, Google, Absher) that say 'do not share this code'"),
    ("legit", 20, "REAL-looking delivery updates and driver messages (Noon, Amazon, SMSA, iMile, Keeta, Jahez, Mrsool, HungerStation) including real-brand links and delivery OTPs"),
    ("legit", 20, "REAL-looking marketing SMS and emails from Saudi brands and banks (cashback, discounts, wallet credit, 'limited time' offers) with official short links"),
    ("legit", 15, "normal personal and work messages: family, friends asking to pay back money, colleagues, university announcements, appointment reminders"),
]

PROMPT = """Write {count} different, realistic messages that people in Saudi Arabia / the Gulf receive.
Type: {desc}
Label: {label} ({meaning})

Rules:
- Mix languages naturally: mostly Arabic (Gulf/Saudi dialect and formal Arabic), some English, some mixed, a few Arabizi.
- Vary length, tone, senders, brands and formatting (emojis, line breaks, links, amounts). Avoid repeating templates.
- Use made-up numbers, names and links. Do NOT include any real person's private data.
- Scam links should look like real scam links (lookalike domains, shorteners). Legit links should be official brand domains.
Reply with ONLY JSON: {{"messages": [{{"text": "...", "sender": "...", "channel": "sms|whatsapp|email|social"}}]}}"""


def ask(label, count, desc):
    meaning = "a scam" if label == "scam" else "a genuine, safe message - but one that could LOOK suspicious"
    model = agent.gemini_model()
    body = {"contents": [{"role": "user", "parts": [{"text": PROMPT.format(count=count, desc=desc, label=label,
                                                                             meaning=meaning)}]}],
            "generationConfig": {"temperature": 1.0, "responseMimeType": "application/json"}}
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    for attempt in range(3):
        r = requests.post(url, headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"].strip()}, json=body, timeout=120)
        if r.status_code == 429:
            raise SystemExit("Gemini daily limit reached. Run again later; finished batches are kept.")
        if r.status_code >= 500:
            time.sleep(15)
            continue
        if r.status_code >= 400:
            raise RuntimeError(agent._http_error(r))
        text = "".join(p.get("text", "") for p in r.json()["candidates"][0]["content"]["parts"])
        return json.loads(re.search(r"\{.*\}", text, re.S).group(0))["messages"]
    raise RuntimeError("Gemini busy, try again later")


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "~/Downloads/training_data/validation.csv").expanduser()
    cache_file = out.with_suffix(".cache.json")
    cache = json.loads(cache_file.read_text(encoding="utf-8")) if cache_file.exists() else {}
    for i, (label, count, desc) in enumerate(BATCHES):
        key = str(i)
        if key in cache:
            continue
        print(f"Batch {i + 1}/{len(BATCHES)}: {count} {label} - {desc[:60]}...")
        cache[key] = {"label": label, "messages": ask(label, count, desc)}
        cache_file.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
        time.sleep(5)

    rows, seen = [], set()
    for key in sorted(cache, key=int):
        for m in cache[key]["messages"]:
            t = (m.get("text") or "").strip()
            if t and t not in seen:
                seen.add(t)
                rows.append({"label": cache[key]["label"], "text": t, "sender": m.get("sender", ""),
                             "channel": m.get("channel", "")})
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "label", "text", "language", "channel", "sender",
                                          "source_files", "notes", "checked"])
        w.writeheader()
        for n, r in enumerate(rows, 1):
            ar = len(re.findall(r"[؀-ۿ]", r["text"]))
            en = len(re.findall(r"[A-Za-z]", r["text"]))
            lang = "mixed" if ar and en and min(ar, en) / max(ar, en) > 0.25 else ("ar" if ar >= en else "en")
            w.writerow({"id": f"v{n}", **r, "language": lang, "source_files": "synthetic (Gemini)",
                        "notes": "", "checked": ""})
    s = sum(r["label"] == "scam" for r in rows)
    print(f"\nSaved {out}: {len(rows)} messages ({s} scam, {len(rows) - s} legit). Please review it.")


if __name__ == "__main__":
    if not agent.provider():
        raise SystemExit("Needs AI_PROVIDER=gemini and GEMINI_API_KEY in .env")
    main()
