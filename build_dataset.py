"""
Turn the scam / legit screenshots into one spreadsheet (CSV) for the benchmark.

Usage (from the payshield folder, with your .env containing GEMINI_API_KEY):
    python build_dataset.py ~/Downloads/training_data

- Reads every image in <folder>/scam and <folder>/legit with Gemini.
- Splits threads of separate notifications (e.g. many Mobily ads) into one row per message.
- Merges conversations that were split across several screenshots into one row.
- Removes near-duplicate messages.
- Saves progress after every image, so you can stop (Ctrl+C) and run it again to continue.
- Writes <folder>/dataset.csv  (opens in Excel / Numbers; Arabic shows correctly).
"""

import csv
import difflib
import json
import os
import re
import sys
import time
from pathlib import Path

# --- load .env (same as app.py) ------------------------------------------------
_env = Path(__file__).with_name(".env")
if _env.exists():
    for line in _env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

import base64  # noqa: E402

import requests  # noqa: E402

import agent  # noqa: E402

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".heic"}
MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".heic": "image/heic"}
PAUSE = float(os.getenv("DATASET_PAUSE", "4"))   # seconds between calls (free-tier friendly)

# Conversations that were captured in several screenshots -> one benchmark row.
GROUPS = [
    ["scam/IMG_3643", "scam/IMG_3644", "scam/IMG_3645"],
    ["scam/IMG_3677", "scam/IMG_3678"],
    ["scam/IMG_3681", "scam/IMG_3682"],
    ["scam/IMG_3683", "scam/IMG_3684"],
    ["scam/IMG_3694", "scam/IMG_3695"],
]

PROMPT = """You are preparing a dataset of real messages. This is a phone screenshot.
Transcribe the message text EXACTLY as written, in its original language (Arabic stays Arabic). Do not translate or fix spelling.
Include links, amounts and the sender name if shown. Ignore phone UI (clock, battery, keyboard, buttons like Reply/Block, app menus).
Some parts are covered with green boxes for privacy: write [REDACTED] in their place.

Splitting rule:
- If the screenshot shows several SEPARATE notifications/ads/SMS sent on different dates by the same sender, return each one as a separate item.
- If it is one conversation (several bubbles back and forth), one email, or one post, return ONE item with the whole text in order.
- If the screenshot shows a video/TikTok/news report ABOUT a scam, transcribe only the scam message itself.

Reply with ONLY this JSON:
{"channel": "sms" | "whatsapp" | "email" | "social" | "other",
 "sender": "sender name/number/email as shown, or empty",
 "items": ["message 1 text", "message 2 text"]}"""


def read_image(path: Path) -> dict:
    b64 = base64.b64encode(path.read_bytes()).decode()
    mime = MIME.get(path.suffix.lower(), "image/png")
    model = agent.gemini_model()
    body = {"contents": [{"role": "user", "parts": [{"inlineData": {"mimeType": mime, "data": b64}}, {"text": PROMPT}]}],
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json"}}
    thinking = agent._thinking_config(model)
    if thinking:
        body["generationConfig"]["thinkingConfig"] = thinking
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {"x-goog-api-key": os.environ["GEMINI_API_KEY"].strip()}
    for attempt in range(4):
        r = requests.post(url, headers=headers, json=body, timeout=90)
        if r.status_code == 429 or r.status_code >= 500:     # rate limit / busy: wait and retry
            wait = 20 * (attempt + 1)
            print(f"    Gemini busy ({r.status_code}), waiting {wait}s ...")
            time.sleep(wait)
            continue
        if r.status_code >= 400:
            raise RuntimeError(agent._http_error(r))
        parts = r.json()["candidates"][0]["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts)
        m = re.search(r"\{.*\}", text, re.S)
        data = json.loads(m.group(0))
        items = [i.strip() for i in data.get("items", []) if isinstance(i, str) and i.strip()]
        return {"channel": data.get("channel", "other"), "sender": data.get("sender", ""), "items": items}
    raise RuntimeError("Gemini kept refusing (rate limit). Wait a few minutes and run again.")


TIME_ONLY = re.compile(r"(\d{1,2}:\d{2}\s*(AM|PM|ص|م)?|[\d:\s]*(ص|م))", re.I)


def language(text: str) -> str:
    ar = len(re.findall(r"[؀-ۿ]", text))
    en = len(re.findall(r"[A-Za-z]", text))
    if ar and en and min(ar, en) / max(ar, en) > 0.25:
        return "mixed"
    return "ar" if ar >= en else "en"


def _norm(t: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w؀-ۿ ]", " ", t)).strip().lower()


def build(folder: Path):
    cache_file = folder / "dataset_cache.json"
    cache = json.loads(cache_file.read_text(encoding="utf-8")) if cache_file.exists() else {}

    files = []
    for label in ("scam", "legit"):
        d = folder / label
        if d.is_dir():
            files += [(label, p) for p in sorted(d.iterdir()) if p.suffix.lower() in IMAGE_EXT]
    if not files:
        raise SystemExit(f"No images found in {folder}/scam or {folder}/legit")

    todo = [(l, p) for l, p in files if f"{l}/{p.stem}" not in cache]
    print(f"{len(files)} screenshots found, {len(files) - len(todo)} already read, {len(todo)} to read.")
    print(f"Model: {agent.gemini_model()}   (about {round(len(todo) * (PAUSE + 4) / 60)} min)\n")

    for n, (label, path) in enumerate(todo, 1):
        key = f"{label}/{path.stem}"
        print(f"[{n}/{len(todo)}] {key} ...", end=" ", flush=True)
        try:
            cache[key] = {"label": label, "file": f"{label}/{path.name}", **read_image(path)}
            print(f"{len(cache[key]['items'])} message(s)")
        except KeyboardInterrupt:
            print("\nStopped. Run the same command again to continue.")
            break
        except Exception as exc:
            print(f"FAILED: {agent.redact(exc)[:150]}")
            continue
        cache_file.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
        time.sleep(PAUSE)

    # --- merge split conversations -------------------------------------------
    rows, used = [], set()
    for group in GROUPS:
        members = [cache[k] for k in group if k in cache]
        if not members:
            continue
        lines, seen = [], set()
        for m in members:
            for item in [i for i in m["items"] if not TIME_ONLY.fullmatch(i.strip())]:
                for line in item.splitlines():
                    key = _norm(line)
                    if key and key not in seen:
                        seen.add(key)
                        lines.append(line)
        rows.append({"label": members[0]["label"], "text": "\n".join(lines), "channel": members[0]["channel"],
                     "sender": members[0]["sender"], "source_files": " + ".join(m["file"] for m in members),
                     "notes": "merged from several screenshots"})
        used.update(group)

    for key, entry in cache.items():
        if key in used:
            continue
        items = [i for i in entry["items"] if not TIME_ONLY.fullmatch(i.strip())]
        if not items:
            continue
        # Only threads of separate legit SMS notifications become one row per message.
        # Everything else (chats, scam messages, emails, posts) stays ONE row, so a
        # conversation is judged as a whole - like PayShield would see it.
        if entry["label"] == "legit" and entry["channel"] == "sms" and len(items) > 1:
            for item in items:
                rows.append({"label": entry["label"], "text": item, "channel": entry["channel"],
                             "sender": entry["sender"], "source_files": entry["file"], "notes": "from a thread"})
        else:
            lines, seen = [], set()
            for item in items:
                if _norm(item) not in seen:
                    seen.add(_norm(item))
                    lines.append(item)
            rows.append({"label": entry["label"], "text": "\n".join(lines), "channel": entry["channel"],
                         "sender": entry["sender"], "source_files": entry["file"], "notes": ""})

    # --- remove near-duplicates (same ad captured twice, overlapping threads) --
    unique = []
    for row in rows:
        n = _norm(row["text"])
        dup = next((u for u in unique if u["label"] == row["label"] and
                    difflib.SequenceMatcher(None, _norm(u["text"]), n).ratio() > 0.92), None)
        if dup:
            if row["source_files"] not in dup["source_files"]:
                dup["source_files"] += " + " + row["source_files"]
            dup["notes"] = (dup["notes"] + "; " if dup["notes"] else "") + "duplicate removed"
        else:
            unique.append(row)

    out = folder / "dataset.csv"
    with out.open("w", encoding="utf-8-sig", newline="") as f:     # utf-8-sig so Excel shows Arabic
        w = csv.DictWriter(f, fieldnames=["id", "label", "text", "language", "channel", "sender",
                                          "source_files", "notes", "checked"])
        w.writeheader()
        for i, row in enumerate(unique, 1):
            w.writerow({"id": i, **row, "language": language(row["text"]), "checked": ""})

    s = sum(r["label"] == "scam" for r in unique)
    print(f"\nSaved {out}")
    print(f"{len(unique)} unique messages: {s} scam, {len(unique) - s} legit "
          f"({len(rows) - len(unique)} duplicates removed).")
    missing = len(files) - len([k for k in cache if any(k == f'{l}/{p.stem}' for l, p in files)])
    if missing:
        print(f"{missing} screenshot(s) failed. Run the command again to retry them.")


if __name__ == "__main__":
    if not agent.provider() or os.getenv("AI_PROVIDER", "").lower() != "gemini":
        raise SystemExit("This needs AI_PROVIDER=gemini and GEMINI_API_KEY in .env")
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else "~/Downloads/training_data").expanduser()
    build(folder)
