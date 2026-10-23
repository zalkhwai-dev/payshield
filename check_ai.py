"""
Check that your AI key works and pick the fastest model.  Run:  python check_ai.py
It never prints your key.
"""

import os
import re
import time
from pathlib import Path

import requests

env = Path(__file__).with_name(".env")
if not env.exists():
    raise SystemExit("No .env file found in this folder. Run:  cp .env.example .env")
for line in env.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

import agent  # noqa: E402

prov = os.getenv("AI_PROVIDER", "").strip()
key = os.getenv("GEMINI_API_KEY" if prov == "gemini" else "ANTHROPIC_API_KEY", "").strip()
print(f"AI_PROVIDER = {prov or '(empty)'}")
print(f"Key found   = {'yes, ' + str(len(key)) + ' characters' if key else 'NO - the key line is empty'}")
if not agent.provider():
    raise SystemExit("\nAI is not configured. Set AI_PROVIDER=gemini and GEMINI_API_KEY=... in .env")


def explain(exc) -> str:
    msg = agent.redact(exc)
    if "401" in msg or "403" in msg or "API key not valid" in msg:
        msg += "\n   Google rejected the key. Copy it again from aistudio.google.com/apikey with the copy button."
    elif "429" in msg:
        msg += "\n   Free-tier limit reached. Wait a minute and try again."
    return msg


if prov == "gemini":
    print("\n1) Models available to your key ...")
    try:
        models = agent.gemini_models()
    except Exception as exc:
        raise SystemExit(f"   FAILED: {explain(exc)}")
    if not models:
        raise SystemExit("   No Gemini 'flash' models found for this key.")
    print("   " + ", ".join(models[:8]) + (" ..." if len(models) > 8 else ""))

    print("\n2) Speed test (fastest candidates first, up to 30 s each) ...")
    results = []
    for m in models[:4]:
        t = time.monotonic()
        try:
            agent._gemini_call([{"role": "user", "parts": [{"text": "Reply with the word: ok"}]}],
                               with_tools=False, model=m, timeout=30, system=False)
            secs = round(time.monotonic() - t, 1)
            print(f"   {m:34} OK in {secs}s")
            results.append((secs, m))
        except requests.Timeout:
            print(f"   {m:34} too slow (no answer in 30 s)")
        except Exception as exc:
            print(f"   {m:34} failed: {explain(exc)[:90]}")
    if not results:
        raise SystemExit("\nNo model answered. Try again in a few minutes, or switch network (VPN off / mobile hotspot).")

    best = min(results)[1]
    current = os.getenv("AI_MODEL", "").strip()
    if current != best:
        text = env.read_text(encoding="utf-8")
        if re.search(r"^AI_MODEL=.*$", text, re.M):
            text = re.sub(r"^AI_MODEL=.*$", f"AI_MODEL={best}", text, flags=re.M)
        else:
            text += f"\nAI_MODEL={best}\n"
        env.write_text(text, encoding="utf-8")
        os.environ["AI_MODEL"] = best
        print(f"\n   Saved the fastest model to .env:  AI_MODEL={best}")
    else:
        print(f"\n   Already using the fastest model: {best}")

if prov == "gemini":
    print("\n2b) Which part is slow? (30 s limit each)")
    m = os.getenv("AI_MODEL") or agent.gemini_model()
    short = [{"role": "user", "parts": [{"text": "Is 'pay a 5 SAR customs fee at aramex-sa-track.xyz' a scam? One word."}]}]
    full = [{"role": "user", "parts": [{"text": agent._user_prompt(
        "Aramex: your parcel is on hold, pay the customs fee within 24h: http://aramex-sa-track.xyz/pay",
        "aramex.ksa@gmail.com", 4, "USD", "goods_services", ["urgency", "fee_to_receive"])}]}]
    tests = [("A short question", short, False, False),
             ("B + PayShield instructions", short, False, True),
             ("C + investigation tools", short, True, False),
             ("D full agent request", full, True, True)]
    for label, contents, tools_on, system_on in tests:
        t = time.monotonic()
        try:
            out = agent._gemini_call(contents, with_tools=tools_on, model=m, timeout=30, system=system_on)
            kind = "tool call" if any("functionCall" in p for p in out.get("parts", [])) else "text"
            print(f"   {label:30} OK in {time.monotonic() - t:.1f}s ({kind})")
        except requests.Timeout:
            print(f"   {label:30} too slow (no answer in 30 s)")
        except Exception as exc:
            print(f"   {label:30} failed: {explain(exc)[:100]}")

os.environ["PAYSHIELD_DEBUG"] = "1"
print("\n3) Full agent investigation (may take 10-40 s) ...")
r = agent.run_agent("Aramex: your parcel is on hold, pay the customs fee within 24h: http://aramex-sa-track.xyz/pay",
                    "aramex.ksa@gmail.com", 4, "USD", "goods_services", ["urgency", "fee_to_receive"])
if r:
    print(f"   OK in {r['seconds']}s. Risk {r['risk_score']}/100, type: {r.get('scam_type')}")
    for s in r["steps"]:
        print(f"   - tool: {s['tool']} {s['args']}")
    print("\nEverything works. Restart the app with:  python app.py")
else:
    print(f"   FAILED: {agent.last_error()}")
