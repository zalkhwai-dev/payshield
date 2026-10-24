"""
Measure how well PayShield detects scams on the real-message dataset.

    python benchmark.py ~/Downloads/training_data/dataset.csv            # rules only (fast, offline)
    python benchmark.py ~/Downloads/training_data/dataset.csv --agent    # rules + AI agent (needs Gemini)

A message counts as "flagged" when PayShield does not let the payment go straight
through (decision VERIFY or BLOCK). Results are also shown for BLOCK alone.
Agent results are cached, so an interrupted run continues where it stopped.
Writes benchmark_results.csv (one row per message) next to the dataset.
"""

import csv
import re
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

_env = Path(__file__).with_name(".env")
if _env.exists():
    for line in _env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

USE_AGENT = "--agent" in sys.argv
if not USE_AGENT:
    os.environ.pop("AI_PROVIDER", None)      # force rules-only

import agent  # noqa: E402
from analyzer import finalize, rule_phase  # noqa: E402

PAUSE = float(os.getenv("BENCH_PAUSE", "4"))


def metrics(pairs):
    """pairs: list of (truth_is_scam, predicted_scam)"""
    tp = sum(t and p for t, p in pairs)
    tn = sum(not t and not p for t, p in pairs)
    fp = sum(not t and p for t, p in pairs)
    fn = sum(t and not p for t, p in pairs)
    n = len(pairs) or 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"n": len(pairs), "accuracy": (tp + tn) / n, "precision": prec, "recall": rec, "f1": f1,
            "false_alarm_rate": fp / (fp + tn) if fp + tn else 0.0, "tp": tp, "tn": tn, "fp": fp, "fn": fn}


def show(title, m):
    print(f"\n{title}  (n={m['n']})")
    print(f"  Accuracy        {m['accuracy']:6.1%}")
    print(f"  Scams caught    {m['recall']:6.1%}   (recall: {m['tp']} of {m['tp'] + m['fn']} scams)")
    print(f"  Precision       {m['precision']:6.1%}   (of flagged messages, how many were really scams)")
    print(f"  False alarms    {m['false_alarm_rate']:6.1%}   ({m['fp']} of {m['fp'] + m['tn']} real messages wrongly flagged)")
    print(f"  F1 score        {m['f1']:6.1%}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = Path(args[0] if args else "~/Downloads/training_data/dataset.csv").expanduser()
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig")))
    rows = [r for r in rows if not re.search(r"\bremove\b", r.get("notes", "").lower())]
    if USE_AGENT and not agent.provider():
        raise SystemExit("--agent needs AI_PROVIDER=gemini and GEMINI_API_KEY in .env")

    cache_file = path.with_name("benchmark_agent_cache.json")
    cache = json.loads(cache_file.read_text(encoding="utf-8")) if cache_file.exists() else {}
    mode = "rules + AI agent" if USE_AGENT else "rules only"
    print(f"PayShield benchmark - {mode} - {len(rows)} messages from {path.name}")
    if USE_AGENT:
        print(f"AI instructions version: {agent.PROMPT_ID}")

    results = []
    for i, r in enumerate(rows, 1):
        text = r["text"]
        rules = rule_phase(text, r.get("sender", ""), 0, "goods_services")
        ai, err = None, None
        if USE_AGENT:
            key = f'{r["id"]}@{agent.PROMPT_ID}'
            if key in cache:
                ai = cache[key]
            else:
                print(f"[{i}/{len(rows)}] id {key} ...", end=" ", flush=True)
                t = time.monotonic()
                for attempt in range(3):
                    ai = agent.run_agent(text, r.get("sender", ""), 0, "USD", "goods_services",
                                         [x["id"] for x in rules["reasons"]])
                    err = None if ai else agent.last_error()
                    if ai or not err or "429" not in str(err):
                        break
                    limit = re.search(r"Quota exceeded for metric: (\S+).*?limit: (\d+)", str(err), re.S)
                    if limit:
                        print(f"\n    Gemini limit hit: {limit.group(1).split('/')[-1]} (limit {limit.group(2)})")
                    if re.search(r"per ?day", str(err), re.I) or attempt == 2:
                        print("\n\nGemini's daily free limit is used up. Your progress is saved.")
                        print("Run the same command again tomorrow after the limit resets.")
                        sys.exit(1)
                    print("    Per-minute limit - waiting 65 seconds, then continuing ...", flush=True)
                    time.sleep(65)
                print(f"{'ok' if ai else 'AI failed: ' + str(err)[:60]} ({time.monotonic() - t:.1f}s)")
                if ai:
                    cache[key] = {k: ai[k] for k in ("risk_score", "scam_type") if k in ai}
                    cache_file.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
                time.sleep(PAUSE)
        res = finalize(rules, ai, err)
        results.append({
            "id": r["id"], "label": r["label"], "language": r.get("language", ""), "channel": r.get("channel", ""),
            "decision": res["decision"], "risk_score": res["risk_score"], "engine": res["engine"],
            "scam_type": res["scam_type"], "signals": ", ".join(x["id"] for x in res["reasons"]),
            "correct": (r["label"] == "scam") == (res["decision"] != "APPROVE"),
            "text": text[:300],
        })

    truth = [x["label"] == "scam" for x in results]
    flagged = [x["decision"] != "APPROVE" for x in results]
    blocked = [x["decision"] == "BLOCK" for x in results]
    agent_used = sum(x["engine"] != "rules" for x in results)

    print("\n" + "=" * 60)
    if USE_AGENT:
        print(f"AI agent answered for {agent_used} of {len(results)} messages (others fell back to rules).")
    show(f"OVERALL ({mode}) - flagged = VERIFY or BLOCK", metrics(list(zip(truth, flagged))))
    show("BLOCK only", metrics(list(zip(truth, blocked))))
    groups = defaultdict(list)
    for x, t, p in zip(results, truth, flagged):
        groups[x["language"]].append((t, p))
    print("\nBy language (flagged):")
    for lang, pairs in sorted(groups.items()):
        m = metrics(pairs)
        print(f"  {lang:6} n={m['n']:3}  accuracy {m['accuracy']:6.1%}  scams caught {m['recall']:6.1%}  "
              f"false alarms {m['false_alarm_rate']:6.1%}")

    suffix = "agent" if USE_AGENT else "rules"
    name = f"benchmark_results_{suffix}.csv" if path.stem == "dataset" else f"benchmark_results_{path.stem}_{suffix}.csv"
    out = path.with_name(name)
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0]))
        w.writeheader()
        w.writerows(results)
    misses = [x for x in results if not x["correct"]]
    print(f"\n{len(misses)} mistakes. Details saved to {out.name}")
    for x in misses[:12]:
        kind = "MISSED SCAM " if x["label"] == "scam" else "FALSE ALARM "
        print(f"  {kind} id {x['id']:>3} {x['decision']:7} {x['risk_score']:3}  {x['text'][:70]!r}")


if __name__ == "__main__":
    main()
