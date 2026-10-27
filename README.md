# PayShield AI 🛡️

**Try it live: [payshield-2w44.onrender.com](https://payshield-2w44.onrender.com)** (free hosting, so the first visit can take about a minute to wake up). Log in at checkout with a PayPal sandbox test account.

**Check before you pay.** PayShield is an AI agent that sits in front of PayPal checkout. You paste a payment request, invoice or seller message, and the agent decides whether the payment should go through:

| Decision | What happens |
|---|---|
| ✅ **APPROVE** | No major warning signs. The PayPal checkout button appears. |
| ⚠️ **VERIFY** | Some warning signs. The user must answer safety questions first. Any "No" escalates to BLOCK. |
| ⛔ **BLOCK** | High risk. The payment is refused, and the server will not create a PayPal order. |

Built for the **PayPal AI Hackathon 2026**, with a focus on scams common in **Saudi Arabia and the Gulf**: fake delivery fees (Aramex, SMSA, Saudi Post), fake bank and Absher messages, job scams, and "pay as Friends & Family" marketplace scams. Every explanation is shown in **English and Arabic**.

## How it works

```
Message or screenshot
   │
   ├─► Screenshot? The AI model reads the text from the image
   ├─► De-obfuscation: P@yPal, paypa1, u.r.g.e.n.t, emojis/invisible chars, Cyrillic look-alikes, Arabic tatweel
   ├─► Rule engine: Arabic + English + Arabizi scam signals, link analysis, payment-type checks
   ├─► AI agent investigates with tools, then gives a verdict + explanation (EN/AR)
   │      check_link · expand_short_link · domain_age (RDAP) · safe_browsing · scan_text_rules
   ├─► Decision: APPROVE / VERIFY / BLOCK
   │      instant "Quick check" from the rules, then the "Final score" once the agent finishes
   │      (payment stays locked until then)
   └─► Flask server enforces the decision ─► PayPal Orders v2 (sandbox)
```

**What makes it more than a text classifier**
- **It acts on the payment.** A blocked check cannot create a PayPal order: the server returns 403, even if someone edits the page.
- **The agent investigates.** It decides which tools to call (domain age, real destination of short links, Safe Browsing) and the UI shows every step it took.
- **Built for the Gulf.** Fake Aramex/SMSA/SPL fees, Absher/bank account threats, job-fee scams, marketplace Friends & Family requests, in Arabic, English and Arabizi (`ad5ol 3la elrabt`, `3ajel`).
- **Hard to fool.** Disguised spelling is undone before analysis, and using a disguise is itself a red flag.
- **Shows its evidence.** Suspicious words are highlighted in the original message.
- **Screenshot input.** Upload a WhatsApp/SMS screenshot instead of copying text.
- **Fails safe.** If the AI is unavailable, the rule engine still protects the payment.
- **Measured on real messages.** Tested on 159 real scam and genuine messages collected in Saudi Arabia (see Benchmark).

### How the final decision is made
- The rules give an instant **Quick check**. The agent's investigation gives the **Final score**.
- If the agent finds a scam (score ≥ 70), its verdict decides, and the payment is blocked.
- If the agent checked and found the message safe, a single keyword rule can only ask the user to **verify**, not block. This stops false alarms on real one-time-code messages like "your code is 4821, do not share it".
- Without the agent, strong rule signals (asking for a code, lookalike website, raw IP link) block on their own.

## Benchmark: real Saudi messages

We collected **159 real messages** from phones in Saudi Arabia: **64 scams** (fake delivery fees, bank and government impersonation, account takeover, جمعية scams, fake tickets, marketplace scams) and **95 genuine messages** (bank alerts, OTP codes, delivery updates, marketing, personal chats). They cover SMS, WhatsApp, email and social media, and are mostly Arabic, with English and mixed-language messages too. Private details were covered before transcription. The dataset itself is not published, to protect the people in it.

"Flagged" means PayShield did not let the payment go straight through (VERIFY or BLOCK).

| Version | Scams caught | Scams blocked outright | False alarms | Real messages blocked | Accuracy |
|---|---|---|---|---|---|
| v1: rules + AI agent | 87.5% (56 / 64) | 14.1% (9 / 64) | 15.8% (15 / 95) | 5.3% (5 / 95) | 85.5% |
| **v2: AI verdict decides, OTP fix** | **92.2% (59 / 64)** | **82.8% (53 / 64)** | 15.8% (15 / 95) | 10.5% (10 / 95) | **87.4%** |

v2 catches more scams and blocks most of them outright instead of only asking the user to verify. The trade-off: real marketing messages that look like scams (prize ads, recharge offers with short links) are blocked more often. Remaining misses include fake event tickets and fake government notices with no link to investigate. These are the next things to improve.

**How we avoid fooling ourselves:** the 159 real messages are used only as a final exam. Changes are developed on a **separate check set** of 137 synthetic messages (generated, then reviewed by hand) and the real set is run once at the end. A benchmark that tunes on its own test messages would report inflated numbers.

Run it yourself on your own labelled messages:

```bash
python benchmark.py path/to/messages.csv            # rules only (offline)
python benchmark.py path/to/messages.csv --agent    # rules + AI agent
```

## How it fits with PayPal

PayPal already warns users about possible scams on some Friends & Family payments. PayShield works one step earlier and more broadly: it **reads the message behind the payment** (the SMS, WhatsApp chat or invoice that made someone want to pay), explains what is wrong in Arabic or English, investigates the links, and works for any payment type.

## Deploy your own copy on Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/zalkhwai-dev/payshield)

The repo includes a [Render Blueprint](render.yaml). It creates a free web service with the right build and start commands, a health check, auto-deploy on every push, and visitor limits that protect the free AI quota. Render asks for your Gemini key and PayPal sandbox keys during setup; they are never stored in the repo. The [live demo](https://payshield-2w44.onrender.com) runs on exactly this setup.

## Run it locally

Requires Python 3.10+.

```bash
cd payshield
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # then fill in your keys (see below)
python app.py
```

Open **http://localhost:5050** and try the three example buttons.

Without keys, the app runs in **demo mode**: the AI agent and decisions work fully, and checkout is simulated.

### Connect PayPal sandbox
1. Sign in at [developer.paypal.com](https://developer.paypal.com) → **Apps & Credentials** → **Sandbox** → create an app.
2. Copy the **Client ID** and **Secret** into `.env`.
3. Use the sandbox **personal** test account (Testing Tools → Sandbox Accounts) to log in at checkout. No real money moves.

### Connect the AI agent
Get a free Gemini key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey), then set `AI_PROVIDER=gemini` and `GEMINI_API_KEY=...` in `.env`. (Claude also works: `AI_PROVIDER=anthropic` + `ANTHROPIC_API_KEY`.) Screenshot reading and agent investigation need this key; everything else works without it.

### Google Safe Browsing (optional)
Enable the Safe Browsing API in Google Cloud and set `GOOGLE_SAFE_BROWSING_KEY`. The agent uses it automatically.

## Tests

```bash
python test_payshield.py
```

Includes a mocked AI-agent loop (no API key needed). Also checks that real OTP notices are not treated as credential theft while requests for a code are. Covers Arabic delivery scams, OTP theft, lookalike PayPal links, Friends & Family marketplace scams, job-fee scams, normal invoices in English and Arabic, disguised spelling and Arabizi, highlight positions, agent tool calls, the agent clearing a false alarm, falling back to rules when the AI is offline, and server-side enforcement (a blocked check cannot create a PayPal order).

## Project structure

```
payshield/
├── app.py              Flask server + decision enforcement
├── render.yaml         Render Blueprint (one-click deploy)
├── analyzer.py         Rule engine + final decision
├── agent.py            AI agent loop (Gemini / Claude) + screenshot reading
├── tools.py            Investigation tools the agent can call
├── normalize.py        Undo scammer disguises, keep positions for highlighting
├── paypal_client.py    PayPal Orders v2 (sandbox)
├── benchmark.py        Measure accuracy on a labelled CSV of messages
├── build_dataset.py    Turn scam / genuine screenshots into a labelled CSV (Gemini reads them)
├── make_validation.py  Generate a separate synthetic check set for development
├── check_ai.py         Diagnose the Gemini key, pick the fastest model
├── templates/index.html
├── static/app.js       UI, English/Arabic, PayPal buttons
├── static/style.css
└── test_payshield.py
```

## Roadmap
- Browser extension that checks payment pages before the PayPal button is clicked
- WhatsApp / SMS forwarding: forward a suspicious message and get a verdict back
- Learn from confirmed scam reports to update the rules automatically

## License
MIT. See [LICENSE](LICENSE).
