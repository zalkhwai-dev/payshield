# PayShield AI 🛡️

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
   ├─► Decision: APPROVE / VERIFY / BLOCK  (strong rule evidence can never be overruled)
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

Includes a mocked AI-agent loop (no API key needed). Covers Arabic delivery scams, OTP theft, lookalike PayPal links, Friends & Family marketplace scams, job-fee scams, normal invoices in English and Arabic, disguised spelling and Arabizi, highlight positions, agent tool calls, the agent clearing a false alarm, falling back to rules when the AI is offline, and server-side enforcement (a blocked check cannot create a PayPal order).

## Project structure

```
payshield/
├── app.py              Flask server + decision enforcement
├── analyzer.py         Rule engine + final decision
├── agent.py            AI agent loop (Gemini / Claude) + screenshot reading
├── tools.py            Investigation tools the agent can call
├── normalize.py        Undo scammer disguises, keep positions for highlighting
├── paypal_client.py    PayPal Orders v2 (sandbox)
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
