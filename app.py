"""
PayShield AI - Flask backend.

Flow:
  1. POST /api/check          -> the AI agent analyzes the payment request and decides
  2. POST /api/verify         -> (only for VERIFY) user confirms the safety questions
  3. POST /api/orders         -> creates the PayPal sandbox order, ONLY if the agent allowed it
  4. POST /api/orders/<id>/capture -> completes the payment

The decision is enforced on the server, so a blocked payment cannot be
pushed through by editing the web page.
"""

import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request

# --- tiny .env loader (keeps dependencies minimal) ---------------------------
_env = Path(__file__).with_name(".env")
if _env.exists():
    for line in _env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

import paypal_client  # noqa: E402  (needs env loaded first)
from agent import extract_text_from_image, provider  # noqa: E402
from agent import last_error, run_agent  # noqa: E402
from analyzer import finalize, rule_phase  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

# In-memory store of checks. Fine for a hackathon demo; use a database in production.
CHECKS: dict[str, dict] = {}
SUPPORTED_CURRENCIES = {"USD", "EUR", "GBP", "AUD", "CAD"}


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/config")
def config():
    return jsonify({
        "paypal_client_id": os.getenv("PAYPAL_CLIENT_ID") if paypal_client.is_configured() else None,
        "demo_mode": not paypal_client.is_configured(),
        "ai_enabled": bool(provider()),
    })


@app.post("/api/check")
def check():
    body = request.get_json(silent=True) or {}
    message = str(body.get("message", "")).strip()
    extracted = None
    image = body.get("image")
    if image:
        mime = str(body.get("image_type", "image/png"))
        if mime not in {"image/png", "image/jpeg", "image/webp"}:
            return jsonify({"error": "Screenshot must be PNG, JPG or WEBP."}), 400
        if len(image) > 7_000_000:
            return jsonify({"error": "Screenshot is too large (max about 5 MB)."}), 400
        if not provider():
            return jsonify({"error": "Reading screenshots needs the AI model. Add your Gemini key to .env."}), 400
        extracted = extract_text_from_image(image, mime)
        if not extracted:
            return jsonify({"error": "Could not read text from the screenshot. Try pasting the text instead."}), 502
        message = (message + "\n" + extracted).strip()
    if not message:
        return jsonify({"error": "Please paste the payment request or seller message."}), 400
    try:
        amount = round(float(body.get("amount", 0)), 2)
    except (TypeError, ValueError):
        return jsonify({"error": "Amount must be a number."}), 400
    if amount <= 0:
        return jsonify({"error": "Amount must be greater than 0."}), 400
    currency = str(body.get("currency", "USD")).upper()
    if currency not in SUPPORTED_CURRENCIES:
        currency = "USD"
    payment_type = body.get("payment_type", "goods_services")
    seller = str(body.get("seller", "")).strip()

    # Phase 1 (instant): rule engine. Phase 2 (background): AI agent investigation.
    rules = rule_phase(message, seller, amount, payment_type)
    use_agent = bool(provider())
    result = finalize(rules, None, pending=use_agent)
    check_id = uuid.uuid4().hex[:12]
    base = {"check_id": check_id, "amount": amount, "currency": currency,
            "analyzed_text": message, "extracted_from_image": extracted}
    record = CHECKS[check_id] = {
        "decision": result["decision"],
        "verified": False,
        "pending": use_agent,
        "amount": amount,
        "currency": currency,
        "seller": seller,
        "risk_score": result["risk_score"],
        "result": {**base, **result},
        "created": datetime.now(timezone.utc).isoformat(),
    }
    if use_agent:
        def investigate():
            ai = run_agent(message, seller, amount, currency, payment_type, [r["id"] for r in rules["reasons"]])
            final = finalize(rules, ai, None if ai else last_error())
            record.update(decision=final["decision"], risk_score=final["risk_score"],
                          result={**base, **final}, pending=False)
        threading.Thread(target=investigate, daemon=True).start()
    return jsonify(record["result"])


@app.get("/api/check/<check_id>")
def check_status(check_id):
    """The page polls this until the AI agent has finished."""
    record = CHECKS.get(check_id)
    if not record:
        return jsonify({"error": "Unknown check."}), 404
    return jsonify(record["result"])


@app.post("/api/verify")
def verify():
    body = request.get_json(silent=True) or {}
    record = CHECKS.get(body.get("check_id", ""))
    if not record:
        return jsonify({"error": "Unknown check."}), 404
    if record["pending"]:
        return jsonify({"error": "The AI agent is still investigating. Please wait a moment."}), 409
    if record["decision"] != "VERIFY":
        return jsonify({"error": "This payment does not need verification."}), 400
    answers = body.get("answers", [])
    if answers and all(a is True for a in answers):
        record["verified"] = True
        return jsonify({"allowed": True})
    # Any "no" answer means the agent escalates to BLOCK.
    record["decision"] = "BLOCK"
    record["result"]["decision"] = "BLOCK"
    return jsonify({
        "allowed": False,
        "message_en": "Because you could not confirm these points, PayShield blocked the payment. Better safe than sorry.",
        "message_ar": "لأنك لم تستطع تأكيد هذه النقاط، أوقف PayShield الدفعة. الاحتياط أفضل.",
    })


def _payment_allowed(record: dict) -> bool:
    if record.get("pending"):
        return False   # never pay before the AI agent has finished
    return record["decision"] == "APPROVE" or (record["decision"] == "VERIFY" and record["verified"])


@app.post("/api/orders")
def create_order():
    body = request.get_json(silent=True) or {}
    check_id = body.get("check_id", "")
    record = CHECKS.get(check_id)
    if not record:
        return jsonify({"error": "Run a PayShield check first."}), 404
    if not _payment_allowed(record):
        return jsonify({"error": "PayShield blocked this payment.", "decision": record["decision"]}), 403

    description = f"PayShield-checked payment to {record['seller'] or 'seller'} (risk {record['risk_score']}/100)"
    if not paypal_client.is_configured():
        order_id = "DEMO-" + uuid.uuid4().hex[:10].upper()
        record["order_id"] = order_id
        return jsonify({"id": order_id, "demo": True})
    try:
        order = paypal_client.create_order(record["amount"], record["currency"], description, check_id)
    except Exception as exc:
        return jsonify({"error": f"PayPal error: {exc}"}), 502
    record["order_id"] = order["id"]
    return jsonify({"id": order["id"], "demo": False})


@app.post("/api/orders/<order_id>/capture")
def capture_order(order_id):
    record = next((r for r in CHECKS.values() if r.get("order_id") == order_id), None)
    if not record or not _payment_allowed(record):
        return jsonify({"error": "This order was not approved by PayShield."}), 403
    if order_id.startswith("DEMO-"):
        return jsonify({"status": "COMPLETED", "id": order_id, "demo": True})
    try:
        result = paypal_client.capture_order(order_id)
    except Exception as exc:
        return jsonify({"error": f"PayPal error: {exc}"}), 502
    return jsonify({"status": result.get("status"), "id": result.get("id"), "demo": False})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5050"))
    mode = "PayPal sandbox" if paypal_client.is_configured() else "DEMO mode (no PayPal keys yet)"
    print(f"\n  PayShield AI running at http://localhost:{port}  [{mode}]\n")
    app.run(host="127.0.0.1", port=port, debug=os.getenv("FLASK_DEBUG") == "1")
