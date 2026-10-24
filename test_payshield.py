"""Run with:  python -m pytest -q   (or simply: python test_payshield.py)"""

import os

os.environ.pop("AI_PROVIDER", None)          # tests use the rule engine only
os.environ.pop("PAYPAL_CLIENT_ID", None)     # and demo-mode payments

from analyzer import analyze  # noqa: E402
from app import app  # noqa: E402

CASES = [
    ("Arabic fake delivery fee",
     "أرامكس: شحنتك معلقة. ادفع الرسوم الجمركية خلال 24 ساعة: https://aramex-sa-track.xyz/pay",
     "aramex.ksa@gmail.com", 4, "friends_family", "BLOCK"),
    ("OTP request",
     "To release your refund please send me the verification code you just received",
     "paypal support", 10, "goods_services", "BLOCK"),
    ("Lookalike PayPal link",
     "Your account is limited. Log in at http://paypa1-secure.com to restore access.",
     "", 1, "goods_services", "BLOCK"),
    ("Friends & Family marketplace seller",
     "PS5 sealed only $150, send as Friends & Family to avoid fees, many buyers waiting",
     "gamer.deals@outlook.com", 150, "friends_family", "BLOCK"),
    ("Job with registration fee",
     "Congratulations! You are hired for a work from home job. Pay the $30 registration fee to start.",
     "hr.jobs@gmail.com", 30, "goods_services", "VERIFY"),
    ("Normal invoice",
     "Invoice #1042 from Riyadh Calligraphy Studio for the invitation design. Thank you!",
     "billing@riyadhcalligraphy.com", 45, "goods_services", "APPROVE"),
    ("Normal Arabic invoice",
     "فاتورة رقم 77 لتصميم شعار المتجر حسب الاتفاق. شكراً لتعاملك معنا",
     "studio@designhouse.com", 60, "goods_services", "APPROVE"),
]


def test_decisions():
    for name, msg, seller, amount, ptype, expected in CASES:
        r = analyze(msg, seller, amount, "USD", ptype)
        assert r["decision"] == expected, f"{name}: got {r['decision']} ({r['risk_score']}), expected {expected}"


def test_blocked_payment_cannot_be_forced():
    c = app.test_client()
    r = c.post("/api/check", json={"message": CASES[0][1], "seller": CASES[0][2], "amount": 4,
                                   "payment_type": "friends_family"}).get_json()
    assert r["decision"] == "BLOCK"
    resp = c.post("/api/orders", json={"check_id": r["check_id"]})
    assert resp.status_code == 403


def test_safe_payment_full_flow():
    c = app.test_client()
    r = c.post("/api/check", json={"message": CASES[5][1], "seller": CASES[5][2], "amount": 45}).get_json()
    assert r["decision"] == "APPROVE"
    order = c.post("/api/orders", json={"check_id": r["check_id"]}).get_json()
    cap = c.post(f"/api/orders/{order['id']}/capture").get_json()
    assert cap["status"] == "COMPLETED"


def test_verify_flow():
    c = app.test_client()
    r = c.post("/api/check", json={"message": CASES[4][1], "seller": CASES[4][2], "amount": 30}).get_json()
    assert r["decision"] == "VERIFY"
    assert c.post("/api/orders", json={"check_id": r["check_id"]}).status_code == 403   # not verified yet
    v = c.post("/api/verify", json={"check_id": r["check_id"], "answers": [True, False, True]}).get_json()
    assert v["allowed"] is False
    assert c.post("/api/orders", json={"check_id": r["check_id"]}).status_code == 403   # escalated to BLOCK


if __name__ == "__main__":
    for name, msg, seller, amount, ptype, expected in CASES:
        r = analyze(msg, seller, amount, "USD", ptype)
        mark = "OK  " if r["decision"] == expected else "FAIL"
        print(f"{mark} {name:38} -> {r['decision']:7} score={r['risk_score']:3}  {[x['id'] for x in r['reasons']]}")
    test_decisions(); test_blocked_payment_cannot_be_forced(); test_safe_payment_full_flow(); test_verify_flow()
    print("\nAll tests passed.")


# ---------------------------------------------------------------- v2 tests ----
def test_disguised_scams():
    tricky = [
        "Your P@yPal acc0unt is l.i.m.i.t.e.d. Log in to restore: http://paypa1-secure.com",
        "salam, shi7natak m3alaga, ad5ol 3la elrabt w ed2a3 el rsoom 3ajel bit.ly/xx12",
        "عـــاجل: تم تعليق حسابك في الراجحي، حدّث بياناتك وأرسل رمز التحقق",
        "Send the ver​ification c​ode you got to unlock your refund",
    ]
    for msg in tricky:
        r = analyze(msg, "", 5, "USD", "goods_services")
        assert r["decision"] == "BLOCK", f"{msg!r}: {r['decision']} {r['risk_score']}"
        assert r["highlights"], f"no highlights for {msg!r}"


def test_highlights_point_to_original_text():
    msg = "URGENT!! Pay the customs fee: http://aramex-sa-track.xyz"
    r = analyze(msg, "", 5)
    marked = [msg[h["start"]:h["end"]] for h in r["highlights"]]
    assert "URGENT" in marked[0] and any("aramex-sa-track.xyz" in m for m in marked), marked


def _fake_response(payload):
    class R:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return payload
    return R()


def test_gemini_agent_loop(monkeypatch=None):
    import agent, tools
    calls = {"n": 0}

    def fake_post(url, **kw):
        calls["n"] += 1
        if calls["n"] == 1:   # model decides to investigate the link
            return _fake_response({"candidates": [{"content": {"role": "model", "parts": [
                {"functionCall": {"name": "domain_age", "args": {"domain": "aramex-sa-track.xyz"}}}]}}]})
        # second round: model has seen the tool result and answers
        sent = kw["json"]["contents"][-1]["parts"][0]["functionResponse"]
        assert sent["name"] == "domain_age" and sent["response"]["age_days"] == 3
        return _fake_response({"candidates": [{"content": {"role": "model", "parts": [{"text": (
            '{"risk_score": 95, "scam_type": "fake delivery fee", "explanation_en": "Domain is 3 days old.",'
            ' "explanation_ar": "عمر النطاق 3 أيام.", "verify_questions_en": [], "verify_questions_ar": []}')}]}}]})

    old_post, old_tool = agent.requests.post, tools.TOOLS["domain_age"]
    os.environ.update(AI_PROVIDER="gemini", GEMINI_API_KEY="test")
    agent.requests.post = fake_post
    tools.TOOLS["domain_age"] = (lambda domain: {"domain": domain, "age_days": 3}, old_tool[1], old_tool[2])
    try:
        r = analyze("Aramex: pay the fee at aramex-sa-track.xyz", "", 4)
        assert r["engine"] == "rules + AI agent"
        assert r["agent_steps"][0]["tool"] == "domain_age"
        assert r["decision"] == "BLOCK" and r["scam_type"] == "fake delivery fee"
    finally:
        agent.requests.post, tools.TOOLS["domain_age"] = old_post, old_tool
        os.environ.pop("AI_PROVIDER"); os.environ.pop("GEMINI_API_KEY")


def test_agent_can_clear_false_alarm():
    import agent
    old = agent.run_agent
    import analyzer
    analyzer.run_agent = lambda *a: {"risk_score": 5, "scam_type": "none", "steps": []}
    try:
        r = analyze("Urgent: invoice #88 for the logo design we discussed, due today. Thanks!",
                    "studio@designhouse.com", 40)
        assert r["decision"] == "APPROVE", r
    finally:
        analyzer.run_agent = old


def test_agent_failure_falls_back_to_rules():
    import agent
    os.environ.update(AI_PROVIDER="gemini", GEMINI_API_KEY="test")
    old = agent.requests.post
    def boom(*a, **k): raise agent.requests.ConnectionError("offline")
    agent.requests.post = boom
    try:
        r = analyze(CASES[0][1], CASES[0][2], 4, "USD", "friends_family")
        assert r["engine"] == "rules" and r["decision"] == "BLOCK"
    finally:
        agent.requests.post = old
        os.environ.pop("AI_PROVIDER"); os.environ.pop("GEMINI_API_KEY")


def test_background_agent_flow():
    """Rules answer instantly; payment stays locked until the agent finishes."""
    import time
    import app as appmod
    old_run, old_prov = appmod.run_agent, appmod.provider
    def slow_agent(*a):
        time.sleep(0.4)
        return {"risk_score": 2, "scam_type": "none", "steps": [{"tool": "domain_age", "args": {}, "result": "{}"}]}
    appmod.run_agent, appmod.provider = slow_agent, (lambda: "gemini")
    try:
        c = app.test_client()
        r = c.post("/api/check", json={"message": CASES[5][1], "seller": CASES[5][2], "amount": 45}).get_json()
        assert r["agent_pending"] is True and r["engine"] == "rules"
        assert c.post("/api/orders", json={"check_id": r["check_id"]}).status_code == 403   # locked while pending
        for _ in range(30):
            time.sleep(0.1)
            r2 = c.get(f"/api/check/{r['check_id']}").get_json()
            if not r2["agent_pending"]:
                break
        assert r2["agent_pending"] is False and r2["engine"] == "rules + AI agent" and r2["decision"] == "APPROVE"
        assert c.post("/api/orders", json={"check_id": r["check_id"]}).status_code == 200
    finally:
        appmod.run_agent, appmod.provider = old_run, old_prov


if __name__ == "__main__":
    test_background_agent_flow()
    test_disguised_scams(); test_highlights_point_to_original_text(); test_gemini_agent_loop()
    test_agent_can_clear_false_alarm(); test_agent_failure_falls_back_to_rules()
    print("All v2 tests passed.")


def test_otp_notices():
    from analyzer import rule_phase, finalize
    notice = rule_phase("Your STC Pay verification code is 7391. Do not share this code with anyone.", "", 0, "goods_services")
    assert "credentials" not in [r["id"] for r in notice["reasons"]]
    ask = rule_phase("I sent the code to your number by mistake, send me the 6 digit code please", "", 0, "goods_services")
    assert "credentials" in [r["id"] for r in ask["reasons"]]
    # agent found a scam -> its verdict decides, even if rules saw little
    assert finalize(rule_phase("hello", "", 0, "goods_services"), {"risk_score": 90, "scam_type": "x"})["decision"] == "BLOCK"
    # agent checked and found it safe -> a hard-stop rule asks to verify instead of blocking
    assert finalize(ask, {"risk_score": 5, "scam_type": "none"})["decision"] == "VERIFY"
    assert finalize(ask, None)["decision"] == "BLOCK"
    print("OTP / combination tests passed.")


if __name__ == "__main__":
    test_otp_notices()
