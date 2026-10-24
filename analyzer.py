"""
PayShield AI - scam analyzer and payment-decision agent.

Two layers work together:
  1. Rule engine  - fast, explainable checks tuned for Gulf / Saudi scams (Arabic + English).
  2. LLM layer    - optional. If an API key is set, an AI model reads the request,
                    judges it, and writes a plain-language explanation.

The agent then makes ONE decision:
  APPROVE -> safe enough, PayPal checkout is shown
  VERIFY  -> suspicious, user must answer safety questions before paying
  BLOCK   -> high risk, payment is refused
"""

import re
from urllib.parse import urlparse

import agent as _agent
from agent import run_agent
from normalize import detect_tricks, fold_arabic, normalize, to_original_span

# ---------------------------------------------------------------------------
# Rule definitions. Each rule: id, weight (0-100), regex patterns, EN + AR reason
# ---------------------------------------------------------------------------
RULES = [
    {
        "id": "urgency",
        "weight": 15,
        "patterns": [
            r"\burgent(ly)?\b", r"\bimmediately\b", r"\bwithin \d+ (hours?|minutes?)\b",
            r"\blast (chance|warning)\b", r"\bact now\b", r"\bbe quick\b", r"\bhurry\b",
            r"\bmany (other )?buyers\b", r"\bbefore (it'?s|someone else)\b", r"\bexpires? (today|soon)\b",
            r"عاجل", r"فورا|فوراً", r"خلال \d+ ساع", r"آخر فرصة|اخر فرصة", r"سيتم (إيقاف|ايقاف|تعليق)",
        ],
        "en": "Creates pressure to act fast. Scammers rush you so you don't stop and think.",
        "ar": "يضغط عليك للتصرف بسرعة. المحتالون يستعجلونك حتى لا تفكر.",
    },
    {
        "id": "friends_family",
        "weight": 30,
        "patterns": [
            r"friends?\s*(&|and)\s*family", r"\bF&F\b", r"send (it )?as (a )?gift",
            r"personal payment", r"no (fees|protection) needed",
            r"أصدقاء وعائلة|اصدقاء وعائلة|اصدقاء و عائلة", r"كهدية",
        ],
        "en": "Asks you to pay as 'Friends & Family'. That removes PayPal Buyer Protection, so you can't get your money back.",
        "ar": "يطلب الدفع كـ 'أصدقاء وعائلة'. هذا يلغي حماية المشتري في PayPal ولن تستطيع استرجاع أموالك.",
    },
    {
        "id": "off_platform",
        "weight": 25,
        "patterns": [
            r"\bwestern union\b", r"\bgift ?cards?\b", r"\bitunes card\b", r"\bbitcoin\b|\bcrypto\b|\busdt\b",
            r"\bbank transfer\b", r"\bwire (the )?money\b", r"\bstc ?pay\b.*(only|instead)",
            r"بطاقة (هدايا|ايتونز|آيتونز)", r"تحويل بنكي", r"بيتكوين|عملات رقمية",
        ],
        "en": "Pushes you to pay outside protected methods (gift cards, crypto, wire transfer). These payments can't be reversed.",
        "ar": "يدفعك للدفع بطرق غير محمية (بطاقات هدايا، عملات رقمية، تحويل بنكي). هذه المدفوعات لا يمكن استرجاعها.",
    },
    {
        "id": "credentials",
        "weight": 35,
        "patterns": [
            r"\b(otp|one[- ]time (password|code)|verification code|pin)\b", r"\bcvv\b",
            r"\b(password|card number)\b", r"\babsher\b.*(code|رمز)",
            r"رمز التحقق|الرمز السري|كلمة المرور|رقم البطاقة|رمز أبشر|رمز ابشر",
        ],
        "en": "Asks for a code, password or card details. No real seller, bank or PayPal will ever ask for these.",
        "ar": "يطلب رمزاً أو كلمة مرور أو بيانات بطاقة. لا يوجد بائع أو بنك أو PayPal حقيقي يطلب هذه البيانات أبداً.",
    },
    {
        "id": "fee_to_receive",
        "weight": 25,
        "patterns": [
            r"(customs|delivery|shipping|release|processing|clearance) fee",
            r"pay .{0,25}to (receive|claim|release)", r"\byou (have )?won\b", r"\bprize\b|\blottery\b",
            r"رسوم (جمركية|التوصيل|الشحن|الإفراج|التخليص)", r"ربحت|فزت|جائزة|سحب", r"شحنتك (معلقة|متوقفة)",
        ],
        "en": "Asks for a small fee to release a parcel or prize. This is one of the most common scams in the Gulf.",
        "ar": "يطلب رسوماً صغيرة للإفراج عن شحنة أو جائزة. هذه من أكثر عمليات الاحتيال انتشاراً في الخليج.",
    },
    {
        "id": "impersonation",
        "weight": 15,
        "patterns": [
            r"\b(aramex|smsa|dhl|saudi post|spl|fedex)\b", r"\b(al ?rajhi|snb|ncb|riyad bank|stc)\b",
            r"\b(paypal (support|security|team))\b", r"\bministry\b",
            r"أرامكس|ارامكس|سمسا|البريد السعودي|سبل|الراجحي|الأهلي|بنك الرياض|وزارة|أبشر|ابشر",
        ],
        "en": "Claims to be a delivery company, bank or government body. Scammers often pretend to be trusted brands.",
        "ar": "يدّعي أنه شركة توصيل أو بنك أو جهة حكومية. المحتالون ينتحلون أسماء جهات موثوقة كثيراً.",
    },
    {
        "id": "too_good",
        "weight": 15,
        "patterns": [
            r"\b(90|80|70)% off\b", r"\bbrand new\b.*\b(cheap|half price)\b", r"\bfree iphone\b",
            r"\bguaranteed (profit|returns?)\b", r"\bdouble your money\b",
            r"\b(sealed|brand new)\b.{0,40}\bonly \$?\d+", r"\bmoving (abroad|overseas|away)\b",
            r"خصم (90|80|70)", r"ربح مضمون", r"ضاعف أموالك|ضاعف فلوسك",
        ],
        "en": "The offer looks too good to be true (huge discount or guaranteed profit).",
        "ar": "العرض أفضل من أن يكون حقيقياً (خصم ضخم أو ربح مضمون).",
    },
    {
        "id": "click_link",
        "weight": 10,
        "patterns": [r"\bclick (the |this |on the )?(link|button) (below|now|to)\b", r"\btap (the|this) link\b",
                     r"اضغط على الرابط|ادخل على الرابط|افتح الرابط|اضغط الرابط"],
        "en": "Pushes you to click a link. Real companies ask you to open their official app or website yourself.",
        "ar": "يدفعك للضغط على رابط. الشركات الحقيقية تطلب منك فتح تطبيقها أو موقعها الرسمي بنفسك.",
    },
    {
        "id": "account_threat",
        "weight": 25,
        "patterns": [
            r"account (is |has been |will be )?(limited|suspended|locked|blocked|closed)",
            r"(log ?in|sign ?in|verify).{0,40}(restore|unlock|reactivate|avoid)",
            r"(تم|سيتم) (تعليق|إيقاف|ايقاف|قفل) حسابك", r"حدّث بياناتك|حدث بياناتك",
        ],
        "en": "Threatens that your account is limited or locked to make you log in through their link.",
        "ar": "يهددك بأن حسابك مقيد أو مقفل ليجعلك تسجل الدخول عبر رابطهم.",
    },
    {
        "id": "job_scam",
        "weight": 35,
        "patterns": [
            r"\byou('re| are| have been) hired\b", r"تم قبولك في الوظيفة",
            r"(registration|training|visa|application) fee", r"work from home.*\$\d+",
            r"رسوم (التسجيل|التدريب|التأشيرة)", r"وظيفة.*(دفع|رسوم)",
        ],
        "en": "Job offer that asks you to pay first. Real employers never charge you to hire you.",
        "ar": "عرض وظيفة يطلب منك الدفع أولاً. جهات التوظيف الحقيقية لا تطلب منك مالاً.",
    },
]

# Arabizi (Arabic written with Latin letters + numbers, common in the Gulf).
# Matched on the RAW text and counted under the same category as the Arabic/English rule.
ARABIZI_RULES = [
    {"same_as": "urgency", "patterns": [r"\b3aa?jel\b|\b3ajil\b", r"\bbsor3a\b|\bbsr3a\b", r"\b5ilal \d+ sa3a"]},
    {"same_as": "click_link", "patterns": [r"\b(ad5ol|ed5ol|odkhol|edkhal|adkhol)\b", r"\b(el|al) ?rabe?t\b", r"\bidghat\b|\bedghat\b"]},
    {"same_as": "fee_to_receive", "patterns": [r"\brsoo?m\b", r"\b(fozt|fizt|rb7t|ruba7t)\b", r"\bjayza\b|\bja2eza\b"]},
    {"same_as": "credentials", "patterns": [r"\b(ramz|rmz) (el|al)? ?ta7a?qq?o?q\b", r"\bel ?ramz\b", r"\botp\b"]},
    {"same_as": "account_threat", "patterns": [r"\b7sab(ak|ek)\b.{0,20}\b(mwgaf|maw2oof|mo3alla?g|ta3leeg)"]},
]

# Compile once. Arabic letters in patterns are folded the same way as the text.
for _rule in RULES:
    _rule["compiled"] = [re.compile(fold_arabic(p), re.I) for p in _rule["patterns"]]
for _rule in ARABIZI_RULES:
    _rule["compiled"] = [re.compile(p, re.I) for p in _rule["patterns"]]
RULES_BY_ID = {r["id"]: r for r in RULES}

# A real OTP notice WARNS you not to share the code. A scam ASKS you to send it.
OTP_WARNING = re.compile(fold_arabic(
    r"(do not|don'?t|never|not to)\s+(share|give|disclose|tell)|"
    r"لا\s*(تشارك|تقم بمشاركة|تعط|تفصح|تقم بالإفصاح|تخبر)|عدم\s*(مشاركة|الإفصاح|اعطاء|إعطاء)|"
    r"سرية\s*(الرمز|الكود|حسابك|بياناتك)|حافظ على سرية|ما\s*تشارك|\bma? ?t?shari?k|\bla tushari"), re.I)
CODE_REQUEST = re.compile(fold_arabic(
    r"\b(send|give|tell|forward|share|read)\b.{0,25}\b(code|otp|pin|password)\b|"
    r"\b(code|otp)\b.{0,15}\b(to me|back)\b|"
    r"(ارسل|أرسل|ترسل|ترسله|رسل|عطني|اعطني|أعطني|تعطيني|ابي|أبي|ابغى|أبغى|قول لي|قولي)\s*(لي)?.{0,25}(الرمز|الكود|رمز|كود|الرقم اللي|otp|code)|"
    r"(ارسله|أرسله|رسله|ترسله|ارسلها|أرسلها|ترسلها|عطنيه|اعطنيه|أعطنيه|عطني اياه|قوله)\s*(لي|لنا)?\s|"
    r"\b(tgzli|ersel|ersal|ersli|3tni|a3tini|3teni)\b"), re.I)


CODE_GIVEN = re.compile(fold_arabic(
    r"\b(code|otp|pin)\b[^0-9\n]{0,25}\d{4,8}|(رمز|الرمز|كود|الكود)[^0-9\n]{0,30}\d{4,8}|"
    r"\d{4,8}[^0-9\n]{0,15}(is your|هو رمز|رمز)"), re.I)


def is_otp_notice(norm_text: str) -> bool:
    """True for a normal 'your code is 1234, do not share it' message: it GIVES you a code or
    warns you to keep it secret, and nobody asks you to send the code anywhere."""
    if not (OTP_WARNING.search(norm_text) or CODE_GIVEN.search(norm_text)):
        return False
    return not asks_for_code(norm_text)


def asks_for_code(norm_text: str):
    """Match object if someone asks the reader to send / give them a code (ignores 'do not share' warnings)."""
    without_warnings = re.sub(OTP_WARNING.pattern + r".{0,30}", lambda m: " " * len(m.group(0)), norm_text, flags=re.I)
    return CODE_REQUEST.search(without_warnings)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "tiny.cc"}
RISKY_TLDS = {".xyz", ".top", ".click", ".live", ".icu", ".shop", ".buzz", ".info", ".online", ".site", ".vip", ".cfd", ".sbs"}
TRUSTED_BRANDS = ["paypal", "aramex", "smsa", "dhl", "absher", "alrajhi", "stc", "amazon", "noon", "splonline", "apple"]
OFFICIAL_DOMAINS = {
    "paypal.com", "aramex.com", "smsaexpress.com", "dhl.com", "absher.sa", "alrajhibank.com.sa",
    "stc.com.sa", "amazon.sa", "amazon.com", "noon.com", "splonline.com.sa", "apple.com",
    # other official domains of the same brands
    "stcpay.com.sa", "mystc.com.sa", "alrajhitakaful.com", "alrajhi-capital.sa", "alrajhicapital.com",
    "smsa.com.sa", "dhl.com.sa", "aramex.com.sa", "amazon.ae", "amazon.eg", "noon.sa", "icloud.com",
    "paypal.me", "paypalobjects.com", "spl.com.sa",
}

URL_RE = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|xyz|top|click|live|icu|shop|buzz|online|site|vip|cfd|sbs|ly|gy|gd|co|io|me|sa|ae|link|app)\b(?:/[^\s<>\"']*)?)", re.I)


def _registered_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 3 and parts[-2] in {"com", "gov", "edu", "org", "net"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def check_links(text: str):
    """Return (score, findings, links) for every link in the text."""
    findings, links, score = [], [], 0
    for raw in URL_RE.findall(text or ""):
        url = raw if raw.lower().startswith("http") else "http://" + raw
        host = (urlparse(url).hostname or "").lower()
        if not host or "." not in host or host.endswith((".png", ".jpg")):
            continue
        # skip the domain part of e-mail addresses (handled separately)
        if "@" + raw in text:
            continue
        links.append(host)
        reg = _registered_domain(host)
        if host in SHORTENERS or reg in SHORTENERS:
            score += 20
            findings.append(("short_link", host,
                             "Uses a shortened link that hides the real website.",
                             "يستخدم رابطاً مختصراً يخفي الموقع الحقيقي."))
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            score += 30
            findings.append(("ip_link", host,
                             "Link goes to a raw IP address instead of a real website name.",
                             "الرابط يذهب إلى عنوان IP بدلاً من اسم موقع حقيقي."))
        if any(host.endswith(t) for t in RISKY_TLDS):
            score += 15
            findings.append(("risky_tld", host,
                             f"Website ending ({host.rsplit('.', 1)[-1]}) is often used by scam sites.",
                             f"نهاية الموقع ({host.rsplit('.', 1)[-1]}) تُستخدم كثيراً في مواقع الاحتيال."))
        if reg not in OFFICIAL_DOMAINS:
            for brand in TRUSTED_BRANDS:
                squashed = re.sub(r"[^a-z0-9]", "", host).replace("1", "l").replace("0", "o").replace("rn", "m")
                if brand in squashed or _looks_like(brand, reg.split(".")[0]):
                    score += 35
                    findings.append(("lookalike", host,
                                     f"Fake website pretending to be {brand.title()}. The real one is not '{host}'.",
                                     f"موقع مزيف ينتحل اسم {brand.title()}. الموقع الحقيقي ليس '{host}'."))
                    break
    return min(score, 60), findings, links


def _looks_like(a: str, b: str) -> bool:
    """Simple typo-squatting check (edit distance 1-2, e.g. paypa1, paypall)."""
    if a == b or abs(len(a) - len(b)) > 2 or len(a) < 4:
        return False
    swapped = b.replace("1", "l").replace("0", "o").replace("rn", "m")
    if swapped == a:
        return True
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1] <= 2


def rule_engine(message: str, payment_type: str, amount: float, seller: str):
    """Returns (score, reasons, links, highlights). Highlights point into the ORIGINAL message."""
    reasons, score, highlights = [], 0, []
    norm_msg, imap = normalize(message)
    norm_seller, _ = normalize(seller or "")

    otp_notice = is_otp_notice(norm_msg)
    for rule in RULES:
        if rule["id"] == "credentials" and otp_notice:
            continue
        hit = False
        for rx in rule["compiled"]:
            for m in rx.finditer(norm_msg):
                if m.end() > m.start():
                    s0, e0 = to_original_span(m.start(), m.end(), imap)
                    highlights.append({"start": s0, "end": e0, "id": rule["id"]})
                    hit = True
            if rx.search(norm_seller):
                hit = True
        if hit:
            score += rule["weight"]
            reasons.append({"id": rule["id"], "en": rule["en"], "ar": rule["ar"]})

    request = asks_for_code(norm_msg)
    if request and not any(r["id"] == "credentials" for r in reasons):
        base = RULES_BY_ID["credentials"]
        score += base["weight"]
        reasons.append({"id": "credentials", "en": base["en"], "ar": base["ar"]})
        s0, e0 = to_original_span(request.start(), request.end(), imap)
        highlights.append({"start": s0, "end": e0, "id": "credentials"})

    for rule in ARABIZI_RULES:
        spans = [m.span() for rx in rule["compiled"] for m in rx.finditer(message)]
        if not spans or (rule["same_as"] == "credentials" and otp_notice):
            continue
        highlights += [{"start": a, "end": b, "id": rule["same_as"]} for a, b in spans]
        if not any(r["id"] == rule["same_as"] for r in reasons):
            base = RULES_BY_ID[rule["same_as"]]
            score += base["weight"]
            reasons.append({"id": base["id"], "en": base["en"], "ar": base["ar"], "detail": "Arabizi"})

    tricks = detect_tricks(message)
    if tricks:
        score += 20
        reasons.append({"id": "disguised_text", "detail": ", ".join(tricks),
                        "en": "Uses disguised spelling to fool filters. Honest sellers don't hide their words.",
                        "ar": "يستخدم كتابة مموهة لخداع أنظمة الحماية. البائع الصادق لا يخفي كلماته."})

    text = f"{message}\n{seller}"
    link_score, link_findings, links = check_links(text)
    score += link_score
    low_msg = message.lower()
    for fid, host, en, ar in link_findings:
        reasons.append({"id": fid, "en": en, "ar": ar, "detail": host})
        pos = low_msg.find(host)
        if pos >= 0:
            highlights.append({"start": pos, "end": pos + len(host), "id": fid})

    if payment_type == "friends_family":
        score += 15
    if payment_type == "friends_family" and not any(r["id"] == "friends_family" for r in reasons):
        score += 5
        reasons.append({"id": "ff_selected",
                        "en": "You chose 'Friends & Family' to pay someone you may not know. You would lose Buyer Protection.",
                        "ar": "اخترت 'أصدقاء وعائلة' للدفع لشخص قد لا تعرفه. ستفقد حماية المشتري."})

    if seller and re.search(r"@(gmail|hotmail|outlook|yahoo)\.", seller, re.I) and \
            any(r["id"] == "impersonation" for r in reasons):
        score += 15
        reasons.append({"id": "free_email",
                        "en": "Claims to be a company but uses a free personal email address.",
                        "ar": "يدّعي أنه شركة لكنه يستخدم بريداً إلكترونياً شخصياً مجانياً."})

    if amount and amount >= 1000 and score >= 20:
        score += 10
        reasons.append({"id": "high_amount",
                        "en": "Large amount combined with warning signs.",
                        "ar": "مبلغ كبير مع وجود علامات تحذيرية."})

    return min(score, 100), reasons, links, _merge(highlights)


def _merge(spans):
    """Merge overlapping highlight spans so the UI can draw them cleanly."""
    spans = sorted(spans, key=lambda h: (h["start"], -h["end"]))
    merged = []
    for h in spans:
        if merged and h["start"] <= merged[-1]["end"]:
            merged[-1]["end"] = max(merged[-1]["end"], h["end"])
            if h["id"] not in merged[-1]["ids"]:
                merged[-1]["ids"].append(h["id"])
        else:
            merged.append({"start": h["start"], "end": h["end"], "ids": [h["id"]]})
    return merged


# ---------------------------------------------------------------------------
# The agent: combine signals and decide
# ---------------------------------------------------------------------------
DEFAULT_QUESTIONS = {
    "en": [
        "Do you personally know this seller, or have you checked their reviews?",
        "Did YOU start this purchase (it was not an unexpected message)?",
        "Is the website address the official one (not a lookalike)?",
    ],
    "ar": [
        "هل تعرف هذا البائع شخصياً أو تحققت من تقييماته؟",
        "هل أنت من بدأ عملية الشراء (وليست رسالة مفاجئة)؟",
        "هل عنوان الموقع هو الرسمي (وليس موقعاً مشابهاً)؟",
    ],
}

SCAM_TYPES = [  # most specific first
    ("credentials", "credential theft"), ("lookalike", "fake website (phishing)"),
    ("account_threat", "account phishing"), ("fee_to_receive", "fake fee / prize scam"),
    ("job_scam", "fake job offer"), ("friends_family", "unprotected payment request"),
    ("off_platform", "irreversible payment request"), ("too_good", "too-good-to-be-true offer"),
    ("ip_link", "suspicious link"), ("short_link", "suspicious link"), ("risky_tld", "suspicious link"),
    ("impersonation", "brand impersonation"), ("urgency", "pressure tactics"),
]


def _main_type(reasons):
    ids = {r["id"] for r in reasons}
    return next((label for rid, label in SCAM_TYPES if rid in ids), "none detected")


APPROVE_BELOW = 35
BLOCK_FROM = 70


def rule_phase(message: str, seller: str = "", amount: float = 0, payment_type: str = "goods_services") -> dict:
    rule_score, reasons, links, highlights = rule_engine(message, payment_type, amount, seller)
    return {"rule_score": rule_score, "reasons": reasons, "links": links, "highlights": highlights}


def finalize(rules: dict, ai: dict | None, ai_error: str | None = None, pending: bool = False) -> dict:
    """Combine the rule engine and the AI agent into one decision."""
    rule_score, reasons = rules["rule_score"], rules["reasons"]
    hard_stop = any(r["id"] in {"credentials", "lookalike", "ip_link"} for r in reasons)
    if ai:
        # The agent investigated (links, domain age, ...), so its verdict counts most.
        ai_score = ai["risk_score"]
        ai_says_safe = ai_score < APPROVE_BELOW
        score = round(0.3 * rule_score + 0.7 * ai_score)
        if ai_score >= BLOCK_FROM:
            # The agent found a scam: weak rule scores must not water it down.
            score = max(score, ai_score)
        elif rule_score >= BLOCK_FROM or hard_stop:
            # Strong rule evidence. If the agent checked and found it safe, ask the user to
            # verify instead of blocking; otherwise block.
            score = max(score, APPROVE_BELOW if ai_says_safe else BLOCK_FROM)
        engine = "rules + AI agent"
    else:
        score = rule_score
        engine = "rules"
        # Hard stops: without the agent, some signals alone are enough to block.
        if hard_stop:
            score = max(score, BLOCK_FROM)

    if score >= BLOCK_FROM:
        decision = "BLOCK"
    elif score >= APPROVE_BELOW:
        decision = "VERIFY"
    else:
        decision = "APPROVE"

    summary = {
        "BLOCK": ("High risk. PayShield blocked this payment to protect your money.",
                  "خطر عالٍ. أوقف PayShield هذه الدفعة لحماية أموالك."),
        "VERIFY": ("Some warning signs. Please confirm a few things before paying.",
                   "توجد بعض العلامات التحذيرية. يرجى التأكد من بعض الأمور قبل الدفع."),
        "APPROVE": ("No major warning signs found. You can pay with PayPal Buyer Protection.",
                    "لم نجد علامات تحذيرية كبيرة. يمكنك الدفع مع حماية المشتري من PayPal."),
    }[decision]

    return {
        "risk_score": score,
        "decision": decision,
        "engine": engine,
        "agent_pending": pending,
        "scam_type": (ai or {}).get("scam_type") or _main_type(reasons),
        "summary_en": summary[0],
        "summary_ar": summary[1],
        "ai_explanation_en": (ai or {}).get("explanation_en"),
        "ai_explanation_ar": (ai or {}).get("explanation_ar"),
        "ai_seconds": (ai or {}).get("seconds"),
        "reasons": reasons,
        "links": rules["links"],
        "highlights": rules["highlights"],
        "agent_steps": (ai or {}).get("steps", []),
        "ai_error": ai_error,
        "verify_questions": {
            "en": (ai or {}).get("verify_questions_en") or DEFAULT_QUESTIONS["en"],
            "ar": (ai or {}).get("verify_questions_ar") or DEFAULT_QUESTIONS["ar"],
        } if decision == "VERIFY" else None,
    }


def analyze(message: str, seller: str = "", amount: float = 0, currency: str = "USD",
            payment_type: str = "goods_services") -> dict:
    """Rules + AI agent in one blocking call (used by tests and scripts)."""
    rules = rule_phase(message, seller, amount, payment_type)
    ai = run_agent(message, seller, amount, currency, payment_type, [r["id"] for r in rules["reasons"]])
    return finalize(rules, ai, None if ai else _agent.last_error())
