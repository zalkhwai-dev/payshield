// PayShield AI - front end
const I18N = {
  en: {
    title: "Check before you pay.",
    subtitle: "Paste a payment request, invoice or seller message. PayShield's AI agent checks it for scams and only lets the PayPal payment go through if it's safe.",
    msgLabel: "Payment request or seller message",
    msgPh: "e.g. Your Aramex parcel is on hold. Pay a customs fee within 24 hours: aramex-sa-track.xyz",
    tryLabel: "Try an example:", s1: "Fake delivery fee", s2: "F&F seller", s3: "Normal purchase",
    s4: "\"New number\" scam", s5: "Friend splitting a bill",
    proof: "Tested on 159 real messages from Saudi Arabia: 92% of scams caught",
    sellerLabel: "Seller / recipient (email or name)", sellerPh: "seller@example.com",
    amountLabel: "Amount", currencyLabel: "Currency", typeLabel: "How are you asked to pay?",
    typeGS: "Goods & Services (Buyer Protection)", typeFF: "Friends & Family",
    checkBtn: "Check this payment", checking: "Checking…",
    waiting: "Your safety report will appear here.",
    footer: "Hackathon prototype · PayPal Sandbox only · No real money moves.",
    reasons: "What PayShield found", noReasons: "No warning signs found.",
    APPROVE: "SAFE TO PAY", VERIFY: "VERIFY FIRST", BLOCK: "BLOCKED",
    engine: (e, t) => `Checked by ${e}${t && !/^none/i.test(t) ? " · Type: " + t : ""}`,
    verifyTitle: "Answer honestly before paying:", yes: "Yes", no: "No", confirm: "Confirm answers",
    blockedMsg: "Payment blocked. Do not send money to this person.",
    demoNote: "Demo mode: add your PayPal sandbox keys in .env to use real PayPal checkout.",
    liveNote: "Connected to PayPal Sandbox", demoPay: "Pay with PayPal (demo)",
    demoHint: "Simulated checkout — no PayPal keys configured yet.",
    paid: (id) => `Payment completed ✓ (order ${id})`, error: "Something went wrong: ",
    converted: (a, c, u) => `PayPal doesn't process ${c}, so you'll pay $${u} USD (${a} ${c}, fixed rate ${c === "SAR" ? "3.75" : "3.6725"} ${c} = 1 USD).`,
    shotBtn: "Or upload a screenshot", markedTitle: "Suspicious parts of the message",
    stepsTitle: (n) => `How the AI agent investigated (${n} ${n === 1 ? "step" : "steps"})`, needInput: "Paste a message or upload a screenshot.",
    fromImage: "Text read from your screenshot",
    agentWorking: "Quick check done. The AI agent is investigating links and the seller…",
    agentWait: "Payment unlocks when the AI agent finishes.",
    agentTime: (s) => ` · AI agent: ${s}s`,
    stageQuick: "Quick check", stageFinal: "Final score", stageRules: "Rules only",
    stageFrom: (q) => `Quick check said ${q}. The AI agent's investigation updated it.`,
    tools: { check_link: "Checked link", expand_short_link: "Expanded short link", domain_age: "Looked up domain age",
             safe_browsing: "Asked Google Safe Browsing", scan_text_rules: "Scanned text with rules" },
  },
  ar: {
    title: "تحقّق قبل أن تدفع.",
    subtitle: "الصق طلب الدفع أو الفاتورة أو رسالة البائع. يفحصها وكيل PayShield الذكي بحثاً عن الاحتيال ولا يسمح بالدفع عبر PayPal إلا إذا كانت آمنة.",
    msgLabel: "طلب الدفع أو رسالة البائع",
    msgPh: "مثال: شحنتك من أرامكس معلقة. ادفع رسوم الجمارك خلال 24 ساعة: aramex-sa-track.xyz",
    tryLabel: "جرّب مثالاً:", s1: "رسوم توصيل مزيفة", s2: "بائع يطلب أصدقاء وعائلة", s3: "شراء عادي",
    s4: "احتيال «رقمي الجديد»", s5: "صديقة تقسم الفاتورة",
    proof: "تم اختباره على 159 رسالة حقيقية من السعودية: اكتشف 92% من رسائل الاحتيال",
    sellerLabel: "البائع / المستلم (بريد أو اسم)", sellerPh: "seller@example.com",
    amountLabel: "المبلغ", currencyLabel: "العملة", typeLabel: "كيف يُطلب منك الدفع؟",
    typeGS: "سلع وخدمات (مع حماية المشتري)", typeFF: "أصدقاء وعائلة",
    checkBtn: "افحص هذه الدفعة", checking: "جارٍ الفحص…",
    waiting: "سيظهر تقرير الأمان هنا.",
    footer: "نموذج أولي للهاكاثون · بيئة PayPal التجريبية فقط · لا تُحوَّل أموال حقيقية.",
    reasons: "ما وجده PayShield", noReasons: "لم توجد علامات تحذيرية.",
    APPROVE: "آمن للدفع", VERIFY: "تحقّق أولاً", BLOCK: "تم الإيقاف",
    engine: (e, t) => `تم الفحص بواسطة ${e === "rules" ? "القواعد" : "القواعد + الوكيل الذكي"}`,
    verifyTitle: "أجب بصدق قبل الدفع:", yes: "نعم", no: "لا", confirm: "تأكيد الإجابات",
    blockedMsg: "تم إيقاف الدفع. لا ترسل أموالاً لهذا الشخص.",
    demoNote: "وضع العرض: أضف مفاتيح PayPal التجريبية في ملف ‎.env لاستخدام الدفع الحقيقي.",
    liveNote: "متصل ببيئة PayPal التجريبية", demoPay: "ادفع عبر PayPal (تجريبي)",
    demoHint: "دفع محاكى — لم تُضف مفاتيح PayPal بعد.",
    paid: (id) => `تم الدفع بنجاح ✓ (طلب ${id})`, error: "حدث خطأ: ",
    converted: (a, c, u) => `لا يدعم PayPal عملة ${c === "SAR" ? "الريال السعودي" : "الدرهم الإماراتي"}، لذلك ستدفع ${u} دولار أمريكي (${a} ${c} بسعر ثابت ${c === "SAR" ? "3.75" : "3.6725"} = 1 دولار).`,
    shotBtn: "أو ارفع لقطة شاشة", markedTitle: "الأجزاء المشبوهة في الرسالة",
    stepsTitle: (n) => `كيف حقق الوكيل الذكي (${n} خطوات)`, needInput: "الصق رسالة أو ارفع لقطة شاشة.",
    fromImage: "النص المقروء من لقطة الشاشة",
    agentWorking: "انتهى الفحص السريع. الوكيل الذكي يحقق في الروابط والبائع…",
    agentWait: "يُفتح الدفع عندما ينتهي الوكيل الذكي.",
    agentTime: (s) => ` · الوكيل الذكي: ${s} ث`,
    stageQuick: "فحص سريع", stageFinal: "النتيجة النهائية", stageRules: "القواعد فقط",
    stageFrom: (q) => `الفحص السريع أعطى ${q}، ثم حدّثها تحقيق الوكيل الذكي.`,
    tools: { check_link: "فحص الرابط", expand_short_link: "فك الرابط المختصر", domain_age: "عمر النطاق",
             safe_browsing: "سؤال Google Safe Browsing", scan_text_rules: "فحص النص بالقواعد" },
  },
};

const SAMPLES = {
  delivery: {
    message: "أرامكس: شحنتك معلقة بسبب عدم سداد رسوم جمركية. ادفع الرسوم خلال 24 ساعة وإلا سيتم إرجاع الشحنة: https://aramex-sa-track.xyz/pay\nAramex: your parcel is on hold. Pay the customs fee within 24 hours.",
    seller: "aramex.delivery.ksa@gmail.com", amount: 4, ptype: "friends_family",
  },
  ff: {
    message: "Hi! PS5 brand new sealed, only $150 because I'm moving abroad this week. Please send as Friends & Family to avoid fees, I'll ship today. Many other buyers waiting so be quick.",
    seller: "gamer.deals22@outlook.com", amount: 150, ptype: "friends_family",
  },
  newnum: {
    message: "هلا حبيبتي 🌸 هذا رقمي الجديد احفظيه، جوالي القديم خرب. عندي موضوع ضروري: أمي في المستشفى والبنك موقف حسابي. تقدرين تحولين لي 500 ريال الحين عبر PayPal (أصدقاء وعائلة) وأرجعها لك بكرة إن شاء الله؟ لا تتصلين الحين لأني ما أقدر أرد",
    seller: "+966 5x xxx xxxx", amount: 500, ptype: "friends_family",
  },
  split: {
    message: "هلا نورة! هذي فاتورة عشاء أمس في المطعم، نصيبك 85 ريال. حوليها لي على PayPal لما تفضين، مو مستعجلة 😊",
    seller: "Sara (friend)", amount: 85, ptype: "friends_family",
  },
  safe: {
    message: "Invoice #1042 from Riyadh Calligraphy Studio for the custom wedding invitation design we agreed on last week. Thank you for your order!",
    seller: "billing@riyadhcalligraphy.com", amount: 45, ptype: "goods_services",
  },
};

let lang = "en";
let config = { demo_mode: true };
let lastResult = null;
const $ = (s) => document.querySelector(s);
const t = (k) => I18N[lang][k];

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  $("#langBtn").textContent = lang === "ar" ? "English" : "العربية";
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  renderMode();
  if (lastResult) renderResult(lastResult);
}

function renderMode() {
  const note = $("#modeNote");
  note.textContent = config.demo_mode ? t("demoNote") : t("liveNote");
  note.classList.toggle("live", !config.demo_mode);
}

async function api(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

const COLORS = {
  APPROVE: ["--safe", "--safe-bg"], VERIFY: ["--warn", "--warn-bg"], BLOCK: ["--risk", "--risk-bg"],
};

function renderResult(r) {
  const box = $("#result");
  box.classList.remove("empty");
  box.replaceChildren($("#resultTpl").content.cloneNode(true));
  const [c, cbg] = COLORS[r.decision];
  box.style.setProperty("--c", `var(${c})`);
  box.style.setProperty("--cbg", `var(${cbg})`);

  box.querySelector(".score b").textContent = r.risk_score;
  // Which stage this score comes from: instant rule check, final AI verdict, or rules only (no AI).
  box.querySelector(".stage").textContent =
    r.agent_pending ? t("stageQuick") : r.engine === "rules" ? t("stageRules") : t("stageFinal");
  // Only explain the change when it matters: the decision changed, or the score moved a lot.
  const changed = !r.agent_pending && r.quick_score != null &&
    (Math.abs(r.quick_score - r.risk_score) >= 15 || (r.quick_decision && r.quick_decision !== r.decision));
  box.querySelector(".stage-note").textContent = changed ? t("stageFrom")(r.quick_score) : "";
  requestAnimationFrame(() => {
    box.querySelector(".bar").style.strokeDashoffset = 314 - (314 * r.risk_score) / 100;
  });
  box.querySelector(".badge").textContent = t(r.decision);
  box.querySelector(".summary").textContent = lang === "ar" ? r.summary_ar : r.summary_en;
  box.querySelector(".engine").textContent = t("engine")(r.engine, r.scam_type)
    + (r.ai_seconds ? t("agentTime")(r.ai_seconds) : "")
    + (r.ai_error ? (lang === "ar" ? ` · لم يستجب الوكيل الذكي: ${r.ai_error}` : ` · AI agent unavailable: ${r.ai_error}`) : "");
  box.querySelector(".ai-text").textContent = (lang === "ar" ? r.ai_explanation_ar : r.ai_explanation_en) || "";
  box.querySelector(".reasons-title").textContent = t("reasons");

  const ul = box.querySelector(".reasons");
  if (!r.reasons.length) {
    const li = document.createElement("li"); li.textContent = t("noReasons"); ul.append(li);
  }
  r.reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = lang === "ar" ? reason.ar : reason.en;
    if (reason.detail) { const code = document.createElement("code"); code.textContent = " " + reason.detail; li.append(document.createElement("br"), code); }
    ul.append(li);
  });

  renderMarked(box, r);
  renderSteps(box, r);

  if (r.agent_pending) {
    const div = document.createElement("div"); div.className = "pending";
    const spin = document.createElement("span"); spin.className = "spinner";
    const txt = document.createElement("span"); txt.textContent = t("agentWorking");
    div.append(spin, txt);
    const hint = document.createElement("p"); hint.className = "hint"; hint.textContent = t("agentWait");
    box.querySelector(".pay").replaceChildren(div, hint);
    return;
  }
  if (r.decision === "BLOCK") showBlocked(r.blocked_msg);
  else if (r.decision === "VERIFY" && !r.verified) renderVerify(r);
  else renderPay(r);
}

function renderMarked(box, r) {
  const p = box.querySelector(".marked");
  box.querySelector(".marked-title").textContent = r.extracted_from_image ? t("fromImage") : t("markedTitle");
  if (!r.highlights?.length && !r.extracted_from_image) return;
  const text = r.analyzed_text || "";
  let pos = 0;
  (r.highlights || []).forEach((h) => {
    if (h.start > pos) p.append(document.createTextNode(text.slice(pos, h.start)));
    const m = document.createElement("mark");
    m.textContent = text.slice(h.start, h.end);
    p.append(m);
    pos = h.end;
  });
  p.append(document.createTextNode(text.slice(pos)));
}

function renderSteps(box, r) {
  const steps = r.agent_steps || [];
  const ol = box.querySelector(".steps ol");
  box.querySelector(".steps summary").textContent = t("stepsTitle")(steps.length);
  steps.forEach((s) => {
    const li = document.createElement("li");
    const b = document.createElement("b"); b.textContent = t("tools")[s.tool] || s.tool;
    const arg = Object.values(s.args || {})[0] || "";
    const code = document.createElement("code"); code.textContent = s.result;
    li.append(b, document.createTextNode(arg ? `: ${arg}` : ""), code);
    ol.append(li);
  });
}

function showBlocked(msg) {
  const pay = $("#result .pay");
  const div = document.createElement("div");
  div.className = "blocked";
  div.textContent = msg || t("blockedMsg");
  pay.replaceChildren(div);
}

function renderVerify(r) {
  const box = $("#result .verify");
  const qs = r.verify_questions[lang];
  const answers = new Array(qs.length).fill(null);
  const title = document.createElement("h3");
  title.className = "reasons-title"; title.textContent = t("verifyTitle");
  box.replaceChildren(title);
  qs.forEach((q, i) => {
    const row = document.createElement("div"); row.className = "q";
    const span = document.createElement("span"); span.textContent = q;
    const yn = document.createElement("div"); yn.className = "yn";
    [["yes", true], ["no", false]].forEach(([key, val]) => {
      const b = document.createElement("button"); b.type = "button"; b.textContent = t(key);
      b.onclick = () => {
        answers[i] = val;
        yn.querySelectorAll("button").forEach((x) => x.className = "");
        b.className = val ? "on-yes" : "on-no";
        confirmBtn.disabled = answers.includes(null);
      };
      yn.append(b);
    });
    row.append(span, yn); box.append(row);
  });
  const confirmBtn = document.createElement("button");
  confirmBtn.className = "primary"; confirmBtn.type = "button"; confirmBtn.textContent = t("confirm"); confirmBtn.disabled = true;
  confirmBtn.onclick = async () => {
    try {
      const v = await api("/api/verify", { check_id: r.check_id, answers });
      box.replaceChildren();
      if (v.allowed) { r.verified = true; renderPay(r); }
      else { r.decision = "BLOCK"; r.blocked_msg = lang === "ar" ? v.message_ar : v.message_en; renderResult(r); }
    } catch (e) { alert(t("error") + e.message); }
  };
  box.append(confirmBtn);
}

let sdkCurrency = null;
function loadPayPalSdk(currency) {
  if (window.paypal && sdkCurrency === currency) return Promise.resolve();
  document.querySelectorAll("script[data-paypal]").forEach((s) => s.remove());
  delete window.paypal;
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = `https://www.paypal.com/sdk/js?client-id=${encodeURIComponent(config.paypal_client_id)}&currency=${currency}&intent=capture`;
    s.dataset.paypal = "1";
    s.onload = () => { sdkCurrency = currency; resolve(); };
    s.onerror = () => reject(new Error("Could not load PayPal SDK"));
    document.head.append(s);
  });
}

function showPaid(id) {
  const div = document.createElement("div"); div.className = "done"; div.textContent = t("paid")(id);
  $("#result .pay").replaceChildren(div);
}

function conversionNote(r) {
  if (!r.pay_currency || r.pay_currency === r.currency) return null;
  const p = document.createElement("p"); p.className = "hint";
  p.textContent = t("converted")(r.amount, r.currency, Number(r.pay_amount).toFixed(2));
  return p;
}

async function renderPay(r) {
  const pay = $("#result .pay");
  if (r.paid_id) return showPaid(r.paid_id);
  const note = conversionNote(r);
  if (config.demo_mode) {
    const btn = document.createElement("button"); btn.className = "demo-pay"; btn.type = "button"; btn.textContent = t("demoPay");
    btn.onclick = async () => {
      try {
        const order = await api("/api/orders", { check_id: r.check_id });
        const cap = await api(`/api/orders/${order.id}/capture`, {});
        r.paid_id = cap.id; showPaid(cap.id);
      } catch (e) { alert(t("error") + e.message); }
    };
    const hint = document.createElement("p"); hint.className = "hint"; hint.textContent = t("demoHint");
    pay.replaceChildren(...[note, btn, hint].filter(Boolean));
    return;
  }
  const holder = document.createElement("div"); holder.id = "paypal-buttons";
  pay.replaceChildren(...[note, holder].filter(Boolean));
  try {
    await loadPayPalSdk(r.pay_currency || r.currency);
    window.paypal.Buttons({
      createOrder: async () => (await api("/api/orders", { check_id: r.check_id })).id,
      onApprove: async (data) => {
        const cap = await api(`/api/orders/${data.orderID}/capture`, {});
        r.paid_id = cap.id; showPaid(cap.id);
      },
      onError: (err) => alert(t("error") + (err?.message || err)),
    }).render("#paypal-buttons");
  } catch (e) { alert(t("error") + e.message); }
}

$("#checkForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("#checkBtn");
  btn.disabled = true; btn.textContent = t("checking");
  try {
    const file = $("#shot").files[0];
    if (!$("#message").value.trim() && !file) throw new Error(t("needInput"));
    const payload = {
      message: $("#message").value, seller: $("#seller").value,
      amount: $("#amount").value, currency: $("#currency").value, payment_type: $("#ptype").value,
    };
    if (file) { payload.image = await toBase64(file); payload.image_type = file.type; }
    lastResult = await api("/api/check", payload);
    renderResult(lastResult);
    if (lastResult.agent_pending) pollAgent(lastResult.check_id);
    if (window.innerWidth < 860) $("#result").scrollIntoView({ behavior: "smooth" });
  } catch (e) { alert(t("error") + e.message); }
  finally { btn.disabled = false; btn.textContent = t("checkBtn"); }
});

async function pollAgent(id) {
  const started = Date.now();
  while (Date.now() - started < 90000) {
    await new Promise((res) => setTimeout(res, 1200));
    if (!lastResult || lastResult.check_id !== id) return;   // user started a new check
    try {
      const r = await (await fetch(`/api/check/${id}`)).json();
      if (!r.agent_pending) {
        r.quick_score = lastResult.risk_score; r.quick_decision = lastResult.decision;
        lastResult = r; renderResult(r); return;
      }
    } catch (e) { /* keep waiting */ }
  }
}

function toBase64(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(String(fr.result).split(",")[1]);
    fr.onerror = reject;
    fr.readAsDataURL(file);
  });
}

$("#shot").addEventListener("change", () => {
  const f = $("#shot").files[0];
  $("#shotName").textContent = f ? f.name : "";
  $("#shotClear").hidden = !f;
});
$("#shotClear").addEventListener("click", () => {
  $("#shot").value = ""; $("#shotName").textContent = ""; $("#shotClear").hidden = true;
});

document.querySelectorAll("[data-sample]").forEach((b) => b.addEventListener("click", () => {
  const s = SAMPLES[b.dataset.sample];
  $("#message").value = s.message; $("#seller").value = s.seller; $("#amount").value = s.amount; $("#ptype").value = s.ptype;
  $("#currency").value = "SAR";
}));

$("#langBtn").addEventListener("click", () => { lang = lang === "en" ? "ar" : "en"; applyLang(); });

fetch("/api/config").then((r) => r.json()).then((c) => { config = c; renderMode(); }).catch(() => {});
applyLang();
