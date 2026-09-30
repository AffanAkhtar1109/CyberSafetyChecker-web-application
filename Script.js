/* =====================================================================
   CYBER SAFETY CHECKER - PROJECT NOTES (for the competition demo)
   =====================================================================

   WHAT THE FRONTEND DOES (index.html + style.css)
   - index.html holds the page structure: tabs, text box, URL box,
     buttons, empty result areas and the safety tips.
   - style.css gives it the dark theme and makes it work on phones.

   WHAT JAVASCRIPT DOES (this file)
   - Listens for button clicks, reads what the user typed, runs the
     analysis, and builds the result card on the page.
   - Everything runs inside the browser. Nothing is sent to a server.

   HOW THE MESSAGE ANALYSIS WORKS
   - We keep a list of RULES. Each rule looks for one warning pattern
     (for example: asking for an OTP, urgent language, prize offers).
   - Every rule that matches adds "points". Total points decide the
     level: Low (0-2), Medium (3-6), High (7+).
   - It is keyword/pattern matching, so it can be wrong in both
     directions. The wording always says "potential warning signs".

   HOW THE URL ANALYSIS WORKS
   - The browser's built-in URL tool splits the address into parts
     (protocol, hostname, path).
   - We then run simple checks: HTTP vs HTTPS, IP address instead of a
     domain, very long URL, "@" symbol, punycode (xn--), many subdomains,
     many hyphens, risky keywords, uncommon endings (.xyz, .top ...),
     link shorteners, unusual ports, and heavy encoding.
   - Points are added in the same way as for messages.
   - These are indicators only, NOT proof that a site is harmful.

   WHAT COULD BE ADDED IN A FUTURE VERSION (real AI API / backend)
   - Send the text to an AI model through a small backend so it can
     understand meaning and tone, not just keywords.
   - Check URLs against live threat databases (for example Google Safe
     Browsing) and look up domain age.
   - Support more languages, and let users report scams.
   - Keep API keys on the backend, never inside this file.
   ===================================================================== */

"use strict";

const $ = (id) => document.getElementById(id);

/* ---------- 1. Tabs ---------- */
function switchTab(name) {
  ["message", "url"].forEach((t) => {
    const active = t === name;
    $("tab-" + t).classList.toggle("active", active);
    $("tab-" + t).setAttribute("aria-selected", active);
    $("panel-" + t).hidden = !active;
  });
}
$("tab-message").addEventListener("click", () => switchTab("message"));
$("tab-url").addEventListener("click", () => switchTab("url"));

/* ---------- 2. Message rules ---------- */
// Each rule: a label, a regex to look for, points, and a simple reason.
const MESSAGE_RULES = [
  { label: "Asks for an OTP, PIN, CVV or password", points: 4,
    re: /\b(otp|one[- ]time (password|code)|pin|cvv|password|passcode|card number)\b/i,
    why: "Real companies do not ask you to share these codes." },
  { label: "Urgent or threatening language", points: 2,
    re: /\b(urgent|immediately|act now|within \d+ (hours?|minutes?)|last warning|final notice|expires? (today|soon)|right away)\b/i,
    why: "Pressure is used to stop you from thinking carefully." },
  { label: "Claims your account is blocked or suspended", points: 2,
    re: /\b(account|card|sim|wallet).{0,30}(blocked|suspended|locked|deactivated|closed|compromised)\b/i,
    why: "Fear of losing access is a common trick." },
  { label: "Prize, lottery or reward offer", points: 3,
    re: /\b(you (have )?won|winner|lottery|lucky draw|prize|reward|cashback|free gift|congratulations)\b/i,
    why: "Unexpected prizes are a classic bait." },
  { label: "Asks you to verify, update or confirm details (e.g. KYC)", points: 2,
    re: /\b(verify|update|confirm|re-?activate|validate).{0,25}(account|details|kyc|identity|information|bank)\b|\bkyc\b/i,
    why: "Legitimate updates are usually done inside the official app or website." },
  { label: "Requests payment by gift card, crypto or wire transfer", points: 4,
    re: /\b(gift ?cards?|bitcoin|crypto|wire transfer|western union|upi (pin|request))\b/i,
    why: "These payment methods are hard to reverse." },
  { label: "Contains a link", points: 1,
    re: /(https?:\/\/|www\.)\S+/i,
    why: "Links can lead to fake pages. Do not open links you did not expect." },
  { label: "Uses a shortened link", points: 2,
    re: /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd|shorturl\.at)\//i,
    why: "Short links hide the real destination." },
  { label: "Generic greeting (no real name)", points: 1,
    re: /\b(dear (customer|user|sir|madam|member|friend|account holder))\b/i,
    why: "Messages from companies you use often include your name." },
  { label: "Mentions an attachment or asks you to download something", points: 1,
    re: /\b(attached|attachment|download|install|open the file|invoice\.(zip|exe|pdf))\b/i,
    why: "Unexpected files can carry harmful software." },
  { label: "Emotional pressure or secrecy", points: 1,
    re: /\b(don'?t tell anyone|keep (this )?secret|confidential|help me|stuck abroad|emergency)\b/i,
    why: "Scammers often ask you to keep things secret." }
];

function analyzeMessage(text) {
  const flags = [];
  let score = 0;

  MESSAGE_RULES.forEach((rule) => {
    if (rule.re.test(text)) { flags.push({ label: rule.label, why: rule.why }); score += rule.points; }
  });

  // Extra style checks
  const letters = text.replace(/[^A-Za-z]/g, "");
  const capsRatio = letters.length > 20
    ? letters.replace(/[^A-Z]/g, "").length / letters.length : 0;
  if (capsRatio > 0.5) {
    flags.push({ label: "Lots of CAPITAL LETTERS", why: "Shouting text is often used to create panic." });
    score += 1;
  }
  if ((text.match(/!/g) || []).length >= 3) {
    flags.push({ label: "Many exclamation marks", why: "Excited or alarming tone is a pressure technique." });
    score += 1;
  }

  const level = score >= 7 ? "high" : score >= 3 ? "medium" : "low";
  return { level, flags };
}

/* ---------- 3. URL checks ---------- */
const RISKY_WORDS = ["login", "signin", "verify", "secure", "update", "account", "bank", "wallet", "confirm", "password", "support", "billing"];
const RISKY_ENDINGS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".zip", ".work", ".loan", ".country", ".support"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "shorturl.at"];
const BRANDS = ["paypal", "google", "amazon", "microsoft", "apple", "facebook", "instagram", "netflix", "sbi", "hdfc", "icici", "paytm", "whatsapp"];

function analyzeUrl(input) {
  const flags = [];
  let score = 0;
  const add = (label, why, pts) => { flags.push({ label, why }); score += pts; };

  let raw = input.trim();
  let assumedScheme = false;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) { raw = "http://" + raw; assumedScheme = true; }

  let url;
  try { url = new URL(raw); } catch (e) { return null; }
  if (!url.hostname.includes(".") && !/^\[.*\]$/.test(url.hostname)) return null;

  const host = url.hostname.toLowerCase();
  const full = input.trim();

  if (url.protocol === "http:" && !assumedScheme) {
    add("Uses HTTP instead of HTTPS", "HTTP traffic is not encrypted. Many safe sites use HTTPS, so its absence is a warning sign.", 2);
  } else if (assumedScheme) {
    flags.push({ label: "No protocol (http/https) was typed", why: "We could not tell if the site uses HTTPS. Look for the padlock in your browser." });
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) {
    add("Uses an IP address instead of a domain name", "Normal websites use names. IP addresses are often used to hide identity.", 3);
  }

  if (full.length > 75) add("Very long URL (" + full.length + " characters)", "Long URLs can hide the real destination.", 1);
  if (full.length > 150) score += 1;

  if (url.username || raw.replace(/^[a-z]+:\/\//i, "").split("/")[0].includes("@")) {
    add("Contains an @ symbol", "Text before @ is ignored by the browser, which can disguise the real site.", 3);
  }

  if (host.includes("xn--")) add("Uses punycode (xn--)", "This can be used to imitate real names with look-alike characters.", 3);

  const parts = host.split(".");
  if (parts.length > 4) add("Many subdomains (" + parts.length + " parts)", "Extra parts can make a fake address look official.", 2);

  if ((host.match(/-/g) || []).length >= 3) add("Many hyphens in the domain", "Long hyphenated names are often used in look-alike domains.", 1);

  const foundWords = RISKY_WORDS.filter((w) => host.includes(w));
  if (foundWords.length) add("Domain contains words like: " + foundWords.join(", "), "Such words are often added to fake pages to look trustworthy.", foundWords.length > 1 ? 2 : 1);

  const ending = RISKY_ENDINGS.find((e) => host.endsWith(e));
  if (ending) add("Uncommon domain ending (" + ending + ")", "Some endings are used more often in abuse. Plenty of safe sites use them too.", 1);

  if (SHORTENERS.includes(host)) add("Link shortener", "The real destination is hidden.", 2);

  const brand = BRANDS.find((b) => host.includes(b) && !new RegExp("(^|\\.)" + b + "\\.(com|in|co\\.in|net|org)$").test(host));
  if (brand) add("Contains the name '" + brand + "' but may not be its official domain", "Look-alike names are a common trick. Check the main domain carefully.", 2);

  if (url.port && !["80", "443", ""].includes(url.port)) add("Unusual port number (" + url.port + ")", "Normal websites rarely use custom ports.", 1);

  if ((full.match(/%[0-9a-f]{2}/gi) || []).length >= 3 || /[<>"'{}|\\^`]/.test(full)) {
    add("Unusual characters or heavy encoding", "Odd symbols can hide the true address or content.", 1);
  }

  const level = score >= 6 ? "high" : score >= 3 ? "medium" : "low";
  return { level, flags, host };
}

/* ---------- 4. Showing results ---------- */
const LEVEL_TEXT = { low: "Low risk", medium: "Medium risk", high: "High risk" };

// Helper: make an element safely (textContent avoids running pasted code)
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function renderResult(box, data, explanation, recommendations, note) {
  box.replaceChildren();
  const card = el("div", "", "result-card " + data.level);

  card.append(el("span", LEVEL_TEXT[data.level] + " (estimated)", "badge"));

  card.append(el("h3", "Potential warning signs detected"));
  if (data.flags.length) {
    const ul = el("ul");
    data.flags.forEach((f) => {
      const li = el("li", f.label);
      li.append(el("div", f.why, "why"));
      ul.append(li);
    });
    card.append(ul);
  } else {
    card.append(el("p", "No common warning signs were found by these basic checks."));
  }

  card.append(el("h3", "Simple explanation"));
  card.append(el("p", explanation));

  card.append(el("h3", "Safety recommendations"));
  const rec = el("ul");
  recommendations.forEach((r) => rec.append(el("li", r)));
  card.append(rec);

  card.append(el("div", note, "note"));
  box.append(card);
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/* ---------- 5. Message button ---------- */
const MESSAGE_EXPLAIN = {
  low: "Few or no common warning patterns were found. That does not guarantee the message is safe, so stay careful with anything unexpected.",
  medium: "Some patterns often seen in scam messages were found. Treat the message with caution and verify it before acting.",
  high: "Several patterns often seen in scam messages were found together. Do not reply, click links, or share any codes until you verify it independently."
};
const MESSAGE_RECS = {
  low: ["Still verify the sender if the message is unexpected.", "Never share OTPs or passwords."],
  medium: ["Do not click links in the message.", "Contact the company using its official website or app.", "Do not share personal or bank details."],
  high: ["Do not click links or open attachments.", "Never share OTPs, PINs or passwords.", "Contact the real organisation using a number from its official website.", "Report it (for example to your bank or the national cyber crime portal) and delete it."]
};

$("analyzeMessageBtn").addEventListener("click", () => {
  const text = $("messageInput").value.trim();
  const box = $("messageResult");
  if (!text) {
    box.replaceChildren(el("div", "Please paste a message first.", "note"));
    return;
  }
  const data = analyzeMessage(text);
  renderResult(box, data, MESSAGE_EXPLAIN[data.level], MESSAGE_RECS[data.level],
    "This is a simple pattern check, not proof. Only the sender or the official organisation can confirm whether a message is genuine.");
});

$("messageExampleBtn").addEventListener("click", () => {
  $("messageInput").value = "Dear customer, your bank account will be BLOCKED today! Verify your KYC immediately and share the OTP at http://bit.ly/kyc-update to avoid suspension.";
});
$("messageClearBtn").addEventListener("click", () => {
  $("messageInput").value = "";
  $("messageResult").replaceChildren();
});

/* ---------- 6. URL button ---------- */
const URL_EXPLAIN = {
  low: "These basic checks did not find many common warning signs in the address itself.",
  medium: "The address has some characteristics that are sometimes seen in misleading websites. Check it carefully before visiting.",
  high: "The address has several characteristics that are often seen in misleading websites. It is safer not to enter any personal information on it."
};
const URL_RECS = {
  low: ["Look for the padlock and check the spelling of the domain.", "Avoid entering passwords on pages you reached through a link."],
  medium: ["Type the official website address yourself instead of using this link.", "Do not enter passwords or payment details here."],
  high: ["Avoid opening this link.", "Go to the official website by typing its address or using its app.", "Never enter passwords, OTPs or card details on this site."]
};

$("checkUrlBtn").addEventListener("click", () => {
  const input = $("urlInput").value.trim();
  const box = $("urlResult");
  if (!input) {
    box.replaceChildren(el("div", "Please enter a URL first.", "note"));
    return;
  }
  const data = analyzeUrl(input);
  if (!data) {
    box.replaceChildren(el("div", "That does not look like a valid web address. Try something like https://example.com", "note"));
    return;
  }
  renderResult(box, data, URL_EXPLAIN[data.level], URL_RECS[data.level],
    "Important: these are indicators, NOT proof. A safe website can trigger some of them, and a harmful website can trigger none. This tool never visits the link.");
});

$("urlExampleBtn").addEventListener("click", () => {
  $("urlInput").value = "http://secure-login.paypal-verify-account.xyz/update?id=839201";
});
$("urlClearBtn").addEventListener("click", () => {
  $("urlInput").value = "";
  $("urlResult").replaceChildren();
});

// Pressing Enter in the URL box works like clicking "Check URL"
$("urlInput").addEventListener("keydown", (e) => { if (e.key === "Enter") $("checkUrlBtn").click(); });
