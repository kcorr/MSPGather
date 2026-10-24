"use strict";

/* MSPGather core: shared helpers, components, registry, menu and router.
   Tools live in static/tools/*.js and call registerTool(). */

/* ------------------------------------------------------------------ helpers */
// Everything we render can come from untrusted mail headers, so DOM nodes are
// built with textContent only. Never use innerHTML with data.
function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if ((k === "href" || k === "src") && !/^(https?:|mailto:|#|\/|blob:|data:image\/)/i.test(String(v).trim())) continue;
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

const SEV_LABEL = { critical: "Critical", warning: "Warning", info: "Info", ok: "OK" };
const badge = (sev, text) => el("span", { class: `badge sev-${sev}` }, text || SEV_LABEL[sev] || sev);
const resultSev = (r) => ({ pass: "ok", fail: "critical", hardfail: "critical", softfail: "warning", permerror: "critical",
  temperror: "warning", neutral: "info", none: "info", bestguesspass: "ok", softpass: "warning" }[String(r).toLowerCase()] || "info");

function card(title, body, opts = {}) {
  return el("section", { class: "card" },
    title ? el("h2", {}, title, opts.extra ? [el("span", { class: "spacer" }), opts.extra] : null) : null,
    el("div", { class: opts.flush ? "card-body flush" : "card-body" }, body));
}

function kv(rows) {
  return el("dl", { class: "kv" }, rows.filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
}

function table(cols, rows, rowClass) {
  return el("div", { class: "table-wrap" }, el("table", { class: "t" },
    el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c)))),
    el("tbody", {}, rows.map((r, i) => el("tr", { class: rowClass ? rowClass(i) : null }, r.map((c) => el("td", {}, c)))))));
}

function copyText(text, btn) {
  const done = () => { const o = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = o), 1200); };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, () => {});
  } else {
    const ta = el("textarea", { style: "position:fixed;opacity:0" }, text);
    document.body.append(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
    ta.remove();
  }
}

function code(text) {
  const btn = el("button", { class: "icon-btn copy", type: "button" }, "Copy");
  btn.addEventListener("click", () => copyText(text, btn));
  return el("div", { class: "code" }, btn, text);
}

function findingsList(list, opts = {}) {
  if (!list || !list.length) return el("div", { class: "card-body hint" }, "Nothing to report.");
  const order = { critical: 0, warning: 1, info: 2, ok: 3 };
  const items = [...list].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  return el("ul", { class: "findings" }, items.map((f) => el("li", { class: "finding" },
    el("div", {}, badge(f.severity)),
    el("div", {},
      el("div", { class: "f-title" }, opts.area && f.area ? el("span", { class: "f-area" }, f.area) : null, f.title),
      f.detail ? el("div", { class: "f-detail" }, f.detail) : null))));
}

function stat(label, value, small) {
  return el("div", { class: "stat" }, el("div", { class: "s-label" }, label), el("div", { class: small ? "s-value small" : "s-value" }, value ?? "—"));
}

function sevCounts(findings) {
  const c = { critical: 0, warning: 0, info: 0, ok: 0 };
  (findings || []).forEach((f) => { if (f.severity in c) c[f.severity]++; });
  return c;
}

function link(tool, params, text) {
  const qs = new URLSearchParams(params).toString();
  return el("a", { href: `#${tool}${qs ? "?" + qs : ""}` }, text);
}

function fmtDuration(s) {
  if (s == null) return "—";
  const neg = s < 0; s = Math.abs(Math.round(s));
  let out = s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : s < 86400 ? `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m` : `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
  return neg ? "-" + out : out;
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

/** Signed-in user ({auth_enabled, username, role, csrf, ...}); set at start-up. */
let ME = { auth_enabled: false, role: "admin", csrf: null };

async function api(path, opts = {}) {
  const method = opts.method || (opts.body ? "POST" : "GET");
  const headers = {};
  if (opts.body) headers["content-type"] = "application/json";
  if (method !== "GET" && ME.csrf) headers["x-csrf-token"] = ME.csrf;
  const res = await fetch(path, { method, headers, credentials: "same-origin",
    body: opts.body ? JSON.stringify(opts.body) : undefined });
  if (res.status === 401 && ME.auth_enabled) {
    location.href = "/login";  // session expired or signed out elsewhere
    throw new Error("Your session has ended. Sign in again.");
  }
  let data;
  try { data = await res.json(); } catch (e) { throw new Error(`Server returned ${res.status}`); }
  if (!res.ok) {
    const d = data && data.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || `Server returned ${res.status}`);
  }
  return data;
}

async function runInto(target, label, fn, renderFn) {
  target.replaceChildren(el("div", { class: "loading" }, el("div", { class: "spinner" }), label));
  const t0 = performance.now();
  try {
    const data = await fn();
    target.replaceChildren(renderFn(data));
    target.prepend(el("div", { class: "hint", style: "margin:-6px 0 10px" }, `Completed in ${((performance.now() - t0) / 1000).toFixed(1)}s`));
  } catch (e) {
    target.replaceChildren(el("div", { class: "error-box" }, e.message || String(e)));
  }
}

let META = { resolvers: ["system"], record_types: ["A"] };
function resolverSelect(name, value) {
  return el("select", { name, id: name }, META.resolvers.map((r) => el("option", { value: r, selected: r === value }, r)));
}

/* ------------------------------------------------------- readability components */
// Every tool result should read top-down: verdict → what's wrong + how to fix → details.

const SEV_ICON = { critical: "!", warning: "!", info: "i", ok: "✓" };

/** The one-sentence answer at the top of every result. */
function verdict(sev, title, sub) {
  return el("div", { class: `verdict sev-${sev}` }, el("div", { class: "v-icon" }, SEV_ICON[sev] || "i"),
    el("div", {}, el("div", { class: "v-title" }, title), sub ? el("div", { class: "v-sub" }, sub) : null));
}

/** Numbered fix steps. steps: [{title, detail?, commands?: [string]}] or strings. */
function nextSteps(steps, title = "What to do") {
  const items = (steps || []).filter(Boolean).map((s) => (typeof s === "string" ? { title: s } : s));
  if (!items.length) return null;
  return card(title, el("ol", { class: "steps" }, items.map((s) => el("li", {},
    el("div", { class: "step-title" }, s.title),
    s.detail ? el("div", { class: "step-detail" }, s.detail) : null,
    (s.commands || []).map((c) => code(c))))));
}

/** Small "label: value" chips row, e.g. key facts under a verdict. */
function facts(pairs) {
  return el("div", { class: "facts" }, pairs.filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => el("div", { class: "fact" }, el("span", { class: "fact-k" }, k), el("span", { class: "fact-v" }, v))));
}

/** Overall severity of a findings list (worst wins). */
function worstSeverity(findings) {
  const order = ["critical", "warning", "info", "ok"];
  for (const s of order) if ((findings || []).some((f) => f.severity === s)) return s;
  return "ok";
}

/** Tool-specific CSS. Prefix your selectors with your tool id to avoid clashes. */
function addStyles(css) {
  document.head.append(el("style", {}, css));
}

/** Standard single-row input form that writes its values into the URL hash, so results are linkable. */
function hashForm(toolId, fields, params, submitLabel = "Run") {
  const inputs = {};
  const form = el("form", { class: "tool-form" }, fields.map((f) => {
    let input;
    if (f.type === "select") {
      input = el("select", { name: f.name }, f.options.map((o) => {
        const [v, l] = Array.isArray(o) ? o : [o, o];
        return el("option", { value: v, selected: String(v) === (params.get(f.name) ?? String(f.value ?? "")) }, l);
      }));
    } else if (f.type === "checkbox") {
      input = el("input", { type: "checkbox", name: f.name, checked: params.has(f.name) ? params.get(f.name) === "1" : !!f.value });
      inputs[f.name] = input;
      return el("label", { class: "check" }, input, f.label);
    } else {
      input = el("input", { type: "text", name: f.name, placeholder: f.placeholder || "", value: params.get(f.name) ?? f.value ?? "", required: !!f.required, spellcheck: "false" });
    }
    inputs[f.name] = input;
    return el("div", { class: f.grow ? "field grow" : "field" }, el("label", {}, f.label), input);
  }), el("button", { class: "btn", type: "submit" }, submitLabel));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const p = new URLSearchParams();
    for (const [name, input] of Object.entries(inputs)) {
      const v = input.type === "checkbox" ? (input.checked ? "1" : "0") : input.value.trim();
      if (v !== "") p.set(name, v);
    }
    const next = `#${toolId}?${p}`;
    if (location.hash === next) route(); else location.hash = next;
  });
  return form;
}

/** Big paste box + buttons, for tools that analyze pasted text. */
function pasteBox({ placeholder, onRun, runLabel = "Analyze", sample, sampleLabel = "Load sample", rows }) {
  const ta = el("textarea", { placeholder, spellcheck: "false", style: rows ? `min-height:${rows * 20}px` : null });
  const run = () => ta.value.trim() && onRun(ta.value);
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
  const buttons = [el("button", { class: "btn", type: "button", onclick: run }, runLabel)];
  if (sample) buttons.push(el("button", { class: "btn secondary", type: "button", onclick: async () => {
    ta.value = typeof sample === "function" ? await sample() : sample; run(); } }, sampleLabel));
  buttons.push(el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; ta.focus(); } }, "Clear"));
  return { element: card(null, [ta, el("div", { class: "btn-row" }, buttons, el("span", { class: "hint", style: "align-self:center" }, "Ctrl+Enter to run"))]), textarea: ta };
}

/* ------------------------------------------------------------------- icons */
const ICONS = {
  home: "M4 11l8-7 8 7v9H4zM10 20v-6h4v6",
  admin: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7zM12 9a2 2 0 100 4 2 2 0 000-4zM9 16c.5-1.5 1.6-2.2 3-2.2s2.5.7 3 2.2",
  discovery: "M12 3a9 9 0 100 18 9 9 0 000-18zM15.5 8.5l-2 5-5 2 2-5z",
  email: "M3 6h18v12H3zM3 7l9 6 9-6",
  identity: "M12 12a4 4 0 100-8 4 4 0 000 8zM4 21c0-4 3.6-6 8-6s8 2 8 6",
  m365: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  network: "M12 3v6M5 21v-4h14v4M12 9a3 3 0 100 6 3 3 0 000-6zM12 15v2",
  windows: "M3 5l8-1v8H3zM13 4l8-1v9h-8zM3 13h8v8l-8-1zM13 13h8v8l-8-1z",
  security: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7zM9 12l2 2 4-4",
};
function iconSvg(path) {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("fill", "none"); s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.8"); s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round");
  const p = document.createElementNS("http://www.w3.org/2000/svg", "path"); p.setAttribute("d", path || ""); s.append(p);
  return s;
}
const icon = (id) => iconSvg(ICONS[id]);

/* ================================================================= REGISTRY */
// Top-level menu sections, in display order. Sections with no tools are hidden.
const CATEGORIES = [
  { id: "discovery", title: "Discovery", desc: "Profile a prospect or new client from their domain name: email, identity, SaaS, infrastructure, website." },
  { id: "email", title: "Email", desc: "Mail flow, loops, bounces, authentication and deliverability." },
  { id: "identity", title: "Identity", desc: "Entra ID sign-in failures, tokens, tenants and federation." },
  { id: "m365", title: "Microsoft 365", desc: "Outlook connectivity, Autodiscover and Microsoft 365 network paths." },
  { id: "network", title: "DNS & Network", desc: "DNS, IP ownership, certificates, ports, domains and subnets." },
  { id: "windows", title: "Windows", desc: "Error codes, event logs, lockouts and crashes." },
  { id: "security", title: "Security", desc: "Suspicious links, lookalike domains and phishing triage." },
  { id: "admin", title: "Administration", desc: "Your account, users and the audit log." },
];

const TOOLS = [];
/**
 * Register a tool. Each tool file in static/tools/ calls this.
 * {category, group, id, title, desc, icon (SVG path, 24x24), render(main, params), keywords?}
 */
function registerTool(tool) {
  if (TOOLS.some((t) => t.id === tool.id)) { console.error(`Duplicate tool id ${tool.id}`); return; }
  TOOLS.push(tool);
}

/* ===================================================================== HOME */
// Words people type that don't appear in tool descriptions.
const SEARCH_SYNONYMS = {
  o365: "microsoft 365", office365: "microsoft 365", "office 365": "microsoft 365", exchange: "microsoft 365 email", outlook: "outlook autodiscover email",
  gmail: "google", "google workspace": "google", nslookup: "dns", dig: "dns", propagation: "dns", blacklisted: "blacklist", blocklisted: "blacklist",
  rbl: "blacklist", spamhaus: "blacklist", junk: "spam", spoofing: "spoof", spoofed: "spoof", phish: "phishing", bounce: "ndr", bounced: "ndr",
  undeliverable: "ndr", relay: "smtp", "open relay": "smtp", certificate: "tls certificate", cert: "certificate", ssl: "tls certificate",
  expired: "certificate registration expiry", whois: "registration", registrar: "registration", assessment: "discovery prospect audit",
  prospect: "discovery", audit: "audit", lockout: "lockout", locked: "lockout", "event id": "event", bsod: "bug check crash", crash: "crash",
  mfa: "sign-in mfa", "conditional access": "conditional access", jwt: "token", saml: "token", "hybrid join": "device join dsregcmd",
  dsregcmd: "device join", aad: "entra", "azure ad": "entra", "website down": "http", port: "port", vpn: "subnet vpn port",
  ping: "port connectivity", "not delivered": "ndr header bounce", "not arriving": "ndr header bounce", "didn't receive": "ndr header bounce",
  "missing email": "ndr header bounce", "going to spam": "header spam blacklist", "slow email": "header delay", delayed: "header delay",
  "password prompt": "autodiscover", "certificate error": "tls certificate", tls: "tls certificate", cidr: "subnet", "ip address": "ip owner",
};

/** Recognise what was typed (a code, an IP, a domain…) and offer the tool that answers it, pre-filled. */
function searchIntents(raw) {
  const q = raw.trim();
  if (!q) return [];
  const out = [];
  const add = (tool, params, label) => { if (visibleTools().some((t) => t.id === tool)) out.push({ href: "#" + tool + (params ? "?" + new URLSearchParams(params) : ""), label }); };
  let m;
  if ((m = q.match(/^(?:AADSTS)?(\d{5,7})$/i)) && /^aadsts/i.test(q)) add("aadsts", { c: "AADSTS" + m[1] }, `Decode sign-in error AADSTS${m[1]}`);
  if (/^(0x)?[0-9a-f]{8}$/i.test(q) || /^0x[0-9a-f]{1,8}$/i.test(q) || /^-\d{6,11}$/.test(q) || /^(KDC_ERR_|ERROR_|STATUS_|E_|WU_E_)/i.test(q)) add("errcode", { q }, `Look up error code ${q}`);
  if (/^\d{5,6}$/.test(q)) { add("aadsts", { c: "AADSTS" + q }, `Decode sign-in error AADSTS${q}`); add("errcode", { q }, `Look up Windows error ${q}`); }
  if (/^\d{1,4}$/.test(q)) { add("errcode", { q }, `Look up error code ${q}`); add("eventlog", null, `Analyse events (event ID ${q})`); }
  if (/^[245]\.\d{1,3}\.\d{1,3}$/.test(q)) add("ndr", null, `Decode a bounce with ${q} (paste the NDR)`);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q) || (/^[0-9a-f:]+$/i.test(q) && q.includes(":") && q.length > 2)) {
    add("ip", { t: q }, `Who owns ${q}`); add("blacklist", { t: q }, `Check ${q} on blocklists`);
  }
  const dm = q.replace(/^[a-z]+:\/\//i, "").split("/")[0].split("@").pop().toLowerCase().replace(/^www\./, "");
  if (/^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(dm) && !/^\d+(\.\d+)+$/.test(dm)) {
    add("discover", { d: dm }, `Profile ${dm} (Domain Discovery)`);
    add("domain", { d: dm }, `Check ${dm} mail health (Domain Health)`);
    add("tenant", { d: dm }, `Microsoft 365 tenant for ${dm}`);
    if (/^https?:\/\//i.test(q)) add("url", { u: q }, `Analyse this link for phishing`);
  }
  return out;
}

function renderHome(main, params) {
  main.replaceChildren(el("div", { class: "page-head" }, el("h1", {}, "MSPGather"),
    el("p", {}, "Troubleshooting tools for escalated issues. Every tool starts with a plain-language verdict, then what's wrong and how to fix it.")));
  const q = el("input", { type: "text", class: "home-search", placeholder: "Search, or paste a domain, IP, error code (0x80070005, AADSTS50126, 5.7.1)…", value: params.get("q") || "", autofocus: true, spellcheck: "false" });
  const intents = el("div", { class: "home-intents" });
  const grid = el("div");
  const draw = () => {
    const term = q.value.trim().toLowerCase();
    const found = searchIntents(q.value);
    intents.replaceChildren(...found.map((i, n) => el("a", { class: n === 0 ? "home-intent first" : "home-intent", href: i.href }, i.label, " →")));
    let expanded = term;
    for (const [k, v] of Object.entries(SEARCH_SYNONYMS)) if (term.includes(k)) expanded += " " + v;
    const words = term.split(/\s+/).filter((w) => w.length > 1);
    const hay = (t) => `${t.title} ${t.desc} ${t.keywords || ""} ${t.group} ${t.category}`.toLowerCase();
    // Every typed word must start a word in the tool's text (or come from a synonym), so "in" doesn't match "login".
    const wordMatch = (text, w) => new RegExp("(^|[^a-z0-9])" + w.replace(/[.*+?^$(){}|[\]\\]/g, "\\$&")).test(text);
    const synWords = expanded.slice(term.length).split(/\s+/).filter(Boolean);
    const match = (t) => !words.length || words.every((w) => wordMatch(hay(t), w) || synWords.some((sw) => wordMatch(hay(t), sw)));
    const tile = (t) => el("a", { class: "home-tool", href: "#" + t.id },
      el("div", { class: "home-tool-title" }, iconSvg(t.icon), t.title), el("div", { class: "home-tool-desc" }, t.desc));
    if (words.length) {
      // Rank: a hit in the title beats keywords, which beat the description.
      const all = [...words, ...synWords];
      const score = (t) => all.reduce((n, w) => n + (wordMatch(t.title.toLowerCase(), w) ? 6 : 0) + (wordMatch((t.keywords || "").toLowerCase(), w) ? 3 : 0)
        + (wordMatch(t.desc.toLowerCase(), w) ? 1 : 0), 0);
      const ranked = visibleTools().filter(match).sort((a, b) => score(b) - score(a));
      grid.replaceChildren(...(ranked.length ? [el("section", { class: "home-cat" }, el("h2", {}, "Matching tools"), el("div", { class: "home-grid" }, ranked.map(tile)))] : []));
      if (!grid.children.length && !found.length) grid.append(el("div", { class: "hint" }, "No tool matches that search. Error code? Try ",
        link("errcode", { q: q.value.trim() }, "Error Code Lookup"), ". A domain or IP? Paste it here on its own."));
      return;
    }
    grid.replaceChildren(...CATEGORIES.map((cat) => {
      const tools = visibleTools().filter((t) => t.category === cat.id && match(t));
      if (!tools.length) return null;
      return el("section", { class: "home-cat" },
        el("h2", {}, icon(cat.id), cat.title, el("span", { class: "home-cat-desc" }, cat.desc)),
        el("div", { class: "home-grid" }, tools.map((t) => el("a", { class: "home-tool", href: `#${t.id}` },
          el("div", { class: "home-tool-title" }, iconSvg(t.icon), t.title),
          el("div", { class: "home-tool-desc" }, t.desc)))));
    }).filter(Boolean));
    if (!grid.children.length && !found.length) grid.append(el("div", { class: "hint" }, "No tool matches that search. Error code? Try ",
      link("errcode", term ? { q: q.value.trim() } : {}, "Error Code Lookup"), ". A domain or IP? Paste it here on its own."));
  };
  q.addEventListener("input", draw);
  q.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const first = intents.querySelector("a") || grid.querySelector("a.home-tool");
      if (first) location.hash = first.getAttribute("href");
    }
  });
  main.append(q, intents, grid);
  draw();
}

/* ===================================================================== NAV */
// Sections start collapsed; the one you are in opens automatically, and any
// section you open yourself stays open (remembered per browser).
const NAV_KEY = "mspgather-nav-open";
function loadOpen() {
  try { return new Set(JSON.parse(localStorage.getItem(NAV_KEY) || "[]")); } catch (e) { return new Set(); }
}
function saveOpen(set) {
  try { localStorage.setItem(NAV_KEY, JSON.stringify([...set])); } catch (e) { /* storage blocked */ }
}
function setCategoryOpen(catId, open) {
  const sec = document.querySelector(`.nav-cat[data-cat="${catId}"]`);
  if (!sec) return;
  sec.querySelector(".nav-cat-btn").setAttribute("aria-expanded", String(open));
  sec.querySelector(".nav-cat-body").hidden = !open;
}

/** Tools visible to the signed-in user. adminOnly/authOnly tools are hidden otherwise; the server enforces access anyway. */
function visibleTools() {
  return TOOLS.filter((t) => (!t.authOnly || ME.auth_enabled) && (!t.adminOnly || (ME.auth_enabled && ME.role === "admin")));
}

function buildNav() {
  const nav = document.getElementById("nav");
  const opened = loadOpen();
  nav.append(el("a", { href: "#", "data-id": "home", class: "nav-home" }, icon("home"), "All tools"));
  CATEGORIES.forEach((cat) => {
    const tools = visibleTools().filter((t) => t.category === cat.id);
    if (!tools.length) return;
    const body = el("div", { class: "nav-cat-body", id: `nav-${cat.id}` });
    // Groups in order of first appearance.
    const groups = [...new Set(tools.map((t) => t.group))];
    groups.forEach((g) => {
      body.append(el("div", { class: "nav-group" }, g));
      tools.filter((t) => t.group === g).forEach((t) => body.append(el("a", { href: `#${t.id}`, "data-id": t.id }, iconSvg(t.icon), t.title)));
    });
    const btn = el("button", { type: "button", class: "nav-cat-btn", "aria-controls": `nav-${cat.id}`, "aria-expanded": "true" },
      icon(cat.id), el("span", { class: "nav-cat-title" }, cat.title), el("span", { class: "chev", "aria-hidden": "true" }, "›"));
    btn.addEventListener("click", () => {
      const open = btn.getAttribute("aria-expanded") !== "true";
      setCategoryOpen(cat.id, open);
      const set = loadOpen();
      open ? set.add(cat.id) : set.delete(cat.id);
      saveOpen(set);
    });
    nav.append(el("div", { class: "nav-cat", "data-cat": cat.id }, btn, body));
    setCategoryOpen(cat.id, opened.has(cat.id));
  });
}

// A link from outside (email, chat, another site) must not make the server scan something
// on the signed-in engineer's behalf. Navigation counts as "from the app" only right after a
// real click/keypress/submit in this page, or when returning to a history entry the app made.
let LAST_GESTURE = 0;
["click", "submit", "keydown"].forEach((t) => document.addEventListener(t, (e) => { if (e.isTrusted) LAST_GESTURE = Date.now(); }, true));

function confirmLinkRun(main, tool, params) {
  const rows = [...params.entries()].map(([k, v]) => [k, v.length > 300 ? v.slice(0, 300) + "…" : v]);
  main.append(card(null, [
    el("div", { class: "notice" }, "You opened this from a link, so it hasn't run yet. Check the input before running it: ",
      "MSPGather will look it up or connect to it from the server, as you."),
    table(["Field", "Value"], rows),
    el("div", { style: "display:flex;gap:8px;margin-top:12px" },
      el("button", { class: "btn", type: "button", onclick: () => { history.replaceState({ mspg: true }, ""); route(); } }, "Run"),
      el("button", { class: "btn secondary", type: "button", onclick: () => { location.hash = tool.id; } }, "Open the tool empty")),
  ]));
}

function route() {
  const [id, qs] = location.hash.slice(1).split("?");
  const fromApp = Date.now() - LAST_GESTURE < 2000 || (history.state && history.state.mspg);
  if (fromApp) history.replaceState({ mspg: true }, "");
  const params = new URLSearchParams(qs || "");
  const main = document.getElementById("main");
  const tool = visibleTools().find((t) => t.id === id);
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.id === (tool ? tool.id : "home")));
  document.querySelectorAll(".nav-cat").forEach((s) => s.classList.toggle("has-active", !!tool && s.dataset.cat === tool.category));
  window.scrollTo(0, 0);
  if (!tool) {
    const opened = loadOpen();
    CATEGORIES.forEach((c) => setCategoryOpen(c.id, opened.has(c.id)));
    document.title = "MSPGather";
    renderHome(main, params);
    return;
  }
  const cat = CATEGORIES.find((c) => c.id === tool.category);
  // The current section is always open; others only if the user opened them.
  const opened = loadOpen();
  CATEGORIES.forEach((c) => setCategoryOpen(c.id, c.id === tool.category || opened.has(c.id)));
  document.title = `${tool.title} · MSPGather`;
  main.replaceChildren(el("div", { class: "page-head" },
    el("div", { class: "crumb" }, cat ? cat.title : tool.category, " / ", tool.group),
    el("h1", {}, tool.title), el("p", {}, tool.desc)));
  if (!fromApp && [...params.keys()].length) { confirmLinkRun(main, tool, params); return; }
  try {
    tool.render(main, params);
  } catch (e) {
    console.error(e);
    main.append(el("div", { class: "error-box" }, `This tool failed to load: ${e.message}`));
  }
}

function initTheme() {
  const root = document.documentElement;
  let saved = null;
  try { saved = localStorage.getItem("mspgather-theme"); } catch (e) { /* storage blocked */ }
  if (saved) root.dataset.theme = saved;
  document.getElementById("theme-toggle").addEventListener("click", () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("mspgather-theme", root.dataset.theme); } catch (e) { /* ignore */ }
  });
}

// Runs after every tool script has loaded (scripts are synchronous, in order).
async function loadMe() {
  const res = await fetch("/api/auth/me", { credentials: "same-origin" });
  if (res.status === 401) { location.replace("/login"); return false; }
  ME = await res.json();
  if (ME.auth_enabled && ME.stage !== "full") { location.replace("/login"); return false; }
  const box = document.getElementById("user-box");
  if (ME.auth_enabled && box) {
    const out = el("button", { class: "icon-btn", type: "button", onclick: async () => {
      try { await api("/api/auth/logout", { body: {} }); } catch (e) { /* ignore */ }
      location.replace("/login");
    } }, "Sign out");
    box.replaceChildren(el("a", { href: "#account", class: "user-name", title: "My account" }, ME.username), out);
    box.hidden = false;
  }
  return true;
}

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  if (!(await loadMe())) return;
  buildNav();
  try {
    META = await api("/api/meta");
    document.getElementById("version").textContent = `v${META.version}`;
  } catch (e) { /* keep defaults */ }
  window.addEventListener("hashchange", route);
  route();
});
