"use strict";

/* MSPGather core: shared helpers and UI components, the tool registry, the app
   shell (top bar, workspace sidebar, command palette) and the hash router.
   Tools live in static/tools/*.js and call registerTool(). */

/* ------------------------------------------------------------------ DOM helpers */
// Everything we render can come from untrusted mail headers, DNS or websites, so
// DOM nodes are built with textContent only. Never use innerHTML with data.
function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    // URLs from data may carry a scheme: allow only web, mail, blob and image data URLs (relative paths are fine).
    else if ((k === "href" || k === "src") && unsafeUrl(v)) continue;
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

/** True for URLs with a scheme other than web, mail, blob or image data. Browsers ignore tabs,
 *  newlines and leading control characters in URLs, so those are removed before checking. */
function unsafeUrl(v) {
  const u = String(v).replace(/[\x00-\x20\x7f]/g, "");
  return /^[a-z][a-z0-9+.-]*:/i.test(u) && !/^(https?:|mailto:|blob:|data:image\/(png|gif|jpe?g|webp|svg\+xml)[;,])/i.test(u);
}

const SVG_NS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs, ...children) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null && v !== false) n.setAttribute(k, v);
  for (const c of children.flat(Infinity)) if (c) n.append(c);
  return n;
}

/* Storage can be blocked (private windows, policies): never let it break the app. */
const store = {
  get(k, session) { try { return (session ? sessionStorage : localStorage).getItem(k); } catch (e) { return null; } },
  set(k, v, session) { try { (session ? sessionStorage : localStorage).setItem(k, v); } catch (e) { /* ignore */ } },
  json(k, fallback) { try { return JSON.parse(this.get(k) || "null") ?? fallback; } catch (e) { return fallback; } },
};

/* ------------------------------------------------------------------ icons */
const ICONS = {
  home: "M4 11l8-7 8 7v9H4zM10 20v-6h4v6",
  discover: "M12 3a9 9 0 100 18 9 9 0 000-18zM15.5 8.5l-2 5-5 2 2-5z",
  harden: "M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6zM9 12l2 2 4-4",
  troubleshoot: "M21 7.5a4.5 4.5 0 01-6.2 4.2L7 19.5a1.9 1.9 0 01-2.7-2.7l7.8-7.8A4.5 4.5 0 0116.5 3L14 5.5l.5 2.5 2.5.5z",
  admin: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7zM12 9a2 2 0 100 4 2 2 0 000-4zM9 16c.5-1.5 1.6-2.2 3-2.2s2.5.7 3 2.2",
  search: "M11 4a7 7 0 100 14 7 7 0 000-14zM20 20l-3.6-3.6",
  menu: "M4 7h16M4 12h16M4 17h16",
  close: "M6 6l12 12M18 6L6 18",
  sun: "M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4",
  moon: "M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z",
  user: "M12 12a4 4 0 100-8 4 4 0 000 8zM4 21c0-4 3.6-6 8-6s8 2 8 6",
  users: "M9 11a3.5 3.5 0 100-7 3.5 3.5 0 000 7zM2.5 20c0-3.5 3-5.5 6.5-5.5s6.5 2 6.5 5.5M16 4.3a3.5 3.5 0 010 6.4M18 14.8c2 .7 3.5 2.4 3.5 5.2",
  list: "M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01",
  settings: "M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1M15 4v4M9 10v4M17 16v4",
  info: "M12 3a9 9 0 100 18 9 9 0 000-18zM12 11v5M12 8h.01",
  help: "M12 3a9 9 0 100 18 9 9 0 000-18zM9.5 9.2a2.6 2.6 0 015 .6c0 1.7-2.5 2.2-2.5 3.7M12 17h.01",
  logout: "M14 4h4a2 2 0 012 2v12a2 2 0 01-2 2h-4M10 16l-4-4 4-4M6 12h10",
  external: "M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5",
  check: "M5 12.5l4.5 4.5L19 7.5",
  x: "M7 7l10 10M17 7L7 17",
  alert: "M12 4l9 16H3zM12 10v4M12 17h.01",
  octagon: "M8 3h8l5 5v8l-5 5H8l-5-5V8zM12 8v5M12 16h.01",
  copy: "M9 9h11v11H9zM15 9V4H4v11h5",
  print: "M7 9V3h10v6M7 17H4v-7h16v7h-3M7 14h10v7H7z",
  save: "M6 3h12v18l-6-4-6 4z",
  clock: "M12 3a9 9 0 100 18 9 9 0 000-18zM12 7v5l3 2",
  globe: "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z",
  mail: "M3 6h18v12H3zM3 7l9 6 9-6",
  lock: "M6 11h12v10H6zM8.5 11V7.5a3.5 3.5 0 017 0V11",
  server: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
  cloud: "M7 18a4.5 4.5 0 01-.6-9A6 6 0 0118 8.5a4.8 4.8 0 01-.5 9.5z",
  key: "M15 3a6 6 0 11-5.3 8.8L3 18.5V21h3l.5-.5V18H9l1.5-1.5V14l.4-.4A6 6 0 1115 3zM16.5 7.5h.01",
  building: "M4 21V5l8-2v18M12 7l8 2v12M7 8h2M7 12h2M7 16h2M15 12h2M15 16h2M2 21h20",
  arrow: "M5 12h14M13 6l6 6-6 6",
  sparkle: "M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 15l.7 2.3L22 18l-2.3.7L19 21l-.7-2.3L16 18l2.3-.7z",
  flag: "M5 21V4M5 4h11l-2 4 2 4H5",
  file: "M14 3H6v18h12V7zM14 3v4h4",
  plug: "M9 3v5M15 3v5M6 8h12v3a6 6 0 01-12 0zM12 17v4",
  radar: "M12 3a9 9 0 109 9M12 7a5 5 0 105 5M12 12l6.5-6.5M12 11a1 1 0 100 2 1 1 0 000-2z",
  cpu: "M7 7h10v10H7zM10 10h4v4h-4zM9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4",
  eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 9a3 3 0 100 6 3 3 0 000-6z",
  refresh: "M20 11a8 8 0 00-14.3-4.6L4 8M4 4v4h4M4 13a8 8 0 0014.3 4.6L20 16M20 20v-4h-4",
  download: "M12 4v11M7 10l5 5 5-5M5 20h14",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
  "chev-down": "M6 9l6 6 6-6",
  "chev-right": "M9 6l6 6-6 6",
  dots: "M5 10.6a1.4 1.4 0 100 2.8 1.4 1.4 0 000-2.8zM12 10.6a1.4 1.4 0 100 2.8 1.4 1.4 0 000-2.8zM19 10.6a1.4 1.4 0 100 2.8 1.4 1.4 0 000-2.8z",
  target: "M12 3a9 9 0 100 18 9 9 0 000-18zM12 7a5 5 0 100 10 5 5 0 000-10zM12 11a1 1 0 100 2 1 1 0 000-2z",
  history: "M3 12a9 9 0 103-6.7L3 8M3 3v5h5M12 7v5l3 3",
  layers: "M12 3l9 5-9 5-9-5zM3 13l9 5 9-5",
  link: "M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1",
  phone: "M5 4h4l2 5-2.5 1.5a11 11 0 005 5L15 13l5 2v4a1 1 0 01-1 1A16 16 0 014 5a1 1 0 011-1z",
  monitor: "M3 5h18v11H3zM8 20h8M12 16v4",
  database: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  briefcase: "M4 8h16v11H4zM9 8V5h6v3M4 13h16",
  bolt: "M13 3L4 14h7l-1 7 9-11h-7z",
  certificate: "M4 4h16v12H4zM8 8h8M8 11h5M15 14a2 2 0 100 4 2 2 0 000-4zM14 17.5V21l1-.6 1 .6v-3.5",
  device: "M5 4h14v11H5zM2 19h20",
  compare: "M7 4v16M17 4v16M4 8l3-4 3 4M14 16l3 4 3-4",
  clipboard: "M9 4h6v3H9zM9 5H6v16h12V5h-3M9 12h6M9 16h4",
  email: "M3 6h18v12H3zM3 7l9 6 9-6",
  identity: "M12 12a4 4 0 100-8 4 4 0 000 8zM4 21c0-4 3.6-6 8-6s8 2 8 6",
  m365: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  network: "M12 3v6M5 21v-4h14v4M12 9a3 3 0 100 6 3 3 0 000-6zM12 15v2",
  windows: "M3 5l8-1v8H3zM13 4l8-1v9h-8zM3 13h8v8l-8-1zM13 13h8v8l-8-1z",
  security: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7zM9 12l2 2 4-4",
  inbox: "M3 13l3-8h12l3 8v6H3zM3 13h5l1 3h6l1-3h5",
  loop: "M17 2l3 3-3 3M4 11V9a4 4 0 014-4h12M7 22l-3-3 3-3M20 13v2a4 4 0 01-4 4H4",
  spam: "M4 4h16v16H4zM4 9h16M9 14l6 0",
};
function iconSvg(path) {
  const s = svgEl("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" });
  s.append(svgEl("path", { d: path || "" }));
  return s;
}
const icon = (id) => iconSvg(ICONS[id] || id);
const SEV_ICON = { critical: "octagon", warning: "alert", info: "info", ok: "check" };
const sevIcon = (sev) => icon(SEV_ICON[sev] || "info");

/* ------------------------------------------------------------------ small components */
const SEV_LABEL = { critical: "Critical", warning: "Warning", info: "Info", ok: "OK" };
const badge = (sev, text) => el("span", { class: `badge sev-${sev}` }, text || SEV_LABEL[sev] || sev);
const resultSev = (r) => ({ pass: "ok", fail: "critical", hardfail: "critical", softfail: "warning", permerror: "critical",
  temperror: "warning", neutral: "info", none: "info", bestguesspass: "ok", softpass: "warning" }[String(r).toLowerCase()] || "info");

/** A titled panel. opts: {flush, extra (node in the header), icon (icon id), id} */
function card(title, body, opts = {}) {
  return el("section", { class: "card", id: opts.id || null },
    title ? el("h2", {}, opts.icon ? icon(opts.icon) : null, title, opts.extra ? [el("span", { class: "spacer" }), opts.extra] : null) : null,
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

let TOAST_TIMER = null;
function toast(message) {
  const t = document.getElementById("toast");
  if (!t) return;
  t.textContent = message;
  t.classList.add("show");
  clearTimeout(TOAST_TIMER);
  TOAST_TIMER = setTimeout(() => t.classList.remove("show"), Math.min(9000, Math.max(1800, message.length * 55)));
}

function copyText(text, btn) {
  const done = () => {
    toast("Copied to clipboard");
    if (btn) { btn.dataset.copied = "1"; setTimeout(() => delete btn.dataset.copied, 1200); }
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, () => {});
  } else {
    const ta = el("textarea", { style: "position:fixed;opacity:0;top:0;left:0" }, text);
    document.body.append(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
    ta.remove();
  }
}

function code(text) {
  const btn = el("button", { class: "icon-btn copy", type: "button", title: "Copy" }, icon("copy"), "Copy");
  btn.addEventListener("click", () => copyText(text, btn));
  return el("div", { class: "code" }, btn, text);
}

function findingsList(list, opts = {}) {
  if (!list || !list.length) return el("div", { class: "card-body hint" }, "Nothing to report.");
  const order = { critical: 0, warning: 1, info: 2, ok: 3 };
  const items = [...list].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  return el("ul", { class: "findings" }, items.map((f) => el("li", { class: "finding", "data-sev": f.severity },
    el("span", { class: "f-icon" }, sevIcon(f.severity)),
    el("div", {},
      el("div", { class: "f-title" }, opts.area && f.area ? el("span", { class: "f-area" }, f.area) : null, el("span", {}, f.title), badge(f.severity)),
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

/** "3 days ago" style relative time for lists. */
function fmtAgo(when) {
  const t = typeof when === "number" ? when : new Date(when).getTime();
  if (!t || isNaN(t)) return "";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)} d ago`;
  return new Date(t).toISOString().slice(0, 10);
}

/** Circular score with a label in the middle (grade letter or number). */
function scoreRing(score, label, size = 96, gradeClass = "") {
  const sw = Math.max(6, Math.round(size / 12));
  const r = (size - sw) / 2, c = 2 * Math.PI * r;
  const fill = (Math.max(0, Math.min(100, score || 0)) / 100) * c;
  return el("div", { class: `ring ${gradeClass}`, style: `width:${size}px;height:${size}px` },
    svgEl("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}`, "aria-hidden": "true" },
      svgEl("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "var(--panel-3)", "stroke-width": sw }),
      svgEl("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "var(--grade, var(--accent))", "stroke-width": sw, "stroke-linecap": "round", "stroke-dasharray": `${fill} ${c}` })),
    el("div", { class: "ring-label" }, el("div", {}, el("b", { style: size < 70 ? "font-size:18px" : null }, label), size >= 70 ? el("span", {}, `${score}/100`) : null)));
}

function meter(pct, color) {
  return el("div", { class: "meter" }, el("div", { class: "meter-track" },
    el("div", { class: "meter-fill", style: `width:${Math.max(0, Math.min(100, pct))}%;${color ? `background:${color}` : ""}` })));
}

/* ------------------------------------------------------------------ API */
/** Signed-in user ({auth_enabled, username, role, csrf, ...}); set at start-up. */
let ME = { auth_enabled: false, role: "admin", csrf: null };
let META = { resolvers: ["system"], record_types: ["A"] };

async function api(path, opts = {}) {
  const method = opts.method || (opts.body ? "POST" : "GET");
  const headers = {};
  if (opts.body) headers["content-type"] = "application/json";
  if (method !== "GET" && ME.csrf) headers["x-csrf-token"] = ME.csrf;
  // Active tests need the engineer's explicit authorization confirmation (see attestBar).
  if (CURRENT_TOOL && CURRENT_TOOL.access === "active" && isAttested(CURRENT_TOOL.id)) headers["x-mspg-authorized"] = "1";
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
    const err = new Error(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || `Server returned ${res.status}`);
    err.status = res.status;
    if (res.status === 428) pulseAttest();
    throw err;
  }
  return data;
}

/** Run fn(), showing progress in target, then render the result (or the error). */
async function runInto(target, label, fn, renderFn, opts = {}) {
  target.replaceChildren(el("div", { class: "progress-card" },
    el("div", { class: "loading", style: "padding:0" }, el("div", { class: "spinner" }), label),
    opts.steps && opts.steps.length ? el("div", { class: "progress-steps" }, opts.steps.map((s) => el("span", { class: "progress-step" }, el("span", { class: "dot" }), s))) : null));
  const t0 = performance.now();
  try {
    const data = await fn();
    target.replaceChildren(renderFn(data));
    if (!opts.quiet) target.prepend(el("div", { class: "done-time" }, `Completed in ${((performance.now() - t0) / 1000).toFixed(1)}s`));
  } catch (e) {
    target.replaceChildren(el("div", { class: "error-box" }, e.message || String(e)));
  }
}

function resolverSelect(name, value) {
  return el("select", { name, id: name }, META.resolvers.map((r) => el("option", { value: r, selected: r === value }, r)));
}

/* ------------------------------------------------------- readability components */
// Every tool result reads top-down: verdict → what's wrong + how to fix → details.

/** The one-sentence answer at the top of every result. */
function verdict(sev, title, sub) {
  return el("div", { class: `verdict sev-${sev}`, role: "status" }, el("div", { class: "v-icon" }, sevIcon(sev)),
    el("div", { style: "min-width:0" }, el("div", { class: "v-title" }, title), sub ? el("div", { class: "v-sub" }, sub) : null));
}

/** Numbered fix steps. steps: [{title, detail?, commands?: [string]}] or strings. */
function nextSteps(steps, title = "What to do") {
  const items = (steps || []).filter(Boolean).map((s) => (typeof s === "string" ? { title: s } : s));
  if (!items.length) return null;
  return card(title, el("ol", { class: "steps" }, items.map((s) => el("li", {},
    el("div", { class: "step-title" }, s.title),
    s.detail ? el("div", { class: "step-detail" }, s.detail) : null,
    (s.commands || []).map((c) => code(c))))), { icon: "check" });
}

/** Key facts under a verdict: small label/value tiles. */
function facts(pairs) {
  return el("div", { class: "facts" }, pairs.filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => el("div", { class: "fact" }, el("span", { class: "fact-k", title: k }, k), el("span", { class: "fact-v" }, v))));
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
      input = el("input", { type: "text", name: f.name, placeholder: f.placeholder || "", value: params.get(f.name) ?? f.value ?? "", required: !!f.required, spellcheck: "false", autocomplete: "off" });
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

/** Big landing-page input (domain, IP…) that writes into the URL hash like hashForm. */
function heroSearch(toolId, { name = "d", placeholder = "", button = "Run", value = "", icon: ic = "search", options = [] }) {
  const input = el("input", { type: "text", name, placeholder, value, spellcheck: "false", autocomplete: "off", "aria-label": placeholder });
  const opts = options.map((o) => {
    const cb = el("input", { type: "checkbox", name: o.name, checked: !!o.checked });
    return { o, cb, label: el("label", { class: "check" }, cb, o.label) };
  });
  const form = el("form", { class: "hero-form" }, el("div", { class: "hero-input" }, icon(ic), input),
    el("button", { class: "btn lg", type: "submit" }, button, icon("arrow")));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (!v) { input.focus(); return; }
    const p = new URLSearchParams({ [name]: v });
    opts.forEach(({ o, cb }) => { if (cb.checked) p.set(o.name, "1"); });
    const next = `#${toolId}?${p}`;
    if (location.hash === next) route(); else location.hash = next;
  });
  return { form, input, options: opts.length ? el("div", { class: "hero-opts" }, opts.map((x) => x.label)) : null };
}

/** Big paste box + buttons, for tools that analyze pasted text. */
function pasteBox({ placeholder, onRun, runLabel = "Analyze", sample, sampleLabel = "Load sample", rows }) {
  const ta = el("textarea", { placeholder, spellcheck: "false", style: rows ? `min-height:${rows * 20}px` : null, "aria-label": placeholder });
  const run = () => ta.value.trim() && onRun(ta.value);
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
  const buttons = [el("button", { class: "btn", type: "button", onclick: run }, runLabel)];
  if (sample) buttons.push(el("button", { class: "btn secondary", type: "button", onclick: async () => {
    ta.value = typeof sample === "function" ? await sample() : sample; run(); } }, sampleLabel));
  buttons.push(el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; ta.focus(); } }, "Clear"));
  return { element: card(null, [ta, el("div", { class: "btn-row" }, buttons, el("span", { class: "hint" }, "Ctrl+Enter to run"))]), textarea: ta };
}

/** Landing-page card linking to a tool. */
function toolCard(t, opts = {}) {
  return el("a", { class: opts.compact ? "tool-card compact" : "tool-card", "data-mode": t.mode, href: `#${t.id}${opts.params ? "?" + new URLSearchParams(opts.params) : ""}` },
    el("div", { class: "tool-card-top" }, el("span", { class: "tool-card-icon" }, iconSvg(t.icon)), opts.compact ? null : t.title),
    opts.compact ? el("div", {}, el("b", {}, t.title), el("p", {}, opts.blurb || t.desc)) : el("p", {}, opts.blurb || t.desc),
    !opts.compact && ["active", "contacts"].includes(t.access) ? accessChip(t.access) : null);
}

/* ------------------------------------------------------------------ recents */
// Per-browser convenience only: the domains you looked at, for quick re-runs.
function recentAdd(domain, tool) {
  if (!domain) return;
  const list = store.json("mspg-recent", []).filter((r) => !(r.d === domain && r.t === tool));
  list.unshift({ d: domain, t: tool, at: Date.now() });
  store.set("mspg-recent", JSON.stringify(list.slice(0, 15)));
}
const recentList = (tool) => store.json("mspg-recent", []).filter((r) => !tool || r.t === tool);

/* ================================================================= REGISTRY */
/** Workspaces, in tab order. Each tool belongs to exactly one (see PLACEMENT). */
const MODES = [
  { id: "discover", title: "Discover", home: "discover", icon: "discover",
    tagline: "Profile prospects from public data", groups: ["Prospects", "Brand & identity"] },
  { id: "harden", title: "Harden", home: "harden", icon: "harden",
    tagline: "Fix public-facing security, record by record", groups: ["Plan", "Records & policies", "Monitor", "Verify (authorized)"] },
  { id: "troubleshoot", title: "Troubleshoot", home: "troubleshoot", icon: "troubleshoot",
    tagline: "Find the cause of an issue fast", groups: ["Start", "Email", "Identity & devices", "Microsoft 365", "Network & web", "Windows", "Security"] },
];
const ADMIN_MODE = { id: "admin", title: "Administration", home: "about", icon: "admin", tagline: "Account, team, branding and help", groups: ["Account", "Team", "Help"] };

/** What a tool touches on the network. Shown on every tool; "active" requires authorization. */
const ACCESS = {
  offline: { label: "Local analysis", icon: "cpu",
    tip: "Analyzes what you paste or type on the MSPGather server. Nothing is sent to the target." },
  passive: { label: "Public lookups", icon: "globe",
    tip: "Uses public information only: DNS, domain registries, certificate logs and similar public sources. Nothing is scanned." },
  contacts: { label: "Contacts target", icon: "plug",
    tip: "Makes ordinary client requests to the target, like a browser or Outlook would. No probing or scanning." },
  active: { label: "Active test", icon: "radar",
    tip: "Probes the target's ports or protocols. Run it only against systems you own or are authorized to test." },
};

/** Where every tool lives: id → [workspace, group, access]. Order here is sidebar order. */
const PLACEMENT = {
  discover: ["discover", "Prospects", "passive"],
  assessments: ["discover", "Prospects", "offline"],
  bulkaudit: ["discover", "Prospects", "passive"],
  lookalike: ["discover", "Brand & identity", "passive"],
  tenant: ["discover", "Brand & identity", "passive"],
  harden: ["harden", "Plan", "passive"],
  spfbuild: ["harden", "Records & policies", "passive"],
  dmarcbuild: ["harden", "Records & policies", "passive"],
  mtasts: ["harden", "Records & policies", "passive"],
  parked: ["harden", "Records & policies", "passive"],
  dmarcreport: ["harden", "Monitor", "passive"],
  tls: ["harden", "Verify (authorized)", "active"],
  ports: ["harden", "Verify (authorized)", "active"],
  troubleshoot: ["troubleshoot", "Start", "offline"],
  headers: ["troubleshoot", "Email", "passive"],
  ndr: ["troubleshoot", "Email", "passive"],
  domain: ["troubleshoot", "Email", "passive"],
  spf: ["troubleshoot", "Email", "passive"],
  blacklist: ["troubleshoot", "Email", "passive"],
  smtp: ["troubleshoot", "Email", "active"],
  aadsts: ["troubleshoot", "Identity & devices", "offline"],
  token: ["troubleshoot", "Identity & devices", "offline"],
  dsreg: ["troubleshoot", "Identity & devices", "offline"],
  idconvert: ["troubleshoot", "Identity & devices", "offline"],
  autodiscover: ["troubleshoot", "Microsoft 365", "contacts"],
  m365net: ["troubleshoot", "Microsoft 365", "offline"],
  dns: ["troubleshoot", "Network & web", "passive"],
  ip: ["troubleshoot", "Network & web", "passive"],
  http: ["troubleshoot", "Network & web", "contacts"],
  whois: ["troubleshoot", "Network & web", "passive"],
  certdecode: ["troubleshoot", "Network & web", "contacts"],
  subnet: ["troubleshoot", "Network & web", "offline"],
  errcode: ["troubleshoot", "Windows", "offline"],
  eventlog: ["troubleshoot", "Windows", "offline"],
  url: ["troubleshoot", "Security", "contacts"],
  account: ["admin", "Account", "offline"],
  users: ["admin", "Team", "offline"],
  audit: ["admin", "Team", "offline"],
  settings: ["admin", "Team", "offline"],
  about: ["admin", "Help", "offline"],
};
const LEGACY_MODE = { discovery: "discover", admin: "admin" };
const PLACEMENT_ORDER = Object.keys(PLACEMENT);

const TOOLS = [];
/**
 * Register a tool. Each tool file in static/tools/ calls this.
 * {id, title, desc, icon (24x24 SVG path), render(page, params), keywords?, mode?, group?, access?,
 *  landing? (renders its own hero instead of the standard page header), adminOnly?, authOnly?}
 * PLACEMENT above decides the workspace, group and access level for known tools.
 */
function registerTool(tool) {
  if (TOOLS.some((t) => t.id === tool.id)) { console.error(`Duplicate tool id ${tool.id}`); return; }
  const p = PLACEMENT[tool.id];
  if (p) [tool.mode, tool.group, tool.access] = p;
  tool.mode = tool.mode || LEGACY_MODE[tool.category] || "troubleshoot";
  tool.group = tool.group || "Other";
  tool.access = ACCESS[tool.access] ? tool.access : "passive";
  TOOLS.push(tool);
  TOOLS.sort((a, b) => ((PLACEMENT_ORDER.indexOf(a.id) + 1) || 999) - ((PLACEMENT_ORDER.indexOf(b.id) + 1) || 999));
}

/** Tools visible to the signed-in user. adminOnly/authOnly tools are hidden otherwise; the server enforces access anyway. */
function visibleTools() {
  return TOOLS.filter((t) => (!t.authOnly || ME.auth_enabled) && (!t.adminOnly || !ME.auth_enabled || ME.role === "admin"));
}
const toolById = (id) => visibleTools().find((t) => t.id === id);
const modeOf = (id) => MODES.find((m) => m.id === id) || ADMIN_MODE;

function accessChip(access) {
  const a = ACCESS[access] || ACCESS.passive;
  return el("span", { class: `access a-${access}`, title: a.tip }, icon(a.icon), a.label);
}

/* ================================================================= SEARCH */
// Words people type that don't appear in tool descriptions.
const SEARCH_SYNONYMS = {
  o365: "microsoft 365", office365: "microsoft 365", "office 365": "microsoft 365", exchange: "microsoft 365 email", outlook: "outlook autodiscover email",
  gmail: "google", "google workspace": "google", nslookup: "dns", dig: "dns", propagation: "dns", blacklisted: "blacklist", blocklisted: "blacklist",
  rbl: "blacklist", spamhaus: "blacklist", junk: "spam", spoofing: "spoof", spoofed: "spoof", phish: "phishing", bounce: "ndr", bounced: "ndr",
  undeliverable: "ndr", relay: "smtp", "open relay": "smtp", certificate: "tls certificate", cert: "certificate", ssl: "tls certificate",
  expired: "certificate registration expiry", whois: "registration", registrar: "registration", assessment: "discovery prospect audit",
  prospect: "discovery", lead: "discovery prospect", sales: "discovery prospect", presales: "discovery prospect", onboarding: "discovery hardening",
  audit: "audit", lockout: "lockout", locked: "lockout", "event id": "event", bsod: "bug check crash", crash: "crash",
  mfa: "sign-in mfa", "conditional access": "conditional access", jwt: "token", saml: "token", "hybrid join": "device join dsregcmd",
  dsregcmd: "device join", aad: "entra", "azure ad": "entra", "website down": "http", port: "port", vpn: "subnet vpn port",
  ping: "port connectivity", "not delivered": "ndr header bounce", "not arriving": "ndr header bounce", "didn't receive": "ndr header bounce",
  "missing email": "ndr header bounce", "going to spam": "header spam blacklist", "slow email": "header delay", delayed: "header delay",
  "password prompt": "autodiscover", "certificate error": "tls certificate", tls: "tls certificate", cidr: "subnet", "ip address": "ip owner",
  harden: "hardening", secure: "hardening", "mta-sts": "mta-sts", parked: "parked lockdown", typosquat: "lookalike", "dkim": "dkim hardening",
};

/** Recognise what was typed (a code, an IP, a domain…) and offer the tool that answers it, pre-filled. */
function searchIntents(raw) {
  const q = raw.trim();
  if (!q || q.length > 300) return [];
  const out = [];
  const add = (tool, params, label, sub) => {
    const t = toolById(tool);
    if (t) out.push({ href: "#" + tool + (params ? "?" + new URLSearchParams(params) : ""), label, sub: sub || t.title, icon: t.icon, mode: t.mode });
  };
  let m;
  if ((m = q.match(/^(?:AADSTS)?(\d{5,7})$/i)) && /^aadsts/i.test(q)) add("aadsts", { c: "AADSTS" + m[1] }, `Decode sign-in error AADSTS${m[1]}`);
  if (/^(0x)?[0-9a-f]{8}$/i.test(q) || /^0x[0-9a-f]{1,8}$/i.test(q) || /^-\d{6,11}$/.test(q) || /^(KDC_ERR_|ERROR_|STATUS_|E_|WU_E_)/i.test(q)) add("errcode", { q }, `Look up error code ${q}`);
  if (/^\d{5,6}$/.test(q)) { add("aadsts", { c: "AADSTS" + q }, `Decode sign-in error AADSTS${q}`); add("errcode", { q }, `Look up Windows error ${q}`); }
  if (/^\d{1,4}$/.test(q)) { add("errcode", { q }, `Look up error code ${q}`); add("eventlog", null, `Analyse events (event ID ${q})`); }
  if (/^[245]\.\d{1,3}\.\d{1,3}$/.test(q)) add("ndr", null, `Decode a bounce with ${q}`, "Paste the bounce message into the NDR Decoder");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q) || (/^[0-9a-f:]+$/i.test(q) && q.includes(":") && q.length > 2)) {
    add("ip", { t: q }, `Who owns ${q}`); add("blacklist", { t: q }, `Check ${q} on blocklists`);
  }
  if (/^https?:\/\/\S+$/i.test(q)) add("url", { u: q }, "Analyse this link for phishing");
  const dm = q.replace(/^[a-z]+:\/\//i, "").split("/")[0].split("@").pop().toLowerCase().replace(/^www\./, "");
  if (!/\s/.test(q) && /^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(dm) && !/^\d+(\.\d+)+$/.test(dm)) {
    add("discover", { d: dm }, `Profile ${dm}`, "Prospect Discovery: stack, posture and talking points");
    add("harden", { d: dm }, `Hardening plan for ${dm}`, "What to fix, record by record");
    add("domain", { d: dm }, `Email health of ${dm}`, "Domain Health: MX, SPF, DKIM, DMARC");
    add("tenant", { d: dm }, `Microsoft 365 tenant for ${dm}`);
    add("lookalike", { d: dm }, `Lookalike domains of ${dm}`);
  }
  return out;
}

/** Tools matching free text, best first. */
function searchTools(raw) {
  const term = raw.trim().toLowerCase();
  if (!term) return [];
  let expanded = term;
  for (const [k, v] of Object.entries(SEARCH_SYNONYMS)) if (term.includes(k)) expanded += " " + v;
  const words = term.split(/\s+/).filter((w) => w.length > 1);
  const synWords = expanded.slice(term.length).split(/\s+/).filter(Boolean);
  const hay = (t) => `${t.title} ${t.desc} ${t.keywords || ""} ${t.group} ${modeOf(t.mode).title}`.toLowerCase();
  // Every typed word must start a word in the tool's text (or come from a synonym), so "in" doesn't match "login".
  const wordMatch = (text, w) => new RegExp("(^|[^a-z0-9])" + w.replace(/[.*+?^$(){}|[\]\\]/g, "\\$&")).test(text);
  const match = (t) => words.length && words.every((w) => wordMatch(hay(t), w) || synWords.some((sw) => wordMatch(hay(t), sw)));
  const all = [...words, ...synWords];
  const score = (t) => all.reduce((n, w) => n + (wordMatch(t.title.toLowerCase(), w) ? 6 : 0) + (wordMatch((t.keywords || "").toLowerCase(), w) ? 3 : 0)
    + (wordMatch(t.desc.toLowerCase(), w) ? 1 : 0), 0);
  return visibleTools().filter(match).sort((a, b) => score(b) - score(a));
}

/* ================================================================= SHELL */
let CURRENT_TOOL = null;
let SIDEBAR_MODE = null;
let HANDOFF = null;   // {tool, text}: pasted content handed to a tool by the triage page or palette
let RETRY_ON_ATTEST = false;

function buildTopbar() {
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  const bar = document.getElementById("topbar");
  bar.replaceChildren(
    el("button", { class: "icon-btn menu-btn", type: "button", "aria-label": "Open tool menu", onclick: () => toggleNav() }, icon("menu")),
    el("a", { class: "brand", href: "#discover", "aria-label": "MSPGather home" }, el("img", { src: "logo.svg", alt: "", width: 30, height: 30 }),
      el("span", {}, "MSPGather", el("small", {}, "Discover · Harden · Troubleshoot"))),
    el("nav", { class: "modes", "aria-label": "Workspaces" }, MODES.map((m) =>
      el("a", { class: "mode-tab", href: `#${m.home}`, "data-mode": m.id, title: m.tagline, "aria-label": m.title }, icon(m.icon), el("span", {}, m.title)))),
    el("button", { class: "search-btn", type: "button", onclick: () => openPalette(), "aria-label": "Search tools (Ctrl+K)" },
      icon("search"), el("span", {}, "Search, or paste a domain, IP or error code"), el("kbd", {}, isMac ? "⌘K" : "Ctrl K")),
    el("div", { class: "top-actions" },
      el("button", { class: "icon-btn", type: "button", id: "theme-toggle", title: "Switch light / dark theme", "aria-label": "Switch light or dark theme", onclick: toggleTheme },
        el("span", { class: "theme-dark-icon" }, icon("moon")), el("span", { class: "theme-light-icon" }, icon("sun"))),
      el("div", { class: "user-menu", id: "user-menu" })));
}

function buildUserMenu() {
  const wrap = document.getElementById("user-menu");
  const menu = el("div", { class: "menu", role: "menu", hidden: true });
  const item = (href, ic, text) => el("a", { href, role: "menuitem" }, icon(ic), text);
  if (ME.auth_enabled) {
    menu.append(el("div", { class: "menu-head" }, el("b", {}, ME.username), el("span", { class: "sub" }, ME.role === "admin" ? "Administrator" : "Engineer")),
      item("#account", "user", "My account"));
    if (ME.role === "admin") menu.append(item("#users", "users", "Users"), item("#audit", "list", "Audit log"));
  }
  if (toolById("settings")) menu.append(item("#settings", "settings", "Report branding"));
  menu.append(item("#about", "info", "About & responsible use"));
  if (ME.auth_enabled) {
    menu.append(el("div", { class: "menu-sep" }), el("button", { type: "button", role: "menuitem", onclick: async () => {
      try { await api("/api/auth/logout", { body: {} }); } catch (e) { /* ignore */ }
      location.replace("/login");
    } }, icon("logout"), "Sign out"));
  }
  const btn = ME.auth_enabled
    ? el("button", { class: "avatar-btn", type: "button", "aria-haspopup": "menu", "aria-expanded": "false", "aria-label": `Account menu for ${ME.username}` },
      el("span", { class: "avatar", "aria-hidden": "true" }, (ME.username || "?").slice(0, 1)), el("span", { class: "avatar-name" }, ME.username), icon("chev-down"))
    : el("button", { class: "icon-btn", type: "button", "aria-haspopup": "menu", "aria-expanded": "false", "aria-label": "Menu", title: "Menu" }, icon("dots"));
  const close = () => { menu.hidden = true; btn.setAttribute("aria-expanded", "false"); };
  btn.addEventListener("click", (e) => { e.stopPropagation(); const open = menu.hidden; menu.hidden = !open; btn.setAttribute("aria-expanded", String(open)); });
  document.addEventListener("click", (e) => { if (!wrap.contains(e.target)) close(); });
  menu.addEventListener("click", (e) => { if (e.target.closest("a")) close(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  wrap.replaceChildren(btn, menu);
}

function buildSidebar(modeId) {
  const mode = modeOf(modeId);
  const tools = visibleTools().filter((t) => t.mode === mode.id);
  const groups = [...new Set([...mode.groups, ...tools.map((t) => t.group)])].filter((g) => tools.some((t) => t.group === g));
  const nav = el("nav", { class: "nav", "aria-label": `${mode.title} tools` });
  groups.forEach((g) => {
    nav.append(el("div", { class: "nav-group" }, g));
    tools.filter((t) => t.group === g).forEach((t) => nav.append(el("a", { href: `#${t.id}`, "data-id": t.id, title: t.title },
      iconSvg(t.icon), el("span", {}, t.navTitle || t.title),
      t.access === "active" ? el("span", { class: "nav-flag", title: ACCESS.active.tip }, "Active") : null)));
  });
  document.getElementById("sidebar").replaceChildren(
    el("div", { class: "side-head" }, el("div", { class: "side-head-icon" }, icon(mode.icon)),
      el("div", {}, el("div", { class: "side-title" }, mode.title), el("div", { class: "side-tag" }, mode.tagline))),
    nav,
    el("div", { class: "side-foot" }, el("a", { href: "#about" }, icon("info"), "Responsible use & data sources"),
      el("span", {}, META.version ? `MSPGather v${META.version}` : "MSPGather")));
  SIDEBAR_MODE = mode.id;
}

function toggleNav(open) {
  const on = open ?? !document.body.classList.contains("nav-open");
  document.body.classList.toggle("nav-open", on);
  document.getElementById("backdrop").hidden = !on;
}

function pageHead(tool) {
  const mode = modeOf(tool.mode);
  return el("div", { class: "page-head" }, el("div", { class: "page-icon" }, iconSvg(tool.icon)),
    el("div", { style: "min-width:0" },
      el("div", { class: "crumb" }, el("a", { href: `#${mode.home}` }, mode.title), el("span", { "aria-hidden": "true" }, "/"), el("span", {}, tool.group)),
      el("h1", {}, tool.title, tool.mode === "admin" ? null : accessChip(tool.access)),
      tool.desc ? el("p", {}, tool.desc) : null));
}

/* ------------------------------------------------------------------ active-test authorization */
const isAttested = (id) => store.get(`mspg-auth:${id}`, true) === "1";

function attestBar(tool) {
  const ok = isAttested(tool.id);
  const box = el("input", { type: "checkbox", checked: ok, "aria-label": "I own, or am authorized to test, the systems I enter here" });
  const bar = el("div", { class: ok ? "attest ok" : "attest", id: "attest" }, icon(ok ? "lock" : "radar"),
    el("div", {},
      el("div", { class: "attest-title" }, "Active test: run it only on systems you're authorized to test"),
      el("p", {}, "This tool connects to the target and probes it (open ports, TLS protocol support or a live SMTP session). Probing systems without permission can breach computer-misuse laws and your internet provider's acceptable-use policy. Use it for your own or your clients' systems, with their permission. Each run is recorded in the audit log."),
      el("label", {}, box, "I own, or am authorized to test, the systems I enter here (remembered until this tab closes)")));
  box.addEventListener("change", () => {
    store.set(`mspg-auth:${tool.id}`, box.checked ? "1" : "", true);
    bar.classList.toggle("ok", box.checked);
    bar.firstChild.replaceWith(icon(box.checked ? "lock" : "radar"));
    if (box.checked && RETRY_ON_ATTEST) { RETRY_ON_ATTEST = false; history.replaceState({ mspg: true }, ""); route(); }
  });
  return bar;
}

function pulseAttest() {
  const bar = document.getElementById("attest");
  if (!bar) return;
  RETRY_ON_ATTEST = true;
  bar.classList.remove("pulse"); void bar.offsetWidth; bar.classList.add("pulse");
  bar.scrollIntoView({ behavior: "smooth", block: "center" });
}

/* ------------------------------------------------------------------ router */
// A link from outside (email, chat, another site) must not make the server look something
// up or connect somewhere on the signed-in engineer's behalf. Navigation counts as "from the
// app" only right after a real click/keypress/submit in this page, or when returning to a
// history entry the app made.
let LAST_GESTURE = 0;
["click", "submit", "keydown"].forEach((t) => document.addEventListener(t, (e) => { if (e.isTrusted) LAST_GESTURE = Date.now(); }, true));

function confirmLinkRun(page, tool, params) {
  const rows = [...params.entries()].map(([k, v]) => [k, v.length > 300 ? v.slice(0, 300) + "…" : v]);
  page.append(card("Opened from a link", [
    el("p", { style: "margin:0 0 12px" }, "This hasn't run yet. Check the input first: MSPGather will look it up",
      tool.access === "active" || tool.access === "contacts" ? " or connect to it" : "", " from the server, as you."),
    table(["Field", "Value"], rows),
    el("div", { class: "btn-row" },
      el("button", { class: "btn", type: "button", onclick: () => { history.replaceState({ mspg: true }, ""); route(); } }, "Run it"),
      el("button", { class: "btn secondary", type: "button", onclick: () => { location.hash = tool.id; } }, "Open the tool empty")),
  ], { icon: "link" }));
}

/** Put pasted text into the tool's first text box and run it (used by the triage page and palette). */
function applyHandoff(page, text) {
  const ta = page.querySelector("textarea");
  if (!ta) return;
  ta.value = text;
  ta.dispatchEvent(new Event("input", { bubbles: true }));
  const btn = [...page.querySelectorAll("button.btn")].find((b) => !b.classList.contains("secondary")
    && (ta.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING));
  if (btn) btn.click();
}

function handOff(toolId, text) {
  HANDOFF = { tool: toolId, text };
  if (location.hash.slice(1).split("?")[0] === toolId) route(); else location.hash = toolId;
}

function notFound(page, id) {
  page.append(el("div", { class: "empty", style: "margin-top:40px" }, icon("help"),
    el("div", { style: "font-weight:650;color:var(--text)" }, `There's no page called "${id}".`),
    el("div", {}, "It may be for administrators only, or the link is out of date. ", link("discover", {}, "Go to Discover"), " or press Ctrl+K to search.")));
}

function route() {
  const [rawId, qs] = location.hash.slice(1).split("?");
  const id = decodeURIComponent(rawId || "") || "discover";
  const fromApp = Date.now() - LAST_GESTURE < 2000 || (history.state && history.state.mspg);
  if (fromApp) history.replaceState({ mspg: true }, "");
  const params = new URLSearchParams(qs || "");
  const main = document.getElementById("main");
  const tool = toolById(id);
  const mode = tool ? tool.mode : "discover";
  toggleNav(false);
  closePalette();
  CURRENT_TOOL = tool || null;
  RETRY_ON_ATTEST = false;
  document.body.dataset.mode = mode;
  if (SIDEBAR_MODE !== mode) buildSidebar(mode);
  document.querySelectorAll(".mode-tab").forEach((a) => (a.dataset.mode === mode ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  document.querySelectorAll("#sidebar .nav a").forEach((a) => (tool && a.dataset.id === tool.id ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  const page = el("div", { class: "page" });
  main.replaceChildren(page);
  window.scrollTo(0, 0);
  if (!tool) { document.title = "Not found · MSPGather"; notFound(page, id); return; }
  document.title = `${params.get("d") || params.get("t") ? (params.get("d") || params.get("t")) + " · " : ""}${tool.title} · MSPGather`;
  const hasParams = [...params.keys()].length > 0;
  if (!tool.landing) page.append(pageHead(tool));  // landing pages draw their own header
  if (tool.access === "active") page.append(attestBar(tool));
  if (!fromApp && hasParams) { confirmLinkRun(page, tool, params); return; }
  try {
    tool.render(page, params);
  } catch (e) {
    console.error(e);
    page.append(el("div", { class: "error-box" }, `This tool failed to load: ${e.message}`));
  }
  if (HANDOFF && HANDOFF.tool === tool.id) {
    const h = HANDOFF; HANDOFF = null;
    setTimeout(() => applyHandoff(page, h.text), 0);
  }
}

/* ------------------------------------------------------------------ command palette */
let PALETTE = null;
function buildPalette() {
  const box = document.getElementById("palette");
  const input = el("input", { type: "text", placeholder: "Search tools, or paste a domain, IP, URL or error code…", spellcheck: "false", autocomplete: "off", "aria-label": "Search" });
  const list = el("div", { class: "palette-list", role: "listbox" });
  box.replaceChildren(el("div", { class: "palette-box", role: "dialog", "aria-modal": "true", "aria-label": "Search" },
    el("div", { class: "palette-input" }, icon("search"), input, el("kbd", {}, "Esc")), list,
    el("div", { class: "palette-foot" }, el("span", {}, el("kbd", {}, "↑"), " ", el("kbd", {}, "↓"), " move"), el("span", {}, el("kbd", {}, "Enter"), " open"),
      el("span", {}, "Paste a whole header, bounce or log on the ", link("troubleshoot", {}, "Troubleshoot"), " page"))));
  let items = [], sel = 0;
  const go = (it) => { if (!it) return; closePalette(); if (location.hash === it.href) route(); else location.hash = it.href; };
  const draw = () => {
    const q = input.value;
    const sections = [];
    const intents = searchIntents(q);
    if (intents.length) sections.push(["Do this", intents]);
    if (q.trim()) {
      const tools = searchTools(q).slice(0, 12).map((t) => ({ href: `#${t.id}`, label: t.title, sub: t.desc, icon: t.icon, mode: t.mode }));
      if (tools.length) sections.push(["Tools", tools]);
    } else {
      const rec = recentList().slice(0, 5).map((r) => {
        const t = toolById(r.t);
        return t ? { href: `#${r.t}?${new URLSearchParams({ d: r.d })}`, label: r.d, sub: `${t.title} · ${fmtAgo(r.at)}`, icon: "history", mode: t.mode } : null;
      }).filter(Boolean);
      if (rec.length) sections.push(["Recent", rec]);
      sections.push(["Workspaces", MODES.map((m) => ({ href: `#${m.home}`, label: m.title, sub: m.tagline, icon: ICONS[m.icon], mode: m.id }))]);
      sections.push(["All tools", visibleTools().filter((t) => t.mode !== "admin" && !t.landing).map((t) => ({ href: `#${t.id}`, label: t.title, sub: t.desc, icon: t.icon, mode: t.mode }))]);
    }
    items = sections.flatMap(([, xs]) => xs);
    sel = Math.min(sel, Math.max(0, items.length - 1));
    let n = 0;
    list.replaceChildren(...(items.length ? sections.flatMap(([title, xs]) => [el("div", { class: "palette-section" }, title),
      ...xs.map((it) => {
        const idx = n++;
        const row = el("a", { class: "palette-item", href: it.href, role: "option", "aria-selected": String(idx === sel), "data-idx": idx },
          el("span", { class: "pi-icon" }, iconSvg(ICONS[it.icon] || it.icon)),
          el("span", { class: "pi-main" }, el("div", { class: "pi-title" }, it.label), it.sub ? el("div", { class: "pi-sub" }, it.sub) : null),
          it.mode && it.mode !== "admin" ? el("span", { class: "pi-mode" }, modeOf(it.mode).title) : null);
        row.addEventListener("click", (e) => { e.preventDefault(); go(it); });
        row.addEventListener("mousemove", () => { if (sel !== idx) { sel = idx; mark(); } });
        return row;
      })]) : [el("div", { class: "palette-empty" }, "No match. A long paste (headers, a bounce, a log)? Use the ", link("troubleshoot", {}, "Troubleshoot"), " page.")]));
  };
  const mark = () => list.querySelectorAll(".palette-item").forEach((r) => {
    const on = Number(r.dataset.idx) === sel;
    r.setAttribute("aria-selected", String(on));
    if (on) r.scrollIntoView({ block: "nearest" });
  });
  input.addEventListener("input", () => { sel = 0; draw(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); mark(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); mark(); }
    else if (e.key === "Enter") { e.preventDefault(); go(items[sel]); }
    else if (e.key === "Escape") { e.preventDefault(); closePalette(); }
  });
  box.addEventListener("mousedown", (e) => { if (e.target === box) closePalette(); });
  PALETTE = { box, input, draw };
}
function openPalette(initial = "") {
  if (!PALETTE) return;
  PALETTE.box.hidden = false;
  PALETTE.input.value = initial;
  PALETTE.draw();
  setTimeout(() => PALETTE.input.focus(), 0);
}
function closePalette() { if (PALETTE) PALETTE.box.hidden = true; }

/* ------------------------------------------------------------------ theme + start-up */
function initTheme() {
  const saved = store.get("mspgather-theme");
  if (saved) document.documentElement.dataset.theme = saved;
}
function toggleTheme() {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  store.set("mspgather-theme", root.dataset.theme);
}

// Runs after every tool script has loaded (scripts are synchronous, in order).
async function loadMe() {
  const res = await fetch("/api/auth/me", { credentials: "same-origin" });
  if (res.status === 401) { location.replace("/login"); return false; }
  ME = await res.json();
  if (ME.auth_enabled && ME.stage !== "full") { location.replace("/login"); return false; }
  return true;
}

initTheme();
document.addEventListener("DOMContentLoaded", async () => {
  if (!(await loadMe())) return;
  try { META = await api("/api/meta"); } catch (e) { /* keep defaults */ }
  buildTopbar();
  buildUserMenu();
  buildPalette();
  document.getElementById("skip-link").addEventListener("click", (e) => { e.preventDefault(); document.getElementById("main").focus(); });
  document.getElementById("backdrop").addEventListener("click", () => toggleNav(false));
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "") || document.activeElement?.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); PALETTE.box.hidden ? openPalette() : closePalette(); }
    else if (e.key === "/" && !typing && PALETTE.box.hidden) { e.preventDefault(); openPalette(); }
  });
  window.addEventListener("hashchange", route);
  route();
});
