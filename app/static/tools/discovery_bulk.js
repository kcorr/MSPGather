"use strict";
/* Bulk Domain Audit: email-security basics for a whole client list in one table. */

addStyles(`
.bulkaudit-progress { height: 8px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border); overflow: hidden; margin: 6px 0 4px; }
.bulkaudit-progress > span { display: block; height: 100%; background: var(--accent); transition: width .3s; }
.bulkaudit-status { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; font-size: 13px; color: var(--muted); margin-bottom: 14px; }
.bulkaudit-toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; padding: 10px 16px; border-bottom: 1px solid var(--border); }
.bulkaudit-toolbar input[type=text] { flex: 1 1 220px; }
.bulkaudit-table th { cursor: pointer; user-select: none; white-space: nowrap; }
.bulkaudit-table th[aria-sort=ascending]::after { content: " ▲"; font-size: 10px; }
.bulkaudit-table th[aria-sort=descending]::after { content: " ▼"; font-size: 10px; }
.bulkaudit-table td { vertical-align: top; }
.bulkaudit-table td.bulkaudit-crit { background: var(--crit-soft); color: var(--crit); font-weight: 600; }
.bulkaudit-table td.bulkaudit-warn { background: var(--warn-soft); color: var(--warn); font-weight: 600; }
.bulkaudit-table td .sub { font-weight: 400; }
.bulkaudit-links { font-size: 12px; }
.bulkaudit-grade { display: inline-grid; place-items: center; width: 26px; height: 26px; border-radius: 7px; color: #fff; font-weight: 800; margin-right: 6px; }
.bulkaudit-grade-A, .bulkaudit-grade-B { background: var(--ok); }
.bulkaudit-grade-C { background: var(--warn); }
.bulkaudit-grade-D, .bulkaudit-grade-F { background: var(--crit); }
`);

const BULKAUDIT_MAX = 50;
const BULKAUDIT_PARALLEL = 2; // batches in flight at once
const BULKAUDIT_DMARC_RANK = { reject: 3, quarantine: 2, none: 1 };
const BULKAUDIT_SEV_RANK = { critical: 2, warning: 1 };

function renderBulkauditTool(main, params) {
  const preset = (params.get("d") || "").split(",").map((s) => s.trim()).filter(Boolean);
  const ta = el("textarea", { placeholder: "One domain per line, or comma separated (up to 50). Email addresses and URLs are fine: admin@contoso.com, https://www.fabrikam.com", spellcheck: "false", style: "min-height:160px" }, preset.join("\n"));
  const out = el("div");
  const run = () => {
    const list = ta.value.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
    if (!list.length) return;
    const next = `#bulkaudit?${new URLSearchParams({ d: list.join(",") })}`;
    if (location.hash === next) route(); else location.hash = next;
  };
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
  main.append(card(null, [ta, el("div", { class: "btn-row" },
    el("button", { class: "btn", type: "button", onclick: run }, "Audit domains"),
    el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; ta.focus(); } }, "Clear"),
    el("span", { class: "hint", style: "align-self:center" }, "Ctrl+Enter to run · about 2–6 s per batch of 6 domains"))]), out);
  if (preset.length) bulkauditRun(out, preset.join("\n"));
}

async function bulkauditRun(out, text) {
  out.replaceChildren(el("div", { class: "loading" }, el("div", { class: "spinner" }), "Checking the list…"));
  let norm;
  try {
    norm = await api("/api/bulk/normalize", { body: { text } });
  } catch (e) {
    out.replaceChildren(el("div", { class: "error-box" }, e.message || String(e)));
    return;
  }
  const state = { rows: [], invalid: norm.invalid, order: new Map(norm.domains.map((d, i) => [d.domain, i])),
    total: norm.domains.length, done: 0, stopped: false, sort: { key: null, dir: 1 }, filter: "", show: "all", t0: performance.now(), batchTimes: [] };
  const bar = el("span", { style: "width:0%" });
  const statusText = el("span", {});
  const stopBtn = el("button", { class: "btn secondary", type: "button", onclick: () => { state.stopped = true; stopBtn.disabled = true; statusText.textContent += " · stopping after the current batch…"; } }, "Stop");
  const progress = el("div", {}, el("div", { class: "bulkaudit-progress" }, bar), el("div", { class: "bulkaudit-status" }, statusText, stopBtn));
  const notes = [];
  if (norm.duplicates) notes.push(`${norm.duplicates} duplicate${norm.duplicates === 1 ? "" : "s"} removed`);
  if (norm.truncated) notes.push(`${norm.truncated} domain(s) over the ${norm.max}-domain limit skipped`);
  if (norm.invalid.length) notes.push(`${norm.invalid.length} invalid entr${norm.invalid.length === 1 ? "y" : "ies"} skipped: ${norm.invalid.map((x) => x.input).join(", ")}`);
  const result = el("div");
  out.replaceChildren(progress, notes.length ? el("div", { class: "notice" }, notes.join(" · ")) : "", result);

  const domains = norm.domains.map((d) => d.domain);
  const size = Math.max(5, Math.min(8, norm.batch_size || 6));
  const batches = [];
  for (let i = 0; i < domains.length; i += size) batches.push(domains.slice(i, i + size));
  const paint = () => {
    bar.style.width = `${state.total ? Math.round((100 * state.done) / state.total) : 100}%`;
    const avg = state.batchTimes.length ? state.batchTimes.reduce((a, b) => a + b, 0) / state.batchTimes.length : null;
    statusText.textContent = `Audited ${state.done} of ${state.total} domain${state.total === 1 ? "" : "s"}` +
      (avg != null ? ` · ${(avg / 1000).toFixed(1)} s per batch` : "") + ` · ${((performance.now() - state.t0) / 1000).toFixed(0)} s elapsed`;
    // Keep the cursor in the filter box when a batch lands while someone is typing.
    const focused = document.activeElement && document.activeElement.dataset && document.activeElement.dataset.bulkauditFilter != null;
    const caret = focused ? document.activeElement.selectionStart : null;
    result.replaceChildren(bulkauditResult(state));
    if (focused) { const f = result.querySelector("[data-bulkaudit-filter]"); if (f) { f.focus(); f.setSelectionRange(caret, caret); } }
  };
  paint();
  let next = 0;
  const worker = async () => {
    while (next < batches.length && !state.stopped && out.isConnected) {
      const batch = batches[next++];
      const t = performance.now();
      try {
        const r = await api("/api/bulk/audit", { body: { domains: batch } });
        state.rows.push(...r.rows);
      } catch (e) {
        batch.forEach((d) => state.rows.push({ domain: d, error: e.message || String(e), problems: [{ col: "domain", severity: "warning", text: "Audit request failed" }] }));
      }
      state.batchTimes.push(performance.now() - t);
      state.done += batch.length;
      if (out.isConnected) paint();
    }
  };
  await Promise.all(Array.from({ length: Math.min(BULKAUDIT_PARALLEL, batches.length) }, worker));
  stopBtn.remove();
  if (state.stopped) statusText.textContent += ` · stopped (${state.total - state.done} not audited)`;
  else statusText.textContent = `Audited ${state.done} domain${state.done === 1 ? "" : "s"} in ${((performance.now() - state.t0) / 1000).toFixed(1)} s`;
  bar.style.width = "100%";
}

/* ----------------------------------------------------------------- columns */
function bulkauditSpfText(r) {
  const s = r.spf;
  if (!s) return "—";
  if (!s.record) return "none";
  return `${s.lookups}/10 ${s.valid ? "valid" : "broken"}`;
}
function bulkauditDmarcText(r) {
  const d = r.dmarc;
  if (!d) return "—";
  if (!d.record) return "missing";
  let t = d.policy ? `p=${d.policy}` : "invalid";
  if (d.pct && d.pct !== "100") t += ` pct=${d.pct}`;
  if (d.t === "y") t += " t=y";
  if (d.inherited) t += " (inherited)";
  return t;
}
function bulkauditSigninText(r) {
  const s = r.signin;
  if (!s) return "—";
  if (s.error && !s.namespace) return "lookup failed";
  if (s.namespace === "Managed") return "Managed (cloud)";
  if (s.namespace === "Federated") {
    let host = "";
    try { host = s.auth_url ? new URL(s.auth_url).hostname : ""; } catch (e) { host = ""; }
    return `Federated${host ? ` (${host})` : s.brand ? ` (${s.brand})` : ""}`;
  }
  if (s.namespace === "Unknown") return "No Entra tenant";
  return s.namespace || "—";
}
function bulkauditMailText(r) {
  const m = r.mail;
  if (!m || !m.host) return "—";
  return m.gateways && m.gateways.length ? `${m.host} via ${m.gateways.join(", ")}` : m.host;
}

const BULKAUDIT_COLS = [
  { key: "domain", label: "Domain", text: (r) => r.domain, sort: (r) => r.domain,
    cell: (r) => el("div", {}, el("strong", { class: "mono" }, r.domain),
      r.invalid ? null : el("div", { class: "bulkaudit-links" }, link("discover", { d: r.domain }, "Discover"), " · ", link("domain", { d: r.domain }, "Domain health")),
      r.exists === false ? el("div", { class: "sub" }, "does not exist in DNS") : null,
      r.error ? el("div", { class: "sub" }, r.error) : null) },
  { key: "mail", label: "Mail platform / gateway", text: bulkauditMailText, sort: bulkauditMailText,
    cell: (r) => el("div", {}, r.mail && r.mail.host ? r.mail.host : "—",
      r.mail && r.mail.gateways && r.mail.gateways.length ? el("div", { class: "sub" }, `via ${r.mail.gateways.join(", ")}`) : null) },
  { key: "spf", label: "SPF", text: bulkauditSpfText, sort: (r) => (!r.spf ? -2 : !r.spf.record ? -1 : r.spf.valid ? r.spf.lookups : 100 + r.spf.lookups),
    cell: (r) => el("div", {}, bulkauditSpfText(r), r.spf && r.spf.broken ? el("div", { class: "sub" }, r.spf.broken) : null) },
  { key: "dmarc", label: "DMARC", text: bulkauditDmarcText, sort: (r) => (r.dmarc ? (BULKAUDIT_DMARC_RANK[r.dmarc.policy] || 0) : -1) },
  { key: "dkim", label: "DKIM", text: (r) => (!r.dkim ? "—" : r.dkim.selectors.length ? `${r.dkim.selectors.length} found` : "none found"),
    sort: (r) => (r.dkim ? r.dkim.selectors.length : -1),
    cell: (r) => el("div", { title: r.dkim ? r.dkim.selectors.join(", ") : "" }, !r.dkim ? "—" : r.dkim.selectors.length ? `${r.dkim.selectors.length} found` : "none found",
      r.dkim && r.dkim.selectors.length ? el("div", { class: "sub mono" }, r.dkim.selectors.slice(0, 3).join(", ") + (r.dkim.selectors.length > 3 ? " …" : "")) : null) },
  { key: "mta_sts", label: "MTA-STS", text: (r) => (!r.mta_sts ? "—" : r.mta_sts.broken ? "broken" : r.mta_sts.mode || "off"),
    sort: (r) => (!r.mta_sts ? -1 : { enforce: 3, testing: 2, none: 1 }[r.mta_sts.mode] || 0) },
  { key: "dnssec", label: "DNSSEC", text: (r) => r.dnssec || "—", sort: (r) => ({ signed: 2, unsigned: 1, broken: 0 }[r.dnssec] ?? -1) },
  { key: "expiry", label: "Expires in", text: (r) => (!r.registration ? "—" : r.registration.days_left == null ? "not published" : `${r.registration.days_left} days`),
    sort: (r) => (r.registration && r.registration.days_left != null ? r.registration.days_left : 1e9),
    cell: (r) => el("div", {}, !r.registration ? "—" : r.registration.days_left == null ? el("span", { class: "sub" }, "not published") : `${r.registration.days_left} days`,
      r.registration && r.registration.expires ? el("div", { class: "sub" }, r.registration.expires) : null) },
  { key: "signin", label: "Sign-in", text: bulkauditSigninText, sort: bulkauditSigninText },
  { key: "grade", label: "Email grade", text: (r) => (r.grade ? `${r.grade.grade} (${r.grade.score})` : r.parked ? "parked" : "—"),
    sort: (r) => (r.grade ? r.grade.score : r.parked ? 101 : -1),
    cell: (r) => (r.grade ? el("span", { title: r.grade.items.map((i) => `${i.label}: ${i.points}/${i.max} (${i.note})`).join("\n") },
      el("span", { class: `bulkaudit-grade bulkaudit-grade-${r.grade.grade}` }, r.grade.grade), `${r.grade.score}`)
      : el("span", { class: "sub" }, r.parked ? "parked (no mail)" : "—")) },
];

function bulkauditWorst(r, col) {
  let w = null;
  (r.problems || []).forEach((p) => { if (p.col === col && (BULKAUDIT_SEV_RANK[p.severity] || 0) > (BULKAUDIT_SEV_RANK[w] || 0)) w = p.severity; });
  return w;
}

/* ----------------------------------------------------------------- result */
function bulkauditResult(state) {
  const frag = el("div");
  const rows = state.rows.filter((r) => !r.invalid);
  if (!rows.length && state.done < state.total) {
    frag.append(el("div", { class: "loading" }, el("div", { class: "spinner" }), "Auditing the first batch…"));
    return frag;
  }
  const s = bulkauditSummary(rows, state);
  frag.append(verdict(s.sev, s.title, s.sub));
  frag.append(facts(s.facts));
  frag.append(card("Findings", findingsList(s.findings), { flush: true }));
  const steps = nextSteps(s.steps);
  if (steps) frag.append(steps);
  frag.append(bulkauditTable(state));
  frag.append(el("p", { class: "hint" }, "Email grade uses Domain Discovery's scoring weights for DMARC, SPF, DKIM, inbound filtering, MTA-STS/TLS-RPT, DNSSEC and domain registration. " +
    "Website and remote-access checks are skipped in the bulk audit, so the percentage is recalculated over the email items only and can differ slightly from Domain Discovery. " +
    "DKIM is checked on common selectors only; the mail platform is a simplified version of Discovery's detection."));
  return frag;
}

function bulkauditList(names, max = 3) {
  return names.slice(0, max).join(", ") + (names.length > max ? ` and ${names.length - max} more` : "");
}

function bulkauditSummary(rows, state) {
  const live = rows.filter((r) => r.exists !== false && !r.error);
  const spoofable = live.filter((r) => r.dmarc && !(r.dmarc.policy === "reject" || r.dmarc.policy === "quarantine"));
  const noDmarc = spoofable.filter((r) => !r.dmarc.record);
  const expiring = live.filter((r) => r.registration && r.registration.days_left != null && r.registration.days_left < 30)
    .sort((a, b) => a.registration.days_left - b.registration.days_left);
  const brokenSpf = live.filter((r) => r.spf && r.spf.record && !r.spf.valid);
  const noSpf = live.filter((r) => r.spf && !r.spf.record && !r.parked);
  const dnssecBroken = live.filter((r) => r.dnssec === "broken");
  const stsBroken = live.filter((r) => r.mta_sts && r.mta_sts.broken);
  const missing = rows.filter((r) => r.exists === false);
  const failed = rows.filter((r) => r.error);
  const n = rows.length;
  const spfDesc = (r) => (r.spf.lookups > 10 ? `${r.domain} has broken SPF (${r.spf.lookups}/10 lookups)` : `${r.domain} has broken SPF (${r.spf.broken})`);

  const parts = [];
  if (spoofable.length) parts.push(`${spoofable.length} of ${live.length} domain${live.length === 1 ? "" : "s"} can be spoofed (no DMARC enforcement)`);
  if (expiring.length) parts.push(`${expiring.length} expire${expiring.length === 1 ? "s" : ""} within 30 days`);
  if (brokenSpf.length === 1) parts.push(spfDesc(brokenSpf[0]));
  else if (brokenSpf.length) parts.push(`${brokenSpf.length} have broken SPF`);
  if (missing.length) parts.push(`${missing.length} do${missing.length === 1 ? "es" : ""}n't exist in DNS`);
  if (dnssecBroken.length) parts.push(`${bulkauditList(dnssecBroken.map((r) => r.domain), 2)} ha${dnssecBroken.length === 1 ? "s" : "ve"} broken DNSSEC`);

  let sev = "ok";
  rows.forEach((r) => (r.problems || []).forEach((p) => { if (p.severity === "critical") sev = "critical"; else if (p.severity === "warning" && sev === "ok") sev = "warning"; }));
  const doneAll = state.done >= state.total;
  const minor = rows.reduce((k, r) => k + (r.problems || []).filter((p) => p.severity === "warning").length, 0);
  // Nothing serious: the headline says healthy, so the banner shouldn't look like a warning.
  if (!parts.length && sev === "warning") sev = "info";
  const title = parts.length ? parts.join("; ") + "."
    : `All ${n} domain${n === 1 ? "" : "s"} pass the key checks: DMARC enforced, SPF valid, nothing expiring within 30 days${minor ? ` (${minor} smaller issue${minor === 1 ? "" : "s"} highlighted below)` : ""}.`;
  const sub = (doneAll ? "" : `Partial result: ${state.done} of ${state.total} audited so far. `) +
    (state.invalid.length ? `${state.invalid.length} invalid entr${state.invalid.length === 1 ? "y" : "ies"} skipped. ` : "") +
    "Click a column header to sort; problem cells are highlighted.";

  const grades = {};
  rows.forEach((r) => { if (r.grade) grades[r.grade.grade] = (grades[r.grade.grade] || 0) + 1; });
  const facts = [["Domains", `${n}${doneAll ? "" : ` of ${state.total}`}`],
    ["DMARC enforced", `${live.length - spoofable.length} of ${live.length}`],
    ["Grades", ["A", "B", "C", "D", "F"].filter((g) => grades[g]).map((g) => `${g}×${grades[g]}`).join(" ") || "—"],
    ["Microsoft 365", String(live.filter((r) => r.mail && r.mail.host === "Microsoft 365").length)],
    ["Federated sign-in", String(live.filter((r) => r.signin && r.signin.namespace === "Federated").length)]];

  const F = [];
  if (noDmarc.length) F.push({ severity: "critical", title: `${noDmarc.length} domain(s) have no DMARC record: ${bulkauditList(noDmarc.map((r) => r.domain), 6)}`,
    detail: "Anyone can send mail as these domains and receivers have no policy telling them to block it. Start with p=none and a rua= report address, then move to quarantine and reject." });
  const monitor = spoofable.filter((r) => r.dmarc.record);
  if (monitor.length) F.push({ severity: "warning", title: `${monitor.length} domain(s) are at p=none (monitoring only): ${bulkauditList(monitor.map((r) => r.domain), 6)}`,
    detail: "Spoofed mail is still delivered. Review the aggregate reports and move to quarantine, then reject." });
  brokenSpf.forEach((r) => F.push({ severity: "critical", title: spfDesc(r),
    detail: "A broken SPF record (PermError) means receivers treat SPF as failed for every message, so DMARC relies on DKIM alone. Open the SPF Inspector for that domain." }));
  if (noSpf.length) F.push({ severity: "critical", title: `${noSpf.length} domain(s) have no SPF record: ${bulkauditList(noSpf.map((r) => r.domain), 6)}`,
    detail: "Publish SPF listing every service that sends as the domain, or v=spf1 -all if it sends no mail." });
  expiring.forEach((r) => F.push({ severity: r.registration.days_left < 7 ? "critical" : "warning",
    title: `${r.domain} ${r.registration.days_left < 0 ? "expired" : "expires"} in ${r.registration.days_left} days (${r.registration.expires || "date unknown"})`,
    detail: `Registrar: ${r.registration.registrar || "unknown"}. Auto-renew status isn't published in RDAP, so confirm it in the registrar account.` }));
  if (dnssecBroken.length) F.push({ severity: "critical", title: `Broken DNSSEC: ${bulkauditList(dnssecBroken.map((r) => r.domain), 6)}`,
    detail: "A DS record is published at the registry but the zone doesn't validate, so validating resolvers (Google, Cloudflare, many ISPs) fail to resolve the domain. Fix or remove the DS record." });
  if (stsBroken.length) F.push({ severity: "critical", title: `MTA-STS problem: ${bulkauditList(stsBroken.map((r) => `${r.domain} (${r.mta_sts.broken})`), 3)}`,
    detail: "The _mta-sts TXT record exists but the policy can't be fetched or is invalid. Senders that cached an enforce policy may refuse to deliver." });
  const noDkim = live.filter((r) => (r.problems || []).some((p) => p.col === "dkim"));
  if (noDkim.length) F.push({ severity: "warning", title: `${noDkim.length} domain(s) without a DKIM key on common selectors: ${bulkauditList(noDkim.map((r) => r.domain), 6)}`,
    detail: "DKIM may still be on a custom selector (check a real message's DKIM-Signature s= tag in Domain Health). Without DKIM, DMARC depends on SPF alone and breaks on forwarding." });
  if (missing.length) F.push({ severity: "critical", title: `${missing.length} domain(s) don't exist in DNS: ${bulkauditList(missing.map((r) => r.domain), 6)}`,
    detail: "Misspelled, expired or never registered. Check the spelling and the registration (Domain / WHOIS tool)." });
  if (failed.length) F.push({ severity: "warning", title: `${failed.length} domain(s) couldn't be audited: ${bulkauditList(failed.map((r) => r.domain), 6)}`, detail: failed[0].error });
  const slow = rows.filter((r) => (r.timed_out || []).length);
  if (slow.length) F.push({ severity: "info", title: `Some checks timed out for ${bulkauditList(slow.map((r) => r.domain), 4)}`,
    detail: "Those cells show '—'. Open Domain Health for the full check." });
  if (!F.length) F.push({ severity: "ok", title: "No fleet-wide problems found", detail: "" });

  const steps = [];
  if (spoofable.length) steps.push({ title: "Roll out DMARC enforcement on the spoofable domains",
    detail: "Use Domain Health → 'Fix / next stage' (DMARC builder) per domain: p=none with reports first, then quarantine, then reject. Domains that send no mail can go straight to v=spf1 -all and p=reject." });
  if (brokenSpf.length || noSpf.length) steps.push({ title: "Fix SPF", detail: "Open the SPF Inspector for each highlighted domain: remove unused includes, flatten where needed, and stay at or under 10 lookups." });
  if (expiring.length) steps.push({ title: "Renew the expiring domains", detail: "Confirm auto-renew and the payment card at the registrar for every domain expiring within 30 days." });

  return { sev, title, sub, facts, findings: F, steps };
}

function bulkauditTable(state) {
  const wrap = el("div");
  const draw = () => {
    const q = state.filter.toLowerCase();
    let rows = state.rows.filter((r) => !r.invalid);
    rows = rows.filter((r) => {
      if (state.show === "problems" && !(r.problems || []).some((p) => BULKAUDIT_SEV_RANK[p.severity])) return false;
      if (state.show === "critical" && !(r.problems || []).some((p) => p.severity === "critical")) return false;
      return !q || BULKAUDIT_COLS.some((c) => String(c.text(r)).toLowerCase().includes(q));
    });
    const { key, dir } = state.sort;
    const col = BULKAUDIT_COLS.find((c) => c.key === key);
    rows.sort((a, b) => {
      if (!col) return (state.order.get(a.domain) ?? 1e6) - (state.order.get(b.domain) ?? 1e6);
      const x = col.sort(a), y = col.sort(b);
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * dir || a.domain.localeCompare(b.domain);
    });
    state.view = rows;
    const thead = el("tr", {}, BULKAUDIT_COLS.map((c) => el("th", {
      "aria-sort": key === c.key ? (dir > 0 ? "ascending" : "descending") : null, title: "Sort",
      onclick: () => { state.sort = { key: c.key, dir: state.sort.key === c.key ? -state.sort.dir : 1 }; draw(); } }, c.label)));
    const body = rows.map((r) => el("tr", {}, BULKAUDIT_COLS.map((c) => {
      const w = bulkauditWorst(r, c.key);
      const why = (r.problems || []).filter((p) => p.col === c.key).map((p) => p.text).join("\n");
      if (r.exists === false && c.key !== "domain") return el("td", { class: "sub" }, "—");
      return el("td", { class: w === "critical" ? "bulkaudit-crit" : w === "warning" ? "bulkaudit-warn" : null, title: why || null },
        c.cell ? c.cell(r) : c.text(r));
    })));
    table.replaceChildren(el("thead", {}, thead), el("tbody", {}, body.length ? body
      : el("tr", {}, el("td", { colspan: BULKAUDIT_COLS.length, class: "hint" }, "No domains match the filter."))));
    exportBtn.textContent = `Export CSV (${rows.length})`;
  };
  const filter = el("input", { type: "text", placeholder: "Filter: domain, platform, policy…", value: state.filter, "data-bulkaudit-filter": "",
    oninput: (e) => { state.filter = e.target.value; draw(); } });
  const show = el("select", { onchange: (e) => { state.show = e.target.value; draw(); } },
    [["all", "All domains"], ["problems", "With problems"], ["critical", "Critical only"]].map(([v, l]) => el("option", { value: v, selected: state.show === v }, l)));
  const exportBtn = el("button", { class: "btn secondary", type: "button", onclick: () => bulkauditExport(state.view || []) }, "Export CSV");
  const table = el("table", { class: "t bulkaudit-table" });
  wrap.append(card(`Domains (${state.rows.filter((r) => !r.invalid).length})`, [
    el("div", { class: "bulkaudit-toolbar" }, filter, show, exportBtn),
    el("div", { class: "table-wrap" }, table)], { flush: true }));
  draw();
  return wrap;
}

/* ------------------------------------------------------------------- CSV */
function bulkauditCsvField(v) {
  let s = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // don't let spreadsheets treat values as formulas
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function bulkauditExport(rows) {
  const head = ["Domain", "Exists", "Mail platform", "Gateways", "SPF record", "SPF lookups", "SPF status", "DMARC policy", "DMARC pct", "DMARC t",
    "DKIM selectors", "MTA-STS", "DNSSEC", "Expires", "Days left", "Registrar", "Sign-in", "Tenant ID", "Grade", "Score", "Problems"];
  const lines = [head.map(bulkauditCsvField).join(",")];
  rows.forEach((r) => {
    lines.push([
      r.domain, r.exists === false ? "no" : "yes", r.mail ? r.mail.host : "", r.mail ? (r.mail.gateways || []).join("; ") : "",
      r.spf ? r.spf.record || "" : "", r.spf ? r.spf.lookups : "", r.spf ? (!r.spf.record ? "none" : r.spf.valid ? "valid" : `broken: ${r.spf.broken}`) : "",
      r.dmarc ? (r.dmarc.record ? r.dmarc.policy || "invalid" : "missing") : "", r.dmarc ? r.dmarc.pct || "" : "", r.dmarc ? r.dmarc.t || "" : "",
      r.dkim ? r.dkim.selectors.join("; ") : "", r.mta_sts ? (r.mta_sts.broken ? "broken" : r.mta_sts.mode || "off") : "", r.dnssec || "",
      r.registration ? r.registration.expires || "" : "", r.registration && r.registration.days_left != null ? r.registration.days_left : "",
      r.registration ? r.registration.registrar || "" : "", bulkauditSigninText(r), r.signin ? r.signin.tenant_id || "" : "",
      r.grade ? r.grade.grade : r.parked ? "parked" : "", r.grade ? r.grade.score : "",
      (r.problems || []).filter((p) => BULKAUDIT_SEV_RANK[p.severity]).map((p) => p.text).join("; "),
    ].map(bulkauditCsvField).join(","));
  });
  const blob = new Blob(["﻿" + lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: `bulk-domain-audit-${new Date().toISOString().slice(0, 10)}.csv` });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

registerTool({ category: "discovery", group: "Clients", id: "bulkaudit", title: "Bulk Domain Audit", render: renderBulkauditTool,
  icon: "M4 6h16M4 12h16M4 18h10M18 16l2 2 3-4",
  keywords: "bulk audit fleet clients many domains dmarc spf dkim mta-sts dnssec expiry federated grade csv export portfolio",
  desc: "Paste up to 50 client domains: one table with mail platform, SPF, DMARC, DKIM, MTA-STS, DNSSEC, expiry, sign-in type and an email security grade, with problems highlighted and CSV export." });
