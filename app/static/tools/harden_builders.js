"use strict";
/* Harden → Records & policies: MTA-STS & TLS-RPT Builder and Parked Domain Lockdown.
   Both only read DNS (plus the published MTA-STS policy file); neither connects to a
   mail server. The server builds every record; the browser renders and copies them. */

addStyles(`
.mtasts-stages { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; }
.mtasts-stage { text-align: left; border: 1px solid var(--border); background: var(--panel); color: var(--text); border-radius: 8px; padding: 10px 12px; font: inherit; cursor: pointer; }
.mtasts-stage:hover { border-color: var(--accent); }
.mtasts-stage.on { border-color: var(--accent); background: var(--accent-soft); }
.mtasts-stage b { display: block; margin-bottom: 2px; }
.mtasts-stage span { color: var(--muted); font-size: 12.5px; }
.mtasts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin-top: 12px; }
.mtasts-grid .field input, .mtasts-grid .field select { width: 100%; }
.mtasts-status { min-height: 18px; margin-top: 8px; }
.mtasts-rec { border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; background: var(--panel); }
.mtasts-rec + .mtasts-rec { margin-top: 12px; }
.mtasts-rec-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-weight: 650; margin-bottom: 4px; }
.mtasts-rec .table-wrap { border: 1px solid var(--border); border-radius: 7px; margin: 8px 0; }
.mtasts-label { color: var(--muted); font-size: 12px; font-weight: 600; margin: 10px 0 2px; }
.mtasts-cur { font-family: var(--mono); font-size: 12.5px; color: var(--muted); overflow-wrap: anywhere; padding: 1px 0; }
.mtasts-list { margin: 4px 0 10px; padding-left: 20px; }
.mtasts-list li { margin: 3px 0; }
.mtasts-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 8px 0; }
.mtasts-diff { display: flex; flex-direction: column; gap: 4px; margin: 6px 0 10px; }
.mtasts-add, .mtasts-del { font-family: var(--mono); font-size: 12.5px; padding: 3px 8px; border-radius: 5px; overflow-wrap: anywhere; }
.mtasts-add { background: var(--ok-soft); color: var(--ok); }
.mtasts-del { background: var(--crit-soft); color: var(--crit); text-decoration: line-through; }
.mtasts-links { display: flex; gap: 14px; flex-wrap: wrap; margin: 4px 0 16px; font-size: 13px; }
.parked-tabs { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 14px; background: var(--panel); }
.parked-tabs button { border: 0; background: transparent; color: var(--text); padding: 7px 14px; font: inherit; cursor: pointer; }
.parked-tabs button + button { border-left: 1px solid var(--border); }
.parked-tabs button.on { background: var(--accent-soft); color: var(--accent); font-weight: 600; cursor: default; }
.parked-multi .field { margin-top: 10px; max-width: 460px; }
.parked-multi .field input { width: 100%; }
.parked-table td:first-child { min-width: 170px; }
.parked-table td:first-child strong { overflow-wrap: normal; }
.parked-table td.parked-cell { white-space: nowrap; }
.parked-table td.parked-todo { min-width: 140px; }
.parked-table td.parked-ok { color: var(--ok); }
.parked-table td.parked-warn { background: var(--warn-soft); color: var(--warn); font-weight: 600; }
.parked-table td.parked-crit { background: var(--crit-soft); color: var(--crit); font-weight: 600; }
.parked-table td .sub { font-weight: 400; }
`);

/* ------------------------------------------------------------- shared pieces */
// Record status → badge. Both builders describe records with the same words.
const MTASTS_STATUS = {
  correct: ["ok", "Already correct"], missing: ["warning", "Missing"], update: ["info", "Needs update"],
  conflicting: ["critical", "Conflicting"], unknown: ["warning", "Couldn't check"],
};

function mtastsStatusBadge(r) {
  if (r.optional && r.status === "missing") return badge("info", "Missing (optional)");
  const [sev, label] = MTASTS_STATUS[r.status] || ["info", r.status];
  return badge(sev, label);
}

const mtastsTtl = (ttl) => (ttl === 3600 ? "3600 (1 hour)" : String(ttl));

/** One DNS record: what it's for, a name / type / value table, the value and the
 *  zone-file line to copy, and what's published at that name now. */
function mtastsRecordBlock(r) {
  const isMx = r.type === "MX";
  const name = el("div", {}, el("span", { class: "mono" }, r.host), r.host !== r.fqdn ? el("div", { class: "sub mono" }, r.fqdn) : null);
  const value = el("span", { class: "mono" }, r.value);
  const current = (r.current || []).filter(Boolean);
  const replace = r.status !== "correct" && r.action !== "hold";
  return el("div", { class: "mtasts-rec" },
    el("div", { class: "mtasts-rec-head" }, el("span", {}, r.label), mtastsStatusBadge(r)),
    r.why ? el("div", { class: "hint" }, r.why) : null,
    table(isMx ? ["Name / host", "Type", "Priority", "Value", "TTL"] : ["Name / host", "Type", "Value", "TTL"],
      [isMx ? [name, "MX", String(r.priority), value, mtastsTtl(r.ttl)] : [name, r.type, value, mtastsTtl(r.ttl)]]),
    isMx ? null : [el("div", { class: "mtasts-label" }, "Value"), code(r.value)],
    el("div", { class: "mtasts-label" }, "Zone file (BIND)"), code(r.bind),
    current.length ? [el("div", { class: "mtasts-label" }, replace ? "Published now (replace this)" : "Published now"),
      current.map((c) => el("div", { class: "mtasts-cur" }, c))] : null,
    r.note ? el("div", { class: "hint", style: "margin-top:8px" }, r.note) : null);
}

function mtastsDownload(text, filename, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/* ===================================================== MTA-STS & TLS-RPT BUILDER */
const MTASTS_STAGES = [
  { mode: "testing", age: 86400, title: "1 · Testing", desc: "Senders report TLS failures but still deliver. Start here, with TLS-RPT, for 2+ weeks." },
  { mode: "enforce", age: 604800, title: "2 · Enforce", desc: "Senders refuse to deliver unless a listed MX host offers valid TLS." },
  { mode: "none", age: 86400, title: "Retire (mode: none)", desc: "Switches MTA-STS off cleanly before you remove it." },
];
const MTASTS_AGES = [[86400, "1 day (86400)"], [604800, "1 week (604800)"], [1209600, "2 weeks (1209600)"],
  [2592000, "30 days (2592000)"], [31557600, "About a year, the maximum (31557600)"]];

function renderMtastsTool(main, params) {
  const out = el("div");
  main.append(card(null, hashForm("mtasts", [
    { name: "d", label: "Domain", placeholder: "contoso.com", grow: true, required: true },
  ], params, "Build records")), out);
  const domain = (params.get("d") || "").trim();
  if (!domain) {
    out.append(el("div", { class: "hint" }, "Reads the domain's MX hosts, its published MTA-STS policy and TLS-RPT record, then builds the policy file, "
      + "both DNS records and the hosting steps. DNS and the policy URL only: it never connects to the mail servers."));
    return;
  }
  const preset = { mode: params.get("mode") || "", max_age: params.get("max_age") || "", rua: params.get("rua") || "" };
  runInto(out, `Reading MX, MTA-STS and TLS-RPT for ${domain}…`, () => api(mtastsUrl(domain, preset)), (b) => mtastsBuilderUI(domain, b, preset));
}

function mtastsUrl(domain, s) {
  const qs = new URLSearchParams();
  ["mode", "max_age", "rua"].forEach((k) => { if (s[k] != null && String(s[k]).trim() !== "") qs.set(k, String(s[k]).trim()); });
  const q = qs.toString();
  return `/api/builder/mtasts/${encodeURIComponent(domain)}${q ? "?" + q : ""}`;
}

function mtastsBuilderUI(domain, first, preset) {
  const root = el("div");
  if (!first.generated.buildable) {
    root.append(...mtastsTop(first), mtastsDetails(first), mtastsLinks(first));
    return root;
  }
  // rua is sent only once the engineer edits it, so the server keeps using the published
  // address (or keeps flagging its suggested one) until then.
  const state = { mode: first.inputs.mode, max_age: String(first.inputs.max_age), rua: preset.rua || "", ruaTouched: !!preset.rua };
  const top = el("div"), bottom = el("div"), stageBox = el("div");
  const status = el("div", { class: "hint mtasts-status", "aria-live": "polite" });
  const err = el("div", { class: "error-box", hidden: true, style: "margin:10px 0 0" });
  const ageSel = el("select", { "aria-label": "max_age" });
  const ruaIn = el("input", { type: "text", spellcheck: "false", autocomplete: "off", placeholder: "tls-reports@contoso.com or https://…",
    value: preset.rua || first.inputs.rua.map((u) => u.replace(/^mailto:/i, "")).join(", ") });
  let seq = 0, timer = null;

  const draw = (b) => {
    top.replaceChildren(...mtastsTop(b));
    bottom.replaceChildren(...mtastsGenerated(b), mtastsDetails(b), mtastsLinks(b));
  };
  const remember = () => {
    // Keep the settings in the address bar (without re-running) so the page can be reloaded or shared.
    const p = new URLSearchParams({ d: domain, mode: state.mode, max_age: state.max_age });
    if (state.ruaTouched && state.rua.trim()) p.set("rua", state.rua.trim());
    try { history.replaceState(history.state, "", `#mtasts?${p}`); } catch (e) { /* ignore */ }
  };
  const rebuild = (delay) => {
    clearTimeout(timer);
    status.textContent = "Rebuilding the records…";
    timer = setTimeout(async () => {
      const my = ++seq;
      try {
        const b = await api(mtastsUrl(domain, { mode: state.mode, max_age: state.max_age, rua: state.ruaTouched ? state.rua : "" }));
        if (my !== seq) return;
        err.hidden = true;
        status.textContent = "";
        draw(b);
        remember();
      } catch (e) {
        if (my !== seq) return;
        status.textContent = "";
        err.textContent = `Not rebuilt: ${e.message || e}`;
        err.hidden = false;
      }
    }, delay);
  };
  const drawAges = () => {
    const opts = MTASTS_AGES.some(([v]) => String(v) === state.max_age) ? MTASTS_AGES : [[Number(state.max_age), `${state.max_age} seconds`], ...MTASTS_AGES];
    ageSel.replaceChildren(...opts.map(([v, l]) => el("option", { value: String(v), selected: String(v) === state.max_age }, l)));
  };
  const drawStages = () => stageBox.replaceChildren(el("div", { class: "mtasts-stages", role: "group", "aria-label": "Policy mode" },
    MTASTS_STAGES.map((s) => el("button", {
      type: "button", class: s.mode === state.mode ? "mtasts-stage on" : "mtasts-stage", "aria-pressed": String(s.mode === state.mode),
      onclick: () => {
        if (state.mode === s.mode) return;
        state.mode = s.mode;
        state.max_age = String(s.age);
        drawStages();
        drawAges();
        rebuild(0);
      },
    }, el("b", {}, s.title), el("span", {}, s.desc)))));
  ageSel.addEventListener("change", () => { state.max_age = ageSel.value; rebuild(0); });
  ruaIn.addEventListener("input", () => { state.rua = ruaIn.value; state.ruaTouched = true; rebuild(700); });
  drawStages();
  drawAges();

  const settings = card("Policy settings", [
    stageBox,
    el("div", { class: "mtasts-grid" },
      el("div", { class: "field" }, el("label", {}, "How long senders cache the policy (max_age)"), ageSel),
      el("div", { class: "field" }, el("label", {}, "Send TLS-RPT reports to (rua)"), ruaIn)),
    el("div", { class: "hint", style: "margin-top:8px" }, "Email addresses or https:// report URLs, comma separated. Every change rebuilds the records below."),
    status, err,
  ], { icon: "settings" });
  root.append(top, settings, bottom);
  draw(first);
  return root;
}

function mtastsTop(b) {
  const c = b.current;
  const hosts = c.mx || [];
  const providers = [...new Set(hosts.map((h) => h.provider).filter(Boolean))];
  const pol = c.policy || {};
  const rpt = c.tlsrpt || {};
  const stage = { off: "not set up", broken: "broken", testing: "testing", enforce: "enforce", none: "mode: none (off)" }[b.stage] || b.stage;
  return [
    verdict(b.severity, b.headline, b.subline),
    facts([
      ["MX hosts", hosts.length ? `${hosts.length}${providers.length ? ` (${providers.join(", ")})` : ""}` : c.null_mx ? "null MX" : "none"],
      ["MTA-STS now", stage],
      ["Cache time now", pol.max_age != null ? `${pol.max_age_text} (${pol.max_age})` : null],
      ["TLS-RPT now", rpt.valid ? "on" : (rpt.records || []).length ? "invalid" : "off"],
      ["Policy host", c.policy_host ? `${c.policy_host.name} ${c.policy_host.resolves ? "is in DNS" : "isn't in DNS"}` : null],
    ]),
    card("Findings", findingsList(b.findings, { area: true }), { flush: true }),
  ];
}

function mtastsGenerated(b) {
  const g = b.generated;
  if (!g.buildable) return [];
  const p = g.policy, h = g.hosting;
  const rec = Object.fromEntries(g.records.map((r) => [r.id, r]));
  const parts = [];
  if (g.findings.length) parts.push(card("Check before publishing", findingsList(g.findings, { area: true }), { flush: true }));

  parts.push(card(rec.tlsrpt.status === "correct" ? "Step 1 · TLS-RPT record: already correct" : "Step 1 · Publish the TLS-RPT record",
    mtastsRecordBlock(rec.tlsrpt), { icon: "mail" }));

  parts.push(card(p.status === "correct" ? "Step 2 · Policy file: no changes" : "Step 2 · Host the policy file", [
    kv([
      ["URL", el("span", { class: "mono" }, h.url)],
      ["Content-Type", el("span", { class: "mono" }, "text/plain")],
      ["Certificate", `publicly trusted, valid for ${h.host}`],
      ["Status", mtastsStatusBadge({ status: p.status })],
    ]),
    el("div", { class: "mtasts-label" }, `mta-sts.txt (mode: ${p.mode}, ${p.mx.length} mx line${p.mx.length === 1 ? "" : "s"}, max_age ${p.max_age})`),
    code(p.text),
    el("div", { class: "mtasts-actions" },
      el("button", { class: "btn secondary", type: "button", onclick: () => mtastsDownload(p.text, "mta-sts.txt", "text/plain") }, "Download mta-sts.txt"),
      el("span", { class: "hint" }, p.note)),
    p.added.length || p.removed.length ? el("div", { class: "mtasts-diff" }, el("div", { class: "hint" }, "mx lines compared with the published policy:"),
      p.added.map((x) => el("div", { class: "mtasts-add" }, `+ mx: ${x}`)), p.removed.map((x) => el("div", { class: "mtasts-del" }, `− mx: ${x}`))) : null,
    el("div", { class: "mtasts-label" }, "Hosting requirements"),
    el("ul", { class: "mtasts-list" }, h.requirements.map((t) => el("li", {}, t))),
    el("div", { class: "mtasts-label" }, "Where to host it"),
    el("ul", { class: "mtasts-list" }, h.options.map((t) => el("li", {}, t))),
    h.caveats.map((t) => el("div", { class: "notice" }, t)),
    el("div", { class: "mtasts-label" }, "Check the file once it's uploaded"),
    code(h.verify[0]),
    el("div", { class: "hint" }, "Expect status 200, Content-Type: text/plain and the policy text. A 301/302 redirect or a certificate error means senders "
      + "can't use it. In Windows PowerShell, type curl.exe instead of curl."),
  ], { icon: "file" }));

  parts.push(card(rec.sts.status === "correct" ? "Step 3 · MTA-STS record: already correct" : "Step 3 · Publish the _mta-sts record (last)", [
    mtastsRecordBlock(rec.sts),
    el("div", { class: "mtasts-label" }, "Check both DNS records after publishing"),
    h.verify.slice(1).map((c) => code(c)),
  ], { icon: "lock" }));

  parts.push(nextSteps(b.rollout.map((s) => ({ title: s.current ? `${s.title} (you are here)` : s.title, detail: s.detail })),
    b.inputs && b.inputs.mode === "none" ? "Retiring MTA-STS" : "Recommended rollout"));
  return parts.filter(Boolean);
}

function mtastsDetails(b) {
  const c = b.current;
  const pol = c.policy || {};
  const rpt = c.tlsrpt || {};
  const ph = c.policy_host;
  const hosts = c.mx || [];
  const fetched = !!pol.fetched;
  const covered = (v) => (v == null ? el("span", { class: "sub" }, "—") : v ? badge("ok", "covered") : badge("critical", "not covered"));
  const rows = hosts.map((h) => [String(h.preference),
    el("div", {}, el("span", { class: "mono" }, h.host), h.cname ? el("div", { class: "sub mono" }, `CNAME → ${h.cname}`) : null,
      h.ip_literal ? el("div", { class: "sub" }, "an IP address, not a host name") : null),
    h.provider || el("span", { class: "sub" }, "Unknown / self-hosted"),
    fetched ? covered(h.covered) : el("span", { class: "sub" }, "no policy"), covered(h.covered_new)]);
  const txts = (list) => (list && list.length ? el("div", {}, list.map((r) => el("div", { class: "mono" }, r))) : "none");
  return card("Details: what's published now", [
    rows.length ? table(["Pref", "MX host", "Provider", "Published policy", "New policy"], rows, (i) => (fetched && hosts[i].covered === false ? "hl" : null))
      : el("div", { class: "card-body hint" }, c.null_mx ? "Null MX: this domain accepts no mail." : "No MX records."),
    el("div", { class: "card-body" }, kv([
      ["_mta-sts TXT", txts(c.sts_records)],
      ["Policy URL", el("span", { class: "mono" }, pol.url)],
      ["Policy file", fetched ? `fetched: mode ${pol.mode || "?"}, ${pol.mx.length} mx line${pol.mx.length === 1 ? "" : "s"}`
        : (c.sts_records || []).length ? "couldn't be fetched (see Findings)" : "not checked: senders only fetch it once the _mta-sts record exists"],
      ["_smtp._tls TXT", txts(rpt.records)],
      ["mta-sts host", ph ? el("span", { class: "mono" }, ph.name + (ph.cname ? ` → ${ph.cname}` : "")
        + (ph.addresses.length ? ` (${ph.addresses.slice(0, 3).join(", ")}${ph.addresses.length > 3 ? ", …" : ""})` : " (not in DNS)")) : null],
    ])),
    fetched && pol.raw ? el("div", { class: "card-body", style: "padding-top:0" }, el("div", { class: "mtasts-label" }, "Published policy file"), code(pol.raw)) : null,
  ], { flush: true });
}

function mtastsLinks(b) {
  const noMail = b.current.null_mx || !(b.current.mx || []).length;
  return el("div", { class: "mtasts-links" },
    noMail ? link("parked", { d: b.domain }, "Parked Domain Lockdown →") : null,
    noMail ? null : link("dmarcreport", {}, "Read TLS-RPT reports (DMARC Report Analyzer) →"),
    noMail ? null : link("smtp", { t: b.domain }, "Test STARTTLS on the MX hosts (SMTP Test) →"),
    link("domain", { d: b.domain }, "Domain Health →"));
}

/* ========================================================== PARKED DOMAIN LOCKDOWN */
const PARKED_MAX = 20;
const PARKED_NAMES = { mx: "null MX", spf: "SPF", dmarc: "DMARC", dkim: "DKIM revocation" };
const PARKED_FACT = { mx: "Null MX", spf: "SPF -all", dmarc: "DMARC reject", dkim: "DKIM revoked" };
const PARKED_CSV_ACTION = { none: "Keep (already correct)", add: "Add", replace: "Replace", hold: "Don't publish", check: "Check again" };

function renderParkedTool(main, params) {
  const multi = params.has("list") || params.get("m") === "multi";
  const tab = (on, label, hash) => el("button", { type: "button", class: on ? "on" : null, "aria-pressed": String(on),
    onclick: () => { if (!on) location.hash = hash; } }, label);
  main.append(el("div", { class: "parked-tabs", role: "group", "aria-label": "How many domains" },
    tab(!multi, "One domain", "parked"), tab(multi, `Several domains (up to ${PARKED_MAX})`, "parked?m=multi")));
  if (multi) parkedMulti(main, params);
  else parkedSingle(main, params);
}

const parkedState = (r) => (!r ? "—" : { correct: "in place", missing: r.optional ? "missing (optional)" : "missing",
  conflicting: "conflicting", unknown: "couldn't check" }[r.status] || r.status);
const parkedTodo = (records) => (records || []).filter((r) => r.action === "add" || r.action === "replace");
const parkedRua = (rua) => (rua && rua.length ? { rua: rua.map((u) => u.replace(/^mailto:/i, "")).join(",") } : {});
/** "null MX, SPF + DKIM revocation (optional)" */
function parkedTodoText(todo) {
  const required = todo.filter((x) => !x.optional).map((x) => PARKED_NAMES[x.id]).join(", ");
  const optional = todo.filter((x) => x.optional).map((x) => `${PARKED_NAMES[x.id]} (optional)`).join(", ");
  return [required, optional].filter(Boolean).join(" + ");
}

function parkedSingle(main, params) {
  const out = el("div");
  main.append(card(null, hashForm("parked", [
    { name: "d", label: "Domain", placeholder: "contoso.net", grow: true, required: true },
    { name: "rua", label: "DMARC reports to (optional)", placeholder: "dmarc@contoso.com" },
  ], params, "Check")), out);
  const domain = (params.get("d") || "").trim();
  if (!domain) {
    out.append(el("div", { class: "hint" }, "For a domain that sends and receives no mail (parked, defensive or retired): checks its MX, SPF, DMARC and "
      + "DKIM records, shows which lockdown records are in place, and gives the exact records to publish. DNS lookups only."));
    return;
  }
  const rua = (params.get("rua") || "").trim();
  runInto(out, `Checking MX, SPF, DMARC and DKIM for ${domain}…`,
    () => api(`/api/builder/parked/${encodeURIComponent(domain)}${rua ? `?rua=${encodeURIComponent(rua)}` : ""}`), renderParkedResult);
}

function renderParkedResult(r) {
  const frag = el("div");
  const rec = Object.fromEntries(r.records.map((x) => [x.id, x]));
  const todo = parkedTodo(r.records);
  const blocks = r.records.map(mtastsRecordBlock);
  frag.append(verdict(r.severity, r.headline, r.subline));
  frag.append(facts([["Status", r.status_label], ...["mx", "spf", "dmarc", "dkim"].map((id) => [PARKED_FACT[id], parkedState(rec[id])])]));
  frag.append(card("Findings", findingsList(r.findings, { area: true }), { flush: true }));
  if (r.safe) {
    const required = todo.filter((x) => !x.optional).length, optional = todo.length - required;
    const title = required ? `Publish ${required === 1 ? "this record" : `these ${required} records`}${optional ? ` (plus ${optional} optional)` : ""}`
      : optional ? "Lockdown complete: one optional record left" : "Lockdown records: all in place";
    frag.append(card(title, [
      todo.length ? el("div", { class: "hint", style: "margin-bottom:10px" }, "Records marked Already correct can stay as they are. "
        + "For a conflicting record, edit or delete what's published now, then add the new value.") : null,
      blocks,
      todo.length ? [el("div", { class: "mtasts-label" }, "All changes as zone-file lines"), code(parkedZone(r.domain, r.status_label, todo))] : null,
    ], { icon: "lock" }));
  } else {
    frag.append(card("Lockdown records (not safe for this domain)", [
      el("div", { class: "notice" }, r.status === "unknown"
        ? "Some lookups failed, so it isn't clear whether this domain uses mail. Run the check again before publishing anything."
        : "This domain appears to be in use for mail, so these records would break it. They're here for reference only."),
      el("details", {}, el("summary", {}, "Show the lockdown records anyway"), blocks),
    ]));
  }
  frag.append(card("Details: what's published now", table(["Record", "Name", "Published now", "Status"], r.records.map((x) => [
    x.label, el("span", { class: "mono" }, x.fqdn),
    x.current.length ? el("div", {}, x.current.map((c) => el("div", { class: "mono" }, c))) : el("span", { class: "sub" }, "nothing"),
    mtastsStatusBadge(x)]), (i) => (r.records[i].status === "conflicting" ? "hl" : null)), { flush: true }));
  frag.append(el("div", { class: "mtasts-links" }, link("domain", { d: r.domain }, "Domain Health →"),
    link("dmarcbuild", { d: r.domain }, "DMARC Builder →"), link("spfbuild", { d: r.domain }, "SPF Builder →")));
  return frag;
}

function parkedMulti(main, params) {
  const preset = [...new Set((params.get("list") || "").split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean))];
  const ta = el("textarea", { spellcheck: "false", "aria-label": "Domains to check", style: "min-height:150px",
    placeholder: `contoso.net\ncontoso.org\ncontoso-shop.com\n\nOne per line, or separated by commas or spaces (up to ${PARKED_MAX}).` }, preset.join("\n"));
  const rua = el("input", { type: "text", spellcheck: "false", autocomplete: "off", placeholder: "dmarc@contoso.com", value: params.get("rua") || "" });
  const err = el("div", { class: "error-box", hidden: true, style: "margin:10px 0 0" });
  const out = el("div");
  const run = () => {
    const list = [...new Set(ta.value.split(/[\s,;]+/).map((s) => s.trim().toLowerCase()).filter(Boolean))];
    if (!list.length) { ta.focus(); return; }
    if (list.length > PARKED_MAX) {
      err.textContent = `Up to ${PARKED_MAX} domains at a time: this list has ${list.length}. Split it into smaller batches.`;
      err.hidden = false;
      return;
    }
    err.hidden = true;
    const p = new URLSearchParams({ list: list.join(",") });
    if (rua.value.trim()) p.set("rua", rua.value.trim());
    const next = `#parked?${p}`;
    if (location.hash === next) route(); else location.hash = next;
  };
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
  main.append(card(null, el("div", { class: "parked-multi" }, ta,
    el("div", { class: "field" }, el("label", {}, "DMARC reports to (optional, used in every DMARC record)"), rua),
    el("div", { class: "btn-row" },
      el("button", { class: "btn", type: "button", onclick: run }, "Check domains"),
      el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; ta.focus(); } }, "Clear"),
      el("span", { class: "hint", style: "align-self:center" }, "Ctrl+Enter to run")),
    err)), out);
  if (preset.length) {
    runInto(out, `Checking ${preset.length} domain${preset.length === 1 ? "" : "s"}…`,
      () => api("/api/builder/parked", { body: { domains: preset, rua: params.get("rua") || "" } }), renderParkedBulk);
  }
}

function renderParkedBulk(res) {
  const frag = el("div");
  const c = res.counts || {};
  frag.append(verdict(res.severity, res.headline, res.subline));
  frag.append(facts([
    ["Domains", String(res.rows.filter((r) => r.status !== "invalid").length)],
    ["Locked down", String(c.locked || 0)],
    ["Need records", String((c.partial || 0) + (c.open || 0))],
    ["Receive or send mail", String((c.receives_mail || 0) + (c.sends_mail || 0))],
    ["Records to publish", String(res.to_publish)],
    ["Duplicates removed", res.duplicates ? String(res.duplicates) : null],
  ]));
  frag.append(card("Findings", findingsList(res.findings, { area: true }), { flush: true }));
  frag.append(parkedTable(res));
  frag.append(parkedExport(res));
  return frag;
}

function parkedTable(res) {
  const cell = (x) => {
    if (!x) return el("td", { class: "sub" }, "—");
    const cls = { correct: "parked-ok", conflicting: "parked-crit", missing: x.optional ? "" : "parked-warn", unknown: "parked-warn" }[x.status] || "";
    // The published value is in the tooltip and on the domain's Details page, so rows stay one line high.
    // The DKIM column header already says "(optional)".
    return el("td", { class: `parked-cell ${cls}`.trim(), title: x.current.length ? `Published now:\n${x.current.join("\n")}` : null },
      x.status === "correct" ? "✓ in place" : parkedState({ ...x, optional: false }));
  };
  const rows = res.rows.map((row) => {
    const rec = Object.fromEntries((row.records || []).map((x) => [x.id, x]));
    const todo = parkedTodo(row.records);
    const checked = (row.records || []).length > 0;
    return el("tr", { class: row.severity === "critical" ? "hl" : null },
      // Long names may wrap after a dot, never in the middle of a label.
      el("td", {}, el("strong", { class: "mono" }, row.domain.split(".").map((part, i, all) => (i < all.length - 1 ? [`${part}.`, el("wbr")] : part))),
        row.status === "invalid" ? null : el("div", { class: "sub" }, link("parked", { d: row.domain, ...parkedRua(res.rua) }, "Details"), " · ",
          link("domain", { d: row.domain }, "Domain Health"))),
      el("td", { title: row.headline }, badge(row.severity, row.label)),
      ...(checked ? ["mx", "spf", "dmarc", "dkim"].map((id) => cell(rec[id])) : [el("td", { colspan: 4, class: "sub" }, row.error || row.headline)]),
      el("td", { class: "parked-todo" }, !checked ? "—" : !row.safe ? el("span", { class: "sub" }, row.status === "unknown" ? "Check again" : "Nothing: not parked")
        : todo.length ? parkedTodoText(todo) : "Nothing"));
  });
  return card(`Domains (${res.rows.length})`, el("div", { class: "table-wrap" }, el("table", { class: "t parked-table" },
    el("thead", {}, el("tr", {}, ["Domain", "Status", "Null MX", "SPF", "DMARC", "DKIM (optional)", "To publish"].map((h) => el("th", {}, h)))),
    el("tbody", {}, rows))), { flush: true });
}

/** Zone-file lines for one domain's changes, with a comment header. */
function parkedZone(domain, label, todo) {
  return [`; ${domain}: ${label.toLowerCase()}`, ...todo.map((x) => (x.optional ? `; optional\n${x.bind}` : x.bind))].join("\n");
}

function parkedCsvField(v) {
  let s = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;  // a spreadsheet must never treat a value as a formula
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Every record for every domain, one row each. Domains that aren't safe to lock down get one "Not changed" row. */
function parkedCsv(rows) {
  const lines = [["Domain", "Status", "Record", "Name", "Type", "Priority", "Value", "TTL", "Action", "Published now"]];
  rows.forEach((row) => {
    if (!row.safe || !(row.records || []).length) {
      lines.push([row.domain, row.label, "", "", "", "", "", "", row.status === "invalid" ? "Skipped: invalid name" : `Not changed: ${row.label.toLowerCase()}`, ""]);
      return;
    }
    row.records.forEach((x) => lines.push([row.domain, row.label, x.label, x.fqdn, x.type, x.type === "MX" ? x.priority : "", x.value, x.ttl,
      PARKED_CSV_ACTION[x.action] + (x.optional && x.action !== "none" ? " (optional)" : ""), (x.current || []).join(" | ")]));
  });
  return lines.map((l) => l.map(parkedCsvField).join(",")).join("\r\n") + "\r\n";
}

function parkedExport(res) {
  const csv = parkedCsv(res.rows);
  const zone = res.rows.filter((row) => row.safe && parkedTodo(row.records).length)
    .map((row) => parkedZone(row.domain, row.label, parkedTodo(row.records))).join("\n\n");
  const copyBtn = el("button", { class: "btn secondary", type: "button" }, "Copy as CSV");
  copyBtn.addEventListener("click", () => copyText(csv, copyBtn));
  const download = () => mtastsDownload("﻿" + csv, `parked-domain-lockdown-${new Date().toISOString().slice(0, 10)}.csv`, "text/csv;charset=utf-8");
  return card("All records", [
    el("div", { class: "mtasts-actions" }, copyBtn, el("button", { class: "btn secondary", type: "button", onclick: download }, "Download CSV"),
      el("span", { class: "hint" }, "One row per record with its action (Add, Replace, Keep). Domains that receive or send mail are listed but left unchanged.")),
    zone ? [el("div", { class: "mtasts-label" }, "Changes as zone-file lines (only domains that are safe to lock down)"), code(zone)]
      : el("div", { class: "hint" }, "Nothing to publish: every domain that's safe to lock down already is."),
  ], { icon: "download" });
}

/* ============================================================== REGISTRATION */
registerTool({ category: "email", mode: "harden", group: "Records & policies", access: "passive", id: "mtasts", title: "MTA-STS & TLS-RPT Builder",
  render: renderMtastsTool, icon: "M2 5h12v9H2zM2 6l6 4.5L14 6M16.5 14v-1.5a2.5 2.5 0 015 0V14M15 14h8v7h-8z",
  keywords: "mta-sts mtasts tls-rpt tlsrpt smtp tls starttls policy enforce testing downgrade mx certificate well-known mta-sts.txt encryption inbound",
  desc: "Builds the MTA-STS policy file, the _mta-sts and TLS-RPT records and the hosting steps, checked against the domain's MX hosts and any "
    + "published policy, with a testing-to-enforce rollout." });
registerTool({ category: "email", mode: "harden", group: "Records & policies", access: "passive", id: "parked", title: "Parked Domain Lockdown",
  render: renderParkedTool, icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7zM9.5 11.5V10a2.5 2.5 0 015 0v1.5M9 11.5h6V16H9z",
  keywords: "parked domain lockdown null mx spf -all dmarc reject dkim revoke defensive unused typo domains spoofing protect bulk csv",
  desc: "For domains that send and receive no mail: shows which lockdown records (null MX, SPF -all, DMARC reject, DKIM revocation) are in place "
    + "and the exact records to publish, for one domain or up to 20." });
