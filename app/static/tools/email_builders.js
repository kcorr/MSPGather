"use strict";
/* Email → Fix-it builders: SPF Builder and DMARC Builder.
   Every edit rebuilds the record on the server, which validates it against
   live DNS before anyone publishes it. */

addStyles(`
.bld-changes { display: flex; flex-direction: column; gap: 4px; margin-top: 10px; }
.bld-add, .bld-del { font-family: var(--mono); font-size: 12.5px; padding: 3px 8px; border-radius: 5px; overflow-wrap: anywhere; }
.bld-add { background: var(--ok-soft); color: var(--ok); }
.bld-del { background: var(--crit-soft); color: var(--crit); text-decoration: line-through; }
.bld-dns { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; margin: 10px 0 4px; font-size: 13px; }
.bld-dns dt { color: var(--muted); }
.bld-dns dd { margin: 0; font-family: var(--mono); overflow-wrap: anywhere; }
.bld-record { font-size: 14px; padding: 12px 14px; }
.bld-cost { display: flex; align-items: center; gap: 8px; }
.bld-cost .bar { flex: 1; max-width: 120px; margin: 0; }
.bld-add-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: flex-end; margin-top: 12px; }
.bld-add-row .field { flex: 1 1 220px; }
.bld-add-row .field select, .bld-add-row .field input { width: 100%; }
.bld-chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.bld-chip { border: 1px dashed var(--accent); background: var(--accent-soft); color: var(--accent); border-radius: 999px; padding: 4px 12px; font: inherit; font-size: 12.5px; cursor: pointer; }
.bld-opts { display: grid; gap: 8px; }
.bld-opt { display: flex; gap: 10px; align-items: flex-start; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; cursor: pointer; }
.bld-opt.on { border-color: var(--accent); background: var(--accent-soft); }
.bld-opt input { margin-top: 3px; }
.bld-opt-title { font-weight: 600; }
.bld-opt-desc { color: var(--muted); font-size: 12.5px; }
.bld-stages { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 8px; }
.bld-stage { text-align: left; border: 1px solid var(--border); background: var(--panel); color: var(--text); border-radius: 8px; padding: 10px 12px; font: inherit; cursor: pointer; }
.bld-stage.on { border-color: var(--accent); background: var(--accent-soft); }
.bld-stage b { display: block; margin-bottom: 2px; }
.bld-stage span { color: var(--muted); font-size: 12.5px; }
.bld-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
.bld-grid .field input, .bld-grid .field select { width: 100%; }
`);

/** Shared "Publish this record" card. */
function bldPublishCard(b, opts) {
  const changes = [];
  (b.added || []).forEach((t) => changes.push(el("div", { class: "bld-add" }, "+ " + t)));
  (b.removed || []).forEach((t) => changes.push(el("div", { class: "bld-del" }, "− " + t)));
  const body = [
    el("dl", { class: "bld-dns" },
      el("dt", {}, "Type"), el("dd", {}, b.dns.type),
      el("dt", {}, "Host / name"), el("dd", {}, `${b.dns.host}   (${b.dns.fqdn})`),
      el("dt", {}, "TTL"), el("dd", {}, `${b.dns.ttl} (1 hour)`)),
    el("div", { class: "hint" }, "Value:"),
    (() => { const c = code(b.record); c.classList.add("bld-record"); return c; })(),
    opts.replaceNote ? el("div", { class: "notice", style: "margin:10px 0 0" }, opts.replaceNote) : null,
    changes.length ? el("div", { class: "bld-changes" }, el("div", { class: "hint" }, opts.changesLabel || "Changes from the published record:"), changes) : null,
    b.dns.bind ? el("details", { style: "margin-top:10px" }, el("summary", {}, "BIND zone-file format" + (b.dns.chunked ? " (record is over 255 characters, so it's split into quoted strings)" : "")), code(b.dns.bind)) : null,
  ];
  return card(b.unchanged ? "Published record (no changes)" : "Publish this record", body);
}

/* ================================================================ SPF BUILDER */
function renderSpfBuildTool(main, params) {
  const out = el("div");
  main.append(card(null, hashForm("spfbuild", [
    { name: "d", label: "Domain", placeholder: "contoso.com", grow: true, required: true },
  ], params, "Load SPF")), out);
  const domain = params.get("d");
  if (!domain) {
    out.append(el("div", { class: "hint" }, "Loads the domain's current SPF so you can add or remove senders. The new record is checked against live DNS (lookup limit, broken includes) before you publish it."));
    return;
  }
  runInto(out, `Loading SPF for ${domain}…`, () => api(`/api/builder/spf/${encodeURIComponent(domain)}`), (cur) => spfBuilderUI(cur, params.get("add")));
}

function spfBuilderUI(cur, preAdd) {
  const state = { terms: cur.terms.map((t) => t.raw), all: cur.all };
  // Linked from another tool with a sender to add (e.g. IP Lookup found an unauthorised service).
  if (preAdd && !state.terms.some((t) => t.toLowerCase() === preAdd.toLowerCase())) state.terms.push(preAdd);
  const root = el("div");
  const top = el("div");
  const editor = el("div");
  root.append(top, editor);
  let seq = 0, timer = null, last = null;
  let good = { terms: [...state.terms], all: state.all };  // last state the server accepted
  let inputError = "";

  const rebuild = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const my = ++seq;
      const status = el("div", { class: "loading" }, el("div", { class: "spinner" }), "Checking the record against live DNS…");
      if (!last) top.replaceChildren(status); else top.prepend(status);
      try {
        const b = await api("/api/builder/spf", { body: { domain: cur.domain, terms: state.terms, all: state.all } });
        if (my !== seq) return;
        last = b;
        good = { terms: [...state.terms], all: state.all };
        drawTop(b);
        drawEditor(b);
        inputError = "";
      } catch (e) {
        if (my !== seq) return;
        status.remove();
        // Roll back the edit that the server rejected and say why, next to the input.
        state.terms = [...good.terms];
        state.all = good.all;
        inputError = `Not added: ${e.message}`;
        if (last) drawEditor(last); else top.replaceChildren(el("div", { class: "error-box" }, e.message));
        inputError = "";
      }
    }, 250);
  };

  const drawTop = (b) => {
    const parts = [verdict(b.severity, b.headline, b.subline),
      cur.multiple ? el("div", { class: "error-box" }, `${cur.domain} currently publishes ${cur.records.length} SPF records, which makes SPF fail everywhere. Publish the single record below and DELETE the others.`) : null,
      facts([["DNS lookups", `${b.lookup_count}/10`], ["Void lookups", `${b.void_lookups}/2`], ["Authorised networks", String(b.networks)],
        ["Policy for others", state.all]])];
    parts.push(bldPublishCard(b, {
      replaceNote: b.published.length ? `Edit the existing TXT record that starts with "v=spf1" (or delete it and add this one). Never publish two SPF records.` : `${cur.domain} has no SPF record yet, so add this as a new TXT record.`,
    }));
    if (b.findings.length) parts.push(card("Issues in this record", findingsList(b.findings), { flush: true }));
    top.replaceChildren(...parts.filter(Boolean));
  };

  const drawEditor = (b) => {
    const maxCost = Math.max(1, ...b.terms.map((t) => t.lookup_cost));
    const rows = b.terms.map((t, i) => [
      el("span", { class: "mono" }, t.raw),
      t.service || el("span", { class: "sub" }, t.mechanism === "ip4" || t.mechanism === "ip6" ? "IP range" : "—"),
      el("div", { class: "bld-cost" }, String(t.lookup_cost),
        t.lookup_cost ? el("div", { class: t.lookup_cost >= 4 ? "bar crit" : t.lookup_cost >= 2 ? "bar warn" : "bar" }, el("span", { style: `width:${(t.lookup_cost / maxCost) * 100}%` })) : null),
      el("button", { class: "btn secondary", type: "button", onclick: () => { state.terms = state.terms.filter((x) => x.toLowerCase() !== t.raw.toLowerCase()); rebuild(); } }, "Remove"),
    ]);
    const inRecord = new Set(state.terms.map((t) => t.toLowerCase()));
    const groups = [...new Set(cur.catalog.map((c) => c.group))];
    const select = el("select", {}, el("option", { value: "" }, "Choose a service…"),
      groups.map((g) => el("optgroup", { label: g }, cur.catalog.filter((c) => c.group === g).map((c) =>
        el("option", { value: c.term, disabled: inRecord.has(c.term) }, `${c.name}${inRecord.has(c.term) ? " (already in record)" : ""}`)))));
    const note = el("div", { class: "hint" });
    select.addEventListener("change", () => { const c = cur.catalog.find((x) => x.term === select.value); note.textContent = c ? `${c.term}${c.note ? " · " + c.note : ""}` : ""; });
    const custom = el("input", { type: "text", placeholder: "include:vendor.com, ip4:203.0.113.10, 2001:db8::/32 or a vendor domain", spellcheck: "false" });
    const addTerm = (t) => { if (t && !state.terms.some((x) => x.toLowerCase() === t.toLowerCase())) { state.terms.push(t); rebuild(); } };
    custom.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addTerm(custom.value.trim()); } });
    const suggestions = cur.suggestions.filter((s) => !inRecord.has(cur.catalog.find((c) => c.id === s.id).term));

    const allOpts = Object.entries(cur.all_options).map(([q, desc]) => {
      const radio = el("input", { type: "radio", name: "spfall", value: q, checked: state.all === q });
      radio.addEventListener("change", () => { state.all = q; rebuild(); });
      return el("label", { class: state.all === q ? "bld-opt on" : "bld-opt" }, radio,
        el("div", {}, el("div", { class: "bld-opt-title mono" }, q), el("div", { class: "bld-opt-desc" }, desc)));
    });

    editor.replaceChildren(
      card(`Senders in this record (${b.terms.length})`, [
        b.terms.length ? table(["Entry", "Service", "DNS lookups used", ""], rows, (i) => (b.terms[i].error || b.terms[i].lookup_cost >= 4 ? "hl" : null))
          : el("div", { class: "card-body hint" }, "No senders yet. Add the services that send mail as this domain."),
        el("div", { class: "card-body" },
          suggestions.length ? el("div", { class: "bld-chips" }, suggestions.map((s) => {
            const c = cur.catalog.find((x) => x.id === s.id);
            return el("button", { class: "bld-chip", type: "button", onclick: () => addTerm(c.term) }, `+ Add ${c.name} (${s.reason})`);
          })) : null,
          el("div", { class: "bld-add-row" },
            el("div", { class: "field" }, el("label", {}, "Add a known service"), select),
            el("button", { class: "btn", type: "button", onclick: () => addTerm(select.value) }, "Add"),
            el("div", { class: "field" }, el("label", {}, "…or add anything else"), custom),
            el("button", { class: "btn secondary", type: "button", onclick: () => addTerm(custom.value.trim()) }, "Add")),
          note,
          inputError ? el("div", { class: "error-box", style: "margin:10px 0 0" }, inputError) : null,
          el("div", { class: "hint", style: "margin-top:8px" }, "Lookup cost includes everything nested inside an include. Over 10 in total breaks SPF for every message, so remove senders that no longer send mail first.")),
      ], { flush: true }),
      card("Everyone not listed", el("div", { class: "bld-opts" }, allOpts)),
      el("div", { class: "hint" }, link("spf", { d: cur.domain }, "Open the published record in SPF Inspector →")),
    );
  };

  rebuild();
  return root;
}

/* ============================================================== DMARC BUILDER */
const DMARC_STAGES = [
  { id: "monitor", title: "1 · Monitor", desc: "p=none: collect reports, block nothing (2–4 weeks).", p: "none", pct: 100 },
  { id: "q25", title: "2 · Quarantine 25%", desc: "Junk a quarter of failing mail; watch for complaints.", p: "quarantine", pct: 25 },
  { id: "q100", title: "3 · Quarantine 100%", desc: "All failing mail to junk/quarantine.", p: "quarantine", pct: 100 },
  { id: "reject", title: "4 · Reject", desc: "Failing mail is refused outright. The goal.", p: "reject", pct: 100 },
];

function renderDmarcBuildTool(main, params) {
  const out = el("div");
  main.append(card(null, hashForm("dmarcbuild", [
    { name: "d", label: "Domain", placeholder: "contoso.com", grow: true, required: true },
  ], params, "Load DMARC")), out);
  const domain = params.get("d");
  if (!domain) {
    out.append(el("div", { class: "hint" }, "Loads the current DMARC record and checks SPF/DKIM readiness, then walks you through the safe rollout from monitoring to reject."));
    return;
  }
  runInto(out, `Loading DMARC, SPF and DKIM for ${domain}…`, () => api(`/api/builder/dmarc/${encodeURIComponent(domain)}`), (cur) => dmarcBuilderUI(cur));
}

function dmarcBuilderUI(cur) {
  const d = cur.defaults;
  const state = { p: d.p, pct: Number(d.pct) || 100, sp: d.sp === d.p ? "" : d.sp, rua: d.rua.map((x) => x.replace(/^mailto:/i, "")).join(", "),
    ruf: d.ruf.map((x) => x.replace(/^mailto:/i, "")).join(", "), adkim: d.adkim, aspf: d.aspf, fo: d.fo };
  if (!state.rua) state.rua = `dmarc-reports@${cur.domain}`;
  const root = el("div"), top = el("div"), form = el("div");
  root.append(top, form);
  let seq = 0, timer = null;
  const split = (s) => s.split(/[,;\s]+/).map((x) => x.trim()).filter(Boolean);

  const rebuild = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const my = ++seq;
      try {
        const b = await api("/api/builder/dmarc", { body: { domain: cur.domain, p: state.p, sp: state.sp, pct: Number(state.pct), rua: split(state.rua), ruf: split(state.ruf), adkim: state.adkim, aspf: state.aspf, fo: state.fo } });
        if (my !== seq) return;
        const rd = b.readiness;
        top.replaceChildren(...[
          verdict(b.severity, b.headline, b.subline),
          facts([["SPF", rd.spf_ok ? `OK (${rd.spf_lookups}/10 lookups)` : "missing or broken"],
            ["DKIM", rd.dkim_ok ? `keys on ${rd.dkim_selectors.slice(0, 4).join(", ")}${rd.dkim_selectors.length > 4 ? "…" : ""}` : "none found"],
            ["Published", b.current ? (b.inherited ? "inherited from parent" : "yes") : "no record"]]),
          bldPublishCard({ ...b, added: [], removed: [] }, {
            replaceNote: b.current && !b.inherited ? `Replace the existing TXT record at _dmarc.${cur.domain}. Currently: ${b.current}` : `${cur.domain} has no DMARC record of its own yet, so add this as a new TXT record.`,
          }),
          b.findings.length ? card("Check before publishing", findingsList(b.findings), { flush: true }) : null,
          b.auth.length ? card("Report destinations", table(["Address", "Authorised?"], b.auth.map((a) => [
            el("span", { class: "mono" }, a.uri.slice(7)),
            !a.external ? badge("ok", "same domain") : a.authorized ? badge("ok", "authorised") : el("div", {}, badge("warning", "not authorised"), el("div", { class: "sub mono" }, `TXT ${a.check}`)),
          ])), { flush: true }) : null,
        ].filter(Boolean));
      } catch (e) {
        if (my === seq) top.replaceChildren(el("div", { class: "error-box" }, e.message));
      }
    }, 300);
  };

  const field = (label, input) => el("div", { class: "field" }, el("label", {}, label), input);
  const sel = (key, options) => {
    const s = el("select", {}, options.map(([v, l]) => el("option", { value: v, selected: String(state[key]) === String(v) }, l)));
    s.addEventListener("change", () => { state[key] = s.value; drawForm(); rebuild(); });
    return s;
  };
  const txtIn = (key, placeholder) => {
    const i = el("input", { type: "text", value: state[key], placeholder, spellcheck: "false" });
    i.addEventListener("input", () => { state[key] = i.value; rebuild(); });
    return i;
  };

  const drawForm = () => {
    const stageId = (DMARC_STAGES.find((s) => s.p === state.p && Number(s.pct) === Number(state.pct)) || {}).id;
    const pctIn = el("input", { type: "number", min: 0, max: 100, value: state.pct });
    pctIn.addEventListener("input", () => { state.pct = pctIn.value; rebuild(); });
    form.replaceChildren(
      card("Rollout stage", [
        el("div", { class: "bld-stages" }, DMARC_STAGES.map((s) => el("button", { type: "button", class: s.id === stageId ? "bld-stage on" : "bld-stage",
          onclick: () => { state.p = s.p; state.pct = s.pct; drawForm(); rebuild(); } }, el("b", {}, s.title), el("span", {}, s.desc)))),
        el("div", { class: "hint", style: "margin-top:8px" }, "Move one stage at a time. Before each step, check the aggregate reports: every legitimate sender (mail platform, marketing, CRM, invoicing) should pass SPF or DKIM aligned with this domain."),
      ]),
      card("Settings", el("div", { class: "bld-grid" },
        field("Policy (p)", sel("p", [["none", "none: monitor"], ["quarantine", "quarantine: junk"], ["reject", "reject: refuse"]])),
        field("Apply to % of failing mail (pct)", pctIn),
        field("Subdomains (sp)", sel("sp", [["", "same as p (recommended)"], ["none", "none"], ["quarantine", "quarantine"], ["reject", "reject"]])),
        field("Aggregate reports to (rua)", txtIn("rua", "dmarc@contoso.com, you@reporting-service.com")),
        field("Forensic reports to (ruf, optional)", txtIn("ruf", "rarely needed")),
        field("DKIM alignment", sel("adkim", [["r", "relaxed (recommended)"], ["s", "strict"]])),
        field("SPF alignment", sel("aspf", [["r", "relaxed (recommended)"], ["s", "strict"]])),
        field("Failure reporting (fo, only with ruf)", sel("fo", [["0", "0: all checks failed (default)"], ["1", "1: any check failed"], ["d", "d: DKIM failed"], ["s", "s: SPF failed"]])),
      )),
      el("div", { class: "hint" }, link("domain", { d: cur.domain }, "Full Domain Health check →"), "  ·  ", link("spfbuild", { d: cur.domain }, "Fix SPF in the SPF Builder →")),
    );
  };

  drawForm();
  rebuild();
  return root;
}

/* ============================================================== REGISTRATION */
registerTool({ category: "email", group: "Fix-it builders", id: "spfbuild", title: "SPF Builder", render: renderSpfBuildTool,
  icon: "M4 20h4L18.5 9.5a2.1 2.1 0 00-3-3L5 17zM13.5 6.5l3 3", keywords: "spf generator create fix record include add sender flatten lookup limit",
  desc: "Load a domain's SPF, add or remove senders from a list of common services, and get a corrected record that's validated against live DNS (lookup limit, broken includes) before you publish." });
registerTool({ category: "email", group: "Fix-it builders", id: "dmarcbuild", title: "DMARC Builder", render: renderDmarcBuildTool,
  icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7zM9 12h6M12 9v6", keywords: "dmarc generator create record policy reject quarantine rua rollout",
  desc: "Build the DMARC record for each rollout stage (monitor → quarantine → reject), with SPF/DKIM readiness checks and report-address authorisation checks." });
