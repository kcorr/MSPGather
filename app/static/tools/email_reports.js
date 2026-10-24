"use strict";
/* Email → Analyze: DMARC Report Analyzer (aggregate "rua" XML) + TLS-RPT summary.
   Files are read in the browser and sent as base64 in a JSON body; the server
   decompresses them with size limits and refuses XML with DOCTYPE/ENTITY. */

addStyles(`
.dmarcreport-drop { border: 2px dashed var(--border); border-radius: 10px; padding: 22px 16px; text-align: center; cursor: pointer; background: var(--panel); transition: border-color .15s, background .15s; }
.dmarcreport-drop:hover, .dmarcreport-drop.over { border-color: var(--accent); background: var(--accent-soft); }
.dmarcreport-drop-title { font-weight: 600; margin-bottom: 4px; }
.dmarcreport-files { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.dmarcreport-file { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--border); border-radius: 999px; padding: 3px 4px 3px 10px; font-size: 12.5px; background: var(--panel-2); max-width: 100%; }
.dmarcreport-file span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dmarcreport-file button { border: 0; background: transparent; color: var(--muted); cursor: pointer; font: inherit; padding: 0 6px; }
.dmarcreport-file.bad { border-color: var(--crit); color: var(--crit); }
.dmarcreport-paste { margin-top: 10px; }
.dmarcreport-paste textarea { width: 100%; min-height: 140px; margin-top: 8px; }
.dmarcreport-meter { position: relative; height: 16px; border-radius: 8px; background: var(--crit-soft); overflow: hidden; margin: 6px 0 4px; }
.dmarcreport-meter > span { display: block; height: 100%; background: var(--ok); }
.dmarcreport-meter.warn > span { background: var(--warn); }
.dmarcreport-mark { position: absolute; top: 0; bottom: 0; width: 2px; background: var(--text); opacity: .55; }
.dmarcreport-scale { position: relative; height: 16px; font-size: 11.5px; color: var(--muted); }
.dmarcreport-scale span { position: absolute; transform: translateX(-50%); white-space: nowrap; }
.dmarcreport-ready { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-top: 12px; }
.dmarcreport-ready > div { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
.dmarcreport-ready b { display: block; margin-bottom: 4px; }
.dmarcreport-split { display: flex; height: 10px; border-radius: 5px; overflow: hidden; margin: 12px 0 6px; background: var(--panel-2); }
.dmarcreport-split > span { display: block; height: 100%; }
.dmarcreport-legend { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 12.5px; color: var(--muted); }
.dmarcreport-legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; vertical-align: -1px; }
.dmarcreport-domains { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }
.dmarcreport-section { margin-top: 26px; }
.dmarcreport-section > h2 { font-size: 15px; margin: 0 0 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.dmarcreport-list { margin: 0; padding: 0; list-style: none; }
.dmarcreport-list li { overflow-wrap: anywhere; }
`);

const DMARCREPORT_MAX_FILE = 10 * 1024 * 1024;
const DMARCREPORT_SAMPLES = [
  "dmarcreport-contoso-google.xml", "dmarcreport-contoso-microsoft.xml", "dmarcreport-fabrikam-yahoo.xml", "dmarcreport-tlsrpt-contoso.json",
];
const DMARCREPORT_CATS = {
  aligned: { label: "Legitimate & aligned", sev: "ok", color: "var(--ok)" },
  legit_failing: { label: "Legitimate, failing", sev: "critical", color: "var(--crit)" },
  forwarding: { label: "Forwarding / list", sev: "info", color: "var(--info)" },
  spoofing: { label: "Likely spoofing", sev: "warning", color: "var(--warn)" },
};

function dmarcreportB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

const dmarcreportNum = (n) => (n == null ? "—" : Number(n).toLocaleString());
const dmarcreportPct = (a, b) => (b ? `${((a / b) * 100).toFixed(a === b || a === 0 ? 0 : 1)}%` : "—");
const dmarcreportMono = (t) => el("span", { class: "mono" }, t);
const dmarcreportLines = (arr, mono = true) => (arr && arr.length ? el("ul", { class: "dmarcreport-list" }, arr.map((x) => el("li", { class: mono ? "mono" : null }, x))) : el("span", { class: "sub" }, "—"));

/* ================================================================== INPUT UI */
function renderDmarcReportTool(main, params) {
  const files = [];  // {name, size, data_b64 | null, error}
  const out = el("div");
  const list = el("div", { class: "dmarcreport-files" });
  const picker = el("input", { type: "file", multiple: true, accept: ".xml,.gz,.zip,.json,application/xml,text/xml,application/gzip,application/zip,application/json", style: "display:none" });
  const ta = el("textarea", { placeholder: "<?xml version=\"1.0\"?><feedback>…</feedback>   or a TLS-RPT JSON report", spellcheck: "false" });
  const paste = el("details", { class: "dmarcreport-paste" }, el("summary", {}, "…or paste report XML / JSON"), ta);

  const drawList = () => {
    list.replaceChildren(...files.map((f, i) => el("span", { class: f.error ? "dmarcreport-file bad" : "dmarcreport-file", title: f.error || f.name },
      el("span", {}, `${f.name} · ${f.size < 1024 ? f.size + " B" : (f.size / 1024).toFixed(f.size < 102400 ? 1 : 0) + " KB"}${f.error ? " · " + f.error : ""}`),
      el("button", { type: "button", "aria-label": `Remove ${f.name}`, onclick: () => { files.splice(i, 1); drawList(); } }, "×"))));
  };

  const addFiles = async (fileList) => {
    for (const f of [...fileList]) {
      if (files.length >= 300) break;
      const entry = { name: f.name, size: f.size, data_b64: null, error: null };
      if (f.size > DMARCREPORT_MAX_FILE) entry.error = "over 10 MB";
      else if (!/\.(xml|gz|zip|json)$/i.test(f.name)) entry.error = "not .xml/.gz/.zip/.json";
      else {
        try { entry.data_b64 = dmarcreportB64(await f.arrayBuffer()); } catch (e) { entry.error = "could not read"; }
      }
      files.push(entry);
    }
    drawList();
  };

  const drop = el("div", { class: "dmarcreport-drop", tabindex: "0", role: "button" },
    el("div", { class: "dmarcreport-drop-title" }, "Drop DMARC aggregate reports here, or click to choose files"),
    el("div", { class: "hint" }, ".xml, .xml.gz, .zip (as emailed by Google, Microsoft, Yahoo…) and TLS-RPT .json / .json.gz. Several at once is best: a week or more of reports gives a reliable answer. Max 10 MB per file."));
  drop.addEventListener("click", () => picker.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } });
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files); });
  picker.addEventListener("change", () => { addFiles(picker.files); picker.value = ""; });

  let lastBody = null;
  const go = (domain) => {
    const good = files.filter((f) => f.data_b64);
    const body = domain && lastBody ? { ...lastBody, domain } : { files: good.map((f) => ({ name: f.name, data_b64: f.data_b64 })), text: ta.value };
    if (!body.files.length && !body.text.trim()) {
      out.replaceChildren(el("div", { class: "error-box" }, files.length ? "None of the chosen files can be used (see the red ones above)." : "Add some report files or paste a report first."));
      return;
    }
    lastBody = { ...body, domain: undefined };
    runInto(out, "Unpacking reports and identifying senders (reverse DNS for the top 60 IPs)…",
      () => api("/api/dmarcreport/analyze", { body }), (d) => renderDmarcReportResult(d, go));
  };
  const loadSamples = async () => {
    files.length = 0;
    for (const name of DMARCREPORT_SAMPLES) {
      try {
        const buf = await (await fetch(`samples/${name}`)).arrayBuffer();
        files.push({ name, size: buf.byteLength, data_b64: dmarcreportB64(buf), error: null });
      } catch (e) { files.push({ name, size: 0, data_b64: null, error: "could not load" }); }
    }
    drawList();
    go();
  };
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); });

  main.append(card(null, [drop, picker, list, paste, el("div", { class: "btn-row" },
    el("button", { class: "btn", type: "button", onclick: () => go() }, "Analyze"),
    el("button", { class: "btn secondary", type: "button", onclick: loadSamples }, "Load samples (contoso.com + TLS-RPT)"),
    el("button", { class: "btn secondary", type: "button", onclick: () => { files.length = 0; ta.value = ""; lastBody = null; drawList(); out.replaceChildren(); } }, "Clear"))]), out);
  if (params.get("sample") === "1") loadSamples();
}

/* ==================================================================== RESULT */
function renderDmarcReportResult(d, rerun) {
  const frag = el("div");
  if (d.dmarc) frag.append(dmarcreportDmarc(d.dmarc, rerun));
  if (d.tlsrpt) {
    const t = dmarcreportTls(d.tlsrpt);
    frag.append(d.dmarc ? el("div", { class: "dmarcreport-section" }, el("h2", {}, "TLS-RPT (SMTP TLS reports)"), t) : t);
  }
  const inp = d.inputs;
  const parts = [`${inp.files} upload${inp.files === 1 ? "" : "s"}`, `${inp.documents} document${inp.documents === 1 ? "" : "s"}`,
    `${inp.dmarc_reports} DMARC report${inp.dmarc_reports === 1 ? "" : "s"}`, `${inp.tls_reports} TLS-RPT report${inp.tls_reports === 1 ? "" : "s"}`];
  if (inp.duplicates) parts.push(`${inp.duplicates} duplicate${inp.duplicates === 1 ? "" : "s"} skipped`);
  frag.append(card(`Input (${parts.join(" · ")})`, inp.problems.length
    ? table(["File", "Problem"], inp.problems.map((p) => [dmarcreportMono(p.name), p.reason]), () => "hl")
    : el("div", { class: "card-body hint" }, `Every file was read. ${inp.decompressed_mb} MB after decompression.`), { flush: true }));
  return frag;
}

function dmarcreportMeter(r) {
  const pct = r.legit_pass_pct;
  const meter = el("div", { class: pct >= 99 ? "dmarcreport-meter" : "dmarcreport-meter warn" }, el("span"));
  // The interesting part of the scale is 80–100%, so stretch it: 0–80% gets the first 20% of the bar.
  const pos = (p) => (p <= 80 ? (p / 80) * 20 : 20 + ((p - 80) / 20) * 80);
  meter.firstChild.style.width = `${pos(pct)}%`;
  meter.append(el("div", { class: "dmarcreport-mark", style: `left:${pos(95)}%`, title: "95%: quarantine threshold" }),
    el("div", { class: "dmarcreport-mark", style: `left:${pos(99)}%`, title: "99%: reject threshold" }));
  const scale = el("div", { class: "dmarcreport-scale" }, [[0, "0%"], [80, "80%"], [95, "quarantine 95%"], [99, "reject 99%"]].map(([p, l]) =>
    el("span", { style: `left:${Math.min(pos(p), 96)}%${p === 0 ? ";transform:none" : ""}` }, l)));
  return [meter, scale];
}

function dmarcreportDmarc(d, rerun) {
  const frag = el("div");
  const t = d.totals, r = d.readiness, pol = d.policy;
  if (d.domains.length > 1) {
    frag.append(el("div", { class: "dmarcreport-domains" }, el("span", { class: "hint" }, "Reports cover several domains:"),
      d.domains.map((x) => el("button", { type: "button", class: x.domain === d.domain ? "btn" : "btn secondary", onclick: () => x.domain !== d.domain && rerun(x.domain) },
        `${x.domain} (${dmarcreportNum(x.messages)})`))));
  }
  frag.append(verdict(d.severity, d.headline, d.subline));
  frag.append(facts([
    ["Domain", d.domain],
    ["Messages", dmarcreportNum(t.messages)],
    ["DMARC pass", `${t.dmarc_pass_pct}%`],
    ["Period", d.date_begin ? `${d.date_begin.slice(0, 10)} → ${d.date_end.slice(0, 10)}${d.days ? ` (${d.days} days)` : ""}` : null],
    ["Policy", `p=${pol.p || "?"}${pol.pct && pol.pct !== "100" ? ` pct=${pol.pct}` : ""}${pol.sp && pol.sp !== pol.p ? ` sp=${pol.sp}` : ""}`],
    ["Reporters", d.reporters.map((x) => x.name).slice(0, 4).join(", ") + (d.reporters.length > 4 ? "…" : "")],
  ]));

  // ---- readiness
  const split = el("div", { class: "dmarcreport-split" }, ["aligned", "legit_failing", "forwarding", "spoofing"].map((k) => {
    const v = k === "aligned" ? t.aligned : k === "legit_failing" ? t.legit_failing : k === "forwarding" ? t.forwarding : t.spoofing;
    return v ? el("span", { style: `width:${(v / t.messages) * 100}%;background:${DMARCREPORT_CATS[k].color}`, title: `${DMARCREPORT_CATS[k].label}: ${dmarcreportNum(v)}` }) : null;
  }));
  const legend = el("div", { class: "dmarcreport-legend" }, [["aligned", t.aligned], ["legit_failing", t.legit_failing], ["forwarding", t.forwarding], ["spoofing", t.spoofing]]
    .map(([k, v]) => el("span", {}, el("i", { style: `background:${DMARCREPORT_CATS[k].color}` }), `${DMARCREPORT_CATS[k].label}: ${dmarcreportNum(v)} (${dmarcreportPct(v, t.messages)})`)));
  const readyBox = (label, ok, extra) => el("div", {}, el("b", {}, label), badge(ok ? "ok" : "critical", ok ? "Ready" : "Not yet"), el("div", { class: "sub", style: "margin-top:4px" }, extra));
  frag.append(card("Ready for p=quarantine / p=reject?", [
    el("div", {}, el("strong", {}, `${r.legit_pass_pct}%`), ` of legitimate mail passes DMARC (${dmarcreportNum(r.legit_pass)} of ${dmarcreportNum(r.legit_total)}); `,
      el("strong", {}, `${r.legit_fail_pct}%`), " would be junked or rejected."),
    dmarcreportMeter(r),
    el("div", { class: "dmarcreport-ready" },
      readyBox("p=quarantine", r.ready_quarantine, r.ready_quarantine ? "Under 5% of legitimate mail fails." : `${r.legit_fail_pct}% of legitimate mail would go to junk.`),
      readyBox("p=reject", r.ready_reject, r.ready_reject ? "Under 1% of legitimate mail fails." : `${r.legit_fail_pct}% of legitimate mail would be refused.`),
      el("div", {}, el("b", {}, "Spoofing that enforcement stops"), el("div", { class: "s-value small" }, `${dmarcreportNum(t.spoofing)} messages`),
        el("div", { class: "sub" }, `from ${t.spoofing_ips} IP${t.spoofing_ips === 1 ? "" : "s"}`))),
    split, legend,
    el("div", { class: "hint", style: "margin-top:8px" }, "Legitimate = everything that passed DMARC plus failing mail from recognised senders (known platforms, your own servers). Forwarded mail that lost its DKIM signature and likely spoofing are not counted."),
  ]));

  frag.append(card("Findings", findingsList(d.findings), { flush: true }));

  const steps = d.steps.map((s) => ({ title: s.title, commands: s.commands,
    detail: [s.detail, s.link ? [" ", link(s.link.tool, s.link.params, s.link.text)] : null] }));
  const ns = nextSteps(steps);
  if (ns) frag.append(ns);
  frag.append(el("div", { class: "hint", style: "margin:-4px 0 14px" },
    link("dmarcbuild", { d: d.domain }, "Build the next DMARC record in the DMARC Builder →"), "  ·  ",
    link("spfbuild", { d: d.domain }, "SPF Builder →"), "  ·  ", link("domain", { d: d.domain }, "Domain Health →")));

  // ---- details: senders
  const S = d.senders;
  frag.append(card(`Senders (${S.length})`, table(["Sender", "Classification", "Messages", "DMARC pass", "SPF / DKIM aligned", "DKIM d= (selector)", "Envelope from", "Source IPs"],
    S.map((s) => [
      el("div", {}, el("strong", {}, s.name), s.via ? el("div", { class: "sub" }, `identified by ${s.via}`) : null),
      badge(DMARCREPORT_CATS[s.category].sev, DMARCREPORT_CATS[s.category].label),
      dmarcreportNum(s.count),
      dmarcreportPct(s.pass, s.count),
      `${dmarcreportPct(s.spf_aligned, s.count)} / ${dmarcreportPct(s.dkim_aligned, s.count)}`,
      s.dkim_domains.length ? dmarcreportLines(s.dkim_domains.map((x, i) => (i === 0 && s.selectors.length ? `${x} (${s.selectors.join(", ")})` : x))) : el("span", { class: "sub" }, "not signed"),
      dmarcreportLines(s.envelope_from),
      el("div", {}, s.ips.slice(0, 5).map((ip) => el("div", { class: "mono" }, link("ip", { t: ip, d: d.domain }, ip))),
        s.ip_count > 5 ? el("div", { class: "sub" }, `+${s.ip_count - 5} more`) : null),
    ]), (i) => (S[i].category === "legit_failing" || S[i].category === "spoofing" ? "hl" : null)), { flush: true }));

  // ---- details: reporters
  frag.append(card("Who sent the reports", table(["Reporter", "Reports", "Messages", "DMARC pass"],
    d.reporters.map((x) => [el("div", {}, x.name, x.orgs.length && x.orgs.join(", ") !== x.name ? el("div", { class: "sub" }, x.orgs.join(", ")) : null),
      String(x.reports), dmarcreportNum(x.messages), dmarcreportPct(x.pass, x.messages)])), { flush: true }));

  // ---- details: source IPs
  const ipRows = d.ips;
  const ipTable = table(["Source IP", "Reverse DNS / owner", "Sender", "Classification", "Messages", "SPF / DKIM aligned", "Raw SPF", "Raw DKIM", "Disposition", "Header / envelope from"],
    ipRows.map((x) => [
      dmarcreportMono(link("ip", { t: x.ip, d: d.domain }, x.ip)),
      x.ptr ? dmarcreportMono(x.ptr) : el("span", { class: "sub" }, x.special || (x.as_name ? x.as_name : x.looked_up ? "no reverse DNS" : "not looked up")),
      x.sender,
      badge(DMARCREPORT_CATS[x.category].sev, DMARCREPORT_CATS[x.category].label),
      dmarcreportNum(x.count),
      `${dmarcreportPct(x.spf_aligned, x.count)} / ${dmarcreportPct(x.dkim_aligned, x.count)}`,
      Object.keys(x.spf_raw).length ? el("div", {}, Object.entries(x.spf_raw).map(([k]) => badge(resultSev(k), k))) : el("span", { class: "sub" }, "—"),
      dmarcreportLines(x.dkim_raw),
      el("div", {}, Object.entries(x.disposition).map(([k, v]) => el("div", {}, `${k}: ${dmarcreportNum(v)}`)),
        x.reasons.length ? el("div", { class: "sub" }, x.reasons.join("; ")) : null),
      el("div", {}, dmarcreportLines(x.header_from), x.envelope_from.length && x.envelope_from.join() !== x.header_from.join() ? el("div", { class: "sub mono" }, "env: " + x.envelope_from.join(", ")) : null),
    ]), (i) => (ipRows[i].category === "legit_failing" || ipRows[i].category === "spoofing" ? "hl" : null));
  frag.append(card(`Source IPs (${d.ips_total}${d.ips_total > ipRows.length ? `, top ${ipRows.length} shown` : ""})`,
    el("details", {}, el("summary", { style: "padding:10px 16px;cursor:pointer" }, "Show every source IP with raw SPF/DKIM results"), ipTable), { flush: true }));

  frag.append(card(`Reports (${d.reports.length})`, el("details", {}, el("summary", { style: "padding:10px 16px;cursor:pointer" }, "Show report list"),
    table(["Reporter", "Report ID", "Period", "Policy", "Records", "Messages", "File"], d.reports.map((x) => [
      x.org, dmarcreportMono(x.report_id || "—"), x.begin ? `${fmtTime(x.begin)} → ${fmtTime(x.end)}` : "—", `p=${x.p || "?"}`,
      String(x.records), dmarcreportNum(x.messages), dmarcreportMono(x.file)]))), { flush: true }));
  return frag;
}

/* ===================================================================== TLS-RPT */
function dmarcreportTls(d) {
  const frag = el("div");
  const t = d.totals;
  frag.append(verdict(d.severity, d.headline, d.subline));
  frag.append(facts([["Successful sessions", dmarcreportNum(t.success)], ["Failed sessions", dmarcreportNum(t.failure)], ["Failure rate", `${t.fail_pct}%`],
    ["Domains", d.domains.join(", ")]]));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  if (d.failure_types.length) {
    frag.append(card("Failure types, in plain English", table(["Result type", "Sessions", "What it means / fix"],
      d.failure_types.map((f) => [dmarcreportMono(f.type), dmarcreportNum(f.count), f.explain]), () => "hl"), { flush: true }));
  }
  frag.append(card("By policy domain", table(["Domain", "Policy", "MX hosts", "Successful", "Failed", "Reporters"],
    d.policies.map((p) => [p.domain ? link("domain", { d: p.domain }, p.domain) : "—", dmarcreportMono(p.type),
      dmarcreportLines(p.mx_hosts), dmarcreportNum(p.success), dmarcreportNum(p.failure), p.reporters.join(", ")]),
    (i) => (d.policies[i].failure ? "hl" : null)), { flush: true }));
  if (d.mx_failures.length) {
    frag.append(card("Failing MX hosts", table(["MX host", "Failed sessions", "Test it"],
      d.mx_failures.map((m) => [dmarcreportMono(m.mx), dmarcreportNum(m.count),
        el("span", {}, link("smtp", { t: m.mx, port: "25" }, "SMTP test"), "  ·  ", link("tls", { h: `${m.mx}:25` }, "TLS check"))]), () => "hl"), { flush: true }));
  }
  frag.append(card(`TLS-RPT reports (${d.reports.length})`, table(["Reporter", "Report ID", "Period", "Successful", "Failed", "File"],
    d.reports.map((x) => [x.org, dmarcreportMono(x.report_id || "—"), `${x.start ? x.start.slice(0, 10) : "?"} → ${x.end ? x.end.slice(0, 10) : "?"}`,
      dmarcreportNum(x.success), dmarcreportNum(x.failure), dmarcreportMono(x.file)])), { flush: true }));
  return frag;
}

/* ============================================================== REGISTRATION */
registerTool({ category: "email", group: "Analyze", id: "dmarcreport", title: "DMARC Report Analyzer", render: renderDmarcReportTool,
  icon: "M4 20V10M10 20V4M16 20v-7M22 20H2", keywords: "dmarc aggregate report rua xml gz zip analyze senders spoofing alignment reject quarantine readiness tls-rpt tlsrpt mta-sts",
  desc: "Drop DMARC aggregate reports (XML, .gz, .zip) to see who sends as the domain, which legitimate senders fail and how to fix each, what is spoofing, and whether it's ready for p=reject. TLS-RPT reports are summarised too." });
