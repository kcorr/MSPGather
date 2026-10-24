"use strict";
/* Microsoft 365 tools: Autodiscover Walkthrough, Endpoint Connectivity. */

addStyles(`
.autodiscover-walk { list-style: none; margin: 0; padding: 0; }
.autodiscover-walk li { display: grid; grid-template-columns: 34px 1fr auto; gap: 12px; padding: 12px 16px; border-top: 1px solid var(--border); align-items: start; }
.autodiscover-walk li:first-child { border-top: 0; }
.autodiscover-walk .ad-num { width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; font-weight: 650; font-size: 13px; background: var(--panel-2); border: 1px solid var(--border); }
.autodiscover-walk li.ad-answers .ad-num { background: var(--ok); color: #fff; border-color: var(--ok); }
.autodiscover-walk li.ad-bad .ad-num { background: var(--crit); color: #fff; border-color: var(--crit); }
.autodiscover-walk li.ad-slow .ad-num { background: var(--warn); color: #fff; border-color: var(--warn); }
.autodiscover-walk li.ad-unreached { opacity: .55; }
.autodiscover-walk .ad-label { font-weight: 650; }
.autodiscover-walk .ad-summary { margin-top: 2px; }
.autodiscover-walk .ad-detail { color: var(--muted); font-size: 12.5px; margin-top: 2px; }
.autodiscover-walk .ad-stop { margin-top: 6px; font-size: 12px; font-weight: 650; color: var(--ok); }
.autodiscover-walk .ad-reg { font-size: 11.5px; color: var(--muted); margin-top: 4px; }
.autodiscover-step { border-top: 1px solid var(--border); }
.autodiscover-step:first-child { border-top: 0; }
.autodiscover-step > summary { cursor: pointer; padding: 10px 16px; font-weight: 600; list-style-position: inside; }
.autodiscover-step > summary .sub { font-weight: 400; margin-left: 6px; }
.autodiscover-step > .ad-body { padding: 0 16px 12px; }
.m365net-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: 10px; }
.m365net-script > summary { cursor: pointer; margin-top: 10px; color: var(--accent); }
.m365net-label { display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; background: var(--warn-soft); color: var(--warn); margin-bottom: 10px; }
.m365net-problems .badge { margin: 0 4px 3px 0; white-space: normal; display: inline-block; }
.m365net-host .mono { word-break: break-all; }
.m365net-table td { white-space: normal; }
`);

/* ====================================================== AUTODISCOVER WALKTHROUGH */
const AUTODISCOVER_STATE = {
  answers: ["ok", "Answers"],
  fails_fast: ["muted", "Skipped (fast)"],
  slow: ["warning", "Slow / timeout"],
  cert_prompt: ["critical", "Certificate prompt"],
  cred_prompt: ["critical", "Password prompt"],
  redirect: ["info", "Redirect"],
};

function renderAutodiscoverTool(main, params) {
  const out = el("div");
  main.append(card(null, hashForm("autodiscover", [
    { name: "t", label: "Email address (best) or domain", placeholder: "user@contoso.com", grow: true, required: true },
  ], params, "Walk Autodiscover")), out);
  const t = params.get("t");
  if (t) runInto(out, `Testing every Autodiscover step for ${t}… (up to 8 s per step, run in parallel)`,
    () => api(`/api/m365/autodiscover?target=${encodeURIComponent(t)}`), renderAutodiscoverResult);
}

function autodiscoverCertRows(tls) {
  if (!tls) return [];
  const c = tls.certificate || {};
  return [
    ["TLS", `${tls.version || "?"} ${tls.cipher || ""}`],
    ["Certificate for", c.san && c.san.length ? c.san.slice(0, 8).join(", ") + (c.san.length > 8 ? ` (+${c.san.length - 8} more)` : "") : c.subject],
    ["Name matches host", c.hostname_match === undefined ? null : c.hostname_match ? badge("ok", "yes") : badge("critical", "NO")],
    ["Trusted chain", tls.trusted ? badge("ok", "yes") : el("span", {}, badge("critical", "no"), " ", tls.trust_error || "")],
    ["Issuer", c.issuer],
    ["Expires", c.not_after ? el("span", {}, fmtTime(c.not_after), " ", c.expired ? badge("critical", "expired") : c.days_left < 30 ? badge("warning", `${c.days_left} days`) : el("span", { class: "sub" }, `(${c.days_left} days)`)) : null],
    ["Thumbprint", c.thumbprint ? el("span", { class: "mono" }, c.thumbprint) : null],
  ];
}

function autodiscoverStepDetails(s) {
  const p = s.probe || {};
  let rows;
  if (s.id === "srv") {
    rows = [["Query", el("span", { class: "mono" }, p.name)], ["DNS status", p.status],
      ["Records", p.records && p.records.length ? p.records.map((r) => el("div", { class: "mono" }, `${r.priority} ${r.weight} ${r.port} ${r.target}`)) : "none"]];
  } else {
    const d = p.dns || {};
    const h = p.http;
    rows = [
      ["URL", el("span", { class: "mono" }, `${p.method || "GET"} ${p.url}`)],
      ["DNS", d.addresses && d.addresses.length ? el("span", { class: "mono" }, d.addresses.slice(0, 6).join(", ")) : (d.status || "—")],
      ["CNAME / canonical name", d.cname ? el("span", { class: "mono" }, d.cname) : null],
      ["Refused (outbound safety)", p.unsafe && Object.keys(p.unsafe).length ? Object.entries(p.unsafe).map(([ip, why]) => `${ip} (${why})`).join(", ") : null],
      ["Connected to", p.ip ? el("span", {}, el("span", { class: "mono" }, link("ip", { t: p.ip }, p.ip)), p.tcp_ms != null ? ` in ${p.tcp_ms} ms` : "") : null],
      ["TLS handshake", p.tls_ms != null ? `${p.tls_ms} ms` : null],
      ...autodiscoverCertRows(p.tls),
      ["Microsoft 365 internal redirects", p.internal_redirects && p.internal_redirects.length ? p.internal_redirects.map((u) => el("div", { class: "mono" }, u)) : null],
      ["HTTP status", h ? `${h.status} ${h.reason || ""}` : null],
      ["Response type", h ? h.kind : null],
      ["Server", h ? h.server : null],
      ["Content-Type", h ? h.content_type : null],
      ["Location", h && h.location ? el("span", { class: "mono" }, h.location) : null],
      ["WWW-Authenticate", h ? h.www_authenticate : null],
      ["Exchange headers", h && h.exchange_headers && Object.keys(h.exchange_headers).length
        ? Object.entries(h.exchange_headers).map(([k, v]) => el("div", { class: "mono" }, `${k}: ${v}`)) : null],
      ["Error", p.error],
      ["Total time", p.total_ms != null ? `${p.total_ms} ms` : null],
    ];
  }
  const h = p.http;
  return el("details", { class: "autodiscover-step" },
    el("summary", {}, s.label, el("span", { class: "sub" }, s.assess.summary)),
    el("div", { class: "ad-body" }, kv(rows), h && h.body_snippet ? [el("div", { class: "hint" }, "Response body (first 600 bytes)"), code(h.body_snippet)] : null));
}

function renderAutodiscoverResult(d) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  const t = d.tenant || {};
  const consumer = (t.auth_url || "").includes("login.live.com");
  frag.append(facts([
    ["Tested as", d.email + (d.real_email ? "" : " (placeholder)")],
    ["Mailbox in Microsoft 365", d.in_m365 ? "Yes" : "No"],
    ["Tenant", consumer ? "Consumer (Microsoft account)" : t.tenant_id || "None found"],
    ["Sign-in", consumer ? null : t.namespace_type ? t.namespace_type + (t.federation_brand ? ` (${t.federation_brand})` : "") : null],
    ["autodiscover DNS", d.autodiscover_dns.cname ? `CNAME → ${d.autodiscover_dns.cname}` : d.autodiscover_dns.addresses.length ? `A ${d.autodiscover_dns.addresses[0]}` : "none"],
    ["MX", d.mx && d.mx.length ? d.mx[0] : "none"],
  ]));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  const ns = nextSteps(d.fixes);
  if (ns) frag.append(ns);

  // The walk, in Outlook's order. Outlook stops at the first step that answers.
  let stopped = false;
  const items = d.steps.map((s, i) => {
    const [sev, label] = AUTODISCOVER_STATE[s.assess.state] || ["info", s.assess.state];
    const answers = s.assess.state === "answers";
    const unreached = stopped;
    const cls = ["ad-" + (answers ? "answers" : sev === "critical" ? "bad" : sev === "warning" ? "slow" : "other"), unreached ? "ad-unreached" : ""].join(" ");
    const li = el("li", { class: cls },
      el("div", { class: "ad-num" }, String(i + 1)),
      el("div", {},
        el("div", { class: "ad-label" }, s.label),
        el("div", { class: "mono sub" }, s.target),
        el("div", { class: "ad-summary" }, s.assess.summary),
        s.assess.detail ? el("div", { class: "ad-detail" }, s.assess.detail) : null,
        answers && !stopped ? el("div", { class: "ad-stop" }, "✓ Outlook stops here" + (i === 0 ? " (Outlook for Windows); other clients continue below" : "")) : null,
        unreached ? el("div", { class: "ad-reg" }, "Not reached: an earlier step already answered.") : null,
        el("div", { class: "ad-reg" }, "Skip with registry value ", el("span", { class: "mono" }, `${s.reg}=1`))),
      el("div", {}, badge(sev, label)));
    // Direct Connect only stops Outlook for Windows; show the fallback walk for other clients.
    if (answers && i > 0) stopped = true;
    if (answers && i === 0) stopped = false;
    return li;
  });
  frag.append(card("Walkthrough in Outlook's order", [
    el("div", { class: "card-body hint" }, d.order_note),
    el("ol", { class: "autodiscover-walk" }, items),
  ], { flush: true }));

  frag.append(card("Technical details per step", d.steps.map(autodiscoverStepDetails), { flush: true }));
  frag.append(el("div", { class: "hint" }, "Related: ", link("domain", { d: d.domain }, `Domain Health for ${d.domain}`),
    " · Microsoft's Remote Connectivity Analyzer (authenticated tests): https://testconnectivity.microsoft.com"));
  return frag;
}

/* ===================================================== ENDPOINT CONNECTIVITY */
function m365netDn(dn, key) {
  const m = new RegExp(`(?:^|,)\\s*${key}\\s*=\\s*("[^"]*"|[^,]*)`, "i").exec(dn || "");
  return m ? m[1].trim().replace(/^"|"$/g, "") : null;
}

function renderM365netTool(main, params) {
  const tenant = params.get("tenant") || "";
  const scriptBox = el("div", {}, el("div", { class: "hint" }, "Loading script…"));
  const resultOut = el("div");
  const serverOut = el("div");

  main.append(el("div", { class: "notice" },
    "Run the collector on the affected machine (as the affected user), paste its output below, and get a verdict on TLS inspection, blocked endpoints, slow handshakes and proxy mismatches. ",
    "The optional server check at the bottom shows what the same endpoints look like from the MSPGather server, as a clean baseline."));

  main.append(card("1. Run this on the affected machine", [
    hashForm("m365net", [
      { name: "tenant", label: "Tenant name (optional, adds <tenant>.sharepoint.com)", placeholder: "contoso", grow: true },
    ], params, "Update script"),
    scriptBox,
  ]));

  const paste = pasteBox({
    placeholder: "2. Paste the collector output here (everything from -----BEGIN MSPGATHER M365 NETWORK----- to -----END…-----)",
    runLabel: "Analyze",
    sample: async () => (await fetch("samples/m365net-tls-inspection.txt")).text(),
    sampleLabel: "Load sample (TLS inspection)",
    onRun: (raw) => runInto(resultOut, "Analyzing…", () => api("/api/m365/net/analyze", { body: { raw } }), renderM365netResult),
    rows: 8,
  });
  main.append(el("h2", { style: "font-size:15px;margin:22px 0 8px" }, "2. Paste the output"), paste.element, resultOut);

  const serverBtn = el("button", { class: "btn secondary", type: "button", onclick: () => runInto(serverOut, "Testing the same endpoints from the MSPGather server…",
    () => api(`/api/m365/net/server${tenant ? "?tenant=" + encodeURIComponent(tenant) : ""}`), renderM365netServerResult) }, "Run server-side check");
  main.append(card("Compare: from the MSPGather server, not the user's machine", [
    el("div", { class: "hint" }, "Tests DNS, TCP 443 and the TLS certificate for the same endpoints from where MSPGather runs. If the server sees a Microsoft/DigiCert issuer and the user's machine sees something else, the user's network is intercepting TLS."),
    el("div", { class: "m365net-actions" }, serverBtn),
  ]), serverOut);

  api(`/api/m365/net/script${tenant ? "?tenant=" + encodeURIComponent(tenant) : ""}`).then((d) => {
    const copyBtn = el("button", { class: "btn", type: "button" }, "Copy script");
    copyBtn.addEventListener("click", () => copyText(d.script, copyBtn));
    const dl = el("a", { class: "btn secondary", download: "mspgather-m365.ps1", href: URL.createObjectURL(new Blob([d.script], { type: "text/plain" })) }, "Download .ps1");
    scriptBox.replaceChildren(
      el("div", { class: "m365net-actions" }, copyBtn, dl,
        el("span", { class: "hint" }, `Tests ${d.endpoints.length} endpoints. Read-only, Windows PowerShell 5.1, no modules, finishes in under 60 s. Output is also copied to the clipboard.`)),
      el("div", { class: "hint", style: "margin-top:8px" }, "Paste into a Windows PowerShell window opened as the affected user (not \"Run as administrator\": the user's proxy settings matter). ",
        "If execution policy blocks the downloaded file: powershell -ExecutionPolicy Bypass -File .\\mspgather-m365.ps1"),
      el("details", { class: "m365net-script" }, el("summary", {}, "Show the script"), code(d.script)));
  }).catch((e) => scriptBox.replaceChildren(el("div", { class: "error-box" }, e.message)));
}

function m365netIssuerCell(r) {
  if (!r.issuer && !(r.proxied && r.proxied.issuer)) return el("span", { class: "sub" }, "—");
  const issuer = r.issuer || r.proxied.issuer;
  return el("div", {},
    el("div", {}, m365netDn(issuer, "CN") || issuer),
    el("div", { class: "sub" }, m365netDn(issuer, "O") || ""),
    r.vendor ? badge("critical", `intercepted: ${r.vendor}`) : null,
    r.proxied && r.proxied.issuer && r.proxied.issuer !== r.issuer ? el("div", { class: "sub" }, `via proxy: ${m365netDn(r.proxied.issuer, "CN") || r.proxied.issuer}`) : null);
}

function m365netMs(v, warnAt) {
  if (v == null) return el("span", { class: "sub" }, "—");
  return v > warnAt ? badge("warning", `${Math.round(v)} ms`) : `${Math.round(v)} ms`;
}

function m365netTable(rows) {
  return table(["Endpoint", "TCP 443", "TLS", "Certificate issuer", "Status"], rows.map((r) => [
    el("div", { class: "m365net-host" }, el("div", { class: "mono" }, r.host), el("div", { class: "sub" }, r.purpose || ""),
      el("div", { class: "sub mono", title: r.cnames.length ? "CNAME chain: " + r.cnames.join(" → ") : null },
        r.addresses.length ? `${r.addresses[0]}${r.addresses.length > 1 ? ` +${r.addresses.length - 1}` : ""}` : "DNS: no answer")),
    m365netMs(r.tcp_ms, 250),
    el("div", {}, m365netMs(r.tls_ms, 500), r.protocol ? el("div", { class: "sub" }, r.protocol) : null),
    m365netIssuerCell(r),
    el("div", { class: "m365net-problems" }, r.status === "skip" ? badge("muted", "not tested")
      : r.problems.length ? r.problems.map((p) => badge(r.status === "bad" ? "critical" : "warning", p)) : badge("ok", "OK"),
      r.proxied ? el("div", { class: "sub" }, `via proxy ${r.proxied.proxy || ""}: ${r.proxied.status || r.proxied.error || "?"}`) : null),
  ]), (i) => (rows[i].status === "bad" ? "hl" : null));
}

function renderM365netResult(d) {
  const frag = el("div");
  const m = d.machine || {};
  frag.append(verdict(d.severity, d.headline, d.subline));
  frag.append(facts([
    ["Machine", m.computer], ["User", m.user], ["Public IP", m.public_ip],
    ["WinHTTP", d.proxy.winhttp], ["WinINET (user)", d.proxy.wininet],
    ["Endpoints OK", `${d.ok_count}/${d.total}`],
  ]));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  const ns = nextSteps(d.fixes);
  if (ns) frag.append(ns);
  frag.append(card(`Endpoints as seen from ${m.computer || "the machine"}`, m365netTable(d.rows), { flush: true }));

  const px = d.proxy_raw || {};
  const wi = px.wininet || {};
  frag.append(card("Proxy settings", kv([
    ["WinHTTP (services, SYSTEM)", d.proxy.winhttp + (px.winhttp_bypass ? ` · bypass: ${px.winhttp_bypass}` : "")],
    ["WinINET (Outlook, Teams, browsers)", d.proxy.wininet],
    ["Effective proxy for login.microsoftonline.com", d.proxy.effective],
    ["WinINET proxy override", wi.proxy_override],
    ["Automatically detect settings (WPAD)", wi.auto_detect ? "On" : "Off"],
    ["wpad resolves to", px.wpad_dns && [].concat(px.wpad_dns).length ? [].concat(px.wpad_dns).join(", ") : null],
    ["Proxy settings per machine (policy)", px.proxy_settings_per_user_policy === 0 ? "Yes (ProxySettingsPerUser=0)" : null],
    ["netsh winhttp show proxy", px.winhttp_raw ? el("pre", { class: "mono", style: "margin:0;white-space:pre-wrap" }, px.winhttp_raw) : null],
  ])));
  if (d.hosts_file && d.hosts_file.length) frag.append(card("Hosts file entries (Microsoft-related)", code(d.hosts_file.join("\n"))));
  frag.append(card("Collection", kv([
    ["OS", m.os], ["PowerShell", m.ps_version], ["Collected (UTC)", fmtTime(m.collected_utc)], ["Duration", m.duration_s != null ? `${m.duration_s} s` : null],
    ["Tenant tested", m.tenant], ["Public IP source", m.public_ip_source],
    ["Public IP owner", m.public_ip ? link("ip", { t: m.public_ip }, `Look up ${m.public_ip}`) : null],
  ])));
  return frag;
}

function renderM365netServerResult(d) {
  const frag = el("div");
  frag.append(el("div", { class: "m365net-label" }, "From the MSPGather server, not the user's machine"));
  frag.append(verdict(d.severity, d.headline, d.subline));
  frag.append(card("Findings (server)", findingsList(d.findings), { flush: true }));
  frag.append(card("Endpoints as seen from the MSPGather server", m365netTable(d.rows), { flush: true }));
  return frag;
}

registerTool({ category: "m365", group: "Outlook", id: "autodiscover", title: "Autodiscover Walkthrough", render: renderAutodiscoverTool,
  icon: "M11 4a7 7 0 100 14 7 7 0 000-14zM20 20l-4.2-4.2M8 11h6M11 8v6",
  keywords: "outlook profile autodiscover.xml certificate prompt exchange hybrid exclude registry srv cname direct connect",
  desc: "Give it an email address. Tests every Autodiscover step in the order Outlook tries them (Microsoft 365 Direct Connect, root domain, autodiscover subdomain, HTTP redirect, SRV) and names the step that causes certificate prompts or slow profile setup." });
registerTool({ category: "m365", group: "Network path", id: "m365net", title: "Endpoint Connectivity", render: renderM365netTool,
  icon: "M4 12h4l2-6 4 12 2-6h4",
  keywords: "tls ssl inspection decryption fortinet zscaler palo alto proxy winhttp wininet pac wpad firewall teams outlook login blocked",
  desc: "Run a read-only PowerShell collector on the affected PC and paste the result. Detects TLS inspection (and which product), blocked or slow Microsoft 365 endpoints, WinHTTP/WinINET proxy mismatches and odd DNS." });
