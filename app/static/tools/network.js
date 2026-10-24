"use strict";
/* DNS & Network: SSL/TLS checker, port check, HTTP inspector, domain registration (RDAP)
   and subnet calculator (client-side only). Backend: app/modules/netdiag.py (/api/net/...). */

addStyles(`
.tls-cert { border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; margin-bottom: 10px; }
.tls-cert:last-child { margin-bottom: 0; }
.tls-cert.bad { border-color: var(--crit); background: var(--crit-soft); }
.tls-cert.missing { border: 2px dashed var(--crit); background: var(--crit-soft); }
.tls-cert-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 8px; font-weight: 650; }
.tls-cert-n { width: 22px; height: 22px; border-radius: 50%; background: var(--panel-2); border: 1px solid var(--border); display: inline-grid; place-items: center; font-size: 12px; flex: none; }
.tls-arrow { color: var(--muted); text-align: center; margin: -4px 0 6px; font-size: 12px; }
.tls-mono { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
.ports-presets { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; align-items: center; }
.ports-presets .btn { padding: 5px 10px; font-size: 12.5px; }
.ports-legend { display: grid; grid-template-columns: max-content 1fr; gap: 6px 12px; align-items: baseline; }
.ports-banner { font-family: var(--mono); font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; max-width: 420px; }
.subnet-form textarea { min-height: 140px; }
.subnet-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin-top: 10px; }
.subnet-answer { font-size: 15px; font-weight: 600; }
.http-hop-url { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
.http-chain { display: flex; flex-direction: column; gap: 4px; }
.http-chain .chip { display: inline-flex; gap: 8px; align-items: center; padding: 6px 10px; border-radius: 8px; background: var(--panel-2); border: 1px solid var(--border); }
.http-chain .chip.bad { background: var(--crit-soft); border-color: var(--crit); }
.http-chain .arrow { color: var(--muted); padding-left: 14px; font-size: 12px; }
.whois-sec { display: flex; flex-wrap: wrap; gap: 6px; }
`);

/* ------------------------------------------------------------ shared bits */
function netBody(d, extraFacts) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  if (extraFacts && extraFacts.length) frag.append(facts(extraFacts));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  const steps = nextSteps(d.steps);
  if (steps) frag.append(steps);
  return frag;
}

function netDaysBadge(days) {
  if (days == null) return badge("info", "unknown");
  const sev = days < 7 ? "critical" : days < 30 ? "warning" : "ok";
  return badge(sev, days < 0 ? `expired ${-days}d ago` : `${days} days`);
}

function netDate(iso) { return iso ? String(iso).slice(0, 10) : "—"; }

/* ============================================================ SSL / TLS CHECKER */
const tlsProtocolOptions = [
  ["auto", "Auto (from port)"], ["https", "HTTPS (443)"], ["tls", "Generic TLS"],
  ["smtp", "SMTP STARTTLS (25)"], ["submission", "SMTP submission STARTTLS (587)"],
  ["imap", "IMAP STARTTLS (143)"], ["pop3", "POP3 STARTTLS (110)"],
  ["smtps", "SMTPS implicit (465)"], ["imaps", "IMAPS implicit (993)"], ["pop3s", "POP3S implicit (995)"],
  ["ldaps", "LDAPS (636)"], ["rdp", "RDP (3389)"],
];

function renderTlsTool(main, params) {
  const out = el("div");
  main.append(card(null, [hashForm("tls", [
    { name: "h", label: "Host[:port]", placeholder: "vpn.contoso.com, mail.contoso.com:587, 10.0.0.5:3389", grow: true, required: true },
    { name: "p", label: "Protocol", type: "select", options: tlsProtocolOptions, value: "auto" },
  ], params, "Check certificate"),
  el("div", { class: "hint", style: "margin-top:8px" }, "Internal (RFC 1918) servers are allowed; they're tested from the MSPGather server's network. Auto picks STARTTLS for 25/587/143/110 and RDP for 3389.")]), out);
  if (params.get("h")) {
    const qs = new URLSearchParams({ host: params.get("h"), protocol: params.get("p") || "auto" });
    runInto(out, "Connecting, reading the chain and testing TLS 1.0–1.3…", () => api(`/api/net/tls?${qs}`), renderTlsResult);
  }
}

function renderTlsResult(d) {
  const leaf = d.chain && d.chain[0];
  const neg = d.negotiated || {};
  const trust = d.trust || {};
  const frag = netBody(d, leaf ? [
    ["Expires", el("span", {}, netDate(leaf.not_after), " ", netDaysBadge(leaf.days_left))],
    ["Issuer", leaf.issuer_short],
    ["Trusted", trust.verified ? badge("ok", "yes") : trust.verified === false ? badge("critical", "no") : badge("info", "unknown")],
    ["Name match", leaf.hostname_match ? badge("ok", "yes") : badge("critical", "no")],
    ["Negotiated", [neg.version, neg.cipher].filter(Boolean).join(" · ")],
    ["Key", leaf.key && leaf.key.text],
  ] : [["Target", `${d.host}:${d.port}`], ["IP", d.ip], ["Protocol", d.protocol_label]]);
  if (!leaf) return frag;

  if (d.versions && d.versions.length) {
    frag.append(card("Protocol support", table(["Version", "Result", "Detail"], d.versions.map((v) => {
      const legacy = v.version === "TLS 1.0" || v.version === "TLS 1.1";
      const sev = v.accepted == null ? "info" : v.accepted ? (legacy ? "warning" : "ok") : (legacy ? "ok" : "info");
      return [v.version, badge(sev, v.accepted == null ? "not tested" : v.accepted ? "accepted" : "rejected"),
        el("span", { class: "sub" }, v.accepted ? (v.cipher || "") : (v.detail || ""))];
    }), (i) => (d.versions[i].accepted && i < 2 ? "hl" : null)), { flush: true }));
  }

  frag.append(card("Certificate chain (as sent by the server)", tlsChain(d)));
  if (trust.verified && trust.path && trust.path.length) {
    frag.append(card("Trust path (verified against the system trust store)", el("div", { class: "route" },
      [...trust.path].reverse().map((p, i) => [i ? el("span", { class: "arrow" }, "→") : null, el("span", { class: "chip" }, p)]))));
  }
  const conn = [["Target", `${d.host}:${d.port}`], ["IP address", d.ip + (d.other_ips && d.other_ips.length ? ` (also ${d.other_ips.join(", ")})` : "")],
    ["Protocol", d.protocol_label], ["TLS version", neg.version], ["Cipher", neg.cipher ? `${neg.cipher} (${neg.bits}-bit)` : null],
    ["Connect / handshake", neg.connect_ms != null ? `${neg.connect_ms} ms / ${neg.handshake_ms} ms` : null],
    ["Server greeting", d.banner ? el("span", { class: "tls-mono" }, d.banner) : null],
    ["RDP security", d.rdp ? d.rdp.selected : null],
    ["NLA required", d.rdp ? (d.rdp.nla_required === true ? "yes" : d.rdp.nla_required === false ? "no" : "unknown") : null]];
  if (d.http) {
    conn.push(["HTTP response", d.http.status_line || d.http.error], ["Server header", d.http.server],
      ["HSTS", d.http.hsts ? el("span", { class: "tls-mono" }, d.http.hsts) : "not set"], ["Redirects to", d.http.location]);
  }
  frag.append(card("Connection", [kv(conn), el("div", { style: "margin-top:10px", class: "hint" },
    link("ports", { h: d.host, p: String(d.port) }, "Port check this host →"), d.protocol === "https" ? ["  ·  ", link("http", { u: `https://${d.host}${d.port === 443 ? "" : ":" + d.port}/` }, "Inspect HTTP redirects and headers →")] : null)]));
  return frag;
}

function tlsChain(d) {
  const items = [];
  d.chain.forEach((c, i) => {
    const issues = [];
    if (c.expired) issues.push(badge("critical", "expired"));
    else if (c.not_yet_valid) issues.push(badge("critical", "not yet valid"));
    else if (!c.self_signed || i === 0) issues.push(netDaysBadge(c.days_left));
    if (i === 0 && !c.hostname_match) issues.push(badge("critical", "name mismatch"));
    if (i === 0 && c.self_signed) issues.push(badge("critical", "self-signed"));
    if (c.key && c.key.type === "RSA" && c.key.bits < 2048) issues.push(badge("critical", "weak key"));
    if ((c.signature_hash === "sha1" || c.signature_hash === "md5") && !(i > 0 && c.self_signed)) issues.push(badge("critical", c.signature_hash.toUpperCase()));
    const bad = c.expired || c.not_yet_valid || (i === 0 && (!c.hostname_match || c.self_signed)) || (c.key && c.key.type === "RSA" && c.key.bits < 2048);
    const sans = [...(c.san || []), ...(c.ip_san || [])];
    if (i > 0) items.push(el("div", { class: "tls-arrow" }, "↑ signed by"));
    items.push(el("div", { class: "tls-cert" + (bad ? " bad" : "") },
      el("div", { class: "tls-cert-head" }, el("span", { class: "tls-cert-n" }, String(i + 1)), c.subject_cn || c.subject_short,
        badge("info", c.position), issues),
      kv([
        ["Subject", el("span", { class: "tls-mono" }, c.subject)],
        ["Issuer", el("span", { class: "tls-mono" }, c.issuer)],
        ["Names (SAN)", sans.length ? (sans.length > 12 ? el("details", {}, el("summary", {}, `${sans.slice(0, 6).join(", ")} … (${sans.length} names)`), sans.join(", ")) : sans.join(", ")) : (i === 0 ? "none (CN only)" : null)],
        ["Valid", `${fmtTime(c.not_before)} → ${fmtTime(c.not_after)}`],
        ["Key", c.key && c.key.text],
        ["Signature", c.signature],
        ["SHA-1 thumbprint", el("span", { class: "tls-mono" }, c.sha1)],
        ["SHA-256", el("span", { class: "tls-mono" }, c.sha256)],
        ["Serial", el("span", { class: "tls-mono" }, c.serial)],
        ["CA issuers (AIA)", (c.ca_issuers || []).join(", ")],
      ])));
    if (i === 0 && d.missing_intermediate) {
      const m = d.missing_intermediate, aia = m.aia || {};
      items.push(el("div", { class: "tls-arrow" }, "↑ should be signed by"));
      items.push(el("div", { class: "tls-cert missing" },
        el("div", { class: "tls-cert-head" }, el("span", { class: "tls-cert-n" }, "?"), `NOT SENT: ${m.issuer_short}`, badge("critical", "missing intermediate")),
        kv([["Expected subject", el("span", { class: "tls-mono" }, m.issuer)],
          ["Download", aia.url ? el("a", { href: aia.url, target: "_blank", rel: "noopener noreferrer" }, aia.url) : "The leaf has no AIA URL; get the intermediate from the CA's website."],
          ["Downloaded cert", aia.subject ? el("span", { class: "tls-mono" }, aia.subject) : aia.error || null]])));
    }
  });
  return items;
}

/* ================================================================ PORT CHECK */
const portsPresets = [
  ["Web", "80,443"], ["Mail", "25,465,587,993,995,143,110"], ["Remote", "3389,22,5985,5986"],
  ["VPN / firewall", "443,4443,10443,8443,1194,500,4500"], ["Windows / AD", "53,88,135,139,389,445,464,636,3268,3269"], ["SQL", "1433,3306,5432"],
];
const portsTlsPorts = new Set([443, 465, 587, 636, 993, 995, 3269, 3389, 4443, 8443, 10443, 25, 143, 110, 5986]);

function renderPortsTool(main, params) {
  const out = el("div");
  const form = hashForm("ports", [
    { name: "h", label: "Host or IP", placeholder: "203.0.113.10 or vpn.contoso.com", grow: true, required: true },
    { name: "p", label: "Ports (comma list / ranges, max 64)", placeholder: "443,3389,8000-8010", grow: true, value: "80,443" },
  ], params, "Check ports");
  const portsInput = form.querySelector("input[name=p]");
  const hostInput = form.querySelector("input[name=h]");
  const presets = el("div", { class: "ports-presets" }, el("span", { class: "hint" }, "Presets:"),
    portsPresets.map(([label, list]) => el("button", { class: "btn secondary", type: "button", title: list, onclick: () => {
      portsInput.value = list;
      if (hostInput.value.trim()) form.requestSubmit(); else hostInput.focus();
    } }, label)));
  main.append(card(null, [form, presets, el("div", { class: "hint", style: "margin-top:8px" },
    "TCP connect test (5s timeout per port, run in parallel) FROM the MSPGather server's network. UDP (IPsec 500/4500, OpenVPN 1194) can't be tested this way.")]), out);
  if (params.get("h")) {
    const qs = new URLSearchParams({ host: params.get("h"), ports: params.get("p") || "80,443" });
    runInto(out, "Connecting to each port…", () => api(`/api/net/ports?${qs}`), renderPortsResult);
  }
}

function renderPortsResult(d) {
  const frag = netBody(d, [["Target", d.host === d.ip ? d.ip : `${d.host} → ${d.ip}`], ["Address type", d.public ? "public (internet)" : "private / internal"],
    ["Open", String(d.counts.open)], ["Closed", String(d.counts.closed)], ["Filtered", String(d.counts.filtered)],
    ["Tested from", d.egress_ip || "MSPGather server"]]);
  const stateSev = { open: "ok", closed: "info", filtered: "warning", unreachable: "warning" };
  const risky = new Set([3389, 445, 139, 135, 5985, 5986, 23, 1433, 3306, 5432, 5900, 6379, 27017, 2375]);
  frag.append(card("Results", table(["Port", "Service", "State", "Time", "Banner / next step"], d.results.map((r) => [
    el("strong", {}, String(r.port)), r.service || el("span", { class: "sub" }, "—"),
    badge(r.state === "open" && d.public && risky.has(r.port) ? "critical" : stateSev[r.state], r.state),
    r.ms != null ? `${r.ms} ms` : el("span", { class: "sub" }, "> 5 s"),
    el("div", {}, r.banner ? el("div", { class: "ports-banner" }, r.banner) : null, r.error ? el("div", { class: "sub" }, r.error) : null,
      r.state === "open" && portsTlsPorts.has(r.port) ? el("div", { class: "sub" }, link("tls", { h: `${d.host}:${r.port}` }, "Check its certificate →")) : null),
  ]), (i) => (d.results[i].state === "open" && d.public && risky.has(d.results[i].port) ? "hl" : null)), { flush: true }));
  frag.append(card("What the states mean", el("div", { class: "ports-legend" },
    badge("ok", "open"), el("div", {}, "Something accepted the TCP connection: the port is reachable from here."),
    badge("info", "closed"), el("div", {}, "The host (or a firewall in front of it) answered with a reset (RST): the address is reachable, but nothing is listening on that port."),
    badge("warning", "filtered"), el("div", {}, "No answer within 5 seconds: a firewall is silently dropping the traffic, the host is offline, or the address is wrong."),
    badge("warning", "unreachable"), el("div", {}, "A router reported the network or host unreachable (ICMP), or there's no route from this server.")),
  ));
  frag.append(el("div", { class: "hint" }, d.subline, " ", link("ip", { t: d.ip }, "Who owns this IP? →")));
  return frag;
}

/* ============================================================ HTTP INSPECTOR */
function renderHttpTool(main, params) {
  const out = el("div");
  main.append(card(null, [hashForm("http", [
    { name: "u", label: "URL", placeholder: "contoso.com  or  https://portal.contoso.com/login", grow: true, required: true },
  ], params, "Inspect"), el("div", { class: "hint", style: "margin-top:8px" },
    "Without http:// or https:// the check starts at http:// so you can see whether the site upgrades to HTTPS. Public URLs only; fetched from the MSPGather server without cookies.")]), out);
  if (params.get("u")) runInto(out, "Following redirects…", () => api(`/api/net/http?url=${encodeURIComponent(params.get("u"))}`), renderHttpResult);
}

function renderHttpResult(d) {
  const final = d.hops[d.hops.length - 1] || {};
  const cdn = d.findings.filter((f) => f.title.startsWith("Served through ")).map((f) => f.title.replace("Served through ", ""));
  const frag = netBody(d, [
    ["Final status", final.status != null ? badge(final.status >= 500 ? "critical" : final.status >= 400 ? "warning" : "ok", `${final.status} ${final.reason || ""}`) : badge("critical", "no response")],
    ["Redirects", String(d.redirects)], ["First byte", final.ttfb_ms != null ? `${(final.ttfb_ms / 1000).toFixed(2)} s` : null],
    ["TLS", final.tls ? final.tls.version : (final.url || "").startsWith("https") ? null : "none (HTTP)"],
    ["Server", final.server], ["CDN / WAF", cdn.join(", ") || null], ["Title", final.title],
  ]);
  const badHop = (h, i) => !!(h.error || h.cert_error || (h.status >= 500) || (i > 0 && d.hops[i - 1].url.startsWith("https://") && h.url.startsWith("http://")));
  frag.append(card("Redirect chain", el("div", { class: "http-chain" }, d.hops.map((h, i) => [
    i ? el("div", { class: "arrow" }, `↓ ${d.hops[i - 1].status || ""} redirect`) : null,
    el("div", { class: "chip" + (badHop(h, i) ? " bad" : "") },
      h.status != null ? badge(h.status >= 500 ? "critical" : h.status >= 400 ? "warning" : h.status >= 300 ? "info" : "ok", String(h.status)) : badge("critical", h.blocked ? "refused" : "failed"),
      el("span", { class: "http-hop-url" }, h.url)),
  ]))));
  frag.append(card("Hops", table(["#", "URL", "Status", "Location", "Server", "TLS", "Timing"], d.hops.map((h, i) => [
    String(i + 1), el("span", { class: "http-hop-url" }, h.url),
    h.status != null ? `${h.status} ${h.reason || ""}` : el("span", { class: "sub" }, h.error || "—"),
    h.location ? el("span", { class: "http-hop-url" }, h.location) : "—", h.server || "—",
    el("div", {}, h.tls ? h.tls.version : "—", h.cert_error ? el("div", { class: "sub" }, `cert: ${h.cert_error}`) : null,
      h.tls && h.tls.cert ? el("div", { class: "sub" }, `cert expires in ${h.tls.cert.days_left}d`) : null),
    h.ttfb_ms != null ? el("div", {}, `TTFB ${h.ttfb_ms} ms`, el("div", { class: "sub" }, `total ${h.total_ms} ms, ${h.bytes} B${h.truncated ? " (capped)" : ""}`)) : "—",
  ]), (i) => (badHop(d.hops[i], i) ? "hl" : null)), { flush: true }));
  if (final.headers && final.headers.length) {
    const present = new Set(final.headers.map(([k]) => k.toLowerCase()));
    const sec = [["strict-transport-security", "HSTS"], ["content-security-policy", "CSP"], ["x-frame-options", "X-Frame-Options"],
      ["x-content-type-options", "X-Content-Type-Options"], ["referrer-policy", "Referrer-Policy"]];
    frag.append(card("Security headers (final response)", el("div", { class: "whois-sec" },
      sec.map(([k, label]) => badge(present.has(k) ? "ok" : "info", `${present.has(k) ? "✓" : "✗"} ${label}`)))));
    frag.append(card(`Response headers (${final.url})`, table(["Header", "Value"], final.headers.map(([k, v]) => [el("strong", {}, k), el("span", { class: "tls-mono" }, v)])), { flush: true }));
  }
  if (d.host) frag.append(el("div", { class: "hint" }, d.subline, "  ·  ", link("tls", { h: httpUrlHost(final.url || d.start) }, "Full certificate check →")));
  return frag;
}

function httpUrlHost(u) {
  try { const x = new URL(u); return x.port ? `${x.hostname}:${x.port}` : x.hostname; } catch (e) { return u; }
}

/* ======================================================= DOMAIN REGISTRATION */
function renderWhoisTool(main, params) {
  const out = el("div");
  main.append(card(null, hashForm("whois", [
    { name: "d", label: "Domain", placeholder: "contoso.com", grow: true, required: true },
  ], params, "Look up")), out);
  if (params.get("d")) runInto(out, "Querying the registry (RDAP) and live DNS…", () => api(`/api/net/whois?domain=${encodeURIComponent(params.get("d"))}`), renderWhoisResult);
}

function renderWhoisResult(d) {
  const reg = d.registrar || {}, ev = d.events || {}, live = (d.dnssec || {}).live || {};
  const statuses = d.statuses || [];
  const locked = statuses.some((s) => /TransferProhibited$/.test(s.code));
  const frag = el("div");
  if (d.note) frag.append(el("div", { class: "hint", style: "margin-bottom:10px" }, d.note));
  frag.append(netBody(d, d.registered ? [
    ["Registrar", reg.name], ["Created", ev.registered], ["Expires", ev.expires ? el("span", {}, ev.expires, " ", netDaysBadge(d.days_left)) : "not published"],
    ["Transfer lock", d.transfer_lock || (locked ? "on" : "off")], ["DNSSEC", live.ds && live.ds.length ? (live.validated ? "signed, validates" : "signed, NOT validating") : "off"],
  ] : [["Domain", d.domain], ["Live name servers", (d.live_ns || []).length ? String(d.live_ns.length) : "none"]]));
  if (d.whois_link) {
    frag.append(el("div", { class: "notice" }, `Registration data for .${d.tld} isn't published over RDAP. Look it up at the registry: `,
      el("a", { href: d.whois_link, target: "_blank", rel: "noopener noreferrer" }, `IANA entry for .${d.tld} (lists the registry's WHOIS server and website)`)));
  }
  if (d.registered) {
    frag.append(el("div", { class: "grid-2" },
      card("Registration", kv([
        ["Registrar", reg.name], ["IANA registrar ID", reg.iana_id], ["Registrar website", reg.url ? el("a", { href: reg.url, target: "_blank", rel: "noopener noreferrer" }, reg.url) : null],
        ["Created", ev.registered], ["Last changed", ev.updated], ["Expires", ev.expires || "not published"], ["Last transfer", ev.transferred],
        ["RDAP source", d.rdap_source ? el("a", { href: d.rdap_source, target: "_blank", rel: "noopener noreferrer" }, "registry record") : null],
      ])),
      card("Registrar abuse contact", reg.abuse && ((reg.abuse.emails || []).length || (reg.abuse.phones || []).length) ? el("div", {},
        (reg.abuse.emails || []).map((m) => el("div", {}, el("a", { href: "mailto:" + m }, m))),
        (reg.abuse.phones || []).map((p) => el("div", { class: "sub" }, String(p).replace(/^tel:/, "")))) : el("div", { class: "hint" }, "Not published in RDAP."))));
    frag.append(card("Status codes (EPP)", statuses.length ? table(["Status", "What it means"], statuses.map((s) => [
      el("div", {}, badge(s.severity, s.code)), s.meaning]), (i) => (statuses[i].severity === "critical" ? "hl" : null)) : el("div", { class: "card-body hint" }, "No status codes published."), { flush: true }));
  }
  const rdapNs = d.rdap_ns || [], liveNs = d.live_ns || [];
  const allNs = [...new Set([...rdapNs, ...liveNs])].sort();
  if (allNs.length) {
    const showReg = d.registered;
    frag.append(card("Name servers", table(showReg ? ["Name server", "At the registry", "In live DNS"] : ["Name server (live DNS)"], allNs.map((n) => showReg
      ? [el("span", { class: "tls-mono" }, n), rdapNs.includes(n) ? badge("ok", "yes") : badge("warning", "no"), liveNs.includes(n) ? badge("ok", "yes") : badge("warning", "no")]
      : [el("span", { class: "tls-mono" }, n)]),
    (i) => (showReg && rdapNs.length && liveNs.length && !(rdapNs.includes(allNs[i]) && liveNs.includes(allNs[i])) ? "hl" : null)), { flush: true }));
  }
  if (d.registered !== false) {
    frag.append(card("DNSSEC", kv([
      ["Registry says signed", d.dnssec && d.dnssec.rdap_signed != null ? (d.dnssec.rdap_signed ? "yes" : "no") : "unknown"],
      ["DS records (at parent)", live.ds && live.ds.length ? el("div", {}, live.ds.map((x) => el("div", { class: "tls-mono" }, x))) : "none"],
      ["DNSKEY records (in zone)", String(live.dnskey_count || 0) + (live.dnskey_tags && live.dnskey_tags.length ? ` (key tags ${live.dnskey_tags.join(", ")})` : "")],
      ["DS matches a DNSKEY", live.ds_matches_key == null ? "n/a" : live.ds_matches_key ? "yes" : "NO"],
      ["Validating resolver answer", live.validating_rcode ? `${live.validating_rcode}${live.validated ? " (authenticated)" : ""}` : null],
    ])));
  }
  frag.append(el("div", { class: "hint" }, link("dns", { n: d.domain, type: "NS" }, "NS lookup on every resolver →"), "  ·  ",
    link("domain", { d: d.domain }, "Email domain check →")));
  return frag;
}

/* ========================================================= SUBNET CALCULATOR */
const subnetV4Classes = [
  ["0.0.0.0/8", "Reserved (\"this network\")"], ["10.0.0.0/8", "Private (RFC 1918)"], ["100.64.0.0/10", "CGNAT / shared address space (RFC 6598)"],
  ["127.0.0.0/8", "Loopback"], ["169.254.0.0/16", "Link-local (APIPA)"], ["172.16.0.0/12", "Private (RFC 1918)"],
  ["192.0.0.0/24", "IETF protocol assignments"], ["192.0.2.0/24", "Documentation (TEST-NET-1)"], ["192.168.0.0/16", "Private (RFC 1918)"],
  ["198.18.0.0/15", "Benchmarking (RFC 2544)"], ["198.51.100.0/24", "Documentation (TEST-NET-2)"], ["203.0.113.0/24", "Documentation (TEST-NET-3)"],
  ["224.0.0.0/4", "Multicast"], ["240.0.0.0/4", "Reserved"], ["255.255.255.255/32", "Limited broadcast"],
];
const subnetV6Classes = [
  ["::/128", "Unspecified"], ["::1/128", "Loopback"], ["::ffff:0:0/96", "IPv4-mapped"], ["64:ff9b::/96", "NAT64"],
  ["2001:db8::/32", "Documentation"], ["2002::/16", "6to4"], ["fc00::/7", "Unique local (private, ULA)"], ["fe80::/10", "Link-local"],
  ["ff00::/8", "Multicast"], ["2000::/3", "Public (global unicast)"],
];
const subnetHomeRanges = ["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24"];

function subnetParseIp(s) {
  s = String(s || "").trim().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    const parts = s.split(".").map(Number);
    if (parts.some((p) => p > 255)) return null;
    return { v: 4, n: parts.reduce((a, p) => (a << 8n) + BigInt(p), 0n) };
  }
  if (!s.includes(":") || !/^[0-9a-f:.]+$/i.test(s)) return null;
  let tail = [];
  const v4 = s.match(/(\d{1,3}(\.\d{1,3}){3})$/);
  if (v4) {
    const p = subnetParseIp(v4[1]);
    if (!p) return null;
    tail = [Number(p.n >> 16n), Number(p.n & 0xffffn)].map((x) => x.toString(16));
    s = s.slice(0, -v4[1].length) + "0:0";
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const back = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - back.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill("0"), ...back];
  } else groups = head;
  if (tail.length) groups.splice(groups.length - 2, 2, ...tail);
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return { v: 6, n: groups.reduce((a, g) => (a << 16n) + BigInt(parseInt(g, 16)), 0n) };
}

function subnetFmt(v, n) {
  if (v === 4) return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join(".");
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  let best = [-1, 0];
  for (let i = 0; i < 8;) {
    if (g[i] !== "0") { i++; continue; }
    let j = i; while (j < 8 && g[j] === "0") j++;
    if (j - i > best[1]) best = [i, j - i];
    i = j;
  }
  if (best[1] < 2) return g.join(":");
  return `${g.slice(0, best[0]).join(":")}::${g.slice(best[0] + best[1]).join(":")}`;
}

function subnetBits(v) { return v === 4 ? 32n : 128n; }
function subnetMask(v, p) { const b = subnetBits(v); return ((1n << b) - 1n) ^ ((1n << (b - BigInt(p))) - 1n); }

/** Dotted mask (or wildcard) to prefix length; null if not contiguous. */
function subnetMaskToPrefix(n) {
  for (let p = 0; p <= 32; p++) if (subnetMask(4, p) === n) return { prefix: p, wildcard: false };
  for (let p = 0; p <= 32; p++) if ((subnetMask(4, p) ^ 0xffffffffn) === n) return { prefix: p, wildcard: true };
  return null;
}

function subnetParseNet(ipText, maskText) {
  const ip = subnetParseIp(ipText);
  if (!ip) return null;
  let prefix = Number(subnetBits(ip.v)), note = null;
  if (maskText != null && maskText !== "") {
    if (/^\d{1,3}$/.test(maskText)) prefix = Number(maskText);
    else {
      const m = ip.v === 4 ? subnetParseIp(maskText) : null;
      if (!m || m.v !== 4) return { error: `'${maskText}' is not a valid mask` };
      const r = subnetMaskToPrefix(m.n);
      if (!r) return { error: `${maskText} is not a contiguous subnet mask` };
      prefix = r.prefix;
      if (r.wildcard && maskText !== "0.0.0.0") note = `${maskText} read as a wildcard (inverse) mask, i.e. /${prefix}`;
    }
    if (prefix < 0 || prefix > Number(subnetBits(ip.v))) return { error: `/${prefix} is not a valid prefix for IPv${ip.v}` };
  }
  return { v: ip.v, ip: ip.n, prefix, note };
}

function subnetParseLine(raw) {
  const line = raw.replace(/#.*$/, "").trim();
  if (!line) return null;
  const toks = line.split(/\s+/);
  const tryNet = (t1, t2) => {
    if (t2 == null) { const [a, b] = t1.split("/"); return t1.split("/").length > 2 ? null : subnetParseNet(a, b); }
    return subnetParseIp(t1) && subnetParseIp(t1).v === 4 && /^\d{1,3}(\.\d{1,3}){3}$/.test(t2) ? subnetParseNet(t1, t2) : null;
  };
  let net = null, used = 0;
  if (toks.length >= 2) { net = tryNet(toks[toks.length - 2], toks[toks.length - 1]); used = 2; }
  if (!net) { net = tryNet(toks[toks.length - 1]); used = 1; }
  if (!net) {  // "Label:10.0.0.0/8" without a space
    const m = line.match(/^(.*?[^0-9a-f:\s][^:]*):\s*(\S+)$/i);
    if (m) { net = tryNet(m[2]); if (net) return subnetBuild(net, m[1].trim(), raw); }
    return { error: `'${line}' isn't a network (use 10.0.0.0/22, 192.168.1.10 255.255.255.0, or 2001:db8::/48)`, raw };
  }
  if (net.error) return { error: net.error, raw };
  const label = toks.slice(0, toks.length - used).join(" ").replace(/\s*[:=,\-–]+\s*$/, "").trim();
  return subnetBuild(net, label, raw);
}

function subnetBuild(net, label, raw) {
  const { v, prefix } = net;
  const bits = subnetBits(v), size = 1n << (bits - BigInt(prefix));
  const mask = subnetMask(v, prefix);
  const start = net.ip & mask, end = start + size - 1n;
  const r = { label, raw, v, prefix, start, end, size, input: net.ip, note: net.note, hostBits: net.ip !== start };
  if (v === 4) {
    if (prefix === 32) { r.first = start; r.last = start; r.usable = 1n; }
    else if (prefix === 31) { r.first = start; r.last = end; r.usable = 2n; }
    else { r.first = start + 1n; r.last = end - 1n; r.usable = size - 2n; r.broadcast = end; }
  } else { r.first = start; r.last = end; r.usable = size; }
  r.cidr = `${subnetFmt(v, start)}/${prefix}`;
  r.name = label ? `${r.cidr} (${label})` : r.cidr;
  r.type = subnetClassify(r);
  return r;
}

function subnetRange(cidr) {
  const [a, p] = cidr.split("/"); const ip = subnetParseIp(a);
  const size = 1n << (subnetBits(ip.v) - BigInt(p));
  return { v: ip.v, start: ip.n, end: ip.n + size - 1n };
}

function subnetClassify(r) {
  if (r.prefix === 0) return "Default route (all addresses)";
  const classes = r.v === 4 ? subnetV4Classes : subnetV6Classes;
  for (const [cidr, label] of classes) {
    const c = subnetRange(cidr);
    if (r.start >= c.start && r.end <= c.end) return label;
  }
  for (const [cidr] of classes) {
    const c = subnetRange(cidr);
    if (r.start <= c.end && c.start <= r.end) return "Mixed (spans several special ranges)";
  }
  return r.v === 4 ? "Public" : "Reserved / unassigned";
}

function subnetCount(n) {
  if (n <= 2n ** 64n) return n.toLocaleString("en-US");
  let p = 0; while ((1n << BigInt(p)) < n) p++;
  return `2^${p}`;
}

/** "192.168.1.x" style description of a range. */
function subnetDescribe(r) {
  if (r.v === 4 && [8, 16, 24].includes(r.prefix)) {
    const octets = subnetFmt(4, r.start).split(".");
    return octets.slice(0, r.prefix / 8).concat(Array(4 - r.prefix / 8).fill("x")).join(".");
  }
  if (r.start === r.end) return subnetFmt(r.v, r.start);
  return `${subnetFmt(r.v, r.start)} – ${subnetFmt(r.v, r.end)}`;
}

function subnetAnalyze(text, ipText) {
  // New line, ";" or a "," that is followed by an address (so "Site A, HQ: 10.0.0.0/8" keeps its label).
  const lines = String(text || "").split(/\r?\n|;|,(?=\s*[0-9a-f:]*[.:/])/i);
  const nets = [], errors = [];
  lines.forEach((l) => { const r = subnetParseLine(l); if (!r) return; (r.error ? errors : nets).push(r); });
  const F = [];
  const overlaps = [];
  for (let i = 0; i < nets.length; i++) {
    for (let j = i + 1; j < nets.length; j++) {
      const a = nets[i], b = nets[j];
      if (a.v !== b.v || a.prefix === 0 || b.prefix === 0 || !(a.start <= b.end && b.start <= a.end)) continue;
      const small = a.size <= b.size ? a : b;
      overlaps.push([i, j]);
      const same = a.start === b.start && a.end === b.end;
      F.push({ severity: "critical",
        title: same ? `${a.name} and ${b.name} are the same network` : `${a.name} overlaps ${b.name}`,
        detail: `Shared addresses: ${subnetDescribe(small)} (${subnetCount(small.size)} addresses). Each side treats these as local, so traffic to them never enters the tunnel; the classic symptom is one-way or partial traffic. Re-address one side or NAT it on the VPN. Azure VNet peering refuses overlapping address spaces outright.`,
        headline: `${a.name} overlaps ${b.name}. Traffic to ${subnetDescribe(small)} will not route across the VPN.` });
    }
  }
  errors.forEach((e) => F.push({ severity: "warning", title: `Line not understood: ${e.raw.trim().slice(0, 60)}`, detail: e.error }));
  nets.forEach((r) => {
    if (r.note) F.push({ severity: "info", title: `${r.name}: wildcard mask`, detail: r.note });
    if (r.hostBits) {
      const isBcast = r.broadcast != null && r.input === r.broadcast;
      F.push({ severity: isBcast ? "warning" : "info", title: `${subnetFmt(r.v, r.input)} is ${isBcast ? "the broadcast address of" : "a host in"} ${r.cidr}`,
        detail: isBcast ? "The broadcast address can't be assigned to a device." : `Network ${r.cidr}, usable ${subnetFmt(r.v, r.first)} – ${subnetFmt(r.v, r.last)}.` });
    }
    if (r.v === 4 && nets.length > 1 && r.prefix > 0 && r.prefix <= 24) {
      const home = subnetHomeRanges.filter((h) => { const c = subnetRange(h); return r.start <= c.end && c.start <= r.end; });
      if (home.length) F.push({ severity: "info", title: `${r.name} overlaps a common home-router range (${home.join(", ")})`,
        detail: "Remote-access VPN users whose home LAN uses the same range can't reach these addresses through the VPN. Avoid these ranges for office/Azure networks." });
    }
  });
  let lookup = null;
  if (ipText && ipText.trim()) {
    const ip = subnetParseIp(ipText);
    if (!ip) lookup = { error: `'${ipText}' is not a valid IP address` };
    else {
      const hits = nets.filter((r) => r.v === ip.v && ip.n >= r.start && ip.n <= r.end).sort((a, b) => b.prefix - a.prefix);
      lookup = { ip: subnetFmt(ip.v, ip.n), hits };
    }
  }
  let sev = worstSeverity(F), headline;
  const hl = F.find((f) => f.headline);
  if (hl) headline = hl.headline;
  else if (!nets.length) { sev = "warning"; headline = "No valid networks entered."; }
  else if (nets.length === 1) {
    const r = nets[0];
    headline = `${r.cidr}: ${subnetCount(r.usable)} usable ${r.usable === 1n ? "address" : "addresses"} (${subnetFmt(r.v, r.first)} – ${subnetFmt(r.v, r.last)}). ${r.type}.`;
    if (sev === "info") sev = "ok";
  } else {
    headline = `No overlaps between the ${nets.length} networks. They can be routed to each other (VPN / peering) without conflicts.`;
    if (sev === "info") sev = "ok";
  }
  return { nets, errors, F, overlaps, lookup, sev, headline };
}

function renderSubnetTool(main, params) {
  const ta = el("textarea", { spellcheck: "false", placeholder: "One per line, optional label:\nSite A: 10.1.0.0/16\nSite B: 192.168.0.0/23\nAzure hub 10.10.0.0/22\n192.168.1.10 255.255.255.0\n2001:db8:1::/48" }, params.get("n") || "");
  const ipIn = el("input", { type: "text", placeholder: "10.1.2.3 (optional)", value: params.get("ip") || "", spellcheck: "false" });
  const out = el("div");
  const go = () => {
    const p = new URLSearchParams();
    if (ta.value.trim()) p.set("n", ta.value.trim());
    if (ipIn.value.trim()) p.set("ip", ipIn.value.trim());
    const next = `#subnet?${p}`;
    if (location.hash === next) route(); else location.hash = next;
  };
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); });
  ipIn.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } });
  const sample = "Site A (HQ): 192.168.1.0/24\nSite B (branch): 192.168.0.0/23\nAzure hub: 10.10.0.0/16\nAzure spoke: 10.20.0.0/22";
  main.append(card(null, el("div", { class: "subnet-form" }, ta,
    el("div", { class: "subnet-row" },
      el("div", { class: "field grow" }, el("label", {}, "Is this IP in any of these networks?"), ipIn),
      el("button", { class: "btn", type: "button", onclick: go }, "Calculate"),
      el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = sample; ipIn.value = "192.168.1.20"; go(); } }, "Load VPN example"),
      el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; ipIn.value = ""; ta.focus(); } }, "Clear")),
    el("div", { class: "hint", style: "margin-top:8px" }, "Runs in your browser; nothing is sent to the server. Ctrl+Enter to calculate."))), out);
  if (params.get("n")) out.append(renderSubnetResult(subnetAnalyze(params.get("n"), params.get("ip"))));
}

/** An address inside the first overlap (first usable of the smaller network). */
function subnetOverlapProbe(a) {
  const [i, j] = a.overlaps[0];
  const small = a.nets[i].size <= a.nets[j].size ? a.nets[i] : a.nets[j];
  return subnetFmt(small.v, small.first);
}

function renderSubnetResult(a) {
  const frag = el("div");
  frag.append(verdict(a.sev, a.headline, a.nets.length > 1 ? `${a.nets.length} networks · ${a.overlaps.length} overlap${a.overlaps.length === 1 ? "" : "s"}` : null));
  if (a.lookup) {
    const L = a.lookup;
    let msg;
    if (L.error) msg = el("div", { class: "error-box" }, L.error);
    else if (!L.hits.length) msg = el("div", { class: "subnet-answer" }, badge("info", "no"), ` ${L.ip} is not in any of the ${a.nets.length} networks.`);
    else msg = el("div", {}, el("div", { class: "subnet-answer" }, badge("ok", "yes"), ` ${L.ip} is in ${L.hits[0].name}.`),
      L.hits.length > 1 ? el("div", { class: "hint", style: "margin-top:4px" },
        `It's also in ${L.hits.slice(1).map((h) => h.name).join(", ")}. Routers pick the most specific (longest prefix) match, ${L.hits[0].cidr}, so traffic for it may go somewhere you don't expect.`) : null);
    frag.append(card(L.ip ? `Is ${L.ip} in any of these?` : "IP lookup", msg));
  }
  if (a.F.length) frag.append(card("Findings", findingsList(a.F), { flush: true }));
  if (a.overlaps.length) {
    frag.append(nextSteps([
      { title: "Give every site / VNet a unique range", detail: "Plan non-overlapping ranges (e.g. 10.<site>.0.0/16 per site) before building tunnels or peering. Moving the smaller site is usually least work." },
      { title: "If you can't re-address now: NAT on the VPN", detail: "Most firewalls (FortiGate, SonicWall, Meraki, Azure VPN Gateway NAT rules) can translate one side to an unused range for the tunnel." },
      { title: "Check routes on a Windows client", detail: "Shows which interface wins for an address in the overlapping range.", commands: [`Find-NetRoute -RemoteIPAddress ${subnetOverlapProbe(a)}`] },
    ]));
  }
  if (a.nets.length) {
    const inOverlap = new Set(a.overlaps.flat());
    frag.append(card("Networks", table(["Label", "Network", "Usable range", "Usable", "Mask / wildcard", "Broadcast", "Type"], a.nets.map((r) => [
      r.label || el("span", { class: "sub" }, "—"),
      el("strong", { class: "tls-mono" }, r.cidr),
      el("span", { class: "tls-mono" }, `${subnetFmt(r.v, r.first)} – ${subnetFmt(r.v, r.last)}`),
      el("div", {}, subnetCount(r.usable), r.v === 4 && r.prefix <= 29 ? el("div", { class: "sub" }, `Azure: ${subnetCount(r.size - 5n)}`) : null),
      r.v === 4 ? el("div", { class: "tls-mono" }, subnetFmt(4, subnetMask(4, r.prefix)), el("div", { class: "sub" }, subnetFmt(4, subnetMask(4, r.prefix) ^ 0xffffffffn))) : `/${r.prefix}`,
      r.broadcast != null ? el("span", { class: "tls-mono" }, subnetFmt(4, r.broadcast)) : el("span", { class: "sub" }, r.v === 6 ? "n/a (IPv6)" : r.prefix === 31 ? "none (/31 point-to-point)" : "none"),
      r.type,
    ]), (i) => (inOverlap.has(i) ? "hl" : null)), { flush: true }));
    frag.append(el("div", { class: "hint" }, "Azure reserves 5 addresses in every subnet (network, 3 for Azure services, broadcast), shown as 'Azure' under the usable count. /31 is point-to-point (RFC 3021): both addresses usable."));
  }
  return frag;
}

/* ============================================================== REGISTRATION */
registerTool({ category: "network", group: "Certificates", id: "tls", title: "SSL/TLS Checker", render: renderTlsTool,
  icon: "M6 11h12v9H6zM8 11V8a4 4 0 018 0v3M12 15v2",
  keywords: "ssl tls certificate cert chain intermediate expired expiry self-signed hostname mismatch starttls smtp imap pop3 ldaps rdp 3389 hsts thumbprint tls1.0 cipher",
  desc: "Check a server's certificate over HTTPS, STARTTLS (SMTP/IMAP/POP3), LDAPS or RDP: full chain, missing intermediates, expiry, name mismatch, weak keys, trust, and which TLS versions it accepts." });
registerTool({ category: "network", group: "Connectivity", id: "ports", title: "Port Check", render: renderPortsTool,
  icon: "M4 7h16v10H4zM8 11v2M12 11v2M16 11v2",
  keywords: "port scan open closed filtered firewall tcp rdp 3389 smb 445 telnet test-netconnection reachability exposed",
  desc: "Test which TCP ports on a host are open, closed or filtered from the MSPGather server, with banners and a warning when RDP, SMB or WinRM is exposed to the internet." });
registerTool({ category: "network", group: "Connectivity", id: "http", title: "HTTP Inspector", render: renderHttpTool,
  icon: "M4 12h12M12 6l6 6-6 6M4 6h4M4 18h4",
  keywords: "http https redirect chain loop 301 302 headers hsts security headers cdn waf cloudflare front door ttfb slow 503 502",
  desc: "Follow a URL's redirects hop by hop: status codes, HTTPS upgrade, redirect loops, certificate errors, timing, security headers and which CDN/WAF is in front." });
registerTool({ category: "network", group: "Domains", id: "whois", title: "Domain Registration", render: renderWhoisTool,
  icon: "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z",
  keywords: "whois rdap registrar expiry expiration renew clienthold serverhold redemption pending delete transfer lock name servers dnssec ds dnskey",
  desc: "Registrar, expiry date, EPP status codes in plain English (suspended, expired, transfer lock), registry vs live name servers and whether DNSSEC is broken." });
registerTool({ category: "network", group: "Calculators", id: "subnet", title: "Subnet Calculator", render: renderSubnetTool,
  icon: "M4 4h6v6H4zM14 4h6v6h-6zM9 14h6v6H9zM7 10v2h10v-2M12 12v2",
  keywords: "subnet cidr mask wildcard netmask ipv4 ipv6 overlap vpn azure vnet peering range calculator broadcast",
  desc: "Network, broadcast, usable range and mask for any CIDR (IPv4 and IPv6), plus an overlap check across sites for site-to-site VPNs and Azure VNet peering." });
