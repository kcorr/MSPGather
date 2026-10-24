"use strict";
/* Email troubleshooting tools. */

/* =========================================================== HEADER ANALYZER */
function renderHeaderTool(main) {
  const ta = el("textarea", { placeholder: "Paste the full message headers here (Outlook: File → Properties → Internet headers; OWA: … → View → View message details; Gmail: ⋮ → Show original)", spellcheck: "false" });
  const out = el("div");
  const analyze = () => {
    if (!ta.value.trim()) return;
    runInto(out, "Analyzing headers…", () => api("/api/headers/analyze", { body: { raw: ta.value } }), (d) => renderHeaderResult(d));
  };
  main.append(
    card(null, [ta, el("div", { class: "btn-row" },
      el("button", { class: "btn", type: "button", onclick: analyze }, "Analyze"),
      el("button", { class: "btn secondary", type: "button", onclick: async () => { ta.value = await (await fetch("samples/loop-headers.txt")).text(); analyze(); } }, "Load sample (mail loop)"),
      el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; out.replaceChildren(); ta.focus(); } }, "Clear"))]),
    out);
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) analyze(); });
}

function renderSpfPath(sp) {
  const live = sp.live_check;
  const bad = new Set(sp.bad_ips);
  const rows = sp.chain.map((c) => {
    const results = [...new Set(c.spf.map((x) => x.result))];
    let spfCell;
    if (c.is_origin) {
      spfCell = el("div", {}, badge("info", "real sender"),
        live ? el("div", { style: "margin-top:4px" }, badge(resultSev(live.result), `live SPF: ${live.result}`)) : null,
        live && live.trace.length ? el("div", { class: "sub mono" }, live.trace[0].term) : null);
    } else if (bad.has(c.ip)) {
      spfCell = el("div", {}, results.map((r) => badge(resultSev(r), `EOP: ${r}`)),
        el("div", { class: "sub" }, "SPF judged against this IP"));
    } else {
      spfCell = el("span", { class: "sub" }, results.length ? results.join(", ") : "not checked");
    }
    return [
      c.hop,
      el("div", {}, el("strong", {}, c.from_org), el("div", { class: "mono sub" }, link("ip", sp.mailfrom_domain ? { t: c.ip, d: sp.mailfrom_domain } : { t: c.ip }, c.ip)),
        el("div", { class: "mono sub" }, c.host)),
      el("div", {}, el("strong", {}, c.to_org), el("div", { class: "mono sub" }, c.to_host || "")),
      spfCell,
    ];
  });
  const body = [
    el("div", { class: "card-body" }, el("div", { class: "f-detail", style: "white-space:pre-wrap" }, sp.detail)),
    el("div", { class: "hint", style: "padding:0 16px 6px" }, "Hand-offs between organisations (where the IP that matters changes):"),
    table(["Hop", "Handed off by", "To", "SPF"], rows, (i) => (bad.has(sp.chain[i].ip) ? "hl" : null)),
    el("div", { class: "cause" }, el("h3", {}, "Fix"),
      sp.fixes.map((f, i) => el("p", {}, `${i + 1}. ${f}`)),
      sp.commands.map((c) => code(c)),
      el("p", { class: "sub" }, "Exchange Online then evaluates SPF/DMARC against the real sender's IP, and stamps X-MS-Exchange-SkipListedInternetSender to show it skipped the gateway. Re-run this analysis on a new message to confirm.")),
  ];
  return card(["SPF evaluated against an intermediary ", badge(sp.severity, sp.severity === "critical" ? "DMARC failing" : "Enhanced Filtering off")], body, { flush: true });
}

function renderHeaderResult(d) {
  const frag = el("div");
  const s = d.summary;
  const loop = d.loop;
  const counts = sevCounts(d.findings);
  const sp = d.spf_path;
  let vSev = loop.verdict === "likely" ? "critical" : loop.verdict === "possible" ? "warning" : counts.critical ? "critical" : counts.warning ? "warning" : "ok";
  const worst = d.findings.find((f) => f.severity === "critical") || d.findings.find((f) => f.severity === "warning");
  const authRes = ((d.authentication.results || [])[0] || { results: [] }).results;
  const authOf = (m) => (authRes.find((r) => r.method === m) || {}).result;
  const authLine = ["spf", "dkim", "dmarc"].filter(authOf).map((m) => `${m.toUpperCase()} ${authOf(m)}`).join(", ");
  let vTitle = loop.verdict === "likely" ? `Mail loop: the message went round ${loop.route.join(" → ")}`
    : loop.verdict !== "none" ? loop.label
    : worst ? worst.title
    : `Delivered normally: ${authLine || "no authentication results in these headers"}, ${s.total_transit || "?"} end to end`;
  const bulk = d.bulk_sender;
  if (bulk && bulk.failed.length && loop.verdict === "none" && !sp) {
    vSev = counts.critical ? "critical" : "warning";
    vTitle = bulk.headline;
  }
  if (sp && loop.verdict !== "likely") {
    vSev = sp.severity === "critical" ? "critical" : "warning";
    vTitle = "Defender can't trust SPF: it's checking your gateway, not the sender";
  }
  frag.append(el("div", { class: `verdict sev-${vSev}` },
    el("div", { class: "v-icon" }, vSev === "ok" ? "✓" : "!"),
    el("div", {}, el("div", { class: "v-title" }, vTitle),
      el("div", { class: "v-sub" }, `${s.hop_count} hops · transit ${s.total_transit || "—"} · ${counts.critical} critical, ${counts.warning} warnings` +
        (loop.verdict !== "none" ? ` · loop score ${loop.score}` : "")))));
  if (sp) frag.append(renderSpfPath(sp));

  // Summary
  const fromDomain = (s.from.match(/@([\w.-]+)/) || [])[1];
  frag.append(card("Message", kv([
    ["Subject", s.subject], ["From", s.from], ["To", s.to], ["Cc", s.cc], ["Date", s.date], ["Return-Path", s.return_path],
    ["Reply-To", s.reply_to], ["Message-ID", el("span", { class: "mono" }, s.message_id || "")],
    ["Network Message ID", s.network_message_id ? el("span", { class: "mono" }, s.network_message_id) : null],
    ["Sender domain", fromDomain ? el("span", {}, fromDomain, " · ", link("domain", { d: fromDomain }, "Domain health"), " · ", link("spf", { d: fromDomain }, "SPF")) : null],
  ])));

  if (loop.verdict !== "none" || loop.likely_causes.length) {
    const body = [];
    if (loop.route.length) {
      const counts = {}; loop.route.forEach((z) => (counts[z] = (counts[z] || 0) + 1));
      body.push(el("div", { class: "card-body" }, el("div", { class: "hint", style: "margin-bottom:6px" }, "Route by organisation (consecutive hops merged)"),
        el("div", { class: "route" }, loop.route.flatMap((z, i) => [i ? el("span", { class: "arrow" }, "→") : null,
          el("span", { class: counts[z] > 1 ? "chip repeat" : "chip" }, z)]))));
    }
    loop.likely_causes.forEach((c) => body.push(el("div", { class: "cause" }, el("h3", {}, c.title), el("p", {}, c.detail),
      (c.commands || []).map((cmd) => code(cmd)))));
    frag.append(card(["Loop diagnosis ", badge(loop.verdict === "likely" ? "critical" : loop.verdict === "possible" ? "warning" : "ok", loop.label)], body, { flush: true }));
  }

  frag.append(card(`Findings (${d.findings.length})`, findingsList(d.findings), { flush: true }));
  if (d.bulk_sender) frag.append(headersBulkCard(d.bulk_sender));

  // Hops
  const maxDelay = Math.max(1, ...d.hops.map((h) => Math.max(0, h.delay_seconds || 0)));
  const repeated = new Set(Object.keys(loop.repeated_hosts || {}));
  frag.append(card(`Route (${d.hops.length} hops, oldest first)`, table(
    ["#", "From", "By", "Protocol", "Time (UTC)", "Delay"],
    d.hops.map((h) => {
      const delay = h.delay_seconds;
      const cls = delay > 3600 ? "bar crit" : delay > 300 ? "bar warn" : "bar";
      return [
        h.index,
        el("div", {}, el("div", { class: "mono" }, h.from_host || "—"),
          h.from_ip ? el("div", { class: "sub" }, link("ip", fromDomain ? { t: h.from_ip, d: fromDomain } : { t: h.from_ip }, h.from_ip), h.from_private ? " (private)" : "", h.from_provider ? ` · ${h.from_provider}` : "") : null,
          h.helo && h.helo !== h.from_host ? el("div", { class: "sub" }, `HELO ${h.helo}`) : null),
        el("div", {}, el("div", { class: "mono" }, h.by_host || "—"), h.by_provider ? el("div", { class: "sub" }, h.by_provider) : null),
        el("div", {}, h.with || "—", h.via ? el("div", { class: "sub" }, `via ${h.via}`) : null,
          el("div", {}, h.tls ? badge("ok", h.tls_version || "TLS") : badge("muted", "no TLS")), h.cipher ? el("div", { class: "sub mono" }, h.cipher) : null),
        el("div", { class: "mono" }, fmtTime(h.timestamp)),
        el("div", {}, delay == null ? "—" : fmtDuration(delay), delay != null ? el("div", { class: cls }, el("span", { style: `width:${Math.min(100, Math.max(2, (Math.max(0, delay) / maxDelay) * 100))}%` })) : null),
      ];
    }),
    (i) => (repeated.has(d.hops[i].by_host) ? "hl" : null)), { flush: true }));

  // Authentication
  const auth = d.authentication;
  const authBody = [];
  auth.results.forEach((ar, idx) => {
    authBody.push(el("div", { class: "card-body" },
      el("div", { class: "hint" }, `Authentication-Results #${idx + 1}${ar.authserv_id ? ` by ${ar.authserv_id}` : ""}`),
      table(["Check", "Result", "Details"], ar.results.map((r) => [
        r.method.toUpperCase(), badge(resultSev(r.result), r.result),
        el("div", {}, Object.entries(r.props).map(([k, v]) => el("div", { class: "mono" }, `${k}=${v}`)),
          r.action ? el("div", {}, `action=${r.action}`) : null,
          r.reason ? el("div", {}, r.explain || `reason=${r.reason}`) : null,
          r.comment ? el("div", { class: "sub" }, r.comment) : null),
      ]))));
  });
  if (auth.dkim_signatures.length) {
    authBody.push(el("div", { class: "card-body" }, el("div", { class: "hint" }, "DKIM signatures"),
      table(["Domain (d=)", "Selector (s=)", "Algorithm", ""], auth.dkim_signatures.map((s) => [s.d, s.s || "—", s.a || "—",
        s.d && s.s ? link("domain", { d: s.d, sel: s.s }, "Check key") : ""]))));
  }
  if (auth.arc_sets) authBody.push(el("div", { class: "card-body hint" }, `ARC chain: ${auth.arc_sets} set(s). The message was forwarded or modified by an intermediary that vouched for the original authentication results.`));
  if (!authBody.length) authBody.push(el("div", { class: "card-body hint" }, "No Authentication-Results headers found."));
  frag.append(card("Authentication", authBody, { flush: true }));

  if (d.microsoft && d.microsoft.fields.length) {
    frag.append(card("Microsoft 365 / EOP diagnostics", table(["Field", "Value", "Meaning"],
      d.microsoft.fields.map((f) => [f.field, el("span", { class: "mono" }, f.value), f.meaning || ""])), { flush: true }));
  }

  const a = d.alignment;
  frag.append(card("Identity alignment", kv([
    ["From", a.from_display ? `${a.from_display} <${a.from}>` : a.from], ["Envelope (Return-Path)", a.return_path],
    ["SPF domain (smtp.mailfrom)", a.spf_domain], ["DKIM signing domain(s)", a.dkim_domains.join(", ")],
    ["Reply-To", a.reply_to], ["Sender", a.sender],
  ])));

  const filter = el("input", { type: "text", class: "filter", placeholder: "Filter headers…" });
  const tbody = el("div");
  const draw = () => {
    const q = filter.value.toLowerCase();
    tbody.replaceChildren(table(["Header", "Value"], d.headers.filter((h) => !q || h.name.toLowerCase().includes(q) || h.value.toLowerCase().includes(q))
      .map((h) => [el("span", { class: "mono" }, h.name), el("span", { class: "mono" }, h.value)])));
  };
  filter.addEventListener("input", draw); draw();
  frag.append(card(`All headers (${d.headers.length})`, [filter, tbody], { flush: true }));
  return frag;
}

/** Bulk-sender requirements checklist (Gmail / Yahoo / Outlook.com). */
const HEADERS_BULK_BADGE = { na: ["muted", "if marketing"], pass: ["ok", "pass"], fail: ["critical", "fail"], warning: ["warning", "partly"], unknown: ["muted", "unknown"] };
function headersBulkCard(b) {
  const fails = b.items.filter((i) => i.status === "fail").length;
  const unknown = b.items.filter((i) => i.status === "unknown").length;
  const status = fails ? badge("warning", `${fails} of ${b.items.length} missing`) : b.failed.length ? badge("warning", "caveat")
    : unknown ? badge("muted", `${unknown} unverified`) : badge("ok", "all met");
  return card(["Bulk sender requirements (Gmail / Yahoo / Outlook.com) ", status], [
    el("div", { class: "card-body", style: "padding-bottom:0" }, el("strong", {}, b.headline)),
    el("div", { class: "card-body hint" }, "Shown because this looks like bulk mail: ", b.reasons.join(", "),
      ". Major mailbox providers require these from bulk senders; check each provider's current sender guidelines for exact thresholds."),
    table(["Requirement", "Result", "Why"], b.items.map((i) => {
      const [sev, text] = HEADERS_BULK_BADGE[i.status] || ["muted", i.status];
      return [i.label, badge(sev, text), i.detail];
    }), (r) => (b.items[r].status === "fail" ? "hl" : null)),
  ], { flush: true });
}

/* =============================================================== NDR DECODER */
function renderNdrTool(main) {
  const ta = el("textarea", { placeholder: "Paste the bounce / NDR message here, including 'Diagnostic information for administrators' and 'Original message headers' if present.", spellcheck: "false" });
  const out = el("div");
  const go = () => ta.value.trim() && runInto(out, "Decoding…", () => api("/api/ndr/analyze", { body: { raw: ta.value } }), renderNdrResult);
  main.append(card(null, [ta, el("div", { class: "btn-row" },
    el("button", { class: "btn", type: "button", onclick: go }, "Decode"),
    el("button", { class: "btn secondary", type: "button", onclick: async () => { ta.value = await (await fetch("samples/ndr-loop.txt")).text(); go(); } }, "Load sample (5.4.14)"),
    el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; out.replaceChildren(); } }, "Clear"))]), out);
}

function renderNdrResult(d) {
  const frag = el("div");
  const primary = d.codes[0];
  const sev = !primary ? ((d.x500 || []).length ? "critical" : "info") : primary.code.startsWith("5") ? "critical" : primary.code.startsWith("4") ? "warning" : "ok";
  frag.append(el("div", { class: `verdict sev-${sev}` }, el("div", { class: "v-icon" }, "!"),
    el("div", {}, el("div", { class: "v-title" }, d.summary),
      el("div", { class: "v-sub" }, primary ? primary.generic : "", d.is_loop ? " · Mail loop. See the original headers analysis below." : "",
        (d.x500 || []).length && primary ? " · Stale cached address (IMCEAEX): add the X500 address below to the recipient." : ""))));
  (d.x500 || []).forEach((x) => frag.append(ndrX500Card(x)));
  d.codes.forEach((c) => frag.append(card([el("span", { class: "mono" }, `${c.smtp_code ? c.smtp_code + " " : ""}${c.code}`), " ", c.title, " ", !c.known ? badge("muted", "generic") : null], [
    c.cause ? el("p", { style: "margin:0 0 8px" }, el("strong", {}, "Cause: "), c.cause) : null,
    c.fix ? el("p", { style: "margin:0 0 8px" }, el("strong", {}, "Fix: "), c.fix) : null,
    el("div", { class: "hint" }, "Seen in:"), code(c.context),
  ])));
  if (d.components.length) frag.append(card("Exchange diagnostic components", table(["Component", "Meaning"], d.components.map((c) => [el("span", { class: "mono" }, c.component), c.meaning])), { flush: true }));
  const ex = d.exchange;
  const rows = [["Generating server", ex.generating_server], ["Receiving server", ex.receiving_server], ["Rejecting server", ex.rejecting_server],
    ["Remote server returned", ex.remote_server], ["Recipients", d.recipients.join(", ")], ...Object.entries(d.dsn)];
  if (rows.some(([, v]) => v)) frag.append(card("Delivery details", kv(rows)));
  if (d.original_headers) {
    frag.append(el("h2", { style: "font-size:16px;margin:24px 0 10px" }, "Original message headers"));
    frag.append(renderHeaderResult(d.original_headers));
  }
  return frag;
}

/** IMCEAEX → X500: the legacyExchangeDN a stale autocomplete entry pointed at. */
function ndrX500Card(x) {
  const alias = x.alias_hint ? ` The last cn= part (${x.alias_hint}) is usually the recipient's alias at the time the address was cached.` : "";
  return el("div", {}, card(["Stale cached address: X500 needed ", badge("critical", "IMCEAEX")], [
    findingsList([{ severity: "critical",
      title: "The sender's Outlook used a stale cached address (legacyExchangeDN). Add this X500 proxy address to the recipient.",
      detail: "Outlook's autocomplete (or a cached contact) stores the mailbox's old legacyExchangeDN, not its SMTP address. After a migration, " +
        "re-creation or tenant move that DN no longer exists, so Exchange can't resolve it (usually 550 5.1.1 RESOLVER.ADR.ExRecipNotFound)." + alias }]),
    el("div", { class: "hint", style: "margin:10px 0 4px" }, "X500 address (exact, decoded from the IMCEAEX address):"),
    code(x.x500),
    el("details", { style: "margin-top:8px" }, el("summary", {}, "Encoded form found in the NDR"), el("div", { class: "mono sub", style: "word-break:break-all;margin-top:6px" }, x.encoded)),
  ]), nextSteps([
      { title: "Cloud-only recipient (mailbox created in Exchange Online)", detail: "Run in Exchange Online PowerShell (Connect-ExchangeOnline).",
        commands: [`Set-Mailbox <recipient> -EmailAddresses @{add="${x.x500}"}`] },
      { title: "Recipient synced from on-premises AD (Entra Connect)", detail: "Add it in AD (Exchange Online can't change synced attributes), then sync.",
        commands: [`Set-ADUser <user> -Add @{proxyAddresses="${x.x500}"}`, "Start-ADSyncSyncCycle -PolicyType Delta"] },
      { title: "Clear the sender's stale autocomplete entry",
        detail: "In the sender's Outlook, start typing the recipient's name, highlight the old suggestion and press Delete (or click its X), then pick the recipient from the address book. The X500 fixes existing replies and calendar items; this stops new mail using the stale entry." },
  ], "What to do: add the X500 address"));
}

/* ============================================================= DOMAIN HEALTH */
function renderDomainTool(main, params) {
  const dom = el("input", { type: "text", name: "d", placeholder: "contoso.com", value: params.get("d") || "", required: true });
  const sel = el("input", { type: "text", name: "sel", placeholder: "s1, mykey (optional)", value: params.get("sel") || "" });
  const res = resolverSelect("r", params.get("r") || "system");
  const out = el("div");
  const form = el("form", { class: "tool-form" },
    el("div", { class: "field grow" }, el("label", {}, "Domain"), dom),
    el("div", { class: "field" }, el("label", {}, "Extra DKIM selectors"), sel),
    el("div", { class: "field" }, el("label", {}, "Resolver"), res),
    el("button", { class: "btn", type: "submit" }, "Check"));
  form.addEventListener("submit", (e) => { e.preventDefault(); location.hash = "domain?" + new URLSearchParams({ d: dom.value.trim(), sel: sel.value.trim(), r: res.value }); });
  main.append(card(null, form), out);
  if (params.get("d")) {
    const qs = new URLSearchParams({ resolver: params.get("r") || "system", selectors: params.get("sel") || "" });
    runInto(out, `Checking ${params.get("d")}… (DNS, DKIM selectors, MTA-STS, tenant lookup)`, () => api(`/api/domain/${encodeURIComponent(params.get("d"))}?${qs}`), renderDomainResult);
  }
}

function renderDomainResult(d) {
  const frag = el("div");
  const sm = d.summary;
  // Headline: name the worst problems in plain words.
  const problems = d.findings.filter((f) => f.severity === "critical" || f.severity === "warning");
  const sev = sm.critical ? "critical" : sm.warning ? "warning" : "ok";
  const label = (f) => (f.area && !f.title.includes(f.area) ? `${f.area}: ${f.title}` : f.title);
  const parked = d.findings.find((f) => f.title === "Parked domain");
  const title = !problems.length ? (parked ? `${d.domain} is a parked domain, locked down against spoofing` : `${d.domain}: mail configuration looks healthy`)
    : `${d.domain}: ${label(problems[0])}`;
  frag.append(verdict(sev, title, problems.length > 1 ? `${problems.length - 1} more: ` + problems.slice(1, 4).map(label).join(" · ") + (problems.length > 4 ? " …" : "") : null));
  frag.append(facts([
    ["Mail platform", d.mail_platform || "Unknown"], ["Inbound gateway", (d.inbound_gateways || []).join(", ")],
    ["SPF lookups", d.spf.record ? `${d.spf.lookup_count}/10` : "no SPF"],
    ["DMARC", (d.dmarc.tags && d.dmarc.tags.p) ? `p=${d.dmarc.tags.p}` : "none"],
    ["DKIM keys", String(d.dkim.found.filter((k) => k.bits).length)],
    ["MTA-STS", d.mta_sts.policy ? d.mta_sts.policy.mode : "off"],
  ]));
  frag.append(card(`Findings`, findingsList(d.findings, { area: true }), { flush: true }));

  frag.append(card("MX records", d.mx.records.length ? table(["Pref", "Host", "Provider", "IPs / reverse DNS"], d.mx.records.map((r) => [
    r.preference, el("div", {}, el("span", { class: "mono" }, r.host), r.cname ? el("div", { class: "sub" }, `CNAME → ${r.cname}`) : null),
    r.provider || el("span", { class: "sub" }, "Unknown / self-hosted"),
    el("div", {}, r.ips.map((ip) => el("div", { class: "mono" }, link("blacklist", { t: ip.ip }, ip.ip), " ",
      ip.ptr.length ? el("span", { class: "sub" }, `→ ${ip.ptr[0]}`) : el("span", { class: "sub" }, "no PTR"), " ",
      ip.forward_confirmed ? badge("ok", "FCrDNS") : null))),
  ])) : el("div", { class: "hint" }, d.mx.null_mx ? "Null MX: this domain accepts no mail." : "No MX records."), { flush: d.mx.records.length > 0, extra: link("smtp", { t: d.domain }, "Test SMTP →") }));

  const spf = d.spf;
  frag.append(card("SPF", [
    spf.record ? code(spf.record) : el("div", { class: "hint" }, "No SPF record."),
    spf.record ? el("div", { class: "hint" }, `${spf.lookup_count}/10 DNS lookups · ${spf.networks.length} authorised networks · `, link("spf", { d: d.domain }, "Open SPF Inspector →")) : null,
  ], { extra: link("spfbuild", { d: d.domain }, spf.record ? "Fix / edit SPF →" : "Create SPF →") }));

  const dm = d.dmarc;
  frag.append(card("DMARC", dm.record ? [code(dm.record), dm.inherited ? el("div", { class: "hint" }, `Inherited from ${dm.source}`) : null,
    table(["Tag", "Value", "Meaning"], Object.entries(dm.tags).map(([k, v]) => [el("span", { class: "mono" }, k), el("span", { class: "mono" }, v), DMARC_TAGS[k] || ""]))]
    : el("div", { class: "hint" }, "No DMARC record."), { extra: link("dmarcbuild", { d: d.domain }, dm.record ? "Fix / next stage →" : "Create DMARC →") }));

  const dk = d.dkim;
  frag.append(card(`DKIM (${dk.found.length} selector${dk.found.length === 1 ? "" : "s"} found, ${dk.selectors_checked} checked)`, dk.found.length ? table(["Selector", "Key", "CNAME target / status"], dk.found.map((k) => [
    el("span", { class: "mono" }, k.selector),
    k.bits ? `${k.bits}-bit ${k.key_type}` : k.revoked ? badge("info", "revoked") : badge("warning", "no key"),
    el("div", {}, k.cname ? el("div", { class: "mono sub" }, k.cname) : null, k.error ? el("div", { class: "sub" }, k.error) : null, k.testing ? badge("info", "t=y testing") : null),
  ])) : el("div", { class: "card-body hint" }, "No keys found on the common selectors. Add the s= value from a real message's DKIM-Signature as an extra selector."), { flush: true }));

  const sts = d.mta_sts;
  const m = d.m365;
  frag.append(el("div", { class: "grid-2" },
    card("MTA-STS / TLS-RPT / BIMI", kv([
      ["MTA-STS record", sts.record ? el("span", { class: "mono" }, sts.record) : "not configured"],
      ["MTA-STS mode", sts.policy ? sts.policy.mode : null],
      ["MTA-STS mx", sts.policy ? sts.policy.mx.join(", ") : null],
      ["max_age", sts.policy ? sts.policy.max_age : null],
      ["TLS-RPT", d.tls_rpt.record ? el("span", { class: "mono" }, d.tls_rpt.record) : "not configured"],
      ["BIMI", d.bimi.record ? el("span", { class: "mono" }, d.bimi.record) : "not configured"],
    ])),
    card("Microsoft 365 / DNS hosting", kv([
      ["Entra tenant ID", m.tenant_id ? el("span", { class: "mono" }, m.tenant_id) : "not found"],
      ["Namespace", m.namespace_type], ["Federation brand", m.federation_brand], ["Federated auth URL", m.auth_url],
      ["Autodiscover", d.autodiscover.cname || (d.autodiscover.srv.length ? `SRV ${d.autodiscover.srv.join(", ")}` : "none")],
      ["DNS hosting", d.ns.dns_host], ["Name servers", d.ns.hosts.join(", ")],
      ["Lookup error", m.error],
    ]))));
  return frag;
}

const DMARC_BIS_DEPRECATED = " Deprecated in DMARCbis (RFC 9989), but still honoured by many receivers.";
const DMARC_TAGS = {
  v: "Version", p: "Policy for the domain", sp: "Policy for subdomains",
  np: "Policy for non-existent subdomains (DMARCbis). Defaults to sp; np=reject is recommended when p=reject.",
  psd: "Public suffix domain flag (DMARCbis): y = registry / public suffix operator, n = organisational domain, u = unspecified (default).",
  t: "Testing flag (DMARCbis): t=y means receivers treat the policy as one level lower (reject → quarantine, quarantine → none).",
  pct: "Percentage of failing mail the policy applies to." + DMARC_BIS_DEPRECATED,
  rua: "Aggregate report destinations", ruf: "Forensic (failure) report destinations",
  adkim: "DKIM alignment (r = relaxed, s = strict)", aspf: "SPF alignment (r = relaxed, s = strict)",
  fo: "Failure reporting options", ri: "Report interval (seconds)." + DMARC_BIS_DEPRECATED, rf: "Report format." + DMARC_BIS_DEPRECATED,
};

/* ============================================================== SPF INSPECTOR */
function renderSpfTool(main, params) {
  const dom = el("input", { type: "text", placeholder: "contoso.com", value: params.get("d") || "", required: true });
  const ip = el("input", { type: "text", placeholder: "203.0.113.10 (optional)", value: params.get("ip") || "" });
  const res = resolverSelect("r", params.get("r") || "system");
  const out = el("div");
  const form = el("form", { class: "tool-form" },
    el("div", { class: "field grow" }, el("label", {}, "Domain"), dom),
    el("div", { class: "field" }, el("label", {}, "Test sender IP"), ip),
    el("div", { class: "field" }, el("label", {}, "Resolver"), res),
    el("button", { class: "btn", type: "submit" }, "Inspect"));
  form.addEventListener("submit", (e) => { e.preventDefault(); location.hash = "spf?" + new URLSearchParams({ d: dom.value.trim(), ip: ip.value.trim(), r: res.value }); });
  main.append(card(null, form), out);
  if (params.get("d")) {
    const qs = new URLSearchParams({ resolver: params.get("r") || "system" });
    if (params.get("ip")) qs.set("ip", params.get("ip"));
    runInto(out, "Expanding SPF…", () => api(`/api/spf/${encodeURIComponent(params.get("d"))}?${qs}`), renderSpfResult);
  }
}

function renderSpfResult(d) {
  const frag = el("div");
  if (d.test) {
    const sev = resultSev(d.test.result);
    frag.append(el("div", { class: `verdict sev-${sev}` }, el("div", { class: "v-icon" }, sev === "ok" ? "✓" : "!"),
      el("div", {}, el("div", { class: "v-title" }, `${d.test.ip} → SPF ${d.test.result}`),
        el("div", { class: "v-sub" }, d.test.explanation),
        d.test.trace.length ? el("div", { class: "v-sub mono", style: "margin-top:4px" }, "Matched: " + d.test.trace.map((t) => `${t.domain}: ${t.term}`).join("  ⟵  ")) : null,
        d.test.result !== "pass" ? el("div", { style: "margin-top:6px" }, link("ip", { t: d.test.ip, d: d.domain }, "Who owns this IP? →")) : null)));
  }
  const n = d.lookup_count;
  if (!d.test) {
    const bad = d.findings.filter((f) => f.severity === "critical" || f.severity === "warning");
    const sev = worstSeverity(bad.length ? bad : [{ severity: "ok" }]);
    frag.append(verdict(sev,
      bad.length ? `SPF for ${d.domain}: ${bad[0].title}` : `SPF for ${d.domain} is valid (${n}/10 lookups)`,
      bad.length > 1 ? "Also: " + bad.slice(1, 4).map((f) => f.title).join(" · ") : "Enter a sender IP above to test whether a specific server passes."));
  }
  frag.append(el("div", { style: "margin:-6px 0 14px" }, link("spfbuild", { d: d.domain }, "Fix or edit this record in the SPF Builder →")));
  const gaugeCls = n > 10 ? "gauge crit" : n >= 8 ? "gauge warn" : "gauge";
  frag.append(el("div", { class: "stats" },
    el("div", { class: "stat" }, el("div", { class: "s-label" }, "DNS lookups"), el("div", { class: "s-value" }, `${n} / ${d.lookup_limit}`),
      el("div", { class: gaugeCls }, Array.from({ length: Math.max(10, n) }, (_, i) => el("span", { class: i < n ? "on" : null })))),
    stat("Void lookups", `${d.void_lookups} / 2`), stat("Authorised networks", d.networks.length), stat("Includes", d.includes.length)));
  if (d.record) frag.append(card("Record", code(d.record)));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  frag.append(card("Include tree", el("div", { class: "tree" }, el("ul", {}, spfNode(d.tree)))));
  frag.append(card(`Authorised networks (${d.networks.length})`, table(["Network", "From", "Mechanism"],
    d.networks.map((x) => [el("span", { class: "mono" }, x.network), x.source, el("span", { class: "mono" }, x.mechanism)])), { flush: true }));
  return frag;
}

function spfNode(node) {
  const head = el("div", {}, el("span", { class: "t-domain" }, node.domain), " ",
    node.error ? el("span", { class: "t-err" }, node.error) : null);
  const terms = (node.terms || []).map((t) => {
    const lookups = t.lookups ? el("span", { class: "t-lookup", title: "Counts toward the 10-lookup limit" }, " ⬤") : null;
    const extra = [];
    if (t.resolved && t.resolved.length) extra.push(el("span", { class: "t-note" }, ` → ${t.resolved.slice(0, 6).join(", ")}${t.resolved.length > 6 ? ` +${t.resolved.length - 6}` : ""}`));
    if (t.mechanism === "exists") extra.push(el("span", { class: "t-note" }, t.exists ? " (exists)" : " (does not exist)"));
    if (t.note) extra.push(el("span", { class: "t-note" }, ` ${t.note}`));
    if (t.error) extra.push(el("span", { class: "t-err" }, ` ${t.error}`));
    return el("li", {}, el("span", { class: t.ignored ? "t-term t-ignored" : "t-term" }, t.raw), lookups, extra,
      t.child ? el("ul", {}, spfNode(t.child)) : null);
  });
  if (node.redirect) terms.push(el("li", {}, el("span", { class: "t-term" }, `redirect=${node.redirect.domain}`), el("ul", {}, spfNode(node.redirect))));
  return el("li", {}, head, terms.length ? el("ul", {}, terms) : null);
}

/* ================================================================= SMTP TEST */
function renderSmtpTool(main, params) {
  const target = el("input", { type: "text", placeholder: "contoso.com, mx.contoso.com or 203.0.113.10", value: params.get("t") || "", required: true });
  const port = el("select", {}, [25, 587, 465, 2525].map((p) => el("option", { value: p, selected: String(p) === (params.get("port") || "25") }, String(p))));
  const mode = el("select", {}, [["starttls", "STARTTLS"], ["implicit", "Implicit TLS"], ["none", "No TLS"]].map(([v, l]) => el("option", { value: v, selected: v === (params.get("mode") || "starttls") }, l)));
  const helo = el("input", { type: "text", placeholder: "(default)", value: params.get("helo") || "" });
  const mx = el("input", { type: "checkbox", checked: params.get("mx") !== "0" });
  const probe = el("input", { type: "checkbox", checked: !!params.get("rcpt") });
  const from = el("input", { type: "text", placeholder: "empty = null sender <>", value: params.get("from") || "" });
  const rcpt = el("input", { type: "text", placeholder: "user@contoso.com", value: params.get("rcpt") || "" });
  port.addEventListener("change", () => { mode.value = port.value === "465" ? "implicit" : "starttls"; });
  const probeFields = el("div", { class: "tool-form", style: "margin-top:10px" },
    el("div", { class: "field grow" }, el("label", {}, "MAIL FROM"), from),
    el("div", { class: "field grow" }, el("label", {}, "RCPT TO"), rcpt),
    el("div", { class: "hint", style: "flex-basis:100%" }, "Runs MAIL FROM / RCPT TO and then RSET. No message is sent. Shows whether the server accepts the recipient and, if not, the exact rejection."));
  probeFields.hidden = !probe.checked;
  probe.addEventListener("change", () => (probeFields.hidden = !probe.checked));
  const out = el("div");
  const form = el("form", {},
    el("div", { class: "tool-form" },
      el("div", { class: "field grow" }, el("label", {}, "Target"), target),
      el("div", { class: "field" }, el("label", {}, "Port"), port),
      el("div", { class: "field" }, el("label", {}, "TLS"), mode),
      el("div", { class: "field" }, el("label", {}, "HELO name"), helo),
      el("button", { class: "btn", type: "submit" }, "Test")),
    el("div", { class: "tool-form", style: "margin-top:8px;gap:18px" },
      el("label", { class: "check" }, mx, "Resolve domain to its MX hosts"),
      el("label", { class: "check" }, probe, "Test a recipient (RCPT TO)")),
    probeFields);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const p = { t: target.value.trim(), port: port.value, mode: mode.value, mx: mx.checked ? "1" : "0" };
    if (helo.value.trim()) p.helo = helo.value.trim();
    if (probe.checked && rcpt.value.trim()) { p.rcpt = rcpt.value.trim(); p.from = from.value.trim(); }
    location.hash = "smtp?" + new URLSearchParams(p);
  });
  main.append(card(null, form), el("div", { class: "notice" }, "Connections come from the machine running MSPGather. Many ISPs and cloud providers block outbound port 25, so a timeout can mean YOUR side is blocked. Test port 587 to a known server to tell the difference."), out);
  if (params.get("t")) {
    const body = { target: params.get("t"), port: Number(params.get("port") || 25), tls_mode: params.get("mode") || "starttls",
      helo: params.get("helo") || null, resolve_mx: params.get("mx") !== "0" };
    if (params.get("rcpt")) { body.rcpt_to = params.get("rcpt"); body.mail_from = params.get("from") || ""; }
    runInto(out, "Connecting…", () => api("/api/smtp/test", { body }), renderSmtpResult);
  }
}

function renderSmtpResult(d) {
  const frag = el("div");
  const failed = d.results.filter((r) => !r.connected);
  const withIssues = d.results.filter((r) => r.connected && r.findings.some((f) => f.severity === "critical" || f.severity === "warning"));
  const first = (r) => (r.findings.find((f) => f.severity === "critical") || r.findings.find((f) => f.severity === "warning") || {}).title;
  const tlsNote = d.results.every((r) => r.tls) ? "with valid TLS" : d.tls_mode === "none" ? "(TLS not tested)" : "(no TLS negotiated)";
  let sev = d.results.every((r) => r.tls) || d.tls_mode === "none" ? "ok" : "warning";
  let title = d.results.length === 1 ? `${d.results[0].host} accepted the SMTP session ${tlsNote}` : `All ${d.results.length} servers accepted the SMTP session ${tlsNote}`;
  if (failed.length === d.results.length) {
    sev = "critical";
    title = `Could not complete an SMTP session with ${d.target}: ${first(failed[0]) || failed[0].error}`;
  } else if (failed.length) {
    sev = "critical";
    title = `${failed.length} of ${d.results.length} MX hosts failed (${failed.map((r) => r.host).join(", ")}): ${first(failed[0]) || failed[0].error}`;
  } else if (withIssues.length) {
    sev = withIssues.some((r) => r.findings.some((f) => f.severity === "critical")) ? "critical" : "warning";
    title = `${withIssues[0].host}: ${first(withIssues[0])}`;
  }
  frag.append(verdict(sev, title, d.resolved_mx ? `Tested ${d.results.length} MX host(s) of ${d.target} on port ${d.port}` : `Port ${d.port}, ${d.tls_mode}`));
  d.results.forEach((r) => {
    const c = sevCounts(r.findings);
    const status = !r.connected ? badge("critical", "failed") : c.critical ? badge("critical", "problems") : c.warning ? badge("warning", "warnings") : badge("ok", "OK");
    const t = r.tls, cert = t && t.certificate;
    frag.append(card([el("span", { class: "mono" }, `${r.host}:${r.port}`), " ", status, r.provider ? el("span", { class: "sub" }, ` · ${r.provider}`) : null], [
      el("div", { class: "stats" },
        stat("Connect", r.timings_ms.connect != null ? `${r.timings_ms.connect} ms` : "—"),
        stat("TLS", t ? `${t.version}` : r.starttls_offered === false ? "not offered" : "—", true),
        stat("Certificate", cert ? (cert.expired ? "expired" : `${cert.days_left} days left`) : "—", true),
        stat("Trusted chain", t && t.trusted != null ? (t.trusted ? "yes" : "no") : "—", true)),
      findingsList(r.findings),
      kv([["Banner", r.banner ? el("span", { class: "mono" }, r.banner) : null], ["Error", r.error],
        ["EHLO extensions", r.ehlo.length ? el("span", { class: "mono" }, r.ehlo.join(" · ")) : null],
        ["Cipher", t ? `${t.cipher} (${t.bits} bits)` : null],
        ["Cert subject", cert ? cert.subject : null], ["Cert issuer", cert ? cert.issuer : null],
        ["Cert names", cert && cert.san.length ? cert.san.join(", ") : null],
        ["Valid until", cert ? cert.not_after : null], ["Trust error", t ? t.trust_error : null],
        ["RCPT TO", r.rcpt_to ? `${r.rcpt_to.code} ${r.rcpt_to.message}` : null]]),
      el("details", { style: "margin-top:12px" }, el("summary", {}, "SMTP transcript"),
        el("div", { class: "transcript", style: "margin-top:8px" }, r.transcript.map((l) => el("div", { class: l.dir === "C" ? "c" : "s" }, `${l.dir}: ${l.text}`)))),
    ]));
  });
  return frag;
}

/* =========================================================== BLACKLIST CHECK */
function renderBlacklistTool(main, params) {
  const target = el("input", { type: "text", placeholder: "203.0.113.10 or contoso.com", value: params.get("t") || "", required: true });
  const res = resolverSelect("r", params.get("r") || "system");
  const out = el("div");
  const form = el("form", { class: "tool-form" },
    el("div", { class: "field grow" }, el("label", {}, "IP address or domain"), target),
    el("div", { class: "field" }, el("label", {}, "Resolver"), res),
    el("button", { class: "btn", type: "submit" }, "Check"));
  form.addEventListener("submit", (e) => { e.preventDefault(); location.hash = "blacklist?" + new URLSearchParams({ t: target.value.trim(), r: res.value }); });
  main.append(card(null, form), out);
  if (params.get("t")) {
    runInto(out, "Querying blocklists…", () => api(`/api/blacklist/${encodeURIComponent(params.get("t"))}?resolver=${encodeURIComponent(params.get("r") || "system")}`), (d) => {
      const frag = el("div");
      const refused = d.targets.some((t) => t.results.some((r) => r.error && /public|refused/i.test(r.error)));
      const all = d.targets.flatMap((t) => t.results.map((r) => ({ ...r, subject: t.subject })));
      const answered = all.filter((r) => !r.error);
      const listed = all.filter((r) => r.listed);
      const unknown = all.filter((r) => r.error);
      let bsev, btitle;
      if (listed.length) {
        bsev = "critical";
        btitle = `${listed[0].subject} is listed on ${listed.map((r) => r.list).filter((v, i, a) => a.indexOf(v) === i).slice(0, 3).join(", ")}${listed.length > 3 ? ` and ${listed.length - 3} more` : ""}`;
      } else if (!answered.length) {
        bsev = "warning";
        btitle = "Couldn't check: no blocklist answered (" + (unknown[0] ? unknown[0].error : "no applicable lists") + ")";
      } else if (unknown.length) {
        bsev = "info";
        btitle = `Not listed on the ${answered.length} lists that answered; ${unknown.length} couldn't be checked (${[...new Set(unknown.map((r) => r.list))].slice(0, 3).join(", ")})`;
      } else {
        bsev = "ok";
        btitle = `Not listed on any of the ${answered.length} blocklists checked`;
      }
      frag.append(verdict(bsev, btitle, `${d.targets.length} target(s) checked via the ${d.resolver} resolver`));
      if (listed.length) frag.append(nextSteps([
        { title: "Find out why it was listed", detail: "Each list's lookup page (linked in the table) gives the reason and when. Usually: a compromised account or device sending spam, an open relay, or a shared IP from a hosting provider." },
        { title: "Fix the cause before requesting removal", detail: "Reset compromised accounts, stop the spam source and check outbound mail logs. Lists re-add IPs that keep sending spam." },
        { title: "Request delisting", detail: "Use each list's removal page. Many lists (SpamCop, PSBL) expire listings automatically within 24–48h once the spam stops; UCEPROTECT Level 2 lists whole provider ranges and is usually ignored by major mail providers." },
      ]));
      if (refused) frag.append(el("div", { class: "notice" }, "Some lists refused the query because it came through a public DNS resolver. Results from those lists are unknown, not clean. Run MSPGather on a network with its own recursive resolver, or check the list's website."));
      d.targets.forEach((t) => {
        const rd = t.rdns;
        frag.append(card([el("span", { class: "mono" }, t.subject), " ", t.listed ? badge("critical", `${t.listed} listed`) : badge("ok", "clean"), t.policy ? badge("info", `${t.policy} policy`) : null, t.errors ? badge("muted", `${t.errors} unknown`) : null, el("span", { class: "sub" }, ` · ${t.role}`),
          rd ? el("span", { class: "sub" }, ` · PTR ${rd.ptr[0] || "none"}${rd.ptr.length ? (rd.forward_confirmed ? " (FCrDNS ok)" : " (does not resolve back)") : ""}`) : null],
          table(["List", "Status", "Details"], [...t.results].sort((a, b) => (b.listed - a.listed) || (b.policy - a.policy) || (!!b.error - !!a.error)).map((r) => [
            el("div", {}, el("a", { href: r.info, target: "_blank", rel: "noopener noreferrer" }, r.list), el("div", { class: "sub mono" }, r.zone)),
            r.listed ? badge("critical", "listed") : r.policy ? badge("info", "policy") : r.error ? badge("muted", "unknown") : badge("ok", "clean"),
            el("div", {}, r.meaning, r.codes.length ? el("div", { class: "sub mono" }, r.codes.join(", ")) : null, r.reason ? el("div", { class: "sub" }, r.reason) : null, r.error ? el("div", { class: "sub" }, r.error) : null),
          ])), { flush: true }));
      });
      return frag;
    });
  }
}


/* ============================================================ REGISTRATION */
registerTool({ category: "email", group: "Analyze", id: "headers", title: "Header Analyzer", render: renderHeaderTool,
  icon: "M4 5h16M4 10h16M4 15h10M4 20h6", keywords: "received hops loop delay spoof phishing authentication-results",
  desc: "Paste message headers to trace the route, measure each hop's delay, check TLS and SPF/DKIM/DMARC, decode Microsoft 365 spam stamps, and diagnose mail loops." });
registerTool({ category: "email", group: "Analyze", id: "ndr", title: "NDR Decoder", render: renderNdrTool,
  icon: "M12 3l9 16H3zM12 10v4M12 17v.5", keywords: "bounce undeliverable 550 5.7.1 5.4.1 dsn",
  desc: "Paste a bounce message. Decodes enhanced status codes and Exchange diagnostic strings into a cause and a fix, and analyzes any original headers it contains." });
registerTool({ category: "email", group: "Domain", id: "domain", title: "Domain Health", render: renderDomainTool,
  icon: "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18", keywords: "mx dmarc dkim mta-sts bimi tenant",
  desc: "MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, Autodiscover and Microsoft 365 tenant discovery, with cross-checks that catch misconfigurations between them." });
registerTool({ category: "email", group: "Domain", id: "spf", title: "SPF Inspector", render: renderSpfTool,
  icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z", keywords: "include lookup limit permerror",
  desc: "Expands every include, counts lookups against the 10-lookup limit, finds void lookups and loops, and tests whether a specific IP passes." });
registerTool({ category: "email", group: "Connectivity", id: "smtp", title: "SMTP Test", render: renderSmtpTool,
  icon: "M3 12h13M12 7l5 5-5 5M20 4v16", keywords: "starttls port 25 587 certificate rcpt",
  desc: "Live SMTP session: banner, EHLO extensions, STARTTLS, certificate validity and trust, plus an optional recipient test. No message is ever sent." });
registerTool({ category: "email", group: "Connectivity", id: "blacklist", title: "Blacklist Check", render: renderBlacklistTool,
  icon: "M12 3a9 9 0 100 18 9 9 0 000-18zM5.6 5.6l12.8 12.8", keywords: "dnsbl spamhaus blocklist rbl reputation",
  desc: "Check an IP, or a domain plus its MX and A record IPs, against major DNS blocklists, with reverse DNS (FCrDNS) status." });
