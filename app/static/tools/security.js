"use strict";
/* Security: phishing triage (URL Analyzer) and brand protection (Lookalike Domains).
   Suspicious URLs and domains are only ever shown as text (defanged), never as clickable links. */

addStyles(`
.url-wrap { overflow-wrap: anywhere; word-break: break-all; }
.url-chain { list-style: none; margin: 0; padding: 0; }
.url-chain > li { padding: 8px 0; }
.url-chain > li + li { border-top: 1px dashed var(--border); }
.url-chain .url-step { font-size: 12px; color: var(--muted); margin-bottom: 2px; display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.url-follow { display: flex; gap: 8px; align-items: flex-start; margin-top: 10px; font-size: 13px; }
.url-follow input { margin-top: 3px; }
.url-item { margin-bottom: 18px; }
.url-item > summary { font-weight: 600; margin-bottom: 10px; color: var(--text); }
.url-item > summary .badge { margin-right: 6px; }
.lookalike-dom { white-space: nowrap; }
.lookalike-kinds { display: flex; flex-wrap: wrap; gap: 4px; }
.lookalike-kind { font-size: 11.5px; padding: 1px 7px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border); white-space: nowrap; }
`);

/* ------------------------------------------------------------------ shared */
function urlAgeText(days) {
  if (days == null) return null;
  if (days <= 0) return "today";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"} ago`;
  if (days < 730) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

function urlRegisteredText(rdap) {
  if (!rdap) return null;
  if (rdap.created) return `${rdap.created.slice(0, 10)} (${urlAgeText(rdap.age_days)})`;
  return rdap.error ? "unknown" : null;
}

function urlMono(text) {
  return el("span", { class: "mono url-wrap" }, text);
}

/* ============================================================ URL ANALYZER */
function renderUrlTool(main, params) {
  const out = el("div");
  const follow = el("input", { type: "checkbox", id: "url-follow" });
  if (params.get("follow") === "1") follow.checked = true;
  const run = (text) => runInto(out, follow.checked ? "Unwrapping, analysing and following redirects (up to ~30s)…" : "Unwrapping and analysing…",
    () => api("/api/sec/url", { body: { text, follow: follow.checked } }), renderUrlResult);
  const pb = pasteBox({
    placeholder: "Paste a suspicious link, or a whole email body: every link in it is extracted.\nSafe Links, Proofpoint, Barracuda, Google and other rewritten links are unwrapped offline. Defanged links (hxxps://example[.]com) work too.",
    onRun: run, runLabel: "Analyze", rows: 6,
    sample: async () => (await fetch("samples/security-url-phish.txt")).text(), sampleLabel: "Load sample (phishing email)",
  });
  pb.element.querySelector(".card-body").append(el("label", { class: "url-follow", for: "url-follow" }, follow,
    el("span", {}, el("strong", {}, "Follow redirects"), " (off by default). Contacts the site from this server to discover where the link really lands: ",
      "no cookies, no JavaScript, page bodies capped at 64 KB and thrown away except the title, max 10 hops, internal addresses refused at every hop. ",
      el("span", { class: "sub" }, "The site will see this server's IP, and one-time links may be used up."))));
  main.append(pb.element, out);
  if (params.get("u")) {
    pb.textarea.value = params.get("u");
    run(params.get("u"));
  }
}

function renderUrlResult(d) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  if (d.items.length === 1) {
    frag.append(urlRenderItem(d.items[0], true));
    return frag;
  }
  frag.append(card(`Links found (${d.count}${d.truncated ? ", first 25 analysed" : ""}), riskiest first`, table(["", "Real destination", "Verdict"],
    d.items.map((it) => [badge(it.severity, { critical: "Phishing?", warning: "Suspicious", info: "No red flags", ok: "Legitimate" }[it.severity]),
      el("div", {}, urlMono(it.final_defanged), it.layers.length ? el("div", { class: "sub" }, "unwrapped from " + it.layers.map((l) => l.wrapper).join(" → ")) : null),
      it.headline]),
    (i) => (d.items[i].severity === "critical" ? "hl" : null)), { flush: true }));
  d.items.forEach((it, i) => {
    const open = it.severity === "critical" || it.severity === "warning" || i === 0;
    frag.append(el("details", { class: "url-item", open },
      el("summary", {}, badge(it.severity), `Link ${i + 1}: `, el("span", { class: "mono url-wrap" }, it.final_defanged)),
      verdict(it.severity, it.headline, null), urlRenderItem(it, false)));
  });
  return frag;
}

function urlRenderItem(it, single) {
  const frag = el("div");
  const en = it.enrichment || {};
  const rd = en.rdap || {};
  const host = en.hosting || {};
  const cert = (en.tls || {}).cert;
  frag.append(facts([
    ["Real destination", it.ip ? it.ip : it.severity === "critical" || it.severity === "warning" ? (it.domain || "").replace(/\./g, "[.]") : it.domain],
    ["Brand", it.brand], ["Service", it.user_content],
    ["Registered", urlRegisteredText(en.rdap)],
    ["Hosted by", host.owner ? `${host.owner}${host.country ? " (" + host.country + ")" : ""}` : null],
    ["Unwrapped", it.layers.length ? it.layers.map((l) => l.wrapper).join(" → ") : null],
    ["Certificate", cert ? `${cert.issuer_name}, issued ${urlAgeText(cert.age_days)}` : null],
  ]));

  // How the link was unwrapped.
  if (it.layers.length || it.opaque) {
    const steps = [el("li", {}, el("div", { class: "url-step" }, "Link as received"), urlMono(it.input_defanged))];
    it.layers.forEach((l) => steps.push(el("li", {},
      el("div", { class: "url-step" }, badge("info", l.wrapper), l.to ? "decoded offline to:" : "could not be decoded"),
      l.to ? urlMono(l.to_defanged) : el("span", { class: "sub" }, l.error || ""))));
    if (it.opaque) steps.push(el("li", {}, el("div", { class: "url-step" }, badge("warning", it.opaque.wrapper), "opaque"), el("div", { class: "sub" }, it.opaque.note)));
    frag.append(card("Unwrapped link", [el("ol", { class: "url-chain" }, steps),
      el("div", { class: "hint", style: "margin-top:6px" }, "Real destination (defanged, safe to paste into a ticket):"), code(it.final_defanged)]));
  }

  frag.append(card(`Findings (${it.findings.length})`, findingsList(it.findings), { flush: true }));
  const steps = nextSteps(it.steps);
  if (steps) frag.append(steps);

  // Redirect chain.
  const fr = it.redirects;
  if (fr) {
    frag.append(card("Redirect chain (followed from this server)", [
      table(["#", "Address", "Response", "Server", "Notes"], fr.hops.map((h) => [
        h.n,
        el("div", {}, urlMono(h.defanged), h.via && h.via !== "start" ? el("div", { class: "sub" }, `reached via ${h.via}`) : null),
        h.refused ? badge("critical", "refused") : h.error ? badge("warning", "failed") : h.status
          ? badge(h.status >= 400 ? "warning" : h.status >= 300 ? "info" : "ok", `${h.status}${h.method ? " · " + h.method : ""}`) : "—",
        el("div", {}, h.ip ? el("span", { class: "mono" }, h.ip) : "—", h.server ? el("div", { class: "sub" }, h.server) : null),
        el("div", {}, h.refused || h.error || "", h.title ? el("div", {}, "Page title: ", el("strong", {}, h.title)) : null),
      ]), (i) => (fr.hops[i].refused || fr.hops[i].error ? "hl" : null)),
      el("div", { class: "card-body hint" },
        fr.stopped ? fr.stopped + " " : "",
        fr.password_field ? "The landing page contains a password field. " : "",
        fr.uses_js_redirect ? "The page has a JavaScript redirect that was not run. " : "",
        "Requests: HEAD first, then GET if needed; no cookies, no scripts, bodies capped at 64 KB and discarded after reading the title."),
    ], { flush: true }));
  }

  // Landing page (after redirects), when it's a different host.
  const land = it.landing;
  if (land) {
    const len = land.enrichment || {};
    frag.append(card("Where it lands", kv([
      ["Address", urlMono(land.defanged)], ["Domain", land.domain], ["Brand", land.brand], ["Service", land.user_content],
      ["Registered", urlRegisteredText(len.rdap)], ["Registrar", (len.rdap || {}).registrar],
      ["Hosted by", (len.hosting || {}).owner], ["IP", (len.hosting || {}).ip ? link("ip", { t: len.hosting.ip }, len.hosting.ip) : null],
    ])));
  }

  // Details.
  const tls = en.tls || {};
  frag.append(el("div", { class: "grid-2" },
    card("Domain registration (RDAP)", it.ip ? el("div", { class: "hint" }, "The link uses an IP address, so there is no domain registration.") : kv([
      ["Domain", it.domain], ["Registered", rd.created ? fmtTime(rd.created) : null], ["Age", urlAgeText(rd.age_days)],
      ["Registrar", rd.registrar], ["Registrant", rd.registrant], ["Expires", rd.expires ? rd.expires.slice(0, 10) : null],
      ["Status", (rd.status || []).length ? rd.status.join(", ") : null],
      ["Registrar abuse", (rd.abuse_emails || []).length ? rd.abuse_emails.join(", ") : null],
      ["Name servers", (rd.nameservers || []).length ? rd.nameservers.join(", ") : null],
      ["Note", rd.error],
    ])),
    card("DNS, hosting & certificate", kv([
      ["Host", it.host_unicode && it.host_unicode !== it.host ? `${it.host} (displays as ${it.host_unicode})` : it.host],
      ["Addresses", (en.a || []).length ? en.a.join(", ") : en.dns_status ? `none (${en.dns_status})` : null],
      ["Mail servers (MX)", (en.mx || []).length ? en.mx.join(", ") : en.dns_status ? "none" : null],
      ["Hosting owner", host.owner ? `${host.owner}${host.asn ? " · AS" + host.asn : ""}` : host.error || null],
      ["Reverse DNS", host.ptr], ["IP details", host.ip ? link("ip", { t: host.ip }, `Open ${host.ip} in IP Lookup →`) : null],
      ["Certificate issuer", cert ? cert.issuer_name : null],
      ["Certificate issued", cert ? `${cert.not_before.slice(0, 10)} (${urlAgeText(cert.age_days)})` : null],
      ["Certificate trusted", tls.connected ? (tls.verified ? "yes" : `no: ${tls.verify_error || "verification failed"}`) : tls.error ? `couldn't connect: ${tls.error}` : null],
      ["How", en.tls ? "TLS handshake only; no page was requested." : null],
    ]))));
  const parts = [["Scheme", it.scheme], ["Port", it.port], ["Path", it.path ? urlMono(it.path) : null],
    ["Query length", it.query_length ? `${it.query_length} characters` : null], ["SharePoint tenant", it.sharepoint_tenant]];
  if ((it.embedded_urls || []).length) {
    parts.push(["Embedded addresses", el("div", {}, it.embedded_urls.map((e) => el("div", {},
      el("span", { class: "sub" }, `${e.param}= `), urlMono(e.defanged), " ", link("url", { u: e.url }, "Analyse →"))))]);
  }
  frag.append(card("URL parts", kv(parts)));
  if (!single) return frag;
  return frag;
}

/* ======================================================== LOOKALIKE DOMAINS */
function renderLookalikeTool(main, params) {
  const out = el("div");
  main.append(card(null, [hashForm("lookalike", [
    { name: "d", label: "Client domain", placeholder: "contoso.com", grow: true, required: true },
  ], params, "Check lookalikes"), el("div", { class: "hint", style: "margin-top:6px" },
    "Generates ~150–400 typo and look-alike variants and checks which are registered (DNS only, plus registration data for the riskiest 15). Takes up to 30 seconds.")]), out);
  const d = params.get("d");
  if (d) runInto(out, "Generating variants and checking which are registered…", () => api(`/api/sec/lookalike/${encodeURIComponent(d)}`), renderLookalikeResult);
}

const LOOKALIKE_RISK = { high: ["critical", "High"], medium: ["warning", "Medium"], low: ["info", "Low"] };

function lookalikeRows(list) {
  return list.map((c) => {
    const r = c.rdap || {};
    const yours = c.ownership === "probably";
    return [
      el("div", {}, el("span", { class: "mono lookalike-dom" }, c.domain), c.unicode ? el("div", { class: "sub" }, `displays as ${c.unicode}`) : null),
      el("div", { class: "lookalike-kinds" }, c.kind_labels.map((k) => el("span", { class: "lookalike-kind" }, k))),
      yours ? badge("ok", "Probably yours") : badge(LOOKALIKE_RISK[c.risk][0], LOOKALIKE_RISK[c.risk][1]),
      c.has_mx ? el("div", {}, badge("warning", "Has MX"), c.mx.slice(0, 2).map((m) => el("div", { class: "mono sub" }, m)))
        : el("span", { class: "sub" }, c.null_mx ? "null MX (no mail)" : "none"),
      c.hosting && c.hosting.ip ? el("div", {}, link("ip", { t: c.hosting.ip }, c.hosting.ip), c.hosting.as_name ? el("div", { class: "sub" }, c.hosting.as_name) : null)
        : el("span", { class: "sub" }, "no website"),
      r.created ? el("div", {}, r.created.slice(0, 10), el("div", { class: "sub" }, urlAgeText(r.age_days)), r.registrar ? el("div", { class: "sub" }, r.registrar) : null)
        : el("span", { class: "sub" }, r.error ? "unavailable" : "not looked up"),
      el("div", { class: "sub" }, [c.parked ? "Parked / for sale" : null, ...(c.ownership_hints || []).map((h) => `${h[0]} yours: ${h[1]}`)].filter(Boolean).join(" · ") || ""),
    ];
  });
}

function renderLookalikeResult(d) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  frag.append(facts([
    ["Variants checked", d.checked], ["Registered", d.registered_count], ["Not yours", d.theirs_count],
    ["Can send/receive mail", d.mx_count], ["Probably yours", d.yours_count], ["Took", `${d.elapsed}s`],
  ]));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  const steps = nextSteps(d.steps);
  if (steps) frag.append(steps);

  const cols = ["Domain", "Type", "Risk", "Mail (MX)", "Website", "Registered", "Notes"];
  const theirs = d.registered.filter((c) => c.ownership !== "probably");
  const yours = d.registered.filter((c) => c.ownership === "probably");
  if (theirs.length) {
    frag.append(card(`Registered lookalikes, riskiest first (${theirs.length})`, [
      table(cols, lookalikeRows(theirs), (i) => (theirs[i].risk === "high" ? "hl" : null)),
      el("div", { class: "card-body hint" }, "Registration dates are looked up for the riskiest 15 only (registries rate-limit). ",
        "Has MX = the domain can send and receive email, which is what business email compromise (fake invoices, payment-change requests) needs."),
    ], { flush: true }));
  }
  if (yours.length) {
    frag.append(el("details", { style: "margin-bottom:16px" }, el("summary", {}, `Probably ${d.domain}'s own registrations (${yours.length})`),
      card(null, table(cols, lookalikeRows(yours)), { flush: true })));
  }
  frag.append(card(`Baseline: ${d.domain}`, kv([
    ["Name servers", (d.client.ns || []).join(", ") || "none"], ["Mail servers", (d.client.mx || []).join(", ") || "none"],
    ["Registrar", d.client.registrar], ["Registered", d.client.created ? d.client.created.slice(0, 10) : null],
    ["Domain health", link("domain", { d: d.domain }, `Check ${d.domain} →`)],
  ])));
  const notReg = Object.entries(d.not_registered_by_kind || {}).filter(([, n]) => n > 0);
  frag.append(el("details", {}, el("summary", {}, `Not registered (${notReg.reduce((a, [, n]) => a + n, 0)} variants)${d.unknown.length ? `, ${d.unknown.length} unknown` : ""}`),
    card(null, [kv(notReg.map(([k, n]) => [k, String(n)])),
      d.unknown.length ? el("div", { class: "hint", style: "margin-top:8px" }, "Couldn't be checked (DNS timeout): ", d.unknown.join(", ")) : null])));
  return frag;
}

/* ============================================================ REGISTRATION */
registerTool({ category: "security", group: "Phishing triage", id: "url", title: "URL Analyzer", render: renderUrlTool,
  icon: "M10 14a4 4 0 005.66 0l3-3a4 4 0 00-5.66-5.66l-1 1M14 10a4 4 0 00-5.66 0l-3 3a4 4 0 005.66 5.66l1-1",
  keywords: "phishing link url safe links proofpoint urldefense barracuda mimecast unwrap defang punycode homoglyph redirect suspicious click",
  desc: "Paste a suspicious link or email body: unwraps Safe Links / Proofpoint / Barracuda offline, flags lookalike and brand-new domains, and tells you whether it's likely phishing and how to block and clean up." });
registerTool({ category: "security", group: "Brand protection", id: "lookalike", title: "Lookalike Domains", render: renderLookalikeTool,
  icon: "M4 7h7M4 12h5M4 17h7M15 6l5 12M20 6l-5 12",
  keywords: "typosquatting lookalike domain impersonation bec brand homoglyph cousin domain spoof",
  desc: "Enter a client's domain: finds registered typo and look-alike domains, flags the ones with mail servers (business email compromise risk) or registered recently, and gives the block commands." });
