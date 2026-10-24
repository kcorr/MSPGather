"use strict";
/* Discovery: profile a prospect from their domain name. */

addStyles(`
.disc-actions { display: flex; flex-wrap: wrap; gap: 8px; margin: -4px 0 16px; }
.disc-tp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0; }
.disc-tp-col { padding: 12px 16px; border-left: 1px solid var(--border); }
.disc-tp-col:first-child { border-left: 0; }
.disc-tp-col h3 { display: flex; align-items: center; gap: 8px; font-size: 13px; margin: 0 0 8px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
.disc-tp { padding: 8px 0; border-top: 1px solid var(--border); }
.disc-tp:first-of-type { border-top: 0; }
.disc-tp-title { font-weight: 600; }
.disc-tp-area { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.disc-tp-detail { color: var(--muted); font-size: 13px; margin-top: 2px; }
.disc-grade { display: flex; align-items: center; gap: 16px; padding: 14px 16px; border-bottom: 1px solid var(--border); }
.disc-grade-letter { width: 64px; height: 64px; border-radius: 14px; display: grid; place-items: center; font-size: 34px; font-weight: 800; color: #fff; flex: none; }
.disc-grade-A, .disc-grade-B { background: var(--ok); }
.disc-grade-C { background: var(--warn); }
.disc-grade-D, .disc-grade-F { background: var(--crit); }
.disc-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.disc-chip { border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px; font-size: 12.5px; background: var(--panel-2); }
.disc-svc-cat { padding: 10px 16px; border-top: 1px solid var(--border); }
.disc-svc-cat:first-child { border-top: 0; }
.disc-svc-cat h4 { margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
.disc-svc { display: inline-block; margin: 0 6px 6px 0; vertical-align: top; max-width: 100%; }
.disc-svc .disc-chip { display: inline-block; }
.disc-links { display: flex; flex-wrap: wrap; gap: 6px 16px; margin: 4px 0 18px; }
@media print {
  .sidebar, .tool-form, .disc-actions, .disc-links, details { display: none !important; }
  .layout { display: block; }
  main { padding: 0; max-width: none; }
  .card { break-inside: avoid; box-shadow: none; }
}
`);

const DISC_KIND = {
  saas: ["info", "SaaS"], cloud: ["ok", "Cloud / hosting"], onprem: ["warning", "Office connection"],
  own: ["info", "Their own IP range"], dangling: ["critical", "Dangling (target gone)"], unknown: ["muted", "Unrecognised network"], private: ["critical", "Private IP"],
};

function renderDiscoverTool(main, params) {
  const out = el("div");
  main.append(card(null, [
    hashForm("discover", [
      { name: "d", label: "Prospect's domain", placeholder: "contoso.com (or an email address)", grow: true, required: true },
      { name: "ct", type: "checkbox", label: "Also search certificate logs for more host names (slower)" },
    ], params, "Discover"),
    el("div", { class: "hint", style: "margin-top:8px" }, "Uses public information only: DNS records, the public website (one normal page visit), public registration data and Microsoft's public tenant lookup. Nothing is scanned or logged into."),
  ]), out);
  const d = params.get("d");
  if (!d) return;
  const ct = params.get("ct") === "1";
  runInto(out, `Profiling ${d}… (DNS, Microsoft 365, website, registration${ct ? ", certificate logs" : ""})`,
    () => api(`/api/discover/${encodeURIComponent(d)}${ct ? "?ct=true" : ""}`), renderDiscoverResult);
}

function discAge(dateStr) {
  if (!dateStr) return null;
  const years = (Date.now() - new Date(dateStr).getTime()) / (365.25 * 86400000);
  return years >= 1 ? `${Math.floor(years)} years (since ${dateStr.slice(0, 4)})` : `${Math.round(years * 12)} months`;
}

function discIdentityLabel(id) {
  if (!id.tenant_id) return "No Microsoft 365 tenant";
  return id.namespace === "Federated" ? `Federated to ${id.idp || "a third-party IdP"}` : "Microsoft 365, cloud sign-in";
}

function renderDiscoverResult(r) {
  const frag = el("div");
  const f = r.facts, e = r.email, id = r.identity, w = r.website || {};
  const risks = r.talking_points.filter((t) => t.kind === "risk");
  const opps = r.talking_points.filter((t) => t.kind === "opportunity");
  const qs = r.talking_points.filter((t) => t.kind === "question");

  frag.append(verdict(risks.length ? "warning" : "info", r.headline.replace(`${r.domain}: `, `${r.domain} · `) + (risks.length ? ` · Top risk: ${risks[0].title}` : ""),
    `${risks.length} risk${risks.length === 1 ? "" : "s"} to raise · ${opps.length} opportunit${opps.length === 1 ? "y" : "ies"} · ${qs.length} questions to ask. Public information only; confirm with the customer.`));
  frag.append(facts([
    ["Email", f.mail_host], ["Spam filter", (f.gateways || []).join(", ") || (f.mail_host === "Microsoft 365" ? "Microsoft 365 built-in" : f.mail_host === "Google Workspace" ? "Google built-in" : "none found")],
    ["Sign-in", discIdentityLabel(id)], ["Email security grade", `${r.posture.grade} (${r.posture.score}/100)`],
    ["DNS hosted at", f.dns_host], ["Registrar", f.registrar], ["Domain age", discAge(f.registered)],
    ["Website", [f.cms, f.website_host].filter(Boolean).join(" on ") || null],
  ]));

  const copyBtn = el("button", { class: "btn secondary", type: "button" }, "Copy briefing");
  copyBtn.addEventListener("click", () => copyText(discBriefing(r), copyBtn));
  frag.append(el("div", { class: "disc-actions" }, copyBtn,
    el("button", { class: "btn secondary", type: "button", onclick: () => window.print() }, "Print / save as PDF")));

  // ---- talking points
  const tpCol = (title, sev, items, empty) => el("div", { class: "disc-tp-col" },
    el("h3", {}, badge(sev, String(items.length)), title),
    items.length ? items.map((t) => el("div", { class: "disc-tp" }, el("div", { class: "disc-tp-area" }, t.area),
      el("div", { class: "disc-tp-title" }, t.title), el("div", { class: "disc-tp-detail" }, t.detail))) : el("div", { class: "hint" }, empty));
  frag.append(card("Talking points", el("div", { class: "disc-tp-grid" },
    tpCol("Risks to raise", "critical", risks, "Nothing alarming in public records."),
    tpCol("Opportunities to propose", "info", opps, "No obvious projects from public records."),
    tpCol("Questions to ask", "muted", qs, "—")), { flush: true }));

  // ---- posture
  const p = r.posture;
  frag.append(card("Email & domain security posture", [
    el("div", { class: "disc-grade" }, el("div", { class: `disc-grade-letter disc-grade-${p.grade}` }, p.grade),
      el("div", {}, el("div", { style: "font-size:18px;font-weight:650" }, `${p.score}/100`),
        el("div", { class: "hint" }, "Scored from public DNS only: a conversation starter, not a full security assessment."))),
    table(["Area", "Score", "What we found"], p.items.map((i) => [i.label, badge(i.status, `${i.points}/${i.max}`), i.note]),
      (i) => (p.items[i].status === "critical" ? "hl" : null)),
  ], { flush: true }));

  // ---- email + identity
  const mxRows = e.mx.map((m) => `${m.preference} ${m.host}${m.provider ? ` (${m.provider})` : ""}`);
  frag.append(el("div", { class: "grid-2" },
    card("Email", kv([
      ["Mailboxes hosted at", e.mail_host], ["Filtering / gateway", e.gateways.join(", ") || "none in MX"],
      ["MX", mxRows.length ? el("div", {}, mxRows.map((x) => el("div", { class: "mono" }, x))) : (e.null_mx ? "Null MX (receives no mail)" : "none")],
      ["DMARC", e.dmarc.record ? el("div", {}, badge(e.dmarc.policy === "reject" ? "ok" : e.dmarc.policy === "quarantine" ? "info" : "warning", `p=${e.dmarc.policy}`),
        e.dmarc.vendor ? ` reports to ${e.dmarc.vendor}` : "", el("div", { class: "mono sub" }, e.dmarc.record)) : badge("critical", "none")],
      ["SPF", e.spf.record ? el("div", {}, `${e.spf.lookups}/10 lookups`, el("div", { class: "mono sub" }, e.spf.record)) : badge("critical", "none")],
      ["DKIM", e.dkim.length ? e.dkim.map((k) => `${k.selector}${k.service ? ` (${k.service})` : ""}`).join(", ") : "none found on common selectors"],
      ["MTA-STS / TLS-RPT", `${e.mta_sts || "off"} / ${e.tls_rpt ? "on" : "off"}`], ["BIMI logo", e.bimi ? "yes" : "no"],
    ]), { extra: link("domain", { d: r.domain }, "Full check →") }),
    card("Identity & Microsoft 365", kv([
      ["Tenant ID", id.tenant_id ? el("span", { class: "mono" }, id.tenant_id) : "not found"],
      ["Organisation name", id.brand], ["Sign-in", id.tenant_id ? (id.namespace === "Federated" ? `Federated to ${id.idp || "?"}${id.idp_host ? ` (${id.idp_host})` : ""}` : "Cloud (managed)") : null],
      ["Cloud / region", [id.cloud, id.region].filter(Boolean).join(" · ")],
      ["Autodiscover", id.autodiscover || "no CNAME"], ["Intune enrollment", id.intune ? "configured" : "not found"],
      ["Device registration", id.device_registration ? "configured" : "not found"],
      ["Teams / Skype federation", id.srv && id.srv["_sipfederationtls._tcp"] ? id.srv["_sipfederationtls._tcp"].join(", ") : "no SRV record"],
    ]), { extra: link("tenant", { d: r.domain }, "Tenant details →") })));

  // ---- services
  const cats = [...new Set(r.services.map((s) => s.category))];
  frag.append(card(`Services & SaaS detected (${r.services.length})`, r.services.length ? cats.map((c) => el("div", { class: "disc-svc-cat" },
    el("h4", {}, c), r.services.filter((s) => s.category === c).map((s) => el("span", { class: "disc-svc", title: s.evidence.join("\n") },
      el("span", { class: "disc-chip" }, s.name), el("div", { class: "sub", style: "max-width:320px" }, s.evidence[0]))))) :
    el("div", { class: "card-body hint" }, "No third-party services found in public records."), { flush: true }));

  // ---- infrastructure
  const inf = r.infrastructure;
  frag.append(card(`Public host names (${inf.hosts.length} found of ${inf.checked} common names checked)`, [
    inf.wildcard ? el("div", { class: "notice", style: "margin:12px 16px" }, "This domain uses wildcard DNS (every name resolves), so only host names that differ from the wildcard are listed.") : null,
    inf.hosts.length ? table(["Host", "Likely purpose", "Points to", "Runs on"], inf.hosts.map((h) => {
      const [sev, label] = DISC_KIND[h.kind] || ["muted", h.kind];
      return [el("span", { class: "mono" }, h.host), h.purpose,
        el("div", { class: "mono sub" }, h.cname || h.ips.join(", ")),
        el("div", {}, badge(sev, label), h.service ? el("div", { class: "sub" }, h.service) : h.owner ? el("div", { class: "sub" }, h.owner) : null)];
    }), (i) => (inf.hosts[i].kind === "onprem" && ["remote", "vpn", "mail", "identity"].includes(inf.hosts[i].area) ? "hl" : null))
      : el("div", { class: "card-body hint" }, "None of the common host names exist."),
    el("div", { class: "card-body hint" }, "Checked in DNS only; nothing was connected to. 'Office connection' means the IP belongs to a business/home internet provider, so the service is likely running on-premises."),
  ], { flush: true }));

  // ---- website
  frag.append(el("div", { class: "grid-2" },
    card("Website", w.url ? kv([
      ["URL", el("span", { class: "mono" }, w.url)], ["Status", `${w.status}${w.title ? ` · “${w.title}”` : ""}`],
      ["Hosted by", w.host_owner], ["CDN / WAF", (w.cdn || []).join(", ") || "none detected"],
      ["Built with", (w.tech || []).length ? el("div", { class: "disc-chips" }, w.tech.map((t) => el("span", { class: "disc-chip" }, t.name))) : "nothing recognised"],
      ["Generator", w.generator], ["HTTPS", w.https ? (w.hsts ? "yes, with HSTS" : "yes (no HSTS)") : badge("warning", "no")],
      ["security.txt", w.security_txt ? "published" : "no"],
    ]) : el("div", { class: "hint" }, `Website not reachable${w.error ? `: ${w.error}` : ""}.`),
      { extra: w.url ? link("tls", { h: new URL(w.url).hostname }, "Check certificate →") : null }),
    card("Domain & DNS", kv([
      ["Registrar", f.registrar || "not published for this TLD"], ["Registered", r.domain_info.registration && r.domain_info.registration.events ? r.domain_info.registration.events.registered : null],
      ["Expires", f.expires ? `${f.expires}${f.days_left != null ? ` (${f.days_left} days)` : ""}` : null],
      ["Status", r.domain_info.registration ? (r.domain_info.registration.statuses || []).join(", ") : null],
      ["DNSSEC", r.domain_info.registration ? (r.domain_info.registration.dnssec ? "signed" : "not signed") : null],
      ["DNS hosted at", f.dns_host], ["Name servers", (f.name_servers || []).join(", ")],
      ["Certificate authorities (CAA)", (r.domain_info.caa || []).join(", ") || "any (no CAA record)"],
      ["DNS admin contact (SOA)", r.domain_info.soa ? r.domain_info.soa.contact : null],
    ]), { extra: link("whois", { d: r.domain }, "Registration details →") })));

  // ---- certificate logs
  if (r.ct) {
    frag.append(card(`Certificate logs${r.ct.source ? ` (${r.ct.source})` : ""}`, r.ct.error ? el("div", { class: "hint" }, r.ct.error) : [
      el("div", { class: "hint" }, `${r.ct.total} host names have had public certificates. Names that suggest remote access, identity, mail or non-production systems:`),
      r.ct.interesting.length ? el("div", { class: "disc-chips", style: "margin:8px 0" }, r.ct.interesting.map((n) => el("span", { class: "disc-chip mono" }, n))) : el("div", { class: "hint" }, "none"),
      el("details", {}, el("summary", {}, `All ${r.ct.names.length} names`), el("div", { class: "mono sub", style: "margin-top:6px;white-space:pre-wrap" }, r.ct.names.join("\n"))),
    ]));
  }

  // ---- raw TXT
  frag.append(card("TXT records", el("details", {}, el("summary", {}, `${r.txt.all.length} TXT records (verification tokens reveal the services above)`),
    el("div", { style: "margin-top:8px" }, r.txt.all.map((t) => el("div", { class: "mono sub", style: "padding:2px 0" }, t))))));

  frag.append(el("div", { class: "disc-links" }, el("strong", {}, "Dig deeper:"),
    link("domain", { d: r.domain }, "Domain Health"), link("spfbuild", { d: r.domain }, "SPF Builder"), link("dmarcbuild", { d: r.domain }, "DMARC Builder"),
    link("lookalike", { d: r.domain }, "Lookalike domains"), link("blacklist", { t: r.domain }, "Blacklists"), link("autodiscover", { t: r.domain }, "Autodiscover")));
  return frag;
}

/** Plain-text briefing for CRM notes / email. */
function discBriefing(r) {
  const f = r.facts, id = r.identity, L = [];
  L.push(`DISCOVERY BRIEFING: ${r.domain}  (${new Date(r.generated).toLocaleString()})`);
  L.push("Source: public DNS, website and registration data only. Confirm with the customer.", "");
  L.push("SNAPSHOT");
  L.push(`- Email: ${f.mail_host}${f.gateways.length ? ` (filtered by ${f.gateways.join(", ")})` : ""}`);
  L.push(`- Sign-in: ${discIdentityLabel(id)}${id.tenant_id ? ` · tenant ${id.tenant_id}` : ""}${id.region ? ` · ${id.region}` : ""}`);
  L.push(`- Email security grade: ${r.posture.grade} (${r.posture.score}/100). DMARC: ${r.email.dmarc.policy ? "p=" + r.email.dmarc.policy : "none"}${r.email.dmarc.vendor ? ` via ${r.email.dmarc.vendor}` : ""}`);
  L.push(`- Domain: ${f.registrar || "registrar n/a"}${f.registered ? `, registered ${f.registered}` : ""}${f.expires ? `, expires ${f.expires}` : ""}; DNS at ${f.dns_host || "?"}`);
  if (r.website && r.website.url) L.push(`- Website: ${r.website.url}${f.cms ? ` (${f.cms})` : ""}${f.website_host ? ` hosted by ${f.website_host}` : ""}`);
  const sec = (title, kind) => {
    const items = r.talking_points.filter((t) => t.kind === kind);
    if (!items.length) return;
    L.push("", title);
    items.forEach((t) => L.push(`- [${t.area}] ${t.title}`));
  };
  sec("RISKS TO RAISE", "risk");
  sec("OPPORTUNITIES", "opportunity");
  sec("QUESTIONS TO ASK", "question");
  if (r.services.length) {
    L.push("", "SERVICES DETECTED");
    const cats = [...new Set(r.services.map((s) => s.category))];
    cats.forEach((c) => L.push(`- ${c}: ${r.services.filter((s) => s.category === c).map((s) => s.name).join(", ")}`));
  }
  const hosts = r.infrastructure.hosts.filter((h) => ["remote", "vpn", "identity", "mail"].includes(h.area));
  if (hosts.length) {
    L.push("", "NOTABLE HOST NAMES");
    hosts.forEach((h) => L.push(`- ${h.host}: ${h.purpose} → ${h.service || (DISC_KIND[h.kind] || [])[1] || h.kind}${h.owner ? ` (${h.owner})` : ""}`));
  }
  return L.join("\n");
}

registerTool({ category: "discovery", group: "Prospects", id: "discover", title: "Domain Discovery", render: renderDiscoverTool,
  icon: "M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-4.5-4.5M8 11h6M11 8v6",
  keywords: "prospect sales presales new customer recon profile environment spam filter email host tenant saas stack website registrar",
  desc: "Enter a prospect's domain: see where their email is hosted, their spam filter, Microsoft 365 tenant and sign-in, DMARC/SPF/DKIM, SaaS stack, public infrastructure, website and registrar, plus talking points: risks, opportunities and questions." });
