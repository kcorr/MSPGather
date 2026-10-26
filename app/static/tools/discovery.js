"use strict";
/* Discover: profile a prospect from their domain name (public information only). */

const DISC_KIND = {
  saas: ["info", "SaaS"], cloud: ["ok", "Cloud / hosting"], onprem: ["warning", "Office connection"],
  own: ["info", "Their own IP range"], dangling: ["critical", "Dangling (target gone)"], unknown: ["muted", "Unrecognised network"], private: ["critical", "Private IP"],
};

// Talking points → the project you'd propose. Only risks and opportunities (plus a couple of
// tell-tale questions) count as evidence, so every prospect doesn't get every project.
const DISC_PROJECTS = [
  { title: "Email authentication rollout", blurb: "SPF clean-up, DKIM signing and DMARC to p=reject.", icon: "mail",
    match: (t) => t.area === "Email security" && t.kind !== "question" },
  { title: "Email security uplift", blurb: "Defender for Office 365 or gateway review, Enhanced Filtering, phishing protection.", icon: "security",
    match: (t) => /Defender plan|Enhanced Filtering/.test(t.title) },
  { title: "Move to Microsoft 365", blurb: "Retire the self-hosted or small-host mail platform.", icon: "cloud",
    match: (t) => /Self-hosted email|Mail hosted with|on-premises Exchange|Exchange \/ OWA/.test(t.title + " " + t.detail) && t.kind !== "question" },
  { title: "Identity modernisation", blurb: "Cloud authentication, single sign-on and MFA everywhere.", icon: "identity",
    match: (t) => t.area === "Identity" && t.kind !== "question" },
  { title: "Device management", blurb: "Intune, Autopilot and compliance policies.", icon: "device",
    match: (t) => t.area === "Devices" },
  { title: "Secure remote access", blurb: "Replace exposed RDP/VPN with ZTNA, Azure Virtual Desktop or Windows 365.", icon: "lock",
    match: (t) => t.area === "Remote access" },
  { title: "Domain & DNS hygiene", blurb: "Registrar ownership, transfer lock, dangling and stale records.", icon: "globe",
    match: (t) => (t.area === "DNS" || t.area === "Domain") && t.kind === "risk" },
  { title: "Security awareness training", blurb: "Phishing simulations and short training for staff.", icon: "users",
    match: (t) => /awareness training/i.test(t.title) },
  { title: "Website security", blurb: "HTTPS, patching and hosting review.", icon: "monitor",
    match: (t) => t.area === "Website" && t.kind === "risk" },
];

function renderDiscoverTool(page, params) {
  const d = params.get("d");
  if (!d) return discLanding(page);
  const ct = params.get("ct") === "1";
  const bar = heroSearch("discover", { placeholder: "Company domain or email address", button: "Discover", value: d, icon: "discover",
    options: [{ name: "ct", label: "Also search certificate logs", checked: ct }] });
  const out = el("div");
  page.append(el("div", { class: "card no-print", style: "padding:14px 16px" },
    el("div", { style: "display:flex;gap:12px;align-items:center;flex-wrap:wrap" }, bar.form, bar.options)), out);
  bar.form.style.maxWidth = "none";
  bar.form.style.flex = "1 1 520px";
  bar.form.querySelector(".hero-input").style.height = "44px";
  bar.form.querySelector("button").classList.remove("lg");
  bar.form.querySelector("button").style.height = "44px";
  runInto(out, `Profiling ${d} from public data…`,
    () => api(`/api/discover/${encodeURIComponent(d)}${ct ? "?ct=true" : ""}`),
    (r) => {
      recentAdd(r.domain, "discover");
      const report = renderDiscoverResult(r);
      discAttachCompare(report, r);
      return report;
    },
    { steps: ["Mail & DNS records", "Microsoft 365 tenant", "Website", "Registration", `${ct ? "Certificate logs · " : ""}Common host names`], quiet: true });
}

/* ------------------------------------------------------------------ landing */
function discLanding(page) {
  const s = heroSearch("discover", { placeholder: "Company domain or email address, e.g. contoso.com", button: "Discover", icon: "discover",
    options: [{ name: "ct", label: "Also search certificate transparency logs (slower, finds more host names)" }] });
  page.append(el("section", { class: "hero" },
    el("div", { class: "hero-eyebrow" }, icon("discover"), "Prospect discovery"),
    el("h1", {}, "Know your prospect before the first call"),
    el("p", {}, "Enter a company's domain. MSPGather builds a meeting briefing from public data: where their email lives and what filters it, their Microsoft 365 setup, security posture, SaaS stack and internet-facing systems, with risks to raise, projects to propose and questions to ask."),
    s.form, s.options,
    el("div", { class: "hero-chips" }, [["mail", "Email platform & spam filter"], ["identity", "Microsoft 365 tenant & sign-in"], ["harden", "SPF · DKIM · DMARC grade"],
      ["layers", "SaaS & IT provider signals"], ["server", "Remote access & exposed hosts"], ["globe", "Website, DNS & registrar"]]
      .map(([ic, t]) => el("span", { class: "hero-chip" }, icon(ic), t))),
    el("div", { class: "hero-note" }, icon("lock"), "Public information only: DNS records, public registries, Microsoft's public tenant lookup and an ordinary visit to their website. Nothing is scanned, probed or logged into, so it's safe to run before you have a relationship.")));
  setTimeout(() => s.input.focus(), 0);

  const recentWrap = el("div");
  page.append(el("div", { class: "section-title" }, "Recent prospects"), recentWrap);
  discRecent(recentWrap);

  const more = ["bulkaudit", "lookalike", "tenant", "harden"].map(toolById).filter(Boolean);
  if (more.length) page.append(el("div", { class: "section-title" }, "More ways to size up a domain"),
    el("div", { class: "tool-grid" }, more.map((t) => toolCard(t))));
}

async function discRecent(wrap) {
  let saved = [];
  try { saved = (await api("/api/assessments?kind=discovery&limit=12")).items || []; } catch (e) { /* storage unavailable */ }
  const seen = new Set(saved.map((a) => a.domain));
  const local = recentList("discover").filter((r) => !seen.has(r.d)).slice(0, 6);
  if (!saved.length && !local.length) {
    wrap.replaceChildren(el("div", { class: "empty" }, icon("history"), "Prospects you profile appear here. Save a report to share it with your team and compare it later."));
    return;
  }
  wrap.replaceChildren(el("div", { class: "recent-list" },
    saved.map((a) => el("a", { class: "recent", href: `#assessments?id=${a.id}` }, scoreRing(a.score || 0, a.grade || "?", 44, `grade-${a.grade}`),
      el("div", { class: "recent-main" }, el("div", { class: "recent-title" }, a.domain, a.org ? el("span", { class: "muted", style: "font-weight:500" }, ` · ${a.org}`) : null),
        el("div", { class: "recent-sub" }, `Saved ${fmtAgo(a.created)}${a.created_by ? ` by ${a.created_by}` : ""} · ${a.counts ? `${a.counts.risk || 0} risks · ${a.counts.opportunity || 0} opportunities` : ""}`)),
      icon("chev-right"))),
    local.map((r) => el("a", { class: "recent", href: `#discover?${new URLSearchParams({ d: r.d })}` },
      el("span", { class: "tool-card-icon" }, icon("history")),
      el("div", { class: "recent-main" }, el("div", { class: "recent-title" }, r.d), el("div", { class: "recent-sub" }, `Viewed ${fmtAgo(r.at)} · not saved`)),
      icon("chev-right")))));
}

/* ------------------------------------------------------------------ helpers */
function discAge(dateStr) {
  if (!dateStr) return null;
  const years = (Date.now() - new Date(dateStr).getTime()) / (365.25 * 86400000);
  return years >= 1 ? `${Math.floor(years)} years (since ${dateStr.slice(0, 4)})` : `${Math.max(1, Math.round(years * 12))} months (new)`;
}

function discIdentityLabel(id) {
  if (!id.tenant_id) return "No Microsoft 365 tenant";
  return id.namespace === "Federated" ? `Federated to ${id.idp || "a third-party IdP"}` : "Microsoft 365, cloud sign-in";
}

/** Best guess at the organisation's name: the website title's brand part. */
function discOrgName(r) {
  const title = (r.website && r.website.title) || "";
  const brand = title.split(/\s[|·–—-]\s|\s[|·]\s?|:\s/)[0].trim();
  if (brand && brand.length <= 60 && !/^(home|welcome|index|untitled|404|403|just a moment)/i.test(brand)) return brand;
  return null;
}

function discFilter(r) {
  const f = r.facts;
  return (f.gateways || []).join(", ") || (f.mail_host === "Microsoft 365" ? "Microsoft 365 built-in" : f.mail_host === "Google Workspace" ? "Google built-in" : "none found");
}

function discProjects(r) {
  return DISC_PROJECTS.map((p) => ({ ...p, evidence: r.talking_points.filter(p.match) })).filter((p) => p.evidence.length);
}

function discTile(k, v, sub, state, ic) {
  return el("div", { class: `stack-tile ${state || ""}` }, el("span", { class: "st-icon" }, icon(ic || "info")),
    el("div", { style: "min-width:0" }, el("div", { class: "st-k" }, k), el("div", { class: "st-v" }, v || "—"), sub ? el("div", { class: "st-s" }, sub) : null));
}

/* ------------------------------------------------------------------ report */
function renderDiscoverResult(r, opts = {}) {
  const frag = el("div");
  const f = r.facts, e = r.email, id = r.identity, w = r.website || {};
  const risks = r.talking_points.filter((t) => t.kind === "risk");
  const opps = r.talking_points.filter((t) => t.kind === "opportunity");
  const qs = r.talking_points.filter((t) => t.kind === "question");
  const org = discOrgName(r);
  const p = r.posture;

  // ---- header
  const saveBtn = el("button", { class: "btn secondary", type: "button" }, icon("save"), opts.saved ? "Saved" : "Save");
  if (opts.saved) saveBtn.disabled = true;
  saveBtn.addEventListener("click", async () => {
    saveBtn.disabled = true;
    try {
      const res = await api("/api/assessments", { body: { result_id: r.result_id } });
      saveBtn.replaceChildren(icon("check"), "Saved");
      toast("Saved to Prospects");
      if (res && res.id) history.replaceState({ mspg: true }, "", `#assessments?id=${res.id}`);
    } catch (err) { saveBtn.disabled = false; toast(err.message); }
  });
  if (!r.result_id && !opts.saved) saveBtn.hidden = true;
  const copyBtn = el("button", { class: "btn secondary", type: "button", onclick: () => copyText(discBriefing(r), copyBtn) }, icon("copy"), "Copy briefing");
  frag.append(el("div", { class: "report-head" },
    scoreRing(p.score, p.grade, 104, `grade-${p.grade}`),
    el("div", { class: "report-id" },
      el("div", { class: "report-kicker" }, opts.saved ? "Saved prospect briefing" : "Prospect briefing"),
      el("div", { class: "report-title" }, r.domain),
      el("div", { class: "report-org" }, [org, id.brand && id.brand !== org ? `Microsoft 365 tenant "${id.brand}"` : null].filter(Boolean).join(" · ") || "Organisation name not published"),
      el("div", { class: "report-meta" }, el("span", {}, `Generated ${new Date(r.generated).toLocaleString()}`),
        opts.saved ? el("span", {}, `Saved by ${opts.saved.created_by || "—"}`) : null, el("span", {}, "Public data only · confirm with the customer"))),
    el("div", { class: "report-actions" }, saveBtn, copyBtn,
      el("button", { class: "btn", type: "button", onclick: () => discSnapshot(r) }, icon("file"), "Client snapshot"),
      el("button", { class: "btn secondary", type: "button", title: "Print the internal briefing", onclick: () => window.print() }, icon("print")))));

  if (opts.compare) frag.append(opts.compare);

  const sections = [["summary", "Summary"], ["talking", "Talking points"], ["score", "Scorecard"], ["stack", "Stack"], ["email", "Email & identity"],
    ["hosts", "Internet-facing hosts"], ["web", "Website & domain"], ["evidence", "Evidence"]];
  frag.append(el("nav", { class: "report-nav", "aria-label": "Report sections" }, sections.map(([sid, t]) =>
    el("button", { type: "button", onclick: () => document.getElementById(`disc-${sid}`)?.scrollIntoView({ behavior: "smooth", block: "start" }) }, t))));

  // ---- summary
  const top = risks[0];
  const sev = risks.length ? (risks.some((t) => /DMARC record|broken|dangling|exposed|expires|Remote|private/i.test(t.title)) ? "critical" : "warning") : "ok";
  const devices = r.services.filter((s) => s.category === "Device management").map((s) => s.name);
  const rmm = r.services.filter((s) => s.category === "Remote support / RMM").map((s) => s.name);
  // Remote-access names that really run somewhere (not a SaaS page that happens to be called "desktop", not a dead record).
  const remote = r.infrastructure.hosts.filter((h) => ["remote", "vpn"].includes(h.area) && h.kind !== "dangling"
    && (h.kind !== "saas" || h.service_category === "Remote access"));
  frag.append(el("section", { class: "report-section", id: "disc-summary" },
    verdict(sev, top ? `Top risk: ${top.title}` : `No obvious risks in ${r.domain}'s public records`,
      `${risks.length} risk${risks.length === 1 ? "" : "s"} to raise · ${opps.length} opportunit${opps.length === 1 ? "y" : "ies"} to propose · ${qs.length} question${qs.length === 1 ? "" : "s"} to ask`),
    el("div", { class: "stack-grid", style: "margin-bottom:16px" },
      discTile("Email platform", f.mail_host, e.mx.length ? `MX: ${e.mx[0].host}` : (e.null_mx ? "Null MX: receives no mail" : "No MX records"), "info", "mail"),
      discTile("Email filtering", discFilter(r), (f.gateways || []).length ? "Third-party gateway in front of the mailboxes" : "No third-party gateway in MX", (f.gateways || []).length ? "good" : "", "security"),
      discTile("Sign-in", discIdentityLabel(id), id.tenant_id ? `Tenant ${id.tenant_id.slice(0, 8)}… · ${id.region || id.cloud || ""}` : null, id.tenant_id ? "info" : "", "identity"),
      discTile("Email security grade", `${p.grade} · ${p.score}/100`, e.dmarc.policy ? `DMARC p=${e.dmarc.policy}` : "No DMARC record", { A: "good", B: "good", C: "warn" }[p.grade] || "bad", "harden"),
      discTile("Device management", devices.join(", ") || (id.intune ? "Intune enrollment set up" : "No public sign"), id.intune && devices.length ? "Intune enrollment record present" : null, devices.length || id.intune ? "good" : "", "device"),
      discTile("Remote access", remote.length ? `${remote.length} host name${remote.length > 1 ? "s" : ""}` : "None found", remote.slice(0, 2).map((h) => h.host).join(", ") || null,
        remote.some((h) => h.kind === "onprem") ? "bad" : remote.length ? "warn" : "good", "lock"),
      discTile("IT provider signals", rmm.join(", ") || "None visible", rmm.length ? "Remote support / RMM tools in DNS" : "No RMM or remote-support tools in DNS", rmm.length ? "warn" : "", "briefcase"),
      discTile("Website", [f.cms, f.website_host].filter(Boolean).join(" on ") || (w.url ? "Reachable" : "Not reachable"), w.url ? (w.https ? (w.hsts ? "HTTPS with HSTS" : "HTTPS, no HSTS") : "No HTTPS") : null, w.url ? (w.https ? "good" : "bad") : "", "monitor"),
      discTile("Domain", f.registrar || "Registrar not published", [discAge(f.registered), f.days_left != null ? `expires in ${f.days_left} days` : null].filter(Boolean).join(" · ") || null,
        f.days_left != null && f.days_left < 60 ? "bad" : "", "globe"))));

  // ---- talking points + proposal starters
  const tpCol = (kind, title, items, empty) => el("div", { class: `tp-col ${kind}` },
    el("h3", {}, el("span", { class: "count" }, String(items.length)), title),
    items.length ? items.map((t) => el("div", { class: "tp" }, el("div", { class: "tp-area" }, t.area),
      el("div", { class: "tp-title" }, t.title), el("div", { class: "tp-detail" }, t.detail))) : el("div", { class: "hint", style: "padding-top:8px" }, empty));
  const projects = discProjects(r);
  frag.append(el("section", { class: "report-section", id: "disc-talking" },
    card("Talking points", el("div", { class: "tp-grid" },
      tpCol("risk", "Risks to raise", risks, "Nothing alarming in public records."),
      tpCol("opportunity", "Opportunities to propose", opps, "No obvious projects from public records."),
      tpCol("question", "Questions to ask", qs, "—")), { flush: true, icon: "flag",
      extra: el("span", { class: "hint" }, "From public records: confirm with the customer") }),
    projects.length ? card("Proposal starters", el("div", { class: "projects" }, projects.map((pr) => el("div", { class: "project" },
      el("b", {}, icon(pr.icon), pr.title), el("span", {}, pr.blurb),
      el("span", {}, `Based on: ${pr.evidence.map((t) => t.title).slice(0, 2).join("; ")}${pr.evidence.length > 2 ? "…" : ""}`)))), { flush: true, icon: "briefcase" }) : null));

  // ---- scorecard
  frag.append(el("section", { class: "report-section", id: "disc-score" }, card("Email & domain security scorecard", [
    el("div", { class: "scorecard-top" }, scoreRing(p.score, p.grade, 84, `grade-${p.grade}`),
      el("div", { style: "flex:1 1 280px;min-width:0" },
        el("div", { style: "font-weight:700;font-size:15px" }, `Grade ${p.grade}: ${p.items.filter((i) => i.status === "ok").length} of ${p.items.length} areas in good shape`),
        el("div", { class: "hint", style: "margin:2px 0 8px" }, "Scored from public DNS, registry and website data: a conversation starter, not a full security assessment."),
        meter(p.score, `var(--${p.score >= 80 ? "ok" : p.score >= 65 ? "warn" : "crit"})`))),
    el("div", { class: "score-areas" }, p.items.map((i) => el("div", { class: "score-area" },
      el("div", { class: "score-area-top" }, el("span", { style: "display:flex;gap:7px;align-items:center" },
        el("span", { class: "f-icon", style: `width:22px;height:22px;border-radius:7px;background:var(--${{ ok: "ok", warning: "warn", critical: "crit", info: "info" }[i.status]}-soft);color:var(--${{ ok: "ok", warning: "warn", critical: "crit", info: "info" }[i.status]})` }, sevIcon(i.status)),
        i.label), el("span", { class: "score-pts" }, `${i.points}/${i.max}`)),
      el("div", { class: "score-area-note" }, i.note)))),
  ], { flush: true, icon: "harden", extra: link("harden", { d: r.domain }, "Build a hardening plan →") })));

  // ---- services / stack
  const cats = [...new Set(r.services.map((s) => s.category))];
  frag.append(el("section", { class: "report-section", id: "disc-stack" },
    card(`Technology stack (${r.services.length} services detected)`, r.services.length ? el("div", { class: "svc-cats" }, cats.map((c) => el("div", { class: "svc-cat" },
      el("h4", {}, c), r.services.filter((s) => s.category === c).map((s) => el("div", { class: "svc", title: s.evidence.join("\n") },
        el("b", {}, s.name), el("span", {}, s.evidence[0])))))) :
      el("div", { class: "card-body hint" }, "No third-party services found in public records."), { flush: true, icon: "layers",
      extra: el("span", { class: "hint" }, "From DNS verification records, SPF, DKIM, CNAMEs and the website") })));

  // ---- email + identity
  const mxRows = e.mx.map((m) => `${m.preference} ${m.host}${m.provider ? ` (${m.provider})` : ""}`);
  frag.append(el("section", { class: "report-section grid-2", id: "disc-email" },
    card("Email", kv([
      ["Mailboxes hosted at", e.mail_host], ["Filtering / gateway", e.gateways.join(", ") || "none in MX"],
      ["MX", mxRows.length ? el("div", {}, mxRows.map((x) => el("div", { class: "mono" }, x))) : (e.null_mx ? "Null MX (receives no mail)" : "none")],
      ["DMARC", e.dmarc.record ? el("div", {}, badge(e.dmarc.policy === "reject" ? "ok" : e.dmarc.policy === "quarantine" ? "info" : "warning", `p=${e.dmarc.policy}`),
        e.dmarc.vendor ? ` reports to ${e.dmarc.vendor}` : "", el("div", { class: "mono sub" }, e.dmarc.record)) : badge("critical", "none")],
      ["SPF", e.spf.record ? el("div", {}, `${e.spf.lookups}/10 lookups`, el("div", { class: "mono sub" }, e.spf.record)) : badge("critical", "none")],
      ["DKIM", e.dkim.length ? e.dkim.map((k) => `${k.selector}${k.service ? ` (${k.service})` : ""}`).join(", ") : "none found on common selectors"],
      ["MTA-STS / TLS-RPT", `${e.mta_sts || "off"} / ${e.tls_rpt ? "on" : "off"}`], ["BIMI logo", e.bimi ? "yes" : "no"],
    ]), { icon: "mail", extra: link("domain", { d: r.domain }, "Full mail check →") }),
    card("Identity & Microsoft 365", kv([
      ["Tenant ID", id.tenant_id ? el("span", { class: "mono" }, id.tenant_id) : "not found"],
      ["Tenant name", id.brand], ["Sign-in", id.tenant_id ? (id.namespace === "Federated" ? `Federated to ${id.idp || "?"}${id.idp_host ? ` (${id.idp_host})` : ""}` : "Cloud (managed)") : null],
      ["Cloud / region", [id.cloud, id.region].filter(Boolean).join(" · ")],
      ["Autodiscover", id.autodiscover || "no CNAME"], ["Intune enrollment", id.intune ? "configured" : "not found"],
      ["Device registration", id.device_registration ? "configured" : "not found"],
      ["Teams / Skype federation", id.srv && id.srv["_sipfederationtls._tcp"] ? id.srv["_sipfederationtls._tcp"].join(", ") : "no SRV record"],
    ]), { icon: "identity", extra: link("tenant", { d: r.domain }, "Tenant details →") })));

  // ---- infrastructure
  const inf = r.infrastructure;
  frag.append(el("section", { class: "report-section", id: "disc-hosts" }, card(`Internet-facing host names (${inf.hosts.length} of ${inf.checked} common names exist)`, [
    inf.wildcard ? el("div", { class: "notice", style: "margin:12px 16px" }, "This domain uses wildcard DNS (every name resolves), so only host names that differ from the wildcard are listed.") : null,
    inf.hosts.length ? table(["Host", "Likely purpose", "Points to", "Runs on"], inf.hosts.map((h) => {
      const [sev, label] = DISC_KIND[h.kind] || ["muted", h.kind];
      return [el("span", { class: "mono" }, h.host), h.purpose,
        el("div", { class: "mono sub" }, h.cname || h.ips.join(", ")),
        el("div", {}, badge(sev, label), h.service ? el("div", { class: "sub" }, h.service) : h.owner ? el("div", { class: "sub" }, h.owner) : null)];
    }), (i) => (inf.hosts[i].kind === "onprem" && ["remote", "vpn", "mail", "identity"].includes(inf.hosts[i].area) ? "hl" : null))
      : el("div", { class: "card-body hint" }, "None of the common host names exist."),
    el("div", { class: "card-foot hint" }, "Looked up in DNS only; nothing was connected to. 'Office connection' means the IP belongs to a business or home internet provider, so the service probably runs on-premises."),
  ], { flush: true, icon: "server" })));

  // ---- website + domain
  const reg = r.domain_info.registration || {};
  frag.append(el("section", { class: "report-section grid-2", id: "disc-web" },
    card("Website", w.url ? kv([
      ["URL", el("span", { class: "mono" }, w.url)], ["Status", `${w.status}${w.title ? ` · “${w.title}”` : ""}`],
      ["Hosted by", w.host_owner], ["CDN / WAF", (w.cdn || []).join(", ") || "none detected"],
      ["Built with", (w.tech || []).length ? el("div", { class: "chips" }, w.tech.map((t) => el("span", { class: "chip-s" }, t.name))) : "nothing recognised"],
      ["Generator", w.generator], ["HTTPS", w.https ? (w.hsts ? "yes, with HSTS" : "yes (no HSTS)") : badge("warning", "no")],
      ["Certificate", w.tls && w.tls.cert ? `${w.tls.cert.issuer || "?"}${w.tls.cert.days_left != null ? ` · expires in ${w.tls.cert.days_left} days` : ""}` : null],
      ["security.txt", w.security_txt ? "published" : "no"],
    ]) : el("div", { class: "hint" }, `Website not reachable${w.error ? `: ${w.error}` : ""}.`), { icon: "monitor" }),
    card("Domain & DNS", kv([
      ["Registrar", f.registrar || "not published for this TLD"], ["Registered", reg.events ? reg.events.registered : null],
      ["Expires", f.expires ? `${f.expires}${f.days_left != null ? ` (${f.days_left} days)` : ""}` : null],
      ["Status", (reg.statuses || []).join(", ") || null],
      ["DNSSEC", r.domain_info.registration ? (reg.dnssec ? "signed" : "not signed") : null],
      ["DNS hosted at", f.dns_host], ["Name servers", (f.name_servers || []).join(", ")],
      ["Certificate authorities (CAA)", (r.domain_info.caa || []).join(", ") || "any (no CAA record)"],
      ["DNS admin contact (SOA)", r.domain_info.soa ? r.domain_info.soa.contact : null],
    ]), { icon: "globe", extra: link("whois", { d: r.domain }, "Registration details →") })));

  // ---- evidence
  const ev = [];
  if (r.ct) {
    ev.push(card(`Certificate logs${r.ct.source ? ` (${r.ct.source})` : ""}`, r.ct.error ? el("div", { class: "hint" }, r.ct.error) : [
      el("div", { class: "hint" }, `${r.ct.total} host names have had public certificates. Names that suggest remote access, identity, mail or non-production systems:`),
      r.ct.interesting.length ? el("div", { class: "chips", style: "margin:10px 0" }, r.ct.interesting.map((n) => el("span", { class: "chip-s mono" }, n))) : el("div", { class: "hint" }, "none"),
      el("details", {}, el("summary", {}, `All ${r.ct.names.length} names`), el("div", { class: "mono sub", style: "margin-top:6px;white-space:pre-wrap" }, r.ct.names.join("\n"))),
    ], { icon: "certificate" }));
  }
  ev.push(card("TXT records", el("details", {}, el("summary", {}, `${r.txt.all.length} TXT records (verification tokens reveal the services above)`),
    el("div", { style: "margin-top:8px" }, r.txt.all.map((t) => el("div", { class: "mono sub", style: "padding:2px 0" }, t)))), { icon: "file" }));
  frag.append(el("section", { class: "report-section", id: "disc-evidence" }, ev));

  frag.append(el("div", { class: "section-title" }, "Next steps"), el("div", { class: "tool-grid no-print" },
    [["harden", { d: r.domain }, "Turn the findings into a fix list with exact records."], ["lookalike", { d: r.domain }, "Typo domains that could impersonate them."],
      ["domain", { d: r.domain }, "Full mail-flow configuration check."], ["blacklist", { t: r.domain }, "Is their mail server or domain on a blocklist?"]]
      .map(([tid, prm, blurb]) => { const t = toolById(tid); return t ? toolCard(t, { params: prm, blurb }) : null; })));
  return frag;
}

/* ------------------------------------------------------------------ comparison */
/** What changed between two saved (or one saved and one live) prospect reports. */
function discCompare(cur, prev) {
  const c = cur.data, p = prev.data;
  const delta = (c.posture.score ?? 0) - (p.posture.score ?? 0);
  const key = (t) => `${t.area}|${t.title.replace(/d+/g, "#")}`;
  const risks = (x) => x.talking_points.filter((t) => t.kind === "risk");
  const pk = new Set(risks(p).map(key)), ck = new Set(risks(c).map(key));
  const resolved = risks(p).filter((t) => !ck.has(key(t)));
  const added = risks(c).filter((t) => !pk.has(key(t)));
  const when = new Date(prev.created).toLocaleDateString();
  return el("div", { class: "compare" }, icon("compare"),
    el("span", {}, "Since ", el("b", {}, when), ": grade ", el("b", {}, `${p.posture.grade} → ${c.posture.grade}`), " (",
      el("span", { class: delta >= 0 ? "delta-up" : "delta-down" }, `${delta >= 0 ? "+" : ""}${delta} points`), ")"),
    resolved.length ? el("span", {}, el("span", { class: "delta-up" }, `${resolved.length} risk${resolved.length > 1 ? "s" : ""} resolved`), `: ${resolved.map((t) => t.title).slice(0, 3).join("; ")}`) : null,
    added.length ? el("span", {}, el("span", { class: "delta-down" }, `${added.length} new risk${added.length > 1 ? "s" : ""}`), `: ${added.map((t) => t.title).slice(0, 3).join("; ")}`) : null,
    !resolved.length && !added.length ? el("span", { class: "muted" }, "Same risks as last time.") : null,
    prev.id ? el("a", { href: `#assessments?id=${prev.id}`, style: "margin-left:auto" }, "Open earlier report") : null);
}

/** For a live run: compare with the most recent saved report for the same domain, if any. */
async function discAttachCompare(report, r) {
  try {
    const hist = await api(`/api/assessments?kind=discovery&domain=${encodeURIComponent(r.domain)}&limit=1`);
    if (!hist.items.length) return;
    const prev = await api(`/api/assessments/${hist.items[0].id}`);
    const head = report.querySelector(".report-head");
    if (head) head.after(discCompare({ data: r, created: r.generated }, prev));
  } catch (e) { /* comparison is optional */ }
}

/* ------------------------------------------------------------------ client snapshot */
// A one-page, client-facing summary to leave behind or attach to a proposal. Internal sales
// notes (questions, opportunities' wording) stay out of it.
function discSnapshot(r) {
  const wrap = document.getElementById("sheet");
  const org = (META.org && META.org.name) || null;
  const p = r.posture;
  const today = new Date(r.generated).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
  const status = { ok: ["st-ok", "Good"], warning: ["st-warn", "Needs attention"], critical: ["st-crit", "At risk"], info: ["st-warn", "Optional"] };
  const risks = r.talking_points.filter((t) => t.kind === "risk");
  // Only evidence-based recommendations go in front of the client (not the internal questions).
  const recs = discProjects(r).filter((pr) => pr.evidence.some((t) => t.kind !== "question"));
  const good = p.items.filter((i) => i.status === "ok");
  const close = () => { wrap.hidden = true; document.body.classList.remove("sheet-open"); wrap.replaceChildren(); };
  const sheet = el("article", { class: "sheet" },
    el("div", { class: "sh-top" },
      el("div", {}, el("div", { class: "sh-kicker" }, "External security snapshot"), el("h1", {}, r.domain),
        el("div", { style: "color:#4b5563;margin-top:2px" }, `${discOrgName(r) ? discOrgName(r) + " · " : ""}${today}`)),
      el("div", { class: "sh-org" }, org ? el("b", {}, org) : el("b", {}, "Prepared by your IT partner"),
        META.org && META.org.website ? el("div", {}, META.org.website) : null, META.org && META.org.contact ? el("div", {}, META.org.contact) : null)),
    el("div", { class: "sh-score" }, el("div", { class: `sh-grade g-${p.grade}` }, p.grade),
      el("div", {}, el("div", { style: "font-size:17px;font-weight:700" }, `Email & domain security grade ${p.grade} (${p.score}/100)`),
        el("div", { style: "color:#4b5563" }, risks.length ? `${risks.length} issue${risks.length > 1 ? "s" : ""} worth addressing, ${good.length} of ${p.items.length} areas in good shape.` : `${good.length} of ${p.items.length} areas in good shape and no urgent issues found.`))),
    el("h2", {}, "What we checked"),
    el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "Area"), el("th", {}, "What we found"), el("th", {}, "Status"))),
      el("tbody", {}, p.items.map((i) => el("tr", {}, el("td", { style: "font-weight:600" }, i.label), el("td", {}, i.note),
        el("td", { class: (status[i.status] || status.info)[0] }, (status[i.status] || status.info)[1]))))),
    risks.length ? [el("h2", {}, "Key findings"), risks.map((t) => el("div", { class: "sh-item" }, el("b", {}, t.title), el("span", {}, t.detail)))] : null,
    recs.length ? [el("h2", {}, "Recommended next steps"), recs.map((pr) => el("div", { class: "sh-item" }, el("b", {}, pr.title), el("span", {}, pr.blurb)))] : null,
    good.length ? [el("h2", {}, "In good shape"), el("div", {}, good.map((i) => i.label).join(" · "))] : null,
    el("div", { class: "sh-foot" }, `Based only on publicly available information (DNS records, public registries, Microsoft's public tenant information and the public website) collected on ${today}. `,
      "No systems were scanned or accessed. This is not a penetration test or a complete security assessment; some controls (for example mailbox protection, MFA and device security) can only be confirmed from inside the organisation.",
      org ? ` Prepared by ${org}.` : ""));
  wrap.replaceChildren(el("div", { class: "sheet-bar" },
    el("button", { class: "btn", type: "button", onclick: () => window.print() }, icon("print"), "Print / save as PDF"),
    el("button", { class: "btn secondary", type: "button", onclick: close }, icon("close"), "Close")), sheet);
  wrap.hidden = false;
  document.body.classList.add("sheet-open");
  wrap.scrollTop = 0;
  const esc = (ev) => { if (ev.key === "Escape") { close(); document.removeEventListener("keydown", esc); } };
  document.addEventListener("keydown", esc);
  window.addEventListener("hashchange", close, { once: true });
}

/** Plain-text briefing for CRM notes / email. */
function discBriefing(r) {
  const f = r.facts, id = r.identity, L = [];
  L.push(`PROSPECT BRIEFING: ${r.domain}${discOrgName(r) ? ` (${discOrgName(r)})` : ""}  ·  ${new Date(r.generated).toLocaleString()}`);
  L.push("Source: public DNS, registry and website data only. Confirm with the customer.", "");
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
  const projects = discProjects(r);
  if (projects.length) { L.push("", "PROPOSAL STARTERS"); projects.forEach((pr) => L.push(`- ${pr.title}: ${pr.blurb}`)); }
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

registerTool({ id: "discover", title: "Prospect Discovery", navTitle: "Prospect Discovery", landing: true, render: renderDiscoverTool,
  icon: "M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-4.5-4.5M8 11h6M11 8v6",
  keywords: "prospect sales presales new customer lead recon profile environment spam filter email host tenant saas stack website registrar briefing proposal",
  desc: "Profile a prospect from their domain: email platform and filtering, Microsoft 365 tenant, security grade, SaaS stack and internet-facing systems, with talking points and a client-ready snapshot." });
