"use strict";
/* DNS & Network: lookup tools. */

/* ================================================================ DNS LOOKUP */
function renderDnsTool(main, params) {
  const name = el("input", { type: "text", placeholder: "contoso.com or _dmarc.contoso.com or 1.2.3.4", value: params.get("n") || "", required: true });
  const type = el("select", {}, META.record_types.map((t) => el("option", { value: t, selected: t === (params.get("type") || "TXT") }, t)));
  const out = el("div");
  const form = el("form", { class: "tool-form" },
    el("div", { class: "field grow" }, el("label", {}, "Name"), name),
    el("div", { class: "field" }, el("label", {}, "Type"), type),
    el("button", { class: "btn", type: "submit" }, "Look up everywhere"));
  form.addEventListener("submit", (e) => { e.preventDefault(); location.hash = "dns?" + new URLSearchParams({ n: name.value.trim(), type: type.value }); });
  main.append(card(null, form), out);
  if (params.get("n")) {
    runInto(out, "Querying resolvers and authoritative servers…", () => api(`/api/dns?${new URLSearchParams({ name: params.get("n"), type: params.get("type") || "TXT" })}`), (d) => {
      const frag = el("div");
      frag.append(verdict(d.severity, d.headline, d.subline));
      const dnsIssues = (d.findings || []).filter((x) => x.severity !== "ok" || d.severity === "ok");
      if (dnsIssues.length) frag.append(card("Findings", findingsList(dnsIssues), { flush: true }));
      const dnsStale = (r) => r.matches_authoritative === false && d.severity !== "ok";
      frag.append(card("Answers", table(["Source", "Status", "TTL", "Records"], d.results.map((r) => [
        el("div", {}, r.source, r.authoritative ? el("div", { class: "sub" }, "authoritative") : null),
        el("div", {}, badge(r.status === "ok" ? (dnsStale(r) ? "warning" : "ok") : r.status === "nxdomain" || r.status === "noanswer" ? "info" : "critical", r.status),
          dnsStale(r) && !r.authoritative ? el("div", { class: "sub" }, "differs from authoritative") : null),
        r.ttl ?? "—",
        el("div", {}, r.records.length ? r.records.map((x) => el("div", { class: "mono" }, x)) : el("span", { class: "sub" }, r.error || "—")),
      ])), { flush: true }));
      return frag;
    });
  }
}

/* ================================================================= IP LOOKUP */
function renderIpTool(main, params) {
  const target = el("input", { type: "text", placeholder: "203.0.113.10 or mail.contoso.com", value: params.get("t") || "", required: true });
  const dom = el("input", { type: "text", placeholder: "contoso.com (optional)", value: params.get("d") || "" });
  const out = el("div");
  const form = el("form", { class: "tool-form" },
    el("div", { class: "field grow" }, el("label", {}, "IP address or host name"), target),
    el("div", { class: "field grow" }, el("label", {}, "Check against SPF of domain"), dom),
    el("button", { class: "btn", type: "submit" }, "Look up"));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const p = { t: target.value.trim() };
    if (dom.value.trim()) p.d = dom.value.trim();
    location.hash = "ip?" + new URLSearchParams(p);
  });
  main.append(card(null, form), out);
  if (params.get("t")) {
    const qs = params.get("d") ? "?domain=" + encodeURIComponent(params.get("d")) : "";
    runInto(out, "Looking up registry, ASN and reverse DNS…", () => api("/api/ip/" + encodeURIComponent(params.get("t")) + qs), renderIpResult);
  }
}

function contact(c) {
  if (!c) return null;
  return el("div", {}, c.name ? el("div", {}, c.name) : null,
    (c.emails || []).map((m) => el("div", {}, el("a", { href: "mailto:" + m }, m))),
    (c.phones || []).slice(0, 2).map((p) => el("div", { class: "sub" }, p)),
    c.address ? el("div", { class: "sub" }, c.address) : null);
}

function renderIpResult(d) {
  const frag = el("div");
  const rd = d.rdap || {}, asn = d.asn || {}, svc = d.service;
  if (d.resolved_from) frag.append(el("div", { class: "hint", style: "margin-bottom:10px" },
    d.resolved_from + " resolves to " + d.ip + (d.other_ips.length ? " (also " + d.other_ips.join(", ") + ")" : "")));
  const spf = d.spf;
  const vSev = spf ? resultSev(spf.result) : d.special ? "info" : "ok";
  frag.append(el("div", { class: "verdict sev-" + vSev }, el("div", { class: "v-icon" }, vSev === "ok" ? "✓" : "!"),
    el("div", {},
      el("div", { class: "v-title" }, d.special ? d.ip + ": " + d.special : d.ip + " belongs to " + (d.owner || "an unknown owner")),
      el("div", { class: "v-sub" }, [svc ? "Email service: " + svc.name : null, asn.asn ? "AS" + asn.asn + " " + (asn.name || "") : null,
        rd.country || asn.country ? "Country " + (rd.country || asn.country) : null,
        spf ? "SPF for " + spf.domain + ": " + spf.result : null].filter(Boolean).join(" · ")))));
  if (svc) {
    frag.append(card("Email service", [kv([["Service", svc.name], ["Identified by", svc.matched_on + " (" + svc.confidence + " confidence)"]]),
      svc.spf_include ? [el("div", { class: "hint", style: "margin-top:10px" }, "SPF include this service documents:"), code("include:" + svc.spf_include)] : null,
      svc.note ? el("div", { class: "hint", style: "margin-top:6px" }, svc.note) : null]));
  }
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  if (d.special) return frag;
  frag.append(el("div", { class: "grid-2" },
    card("Network owner (RDAP)", kv([
      ["Organisation", (rd.registrant || {}).name], ["Network name", rd.name], ["Handle", rd.handle],
      ["Range", rd.start && rd.end ? rd.start + " – " + rd.end : null], ["CIDR", (rd.cidrs || []).join(", ")],
      ["Country", rd.country], ["Registered", rd.registered ? rd.registered.slice(0, 10) : null],
      ["Last changed", rd.updated ? rd.updated.slice(0, 10) : null], ["Error", rd.error],
      ["Source", rd.source ? el("a", { href: rd.source, target: "_blank", rel: "noopener noreferrer" }, "RDAP record") : null],
    ])),
    card("Routing & reverse DNS", kv([
      ["ASN", asn.asn ? "AS" + asn.asn : "unknown"], ["AS name", asn.name], ["Announced prefix", asn.prefix],
      ["Registry", asn.registry ? asn.registry.toUpperCase() : null], ["Allocated", asn.allocated],
      ["Reverse DNS", d.rdns && d.rdns.ptr.length ? d.rdns.ptr.join(", ") : "none"],
      ["Forward-confirmed", d.rdns && d.rdns.ptr.length ? (d.rdns.forward_confirmed ? "yes" : "no") : null],
      ["Reputation", link("blacklist", { t: d.ip }, "Check blocklists →")],
    ]))));
  frag.append(el("div", { class: "grid-2" },
    card("Abuse contact", rd.abuse ? contact(rd.abuse) : el("div", { class: "hint" }, "No abuse contact published.")),
    card("Registrant", rd.registrant ? contact(rd.registrant) : el("div", { class: "hint" }, "Not published."))));
  if (spf) {
    frag.append(card("SPF check for " + spf.domain, [
      spf.record ? code(spf.record) : el("div", { class: "hint" }, "No SPF record."),
      kv([["Result", badge(resultSev(spf.result), spf.result)], ["Meaning", spf.explanation],
        ["Matched", spf.trace.length ? spf.trace.map((t) => t.domain + ": " + t.term).join("  ⟵  ") : null],
        ["Lookups used", spf.lookup_count + "/10"]]),
      el("div", { style: "margin-top:8px" }, link("spf", { d: spf.domain, ip: d.ip }, "Open in SPF Inspector →"),
        spf.multiple ? ["  ·  ", link("spfbuild", { d: spf.domain }, "Merge the SPF records in the SPF Builder →")] :
        spf.result !== "pass" ? ["  ·  ", link("spfbuild", svc && svc.spf_include ? { d: spf.domain, add: "include:" + svc.spf_include } : { d: spf.domain, add: (d.version === 6 ? "ip6:" : "ip4:") + d.ip }, svc && svc.spf_include ? `Add include:${svc.spf_include} in the SPF Builder →` : `Add ${d.version === 6 ? "ip6" : "ip4"}:${d.ip} in the SPF Builder →`)] : null)]));
  }
  if (rd.remarks && rd.remarks.length) frag.append(card("Registry remarks", el("div", { class: "sub", style: "white-space:pre-wrap" }, rd.remarks.join("\n"))));
  return frag;
}


/* ============================================================ REGISTRATION */
registerTool({ category: "network", group: "Lookup", id: "dns", title: "DNS Lookup", render: renderDnsTool,
  icon: "M4 6h16v4H4zM4 14h16v4H4zM7 8h.5M7 16h.5", keywords: "propagation authoritative resolver ttl record",
  desc: "Query a record on the local resolver, public resolvers, DNS-over-HTTPS and every authoritative name server, to check propagation and stale caches." });
registerTool({ category: "network", group: "Lookup", id: "ip", title: "IP Lookup", render: renderIpTool,
  icon: "M12 21s-7-6.2-7-11.5a7 7 0 0114 0C19 14.8 12 21 12 21zM12 7.5v4M12 13.5v.5", keywords: "whois rdap asn owner abuse ptr reverse",
  desc: "Who owns an IP: registry owner, network range, ASN, abuse contact and reverse DNS. Recognises email sending services and, with a domain, tells you whether the IP passes that domain's SPF and what to add if it doesn't." });
