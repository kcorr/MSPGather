"use strict";
/* About & responsible use: what every tool touches, which sources it uses, and what is stored. */

const ABOUT_TOUCHES = {
  discover: "DNS, public registries (RDAP), Microsoft's public tenant discovery and an ordinary visit to the public website (home page, security.txt, any published MTA-STS policy). Certificate transparency logs only if you tick the box.",
  assessments: "Nothing: reopens reports your team saved.",
  bulkaudit: "DNS and public registries for each domain in the list.",
  lookalike: "DNS and public registries for generated look-alike names.",
  tenant: "Microsoft's public sign-in discovery; for a federated domain, the identity provider's published federation metadata.",
  harden: "The same public sources as Prospect Discovery.",
  spfbuild: "DNS.", dmarcbuild: "DNS.", mtasts: "DNS and the domain's published MTA-STS policy.", parked: "DNS.",
  dmarcreport: "Reports you upload; DNS lookups for the sending IPs in them.",
  tls: "TLS handshakes with the host and port you enter, trying each protocol version.",
  ports: "TCP connections to the ports you list, plus a short read of each service's banner.",
  troubleshoot: "Nothing: recognises what you paste and opens the right tool.",
  headers: "Headers you paste; DNS and registry lookups for the IPs and domains in them.",
  ndr: "The bounce you paste; DNS and registry lookups for addresses in its headers.",
  domain: "DNS and the domain's published MTA-STS policy.",
  spf: "DNS.",
  blacklist: "DNS queries to the blocklist operators listed in the tool.",
  smtp: "A live SMTP session with the mail server (EHLO, STARTTLS and, if you ask, one RCPT TO). It never sends a message.",
  autodiscover: "The same Autodiscover requests Outlook makes for the domain.",
  m365net: "Nothing for pasted collector output; Microsoft's public endpoints for the server-side baseline.",
  dns: "Public resolvers and the domain's own authoritative name servers.",
  ip: "Public registries (RDAP) and Team Cymru's IP-to-ASN service.",
  http: "Ordinary HTTP(S) requests to the URL, following redirects.",
  whois: "Public registries (RDAP) and DNS.",
  certdecode: "Nothing for pasted certificates; one TLS connection when you fetch a chain from a host.",
  url: "Nothing unless you choose to follow the link's redirects (then ordinary web requests).",
};

const ABOUT_SOURCES = [
  ["Your DNS resolver, Cloudflare and Google DNS-over-HTTPS", "DNS lookups. DNS-over-HTTPS is only used when classic DNS fails or drops large answers (DOH_FALLBACK)."],
  ["RDAP registries (through IANA's bootstrap)", "Domain and IP registration data: registrar, dates, status, network owner. Queried straight from each registry, a few requests at a time, backing off when asked. Registry terms forbid high-volume automated use; ARIN's don't allow its data to be used for marketing."],
  ["Team Cymru IP-to-ASN (DNS)", "Which network an IP address belongs to."],
  ["Microsoft (login.microsoftonline.com)", "Public tenant discovery: tenant ID, region, managed or federated sign-in."],
  ["crt.sh and SSLMate CertSpotter", "Optional certificate transparency search in Prospect Discovery. MSPGather sends crt.sh at most 4 requests a minute (it asks for no more than 5); CertSpotter is the fallback, with more queries if CERTSPOTTER_API_KEY is set."],
  ["Spamhaus", "Blacklist Check. The public mirrors are free only for low-volume, non-commercial use and refuse public resolvers. For client work, set SPAMHAUS_DQS_KEY to use the Data Query Service."],
  ["Other blocklists (Barracuda, SpamCop, SURBL, URIBL, UCEPROTECT and others)", "Blacklist Check. SURBL requires a usage agreement for commercial products, URIBL is for low-volume use, and Barracuda asks you to register the DNS servers that query it. Every list is asked about its own test entry first, so a list that refuses your resolver shows as \"couldn't check\", never as clean."],
];

function renderAboutTool(page) {
  const sec = (title, ...body) => card(title, body, { icon: "info" });
  page.append(sec("How MSPGather stays on the right side of the line",
    el("ol", { class: "steps" },
      el("li", {}, el("div", { class: "step-title" }, "Prospect work uses public information only"),
        el("div", { class: "step-detail" }, "Discovery, the hardening plan, lookalike domains and the builders read DNS, public registries, Microsoft's public tenant discovery and the public website, the same as any visitor or mail server. They never scan ports, probe for vulnerabilities, try to log in or verify mailboxes, so they are safe to run before you have a relationship with the company.")),
      el("li", {}, el("div", { class: "step-title" }, "Active tests need authorization, enforced by the server"),
        el("div", { class: "step-detail" }, "The SSL/TLS Checker, Port Check and SMTP Test connect to a server and probe it. They only run after you confirm you own the system or are authorized to test it; the server refuses them otherwise, and each run is recorded in the audit log with that confirmation. Use them on your own and your clients' systems, never on prospects.")),
      el("li", {}, el("div", { class: "step-title" }, "Tools that contact a target behave like a normal client"),
        el("div", { class: "step-detail" }, "HTTP Inspector, Autodiscover, certificate fetch and URL Analyzer (when you choose to follow a link) make the same requests a browser or Outlook would.")),
      el("li", {}, el("div", { class: "step-title" }, "Pasted content stays private"),
        el("div", { class: "step-detail" }, "Headers, bounces, logs, tokens and reports you paste are analysed in memory and never stored or written to the audit log."))),
    el("div", { class: "notice warn", style: "margin:14px 0 0" },
      "General information, not legal advice. Computer-misuse laws (for example the US Computer Fraud and Abuse Act, the UK Computer Misuse Act and EU member-state laws) and internet providers' acceptable-use policies differ by country and contract. Scanning or probing systems you don't own without permission can breach them. When in doubt, get written permission before running an active test.")));

  const levels = ["offline", "passive", "contacts", "active"];
  page.append(card("What each tool touches", [
    el("div", { class: "card-body", style: "display:flex;flex-wrap:wrap;gap:10px 20px;border-bottom:1px solid var(--border)" },
      levels.map((a) => el("div", { style: "display:flex;gap:8px;align-items:flex-start;flex:1 1 230px" }, accessChip(a), el("span", { class: "hint" }, ACCESS[a].tip)))),
    table(["Tool", "Workspace", "Access", "What it contacts"],
      visibleTools().filter((t) => t.mode !== "admin").sort((a, b) => levels.indexOf(b.access) - levels.indexOf(a.access))
        .map((t) => [el("a", { href: `#${t.id}` }, t.title), modeOf(t.mode).title, accessChip(t.access), ABOUT_TOUCHES[t.id] || (t.access === "offline" ? "Nothing: analysed on the server." : ACCESS[t.access].tip)])),
  ], { flush: true, icon: "radar" }));

  page.append(card("Third-party data sources", table(["Source", "Used for"], ABOUT_SOURCES.map(([s, u]) => [el("b", {}, s), u])), { flush: true, icon: "globe" }));

  page.append(card("What MSPGather stores", el("ul", { style: "margin:0;padding-left:20px;line-height:1.8" },
    el("li", {}, "User accounts, MFA secrets and sessions (when sign-in is on)."),
    el("li", {}, "The audit log: sign-ins, account changes and which tool was run against which target (never pasted content). Kept for 90 days by default (MSPGATHER_AUDIT_RETENTION_DAYS)."),
    el("li", {}, "Saved reports, only when someone presses Save. Email addresses that look like a named person are replaced with \"[name removed]\" when saving. Reports are shared with the team, deletable, and removed after 365 days by default (MSPGATHER_ASSESSMENT_RETENTION_DAYS). Treat them like any other prospect or customer record."),
    el("li", {}, "Report branding (your organisation's name and contact for client snapshots)."),
    el("li", {}, "Nothing else. No telemetry, no external accounts.")), { icon: "database" }));

  page.append(el("p", { class: "hint", style: "text-align:center;margin-top:20px" },
    `MSPGather ${META.version ? "v" + META.version : ""} · MIT licensed · `, el("a", { href: "https://github.com/kcorr/MSPGather", rel: "noopener noreferrer", target: "_blank" }, "github.com/kcorr/MSPGather")));
}

registerTool({ id: "about", title: "About & Responsible Use", render: renderAboutTool, icon: ICONS.info,
  keywords: "about legal law responsible use scanning authorization data sources privacy storage gdpr terms",
  desc: "What each tool touches, which public sources MSPGather uses, what it stores, and how active tests are kept to systems you're authorized to test." });
