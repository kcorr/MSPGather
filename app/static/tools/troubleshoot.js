"use strict";
/* Troubleshoot: paste whatever you have and get sent to the right tool, or start from a symptom. */

// What a paste looks like → the tool that reads it. Order matters: a bounce contains headers.
const TS_DETECT = [
  { tool: "token", label: "a JWT token", test: (s) => /^\s*(Bearer\s+)?eyJ[\w-]+\.[\w-]+\.[\w-]*\s*$/.test(s) },
  { tool: "token", label: "a SAML response", test: (s) => /<(saml2?p?:)?Response[\s>]|<saml2?:Assertion[\s>]|SAMLResponse=|^\s*PHNhbWwycDpSZXNwb25z|^\s*PHNhbWxwOlJlc3BvbnNl/i.test(s) },
  { tool: "certdecode", label: "a certificate or CSR", test: (s) => /-----BEGIN (CERTIFICATE|CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST|PKCS7)-----/.test(s) },
  { tool: "dsreg", label: "dsregcmd /status output", test: (s) => /AzureAdJoined\s*:|DomainJoined\s*:|EnterpriseJoined\s*:/i.test(s) },
  { tool: "m365net", label: "the Microsoft 365 connectivity collector output", test: (s) => /BEGIN MSPGATHER M365 NETWORK/.test(s) },
  { tool: "dmarcreport", label: "a DMARC aggregate report", test: (s) => /<feedback[\s>]/i.test(s) && /<record>|<policy_published>/i.test(s) },
  { tool: "dmarcreport", label: "a TLS-RPT report", test: (s) => /"organization-name"/.test(s) && /"policies"/.test(s) },
  { tool: "ndr", label: "a bounce message (NDR)", test: (s) => /Delivery has failed|Undeliverable|Diagnostic information for administrators|Remote Server returned|Diagnostic-Code:|Final-Recipient:|Mail delivery failed|Delivery Status Notification|could not be delivered|Your message (couldn't|wasn't) (be )?delivered/i.test(s) },
  { tool: "headers", label: "email message headers", test: (s) => (s.match(/^(Received|Authentication-Results|ARC-Seal|DKIM-Signature|Return-Path|Message-ID|Received-SPF|X-MS-Exchange-[\w-]+|X-Forefront-Antispam-Report):/gim) || []).length >= 2 },
  { tool: "eventlog", label: "Windows event log entries", test: (s) => /<Event xmlns|\bEventID\b|Event ID:\s*\d|TimeCreated|Log Name:\s|"Id"\s*:\s*\d{3,5}\b|\bTaskDisplayName\b/i.test(s) },
  { tool: "aadsts", label: "an Entra ID sign-in error", test: (s) => /AADSTS\d{5,}|"errorCode"\s*:\s*\d{5,}|Sign-in error code|Correlation ID|Request Id:/i.test(s) },
  { tool: "url", label: "a link to check", test: (s) => /safelinks\.protection\.outlook\.com|urldefense\.|linkprotect\.cudasvc|^\s*https?:\/\/\S+\s*$/i.test(s) },
];

function tsDetect(text) {
  const s = text.trim();
  if (!s) return null;
  const hit = TS_DETECT.find((d) => d.test(s));
  if (hit && toolById(hit.tool)) return { ...hit, kind: "paste" };
  if (!s.includes("\n")) {
    const intents = searchIntents(s);
    const intent = intents.find((i) => i.mode === "troubleshoot") || intents[0];
    if (intent) return { kind: "intent", href: intent.href, label: intent.label, tool: intent.href.slice(1).split("?")[0] };
  }
  return null;
}

const TS_SYMPTOMS = [
  ["inbox", "Email is bouncing", "Decode the NDR: what failed and how to fix it", "ndr"],
  ["loop", "Mail is looping or duplicated", "Trace the route in the message headers", "headers"],
  ["spam", "Mail lands in junk or is spoofed", "SPF, DKIM, DMARC and the spam verdict", "headers"],
  ["clock", "Email is delayed", "Hop-by-hop delays from the headers", "headers"],
  ["octagon", "Our mail server is blocklisted", "Check the IP or domain on blocklists", "blacklist"],
  ["mail", "Domain mail settings look wrong", "MX, SPF, DKIM, DMARC cross-checks", "domain"],
  ["identity", "User can't sign in (AADSTS…)", "Which policy blocked it and why", "aadsts"],
  ["lock", "Account keeps locking out", "Find the lockout source in event logs", "eventlog"],
  ["m365", "Outlook keeps prompting for a password", "Walk through Autodiscover step by step", "autodiscover"],
  ["network", "Microsoft 365 slow on one network", "Detect TLS inspection and blocked endpoints", "m365net"],
  ["device", "PC not joined / no SSO", "Read dsregcmd /status and find the failing step", "dsreg"],
  ["certificate", "Certificate error", "Decode it, or check the server's chain", "certdecode"],
  ["monitor", "Website down or redirect loop", "Follow the redirects hop by hop", "http"],
  ["globe", "DNS change isn't showing", "Compare resolvers and authoritative servers", "dns"],
  ["windows", "Windows error code", "HRESULT, Win32, NTSTATUS, Intune codes", "errcode"],
  ["security", "Suspicious link or email", "Unwrap, check and get block commands", "url"],
];

function renderTroubleshootTool(page) {
  const ta = el("textarea", { spellcheck: "false", "aria-label": "Paste what you have", style: "min-height:170px",
    placeholder: "Paste anything: message headers, a bounce, an AADSTS error or sign-in JSON, dsregcmd /status, event log entries, a certificate, a token, a suspicious link…\nOr type a domain, IP or error code." });
  const detect = el("div", { class: "triage-detect" });
  const go = el("button", { class: "btn", type: "button", disabled: true }, "Analyze", icon("arrow"));
  let hit = null;
  const update = () => {
    hit = tsDetect(ta.value);
    go.disabled = !hit;
    detect.classList.toggle("found", !!hit);
    const t = hit && toolById(hit.tool);
    detect.replaceChildren(...(hit && t
      ? [iconSvg(t.icon), el("div", { style: "flex:1;min-width:0" }, el("b", {}, hit.kind === "paste" ? `Looks like ${hit.label}` : hit.label),
        el("div", { class: "sub" }, `${t.title}: ${t.desc}`)), go]
      : [icon("info"), el("div", { class: "sub", style: "flex:1" }, ta.value.trim() ? "Not sure what this is. Pick a tool from the list below, or check the paste is complete." : "MSPGather will recognise what you paste and open the right tool."), go]));
  };
  const run = () => {
    if (!hit) return;
    if (hit.kind === "paste") handOff(hit.tool, ta.value);
    else location.hash = hit.href;
  };
  go.addEventListener("click", run);
  ta.addEventListener("input", update);
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });

  page.append(el("section", { class: "hero" },
    el("div", { class: "hero-eyebrow" }, icon("troubleshoot"), "Troubleshoot"),
    el("h1", {}, "What's going wrong?"),
    el("p", {}, "Paste what you have and MSPGather opens the right tool with it, or start from a symptom. Every result leads with a one-line verdict, then the cause and the fix."),
    ta, detect,
    el("div", { class: "hero-note" }, icon("lock"), "Pasted content is analysed in memory on the MSPGather server and never stored or logged.")));
  update();
  setTimeout(() => ta.focus(), 0);

  page.append(el("div", { class: "section-title" }, "Start from a symptom"),
    el("div", { class: "symptoms" }, TS_SYMPTOMS.filter(([, , , id]) => toolById(id)).map(([ic, title, sub, id]) =>
      el("a", { class: "symptom", href: `#${id}` }, el("span", { class: "symptom-icon" }, icon(ic)), el("div", {}, el("b", {}, title), el("span", {}, sub))))));

  const mode = modeOf("troubleshoot");
  mode.groups.filter((g) => g !== "Start").forEach((g) => {
    const tools = visibleTools().filter((t) => t.mode === "troubleshoot" && t.group === g);
    if (!tools.length) return;
    page.append(el("div", { class: "section-title" }, g), el("div", { class: "tool-grid" }, tools.map((t) => toolCard(t))));
  });
}

registerTool({ id: "troubleshoot", title: "Triage", navTitle: "Triage: paste anything", landing: true, render: renderTroubleshootTool,
  icon: "M21 7.5a4.5 4.5 0 01-6.2 4.2L7 19.5a1.9 1.9 0 01-2.7-2.7l7.8-7.8A4.5 4.5 0 0116.5 3L14 5.5l.5 2.5 2.5.5z",
  keywords: "triage paste detect symptom problem issue help start",
  desc: "Paste headers, a bounce, an error, a log or a certificate and go straight to the tool that reads it, or start from a symptom." });
