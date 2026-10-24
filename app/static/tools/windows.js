"use strict";
/* Windows tools: Error Code Lookup and Event Log Analyzer. */

addStyles(`
.errcode-examples { display:flex; flex-wrap:wrap; gap:6px; margin-top:10px; align-items:center; }
.errcode-examples a { font-family: var(--mono, ui-monospace, monospace); font-size:12px; padding:2px 8px; border-radius:999px; border:1px solid var(--border, #d0d7de); text-decoration:none; }
.errcode-list { margin:0; padding-left:20px; }
.errcode-list li { margin:4px 0; line-height:1.45; }
.errcode-note { margin:0 0 8px; }
.errcode-chips { display:flex; flex-wrap:wrap; gap:6px; }
.errcode-chips a { font-family: var(--mono, ui-monospace, monospace); font-size:12px; padding:2px 8px; border-radius:6px; border:1px solid var(--border, #d0d7de); text-decoration:none; }
.errcode-alt { padding:10px 16px; border-top:1px solid var(--border, #d0d7de); }
.errcode-alt:first-child { border-top:0; }
.eventlog-collect summary { cursor:pointer; font-weight:600; }
.eventlog-collect .eventlog-tabs { display:flex; flex-wrap:wrap; gap:6px; margin:10px 0; }
.eventlog-collect .eventlog-tabs button.active { outline:2px solid currentColor; }
.eventlog-msg summary { cursor:pointer; }
.eventlog-msg pre { white-space:pre-wrap; word-break:break-word; margin:6px 0 0; font-size:12px; max-height:320px; overflow:auto; }
`);

/* ========================================================== ERROR CODE LOOKUP */
const ERRCODE_EXAMPLES = ["0x80070005", "-2147024891", "1326", "0xC000006A", "KDC_ERR_PREAUTH_FAILED", "0x0000009F", "0x8024402C", "0x80180014", "0x800f0922", "access denied"];

function renderErrcodeTool(main, params) {
  const out = el("div");
  const form = hashForm("errcode", [
    { name: "q", label: "Error code, name or text containing a code", placeholder: "0x80070005, -2147024891, 5, 0xC000006A, 0x7E, KDC_ERR_PREAUTH_FAILED, ERROR_ACCESS_DENIED, 'access denied'…", grow: true, required: true },
  ], params, "Look up");
  main.append(card(null, [form, el("div", { class: "errcode-examples" }, el("span", { class: "hint" }, "Try:"),
    ERRCODE_EXAMPLES.map((x) => link("errcode", { q: x }, x)))]), out);
  if (params.get("q")) runInto(out, "Decoding…", () => api(`/api/win/code?q=${encodeURIComponent(params.get("q"))}`), renderErrcodeResult);
}

function errcodeEntryBody(p) {
  const parts = [];
  if (p.notes && p.notes.length) {
    parts.push(card("In context", p.notes.map((n) => el("div", { class: "notice errcode-note" }, n))));
  }
  if (p.causes && p.causes.length) {
    parts.push(card("Common causes", el("ul", { class: "errcode-list" }, p.causes.map((c) => el("li", {}, c)))));
  }
  const steps = (p.fixes || []).map((f) => ({ title: f }));
  if (p.commands && p.commands.length) steps.push({ title: steps.length ? "Useful commands" : "Commands to investigate", detail: "Replace the example names (contoso.com, jsmith, server names) with yours.", commands: p.commands });
  const ns = nextSteps(steps);
  if (ns) parts.push(ns);
  return parts;
}

function errcodeFactRows(d, p) {
  const rows = [];
  if (p) {
    rows.push(["Type", p.kind_label]);
    if (p.name) rows.push(["Name", el("span", { class: "mono" }, p.name)]);
    if (p.alias && p.alias !== p.name) rows.push(["Also known as", el("span", { class: "mono" }, p.alias)]);
    if (p.win32 != null) rows.push(["Win32 error", `${p.win32} (0x${p.win32.toString(16).toUpperCase()})`]);
    if (p.forms && p.forms.hresult) rows.push(["As HRESULT", el("span", { class: "mono" }, p.forms.hresult)]);
  }
  const shown = new Set([p && p.forms && p.forms.hresult]);
  if (d.structure) d.structure.forms.forEach(([k, v]) => { if (!shown.has(v)) rows.push([k, el("span", { class: "mono" }, v)]); });
  return rows;
}

function renderErrcodeResult(d) {
  const frag = el("div");
  const p = d.primary;
  frag.append(verdict(d.severity, d.headline, d.subline));
  const fr = errcodeFactRows(d, p);
  if (fr.length) frag.append(facts(fr.slice(0, 7)));

  if (d.candidates && d.candidates.length) {
    frag.append(card(`Matching entries (${d.candidates.length})`, table(["Code", "Type", "Name", "Meaning"], d.candidates.map((c) => [
      link("errcode", { q: c.query }, c.display), c.kind_label, el("span", { class: "mono" }, c.name || "—"), c.meaning])), { flush: true }));
  }
  if (p) {
    frag.append(...errcodeEntryBody(p));
  }
  if (d.bugcheck_params && d.bugcheck_params.length) {
    frag.append(card("Bug check parameters", [
      table(["Parameter", "Value"], d.bugcheck_params.map((v, i) => [`Parameter ${i + 1}`, el("span", { class: "mono" }, v)])),
      el("div", { class: "hint", style: "padding:8px 16px" }, "What each parameter means depends on the bug check. WinDbg's !analyze -v explains them for this dump."),
    ], { flush: true }));
  }
  if (d.alternatives && d.alternatives.length) {
    frag.append(card("The same number has other meanings", d.alternatives.map((a) => el("div", { class: "errcode-alt" },
      el("div", {}, badge("info", a.kind_label), " ", el("strong", { class: "mono" }, a.display), a.name ? [" ", el("span", { class: "mono" }, a.name)] : null),
      el("div", { class: "f-detail", style: "margin-top:4px" }, a.meaning),
      el("div", { class: "hint", style: "margin-top:4px" }, "Pick the one that matches where you saw the code. ",
        link("errcode", { q: a.kind === "kerberos" ? `kerberos ${a.display}` : a.kind === "bugcheck" ? `bugcheck ${a.display}` : a.kind === "win32" ? String(a.code) : a.display }, "Show this one →")))), { flush: true }));
  }
  const rel = p ? (p.related || []).filter((r) => r.toUpperCase() !== String(p.display).toUpperCase() && r !== p.alias && r !== p.name) : [];
  if (rel.length) {
    frag.append(card("Related codes", el("div", { class: "errcode-chips" }, rel.map((r) => link("errcode", { q: r }, r)))));
  }
  if (d.others && d.others.length) {
    frag.append(card("Other codes found in your text", el("div", { class: "errcode-chips" }, d.others.map((r) => link("errcode", { q: r }, r)))));
  }
  const st = d.structure;
  if (st) {
    const body = [];
    if (st.fields.length) body.push(table(["Field", "Value", "Meaning"], st.fields.map(([f, v, m]) => [f, el("span", { class: "mono" }, v), m || ""])));
    if (st.notes.length) body.push(el("div", { class: "card-body" }, st.notes.map((n) => el("p", { class: "f-detail", style: "margin:0 0 6px" }, n))));
    body.push(el("div", { class: "card-body" }, kv(st.forms)));
    frag.append(card(`Structure (${st.layout})`, body, { flush: true }));
  }
  return frag;
}

registerTool({
  category: "windows", group: "Codes", id: "errcode", title: "Error Code Lookup", render: renderErrcodeTool,
  icon: "M4 5h16v14H4zM8 9h2M8 13h8M12 9h4",
  keywords: "error code hresult win32 ntstatus 0x8007 0xc000 kerberos kdc_err bug check bsod stop code blue screen windows update 0x8024 intune enrollment 0x8018 autopilot dsregcmd entra join lookup decode",
  desc: "Paste any Windows error code (hex, negative decimal, NTSTATUS, Kerberos, bug check or name) and get what it means, why it happens and how to fix it.",
});

/* ======================================================== EVENT LOG ANALYZER */
const EVENTLOG_SEL = "Select-Object TimeCreated, Id, ProviderName, LogName, MachineName, Message";
const EVENTLOG_COLLECTORS = [
  { id: "lockout", label: "Lockouts (PDC emulator)", note: "Run on an admin machine with the ActiveDirectory module (RSAT). The PDC emulator sees every lockout (4740) and most bad-password events. Paste the clipboard here.",
    cmd: `$pdc = (Get-ADDomain).PDCEmulator\nGet-WinEvent -ComputerName $pdc -FilterHashtable @{LogName='Security'; Id=4740,4771,4776,4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |\n  ${EVENTLOG_SEL} |\n  ConvertTo-Json | Set-Clipboard` },
  { id: "lockall", label: "Lockouts (all DCs)", note: "Same as above, from every domain controller. Slower, but catches failures that hit other DCs first.",
    cmd: `$since = (Get-Date).AddHours(-24)\nGet-ADDomainController -Filter * | ForEach-Object {\n  Get-WinEvent -ComputerName $_.HostName -FilterHashtable @{LogName='Security'; Id=4740,4771,4776,4625; StartTime=$since} -ErrorAction SilentlyContinue\n} | ${EVENTLOG_SEL} | ConvertTo-Json | Set-Clipboard` },
  { id: "source", label: "On the lockout source", note: "Run on the machine named as the lockout source (needs 'Audit Logon' failure auditing). 4625 shows the logon type and caller process; 4648 shows explicit credentials.",
    cmd: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4648; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |\n  ${EVENTLOG_SEL} |\n  ConvertTo-Json | Set-Clipboard` },
  { id: "crash", label: "Crashes & reboots", note: "System log, last 30 days: unexpected shutdowns (41, 6008), bug checks (1001), planned restarts (1074), boots (6005/6006), service crashes, WHEA hardware errors, disk/storage and NTFS errors.",
    cmd: `Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1074,6008,6005,6006,1001,7031,7034,17,18,19,47,7,11,51,129,153,157,55,98; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue |\n  Select-Object TimeCreated, Id, ProviderName, LogName, MachineName, Message,\n    @{n='BugcheckCode'; e={ if ($_.Id -eq 41 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power') { $_.Properties[0].Value } }} |\n  ConvertTo-Json | Set-Clipboard` },
  { id: "apps", label: "App crashes", note: "Application log, last 7 days: application crashes (1000), hangs (1002) and .NET unhandled exceptions (1026).",
    cmd: `Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1002,1026; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |\n  ${EVENTLOG_SEL} |\n  ConvertTo-Json | Set-Clipboard` },
  { id: "security", label: "Security changes", note: "Last 7 days: log cleared (1102/104), audit policy changes, account changes, group membership changes and service installs (4697/7045). Run on a DC for domain accounts.",
    cmd: `$since = (Get-Date).AddDays(-7)\nGet-WinEvent -FilterHashtable @{LogName='Security'; Id=1102,4719,4720,4722,4725,4726,4728,4732,4756,4738,4767,4697; StartTime=$since},\n                            @{LogName='System'; Id=7045,104; StartTime=$since} -ErrorAction SilentlyContinue |\n  ${EVENTLOG_SEL} |\n  ConvertTo-Json | Set-Clipboard` },
  { id: "domain", label: "Domain, GPO & time", note: "System log, last 3 days: Group Policy failures, Netlogon secure channel problems, Kerberos errors and time sync.",
    cmd: `Get-WinEvent -FilterHashtable @{LogName='System'; Id=1129,1053,1058,1085,5719,5722,5723,5805,3210,3,4,36; StartTime=(Get-Date).AddDays(-3)} -ErrorAction SilentlyContinue |\n  ${EVENTLOG_SEL} |\n  ConvertTo-Json | Set-Clipboard` },
  { id: "xml", label: "Non-English Windows (XML)", note: "Messages are localized on non-English systems. Raw XML carries the field names, so the analysis still works. Swap in the Id list you need.",
    cmd: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740,4771,4776,4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |\n  ForEach-Object { $_.ToXml() } | Set-Clipboard` },
];

function eventlogCollectorCard() {
  const body = el("div");
  const tabs = el("div", { class: "eventlog-tabs" });
  const show = (c) => {
    tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.id === c.id));
    body.replaceChildren(el("div", { class: "hint", style: "margin-bottom:6px" }, c.note), code(c.cmd));
  };
  EVENTLOG_COLLECTORS.forEach((c) => tabs.append(el("button", { class: "btn secondary", type: "button", "data-id": c.id, onclick: () => show(c) }, c.label)));
  show(EVENTLOG_COLLECTORS[0]);
  return card(null, el("details", { class: "eventlog-collect" },
    el("summary", {}, "Collect events with PowerShell (copy-paste collectors)"),
    el("div", { class: "hint", style: "margin-top:8px" }, "Each command copies the events to your clipboard as JSON. Also accepted: Event Viewer → Copy → Copy details as text, Save All Events As CSV / XML / tab-delimited text, Get-WinEvent | Format-List *, and wevtutil qe /f:text."),
    tabs, body));
}

const EVENTLOG_SAMPLES = [["windows-lockout.txt", "Sample: lockout"], ["windows-crash.txt", "Sample: crashes"], ["windows-spray.txt", "Sample: password spray"]];

function renderEventlogTool(main) {
  const out = el("div");
  const go = (raw) => runInto(out, "Parsing and analyzing events…", () => api("/api/win/events", { body: { raw } }), renderEventlogResult);
  const pb = pasteBox({ placeholder: "Paste events here: Get-WinEvent … | ConvertTo-Json, Format-List *, Event Viewer 'Copy details as text', CSV or XML export. Multiple events at once are fine.", onRun: go, rows: 12 });
  const row = pb.element.querySelector(".btn-row");
  const clearBtn = [...row.querySelectorAll("button")].find((b) => b.textContent === "Clear");
  EVENTLOG_SAMPLES.forEach(([file, label]) => row.insertBefore(el("button", { class: "btn secondary", type: "button", onclick: async () => {
    pb.textarea.value = await (await fetch(`samples/${file}`)).text(); go(pb.textarea.value);
  } }, label), clearBtn));
  if (clearBtn) clearBtn.addEventListener("click", () => out.replaceChildren());
  main.append(eventlogCollectorCard(), pb.element, out);
}

function eventlogCodeLink(text) {
  // Make the bug check / error code in a summary clickable.
  const m = /(0x[0-9A-Fa-f]{5,8})/.exec(text || "");
  if (!m) return text;
  const i = m.index;
  return el("span", {}, text.slice(0, i), link("errcode", { q: m[1] }, m[1]), text.slice(i + m[1].length));
}

function renderEventlogResult(d) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  frag.append(facts(d.facts));
  frag.append(card(`Findings (${d.findings.length})`, findingsList(d.findings), { flush: true }));
  const ns = nextSteps(d.steps);
  if (ns) frag.append(ns);

  if (d.lockouts.length) {
    frag.append(card("Lockout and bad-password sources", table(
      ["User", "Lockouts", "Failed events", "Most likely source", "Lockout callers (4740)", "Failure sources", "Failure codes", "Logon types (4625)", "Window"],
      d.lockouts.map((r) => [
        el("strong", { style: "white-space:nowrap" }, r.user), r.lockouts, r.failures,
        el("div", {}, el("strong", { class: "mono" }, r.likely_source || "—"), r.likely_ip ? el("div", { class: "sub mono" }, r.likely_ip) : null),
        el("div", {}, r.callers.length ? r.callers.map(([c, n]) => el("div", { class: "mono" }, `${c} ×${n}`)) : "—"),
        el("div", {}, r.sources.map(([s, n, ip]) => el("div", { class: "mono" }, `${s}${ip ? " (" + ip + ")" : ""} ×${n}`))),
        el("div", {}, r.codes.map(([c, n]) => el("div", {}, link("errcode", { q: c }, c), ` ×${n}`))),
        el("div", {}, r.logon_types.length ? r.logon_types.map(([c, t, desc, n]) => el("div", {}, `${c}: type ${t} ${desc} ×${n}`)) : "—"),
        el("div", { class: "sub" }, r.first || "", r.last && r.last !== r.first ? [el("br"), r.last] : null, r.span ? [el("br"), r.span] : null),
      ]), (i) => (d.lockouts[i].lockouts ? "hl" : null)), { flush: true }));
  }

  if (d.spray.length) {
    frag.append(card("Sources failing for many accounts (password spray)", table(
      ["Source", "Accounts", "Attempts", "Unknown usernames", "Window", "Then succeeded as", "Accounts tried"],
      d.spray.map((r) => [el("span", { class: "mono" }, r.source + (r.name ? ` (${r.name})` : "")), r.users, r.attempts, r.nonexistent, r.span || "—",
        r.succeeded.length ? el("strong", {}, r.succeeded.join(", ")) : "—", el("span", { class: "sub" }, r.top_users.join(", "))]),
      (i) => "hl"), { flush: true }));
  }

  d.crashes.forEach((c) => {
    if (!c.incidents.length) return;
    frag.append(card(`Unexpected shutdowns: ${c.computer}`, table(
      ["Time", "Bug check", "Events", "Hardware errors in the 24h before", "Storage errors in the 24h before"],
      c.incidents.map((x) => [x.time || "—",
        x.bugcheck ? el("div", {}, link("errcode", { q: x.bugcheck }, x.bugcheck), x.bugcheck_name ? el("div", { class: "sub mono" }, x.bugcheck_name) : null,
          x.params ? el("div", { class: "sub mono" }, x.params.join(", ")) : null)
          : el("span", { class: "sub" }, x.power_button ? "none (power button held)" : "none recorded"),
        x.events.join(", "), x.hw_before || "—", x.storage_before || "—"]),
      (i) => (c.incidents[i].bugcheck || c.incidents[i].hw_before ? "hl" : null)), { flush: true }));
  });

  if (d.timeline.length) {
    frag.append(card(`Timeline of notable events (${d.timeline.length}${d.timeline_truncated ? ", most recent" : ""})`, table(
      ["Time", "Computer", "Event", "What happened", "Details"],
      d.timeline.map((t) => [el("span", { class: "mono" }, t.time || "—"), t.computer || "—", el("span", {}, badge(t.severity, String(t.id))), t.title, eventlogCodeLink(t.summary)]),
      (i) => (d.timeline[i].severity === "critical" ? "hl" : null)), { flush: true }));
  }

  frag.append(card(`Event types (${d.groups.length})`, table(
    ["Event ID", "Source", "Count", "First", "Last", "Meaning"],
    d.groups.map((g) => [el("strong", {}, String(g.id)), el("span", { class: "sub" }, g.provider || "—"), g.count, g.first || "—", g.last || "—",
      g.known ? el("div", {}, el("div", {}, g.title, g.noise ? [" ", badge("info", "noise")] : null), el("div", { class: "sub" }, g.meaning))
        : el("div", {}, el("span", { class: "sub" }, "Not in the knowledge base. Example: "), g.sample || "")]),
    (i) => (d.groups[i].severity === "critical" ? "hl" : null)), { flush: true }));

  const filter = el("input", { type: "text", class: "filter", placeholder: "Filter events (ID, user, computer, text)…" });
  const holder = el("div");
  const draw = () => {
    const q = filter.value.trim().toLowerCase();
    const rows = d.events.filter((e) => !q || `${e.id} ${e.provider} ${e.computer} ${e.summary} ${e.message}`.toLowerCase().includes(q)).slice(-500).reverse();
    holder.replaceChildren(table(["Time", "ID", "Computer", "Summary"], rows.map((e) => [
      el("span", { class: "mono" }, e.time || "—"), el("span", {}, badge(e.severity, String(e.id))), e.computer || "—",
      el("details", { class: "eventlog-msg" }, el("summary", {}, (e.title ? e.title + ": " : "") + (e.summary || "")), el("pre", {}, e.message || "(no message text)")),
    ])));
  };
  filter.addEventListener("input", draw); draw();
  frag.append(card(`All events (${d.parse.count}${d.parse.events_shown < d.parse.count ? `, showing the last ${d.parse.events_shown}` : ""}; newest first)`, [filter, holder], { flush: true }));
  return frag;
}

registerTool({
  category: "windows", group: "Logs", id: "eventlog", title: "Event Log Analyzer", render: renderEventlogTool,
  icon: "M5 3h11l3 3v15H5zM8 9h8M8 13h8M8 17h5",
  keywords: "event log viewer get-winevent lockout 4740 4625 4771 4776 locked out account password spray crash reboot bsod bug check 41 6008 1001 whea service crash 7031 7045 security log cleared 1102",
  desc: "Paste Windows events (Get-WinEvent JSON, Format-List, Event Viewer text, CSV or XML) and get the lockout source, password sprays, crash causes and what to fix.",
});
