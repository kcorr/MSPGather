"use strict";
/* Harden: a prioritised, fix-by-fix plan for a client's public-facing configuration. */

const HARDEN_STATUS = {
  pass: { icon: "check", label: "Passing" }, fail: { icon: "x", label: "To fix" }, warn: { icon: "alert", label: "Improve" },
  manual: { icon: "clipboard", label: "Check manually" }, unknown: { icon: "help", label: "Couldn't check" }, na: { icon: "info", label: "Not applicable" },
};
const HARDEN_AREA_ICON = { "email-auth": "mail", "mail-transport": "lock", domain: "globe", "dns-hygiene": "layers", web: "monitor", exposure: "server", m365: "m365" };
const hardenGrade = (s) => (s == null ? "?" : s >= 90 ? "A" : s >= 80 ? "B" : s >= 65 ? "C" : s >= 50 ? "D" : "F");

function renderHardenTool(page, params) {
  const d = params.get("d");
  if (!d) return hardenLanding(page);
  const bar = heroSearch("harden", { placeholder: "Client domain", button: "Build plan", value: d, icon: "harden" });
  bar.form.style.maxWidth = "none";
  bar.form.querySelector(".hero-input").style.height = "44px";
  const btn = bar.form.querySelector("button"); btn.classList.remove("lg"); btn.style.height = "44px";
  const out = el("div");
  page.append(el("div", { class: "card no-print", style: "padding:14px 16px" }, bar.form), out);
  runInto(out, `Building a hardening plan for ${d}…`, () => api(`/api/harden/${encodeURIComponent(d)}`), (plan) => {
    recentAdd(plan.domain, "harden");
    const view = renderHardenPlan(plan);
    hardenAttachCompare(view, plan);
    return view;
  }, { steps: ["Email authentication", "Mail transport", "Registration & DNS", "Website", "Exposure"], quiet: true });
}

function hardenLanding(page) {
  const s = heroSearch("harden", { placeholder: "Client domain, e.g. contoso.com", button: "Build plan", icon: "harden" });
  page.append(el("section", { class: "hero" },
    el("div", { class: "hero-eyebrow" }, icon("harden"), "Hardening plan"),
    el("h1", {}, "Lock down a client's domain, fix by fix"),
    el("p", {}, "Enter a client's domain for a prioritised checklist of public-facing controls (SPF, DKIM, DMARC, MTA-STS, DNSSEC, CAA, registrar lock, HTTPS, dangling records, exposed remote access), each with the exact record or command to fix it. Microsoft 365 tenant settings are listed as manual checks with read-only PowerShell."),
    s.form,
    el("div", { class: "hero-note" }, icon("lock"), "Public DNS, registry and website data only, so you can run it before you have admin access, and again afterwards to prove the fixes landed.")));
  setTimeout(() => s.input.focus(), 0);
  const grid = (ids) => el("div", { class: "tool-grid" }, ids.map(toolById).filter(Boolean).map((t) => toolCard(t)));
  page.append(el("div", { class: "section-title" }, "Fix-it builders"), grid(["spfbuild", "dmarcbuild", "mtasts", "parked"]),
    el("div", { class: "section-title" }, "Monitor"), grid(["dmarcreport"]),
    el("div", { class: "section-title" }, "Verify (authorized targets only)"),
    el("p", { class: "hint", style: "margin:-4px 0 12px" }, "These actively probe a server. Use them on your clients' systems with their permission, never on prospects."),
    grid(["tls", "ports"]));
  const recent = recentList("harden").slice(0, 6);
  if (recent.length) page.append(el("div", { class: "section-title" }, "Recent plans"), el("div", { class: "recent-list" }, recent.map((r) =>
    el("a", { class: "recent", href: `#harden?${new URLSearchParams({ d: r.d })}` }, el("span", { class: "tool-card-icon" }, icon("history")),
      el("div", { class: "recent-main" }, el("div", { class: "recent-title" }, r.d), el("div", { class: "recent-sub" }, fmtAgo(r.at))), icon("chev-right")))));
}

function hardenRecords(records) {
  if (!records || !records.length) return null;
  return el("div", { class: "table-wrap" }, el("table", { class: "rec-table" },
    el("thead", {}, el("tr", {}, el("th", {}, "Type"), el("th", {}, "Name"), el("th", {}, "Value"), el("th", {}, ""))),
    el("tbody", {}, records.map((r) => {
      const btn = el("button", { class: "icon-btn copy", type: "button", title: "Copy value" }, icon("copy"));
      btn.addEventListener("click", () => copyText(r.value, btn));
      return el("tr", {}, el("td", {}, r.type), el("td", { class: "mono" }, r.name), el("td", { class: "mono" }, r.value), el("td", {}, btn));
    }))));
}

function hardenControl(c, domain) {
  const st = HARDEN_STATUS[c.status] || HARDEN_STATUS.unknown;
  const fx = c.fix || null;
  const hasFix = fx && (fx.summary || (fx.records || []).length || (fx.commands || []).length || (fx.steps || []).length);
  const panel = hasFix ? el("div", { class: "control-fix", hidden: true },
    fx.summary ? el("div", { style: "font-weight:650" }, fx.summary) : null,
    hardenRecords(fx.records),
    (fx.commands || []).map((cmd) => code(cmd)),
    (fx.steps || []).length ? el("ol", {}, fx.steps.map((s) => el("li", {}, s))) : null,
    fx.tool && toolById(fx.tool) ? el("div", { class: "btn-row" }, el("a", { class: "btn sm", href: `#${fx.tool}${fx.params ? "?" + new URLSearchParams(fx.params) : ""}` },
      fx.tool_label || `Open ${toolById(fx.tool).title}`, icon("arrow"))) : null) : null;
  let action = null;
  if (panel) {
    action = el("button", { class: c.status === "pass" ? "btn ghost sm" : "btn secondary sm", type: "button", "aria-expanded": "false" }, c.status === "pass" ? "Details" : "How to fix");
    action.addEventListener("click", () => {
      panel.hidden = !panel.hidden;
      action.setAttribute("aria-expanded", String(!panel.hidden));
      action.textContent = panel.hidden ? (c.status === "pass" ? "Details" : "How to fix") : "Hide";
    });
  } else if (fx && fx.tool && toolById(fx.tool)) {
    action = el("a", { class: "btn ghost sm", href: `#${fx.tool}${fx.params ? "?" + new URLSearchParams(fx.params) : `?d=${encodeURIComponent(domain)}`}` }, fx.tool_label || "Check", icon("arrow"));
  }
  // An optional control that isn't set up is a suggestion, not a failure: show it amber.
  const look = c.optional && c.status === "fail" ? "warn" : c.status;
  return el("div", { class: "control", "data-status": look, "data-id": c.id },
    el("span", { class: "control-status", title: st.label }, icon(HARDEN_STATUS[look].icon)),
    el("div", { style: "min-width:0" },
      el("div", { class: "control-title" }, c.title,
        c.status === "fail" && c.severity === "critical" ? badge("critical", "Critical") : null,
        c.priority === 1 && c.status !== "pass" && c.severity !== "critical" ? badge("warning", "Do first") : null,
        c.optional ? el("span", { class: "badge sev-muted" }, "Optional") : null,
        ["manual", "unknown", "na"].includes(c.status) ? el("span", { class: "badge sev-muted" }, st.label) : null),
      c.found ? el("div", { class: "control-found" }, c.found) : null,
      c.why && c.status !== "pass" ? el("div", { class: "control-why" }, c.why) : null,
      panel),
    action || el("span"));
}

function renderHardenPlan(plan, opts = {}) {
  const frag = el("div");
  const sm = plan.summary || {};
  const grade = hardenGrade(sm.score);
  const controls = plan.controls || [];
  const saveBtn = el("button", { class: "btn secondary", type: "button" }, icon("save"), opts.saved ? "Saved" : "Save");
  if (opts.saved || !plan.result_id) saveBtn.disabled = true;
  if (!opts.saved && !plan.result_id) saveBtn.hidden = true;
  saveBtn.addEventListener("click", async () => {
    saveBtn.disabled = true;
    try {
      const res = await api("/api/assessments", { body: { result_id: plan.result_id } });
      saveBtn.replaceChildren(icon("check"), "Saved");
      toast("Plan saved");
      if (res && res.id) history.replaceState({ mspg: true }, "", `#assessments?id=${res.id}`);
    } catch (e) { saveBtn.disabled = false; toast(e.message); }
  });
  const copyBtn = el("button", { class: "btn secondary", type: "button", onclick: () => copyText(hardenChecklist(plan), copyBtn) }, icon("copy"), "Copy checklist");
  frag.append(el("div", { class: "report-head" }, scoreRing(sm.score ?? 0, grade, 104, `grade-${grade}`),
    el("div", { class: "report-id" },
      el("div", { class: "report-kicker" }, opts.saved ? "Saved hardening plan" : "Hardening plan"),
      el("div", { class: "report-title" }, plan.domain),
      el("div", { class: "report-org" }, [plan.mail_platform ? `Mail: ${plan.mail_platform}` : null, plan.sends_mail === false ? "Doesn't send mail (parked)" : null].filter(Boolean).join(" · ") || ""),
      el("div", { class: "report-meta" }, el("span", {}, `Checked ${new Date(plan.generated).toLocaleString()}`),
        opts.saved && opts.saved.created_by ? el("span", {}, `Saved by ${opts.saved.created_by}`) : null, el("span", {}, "Public data only"))),
    el("div", { class: "report-actions" }, saveBtn, copyBtn,
      el("button", { class: "btn secondary", type: "button", title: "Print the plan with every fix expanded", onclick: () => window.print() }, icon("print")))));
  if (opts.compare) frag.append(opts.compare);
  frag.append(verdict(plan.severity || "info", plan.headline || `${plan.domain}: hardening plan`, plan.subline));

  const counts = [["fail", "To fix", "critical"], ["warn", "Improve", "warning"], ["pass", "Passing", "ok"], ["manual", "Check manually", "info"], ["unknown", "Couldn't check", "muted"], ["na", "N/A", "muted"]];
  const filters = [["todo", "To do"], ["all", "All"], ["pass", "Passing"], ["manual", "Manual checks"]];
  const tabs = el("div", { class: "tabs no-print", role: "tablist" });
  const body = el("div");
  const show = (f) => {
    tabs.querySelectorAll("button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.f === f)));
    const pick = (c) => f === "all" || (f === "todo" ? ["fail", "warn"].includes(c.status) : f === "pass" ? c.status === "pass" : ["manual", "unknown"].includes(c.status));
    const areas = (plan.areas || []).map((a) => ({ ...a, items: controls.filter((c) => c.area === a.id && pick(c)) })).filter((a) => a.items.length);
    const orphans = controls.filter((c) => !(plan.areas || []).some((a) => a.id === c.area) && pick(c));
    if (orphans.length) areas.push({ id: "other", title: "Other", items: orphans });
    const prio = (c) => ({ fail: 0, warn: 1, manual: 2, unknown: 3, pass: 4, na: 5 }[c.status] ?? 6) * 10 + (c.priority || 3);
    body.replaceChildren(...(areas.length ? areas.map((a) => card(a.title, [
      a.desc ? el("div", { class: "card-body hint", style: "padding:10px 18px;border-bottom:1px solid var(--border)" }, a.desc) : null,
      el("div", {}, a.items.sort((x, y) => prio(x) - prio(y)).map((c) => hardenControl(c, plan.domain))),
    ], { flush: true, icon: HARDEN_AREA_ICON[a.id] || "harden", extra: hardenAreaCount(controls, a.id) }))
      : [el("div", { class: "empty" }, icon("check"), f === "todo" ? "Nothing left to fix in public records. Run the manual checks next." : "Nothing in this view.")]));
  };
  filters.forEach(([f, label]) => {
    const n = f === "all" ? controls.length : controls.filter((c) => (f === "todo" ? ["fail", "warn"].includes(c.status) : f === "pass" ? c.status === "pass" : ["manual", "unknown"].includes(c.status))).length;
    tabs.append(el("button", { type: "button", role: "tab", "data-f": f, onclick: () => show(f) }, `${label} (${n})`));
  });
  frag.append(el("div", { class: "facts" }, counts.filter(([k]) => sm[k]).map(([k, label, sev]) =>
    el("div", { class: "fact" }, el("span", { class: "fact-k" }, label), el("span", { class: "fact-v", style: `color:var(--${{ critical: "crit", warning: "warn", ok: "ok", info: "info", muted: "muted" }[sev]})` }, String(sm[k]))))));
  frag.append(tabs, body);
  show(controls.some((c) => ["fail", "warn"].includes(c.status)) ? "todo" : "all");
  return frag;
}

/** "3 of 5 passing" for an area, counting every applicable control (not just the filtered view). */
function hardenAreaCount(controls, area) {
  const all = controls.filter((c) => c.area === area && !["na", "manual", "unknown"].includes(c.status));
  if (!all.length) return el("span", { class: "hint" }, "Manual checks");
  return el("span", { class: "hint" }, `${all.filter((c) => c.status === "pass").length} of ${all.length} passing`);
}

function hardenCompare(cur, prev) {
  const c = cur.data, p = prev.data;
  const prevById = new Map((p.controls || []).map((x) => [x.id, x]));
  const fixed = (c.controls || []).filter((x) => x.status === "pass" && prevById.get(x.id) && ["fail", "warn"].includes(prevById.get(x.id).status));
  const broke = (c.controls || []).filter((x) => ["fail", "warn"].includes(x.status) && prevById.get(x.id) && prevById.get(x.id).status === "pass");
  const delta = ((c.summary || {}).score ?? 0) - ((p.summary || {}).score ?? 0);
  return el("div", { class: "compare" }, icon("compare"),
    el("span", {}, "Since ", el("b", {}, new Date(prev.created).toLocaleDateString()), ": score ",
      el("b", {}, `${(p.summary || {}).score ?? "?"} → ${(c.summary || {}).score ?? "?"}`), " (",
      el("span", { class: delta >= 0 ? "delta-up" : "delta-down" }, `${delta >= 0 ? "+" : ""}${delta}`), ")"),
    fixed.length ? el("span", {}, el("span", { class: "delta-up" }, `${fixed.length} fixed`), `: ${fixed.map((x) => x.title).slice(0, 3).join("; ")}`) : null,
    broke.length ? el("span", {}, el("span", { class: "delta-down" }, `${broke.length} regressed`), `: ${broke.map((x) => x.title).slice(0, 3).join("; ")}`) : null,
    !fixed.length && !broke.length ? el("span", { class: "muted" }, "No control changed status.") : null,
    prev.id ? el("a", { href: `#assessments?id=${prev.id}`, style: "margin-left:auto" }, "Open earlier plan") : null);
}

async function hardenAttachCompare(view, plan) {
  try {
    const hist = await api(`/api/assessments?kind=hardening&domain=${encodeURIComponent(plan.domain)}&limit=1`);
    if (!hist.items.length) return;
    const prev = await api(`/api/assessments/${hist.items[0].id}`);
    const head = view.querySelector(".report-head");
    if (head) head.after(hardenCompare({ data: plan, created: plan.generated }, prev));
  } catch (e) { /* optional */ }
}

/** Plain-text checklist for a ticket or change request. */
function hardenChecklist(plan) {
  const L = [`HARDENING PLAN: ${plan.domain}  ·  ${new Date(plan.generated).toLocaleString()}`, plan.headline || "", ""];
  const areas = new Map((plan.areas || []).map((a) => [a.id, a.title]));
  const order = (plan.controls || []).filter((c) => !["na"].includes(c.status));
  const section = (title, filter) => {
    const items = order.filter(filter);
    if (!items.length) return;
    L.push(title);
    items.forEach((c) => {
      L.push(`[${c.status === "pass" ? "x" : " "}] ${areas.get(c.area) ? areas.get(c.area) + ": " : ""}${c.title}${c.found ? ` (${c.found})` : ""}`);
      if (c.status !== "pass" && c.fix) {
        if (c.fix.summary) L.push(`      Fix: ${c.fix.summary}`);
        (c.fix.records || []).forEach((r) => L.push(`      ${r.type} ${r.name} = ${r.value}`));
        (c.fix.commands || []).forEach((cmd) => L.push(`      > ${cmd}`));
      }
    });
    L.push("");
  };
  section("TO FIX", (c) => c.status === "fail");
  section("IMPROVE", (c) => c.status === "warn");
  section("CHECK MANUALLY", (c) => ["manual", "unknown"].includes(c.status));
  section("PASSING", (c) => c.status === "pass");
  return L.join("\n");
}

registerTool({ id: "harden", title: "Hardening Plan", landing: true, render: renderHardenTool,
  icon: "M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6zM9 12l2 2 4-4",
  keywords: "harden hardening secure checklist baseline onboarding remediation fix plan dmarc spf dkim mta-sts dnssec caa security txt hsts",
  desc: "A prioritised checklist of a client's public-facing controls with the exact record or command to fix each one, plus manual Microsoft 365 checks." });
