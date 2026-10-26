"use strict";
/* Saved reports: reopen, compare and delete saved prospect briefings and hardening plans. */

function renderAssessmentsTool(page, params) {
  const id = params.get("id");
  if (id) return asmView(page, id);
  page.append(pageHead(toolById("assessments")));
  const filter = el("input", { type: "search", placeholder: "Filter by domain or organisation", "aria-label": "Filter saved reports", style: "width:100%" });
  const out = el("div");
  page.append(el("div", { style: "display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap" },
    el("div", { style: "flex:1 1 320px" }, filter),
    el("a", { class: "btn secondary", href: "#discover" }, icon("discover"), "New prospect"),
    el("a", { class: "btn secondary", href: "#harden" }, icon("harden"), "New hardening plan")), out);
  runInto(out, "Loading saved reports…", () => api("/api/assessments?limit=500"), (d) => asmList(d, filter), { quiet: true });
}

const asmKindLabel = (k) => (k === "discovery" ? "Prospect briefing" : "Hardening plan");

function asmList(d, filter) {
  if (!d.available) return el("div", { class: "notice warn" }, "Saving is turned off because the server has no writable data directory. Mount a volume at /data to keep reports.");
  if (!d.items.length) return el("div", { class: "empty" }, icon("save"), "No saved reports yet. Run ", link("discover", {}, "Prospect Discovery"),
    " or a ", link("harden", {}, "Hardening Plan"), " and press Save to keep it for your team and compare it later.");
  // One row per domain and report type (latest save), with the number of earlier saves.
  const groups = new Map();
  d.items.forEach((a) => { const k = `${a.kind}|${a.domain}`; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(a); });
  const rows = [...groups.values()];
  const wrap = el("div");
  const draw = () => {
    const q = filter.value.trim().toLowerCase();
    const shown = rows.filter((g) => !q || g[0].domain.includes(q) || (g[0].org || "").toLowerCase().includes(q));
    wrap.replaceChildren(card(`${shown.length} saved ${shown.length === 1 ? "report" : "reports"}`, shown.length ? table(["Domain", "Report", "Grade", "Last saved", "Summary", "History", ""],
      shown.map((g) => {
        const a = g[0];
        const del = el("button", { class: "btn ghost sm", type: "button", title: "Delete the latest save", "aria-label": `Delete saved report for ${a.domain}` }, icon("trash"));
        del.addEventListener("click", async () => {
          if (!confirm(`Delete the saved ${asmKindLabel(a.kind).toLowerCase()} for ${a.domain} (saved ${fmtAgo(a.created)})?`)) return;
          try {
            await api(`/api/assessments/${a.id}`, { method: "DELETE" });
            g.shift();
            if (!g.length) rows.splice(rows.indexOf(g), 1);
            toast("Deleted");
            draw();
          } catch (e) { toast(e.message); }
        });
        return [
          el("a", { href: `#assessments?id=${a.id}`, style: "font-weight:650" }, a.domain, a.org ? el("div", { class: "sub" }, a.org) : null),
          asmKindLabel(a.kind),
          scoreRing(a.score || 0, a.grade || "?", 40, `grade-${a.grade}`),
          el("div", {}, fmtAgo(a.created), el("div", { class: "sub" }, a.created_by ? `by ${a.created_by}` : "")),
          a.kind === "discovery" ? `${a.counts.risk || 0} risks · ${a.counts.opportunity || 0} opportunities` : `${a.counts.fail || 0} to fix · ${a.counts.pass || 0} passing`,
          g.length > 1 ? `${g.length} saves` : "—",
          del,
        ];
      })) : el("div", { class: "card-body hint" }, "Nothing matches that filter."), { flush: true, icon: "save" }));
  };
  filter.addEventListener("input", draw);
  draw();
  return wrap;
}

function asmView(page, id) {
  const out = el("div");
  page.append(out);
  runInto(out, "Opening saved report…", async () => {
    const a = await api(`/api/assessments/${encodeURIComponent(id)}`);
    let prev = null;
    try {
      const hist = await api(`/api/assessments?kind=${a.kind}&domain=${encodeURIComponent(a.domain)}&limit=50`);
      const older = hist.items.filter((x) => x.id !== a.id && x.created < a.created);
      if (older.length) prev = await api(`/api/assessments/${older[0].id}`);
    } catch (e) { /* comparison is optional */ }
    return { a, prev };
  }, ({ a, prev }) => {
    const back = el("div", { class: "no-print", style: "margin-bottom:12px" }, link("assessments", {}, "← All saved reports"));
    if (a.kind === "discovery") return el("div", {}, back, renderDiscoverResult(a.data, { saved: a, compare: prev ? discCompare(a, prev) : null }));
    if (a.kind === "hardening" && typeof renderHardenPlan === "function") return el("div", {}, back, renderHardenPlan(a.data, { saved: a, compare: prev ? hardenCompare(a, prev) : null }));
    return el("div", { class: "error-box" }, "This report type can't be displayed.");
  }, { quiet: true });
}

registerTool({ id: "assessments", title: "Saved Reports", landing: true, render: renderAssessmentsTool,
  icon: "M6 3h12v18l-6-4-6 4z",
  keywords: "saved prospects history assessments reports compare progress before after pipeline",
  desc: "Prospect briefings and hardening plans your team saved. Reopen them before a meeting, and compare a new run with the last one to show progress." });
