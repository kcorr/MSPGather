"use strict";
/* Report branding: the organisation shown on client snapshots. */

function renderSettingsTool(page) {
  const out = el("div");
  page.append(out);
  runInto(out, "Loading…", () => api("/api/admin/settings"), (s) => {
    const field = (name, label, placeholder, help) => {
      const input = el("input", { type: "text", name, value: s[name] || "", placeholder, maxlength: name === "org_name" ? 120 : 200, style: "width:100%" });
      return { input, node: el("div", { class: "field", style: "margin-bottom:14px" }, el("label", {}, label), input, help ? el("span", { class: "hint" }, help) : null) };
    };
    const name = field("org_name", "Organisation name", "Contoso IT Services", "Shown as \"Prepared by\" on client snapshots.");
    const site = field("org_website", "Website", "https://contoso-it.example");
    const contact = field("org_contact", "Contact", "help@contoso-it.example · +1 555 0100");
    const msg = el("div");
    const save = el("button", { class: "btn", type: "submit" }, "Save branding");
    const form = el("form", {}, name.node, site.node, contact.node, el("div", { class: "btn-row" }, save), msg);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      save.disabled = true;
      try {
        const r = await api("/api/admin/settings", { method: "PUT", body: { org_name: name.input.value, org_website: site.input.value, org_contact: contact.input.value } });
        META.org = { name: r.org_name, website: r.org_website, contact: r.org_contact };
        toast("Branding saved");
      } catch (err) { msg.replaceChildren(el("div", { class: "error-box", style: "margin-top:12px" }, err.message)); }
      finally { save.disabled = false; }
    });
    return el("div", {},
      s.available ? null : el("div", { class: "notice warn" }, "The server has no writable data directory, so changes here can't be saved. Use the MSPGATHER_ORG_NAME, MSPGATHER_ORG_WEBSITE and MSPGATHER_ORG_CONTACT environment variables instead."),
      card("Client snapshot branding", form, { icon: "settings" }));
  }, { quiet: true });
}

registerTool({ id: "settings", title: "Report Branding", adminOnly: true, render: renderSettingsTool, icon: ICONS.settings,
  keywords: "settings branding organisation name logo report snapshot",
  desc: "Your organisation's name, website and contact, shown on the client snapshots you hand to prospects." });
