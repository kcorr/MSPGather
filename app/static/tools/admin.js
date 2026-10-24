"use strict";
/* Administration: My account (everyone), Users and Audit log (admins).
   Only shown when built-in authentication is on. */

addStyles(`
.adm-actions { display: flex; flex-wrap: wrap; gap: 6px; }
.adm-actions .btn { padding: 5px 10px; font-size: 12.5px; }
.adm-secret { font-family: var(--mono); font-size: 15px; padding: 10px 14px; background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; display: inline-block; margin: 6px 0; user-select: all; }
.adm-qr { width: 200px; height: 200px; background: #fff; padding: 8px; border-radius: 8px; }
.adm-enroll { display: flex; gap: 18px; flex-wrap: wrap; align-items: center; }
.adm-form { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; }
.adm-form .field input, .adm-form .field select { min-width: 200px; }
`);

const admTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "never");

function admPasswordField(label, autocomplete) {
  const input = el("input", { type: "password", autocomplete, maxlength: 256 });
  return { input, field: el("div", { class: "field" }, el("label", {}, label), input) };
}

function admMsg(target, sev, text) {
  target.replaceChildren(el("div", { class: sev === "ok" ? "notice" : "error-box", style: "margin:10px 0 0" }, text));
}

/* ================================================================ MY ACCOUNT */
function renderAccountTool(main) {
  const out = el("div");
  main.append(out);
  const load = async () => {
    let me, sessions;
    try {
      [me, { sessions }] = await Promise.all([api("/api/auth/me"), api("/api/auth/sessions")]);
    } catch (e) { out.replaceChildren(el("div", { class: "error-box" }, e.message)); return; }
    out.replaceChildren(
      verdict(me.mfa_enabled ? "ok" : "warning", me.mfa_enabled ? `Signed in as ${me.username}: two-step verification is on` : `Signed in as ${me.username}: two-step verification is OFF`,
        `${me.role === "admin" ? "Administrator" : "User"} · last sign-in ${admTime(me.last_login)}${me.mfa_enabled ? ` · ${me.recovery_codes_left} recovery codes left` : ""}`),
      accountPassword(), accountMfa(me, load), accountSessions(sessions, load));
  };
  load();
}

function accountPassword() {
  const cur = admPasswordField("Current password", "current-password");
  const nw = admPasswordField("New password (12+ characters)", "new-password");
  const cf = admPasswordField("Confirm new password", "new-password");
  const msg = el("div");
  const btn = el("button", { class: "btn", type: "button", onclick: async () => {
    if (nw.input.value !== cf.input.value) { admMsg(msg, "err", "New passwords don't match."); return; }
    btn.disabled = true;
    try {
      await api("/api/auth/password", { body: { current: cur.input.value, new: nw.input.value } });
      [cur, nw, cf].forEach((x) => (x.input.value = ""));
      admMsg(msg, "ok", "Password changed. Your other sessions were signed out.");
    } catch (e) { admMsg(msg, "err", e.message); } finally { btn.disabled = false; }
  } }, "Change password");
  return card("Password", [el("div", { class: "adm-form" }, cur.field, nw.field, cf.field, btn), msg]);
}

function accountMfa(me, reload) {
  const msg = el("div");
  const body = el("div");
  if (!me.mfa_enabled) {
    const start = el("button", { class: "btn", type: "button", onclick: async () => {
      try {
        const d = await api("/api/auth/mfa/enroll/start", { body: {} });
        const code = el("input", { type: "text", inputmode: "numeric", maxlength: 10, autocomplete: "one-time-code" });
        const qr = d.qr_svg ? el("img", { class: "adm-qr", alt: "QR code", src: "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(d.qr_svg))) }) : null;
        body.replaceChildren(el("div", { class: "adm-enroll" }, qr, el("div", {},
          el("div", { class: "hint" }, "Scan with your authenticator app, or enter this setup key:"), el("div", { class: "adm-secret" }, d.secret),
          el("div", { class: "adm-form", style: "margin-top:8px" }, el("div", { class: "field" }, el("label", {}, "Code from the app"), code),
            el("button", { class: "btn", type: "button", onclick: async () => {
              try {
                const r = await api("/api/auth/mfa/enroll/finish", { body: { code: code.value.trim() } });
                showCodes(body, r.recovery_codes, reload);
              } catch (e) { admMsg(msg, "err", e.message); }
            } }, "Turn on")))));
      } catch (e) { admMsg(msg, "err", e.message); }
    } }, "Set up two-step verification");
    body.append(el("p", { class: "hint" }, "Protect your account with an authenticator app."), start);
  } else {
    const pw = admPasswordField("Your password", "current-password");
    const regen = el("button", { class: "btn secondary", type: "button", onclick: async () => {
      try { const r = await api("/api/auth/recovery-codes", { body: { password: pw.input.value } }); pw.input.value = ""; showCodes(body, r.recovery_codes, reload); }
      catch (e) { admMsg(msg, "err", e.message); }
    } }, "New recovery codes");
    const disable = me.require_mfa ? null : el("button", { class: "btn secondary", type: "button", onclick: async () => {
      if (!confirm("Turn off two-step verification for your account?")) return;
      try { await api("/api/auth/mfa/disable", { body: { password: pw.input.value } }); reload(); } catch (e) { admMsg(msg, "err", e.message); }
    } }, "Turn off");
    body.append(el("p", { class: "hint" }, me.require_mfa ? "Required by this server." : "Optional on this server.",
      ` ${me.recovery_codes_left} unused recovery codes.`), el("div", { class: "adm-form" }, pw.field, regen, disable));
  }
  return card("Two-step verification", [body, msg]);
}

function showCodes(target, codes, reload) {
  target.replaceChildren(el("p", {}, el("strong", {}, "Save these recovery codes now; they won't be shown again.")),
    code(codes.join("\n")), el("button", { class: "btn", type: "button", onclick: reload }, "Done"));
}

function accountSessions(sessions, reload) {
  const others = sessions.filter((s) => !s.current).length;
  return card(`Signed-in sessions (${sessions.length})`, [
    table(["Device", "IP", "Signed in", "Last active", ""], sessions.map((s) => [
      el("span", { class: "sub" }, (s.user_agent || "unknown").slice(0, 90)), s.ip || "—", admTime(s.created), admTime(s.last_seen),
      s.current ? badge("ok", "this session") : ""])),
    others ? el("div", { class: "card-body" }, el("button", { class: "btn secondary", type: "button", onclick: async () => {
      await api("/api/auth/sessions/revoke-others", { body: {} }); reload();
    } }, `Sign out ${others} other session${others > 1 ? "s" : ""}`)) : null,
  ], { flush: true });
}

/* ===================================================================== USERS */
function renderUsersTool(main) {
  const out = el("div");
  const created = el("div");
  const name = el("input", { type: "text", maxlength: 64, autocomplete: "off", spellcheck: "false", placeholder: "jsmith or jsmith@contoso.com" });
  const role = el("select", {}, el("option", { value: "user" }, "User"), el("option", { value: "admin" }, "Administrator"));
  const add = el("button", { class: "btn", type: "button", onclick: async () => {
    try {
      const r = await api("/api/admin/users", { body: { username: name.value.trim(), role: role.value } });
      name.value = "";
      showTemp(created, r.username, r.temporary_password, "created");
      load();
    } catch (e) { admMsg(created, "err", e.message); }
  } }, "Add user");
  main.append(card("Add a user", [el("div", { class: "adm-form" }, el("div", { class: "field" }, el("label", {}, "Username"), name),
    el("div", { class: "field" }, el("label", {}, "Role"), role), add),
    el("div", { class: "hint", style: "margin-top:8px" }, "A one-time temporary password is generated. The user must change it and set up two-step verification at first sign-in."),
    created]), out);

  const act = async (u, changes, label) => {
    try {
      const r = await api(`/api/admin/users/${u.id}`, { method: "PATCH", body: changes });
      if (r.temporary_password) showTemp(created, u.username, r.temporary_password, "reset");
      else admMsg(created, "ok", `${u.username}: ${label}.`);
      load();
    } catch (e) { admMsg(created, "err", e.message); }
  };
  const load = async () => {
    let users;
    try { ({ users } = await api("/api/admin/users")); } catch (e) { out.replaceChildren(el("div", { class: "error-box" }, e.message)); return; }
    const noMfa = users.filter((u) => !u.totp_enabled && !u.disabled);
    out.replaceChildren(
      verdict(noMfa.length ? "warning" : "ok", noMfa.length ? `${noMfa.length} active user${noMfa.length > 1 ? "s haven't" : " hasn't"} set up two-step verification yet` : `${users.length} user${users.length > 1 ? "s" : ""}, all with two-step verification`,
        noMfa.length ? noMfa.map((u) => u.username).join(", ") : null),
      card(`Users (${users.length})`, table(["User", "Role", "Status", "MFA", "Last sign-in", "Actions"], users.map((u) => {
        const status = u.disabled ? badge("muted", "disabled") : u.locked ? badge("critical", "locked") : u.must_change_password ? badge("info", "must change password") : badge("ok", "active");
        const b = (label, changes, done, confirmText) => el("button", { class: "btn secondary", type: "button", onclick: () => {
          if (confirmText && !confirm(confirmText)) return;
          act(u, changes, done);
        } }, label);
        return [el("strong", {}, u.username, u.id === undefined ? "" : ""), u.role === "admin" ? badge("info", "admin") : "user", status,
          u.totp_enabled ? badge("ok", "on") : badge("warning", "off"), admTime(u.last_login),
          el("div", { class: "adm-actions" },
            u.locked ? b("Unlock", { unlock: true }, "unlocked") : null,
            b(u.role === "admin" ? "Make user" : "Make admin", { role: u.role === "admin" ? "user" : "admin" }, "role changed"),
            b(u.disabled ? "Enable" : "Disable", { disabled: !u.disabled }, u.disabled ? "enabled" : "disabled"),
            b("Reset password", { reset_password: true }, "password reset", `Reset ${u.username}'s password? They'll be signed out and get a temporary password.`),
            u.totp_enabled ? b("Reset MFA", { reset_mfa: true }, "MFA reset", `Reset two-step verification for ${u.username}? They'll set it up again at next sign-in.`) : null,
            u.sessions ? b("Sign out", { sign_out: true }, "signed out") : null,
            el("button", { class: "btn secondary", type: "button", onclick: async () => {
              if (!confirm(`Delete ${u.username}? This can't be undone.`)) return;
              try { await api(`/api/admin/users/${u.id}`, { method: "DELETE" }); admMsg(created, "ok", `${u.username} deleted.`); load(); }
              catch (e) { admMsg(created, "err", e.message); }
            } }, "Delete"))];
      })), { flush: true }));
  };
  load();
}

function showTemp(target, username, temp, what) {
  target.replaceChildren(el("div", { class: "notice", style: "margin-top:10px" },
    el("div", {}, el("strong", {}, `${username} ${what}. `), "Give them this temporary password over a secure channel. It's shown only once:"),
    el("div", { class: "adm-secret" }, temp)));
}

/* ================================================================= AUDIT LOG */
function renderAuditTool(main, params) {
  const q = el("input", { type: "text", placeholder: "Filter by user, event, IP or detail…", value: params.get("q") || "", class: "filter", style: "margin:0;width:100%" });
  const out = el("div");
  let timer = null;
  const load = async () => {
    try {
      const { events } = await api(`/api/admin/audit?limit=300&q=${encodeURIComponent(q.value.trim())}`);
      const fails = events.filter((e) => /failed|locked|blocked/.test(e.event)).length;
      out.replaceChildren(
        verdict(fails ? "warning" : "info", `${events.length} recent events${q.value ? ` matching “${q.value}”` : ""}`, fails ? `${fails} failed or blocked sign-in events in this list` : null),
        card(null, table(["Time", "User", "Event", "IP", "Detail"], events.map((e) => [admTime(e.ts), e.username || "—",
          /failed|locked|blocked/.test(e.event) ? badge("warning", e.event) : e.event, e.ip || "—", el("span", { class: "sub mono" }, e.detail || "")]),
          (i) => (/failed|locked|blocked/.test(events[i].event) ? "hl" : null)), { flush: true }));
    } catch (e) { out.replaceChildren(el("div", { class: "error-box" }, e.message)); }
  };
  q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 300); });
  main.append(card(null, q), out);
  load();
}

registerTool({ category: "admin", group: "Account", id: "account", title: "My account", render: renderAccountTool, authOnly: true,
  icon: "M12 12a4 4 0 100-8 4 4 0 000 8zM4 21c0-4 3.6-6 8-6s8 2 8 6", keywords: "password mfa two-step authenticator sessions sign out recovery",
  desc: "Change your password, manage two-step verification and recovery codes, and see where you're signed in." });
registerTool({ category: "admin", group: "Team", id: "users", title: "Users", render: renderUsersTool, authOnly: true, adminOnly: true,
  icon: "M9 11a4 4 0 100-8 4 4 0 000 8zM2 21c0-3.5 3-5.5 7-5.5s7 2 7 5.5M17 11a3 3 0 100-6M22 20c0-2.5-1.8-4-4.5-4.6", keywords: "add user admin reset password unlock mfa disable",
  desc: "Add users, reset passwords and two-step verification, unlock, disable or remove accounts." });
registerTool({ category: "admin", group: "Team", id: "audit", title: "Audit log", render: renderAuditTool, authOnly: true, adminOnly: true,
  icon: "M5 4h14v16H5zM8 8h8M8 12h8M8 16h5", keywords: "audit log sign-in history who ran failed logins",
  desc: "Sign-ins, failed attempts, lockouts, account changes and which tools each user ran." });
