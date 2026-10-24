"use strict";
/* Sign-in flow: setup → password → (forced password change) → MFA / MFA enrolment → app.
   The server decides the next stage; this page just renders it. */

const root = document.getElementById("login-root");

function h(tag, attrs, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

let csrf = null;
async function call(path, body) {
  const headers = { "content-type": "application/json" };
  if (csrf) headers["x-csrf-token"] = csrf;
  const res = await fetch(path, { method: body === undefined ? "GET" : "POST", headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty */ }
  if (!res.ok) throw Object.assign(new Error(data.detail || `Error ${res.status}`), { status: res.status });
  return data;
}

function field(label, attrs) {
  const input = h("input", { class: "login-input", ...attrs });
  return { input, el: h("label", { class: "login-field" }, h("span", {}, label), input) };
}

function errorBox() { return h("div", { class: "error-box", hidden: true, role: "alert" }); }
function showError(box, msg) { box.textContent = msg; box.hidden = false; }

function form(title, intro, fields, button, onSubmit, extra) {
  const err = errorBox();
  const btn = h("button", { class: "btn login-btn", type: "submit" }, button);
  const f = h("form", { class: "login-form", novalidate: true }, h("h1", {}, title), intro ? h("p", { class: "hint" }, intro) : null,
    err, fields.map((x) => x.el), extra || null, btn);
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.hidden = true;
    btn.disabled = true;
    try { await onSubmit(); } catch (ex) { showError(err, ex.message); } finally { btn.disabled = false; }
  });
  root.replaceChildren(f);
  const first = fields.find((x) => !x.input.value);
  (first || fields[0]).input.focus();
}

async function refreshCsrf() {
  try { csrf = (await call("/api/auth/me")).csrf; } catch (e) { csrf = null; }
}

async function next(stage) {
  await refreshCsrf();
  if (stage === "full") { location.replace("/"); return; }
  if (stage === "password_change") return passwordChange();
  if (stage === "mfa") return mfaPrompt();
  if (stage === "mfa_enroll") return mfaEnroll();
  return signIn();
}

function signIn(message) {
  const u = field("Username", { name: "username", autocomplete: "username", required: true, maxlength: 64 });
  const p = field("Password", { name: "password", type: "password", autocomplete: "current-password", required: true, maxlength: 256 });
  form("Sign in", message || null, [u, p], "Sign in", async () => {
    const r = await call("/api/auth/login", { username: u.input.value.trim(), password: p.input.value });
    p.input.value = "";
    await next(r.stage);
  });
}

function setup() {
  const t = field("Setup token", { autocomplete: "off", required: true, spellcheck: "false" });
  const u = field("Admin username", { autocomplete: "username", required: true, maxlength: 64, value: "admin" });
  const p = field("Password (12+ characters)", { type: "password", autocomplete: "new-password", required: true, maxlength: 256 });
  const c = field("Confirm password", { type: "password", autocomplete: "new-password", required: true, maxlength: 256 });
  form("First-time setup", "Create the administrator account. The setup token is printed in the container log: run  docker logs mspgather", [t, u, p, c], "Create admin account", async () => {
    if (p.input.value !== c.input.value) throw new Error("Passwords don't match.");
    await call("/api/auth/setup", { token: t.input.value.trim(), username: u.input.value.trim(), password: p.input.value });
    signIn("Admin account created. Sign in to continue; you'll set up MFA next.");
  });
}

function passwordChange() {
  const p = field("New password (12+ characters)", { type: "password", autocomplete: "new-password", required: true, maxlength: 256 });
  const c = field("Confirm new password", { type: "password", autocomplete: "new-password", required: true, maxlength: 256 });
  form("Choose a new password", "Your password was set by an administrator. Choose your own before continuing. A passphrase of a few random words works well.", [p, c], "Save password", async () => {
    if (p.input.value !== c.input.value) throw new Error("Passwords don't match.");
    const r = await call("/api/auth/password", { new: p.input.value });
    await next(r.stage);
  });
}

function mfaPrompt() {
  const code = field("Code from your authenticator app", { inputmode: "numeric", autocomplete: "one-time-code", required: true, maxlength: 32, spellcheck: "false" });
  form("Two-step verification", "Enter the 6-digit code from your authenticator app. Lost your phone? Enter one of your recovery codes instead.", [code], "Verify", async () => {
    const r = await call("/api/auth/mfa", { code: code.input.value.trim() });
    await next(r.stage);
  }, h("button", { class: "linklike", type: "button", onclick: signOut }, "Cancel and sign out"));
}

async function mfaEnroll() {
  const data = await call("/api/auth/mfa/enroll/start", {});
  const code = field("6-digit code from the app", { inputmode: "numeric", autocomplete: "one-time-code", required: true, maxlength: 10 });
  const qr = data.qr_svg ? h("img", { class: "login-qr", alt: "QR code for your authenticator app",
    src: "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(data.qr_svg))) }) : null;
  const secret = h("code", { class: "login-secret" }, data.secret.replace(/(.{4})/g, "$1 ").trim());
  form("Set up two-step verification", "This server requires an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden…). Scan the QR code, or type the setup key, then enter the code it shows.",
    [code], "Turn on and continue", async () => {
      const r = await call("/api/auth/mfa/enroll/finish", { code: code.input.value.trim() });
      showRecovery(r.recovery_codes);
    });
  // Scan first, then type: put the QR code above the code box.
  const f = root.querySelector("form");
  f.insertBefore(h("div", { class: "login-enroll" }, qr, h("div", {}, h("div", { class: "hint" }, "Setup key:"), secret)), code.el);
}

function showRecovery(codes) {
  const list = h("pre", { class: "login-codes" }, codes.join("\n"));
  const copy = h("button", { class: "btn secondary", type: "button", onclick: async () => {
    try { await navigator.clipboard.writeText(codes.join("\n")); copy.textContent = "Copied"; } catch (e) { copy.textContent = "Select and copy manually"; }
  } }, "Copy codes");
  const cont = h("button", { class: "btn login-btn", type: "button", disabled: true, onclick: () => location.replace("/") }, "Continue to MSPGather");
  const ack = h("input", { type: "checkbox", id: "ack", onchange: () => { cont.disabled = !ack.checked; } });
  root.replaceChildren(h("div", { class: "login-form" },
    h("h1", {}, "Save your recovery codes"),
    h("p", { class: "hint" }, "Each code works once if you lose your phone. Store them in your password manager. They won't be shown again."),
    list, copy, h("label", { class: "check", style: "margin-top:12px" }, ack, "I've saved these codes"), cont));
}

async function signOut() {
  try { await call("/api/auth/logout", {}); } catch (e) { /* ignore */ }
  csrf = null;
  signIn();
}

(async () => {
  try {
    const st = await call("/api/auth/status");
    if (!st.auth_enabled) { location.replace("/"); return; }
    if (st.setup_required) { setup(); return; }
    await next(st.stage);
  } catch (e) {
    root.replaceChildren(h("div", { class: "error-box" }, `Can't reach the server: ${e.message}`));
  }
})();
