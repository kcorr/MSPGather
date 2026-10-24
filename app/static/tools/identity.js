"use strict";
/* Identity (Entra ID) tools: Sign-in Error Decoder, Token Decoder (client-side only), Tenant & Federation. */

addStyles(`
.aadsts-samples { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
.aadsts-codes-list { columns: 2 320px; column-gap: 24px; font-size: 13px; }
.aadsts-codes-list div { break-inside: avoid; padding: 2px 0; }
.aadsts-code-head { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.token-claim { white-space: nowrap; }
.token-val { word-break: break-all; }
.token-list { margin: 0; padding-left: 18px; }
.token-opts { margin-top: 10px; }
`);

const AADSTS_SAMPLES = [
  ["identity-aadsts-ca.txt", "Sample: Conditional Access block (JSON)"],
  ["identity-aadsts-spray.txt", "Sample: password spray (30 sign-ins)"],
  ["identity-aadsts-portal.txt", "Sample: portal 'Basic info' text"],
];
// Codes in the backend knowledge base, so the home-page search finds this tool by code.
const AADSTS_KEYWORD_CODES = "16000 50001 50005 50011 50020 50034 50053 50055 50056 50057 50058 50072 50074 50076 50078 50079 50089 50097 50105 50125 50126 50127 50129 50131 50132 50133 50135 50140 50144 50155 50158 50173 50180 50194 50196 50199 51004 53000 53001 53002 53003 53004 53011 530003 530032 500011 500121 65001 65004 70000 70008 70011 70043 700016 700054 700082 7000215 7000218 7000222 75011 81010 81012 90002 90072 90094 90095 9002313"
  .split(" ").map((c) => `AADSTS${c}`).join(" ");

/* ============================================================ SIGN-IN ERROR DECODER */
function renderAadstsTool(main, params) {
  const ta = el("textarea", { spellcheck: "false", placeholder: "Paste any of:\n• an error code: AADSTS50126 or 50126\n• the error message a user saw\n• sign-in log details copied from Entra admin center → Sign-in logs (Basic info / Device info / Conditional Access tabs)\n• exported sign-in JSON (Graph signIns, portal 'Download JSON', or Log Analytics SigninLogs), one or many records" });
  if (params.get("c")) ta.value = params.get("c");
  const out = el("div");
  const go = () => ta.value.trim() && runInto(out, "Decoding…", () => api("/api/identity/aadsts", { body: { raw: ta.value } }), renderAadstsResult);
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); });
  const kbBody = el("div", { class: "hint" }, "Loading…");
  const kb = el("details", { style: "margin-top:10px" }, el("summary", {}, "Codes in the knowledge base"), kbBody);
  kb.addEventListener("toggle", async () => {
    if (!kb.open || kbBody.dataset.loaded) return;
    kbBody.dataset.loaded = "1";
    try {
      const d = await api("/api/identity/aadsts-codes");
      kbBody.replaceChildren(el("div", { class: "aadsts-codes-list", style: "margin-top:8px" }, d.codes.map((c) => el("div", {},
        link("aadsts", { c: `AADSTS${c.code}` }, `AADSTS${c.code}`), " ", el("span", { class: "sub" }, c.short)))));
    } catch (e) { kbBody.textContent = e.message; }
  });
  main.append(card(null, [ta,
    el("div", { class: "btn-row" },
      el("button", { class: "btn", type: "button", onclick: go }, "Decode"),
      AADSTS_SAMPLES.map(([file, label]) => el("button", { class: "btn secondary", type: "button", onclick: async () => {
        ta.value = await (await fetch(`samples/${file}`)).text(); go(); } }, label)),
      el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; out.replaceChildren(); ta.focus(); } }, "Clear"),
      el("span", { class: "hint", style: "align-self:center" }, "Ctrl+Enter to run")),
    kb]), out);
  if (params.get("c")) go();
}

function aadstsIpLink(ip) {
  return ip ? link("ip", { t: ip }, ip) : null;
}

function renderAadstsResult(d) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  if (d.facts && d.facts.length) frag.append(facts(d.facts));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  const steps = nextSteps(d.steps);
  if (steps) frag.append(steps);

  // Error code explanations.
  d.codes.forEach((c) => {
    const head = el("span", { class: "aadsts-code-head" }, el("span", { class: "mono" }, c.aadsts), c.known ? c.name : "Not in the knowledge base",
      c.count > 1 ? badge("info", `${c.count}×`) : null, c.interrupt ? badge("info", "interrupt") : null);
    frag.append(card(head, c.known ? [
      el("p", { style: "margin:0 0 8px" }, el("strong", {}, "Meaning: "), c.meaning),
      el("div", {}, el("strong", {}, "Typical causes:")),
      el("ul", { class: "token-list", style: "margin:4px 0 8px" }, c.causes.map((x) => el("li", {}, x))),
      el("p", { style: "margin:0 0 8px" }, el("strong", {}, "Fix: "), c.fix),
      el("div", { class: "hint" }, "Microsoft's description: ", el("a", { href: c.url, target: "_blank", rel: "noopener noreferrer" }, c.url)),
    ] : [
      el("p", { style: "margin:0 0 8px" }, "MSPGather doesn't have a verified explanation for this code, so it won't guess. Microsoft's error lookup page explains it:"),
      el("a", { href: c.url, target: "_blank", rel: "noopener noreferrer" }, c.url),
    ]));
  });

  if (d.groups && d.groups.length) {
    frag.append(card(`Repeated failures, grouped by error and IP (${d.groups.length})`, table(["Count", "Error", "IP address", "Accounts", "Client app / app", "First → last"],
      d.groups.map((g) => [String(g.count), el("div", {}, el("span", { class: "mono" }, `AADSTS${g.code}`), el("div", { class: "sub" }, g.short)),
        el("span", { class: "mono" }, aadstsIpLink(g.ip !== "?" ? g.ip : null) || "—"),
        el("div", {}, `${g.users.length}`, el("div", { class: "sub" }, g.users.slice(0, 5).join(", ") + (g.users.length > 5 ? ` +${g.users.length - 5}` : ""))),
        el("div", {}, g.clients.join(", ") || "—", el("div", { class: "sub" }, g.apps.join(", "))),
        el("span", { class: "sub" }, g.first ? `${fmtTime(g.first)} → ${fmtTime(g.last)}` : "—")]),
      (i) => (d.groups[i].count >= 5 && [50126, 50053, 50056, 50034, 51004].includes(d.groups[i].code) ? "hl" : null)), { flush: true }));
  }

  if (d.ca && d.ca.length) {
    const sevFor = (r) => (r === "failure" ? "critical" : r === "success" ? "ok" : r === "reportonlyfailure" ? "warning" : "info");
    frag.append(card("Conditional Access policies (this sign-in)", table(["Policy", "Result", "Grant controls", "Session controls"],
      d.ca.map((p) => [el("strong", {}, p.name), badge(sevFor(p.result), p.result_label), p.grant_controls.join(", ") || "—", p.session_controls.join(", ") || "—"]),
      (i) => (d.ca[i].result === "failure" ? "hl" : null)), { flush: true }));
  }

  if (d.auth_steps && d.auth_steps.length) {
    frag.append(card("Authentication steps", table(["Method", "Succeeded", "Detail"], d.auth_steps.map((s) => [s.method || "—",
      s.succeeded == null ? "—" : badge(s.succeeded ? "ok" : "critical", s.succeeded ? "yes" : "no"), s.detail || "—"]),
      (i) => (d.auth_steps[i].succeeded === false ? "hl" : null)), { flush: true }));
  }

  if (d.primary) {
    const rows = d.primary.map(([k, v]) => [k, k === "IP address" && v ? aadstsIpLink(v) : v ? el("span", { class: /ID$|agent/i.test(k) ? "mono" : null }, v) : null]);
    frag.append(card(d.event_count > 1 ? "Sign-in details (representative record)" : "Sign-in details", kv(rows)));
  }

  if (d.events && d.events.length > 1) {
    const filter = el("input", { type: "text", class: "filter", placeholder: "Filter sign-ins…" });
    const body = el("div");
    const draw = () => {
      const q = filter.value.toLowerCase();
      const rows = d.events.filter((e) => !q || Object.values(e).some((v) => v != null && String(v).toLowerCase().includes(q)));
      body.replaceChildren(table(["Time", "User", "App", "Client app", "IP", "Location", "Result"], rows.map((e) => [
        el("span", { class: "mono" }, fmtTime(e.time)), e.upn || "—", e.app || "—", e.client_app || "—",
        el("span", { class: "mono" }, aadstsIpLink(e.ip) || "—"), e.location || "—",
        e.code === 0 ? badge("ok", "success") : e.code == null ? "—" : el("div", {}, el("span", { class: "mono" }, `AADSTS${e.code}`), el("div", { class: "sub" }, e.short))]),
        (i) => (rows[i].code && rows[i].code !== 0 ? "hl" : null)));
    };
    filter.addEventListener("input", draw); draw();
    frag.append(card(`All sign-ins (${d.event_count}${d.event_count > d.events.length ? `, first ${d.events.length} shown` : ""})`, [filter, body], { flush: true }));
  }
  return frag;
}

/* ===================================================================== TOKEN DECODER */
// Everything here runs in the browser. Tokens are never sent to the MSPGather server.

const TOKEN_MSA_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";
const TOKEN_KNOWN_APPS = {
  "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
  "https://graph.microsoft.com": "Microsoft Graph",
  "00000002-0000-0ff1-ce00-000000000000": "Office 365 Exchange Online",
  "https://outlook.office365.com": "Office 365 Exchange Online",
  "00000003-0000-0ff1-ce00-000000000000": "Office 365 SharePoint Online",
  "00000002-0000-0000-c000-000000000000": "Azure AD Graph (Windows Azure Active Directory, retired)",
  "797f4846-ba00-4fd7-ba43-dac1f8f63013": "Azure Resource Manager (Windows Azure Service Management API)",
  "https://management.azure.com": "Azure Resource Manager",
  "https://management.core.windows.net": "Azure Service Management",
  "cfa8b339-82a2-471a-a3c9-0fc0be7a4093": "Azure Key Vault",
  "https://vault.azure.net": "Azure Key Vault",
  "00000004-0000-0ff1-ce00-000000000000": "Skype for Business Online",
  "0000000a-0000-0000-c000-000000000000": "Microsoft Intune",
  "00000007-0000-0000-c000-000000000000": "Dynamics CRM / Dataverse",
  "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
  "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
  "1b730954-1685-4b74-9bfd-dac224a7b894": "Azure AD PowerShell (retired module)",
  "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph Command Line Tools (Graph PowerShell)",
  "de8bc8b5-d9f9-48b1-a8ad-b748da725064": "Graph Explorer",
  "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
  "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
  "5e3ce6c0-2b1f-4285-8d4b-75ee78787346": "Microsoft Teams web client",
  "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
  "29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
  "9bc3ab49-b65d-410a-85ad-de819febfddc": "SharePoint Online Management Shell",
  "fb78d390-0c51-40cd-8e17-fdbfab77341b": "Microsoft Exchange REST API Based PowerShell",
  "a0c73c16-a7e3-4564-9a95-2bdf47383716": "Exchange Online Remote PowerShell",
  "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": "Azure Portal",
  "0000000c-0000-0000-c000-000000000000": "Microsoft App Access Panel (My Apps)",
  "4765445b-32c6-49b0-83e6-1d93765276ca": "OfficeHome",
  "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7": "Office365 Shell WCSS-Client",
};
// Directory role template IDs (wids). Only IDs we're sure of; unknown ones are shown as-is.
const TOKEN_ROLES = {
  "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
  "f2ef992c-3afb-46b9-b7cf-a126ee74c451": "Global Reader",
  "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
  "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
  "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
  "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
  "5d6b6bb7-de71-4623-b4af-96380a352509": "Security Reader",
  "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f": "Security Operator",
  "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
  "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Administrator",
  "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
  "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
  "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
  "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
  "4d6ac14f-3453-41d0-bef9-a3e0c569773a": "License Administrator",
  "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
  "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
  "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
  "17315797-102d-40b4-93e0-432062caca18": "Compliance Administrator",
  "4a5d8f65-41da-4de4-8968-e035b65339cf": "Reports Reader",
  "f023fd81-a637-4b56-95fd-791ac0226033": "Service Support Administrator",
  "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
  "9360feb5-f418-4baa-8175-e2a00bac4301": "Directory Writers",
  "88d8e3e3-8f55-4a1e-953a-9b9898b8876b": "Directory Readers",
  "d29b2b05-8046-44ba-8758-1e26182fcf32": "Directory Synchronization Accounts",
  "11648597-926c-4cf3-9c36-bcebb0ba8dcc": "Power Platform Administrator",
  "10dae51f-b6af-4016-8d66-8c2a99b929b3": "Guest User",
  "2af84b1e-32c8-42b7-82bc-daa82404023b": "Restricted Guest User",
};
const TOKEN_PRIVILEGED = new Set(["62e90394-69f5-4237-9190-012177145e10", "e8611ab8-c189-46e8-94e1-60213ab1f814", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
  "194ae4cb-b126-40b2-bd5b-6091b380977d", "29232cdf-9323-42fd-ade2-1d097af3e4de", "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "fe930be7-5e62-47db-91af-98c3a49a38b1",
  "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "158c047a-c907-4556-b7ef-446551a6b5f7", "3a2c62db-5318-420d-8d74-23affee5d9d5", "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"]);
const TOKEN_AMR = { pwd: "password", mfa: "multi-factor authentication", rsa: "key-based (Windows Hello, FIDO2, Authenticator, certificate)",
  otp: "one-time passcode (email/text)", fed: "federated identity provider", wia: "Windows Integrated Authentication",
  ngcmfa: "Windows Hello for Business / advanced credential (counts as MFA)", mngcmfa: "advanced credential (counts as MFA)",
  wiaormfa: "Windows Integrated Auth or MFA", none: "no completed authentication" };
const TOKEN_CLAIMS = {
  aud: "Audience: the API this token is for. The API rejects tokens whose aud isn't its own ID or URI.",
  iss: "Issuer. sts.windows.net/{tenant}/ = v1.0 token, login.microsoftonline.com/{tenant}/v2.0 = v2.0 token.",
  iat: "Issued at.", nbf: "Not valid before.", exp: "Expires at.", auth_time: "When the user last entered credentials.",
  tid: "Tenant (directory) ID the token was issued by. For guests this is the resource tenant.",
  oid: "Object ID of the user, or of the service principal for app-only tokens. The stable ID to identify who called.",
  sub: "Subject: a pairwise ID unique to this user + app. Not the same as oid.",
  upn: "User principal name (v1.0 tokens).", unique_name: "Display sign-in name (v1.0). Not guaranteed stable; don't use for authorization.",
  preferred_username: "Sign-in name (v2.0). Display only; it can change.", name: "Display name.", email: "Email address (if present).",
  given_name: "First name.", family_name: "Last name.",
  appid: "Client app ID that requested the token (v1.0).", azp: "Client app ID that requested the token (v2.0).",
  appidacr: "How the client app authenticated: 0 = public client (no secret), 1 = client secret, 2 = certificate.",
  azpacr: "How the client app authenticated: 0 = public client (no secret), 1 = client secret, 2 = certificate.",
  app_displayname: "Name of the client app.",
  scp: "Delegated permissions (scopes): what the app may do on behalf of the user.",
  roles: "App roles: application permissions (app-only token) or app roles assigned to the user.",
  wids: "Directory roles the user holds (role template IDs).",
  amr: "How the user authenticated.",
  acr: "Authentication context class (v1.0): 0 = didn't meet the ISO/IEC 29115 requirements, 1 = standard sign-in.",
  acrs: "Conditional Access authentication contexts satisfied.",
  idtyp: "Token type: app = app-only, user = delegated (user present).",
  ver: "Token version. For access tokens this is set by the API's app registration (accessTokenAcceptedVersion), not by the endpoint the client used.",
  xms_cc: "Client capabilities. cp1 = the client handles claims challenges (Continuous Access Evaluation), so tokens can live longer and be revoked in near real time.",
  deviceid: "Entra ID device ID of the device used.", ipaddr: "IP address the user authenticated from.",
  groups: "Group object IDs the user is a member of.",
  hasgroups: "Group overage: the user is in too many groups to list in the token. The app must get them from Microsoft Graph.",
  _claim_names: "Group overage: groups are not in the token (more than 200). The app must get them from Microsoft Graph.",
  _claim_sources: "Where to fetch the overage claims (Microsoft Graph).",
  onprem_sid: "On-premises AD security identifier (SID) of the synced user.",
  sid: "Session ID (used for sign-out).", nonce: "Replay protection for ID tokens (echoes the client's request).",
  at_hash: "Hash of the access token issued alongside this ID token.", c_hash: "Hash of the authorization code issued alongside this ID token.",
  uti: "Unique token identifier (internal).", rh: "Internal Entra ID claim; ignore.", aio: "Internal Entra ID claim; ignore.",
  signin_state: "Sign-in state flags, e.g. kmsi (stayed signed in), dvc_mngd (managed device), dvc_cmp (compliant device), dvc_dmjd (domain joined), inknownntwk (known network).",
  login_hint: "Opaque login hint for re-authentication.", cnf: "Proof-of-possession key confirmation.",
  tenant_region_scope: "Region of the tenant.", verified_primary_email: "Verified primary email.", verified_secondary_email: "Verified secondary emails.",
};
const TOKEN_SAML_STATUS = {
  Success: "Success: the IdP authenticated the user.",
  Requester: "Requester: the IdP says the REQUEST from the app (service provider) was wrong.",
  Responder: "Responder: the IdP itself failed to process the request.",
  VersionMismatch: "VersionMismatch: unsupported SAML version.",
  AuthnFailed: "AuthnFailed: the IdP could not authenticate the user (bad credentials, failed MFA, or user blocked).",
  InvalidAttrNameOrValue: "InvalidAttrNameOrValue: an attribute in the request was invalid.",
  InvalidNameIDPolicy: "InvalidNameIDPolicy: the IdP can't provide the NameID format the app asked for. Check the app's NameIDPolicy Format vs the IdP's configured name identifier.",
  NoAuthnContext: "NoAuthnContext: the IdP can't satisfy the authentication context the app requested (RequestedAuthnContext).",
  NoAvailableIDP: "NoAvailableIDP: no supported identity provider is available.",
  NoPassive: "NoPassive: the app asked for silent (IsPassive) sign-in but the user must interact.",
  NoSupportedIDP: "NoSupportedIDP: none of the requested IdPs are supported.",
  PartialLogout: "PartialLogout: logout didn't complete everywhere.",
  ProxyCountExceeded: "ProxyCountExceeded: too many IdP proxies.",
  RequestDenied: "RequestDenied: the IdP refused the request (policy, user not assigned to the app, etc.).",
  RequestUnsupported: "RequestUnsupported: the IdP doesn't support this request.",
  RequestVersionDeprecated: "RequestVersionDeprecated: the request's SAML version is deprecated.",
  RequestVersionTooHigh: "RequestVersionTooHigh: SAML version too high.", RequestVersionTooLow: "RequestVersionTooLow: SAML version too low.",
  ResourceNotRecognized: "ResourceNotRecognized: the IdP doesn't recognise the resource.",
  TooManyResponses: "TooManyResponses: too many responses.", UnknownAttrProfile: "UnknownAttrProfile: unknown attribute profile.",
  UnknownPrincipal: "UnknownPrincipal: the IdP doesn't know this user.", UnsupportedBinding: "UnsupportedBinding: the binding requested isn't supported.",
};

/* ---------- encoding helpers */
function tokenB64ToBytes(s) {
  s = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const tokenUtf8 = (bytes) => new TextDecoder("utf-8", { fatal: false }).decode(bytes);
function tokenB64urlJson(part) {
  return JSON.parse(tokenUtf8(tokenB64ToBytes(part)));
}
function tokenToB64url(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = ""; bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const tokenHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();

// Small SHA-1 for thumbprints when crypto.subtle isn't available (plain-http deployments).
function tokenSha1(bytes) {
  const ml = bytes.length * 8;
  const withPad = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  withPad.set(bytes); withPad[bytes.length] = 0x80;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 4, ml >>> 0); dv.setUint32(withPad.length - 8, Math.floor(ml / 2 ** 32));
  let [h0, h1, h2, h3, h4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  const w = new Uint32Array(80);
  const rotl = (x, n) => (x << n) | (x >>> (32 - n));
  for (let off = 0; off < withPad.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    let [a, b, c, d, e] = [h0, h1, h2, h3, h4];
    for (let i = 0; i < 80; i++) {
      const [f, k] = i < 20 ? [(b & c) | (~b & d), 0x5a827999] : i < 40 ? [b ^ c ^ d, 0x6ed9eba1] : i < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc] : [b ^ c ^ d, 0xca62c1d6];
      const t = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = t;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  return [h0, h1, h2, h3, h4].map((x) => x.toString(16).padStart(8, "0")).join("").toUpperCase();
}

/* ---------- minimal DER / X.509 reader (subject, issuer, validity) */
function tokenDerRead(b, pos) {
  const tag = b[pos];
  let len = b[pos + 1], hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f; len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[pos + 2 + i];
    hdr = 2 + n;
  }
  if (pos + hdr + len > b.length) throw new Error("Truncated certificate");
  return { tag, start: pos + hdr, end: pos + hdr + len };
}
function tokenDerChildren(b, node) {
  const out = []; let p = node.start;
  while (p < node.end) { const c = tokenDerRead(b, p); out.push(c); p = c.end; }
  return out;
}
function tokenOid(b, n) {
  const v = b.subarray(n.start, n.end); const parts = [Math.floor(v[0] / 40), v[0] % 40]; let acc = 0;
  for (let i = 1; i < v.length; i++) { acc = acc * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { parts.push(acc); acc = 0; } }
  return parts.join(".");
}
const TOKEN_DN = { "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "E", "0.9.2342.19200300.100.1.25": "DC" };
function tokenDerString(b, n) {
  const v = b.subarray(n.start, n.end);
  if (n.tag === 0x1e) { let s = ""; for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]); return s; }
  return tokenUtf8(v);
}
function tokenDerName(b, n) {
  return tokenDerChildren(b, n).map((set) => tokenDerChildren(b, set).map((atv) => {
    const [o, val] = tokenDerChildren(b, atv);
    const oid = tokenOid(b, o);
    return `${TOKEN_DN[oid] || oid}=${tokenDerString(b, val)}`;
  }).join("+")).join(", ");
}
function tokenDerTime(b, n) {
  const s = tokenUtf8(b.subarray(n.start, n.end));
  const m = n.tag === 0x17 ? s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/) : s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/);
  if (!m) return null;
  let y = Number(m[1]); if (n.tag === 0x17) y += y < 50 ? 2000 : 1900;
  return new Date(Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] || 0)));
}
async function tokenParseCert(b64) {
  const der = tokenB64ToBytes(b64);
  const info = { b64 };
  try {
    const cert = tokenDerRead(der, 0);
    const tbs = tokenDerChildren(der, cert)[0];
    let kids = tokenDerChildren(der, tbs);
    if (kids[0].tag === 0xa0) kids = kids.slice(1);
    const [serial, , issuer, validity, subject] = kids;
    const [nb, na] = tokenDerChildren(der, validity);
    Object.assign(info, { serial: tokenHex(der.subarray(serial.start, serial.end)), issuer: tokenDerName(der, issuer), subject: tokenDerName(der, subject),
      not_before: tokenDerTime(der, nb), not_after: tokenDerTime(der, na) });
  } catch (e) { info.error = `Certificate could not be parsed: ${e.message}`; }
  info.sha1 = tokenSha1(der);
  if (window.crypto && crypto.subtle) {
    try { info.sha256 = tokenHex(await crypto.subtle.digest("SHA-256", der)); } catch (e) { /* not a secure context */ }
  }
  return info;
}

/* ---------- input detection */
async function tokenDecode(input, opts) {
  let s = input.trim().replace(/^(authorization:\s*)?bearer\s+/i, "").replace(/^["']|["']$/g, "");
  const parts = s.split(".");
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(s)) return tokenDecodeJwt(s, opts);
  if (parts.length === 5 && /^eyJ/.test(s)) return { kind: "jwe", header: tokenB64urlJson(parts[0]) };
  // SAML: form body, URL-encoded, base64, deflated (redirect binding) or raw XML.
  const m = s.match(/(?:^|[?&])(SAMLResponse|SAMLRequest)=([^&\s]+)/);
  if (m) s = m[2];
  if (/%[0-9A-F]{2}/i.test(s)) s = decodeURIComponent(s.replace(/\+/g, " "));
  let xml;
  if (s.startsWith("<")) xml = s;
  else {
    let bytes;
    try { bytes = tokenB64ToBytes(s); } catch (e) { throw new Error("Not a JWT, and not base64 / XML. Paste an access/ID token (eyJ…), a SAMLResponse / SAMLRequest value, or SAML XML."); }
    const txt = tokenUtf8(bytes).replace(/^﻿/, "").trimStart();
    if (txt.startsWith("<")) xml = txt;
    else if (typeof DecompressionStream !== "undefined") {
      try {
        const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
        xml = (await new Response(stream).text()).trimStart();
      } catch (e) { /* not deflated */ }
    }
    if (!xml || !xml.startsWith("<")) throw new Error("Decoded the base64, but it isn't SAML XML or a JWT.");
  }
  return tokenDecodeSaml(xml, opts);
}

function tokenDecodeJwt(s, opts) {
  const [h, p, sig] = s.split(".");
  let header, payload;
  try { header = tokenB64urlJson(h); payload = tokenB64urlJson(p); } catch (e) { throw new Error("This looks like a JWT but its header/payload isn't valid base64url JSON."); }
  return { kind: "jwt", header, payload, hasSig: !!sig, opts, now: Date.now() / 1000 };
}

/* ---------- JWT analysis + rendering */
function tokenAppName(id) {
  if (!id) return null;
  const k = String(id).replace(/\/$/, "").toLowerCase();
  return TOKEN_KNOWN_APPS[k] || null;
}
function tokenRel(sec) { return fmtDuration(Math.abs(sec)); }

function tokenAnalyzeJwt(d) {
  const { header: H, payload: P, now } = d;
  const F = [];
  const steps = [];
  const exp = Number(P.exp), nbf = Number(P.nbf), iat = Number(P.iat);
  const scopes = typeof P.scp === "string" ? P.scp.split(" ").filter(Boolean) : [];
  const roles = Array.isArray(P.roles) ? P.roles : [];
  const appOnly = !P.scp && (P.idtyp === "app" || (roles.length && !P.upn && !P.preferred_username && !P.name));
  const isMs = /sts\.windows\.net|login\.microsoftonline\.|login\.windows\.net|microsoftonline\.us|chinacloudapi/i.test(P.iss || "");
  const looksId = !P.scp && !roles.length && (P.nonce || P.at_hash || P.c_hash || (P.aud && (P.aud === P.azp || P.aud === P.appid)) || (!P.appid && !P.azp && P.aud && /^[0-9a-f-]{36}$/i.test(P.aud)));
  const type = looksId ? "ID token" : "Access token";
  const who = P.upn || P.preferred_username || P.unique_name || P.email || (appOnly ? null : P.oid) || null;
  const clientId = P.appid || P.azp;
  const client = P.app_displayname || tokenAppName(clientId) || clientId;
  const aud = Array.isArray(P.aud) ? P.aud.join(", ") : P.aud;
  const audName = tokenAppName(aud) || aud;
  const ver = P.ver || (/\/v2\.0\/?$/.test(P.iss || "") ? "2.0" : P.iss && /sts\.windows\.net/.test(P.iss) ? "1.0" : null);
  let sev = "ok";
  let title;

  if (String(H.alg).toLowerCase() === "none") F.push({ severity: "critical", title: "Token is unsigned (alg: none)", detail: "Any API that accepts this token is badly broken. Entra ID never issues unsigned tokens." });
  if (exp && exp < now) {
    F.push({ severity: "critical", title: `Token expired ${tokenRel(now - exp)} ago (${fmtTime(new Date(exp * 1000).toISOString())})`,
      detail: "APIs reject expired tokens with 401. The client should use its refresh token or sign in again to get a new one." });
    steps.push({ title: "Get a new token", detail: "Expired tokens can't be renewed. Sign out/in of the app, or let MSAL acquire a fresh token (it does this automatically if it still has a valid refresh token)." });
  } else if (nbf && nbf > now + 60) {
    F.push({ severity: "warning", title: `Token isn't valid yet (valid from ${fmtTime(new Date(nbf * 1000).toISOString())}, in ${tokenRel(nbf - now)})`,
      detail: "Usually a clock difference: this PC's clock (or the API server's) is behind. Check the time sync (w32tm /query /status)." });
    steps.push({ title: "Check the clock on this machine and on the API server", commands: ["w32tm /query /status", "w32tm /resync"] });
  }
  if (P.hasgroups || (P._claim_names && P._claim_names.groups)) {
    F.push({ severity: "warning", title: "Group overage: the user's groups are NOT in this token",
      detail: "The user is in more groups than fit (200 in a JWT), so Entra ID left them out. Apps that read the groups claim will think the user is in no groups. The app must call Microsoft Graph, or the app registration can emit only 'Groups assigned to the application'." });
    steps.push({ title: "Fix group overage", detail: "App registration → Token configuration → groups claim → choose 'Groups assigned to the application' (and assign the groups to the enterprise app), or change the app to read group membership from Microsoft Graph (/me/transitiveMemberOf)." });
  }
  const expAud = (d.opts.aud || "").trim();
  if (expAud) {
    const norm = (x) => String(x).trim().toLowerCase().replace(/\/$/, "");
    const auds = Array.isArray(P.aud) ? P.aud : [P.aud];
    if (!auds.some((a) => norm(a) === norm(expAud))) {
      F.push({ severity: "critical", title: `Wrong audience: token is for ${audName || "(none)"}, not ${expAud}`,
        detail: looksId ? "This is an ID token. ID tokens are for the client app itself; never send them to an API. Request an access token for the API instead." :
          "The API will reject it (401, often 'invalid audience'). The client requested a token for a different resource: request a scope on the right API, e.g. " + `${expAud.replace(/\/$/, "")}/.default.` });
      steps.push({ title: "Request the token for the right resource", detail: `The client must ask for a scope on ${expAud} (for example '${expAud.replace(/\/$/, "")}/.default' or a specific scope like '${expAud.replace(/\/$/, "")}/user_impersonation').` });
    } else F.push({ severity: "ok", title: `Audience matches ${expAud}` });
  }
  const expScope = (d.opts.scope || "").trim();
  if (expScope) {
    const want = expScope.split(/[\s,]+/).filter(Boolean);
    const have = new Set([...scopes, ...roles].map((x) => x.toLowerCase()));
    const missing = want.filter((w) => !have.has(w.toLowerCase()));
    if (missing.length) {
      F.push({ severity: "critical", title: `Missing permission: ${missing.join(", ")}`,
        detail: `${appOnly ? "App roles (application permissions)" : "Scopes (delegated permissions)"} in the token: ${[...scopes, ...roles].join(", ") || "none"}. The API will return 403. Add the permission to the app registration and grant consent, then get a NEW token.` });
      steps.push({ title: "Add the permission and grant consent", detail: `App registration → API permissions → Add a permission → ${missing.join(", ")} (${appOnly ? "Application" : "Delegated"}) → Grant admin consent. Then acquire a new token; existing tokens keep the old permissions until they expire.` });
    } else F.push({ severity: "ok", title: `Has the expected permission${want.length > 1 ? "s" : ""}: ${want.join(", ")}` });
  }
  if (looksId && !expAud) F.push({ severity: "info", title: "This looks like an ID token", detail: "ID tokens tell the client app who signed in. They're not meant to be sent to APIs; use an access token for that." });
  if (P.tid === TOKEN_MSA_TENANT) F.push({ severity: "info", title: "Personal Microsoft account (consumer tenant)", detail: "tid 9188040d-… is the Microsoft consumer (MSA) tenant: this is an Outlook.com / Xbox style account, not a work or school account." });
  if (Array.isArray(P.wids)) {
    const priv = P.wids.filter((w) => TOKEN_PRIVILEGED.has(w));
    if (priv.length) F.push({ severity: "info", title: `User holds privileged directory role${priv.length > 1 ? "s" : ""}: ${priv.map((w) => TOKEN_ROLES[w]).join(", ")}`, detail: "Treat this token as highly sensitive." });
  }
  if (!appOnly && Array.isArray(P.amr)) {
    if (P.amr.some((a) => ["mfa", "ngcmfa", "mngcmfa"].includes(a))) F.push({ severity: "ok", title: "User completed MFA (amr contains mfa)" });
    else F.push({ severity: "info", title: `No MFA claim: user authenticated with ${P.amr.map((a) => TOKEN_AMR[a] || a).join(", ")}`, detail: "If a policy should have required MFA for this app, check which Conditional Access policies applied to this sign-in." });
  }
  if (typeof P.xms_cc === "string" ? P.xms_cc === "cp1" : Array.isArray(P.xms_cc) && P.xms_cc.includes("cp1")) {
    F.push({ severity: "info", title: "Client supports Continuous Access Evaluation (xms_cc = cp1)", detail: "Access tokens for CAE-aware resources can be long-lived (up to 28 hours) but are revoked in near real time on critical events (user disabled, password reset, location change)." });
  }
  if (H.nonce) F.push({ severity: "info", title: "Header has a nonce (Microsoft Graph style token)", detail: "Microsoft Graph tokens are not meant to be validated by third parties; signature checks against them fail by design." });
  if (!isMs && P.iss) F.push({ severity: "info", title: `Issuer is not Entra ID: ${P.iss}`, detail: "Claim explanations below assume Entra ID tokens and may not apply." });
  if (exp && iat && exp - iat > 0) F.push({ severity: "info", title: `Token lifetime: ${tokenRel(exp - iat)}`, detail: "Entra ID access tokens normally last 60–90 minutes (longer for CAE-capable clients)." });

  const crit = F.find((f) => f.severity === "critical");
  const resourceTxt = audName ? ` for ${audName}` : "";
  const flow = looksId ? "" : appOnly ? " (app-only, no user)" : " (delegated)";
  const by = appOnly ? (client ? `: app ${client}` : "") : who || client ? `: ${who || "a user"}${client ? ` via ${client}` : ""}` : "";
  if (crit) { sev = "critical"; title = crit.title; }
  else {
    sev = F.some((f) => f.severity === "warning") ? "warning" : "ok";
    const validity = exp ? `, expires in ${tokenRel(exp - now)}` : "";
    // The signature is not checked in the browser, so never call the token "valid".
    title = `${exp ? "Unexpired" : "Decoded"} ${type.toLowerCase()}${resourceTxt}${by}${flow}${validity}`;
    const warn = F.find((f) => f.severity === "warning");
    if (warn) title = `${type}${resourceTxt}: ${warn.title.charAt(0).toLowerCase() + warn.title.slice(1)}`;
  }
  const sub = [`${type}`, ver ? `v${ver}` : null, looksId ? null : appOnly ? "app-only (no user)" : "delegated (user + app)", who ? `user ${who}` : null,
    client ? `client ${client}` : null, P.tid ? `tenant ${P.tid}` : null].filter(Boolean).join(" · ") + ". Signature NOT verified.";
  return { sev, title, sub, F, steps, type, who, client, clientId, audName, aud, ver, appOnly, looksId, scopes, roles };
}

function tokenClaimValue(k, v, now) {
  if (["iat", "nbf", "exp", "auth_time"].includes(k) && typeof v === "number") {
    const iso = new Date(v * 1000).toISOString();
    const rel = v > now ? `in ${tokenRel(v - now)}` : `${tokenRel(now - v)} ago`;
    return el("div", {}, el("span", { class: "mono" }, fmtTime(iso)), el("div", { class: "sub" }, `${rel}${k === "exp" ? (v < now ? " (expired)" : " (not expired)") : ""} · ${v}`));
  }
  if (k === "wids" && Array.isArray(v)) return el("ul", { class: "token-list" }, v.map((w) => el("li", {}, TOKEN_ROLES[w] ? el("strong", {}, TOKEN_ROLES[w]) : el("span", { class: "sub" }, "Role not in MSPGather's list"), " ", el("span", { class: "mono sub" }, w))));
  if (k === "amr" && Array.isArray(v)) return el("div", {}, v.map((a) => el("div", {}, el("span", { class: "mono" }, a), " ", el("span", { class: "sub" }, TOKEN_AMR[a] || ""))));
  if (k === "scp" && typeof v === "string") return el("div", {}, v.split(" ").filter(Boolean).map((s) => el("div", { class: "mono" }, s)));
  if ((k === "aud" || k === "appid" || k === "azp") && tokenAppName(v)) return el("div", {}, el("span", { class: "mono" }, v), el("div", { class: "sub" }, tokenAppName(v)));
  if (k === "tid" && v === TOKEN_MSA_TENANT) return el("div", {}, el("span", { class: "mono" }, v), el("div", { class: "sub" }, "Microsoft consumer (personal account) tenant"));
  if (k === "ipaddr") return link("ip", { t: v }, v);
  if ((k === "appidacr" || k === "azpacr") && ["0", "1", "2"].includes(String(v))) return el("span", {}, String(v), " ", el("span", { class: "sub" }, ["public client", "client secret", "certificate"][Number(v)]));
  if (Array.isArray(v) && v.every((x) => typeof x !== "object")) return el("div", {}, v.length > 25 ? [v.slice(0, 25).map((x) => el("div", { class: "mono" }, String(x))), el("div", { class: "sub" }, `+${v.length - 25} more`)] : v.map((x) => el("div", { class: "mono" }, String(x))));
  if (typeof v === "object") return el("span", { class: "mono token-val" }, JSON.stringify(v));
  return el("span", { class: "mono token-val" }, String(v));
}

function tokenRenderJwt(d) {
  const a = tokenAnalyzeJwt(d);
  const P = d.payload;
  const frag = el("div");
  frag.append(verdict(a.sev, a.title, a.sub));
  frag.append(facts([["Type", a.type], ["Version", a.ver ? `v${a.ver}` : null], ["Audience", a.audName], ["User", a.who], ["Client app", a.client],
    ["Expires", P.exp ? (P.exp < d.now ? `expired ${tokenRel(d.now - P.exp)} ago` : `in ${tokenRel(P.exp - d.now)}`) : null]]));
  frag.append(card("Findings", findingsList(a.F), { flush: true }));
  const st = nextSteps(a.steps); if (st) frag.append(st);
  const order = ["aud", "iss", "tid", "exp", "nbf", "iat", "upn", "preferred_username", "unique_name", "name", "oid", "sub", "appid", "azp", "app_displayname", "scp", "roles", "wids", "groups", "hasgroups", "_claim_names", "amr", "acr", "idtyp", "ver"];
  const keys = [...order.filter((k) => k in P), ...Object.keys(P).filter((k) => !order.includes(k))];
  const hl = new Set(a.F.filter((f) => f.severity === "critical" || f.severity === "warning").flatMap((f) => (/expired|valid yet/.test(f.title) ? ["exp", "nbf"] : /overage/.test(f.title) ? ["hasgroups", "_claim_names"] : /audience/i.test(f.title) ? ["aud"] : /permission/i.test(f.title) ? ["scp", "roles"] : [])));
  frag.append(card(`Claims (${keys.length})`, table(["Claim", "Value", "Meaning"], keys.map((k) => [el("span", { class: "mono token-claim" }, k), tokenClaimValue(k, P[k], d.now), el("span", { class: "sub" }, TOKEN_CLAIMS[k] || "")]),
    (i) => (hl.has(keys[i]) ? "hl" : null)), { flush: true }));
  frag.append(card("Header", [kv([["Algorithm (alg)", d.header.alg], ["Type (typ)", d.header.typ], ["Key ID (kid)", d.header.kid ? el("span", { class: "mono" }, d.header.kid) : null],
    ["Cert thumbprint (x5t)", d.header.x5t ? el("span", { class: "mono" }, d.header.x5t) : null], ["Signature", d.hasSig ? "present, NOT verified by MSPGather" : "missing"]]),
  el("details", { style: "margin-top:10px" }, el("summary", {}, "Raw header and payload JSON"), code(JSON.stringify(d.header, null, 2)), code(JSON.stringify(P, null, 2)))]));
  return frag;
}

/* ---------- SAML analysis + rendering */
const TOKEN_NS = { saml: "urn:oasis:names:tc:SAML:2.0:assertion", samlp: "urn:oasis:names:tc:SAML:2.0:protocol", ds: "http://www.w3.org/2000/09/xmldsig#" };
function tokenX(node, ns, name) { return node ? [...node.getElementsByTagNameNS(TOKEN_NS[ns], name)] : []; }
function tokenX1(node, ns, name) { return tokenX(node, ns, name)[0] || null; }
function tokenKid(node, ns, name) { return node ? [...node.children].filter((c) => c.namespaceURI === TOKEN_NS[ns] && c.localName === name) : []; }
const tokenTxt = (n) => (n ? n.textContent.trim() : null);
const tokenStatusShort = (v) => (v ? v.split(":").pop() : null);

async function tokenDecodeSaml(xml, opts) {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("This XML contains a DOCTYPE/ENTITY declaration. Real SAML messages never do; refusing to parse it.");
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  if (doc.getElementsByTagName("parsererror").length) throw new Error("The decoded data isn't well-formed XML.");
  const root = doc.documentElement;
  const out = { kind: "saml", root: root.localName, xml, opts, now: Date.now(), certs: [] };
  const certNodes = tokenX(root, "ds", "X509Certificate");
  const seen = new Set();
  for (const c of certNodes) {
    const b64 = c.textContent.replace(/\s+/g, "");
    if (!b64 || seen.has(b64)) continue;
    seen.add(b64);
    out.certs.push(await tokenParseCert(b64));
  }
  if (root.localName === "AuthnRequest") {
    const pol = tokenX1(root, "samlp", "NameIDPolicy");
    const rac = tokenX1(root, "samlp", "RequestedAuthnContext");
    Object.assign(out, { id: root.getAttribute("ID"), issuer: tokenTxt(tokenX1(root, "saml", "Issuer")), destination: root.getAttribute("Destination"),
      acs: root.getAttribute("AssertionConsumerServiceURL"), binding: root.getAttribute("ProtocolBinding"), issueInstant: root.getAttribute("IssueInstant"),
      forceAuthn: root.getAttribute("ForceAuthn"), isPassive: root.getAttribute("IsPassive"), nameIdPolicy: pol ? pol.getAttribute("Format") : null,
      requestedAuthn: rac ? { comparison: rac.getAttribute("Comparison"), refs: tokenX(rac, "saml", "AuthnContextClassRef").map(tokenTxt) } : null });
    return out;
  }
  const resp = root.localName === "Response" ? root : null;
  const assertion = root.localName === "Assertion" ? root : tokenX1(root, "saml", "Assertion");
  out.encrypted = !assertion && !!tokenX1(root, "saml", "EncryptedAssertion");
  if (resp) {
    const st = tokenX1(resp, "samlp", "StatusCode");
    const st2 = st ? tokenKid(st, "samlp", "StatusCode")[0] : null;
    Object.assign(out, { id: resp.getAttribute("ID"), destination: resp.getAttribute("Destination"), inResponseTo: resp.getAttribute("InResponseTo"),
      issueInstant: resp.getAttribute("IssueInstant"), responseIssuer: tokenTxt(tokenKid(resp, "saml", "Issuer")[0]),
      status: st ? st.getAttribute("Value") : null, status2: st2 ? st2.getAttribute("Value") : null, statusMessage: tokenTxt(tokenX1(resp, "samlp", "StatusMessage")),
      responseSigned: tokenKid(resp, "ds", "Signature").length > 0 });
  }
  if (assertion) {
    const subj = tokenX1(assertion, "saml", "Subject");
    const nameId = tokenX1(subj, "saml", "NameID");
    const scd = tokenX1(subj, "saml", "SubjectConfirmationData");
    const cond = tokenX1(assertion, "saml", "Conditions");
    const authn = tokenX1(assertion, "saml", "AuthnStatement");
    Object.assign(out, {
      assertionIssuer: tokenTxt(tokenKid(assertion, "saml", "Issuer")[0]), assertionId: assertion.getAttribute("ID"),
      assertionInstant: assertion.getAttribute("IssueInstant"), assertionSigned: tokenKid(assertion, "ds", "Signature").length > 0,
      nameId: tokenTxt(nameId), nameIdFormat: nameId ? nameId.getAttribute("Format") : null,
      recipient: scd ? scd.getAttribute("Recipient") : null, scdNotOnOrAfter: scd ? scd.getAttribute("NotOnOrAfter") : null, scdInResponseTo: scd ? scd.getAttribute("InResponseTo") : null,
      notBefore: cond ? cond.getAttribute("NotBefore") : null, notOnOrAfter: cond ? cond.getAttribute("NotOnOrAfter") : null,
      audiences: tokenX(cond, "saml", "Audience").map(tokenTxt),
      authnInstant: authn ? authn.getAttribute("AuthnInstant") : null, sessionIndex: authn ? authn.getAttribute("SessionIndex") : null,
      authnContext: tokenTxt(tokenX1(authn, "saml", "AuthnContextClassRef")),
      attributes: tokenX(assertion, "saml", "Attribute").map((a) => ({ name: a.getAttribute("Name"), friendly: a.getAttribute("FriendlyName"), values: tokenX(a, "saml", "AttributeValue").map(tokenTxt) })),
    });
  }
  return out;
}

function tokenSamlTime(iso, now) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (isNaN(t)) return iso;
  const rel = (t - now) / 1000;
  return el("div", {}, el("span", { class: "mono" }, fmtTime(iso)), el("div", { class: "sub" }, rel > 0 ? `in ${tokenRel(rel)}` : `${tokenRel(-rel)} ago`));
}

function tokenCertRows(certs, now) {
  return certs.map((c) => {
    const days = c.not_after ? Math.floor((c.not_after - now) / 86400000) : null;
    return { c, days, row: [el("div", {}, el("div", {}, c.subject || "—"), c.issuer && c.issuer !== c.subject ? el("div", { class: "sub" }, `Issued by ${c.issuer}`) : el("div", { class: "sub" }, c.error || "Self-signed")),
      c.not_after ? el("div", {}, fmtTime(c.not_after.toISOString()), el("div", { class: "sub" }, days < 0 ? `expired ${-days} days ago` : `${days} days left`)) : "—",
      el("div", {}, el("div", { class: "mono" }, `SHA-1 ${c.sha1}`), c.sha256 ? el("div", { class: "mono sub" }, `SHA-256 ${c.sha256}`) : null)] };
  });
}

function tokenRenderSaml(d) {
  const frag = el("div");
  const F = [], steps = [];
  const now = d.now;
  const certRows = tokenCertRows(d.certs, now);
  certRows.forEach(({ c, days }) => {
    if (days == null) return;
    if (days < 0) F.push({ severity: "critical", title: `Signing certificate expired ${-days} days ago (${c.subject})`, detail: "Apps that check certificate expiry will reject this sign-in. Renew the SAML signing certificate at the IdP and upload the new one to the app." });
    else if (days <= 30) F.push({ severity: "warning", title: `Signing certificate expires in ${days} days`, detail: "Create the new certificate at the IdP, give it to the app owner, and switch over before it expires." });
  });
  if (d.root === "AuthnRequest") {
    if (d.requestedAuthn) F.push({ severity: "info", title: `App requests a specific authentication context: ${d.requestedAuthn.refs.map((r) => r.split(":").pop()).join(", ")}`, detail: "If Entra ID fails with AADSTS75011, this is why: the user authenticated a different way. Remove RequestedAuthnContext in the app, or set it to 'unspecified'." });
    if (d.isPassive === "true") F.push({ severity: "info", title: "IsPassive=true: silent sign-in only", detail: "If the user must interact, the IdP answers NoPassive." });
    if (d.forceAuthn === "true") F.push({ severity: "info", title: "ForceAuthn=true: the user must re-enter credentials every time" });
    frag.append(verdict(worstSeverity(F) === "ok" ? "info" : worstSeverity(F), `SAML sign-in request (AuthnRequest) from ${d.issuer || "an unknown app"}`, `Sent to ${d.destination || "?"} · reply (ACS) URL ${d.acs || "not specified"}`));
    frag.append(facts([["App entity ID", d.issuer], ["Reply URL (ACS)", d.acs], ["NameID format", d.nameIdPolicy ? d.nameIdPolicy.split(":").pop() : null]]));
    frag.append(card("Findings", findingsList(F), { flush: true }));
    frag.append(card("Request", kv([["ID", d.id], ["Issuer (app entity ID)", d.issuer], ["Destination", d.destination], ["AssertionConsumerServiceURL", d.acs], ["Protocol binding", d.binding],
      ["Issue instant", tokenSamlTime(d.issueInstant, now)], ["NameIDPolicy Format", d.nameIdPolicy], ["RequestedAuthnContext", d.requestedAuthn ? `${d.requestedAuthn.comparison || "exact"}: ${d.requestedAuthn.refs.join(", ")}` : null],
      ["ForceAuthn", d.forceAuthn], ["IsPassive", d.isPassive]])));
    frag.append(el("details", {}, el("summary", {}, "Decoded XML"), code(d.xml)));
    return frag;
  }

  const statusShort = tokenStatusShort(d.status), status2 = tokenStatusShort(d.status2);
  const failed = d.status && statusShort !== "Success";
  if (failed) {
    F.push({ severity: "critical", title: `IdP returned ${statusShort}${status2 ? ` / ${status2}` : ""}${d.statusMessage ? `: ${d.statusMessage}` : ""}`,
      detail: [TOKEN_SAML_STATUS[statusShort], status2 ? TOKEN_SAML_STATUS[status2] : null].filter(Boolean).join(" ") || "Check the IdP's sign-in logs for this time." });
  }
  if (d.encrypted) F.push({ severity: "info", title: "The assertion is encrypted", detail: "Only the app (with its private key) can read the user's details. Status and issuer are still shown." });
  const issuer = d.assertionIssuer || d.responseIssuer;
  const signedAny = d.responseSigned || d.assertionSigned;
  if (!failed && !d.encrypted && d.nameId !== undefined) {
    if (!signedAny) F.push({ severity: "critical", title: "Neither the response nor the assertion is signed", detail: "Apps must reject unsigned SAML. Check the IdP's signing option (Entra ID: Single sign-on → SAML certificates → Signing option)." });
    else F.push({ severity: "ok", title: `Signed: ${[d.responseSigned ? "response" : null, d.assertionSigned ? "assertion" : null].filter(Boolean).join(" and ")}`, detail: "Some apps require the assertion (or the response) specifically to be signed. If the app says 'signature missing', change the signing option. The signature itself is NOT verified here." });
    if (!d.nameId) F.push({ severity: "warning", title: "No NameID in the assertion", detail: "Most apps identify the user by NameID. Configure the Unique User Identifier (Name ID) claim at the IdP." });
  }
  const expAud = (d.opts.aud || "").trim();
  if (expAud && d.audiences) {
    if (!d.audiences.some((a) => a.replace(/\/$/, "").toLowerCase() === expAud.replace(/\/$/, "").toLowerCase()))
      F.push({ severity: "critical", title: `Audience mismatch: assertion is for ${d.audiences.join(", ") || "(none)"}, not ${expAud}`, detail: "The app rejects assertions for a different entity ID. Make the Identifier (Entity ID) at the IdP exactly match what the app expects." });
    else F.push({ severity: "ok", title: `Audience matches ${expAud}` });
  }
  if (d.destination && d.recipient && d.destination !== d.recipient) F.push({ severity: "warning", title: "Destination and Recipient differ", detail: `Response Destination ${d.destination} vs SubjectConfirmation Recipient ${d.recipient}. Apps usually require both to equal their reply (ACS) URL.` });
  if (d.inResponseTo === null && d.root === "Response" && !failed) F.push({ severity: "info", title: "No InResponseTo: IdP-initiated sign-in", detail: "The app didn't request this sign-in (e.g. user clicked the tile in My Apps). Some apps reject unsolicited responses; start the sign-in from the app instead." });
  const issued = Date.parse(d.issueInstant || d.assertionInstant);
  const nb = Date.parse(d.notBefore), noa = Date.parse(d.notOnOrAfter || d.scdNotOnOrAfter);
  if (!isNaN(issued) && issued - now > 60000) F.push({ severity: "warning", title: `Issued ${tokenRel((issued - now) / 1000)} in the future (by this PC's clock)`, detail: "The IdP's clock is ahead of this machine (or this machine is behind). Apps reject assertions that aren't valid yet; most allow only a few minutes of clock skew. Check time sync on the IdP and app servers." });
  else if (!isNaN(nb) && nb - now > 60000) F.push({ severity: "warning", title: `Not valid until ${fmtTime(d.notBefore)} (in ${tokenRel((nb - now) / 1000)})`, detail: "Clock skew between IdP and app. Check time sync." });
  if (!isNaN(noa)) {
    if (noa < now) F.push({ severity: "info", title: `Validity window ended ${tokenRel((now - noa) / 1000)} ago`, detail: "Expected for a capture from earlier. If this was captured just now and the app says 'expired', the app server's clock is ahead; check its time sync." });
    if (!isNaN(nb) && noa - nb < 5 * 60000) F.push({ severity: "warning", title: `Very short validity window (${tokenRel((noa - nb) / 1000)})`, detail: "Small clock differences between IdP and app will make sign-ins fail intermittently." });
  }
  const sev = worstSeverity(F.filter((f) => f.severity !== "info")) || "ok";
  let title;
  const crit = F.find((f) => f.severity === "critical");
  if (failed) title = `SAML sign-in failed at the IdP: ${statusShort}${status2 ? ` / ${status2}` : ""}${d.statusMessage ? ` (${d.statusMessage})` : ""}`;
  else if (crit) title = crit.title;
  else if (F.find((f) => f.severity === "warning")) title = `SAML response for ${d.nameId || "?"}: ${F.find((f) => f.severity === "warning").title}`;
  else if (d.encrypted) title = `SAML response from ${issuer || "?"}: Success, assertion encrypted`;
  else title = `SAML sign-in succeeded: ${d.nameId || "(no NameID)"} for ${(d.audiences || []).join(", ") || "?"} (issued by ${issuer || "?"})`;
  frag.append(verdict(failed ? "critical" : sev, title, `${d.root} · ${d.status ? `status ${statusShort}` : "no status"} · issued ${d.issueInstant || d.assertionInstant ? fmtTime(d.issueInstant || d.assertionInstant) : "?"} · signature NOT verified`));
  frag.append(facts([["Status", statusShort], ["User (NameID)", d.nameId], ["Audience", (d.audiences || []).join(", ")], ["Issuer", issuer], ["Signed", signedAny == null ? null : signedAny ? "yes" : "no"]]));
  frag.append(card("Findings", findingsList(F), { flush: true }));
  if (failed && status2 === "InvalidNameIDPolicy") steps.push({ title: "Align the NameID format", detail: "Set the app's requested NameIDPolicy Format to one the IdP issues (often 'unspecified' or emailAddress), or change the Name identifier format in Entra ID → Enterprise app → Single sign-on → Attributes & Claims → Unique User Identifier." });
  const st = nextSteps(steps); if (st) frag.append(st);
  frag.append(card("Message", kv([["Response ID", d.id], ["Destination", d.destination], ["InResponseTo", d.inResponseTo], ["Issue instant", tokenSamlTime(d.issueInstant, now)],
    ["Response issuer", d.responseIssuer], ["Status", d.status ? el("div", {}, el("span", { class: "mono" }, d.status), d.status2 ? el("div", { class: "mono" }, d.status2) : null, d.statusMessage ? el("div", {}, d.statusMessage) : null) : null],
    ["Assertion issuer", d.assertionIssuer], ["NameID", d.nameId ? el("span", { class: "mono" }, d.nameId) : null], ["NameID format", d.nameIdFormat],
    ["Recipient", d.recipient], ["Audience", d.audiences ? d.audiences.join(", ") : null], ["Not before", tokenSamlTime(d.notBefore, now)],
    ["Not on or after", tokenSamlTime(d.notOnOrAfter, now)], ["Authentication instant", tokenSamlTime(d.authnInstant, now)],
    ["Authentication context", d.authnContext], ["Session index", d.sessionIndex],
    ["Response signed", d.responseSigned == null ? null : d.responseSigned ? "yes" : "no"], ["Assertion signed", d.assertionSigned == null ? null : d.assertionSigned ? "yes" : "no"]])));
  if (d.attributes && d.attributes.length) frag.append(card(`Attributes / claims (${d.attributes.length})`, table(["Name", "Value(s)"], d.attributes.map((a) => [
    el("div", {}, el("span", { class: "mono" }, a.name), a.friendly ? el("div", { class: "sub" }, a.friendly) : null), el("div", {}, a.values.map((v) => el("div", { class: "mono token-val" }, v)))])), { flush: true }));
  if (certRows.length) frag.append(card("Signing certificate", table(["Subject", "Expires", "Thumbprint"], certRows.map((r) => r.row), (i) => (certRows[i].days != null && certRows[i].days <= 30 ? "hl" : null)), { flush: true }));
  frag.append(el("details", {}, el("summary", {}, "Decoded XML"), code(d.xml)));
  return frag;
}

/* ---------- samples (fictional, built at run time so the times are current) */
function tokenSampleJwt(kind) {
  const now = Math.floor(Date.now() / 1000);
  const base = { iss: "https://sts.windows.net/11111111-2222-3333-4444-555555555555/", tid: "11111111-2222-3333-4444-555555555555", ver: "1.0",
    oid: "0b6a8f3e-1c2d-4e5f-8a9b-1c2d3e4f5a6b", sub: "Zm9vYmFyLWZpY3Rpb25hbC1zdWJqZWN0LWlk", upn: "meganb@contoso.com", unique_name: "meganb@contoso.com",
    name: "Megan Bowen", ipaddr: "198.51.100.24", amr: ["pwd", "mfa"], acr: "1", idtyp: "user", deviceid: "9f8e7d6c-5b4a-4321-9876-fedcba987654", xms_cc: ["cp1"] };
  const payload = kind === "expired"
    ? { ...base, aud: "https://contoso-api.contoso.com", appid: "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb", app_displayname: "Contoso Expenses", scp: "user_impersonation",
      iat: now - 3 * 3600 - 600, nbf: now - 3 * 3600 - 600, exp: now - 3 * 3600 + 4200, hasgroups: true, amr: ["pwd"] }
    : { ...base, aud: "00000003-0000-0000-c000-000000000000", appid: "de8bc8b5-d9f9-48b1-a8ad-b748da725064", app_displayname: "Graph Explorer",
      scp: "openid profile User.Read Mail.Read", iat: now - 300, nbf: now - 300, exp: now + 4500, wids: ["62e90394-69f5-4237-9190-012177145e10"] };
  const header = { typ: "JWT", alg: "RS256", kid: "fictional-key-id-1" };
  return `${tokenToB64url(JSON.stringify(header))}.${tokenToB64url(JSON.stringify(payload))}.ZmljdGlvbmFsLXNpZ25hdHVyZS1ub3QtcmVhbA`;
}
const TOKEN_SAMPLE_CERT = "MIIDCjCCAfKgAwIBAgICWjwwDQYJKoZIhvcNAQELBQAwSDE0MDIGA1UEAwwrQ29udG9zbyBJZFAgU0FNTCBTaWduaW5nIChmaWN0aW9uYWwgc2FtcGxlKTEQMA4GA1UECgwHQ29udG9zbzAeFw0yNTAzMDEwMDAwMDBaFw0yODAzMDEwMDAwMDBaMEgxNDAyBgNVBAMMK0NvbnRvc28gSWRQIFNBTUwgU2lnbmluZyAoZmljdGlvbmFsIHNhbXBsZSkxEDAOBgNVBAoMB0NvbnRvc28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzqgxqRzx7gqYs1xd4LDgvx0rvaYJLnc6YbhOrXwFz6IFDaWjy/q2G74i4/Inv6D6XCMTvIx1d8kURv4sAaxBcF/1X69VBGWEqzfHDhXogmGXZSBtEzJBIl4NVRHax+bakj3MpnLxVLeSGdyKU+2vVSFJQ/PuhpS+3qnrs5UNx2qGqW+MrhPY2ru1J3qQWc07exPeSHWBNB5h8XmpDrzvqBC/ff2o3VQqDyH3A26nPA+N9k08PQHF0PT/rs+J0+0FehzEXcmWi7+cQIfNIyd8kGhUQ1HFnNrO34C5xQOU+HOsS4jqVCbi/sn0KG7WUgD2Twrya95NXmPRSCTWWcwD7AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAK2PCO3BMy9VYBQUBRkQQfpQo8/apGCA7fT8swzU+/YbmW8gCBohMzwJv1zn9kjBq54aX12Oz2RQ3x767QwwvLV5+omLXS3ZRxAgYvZIjjrMYI5wdt4Fn4htku6SmUtBzopHMx6cLMLdEgeUUCHBaZcnf5LI08YjvY6eJ22YJB1BkjLWq/ufblz5w95iux2AUWOu/ACR716nGU+9CeJfyKDRcHflsuoGxngXRPunPPEosbSktXwuAa8ZtOymBClu0BbMhbRDqrVC+H6mzcMaMSM0/hEhMieYjmQKvb4iUUl6D1bSIH8l/YVZBwTfspd1IRqa3ROX6+bRJgwkGA30KU0=";
function tokenSampleSaml() {
  const iso = (ms) => new Date(Date.now() + ms).toISOString().replace(/\.\d+Z$/, "Z");
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1f0c2e7a" Version="2.0" IssueInstant="${iso(-60000)}" Destination="https://app.fabrikam.com/saml/acs" InResponseTo="_req8d21">
<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/11111111-2222-3333-4444-555555555555/</Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a7b3c9d1" IssueInstant="${iso(-60000)}" Version="2.0">
<Issuer>https://sts.windows.net/11111111-2222-3333-4444-555555555555/</Issuer>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_a7b3c9d1"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>ZmljdGlvbmFsLWRpZ2VzdA==</DigestValue></Reference></SignedInfo><SignatureValue>ZmljdGlvbmFsLXNpZ25hdHVyZQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>${TOKEN_SAMPLE_CERT}</X509Certificate></X509Data></KeyInfo></Signature>
<Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">meganb@contoso.com</NameID>
<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="_req8d21" NotOnOrAfter="${iso(240000)}" Recipient="https://app.fabrikam.com/saml/acs"/></SubjectConfirmation></Subject>
<Conditions NotBefore="${iso(-360000)}" NotOnOrAfter="${iso(3240000)}"><AudienceRestriction><Audience>https://app.fabrikam.com/saml/metadata</Audience></AudienceRestriction></Conditions>
<AttributeStatement>
<Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>11111111-2222-3333-4444-555555555555</AttributeValue></Attribute>
<Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier"><AttributeValue>0b6a8f3e-1c2d-4e5f-8a9b-1c2d3e4f5a6b</AttributeValue></Attribute>
<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>meganb@contoso.com</AttributeValue></Attribute>
<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"><AttributeValue>5e1d2c3b-4a59-4687-9a8b-7c6d5e4f3a2b</AttributeValue><AttributeValue>6f2e3d4c-5b6a-4798-8b9c-8d7e6f5a4b3c</AttributeValue></Attribute>
</AttributeStatement>
<AuthnStatement AuthnInstant="${iso(-90000)}" SessionIndex="_a7b3c9d1"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext></AuthnStatement>
</Assertion></samlp:Response>`;
  return btoa(xml);
}

function renderTokenTool(main) {
  const ta = el("textarea", { spellcheck: "false", placeholder: "Paste a JWT access or ID token (eyJ…, with or without 'Bearer '), a SAMLResponse / SAMLRequest value (base64, URL-encoded or form body), or SAML XML." });
  const aud = el("input", { type: "text", placeholder: "e.g. https://graph.microsoft.com or api://contoso-api (optional)", spellcheck: "false" });
  const scope = el("input", { type: "text", placeholder: "e.g. Mail.Read (optional)", spellcheck: "false" });
  const out = el("div");
  const go = () => ta.value.trim() && runInto(out, "Decoding locally…", () => tokenDecode(ta.value, { aud: aud.value, scope: scope.value }),
    (d) => (d.kind === "jwt" ? tokenRenderJwt(d) : d.kind === "saml" ? tokenRenderSaml(d) :
      el("div", {}, verdict("info", "This is an encrypted token (JWE), so its claims can't be read", `Header: alg ${d.header.alg}, enc ${d.header.enc}. Only the intended recipient can decrypt it.`))));
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); });
  const sample = (fn) => () => { ta.value = fn(); go(); };
  main.append(
    el("div", { class: "notice" }, "Decoded entirely in your browser: tokens are never sent to the MSPGather server. Signatures are NOT verified; this shows what a token says, not whether it is genuine. Tokens are credentials: don't paste live production tokens into tickets or chat."),
    card(null, [ta,
      el("div", { class: "tool-form token-opts" },
        el("div", { class: "field grow" }, el("label", {}, "Expected audience / entity ID"), aud),
        el("div", { class: "field grow" }, el("label", {}, "Expected scope or role"), scope)),
      el("div", { class: "btn-row" },
        el("button", { class: "btn", type: "button", onclick: go }, "Decode"),
        el("button", { class: "btn secondary", type: "button", onclick: sample(() => tokenSampleJwt("ok")) }, "Sample: Graph access token"),
        el("button", { class: "btn secondary", type: "button", onclick: sample(() => tokenSampleJwt("expired")) }, "Sample: expired token, group overage"),
        el("button", { class: "btn secondary", type: "button", onclick: sample(tokenSampleSaml) }, "Sample: SAML response"),
        el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; out.replaceChildren(); ta.focus(); } }, "Clear"),
        el("span", { class: "hint", style: "align-self:center" }, "Ctrl+Enter to run"))]),
    out);
}

/* ============================================================ TENANT & FEDERATION */
function renderTenantTool(main, params) {
  const out = el("div");
  main.append(card(null, hashForm("tenant", [
    { name: "d", label: "Domain or email address", placeholder: "contoso.com or user@contoso.com", grow: true, required: true },
  ], params, "Look up")), out);
  if (params.get("d")) runInto(out, `Looking up ${params.get("d")}… (Entra discovery, federation metadata)`, () => api(`/api/identity/tenant/${encodeURIComponent(params.get("d"))}`), renderTenantResult);
}

function tenantCertTable(certs) {
  return table(["Subject", "Valid from", "Expires", "Days left", "Thumbprint (SHA-1)"], certs.map((c) => [
    el("div", {}, c.subject, c.issuer !== c.subject ? el("div", { class: "sub" }, `Issued by ${c.issuer}`) : null),
    el("span", { class: "mono" }, fmtTime(c.not_before)), el("span", { class: "mono" }, fmtTime(c.not_after)),
    c.expired ? badge("critical", "expired") : badge(c.days_left <= 30 ? "critical" : c.days_left <= 60 ? "warning" : "ok", `${c.days_left} days`),
    el("span", { class: "mono" }, c.thumbprint_sha1)]), (i) => (certs[i].expired || certs[i].days_left <= 30 ? "hl" : null));
}

function renderTenantResult(d) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  const fed = d.federation;
  frag.append(facts([["Tenant ID", d.tenant_id], ["Sign-in", d.namespace_type === "Managed" ? "Managed (cloud)" : d.namespace_type], ["Cloud", d.cloud_label],
    ["Region", d.region_label], ["Organisation", d.federation_brand], ["Identity provider", d.idp]]));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  const st = nextSteps(d.steps); if (st) frag.append(st);
  if (fed) {
    const h = fed.https || {};
    const c = h.cert;
    frag.append(card(`Identity provider: ${d.idp} (${fed.host})`, kv([
      ["Sign-in URL (AuthURL)", d.auth_url ? el("span", { class: "mono token-val" }, d.auth_url) : null],
      ["Reachable", h.error ? el("span", {}, badge("warning", "no"), " ", h.error) : h.status ? el("span", {}, badge("ok", "yes"), ` HTTP ${h.status} from ${h.ip}${h.tls_version ? ` · ${h.tls_version}` : ""}`) : null],
      ["HTTPS certificate", c ? el("div", {}, h.tls_error ? badge("critical", "untrusted") : c.expired ? badge("critical", "expired") : badge(c.days_left <= 30 ? "warning" : "ok", `${c.days_left} days left`),
        " ", c.subject, el("div", { class: "sub" }, `Issued by ${c.issuer} · expires ${fmtTime(c.not_after)}`), h.tls_error ? el("div", { class: "sub" }, h.tls_error) : null) : null],
      ["Federation metadata", fed.metadata_url && (d.idp_kind === "adfs" || fed.metadata) ? el("div", {}, el("span", { class: "mono token-val" }, fed.metadata_url),
        fed.metadata_error ? el("div", { class: "sub" }, fed.metadata_error) : fed.metadata ? el("div", { class: "sub" }, "Fetched and parsed") : null) : null],
      ["Federation service ID", fed.metadata ? fed.metadata.entity_id : null],
    ])));
    if (fed.metadata && fed.metadata.signing.length) frag.append(card("Token-signing certificates (from federation metadata)", tenantCertTable(fed.metadata.signing), { flush: true }));
    if (fed.metadata && fed.metadata.encryption.length) frag.append(card("Token-decryption / encryption certificates", tenantCertTable(fed.metadata.encryption), { flush: true }));
  }
  frag.append(card("Discovery details", kv([["Domain", el("span", {}, d.domain, " · ", link("domain", { d: d.domain }, "Domain Health →"))], ["Tenant ID", d.tenant_id ? el("span", { class: "mono" }, d.tenant_id) : "not found"],
    ["Namespace type", d.namespace_type], ["Federation brand name", d.federation_brand], ["Cloud instance", d.cloud_instance], ["Tenant region scope", d.region_scope ? `${d.region_scope} (${d.region_label})` : null],
    ["Region sub-scope", d.region_sub_scope], ["Lookup errors", d.errors && d.errors.length ? d.errors.join("; ") : null]])));
  return frag;
}

/* ============================================================== REGISTRATION */
registerTool({ category: "identity", group: "Sign-in", id: "aadsts", title: "Sign-in Error Decoder", render: renderAadstsTool,
  icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7zM9.5 9.5l5 5M14.5 9.5l-5 5",
  keywords: `aadsts entra azure ad sign-in signin login error conditional access ca mfa lockout password spray locked sign-in logs ${AADSTS_KEYWORD_CODES}`,
  desc: "Paste an AADSTS code, an error message or Entra sign-in logs (text or JSON). Explains the error, finds the Conditional Access policy that blocked it, and spots password sprays and stale passwords." });
registerTool({ category: "identity", group: "Tokens", id: "token", title: "Token Decoder", render: renderTokenTool,
  icon: "M7 15a4 4 0 110-8 4 4 0 010 8zM11 11h10M17 11v4M20 11v3",
  keywords: "jwt access token id token bearer claims scp roles aud expired saml samlresponse assertion samlrequest decode",
  desc: "Decode a JWT or SAML response in your browser (nothing is sent to the server): who, which app, which API, scopes and roles, expiry, group overage, and SAML status, audience and signing certificate." });
registerTool({ category: "identity", group: "Tenants", id: "tenant", title: "Tenant & Federation", render: renderTenantTool,
  icon: "M4 21V7l8-4 8 4v14M9 21v-5h6v5M8 10h.01M12 10h.01M16 10h.01",
  keywords: "tenant id entra azure ad federation adfs ad fs okta ping managed federated token-signing certificate getuserrealm gcc high",
  desc: "Look up a domain's Entra tenant ID, cloud and region, and whether sign-in is managed or federated. For AD FS, checks the token-signing and HTTPS certificates for expiry." });
