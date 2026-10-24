"use strict";
/* Identity: Device Join Analyzer (dsregcmd /status, analyzed server-side) and
   Identity Converters (GUID / ImmutableId, SID, FILETIME, userAccountControl,
   encoders and decoders; runs entirely in the browser). */

addStyles(`
.dsreg-samples { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
.dsreg-sec h3 { margin: 14px 0 6px; font-size: 13px; }
.dsreg-sec h3:first-child { margin-top: 0; }
.dsreg-val { word-break: break-all; }
.idconvert-val { word-break: break-all; }
.idconvert-copy { margin-left: 6px; font-size: 11px; padding: 0 6px; vertical-align: middle; position: static; }
.idconvert-flags { margin: 0; padding-left: 18px; }
.idconvert-flags li { margin: 2px 0; }
.idconvert-pre { white-space: pre-wrap; word-break: break-all; margin: 0; }
`);

/* ====================================================== DEVICE JOIN ANALYZER */
const DSREG_SAMPLES = [
  ["devicejoin-hybrid-healthy.txt", "Sample: healthy hybrid join"],
  ["devicejoin-hybrid-pending.txt", "Sample: pending hybrid (not synced)"],
  ["devicejoin-discovery-failure.txt", "Sample: discovery failure (proxy)"],
];

// Samples are static files with fixed dates. Shift every timestamp so the
// sample's anchor (Client Time, else the PRT update time) is 25 minutes ago.
function dsregShiftSample(text) {
  const anchor = (text.match(/Client Time\s*:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/) ||
    text.match(/AzureAdPrtUpdateTime\s*:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/) || [])[1];
  if (!anchor) return text;
  const toMs = (s) => Date.parse(s.replace(" ", "T") + "Z");
  const delta = Date.now() - 25 * 60000 - toMs(anchor);
  return text.replace(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/g, (m) => new Date(toMs(m) + delta).toISOString().slice(0, 19).replace("T", " "));
}

function dsregCodeLinks(codes) {
  if (!codes || !codes.length) return null;
  return el("div", { class: "sub", style: "margin-top:4px" }, "Look up: ",
    codes.map((c, i) => [i ? ", " : "", link("errcode", { q: c.code }, c.code), c.known ? "" : " (not in the knowledge base)"]));
}

function dsregCodeLink(txt) {
  if (!txt) return null;
  const m = txt.match(/0x[0-9a-f]{8}/i);
  return m ? link("errcode", { q: m[0] }, txt) : el("span", { class: "mono" }, txt);
}

function renderDsregTool(main) {
  const ta = el("textarea", { spellcheck: "false", placeholder: "Paste the full output of:  dsregcmd /status\n\nRun it as the affected user in a normal (NOT elevated) command prompt, so the SSO State / PRT section is that user's." });
  const out = el("div");
  const go = () => ta.value.trim() && runInto(out, "Analyzing…", () => api("/api/devicejoin/analyze", { body: { raw: ta.value } }), renderDsregResult);
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); });
  main.append(card(null, [ta,
    el("div", { class: "btn-row" },
      el("button", { class: "btn", type: "button", onclick: go }, "Analyze"),
      DSREG_SAMPLES.map(([file, label]) => el("button", { class: "btn secondary", type: "button", onclick: async () => {
        try { ta.value = dsregShiftSample(await (await fetch(`samples/${file}`)).text()); go(); } catch (e) { out.replaceChildren(el("div", { class: "error-box" }, e.message)); }
      } }, label)),
      el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; out.replaceChildren(); ta.focus(); } }, "Clear"),
      el("span", { class: "hint", style: "align-self:center" }, "Ctrl+Enter to run")),
    el("div", { class: "hint", style: "margin-top:8px" }, "dsregcmd output contains device and tenant IDs. It is analyzed by the MSPGather server and not stored.")]), out);
}

function renderDsregResult(d) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  frag.append(facts(d.facts.map(([k, v]) => [k, v && /ID$/.test(k) ? el("span", { class: "mono" }, v) : v])));
  const findings = d.findings.map((f) => {
    let detail = f.detail || null;
    const extras = [];
    if (f.codes && f.codes.length) extras.push(dsregCodeLinks(f.codes));
    if (/AADSTS/.test(f.detail || "") && d.diag.aadsts.length) extras.push(el("div", { class: "sub", style: "margin-top:4px" }, "Decode: ", d.diag.aadsts.map((c, i) => [i ? ", " : "", link("aadsts", { c }, c)])));
    if (extras.length) detail = el("div", {}, detail, extras);
    return { ...f, detail };
  });
  frag.append(card("Findings", findingsList(findings), { flush: true }));
  const st = nextSteps(d.steps); if (st) frag.append(st);

  // Join diagnostics (only when dsregcmd printed them: domain-joined devices that tried to hybrid join).
  const dg = d.diag;
  if (d.tests.length || dg.client_error || dg.server_error || dg.phase) {
    const parts = [];
    if (d.tests.length) {
      parts.push(table(["Pre-join test", "Result", "What it checks"], d.tests.map((t) => [t.name,
        el("div", {}, badge(t.status === "fail" ? "critical" : t.status === "pass" ? "ok" : "info", t.status === "other" ? t.value : t.status.toUpperCase()),
          t.codes.length ? el("span", {}, " ", t.codes.map((c, i) => [i ? " / " : "", link("errcode", { q: c.code }, c.code)])) : null),
        el("span", { class: "sub" }, t.why)]), (i) => (d.tests[i].status === "fail" ? "hl" : null)));
    }
    parts.push(el("div", { style: "padding:12px 16px" }, kv([
      ["Error phase", dg.phase ? `${dg.phase}${{ "pre-check": " (checks before joining)", precheck: " (checks before joining)", discover: " (finding the registration service: SCP in AD, then enterpriseregistration.windows.net)", auth: " (getting a token for the join)", join: " (the registration service processing the join)" }[dg.phase] || ""}` : null],
      ["Client error code", dsregCodeLink(dg.client_error)],
      ["Server error code", dg.server_error],
      ["Server message", dg.server_message],
      ["Registration type", dg.registration_type],
      ["Previous registration attempt", dg.previous_registration ? fmtTime(dg.previous_registration) : null],
    ])));
    frag.append(card("Hybrid join diagnostics", parts, { flush: true }));
  }

  if (d.prt && d.prt.present != null) {
    const p = d.prt;
    const ref = d.reference_is_client_time ? "the Client Time in the output" : "now";
    frag.append(card("SSO / Primary Refresh Token", kv([
      ["AzureAdPrt", badge(p.present ? (p.state === "ok" ? "ok" : p.state === "stale" ? "warning" : "critical") : "critical", p.present ? "YES" : "NO")],
      ["Last renewed", p.update ? el("span", {}, el("span", { class: "mono" }, fmtTime(p.update)), p.age_seconds != null ? el("span", { class: "sub" }, ` · ${fmtDuration(p.age_seconds)} before ${ref}`) : null) : null],
      ["Expires", p.expiry ? el("span", { class: "mono" }, fmtTime(p.expiry)) : null],
      ["Authority", p.authority ? el("span", { class: "mono dsreg-val" }, p.authority) : null],
      ["Last PRT attempt status", dg.prt_attempt_status ? dsregCodeLink(dg.prt_attempt_status) : null],
      ["AADSTS in the last attempt", dg.aadsts.length ? el("span", {}, dg.aadsts.map((c, i) => [i ? ", " : "", link("aadsts", { c }, c)])) : null],
    ])));
  }

  if (d.sections.length) {
    frag.append(card("Parsed dsregcmd output", el("div", { class: "dsreg-sec", style: "padding:12px 16px" }, d.sections.map((s) => [
      el("h3", {}, s.title),
      table(["Field", "Value"], s.rows.map(([k, v]) => [k, el("span", { class: "mono dsreg-val" }, v || "—")]), (i) => (s.bad.includes(i) ? "hl" : null)),
    ])), { flush: true }));
  }
  return frag;
}

/* ======================================================== IDENTITY CONVERTERS */
// Everything below runs in the browser; nothing is sent to the server.

/* ---------- byte helpers */
function idconvHexToBytes(h) {
  const out = [];
  for (let i = 0; i + 1 < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
  return out;
}
const idconvHex = (bytes, sep = "") => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(sep);
function idconvB64Encode(bytes) {
  let bin = ""; for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function idconvB64Decode(s) {
  let t = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (t.length % 4 === 1) return null;
  while (t.length % 4) t += "=";
  let bin;
  try { bin = atob(t); } catch (e) { return null; }
  return Array.from(bin, (c) => c.charCodeAt(0));
}
function idconvUtf8(bytes) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes)); } catch (e) { return null; }
}
// True when text is mostly printable (allows tabs/newlines).
function idconvPrintable(s) {
  if (s == null || !s.length) return false;
  let bad = 0;
  for (const ch of s) { const c = ch.codePointAt(0); if ((c < 32 && c !== 9 && c !== 10 && c !== 13) || c === 0xfffd || (c >= 0x7f && c < 0xa0)) bad++; }
  return bad / s.length < 0.05;
}
function idconvUtf16le(bytes) {
  if (bytes.length < 4 || bytes.length % 2) return null;
  let zeros = 0;
  for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
  if (zeros < bytes.length / 2 * 0.9) return null;
  const s = new TextDecoder("utf-16le").decode(new Uint8Array(bytes));
  return idconvPrintable(s) ? s : null;
}

/* ---------- GUID <-> bytes (Microsoft GUID layout: first three fields little-endian) */
const IDCONV_GUID_RE = /^\{?([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\}?$/i;
function idconvGuidToBytes(guid) {
  const h = guid.replace(/[{}-]/g, "").toLowerCase();
  const b = idconvHexToBytes(h);
  return [b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], ...b.slice(8)];
}
function idconvBytesToGuid(b) {
  const h = (idx) => idx.map((i) => b[i].toString(16).padStart(2, "0")).join("");
  return `${h([3, 2, 1, 0])}-${h([5, 4])}-${h([7, 6])}-${h([8, 9])}-${h([10, 11, 12, 13, 14, 15])}`;
}
const idconvLdapEscape = (bytes) => Array.from(bytes, (b) => "\\" + b.toString(16).padStart(2, "0")).join("");
// Entra ID objects map to SIDs S-1-12-1-a-b-c-d: the 16 GUID bytes read as four little-endian uint32s.
function idconvGuidToEntraSid(guid) {
  const b = idconvGuidToBytes(guid);
  const u = [0, 4, 8, 12].map((o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0);
  return `S-1-12-1-${u.join("-")}`;
}

/* ---------- SIDs */
const IDCONV_SID_WELLKNOWN = {
  "S-1-0-0": "Nobody", "S-1-1-0": "Everyone", "S-1-2-0": "Local", "S-1-2-1": "Console Logon", "S-1-3-0": "Creator Owner", "S-1-3-1": "Creator Group",
  "S-1-5-1": "NT AUTHORITY\\DIALUP", "S-1-5-2": "NT AUTHORITY\\NETWORK", "S-1-5-3": "NT AUTHORITY\\BATCH", "S-1-5-4": "NT AUTHORITY\\INTERACTIVE",
  "S-1-5-6": "NT AUTHORITY\\SERVICE", "S-1-5-7": "NT AUTHORITY\\ANONYMOUS LOGON", "S-1-5-9": "Enterprise Domain Controllers", "S-1-5-10": "Principal Self (SELF)",
  "S-1-5-11": "NT AUTHORITY\\Authenticated Users", "S-1-5-12": "Restricted Code", "S-1-5-13": "Terminal Server User", "S-1-5-14": "Remote Interactive Logon",
  "S-1-5-15": "This Organization", "S-1-5-17": "IUSR (IIS anonymous user)", "S-1-5-18": "NT AUTHORITY\\SYSTEM (Local System)", "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
  "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE", "S-1-5-113": "Local account", "S-1-5-114": "Local account and member of Administrators group",
  "S-1-5-32-544": "BUILTIN\\Administrators", "S-1-5-32-545": "BUILTIN\\Users", "S-1-5-32-546": "BUILTIN\\Guests", "S-1-5-32-547": "BUILTIN\\Power Users",
  "S-1-5-32-548": "BUILTIN\\Account Operators", "S-1-5-32-549": "BUILTIN\\Server Operators", "S-1-5-32-550": "BUILTIN\\Print Operators",
  "S-1-5-32-551": "BUILTIN\\Backup Operators", "S-1-5-32-552": "BUILTIN\\Replicator", "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
  "S-1-5-32-555": "BUILTIN\\Remote Desktop Users", "S-1-5-32-556": "BUILTIN\\Network Configuration Operators", "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
  "S-1-5-32-559": "BUILTIN\\Performance Log Users", "S-1-5-32-562": "BUILTIN\\Distributed COM Users", "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
  "S-1-5-32-569": "BUILTIN\\Cryptographic Operators", "S-1-5-32-573": "BUILTIN\\Event Log Readers", "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
  "S-1-5-32-580": "BUILTIN\\Remote Management Users",
  "S-1-5-80-0": "NT SERVICE\\ALL SERVICES",
  "S-1-16-0": "Untrusted Mandatory Level", "S-1-16-4096": "Low Mandatory Level", "S-1-16-8192": "Medium Mandatory Level", "S-1-16-8448": "Medium Plus Mandatory Level",
  "S-1-16-12288": "High Mandatory Level", "S-1-16-16384": "System Mandatory Level", "S-1-16-20480": "Protected Process Mandatory Level",
};
// Relative IDs under S-1-5-21-<domain or machine>-RID.
const IDCONV_RIDS = {
  498: "Enterprise Read-only Domain Controllers", 500: "Administrator (built-in account)", 501: "Guest (built-in account)", 502: "krbtgt (Kerberos service account)",
  503: "DefaultAccount", 504: "WDAGUtilityAccount",
  512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests", 515: "Domain Computers", 516: "Domain Controllers", 517: "Cert Publishers",
  518: "Schema Admins", 519: "Enterprise Admins", 520: "Group Policy Creator Owners", 521: "Read-only Domain Controllers", 522: "Cloneable Domain Controllers",
  525: "Protected Users", 526: "Key Admins", 527: "Enterprise Key Admins", 553: "RAS and IAS Servers", 571: "Allowed RODC Password Replication Group",
  572: "Denied RODC Password Replication Group",
};
const IDCONV_PRIV_RIDS = new Set([500, 502, 512, 516, 518, 519, 521, 526, 527]);

function idconvParseSidString(s) {
  const m = s.trim().match(/^S-1-(\d{1,15})((?:-\d{1,10}){0,15})$/i);
  if (!m) return null;
  const auth = Number(m[1]);
  const subs = m[2] ? m[2].slice(1).split("-").map(Number) : [];
  if (auth > 0xffffffffffff || subs.some((x) => x > 0xffffffff)) return null;
  return { auth, subs };
}
function idconvSidToBytes({ auth, subs }) {
  const b = [1, subs.length];
  for (let i = 5; i >= 0; i--) b.push(Math.floor(auth / 2 ** (8 * i)) % 256);
  for (const x of subs) b.push(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff);
  return b;
}
function idconvSidFromBytes(b) {
  if (!b || b.length < 8 || b[0] !== 1 || b[1] > 15 || b.length !== 8 + 4 * b[1]) return null;
  let auth = 0; for (let i = 2; i < 8; i++) auth = auth * 256 + b[i];
  const subs = [];
  for (let i = 0; i < b[1]; i++) { const o = 8 + 4 * i; subs.push((b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0); }
  return { auth, subs };
}
const idconvSidString = ({ auth, subs }) => `S-1-${auth}${subs.map((x) => "-" + x).join("")}`;

/** Describe a SID: {name, note, privileged}. Only well-known values; everything else is described structurally. */
function idconvDescribeSid(sid) {
  const s = idconvSidString(sid);
  if (IDCONV_SID_WELLKNOWN[s]) return { name: IDCONV_SID_WELLKNOWN[s], privileged: ["S-1-5-18", "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-551"].includes(s), note: "Well-known SID (the same on every Windows machine)." };
  const { auth, subs } = sid;
  if (auth === 5 && subs[0] === 21 && subs.length >= 4) {
    const domain = `S-1-5-21-${subs.slice(1, 4).join("-")}`;
    if (subs.length === 4) return { name: "Domain or computer SID (no RID)", note: `Identifies the domain or machine itself: ${domain}.` };
    const rid = subs[subs.length - 1];
    const known = IDCONV_RIDS[rid];
    if (known) return { name: known, rid, domain, privileged: IDCONV_PRIV_RIDS.has(rid),
      note: `Well-known RID ${rid} in domain/machine ${domain}.${rid >= 512 && rid !== 553 ? " Domain groups like this exist only in Active Directory, not on a standalone machine." : ""}${rid === 518 || rid === 519 || rid === 527 || rid === 498 ? " Exists only in the forest root domain." : ""}` };
    return { name: rid >= 1000 ? "A user, group or computer created in this domain/machine" : "Not a RID MSPGather knows", rid, domain,
      note: `RID ${rid} in ${domain}.${rid >= 1000 ? " RIDs from 1000 up are assigned to accounts as they're created; resolve the name with the commands below." : ""}` };
  }
  if (auth === 5 && subs[0] === 32) return { name: "Builtin (local) group not in MSPGather's list", note: "S-1-5-32-x are BUILTIN groups." };
  if (auth === 5 && subs[0] === 80) return { name: "Service SID (NT SERVICE\\<service name>)", note: "S-1-5-80-x is derived from a service's name (a hash), used to grant one service access." };
  if (auth === 5 && subs[0] === 5 && subs.length === 3) return { name: "Logon session SID", note: "Identifies a single logon session; changes every logon." };
  if (auth === 12 && subs[0] === 1 && subs.length === 5) {
    const bytes = [];
    for (const x of subs.slice(1)) bytes.push(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff);
    return { name: "Entra ID user or group", entraId: idconvBytesToGuid(bytes), note: "S-1-12-1-… SIDs represent Entra ID (Azure AD) objects on Entra-joined devices. The four numbers encode the object ID." };
  }
  if (auth === 15 && subs[0] === 2) return { name: "App container / package SID", note: "S-1-15-2-x identifies a Store app (AppContainer)." };
  if (auth === 15 && subs[0] === 3) return { name: "App capability SID", note: "S-1-15-3-x identifies an app capability." };
  if (auth === 16) return { name: "Mandatory integrity level (not in MSPGather's list)", note: "S-1-16-x are integrity levels." };
  return { name: "Not a SID MSPGather recognises", note: "Decoded structurally only." };
}

/* ---------- FILETIME / Integer8 and Unix time */
const IDCONV_EPOCH_MS = 11644473600000n; // ms between 1601-01-01 and 1970-01-01
const IDCONV_NEVER = 9223372036854775807n;
function idconvFiletimeToDate(ft) {
  const ms = ft / 10000n - IDCONV_EPOCH_MS;
  if (ms < -8640000000000000n || ms > 8640000000000000n) return null;
  return new Date(Number(ms));
}
const idconvDateToFiletime = (d) => (BigInt(d.getTime()) + IDCONV_EPOCH_MS) * 10000n;

/* ---------- userAccountControl */
const IDCONV_UAC = [
  [0x1, "SCRIPT", "Logon script runs (legacy)."],
  [0x2, "ACCOUNTDISABLE", "Account is disabled."],
  [0x8, "HOMEDIR_REQUIRED", "Home folder required."],
  [0x10, "LOCKOUT", "Locked out. Note: AD doesn't keep this bit current in userAccountControl; check lockoutTime or msDS-User-Account-Control-Computed."],
  [0x20, "PASSWD_NOTREQD", "No password required: the account may have an empty password regardless of the password policy."],
  [0x40, "PASSWD_CANT_CHANGE", "User can't change password. Note: this is really controlled by a permission on the object, not this bit."],
  [0x80, "ENCRYPTED_TEXT_PWD_ALLOWED", "Password stored with reversible encryption."],
  [0x100, "TEMP_DUPLICATE_ACCOUNT", "Local account for a user from another domain (legacy)."],
  [0x200, "NORMAL_ACCOUNT", "Normal user account."],
  [0x800, "INTERDOMAIN_TRUST_ACCOUNT", "Trust account for a domain that trusts this one."],
  [0x1000, "WORKSTATION_TRUST_ACCOUNT", "Computer account for a workstation or member server."],
  [0x2000, "SERVER_TRUST_ACCOUNT", "Computer account for a domain controller."],
  [0x10000, "DONT_EXPIRE_PASSWORD", "Password never expires."],
  [0x20000, "MNS_LOGON_ACCOUNT", "Majority Node Set (MNS) logon account."],
  [0x40000, "SMARTCARD_REQUIRED", "Smart card required for interactive logon."],
  [0x80000, "TRUSTED_FOR_DELEGATION", "Trusted for unconstrained Kerberos delegation."],
  [0x100000, "NOT_DELEGATED", "Account is sensitive and cannot be delegated."],
  [0x200000, "USE_DES_KEY_ONLY", "Kerberos may only use DES keys for this account."],
  [0x400000, "DONT_REQ_PREAUTH", "Kerberos pre-authentication not required."],
  [0x800000, "PASSWORD_EXPIRED", "Password has expired. Note: AD computes this in msDS-User-Account-Control-Computed rather than storing it here."],
  [0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION", "Trusted to authenticate for delegation (constrained delegation with protocol transition)."],
  [0x4000000, "PARTIAL_SECRETS_ACCOUNT", "Read-only domain controller (RODC) computer account."],
];
function idconvDecodeUac(v) {
  const flags = IDCONV_UAC.filter(([bit]) => (v & bit) !== 0);
  const knownMask = IDCONV_UAC.reduce((a, [bit]) => a | bit, 0);
  const unknown = v & ~knownMask;
  const has = (n) => flags.some((f) => f[1] === n);
  const isUser = has("NORMAL_ACCOUNT");
  const isDc = has("SERVER_TRUST_ACCOUNT");
  const type = isUser ? "normal account" : has("WORKSTATION_TRUST_ACCOUNT") ? "computer account" : isDc ? (has("PARTIAL_SECRETS_ACCOUNT") ? "read-only domain controller account" : "domain controller account") : has("INTERDOMAIN_TRUST_ACCOUNT") ? "trust account" : null;
  const F = [];
  if (has("DONT_REQ_PREAUTH")) F.push({ severity: "critical", title: "DONT_REQ_PREAUTH: Kerberos pre-authentication is off (AS-REP roastable)", detail: "Anyone can request a ticket for this account and crack its password offline. Turn it off unless an old application truly needs it: Set-ADAccountControl <account> -DoesNotRequirePreAuth $false" });
  if (has("TRUSTED_FOR_DELEGATION") && !isDc) F.push({ severity: isUser ? "critical" : "warning", title: `TRUSTED_FOR_DELEGATION on a ${isUser ? "user" : "non-DC computer"} account: unconstrained delegation`,
    detail: "Any user's Kerberos TGT sent to this account can be reused to impersonate them anywhere. Switch to constrained or resource-based constrained delegation: Set-ADAccountControl <account> -TrustedForDelegation $false" });
  if (has("PASSWD_NOTREQD")) F.push({ severity: "warning", title: "PASSWD_NOTREQD: the account isn't required to have a password", detail: "It may have an empty password. Set a password and clear the flag: Set-ADUser <account> -PasswordNotRequired $false" });
  if (has("USE_DES_KEY_ONLY")) F.push({ severity: "warning", title: "USE_DES_KEY_ONLY: Kerberos DES only", detail: "DES is broken and disabled by default since Windows 7 / Server 2008 R2, so Kerberos for this account will fail or be weak. Clear the flag: Set-ADAccountControl <account> -UseDESKeyOnly $false" });
  if (has("ENCRYPTED_TEXT_PWD_ALLOWED")) F.push({ severity: "warning", title: "ENCRYPTED_TEXT_PWD_ALLOWED: password stored with reversible encryption", detail: "The password can be recovered from AD. Clear it (Set-ADUser <account> -AllowReversiblePasswordEncryption $false) and reset the password." });
  if (has("TRUSTED_TO_AUTH_FOR_DELEGATION")) F.push({ severity: "info", title: "TRUSTED_TO_AUTH_FOR_DELEGATION: constrained delegation with protocol transition", detail: "The account can get tickets to its allowed services on behalf of any user without their password. Check msDS-AllowedToDelegateTo is as narrow as possible." });
  if (has("ACCOUNTDISABLE")) F.push({ severity: "info", title: "Account is disabled" });
  if (has("DONT_EXPIRE_PASSWORD") && isUser) F.push({ severity: "info", title: "Password never expires", detail: "Common for service accounts; consider a gMSA instead." });
  if (has("LOCKOUT") || has("PASSWORD_EXPIRED")) F.push({ severity: "info", title: "LOCKOUT / PASSWORD_EXPIRED bits are set in this value", detail: "AD normally reports these in msDS-User-Account-Control-Computed, not userAccountControl. If you read this value from that attribute, it is current." });
  if (unknown) F.push({ severity: "info", title: `Bits not in MSPGather's list: 0x${unknown.toString(16)}`, detail: "Decoded structurally only." });
  if (!type) F.push({ severity: "info", title: "No account-type bit is set", detail: "A real userAccountControl value normally includes NORMAL_ACCOUNT (0x200), WORKSTATION_TRUST_ACCOUNT (0x1000) or SERVER_TRUST_ACCOUNT (0x2000)." });
  const short = { ACCOUNTDISABLE: "disabled", DONT_EXPIRE_PASSWORD: "password never expires", PASSWD_NOTREQD: "no password required", DONT_REQ_PREAUTH: "no Kerberos pre-auth", SMARTCARD_REQUIRED: "smart card required",
    TRUSTED_FOR_DELEGATION: "trusted for delegation", TRUSTED_TO_AUTH_FOR_DELEGATION: "constrained delegation (protocol transition)", NOT_DELEGATED: "sensitive, cannot be delegated", LOCKOUT: "locked out",
    PASSWORD_EXPIRED: "password expired", USE_DES_KEY_ONLY: "DES only", ENCRYPTED_TEXT_PWD_ALLOWED: "reversible encryption", PASSWD_CANT_CHANGE: "can't change password" };
  const bits = flags.map((f) => short[f[1]]).filter(Boolean);
  if (!has("ACCOUNTDISABLE") && type && type !== "trust account") bits.unshift("enabled");
  return { flags, unknown, type, findings: F, summary: `${bits.join(" + ") || "no notable flags"}${type ? ` (${type})` : ""}` };
}

/* ---------- text decoders */
function idconvRfc2047(s) {
  const re = /=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g;
  if (!re.test(s)) return null;
  re.lastIndex = 0;
  let unsupported = null;
  // Whitespace between two adjacent encoded-words is dropped (RFC 2047 section 6.2).
  const out = s.replace(/(=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=)\s+(?==\?[^?\s]+\?[BbQq]\?)/g, "$1").replace(re, (_, cs, enc, txt) => {
    let bytes;
    if (enc.toUpperCase() === "B") bytes = idconvB64Decode(txt) || [];
    else {
      bytes = [];
      const t = txt.replace(/_/g, " ");
      for (let i = 0; i < t.length; i++) {
        if (t[i] === "=" && /^[0-9a-f]{2}$/i.test(t.slice(i + 1, i + 3))) { bytes.push(parseInt(t.slice(i + 1, i + 3), 16)); i += 2; } else bytes.push(t.charCodeAt(i) & 0xff);
      }
    }
    const charset = cs.split("*")[0];
    try { return new TextDecoder(charset).decode(new Uint8Array(bytes)); } catch (e) { unsupported = charset; return new TextDecoder("utf-8").decode(new Uint8Array(bytes)); }
  });
  return { text: out, unsupported };
}
function idconvQuotedPrintable(s) {
  if (!/=[0-9A-F]{2}/.test(s) && !/=\r?\n/.test(s)) return null;
  const t = s.replace(/=\r?\n/g, "");
  const bytes = [];
  for (let i = 0; i < t.length; i++) {
    if (t[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(t.slice(i + 1, i + 3))) { bytes.push(parseInt(t.slice(i + 1, i + 3), 16)); i += 2; }
    else { const enc = new TextEncoder().encode(t[i]); bytes.push(...enc); }
  }
  const utf8 = idconvUtf8(bytes);
  return utf8 != null ? { text: utf8, charset: "UTF-8" } : { text: new TextDecoder("windows-1252").decode(new Uint8Array(bytes)), charset: "Windows-1252 (not valid UTF-8)" };
}
function idconvUrlDecode(s) {
  if (!/%[0-9a-f]{2}/i.test(s)) return null;
  const layers = [];
  let cur = s;
  for (let i = 0; i < 4 && /%[0-9a-f]{2}/i.test(cur); i++) {
    let next;
    try { next = decodeURIComponent(cur); } catch (e) { next = cur.replace(/%([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))); }
    if (next === cur) break;
    layers.push(next); cur = next;
  }
  return layers.length ? layers : null;
}

/* ---------- detection: returns a list of interpretations, most likely first.
   Each: {kind, title, sev, verdict, sub?, rows: [[label, value(string) | {text, copy:false} ]], findings?, steps?, note?} */
function idconvAnalyze(input, now = new Date()) {
  const raw = input.replace(/^﻿/, "");
  const s = raw.trim();
  const R = [];
  if (!s) return R;
  const compact = s.replace(/\s+/g, "");

  // ---- SID string
  const sidStr = idconvParseSidString(s);
  if (sidStr) R.push(idconvSidResult(sidStr, "SID"));

  // ---- GUID string
  if (IDCONV_GUID_RE.test(s)) R.push(idconvGuidResult(s.replace(/[{}]/g, "").toLowerCase(), "objectGUID / GUID"));

  // ---- hex bytes (spaced, \-escaped, 0x-prefixed or plain)
  const hexClean = s.replace(/^0x/i, "").replace(/\\x|\\|0x|[\s:,-]/gi, "");
  const looksHex = /^[0-9a-f]+$/i.test(hexClean) && hexClean.length % 2 === 0 && hexClean.length >= 4 && !/^\d+$/.test(s) && !IDCONV_GUID_RE.test(s);
  if (looksHex) {
    const bytes = idconvHexToBytes(hexClean);
    if (bytes.length === 16) {
      R.push(idconvGuidResult(idconvBytesToGuid(bytes), "16 bytes in AD/LDAP byte order (objectGUID or ms-DS-ConsistencyGuid as shown by ADSI Edit)"));
      if (!/[\s\\:]/.test(s)) R.push({ ...idconvGuidResult(`${hexClean.slice(0, 8)}-${hexClean.slice(8, 12)}-${hexClean.slice(12, 16)}-${hexClean.slice(16, 20)}-${hexClean.slice(20)}`.toLowerCase(), "a GUID written without dashes"), secondary: true });
    }
    const sid = idconvSidFromBytes(bytes);
    if (sid) R.push(idconvSidResult(sid, "binary SID (hex)"));
    const txt = idconvUtf8(bytes);
    if (txt != null && idconvPrintable(txt) && bytes.length !== 16 && !sid) R.push({ kind: "hex", title: "Hex → text", sev: "info", verdict: `Hex decodes to text: “${txt.length > 80 ? txt.slice(0, 80) + "…" : txt}”`,
      rows: [["Text (UTF-8)", { pre: txt }], ["Bytes", String(bytes.length)]] });
  }

  // ---- base64 (incl. base64url)
  const isDate = /^\d{4}-\d{2}-\d{2}/.test(s);
  const b64ish = /^[A-Za-z0-9+/_-]+={0,2}$/.test(compact) && compact.length >= 8 && !/^\d+$/.test(compact) && !looksHex && !sidStr && !IDCONV_GUID_RE.test(s) && !isDate;
  if (b64ish) {
    const bytes = idconvB64Decode(compact);
    if (bytes && bytes.length) {
      if (bytes.length === 16) R.push(idconvGuidResult(idconvBytesToGuid(bytes), "ImmutableId / sourceAnchor (base64 of 16 bytes)", compact));
      const sid = idconvSidFromBytes(bytes);
      if (sid) R.push(idconvSidResult(sid, "binary SID (base64, e.g. objectSid from an LDIF export)"));
      if (bytes.length !== 16 && !sid) {
        const u16 = idconvUtf16le(bytes);
        const txt = idconvUtf8(bytes);
        if (u16) R.push({ kind: "b64", title: "Base64 → text (UTF-16LE)", sev: "info", verdict: "Base64 of UTF-16LE text (the format PowerShell -EncodedCommand uses)",
          sub: "Review decoded scripts carefully before running anything.", rows: [["Text", { pre: u16 }], ["Bytes", String(bytes.length)]] });
        else if (txt != null && idconvPrintable(txt)) R.push({ kind: "b64", title: "Base64 → text", sev: "info", verdict: `Base64 decodes to text: “${txt.length > 80 ? txt.slice(0, 80) + "…" : txt}”`,
          rows: [["Text (UTF-8)", { pre: txt }], ["Bytes", String(bytes.length)], ["Hex", idconvHex(bytes.slice(0, 512), " ") + (bytes.length > 512 ? " …" : "")]] });
        else if (/[+/=]/.test(compact) || compact.length >= 16) R.push({ kind: "b64", title: "Base64 → binary", sev: "info", verdict: `Base64 decodes to ${bytes.length} bytes of binary data (not text)`,
          rows: [["Hex", idconvHex(bytes.slice(0, 1024), " ") + (bytes.length > 1024 ? " …" : "")], ["Bytes", String(bytes.length)], ["First bytes as text", idconvLatinPreview(bytes.slice(0, 64))]] });
      }
    }
  }

  // ---- integers: FILETIME, Unix time, userAccountControl
  if (/^-?\d{1,20}$/.test(s)) R.push(...idconvIntegerResults(BigInt(s), now));
  else if (/^0x[0-9a-f]{1,8}$/i.test(s)) {
    const v = parseInt(s, 16);
    if (v < 0x8000000) R.push(idconvUacResult(v));
    if (v >= 0x80000000) R.push({ kind: "code", title: "Error code?", sev: "info", verdict: `${s} looks like an error code (HRESULT / NTSTATUS), not a userAccountControl value`, rows: [], link: s });
  }

  // ---- dates → FILETIME / Unix
  const dm = s.match(/^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?))?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i);
  if (dm) {
    const zone = dm[3] ? (/^(Z|UTC|GMT)$/i.test(dm[3]) ? "Z" : dm[3].replace(/^([+-]\d{2})(\d{2})$/, "$1:$2")) : "Z";
    const d = new Date(`${dm[1]}T${dm[2] || "00:00:00"}${zone}`);
    if (!isNaN(d)) R.push(idconvDateResult(d, !dm[3]));
  }

  // ---- text decoders
  const r2047 = idconvRfc2047(s);
  if (r2047) R.push({ kind: "rfc2047", title: "RFC 2047 encoded-words (email header)", sev: "info", verdict: `Email header decodes to: “${r2047.text.length > 90 ? r2047.text.slice(0, 90) + "…" : r2047.text}”`,
    sub: r2047.unsupported ? `Charset ${r2047.unsupported} isn't supported by this browser; decoded as UTF-8.` : null, rows: [["Decoded", { pre: r2047.text }]] });
  const url = idconvUrlDecode(s);
  if (url) R.push({ kind: "url", title: "URL decoding", sev: "info", verdict: url.length > 1 ? `URL-encoded ${url.length} times; fully decoded below` : "URL-decoded",
    sub: /\+/.test(s) ? "'+' was left as-is. In a query string (form encoding) '+' means a space." : null,
    rows: url.map((u, i) => [url.length > 1 ? `Decoded (pass ${i + 1})` : "Decoded", { pre: u }]), extra: url[url.length - 1] });
  if (!r2047) {
    const qp = idconvQuotedPrintable(raw);
    if (qp && /=[0-9A-F]{2}|=\r?\n/.test(raw) && !url) R.push({ kind: "qp", title: "Quoted-printable", sev: "info", verdict: "Quoted-printable decoded", sub: `Interpreted as ${qp.charset}.`, rows: [["Decoded", { pre: qp.text }]] });
  }

  // ---- fallback: encode the text
  if (!R.length || R.every((r) => r.secondary)) {
    const bytes = Array.from(new TextEncoder().encode(raw.replace(/\r?\n$/, "")));
    R.push({ kind: "encode", title: "Encode text", sev: "info", verdict: "Not an ID, SID, timestamp or encoded value MSPGather recognises, so here it is encoded",
      rows: [["Base64 (UTF-8)", idconvB64Encode(bytes)], ["Base64 (UTF-16LE, for PowerShell -EncodedCommand)", idconvB64Encode(idconvUtf16Units(raw.replace(/\r?\n$/, "")))],
        ["URL-encoded", encodeURIComponent(raw.replace(/\r?\n$/, ""))], ["Hex (UTF-8)", idconvHex(bytes.slice(0, 2048), " ")]] });
  }
  return R;
}
function idconvUtf16Units(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) { const c = str.charCodeAt(i); out.push(c & 0xff, c >> 8); }
  return out;
}
const idconvLatinPreview = (bytes) => bytes.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");

function idconvGuidResult(guid, what, b64In) {
  const bytes = idconvGuidToBytes(guid);
  const b64 = idconvB64Encode(bytes);
  const hex = idconvHex(bytes);
  const fromB64 = !!b64In;
  return {
    kind: "guid", title: fromB64 ? "ImmutableId → objectGUID" : "GUID → ImmutableId", sev: "info",
    verdict: fromB64 ? `ImmutableId ${b64In} = objectGUID ${guid}` : `objectGUID ${guid} = ImmutableId ${b64}`,
    sub: `Input read as ${what}. The ImmutableId (Entra ID onPremisesImmutableId) is the base64 of the GUID's 16 bytes in Windows byte order (first three groups reversed).`,
    rows: [["objectGUID", guid], ["ImmutableId / sourceAnchor (base64)", b64], ["ms-DS-ConsistencyGuid / bytes (hex)", hex], ["Bytes (spaced)", idconvHex(bytes, " ")],
      ["LDAP filter escape", idconvLdapEscape(bytes)], ["Entra SID form (only if this GUID is an Entra object ID)", idconvGuidToEntraSid(guid)]],
    steps: [
      { title: "Find the on-premises AD user for this ImmutableId", commands: [
        `Get-ADUser -Identity "${guid}" -Properties mS-DS-ConsistencyGuid, UserPrincipalName   # if the sourceAnchor is objectGUID`,
        `Get-ADUser -LDAPFilter "(mS-DS-ConsistencyGuid=${idconvLdapEscape(bytes)})" -Properties UserPrincipalName   # if the sourceAnchor is ms-DS-ConsistencyGuid`] },
      { title: "Hard-match: set the cloud user's ImmutableId to this AD user",
        detail: "Use when Entra Connect created a duplicate or won't match an existing cloud user. Graph PowerShell has no Set-MgUser: Update-MgUser replaces Set-MsolUser -ImmutableId. If the user's UPN is in a federated domain, Graph may refuse the change; switch the UPN to the .onmicrosoft.com domain first. Then run a sync cycle.",
        commands: [`Connect-MgGraph -Scopes "User.ReadWrite.All"`,
          `Update-MgUser -UserId "meganb@contoso.com" -OnPremisesImmutableId "${b64}"   # replace the UPN`,
          `Get-MgUser -UserId "meganb@contoso.com" -Property OnPremisesImmutableId | Select-Object OnPremisesImmutableId`,
          "Start-ADSyncSyncCycle -PolicyType Delta   # on the Entra Connect server"] },
      { title: "Or match from the AD side: write this value into ms-DS-ConsistencyGuid",
        detail: "When the sourceAnchor is ms-DS-ConsistencyGuid, setting it on the AD user to the cloud user's ImmutableId makes the next sync match them.",
        commands: [`Set-ADUser jsmith -Replace @{'mS-DS-ConsistencyGuid' = ([guid]'${guid}').ToByteArray()}   # replace jsmith`,
          `[Convert]::ToBase64String((Get-ADUser jsmith).ObjectGUID.ToByteArray())   # ImmutableId of an AD user (objectGUID anchor)`] },
    ],
  };
}

function idconvSidResult(sid, what) {
  const str = idconvSidString(sid);
  const bytes = idconvSidToBytes(sid);
  const desc = idconvDescribeSid(sid);
  const F = [];
  if (desc.privileged) F.push({ severity: "info", title: `${desc.name} is a privileged identity`, detail: "Membership or rights granted to it are high impact." });
  const rows = [["SID", str], ["Name", desc.name], ["Binary (hex)", idconvHex(bytes)], ["Base64 (objectSid as exported by LDIF / PowerShell)", idconvB64Encode(bytes)],
    ["LDAP filter escape", idconvLdapEscape(bytes)]];
  if (desc.rid != null) rows.push(["RID", String(desc.rid)], ["Domain / machine SID", desc.domain]);
  if (desc.entraId) rows.push(["Entra object ID", desc.entraId]);
  const steps = [{ title: "Resolve the SID to a name", commands: [
    `([System.Security.Principal.SecurityIdentifier]'${str}').Translate([System.Security.Principal.NTAccount]).Value`,
    `Get-ADObject -Filter "objectSid -eq '${str}'" -Properties sAMAccountName   # Active Directory`] }];
  if (desc.entraId) steps.push({ title: "Look up the Entra object", commands: [`Get-MgDirectoryObject -DirectoryObjectId ${desc.entraId}`] });
  return { kind: "sid", title: "SID", sev: "info",
    verdict: `${str} = ${desc.name}${desc.rid != null && IDCONV_RIDS[desc.rid] ? ` (RID ${desc.rid})` : ""}`,
    sub: `Input read as ${what}. ${desc.note}`, rows, findings: F, steps };
}

function idconvRel(d, now) {
  const s = (d.getTime() - now.getTime()) / 1000;
  return s >= 0 ? `in ${fmtDuration(s)}` : `${fmtDuration(-s)} ago`;
}
function idconvDateRows(d, now) {
  const tz = (Intl.DateTimeFormat().resolvedOptions().timeZone) || "local";
  return [["UTC", d.toISOString().replace("T", " ").replace(/\.000Z$/, "Z").replace(/Z$/, " UTC")], [`Local (${tz})`, d.toLocaleString()], ["Relative", idconvRel(d, now)]];
}
function idconvIntegerResults(n, now) {
  const R = [];
  if (n === 0n) {
    R.push({ kind: "filetime", title: "Integer8 (FILETIME): 0", sev: "info", verdict: "0 = never / not set", rows: [],
      findings: [{ severity: "info", title: "pwdLastSet = 0: the user must change their password at next logon" },
        { severity: "info", title: "accountExpires = 0: the account never expires" },
        { severity: "info", title: "lastLogonTimestamp / lastLogon = 0: never logged on (as far as this DC knows)" }] });
    return R;
  }
  if (n === IDCONV_NEVER) {
    R.push({ kind: "filetime", title: "Integer8 (FILETIME): max value", sev: "info", verdict: "9223372036854775807 = never (accountExpires: the account never expires)", rows: [["Hex", "0x7FFFFFFFFFFFFFFF"]] });
    return R;
  }
  if (n < 0n) {
    if (n >= -2147483648n && n <= -268435456n) R.push({ kind: "code", title: "Error code?", sev: "info", verdict: `${n} looks like a signed error code (HRESULT / NTSTATUS)`, rows: [["Hex", "0x" + ((Number(n) >>> 0).toString(16).toUpperCase().padStart(8, "0"))]], link: "0x" + ((Number(n) >>> 0).toString(16).toUpperCase().padStart(8, "0")) });
    return R;
  }
  const digits = n.toString().length;
  if (digits >= 15) {
    const d = idconvFiletimeToDate(n);
    if (d) R.push({ kind: "filetime", title: "Windows FILETIME / Integer8", sev: "info",
      verdict: `${n} = ${d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC")} (${idconvRel(d, now)})`,
      sub: "100-nanosecond intervals since 1601-01-01 UTC: the format of pwdLastSet, lastLogonTimestamp, accountExpires, badPasswordTime and lockoutTime.",
      rows: [...idconvDateRows(d, now), ["Unix seconds", String(Math.floor(d.getTime() / 1000))]],
      findings: [{ severity: "info", title: "If this is lastLogonTimestamp: it can be up to about 14 days behind", detail: "lastLogonTimestamp replicates only when it's older than msDS-LogonTimeSyncInterval (default 14 days, randomised). For the exact last logon, query lastLogon on every DC." }],
      steps: [{ title: "Cross-check on Windows", commands: [`w32tm /ntte ${n}`, `[DateTime]::FromFileTimeUtc(${n})`] }] });
  }
  if (digits >= 12 && digits <= 14) {
    const d = new Date(Number(n));
    if (!isNaN(d)) R.push({ kind: "unix", title: "Unix time (milliseconds)", sev: "info", verdict: `${n} ms = ${d.toISOString().replace("T", " ").replace(/Z$/, " UTC")} (${idconvRel(d, now)})`,
      sub: "Milliseconds since 1970-01-01 UTC (JavaScript, many APIs and logs).", rows: [...idconvDateRows(d, now), ["FILETIME", idconvDateToFiletime(d).toString()]] });
  }
  if (digits >= 9 && digits <= 11) {
    const d = new Date(Number(n) * 1000);
    if (!isNaN(d)) R.push({ kind: "unix", title: "Unix time (seconds)", sev: "info", verdict: `${n} = ${d.toISOString().replace("T", " ").replace(/\.000Z$/, " UTC")} (${idconvRel(d, now)})`,
      sub: "Seconds since 1970-01-01 UTC (JWT exp/iat/nbf, Linux, many APIs).", rows: [...idconvDateRows(d, now), ["FILETIME", idconvDateToFiletime(d).toString()]] });
  }
  if (n < 0x8000000n) R.push(idconvUacResult(Number(n)));
  return R;
}

function idconvUacResult(v) {
  const u = idconvDecodeUac(v);
  return { kind: "uac", title: "userAccountControl", sev: u.findings.some((f) => f.severity === "critical") ? "critical" : u.findings.some((f) => f.severity === "warning") ? "warning" : "info",
    verdict: `UAC ${v} = ${u.summary}.`, sub: `0x${v.toString(16).toUpperCase()} · ${u.flags.length} flag${u.flags.length === 1 ? "" : "s"} set. If this number isn't a userAccountControl value, ignore this interpretation.`,
    flags: u.flags, rows: [["Hex", "0x" + v.toString(16).toUpperCase()]], findings: u.findings,
    steps: [{ title: "Read the live value (and the computed lockout / expiry bits)", commands: [
      "Get-ADUser jsmith -Properties userAccountControl, msDS-User-Account-Control-Computed, lockoutTime | Select-Object Name, userAccountControl, msDS-User-Account-Control-Computed, lockoutTime   # replace jsmith",
      'Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"   # every account with DONT_REQ_PREAUTH',
      'Get-ADObject -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))"   # unconstrained delegation, excluding DCs'] }] };
}

function idconvDateResult(d, assumedUtc) {
  const ft = idconvDateToFiletime(d);
  return { kind: "date", title: "Date → FILETIME / Unix", sev: "info", verdict: `${d.toISOString().replace("T", " ").replace(/\.000Z$/, " UTC")} = FILETIME ${ft}`,
    sub: assumedUtc ? "No time zone was given, so the date was read as UTC." : null,
    rows: [["FILETIME / Integer8", ft.toString()], ["Unix seconds", String(Math.floor(d.getTime() / 1000))], ["Unix milliseconds", String(d.getTime())], ...idconvDateRows(d, new Date())],
    steps: [{ title: "Use it in an AD query", commands: [`Get-ADUser -LDAPFilter "(pwdLastSet<=${ft})" -Properties pwdLastSet   # passwords last set before this date`,
      `Get-ADComputer -LDAPFilter "(lastLogonTimestamp<=${ft})" -Properties lastLogonTimestamp   # computers not seen since (approx.)`] }] };
}

/* ---------- rendering */
function idconvVal(v) {
  if (v && typeof v === "object" && v.pre != null) {
    return el("div", {}, el("pre", { class: "mono idconvert-pre" }, v.pre), idconvCopyBtn(v.pre));
  }
  return el("span", {}, el("span", { class: "mono idconvert-val" }, v), idconvCopyBtn(String(v)));
}
function idconvCopyBtn(text) {
  const btn = el("button", { class: "icon-btn copy idconvert-copy", type: "button" }, "Copy");
  btn.addEventListener("click", () => copyText(text, btn));
  return btn;
}

function idconvRender(results) {
  const frag = el("div");
  if (!results.length) return frag;
  const main = results[0];
  const others = results.length > 1 ? `Also could be: ${results.slice(1).map((r) => r.title).join(", ")} (below).` : null;
  frag.append(verdict(main.sev, main.verdict, [main.sub, others].filter(Boolean).join(" ")));
  const allF = main.findings || [];
  if (allF.length) frag.append(card("Findings", findingsList(allF), { flush: true }));
  results.forEach((r, i) => {
    const body = [];
    if (i > 0) body.push(el("p", { style: "margin:0 0 8px", class: "sub" }, r.verdict, r.sub ? ` ${r.sub}` : ""));
    if (r.flags) body.push(table(["Bit", "Flag", "Meaning"], r.flags.map(([bit, name, mean]) => [el("span", { class: "mono" }, `0x${bit.toString(16).toUpperCase()}`), el("span", { class: "mono" }, name), mean]),
      (k) => (["DONT_REQ_PREAUTH", "PASSWD_NOTREQD", "USE_DES_KEY_ONLY", "ENCRYPTED_TEXT_PWD_ALLOWED"].includes(r.flags[k][1]) || (r.flags[k][1] === "TRUSTED_FOR_DELEGATION" && !r.flags.some((f) => f[1] === "SERVER_TRUST_ACCOUNT")) ? "hl" : null)));
    if (r.rows.length) body.push(kv(r.rows.map(([k, v]) => [k, idconvVal(v)])));
    if (r.link) body.push(el("p", {}, "Look it up: ", link("errcode", { q: r.link }, r.link)));
    if (i > 0 && r.findings && r.findings.length) body.push(findingsList(r.findings));
    frag.append(card(r.title, body));
    if (r.steps && i === 0) { const st = nextSteps(r.steps); if (st) frag.append(st); }
    else if (r.steps) { const st = nextSteps(r.steps, `Commands: ${r.title}`); if (st) frag.append(st); }
  });
  return frag;
}

function renderIdconvertTool(main, params) {
  const ta = el("textarea", { spellcheck: "false", style: "min-height:110px",
    placeholder: "Paste one value:\n• objectGUID 25892e17-80f6-415f-9c65-7395632f0223 or ImmutableId Fy6JJfaAX0GcZXOVYy8CIw==\n• SID S-1-5-21-…-512, or a binary SID in hex/base64\n• FILETIME 133… (pwdLastSet, lastLogonTimestamp, accountExpires), Unix time, or a date\n• userAccountControl 66050 or 0x10202\n• Base64, URL-encoded, =?utf-8?B?…?= / =?utf-8?Q?…?=, quoted-printable or hex text" });
  if (params.get("q")) ta.value = params.get("q");
  const out = el("div");
  const go = () => {
    if (!ta.value.trim()) { out.replaceChildren(); return; }
    try { out.replaceChildren(idconvRender(idconvAnalyze(ta.value))); } catch (e) { out.replaceChildren(el("div", { class: "error-box" }, e.message || String(e))); }
  };
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); go(); } });
  const ex = (label, v) => el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = v; go(); } }, label);
  main.append(
    el("div", { class: "notice" }, "Runs entirely in your browser: nothing you paste here is sent to the MSPGather server."),
    card(null, [ta, el("div", { class: "btn-row" },
      el("button", { class: "btn", type: "button", onclick: go }, "Convert"),
      ex("GUID", "25892e17-80f6-415f-9c65-7395632f0223"), ex("ImmutableId", "Fy6JJfaAX0GcZXOVYy8CIw=="), ex("SID", "S-1-5-21-1004336348-1177238915-682003330-512"),
      ex("FILETIME", "133933824000000000"), ex("UAC", "66050"), ex("Encoded header", "=?utf-8?B?UmU6IENvbnRvc28gaW52b2ljZSDigJMgSnVuZQ==?="),
      el("button", { class: "btn secondary", type: "button", onclick: () => { ta.value = ""; out.replaceChildren(); ta.focus(); } }, "Clear"),
      el("span", { class: "hint", style: "align-self:center" }, "Ctrl+Enter to run"))]),
    out);
  if (ta.value.trim()) go();
}

/* ============================================================== REGISTRATION */
registerTool({ category: "identity", group: "Devices", id: "dsreg", title: "Device Join Analyzer", render: renderDsregTool,
  icon: "M4 5h16v10H4zM9 19h6M12 15v4",
  keywords: "dsregcmd dsregcmd /status hybrid join entra join azure ad join aadj haadj workplace join registered prt primary refresh token sso device registration pending 0x801c001f 0x801c0021 0x801c03f2 0x801c001d winhttp proxy intune mdm enrollment",
  desc: "Paste dsregcmd /status: tells you the join type (Entra, hybrid, pending, registered), whether the user has a working PRT, and why a hybrid join is failing (discovery, auth or join phase), with the fix." });
registerTool({ category: "identity", group: "Converters", id: "idconvert", title: "Identity Converters", render: renderIdconvertTool,
  icon: "M4 8h13l-3-3M20 16H7l3 3",
  keywords: "immutableid sourceanchor objectguid ms-ds-consistencyguid hard match soft match guid base64 sid well-known rid filetime integer8 pwdlastset lastlogontimestamp accountexpires unix epoch timestamp useraccountcontrol uac flags as-rep url decode rfc 2047 encoded-word quoted-printable hex",
  desc: "Convert ImmutableId ↔ objectGUID, SIDs, FILETIME / Unix timestamps and userAccountControl flags, and decode Base64, URL, RFC 2047 and quoted-printable text. Runs in your browser." });
