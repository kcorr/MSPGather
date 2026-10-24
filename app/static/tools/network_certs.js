"use strict";
/* Certificates: Certificate & CSR Decoder. Paste PEM / base64 DER / PKCS#7 certificates and CSRs.
   Backend: app/modules/certdecode.py (/api/cert/...). Decoding is offline; only "Fetch missing intermediate"
   goes out to the internet (AIA URL, public addresses only). Private keys are refused server-side. */

addStyles(`
.certdecode-host { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin-top: 10px; }
.certdecode-host .field { flex: 0 1 340px; }
.certdecode-cert { border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; margin-bottom: 10px; }
.certdecode-cert:last-child { margin-bottom: 0; }
.certdecode-cert.bad { border-color: var(--crit); background: var(--crit-soft); }
.certdecode-cert.missing { border: 2px dashed var(--crit); background: var(--crit-soft); }
.certdecode-cert.warn { border: 2px dashed var(--warn); background: var(--warn-soft); }
.certdecode-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 8px; font-weight: 650; }
.certdecode-n { width: 22px; height: 22px; border-radius: 50%; background: var(--panel); border: 1px solid var(--border); display: inline-grid; place-items: center; font-size: 12px; flex: none; }
.certdecode-arrow { color: var(--muted); text-align: center; margin: -4px 0 6px; font-size: 12px; }
.certdecode-mono { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
.certdecode-fetch { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
`);

const certdecodeMono = (t) => (t ? el("span", { class: "certdecode-mono" }, t) : null);

function certdecodeDays(days, expired) {
  if (expired) return badge("critical", `expired ${-days}d ago`);
  if (days < 7) return badge("critical", `${days}d left`);
  if (days < 30) return badge("warning", `${days}d left`);
  return badge("ok", `${days}d left`);
}

function certdecodeSans(s) {
  if (!s) return null;
  const parts = [];
  if (s.dns && s.dns.length) parts.push(["DNS", s.dns]);
  if (s.ip && s.ip.length) parts.push(["IP", s.ip]);
  if (s.email && s.email.length) parts.push(["Email", s.email]);
  if (s.upn && s.upn.length) parts.push(["UPN", s.upn]);
  if (s.uri && s.uri.length) parts.push(["URI", s.uri]);
  if (!parts.length) return null;
  const total = parts.reduce((n, [, v]) => n + v.length, 0);
  const body = parts.map(([k, v]) => el("div", {}, el("strong", {}, `${k}: `), certdecodeMono(v.join(", "))));
  return total > 12 ? el("details", {}, el("summary", {}, `${total} names`), body) : body;
}

function certdecodeUrls(list) {
  if (!list || !list.length) return null;
  return list.map((u) => el("div", {}, certdecodeMono(u)));
}

function certdecodeCertKv(c) {
  const eku = c.eku ? c.eku.map((e) => (e.oid === "1.3.6.1.5.5.7.3.1" ? el("strong", {}, e.name) : e.name))
    .flatMap((x, i) => (i ? [", ", x] : [x])) : "not restricted (no EKU extension)";
  return kv([
    ["Subject", certdecodeMono(c.subject)],
    ["Issuer", certdecodeMono(c.issuer)],
    ["Names (SAN)", certdecodeSans(c.san) || (c.is_ca ? null : "none (CN only)")],
    ["Valid", el("span", {}, `${fmtTime(c.not_before)} → ${fmtTime(c.not_after)} `, certdecodeDays(c.days_left, c.expired))],
    ["Key", c.key && c.key.text],
    ["Signature", c.signature],
    ["Key usage", c.key_usage ? c.key_usage.join(", ") : null],
    ["Extended key usage", c.is_ca && !c.eku ? null : [eku, " ", c.server_auth === false ? badge("warning", "no Server Auth") : c.server_auth ? badge("ok", "Server Auth") : null]],
    ["Basic constraints", c.is_ca ? `CA${c.path_length != null ? ` (path length ${c.path_length})` : ""}` : "end entity (not a CA)"],
    ["CA issuers (AIA)", certdecodeUrls(c.ca_issuers)],
    ["OCSP", certdecodeUrls(c.ocsp)],
    ["CRL distribution", certdecodeUrls(c.crl)],
    ["Self-signed", c.self_signed ? "yes" : null],
    ["Serial", certdecodeMono(c.serial)],
    ["SHA-1 thumbprint", certdecodeMono(c.sha1)],
    ["SHA-256", certdecodeMono(c.sha256)],
    ["Source", c.source],
  ]);
}

function certdecodeCertBox(c, n, isLeaf) {
  const issues = [];
  if (c.expired) issues.push(badge("critical", "expired"));
  else if (c.not_yet_valid) issues.push(badge("critical", "not yet valid"));
  else if (!c.self_signed || isLeaf) issues.push(certdecodeDays(c.days_left, false));
  if (isLeaf && c.self_signed && !c.is_ca) issues.push(badge("warning", "self-signed"));
  const weak = c.key && c.key.type === "RSA" && c.key.bits < 2048;
  if (weak) issues.push(badge("critical", "weak key"));
  if ((c.signature_hash === "sha1" || c.signature_hash === "md5") && !c.self_signed) issues.push(badge("critical", c.signature_hash.toUpperCase()));
  const bad = c.expired || c.not_yet_valid || weak;
  return el("div", { class: "certdecode-cert" + (bad ? " bad" : "") },
    el("div", { class: "certdecode-head" }, el("span", { class: "certdecode-n" }, String(n)), c.label, badge("info", c.role), issues),
    certdecodeCertKv(c));
}

function certdecodeFetchBox(m, ctx) {
  const status = el("span", { class: "hint" });
  const btn = el("button", { class: "btn secondary", type: "button" }, m.likely_root ? "Fetch issuer certificate" : "Fetch missing intermediate");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    status.textContent = "Downloading from the AIA URL…";
    try {
      const r = await api("/api/cert/fetch", { body: { url: m.aia_url } });
      status.textContent = `Got ${r.certs.map((c) => c.subject_short).join(", ")}. Added to the paste box and re-checking…`;
      ctx.textarea.value = ctx.textarea.value.replace(/\s*$/, "\n") + r.pem;
      ctx.run(ctx.textarea.value);
    } catch (e) {
      status.textContent = e.message || String(e);
      btn.disabled = false;
    }
  });
  return el("div", { class: "certdecode-fetch" }, btn, status,
    el("span", { class: "hint" }, "Downloads only the public CA certificate, from this server, public addresses only."));
}

function certdecodeChain(d, ctx) {
  const items = [];
  d.chain.forEach((idx, pos) => {
    if (pos > 0) items.push(el("div", { class: "certdecode-arrow" }, "↑ signed by"));
    items.push(certdecodeCertBox(d.certs[idx], pos + 1, pos === 0));
  });
  const m = d.missing;
  if (m) {
    items.push(el("div", { class: "certdecode-arrow" }, "↑ should be signed by"));
    const sev = m.likely_root ? "warning" : d.certs.length > 1 ? "critical" : "info";
    items.push(el("div", { class: "certdecode-cert " + (sev === "critical" ? "missing" : "warn") },
      el("div", { class: "certdecode-head" }, el("span", { class: "certdecode-n" }, "?"), `NOT PASTED: ${m.issuer_short}`,
        badge(sev, m.likely_root ? "issuer not included" : "missing intermediate")),
      kv([["Expected subject", certdecodeMono(m.issuer)],
        ["Download (AIA)", m.aia_url ? el("a", { href: m.aia_url, target: "_blank", rel: "noopener noreferrer" }, m.aia_url)
          : "No AIA URL in the certificate; get it from the CA's website or the issuing CA server."]]),
      m.aia_url ? certdecodeFetchBox(m, ctx) : null));
  }
  return items;
}

function certdecodeCsr(c, match) {
  return kv([
    ["Subject", certdecodeMono(c.subject)],
    ["Names requested (SAN)", certdecodeSans(c.san) || badge("warning", "none")],
    ["Key", c.key && c.key.text],
    ["Signature", [c.signature, " ", c.signature_valid ? badge("ok", "valid") : c.signature_valid === false ? badge("critical", "INVALID") : badge("info", "not checked")]],
    ["Key usage", c.key_usage ? c.key_usage.join(", ") : null],
    ["Extended key usage", c.eku ? c.eku.map((e) => e.name).join(", ") : null],
    ["Matches certificate", match ? (match.matches ? badge("ok", "yes, same public key") : badge("critical", "NO, different key")) : null],
    ["Source", c.source],
  ]);
}

function renderCertdecodeResult(d, ctx) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  if (d.facts && d.facts.length) frag.append(facts(d.facts));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  const steps = nextSteps(d.steps);
  if (steps) frag.append(steps);
  if (d.fixed_chain_pem) {
    frag.append(card("Corrected chain (leaf first, public root left out)", [
      el("div", { class: "hint", style: "margin-bottom:8px" }, "Certificates only, safe to copy. Save as fullchain.pem for nginx/Apache/HAProxy or a firewall's chain field."),
      code(d.fixed_chain_pem)]));
  }
  if (d.chain && d.chain.length) {
    frag.append(card(d.chain.length > 1 || d.missing ? "Certificate chain (rebuilt from what you pasted)" : "Certificate", certdecodeChain(d, ctx)));
  }
  const others = (d.certs || []).filter((c) => !d.chain.includes(c.index));
  if (others.length) {
    frag.append(card("Other certificates (not part of this chain)", others.map((c, i) => certdecodeCertBox(c, d.chain.length + i + 1, false))));
  }
  if (d.csr) frag.append(card("Certificate signing request (CSR)", certdecodeCsr(d.csr, d.match)));
  if (d.host_check) {
    const h = d.host_check;
    frag.append(card("Hostname check", kv([["Name", h.host],
      ["Covered", h.covered ? badge("ok", "yes") : badge("critical", "no")],
      ["Matched by", h.matched_by], ["Note", h.note]])));
  }
  return frag;
}

function renderCertdecodeTool(main, params) {
  const out = el("div");
  const host = el("input", { type: "text", name: "certdecode-host", placeholder: "vpn.contoso.com (optional)", spellcheck: "false", value: params.get("h") || "" });
  const ctx = {};
  ctx.run = (text) => runInto(out, "Decoding…", () => api("/api/cert/decode", { body: { text, host: host.value.trim() } }),
    (d) => renderCertdecodeResult(d, ctx));
  const pb = pasteBox({
    placeholder: "Paste a certificate (-----BEGIN CERTIFICATE-----), a whole chain, a CSR (-----BEGIN CERTIFICATE REQUEST-----), "
      + "a .p7b (-----BEGIN PKCS7-----) or base64 without headers.\nPaste a CSR and the certificate together to check they match.\n\n"
      + "Never paste a private key or a PFX: this tool doesn't need it and will refuse it.",
    onRun: ctx.run, runLabel: "Decode", rows: 9,
  });
  ctx.textarea = pb.textarea;
  host.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); if (pb.textarea.value.trim()) ctx.run(pb.textarea.value); } });
  pb.element.querySelector(".card-body").append(el("div", { class: "certdecode-host" },
    el("div", { class: "field" }, el("label", { for: "certdecode-host" }, "Does it cover this name?"), host),
    el("span", { class: "hint" }, "Wildcards follow browser rules: *.contoso.com covers vpn.contoso.com, not contoso.com or a.b.contoso.com.")));
  host.id = "certdecode-host";
  main.append(pb.element, out);
}

registerTool({ category: "network", group: "Certificates", id: "certdecode", title: "Certificate & CSR Decoder", render: renderCertdecodeTool,
  icon: "M5 3h10l4 4v14H5zM15 3v4h4M8 12h8M8 16h5",
  keywords: "certificate csr decode decoder pem der base64 p7b pkcs7 chain order intermediate missing root san wildcard thumbprint serial certreq certutil openssl match key request x509 cer crt",
  desc: "Paste a certificate, chain, CSR or .p7b: subject, SANs, expiry, key, usages and thumbprints in plain English, chain order and missing intermediates, CSR ↔ certificate match and a hostname check." });
