"""Domain mail health: MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, Autodiscover,
Microsoft 365 tenant discovery, and cross-checks between them."""
from __future__ import annotations

import base64
import re
from concurrent.futures import ThreadPoolExecutor

import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from ..core.dns_utils import (addresses, fcrdns, is_ip, is_private_ip, make_resolver,
                              normalize_domain, registered_domain, resolve, txt)
from ..core.providers import PROVIDER_SPF_INCLUDES, provider_for
from .spf import analyze_spf

COMMON_DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "dkim", "mail", "smtp", "k1", "k2", "k3", "s1", "s2",
    "sig1", "key1", "key2", "dkim1", "dkim2", "mx", "everlytickey1", "everlytickey2", "mandrill", "mxvault",
    "zendesk1", "zendesk2", "cm", "pm", "fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3",
    "hs1", "hs2", "smtpapi", "mailjet", "amazonses", "ses", "mimecast20190104", "sel1", "sel2", "a1", "krs",
]
HTTP_TIMEOUT = 6.0


def _f(sev: str, area: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "area": area, "title": title, "detail": detail}


# --------------------------------------------------------------------------- MX
def check_mx(res, domain: str) -> dict:
    rdata, meta = resolve(res, domain, "MX")
    out: dict = {"status": meta["status"], "records": [], "null_mx": False, "providers": [], "findings": []}
    F = out["findings"]
    if meta["status"] in ("timeout", "servfail", "error"):
        F.append(_f("critical", "MX", "MX lookup failed", meta["error"] or meta["status"]))
        return out
    if not rdata:
        if meta["status"] == "nxdomain":
            F.append(_f("critical", "MX", "Domain does not exist (NXDOMAIN)",
                        "Check spelling, domain registration/expiry, and that the zone is delegated to the right name servers."))
            return out
        fallback = addresses(res, domain)
        F.append(_f("critical" if not fallback else "warning", "MX", "No MX records",
                    "Senders fall back to the domain's A/AAAA record (implicit MX): " + ", ".join(fallback)
                    if fallback else "The domain cannot receive mail."))
        return out
    recs = sorted(rdata, key=lambda r: (r.preference, r.exchange.to_text()))
    if len(recs) == 1 and recs[0].exchange.to_text() == ".":
        out["null_mx"] = True
        F.append(_f("info", "MX", "Null MX (RFC 7505): domain accepts no mail",
                    "Correct for send-only or parked domains. Remove it if this domain should receive mail."))
        return out

    def inspect(r) -> dict:
        host = r.exchange.to_text(omit_final_dot=True).lower()
        prov = provider_for(host)
        entry: dict = {"preference": r.preference, "host": host, "provider": prov["name"] if prov else None,
                       "provider_kind": prov["kind"] if prov else None, "cname": None, "ips": [], "issues": []}
        if is_ip(host):
            entry["issues"].append(("critical", "MX points to an IP address literal. MX must be a host name."))
            return entry
        cname, _ = resolve(res, host, "CNAME")
        if cname:
            entry["cname"] = cname[0].target.to_text(omit_final_dot=True)
            entry["issues"].append(("warning", f"MX host is a CNAME to {entry['cname']} (RFC 5321/2181 violation; some senders refuse)."))
        ips = addresses(res, host) or addresses(res, host)
        if not ips:
            for alt, label in (("doh-google", "Google"), ("doh-cloudflare", "Cloudflare")):
                ips = addresses(make_resolver(alt), host)
                if ips:
                    entry["issues"].append(("warning", f"{host} doesn't resolve through every DNS resolver (it did through {label}'s). "
                                                       "Senders whose resolver gets no answer can't deliver: check the mail provider's status, "
                                                       "or the MX record if it was changed recently."))
                    break
        if not ips:
            entry["issues"].append(("critical", f"MX host {host} does not resolve to any IP."))
        for ip in ips[:6]:
            info = fcrdns(res, ip)
            info["private"] = is_private_ip(ip)
            if info["private"]:
                entry["issues"].append(("critical", f"{host} resolves to private address {ip}; unreachable from the internet."))
            entry["ips"].append(info)
        return entry

    with ThreadPoolExecutor(max_workers=6) as pool:
        out["records"] = list(pool.map(inspect, recs))
    for e in out["records"]:
        for sev, msg in e.pop("issues"):
            F.append(_f(sev, "MX", f"MX {e['host']}", msg))
    providers = [e["provider"] or "Unknown / self-hosted" for e in out["records"]]
    out["providers"] = list(dict.fromkeys(providers))
    if len(out["providers"]) > 1:
        F.append(_f("warning", "MX", "MX records point to different providers: " + ", ".join(out["providers"]),
                    "Mail can land at whichever host answers, bypassing your filtering gateway or splitting delivery. "
                    "Usually a leftover record from a migration. Senders try the LOWEST preference number first."))
    prefs = [e["preference"] for e in out["records"]]
    if len(out["records"]) == 1 and not out["records"][0]["provider"]:
        F.append(_f("info", "MX", "Single MX host", "No redundancy if that host is down (senders retry for a few days)."))
    if not any(f["severity"] in ("critical", "warning") for f in F):
        F.append(_f("ok", "MX", f"{len(prefs)} MX record(s) resolve correctly"))
    return out


# ------------------------------------------------------------------------ DMARC
def parse_tags(record: str) -> tuple[dict, list[str], list[str]]:
    tags: dict[str, str] = {}
    order: list[str] = []
    errors: list[str] = []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            errors.append(f"Malformed tag '{part}'")
            continue
        k, v = part.split("=", 1)
        k, v = k.strip().lower(), v.strip()
        tags[k] = v
        order.append(k)
    return tags, order, errors


def _dmarc_record(res, name: str) -> tuple[list[str], dict]:
    recs, meta = txt(res, f"_dmarc.{name}")
    return [r for r in recs if re.match(r"(?i)^\s*v\s*=\s*dmarc1", r)], meta


def check_dmarc(res, domain: str) -> dict:
    out: dict = {"record": None, "source": None, "inherited": False, "tags": {}, "findings": []}
    F = out["findings"]
    recs, meta = _dmarc_record(res, domain)
    source = domain
    org = registered_domain(domain)
    if not recs and org != domain:
        recs, meta = _dmarc_record(res, org)
        source = org
        out["inherited"] = bool(recs)
    if meta["status"] in ("timeout", "servfail", "error") and not recs:
        F.append(_f("warning", "DMARC", "DMARC lookup failed", meta["error"] or meta["status"]))
        return out
    if not recs:
        F.append(_f("critical", "DMARC", "No DMARC record",
                    f"Publish TXT at _dmarc.{domain}, starting with \"v=DMARC1; p=none; rua=mailto:...\" to collect reports. "
                    "Google, Yahoo and Microsoft (Outlook.com) require DMARC for bulk senders."))
        return out
    if len(recs) > 1:
        F.append(_f("critical", "DMARC", "Multiple DMARC records", "Receivers ignore DMARC entirely when more than one exists."))
    record = recs[0]
    out["record"], out["source"] = record, source
    tags, order, errors = parse_tags(record)
    out["tags"] = tags
    for e in errors:
        F.append(_f("warning", "DMARC", "DMARC syntax", e))
    if order and order[0] != "v":
        F.append(_f("critical", "DMARC", "v=DMARC1 must be the first tag"))
    policy_key = "sp" if out["inherited"] and "sp" in tags else "p"
    p = tags.get(policy_key, "").lower()
    if out["inherited"]:
        F.append(_f("info", "DMARC", f"No record at _dmarc.{domain}; inheriting from {org}",
                    f"Effective policy for this subdomain is {policy_key}={p or '(missing)'}."))
    if p not in ("none", "quarantine", "reject"):
        F.append(_f("critical", "DMARC", f"Invalid or missing policy (p={tags.get('p', '')!r})",
                    "p must be none, quarantine or reject. An invalid p makes the record unusable."))
    elif p == "none":
        F.append(_f("warning", "DMARC", "Policy is p=none (monitor only)",
                    "Spoofed mail is still delivered. Review the aggregate reports, then move to quarantine and then reject."))
    elif p == "quarantine":
        F.append(_f("ok", "DMARC", "Policy is p=quarantine"))
    else:
        F.append(_f("ok", "DMARC", "Policy is p=reject"))
    if tags.get("pct") and tags["pct"] != "100":
        F.append(_f("warning", "DMARC", f"pct={tags['pct']}: policy applies to only part of the failing mail",
                    "pct is deprecated in DMARCbis (replaced by the t=y testing flag), but still honoured by many receivers."))
    if tags.get("sp", "").lower() == "none" and p in ("quarantine", "reject"):
        F.append(_f("warning", "DMARC", "sp=none: subdomains are not protected",
                    "Attackers can spoof anything.your-domain. Set sp=quarantine/reject unless subdomains are still being onboarded."))
    if "rua" not in tags:
        F.append(_f("warning", "DMARC", "No aggregate report address (rua)",
                    "Without reports you cannot see who sends as your domain, or what will break when you enforce."))
    for key in ("rua", "ruf"):
        for uri in [u.strip() for u in tags.get(key, "").split(",") if u.strip()]:
            if not uri.lower().startswith("mailto:"):
                F.append(_f("warning", "DMARC", f"{key} URI is not mailto: {uri}"))
                continue
            dest = uri[7:].split("!")[0].split("@")[-1].lower()
            if registered_domain(dest) != registered_domain(source):
                auth, _ = txt(res, f"{source}._report._dmarc.{dest}")
                if not any(a.lower().replace(" ", "").startswith("v=dmarc1") for a in auth):
                    F.append(_f("warning", "DMARC", f"External {key} destination {dest} has not authorised reports",
                                f"Receivers should check TXT {source}._report._dmarc.{dest}. Without it reports to {dest} may be dropped. "
                                "(Most DMARC vendors publish a wildcard, so this can be a false alarm.)"))
    if tags.get("adkim", "r").lower() == "s" or tags.get("aspf", "r").lower() == "s":
        F.append(_f("info", "DMARC", "Strict alignment enabled",
                    "adkim=s / aspf=s need an exact domain match. Subdomain senders (e.g. mail.example.com) will fail."))
    _dmarcbis_findings(F, tags, p, out["inherited"])
    return out


_LEVEL = {"none": 0, "quarantine": 1, "reject": 2}


def _dmarcbis_findings(F: list[dict], tags: dict, p: str, inherited: bool) -> None:
    """DMARCbis tags (np=, psd=, t=). Info level only: many receivers still
    implement RFC 7489 and simply ignore these tags."""
    t = tags.get("t", "").strip().lower()
    if t == "y":
        lower = {"reject": "quarantine", "quarantine": "none"}.get(p)
        F.append(_f("info", "DMARC", "Testing flag t=y is set (DMARCbis)",
                    f"Receivers that support DMARCbis treat the policy as one level lower"
                    + (f" (p={p} is applied as {lower})" if lower else "")
                    + ". Remove t=y (or set t=n) once the aggregate reports look clean."))
    elif t and t != "n":
        F.append(_f("info", "DMARC", f"t={tags['t']} is not a valid testing flag", "DMARCbis allows only t=y or t=n; receivers ignore other values."))

    np_ = tags.get("np", "").strip().lower()
    sp = tags.get("sp", "").strip().lower() or p
    if np_ and np_ not in _LEVEL:
        F.append(_f("info", "DMARC", f"np={tags['np']} is not a valid policy", "np must be none, quarantine or reject. Receivers ignore an invalid np."))
    elif not inherited and p == "reject":
        if not np_ and _LEVEL.get(sp, 2) < 2:
            F.append(_f("info", "DMARC", "Add np=reject to block spoofing from non-existent subdomains",
                        f"DMARCbis np= is the policy for subdomains that don't exist in DNS (e.g. invoices.your-domain), a favourite of spoofers. "
                        f"Without it they fall back to sp={sp}."))
        elif not np_:
            F.append(_f("info", "DMARC", "Consider stating np=reject explicitly",
                        "DMARCbis np= is the policy for non-existent subdomains. It defaults to sp (which defaults to p), so they're already at reject "
                        "where DMARCbis is supported; adding np=reject documents the intent."))
        elif np_ == "reject":
            F.append(_f("ok", "DMARC", "np=reject: non-existent subdomains are protected (DMARCbis)"))
        elif _LEVEL[np_] < 2:
            F.append(_f("info", "DMARC", f"np={np_} is weaker than p=reject",
                        "Non-existent subdomains can be spoofed more easily than the domain itself. Use np=reject unless there's a specific reason."))
    psd = tags.get("psd", "").strip().lower()
    if psd == "y":
        F.append(_f("info", "DMARC", "psd=y: record declares a public suffix domain (DMARCbis)",
                    "Only for registries and public suffix operators (e.g. a TLD or a government suffix). On an ordinary organisation's domain this changes "
                    "how receivers find the organisational domain; remove it unless that's intended."))
    elif psd == "n":
        F.append(_f("info", "DMARC", "psd=n: record declares this the organisational domain (DMARCbis)",
                    "Tells receivers to stop looking further up the DNS tree. Harmless on a registered domain."))
    elif psd and psd != "u":
        F.append(_f("info", "DMARC", f"psd={tags['psd']} is not a valid value", "DMARCbis allows psd=y, n or u."))


# ------------------------------------------------------------------------- DKIM
def _key_bits(p: str, k: str) -> tuple[int | None, str | None]:
    try:
        raw = base64.b64decode(p + "=" * (-len(p) % 4))
    except (ValueError, TypeError):
        return None, "Public key is not valid base64"
    if k == "ed25519":
        return (256, None) if len(raw) == 32 else (None, "ed25519 key is not 32 bytes")
    try:
        key = load_der_public_key(raw)
    except ValueError:
        return None, "Public key could not be parsed"
    if isinstance(key, rsa.RSAPublicKey):
        return key.key_size, None
    if isinstance(key, ed25519.Ed25519PublicKey):
        return 256, None
    return None, "Unsupported key type"


def _check_selector(res, domain: str, sel: str) -> dict | None:
    name = f"{sel}._domainkey.{domain}"
    cname, _ = resolve(res, name, "CNAME")
    recs, meta = txt(res, name)
    target = cname[0].target.to_text(omit_final_dot=True) if cname else None
    if not recs and not target:
        return None
    entry: dict = {"selector": sel, "name": name, "cname": target, "record": None, "bits": None,
                   "key_type": None, "testing": False, "revoked": False, "error": None}
    dkim = [r for r in recs if "p=" in r.replace(" ", "")]
    if not dkim:
        entry["error"] = "CNAME exists but the target has no DKIM key" if target else "TXT found but it is not a DKIM key"
        return entry
    entry["record"] = dkim[0]
    tags, _, _ = parse_tags(dkim[0])
    k = tags.get("k", "rsa").lower()
    entry["key_type"] = k
    entry["testing"] = "y" in tags.get("t", "").lower().split(":")
    p = re.sub(r"\s+", "", tags.get("p", ""))
    if not p:
        entry["revoked"] = True
        return entry
    entry["bits"], entry["error"] = _key_bits(p, k)
    return entry


def check_dkim(res, domain: str, extra: list[str] | None = None) -> dict:
    selectors = list(dict.fromkeys([*(extra or []), *COMMON_DKIM_SELECTORS]))
    out: dict = {"selectors_checked": len(selectors), "found": [], "wildcard": False, "findings": []}
    F = out["findings"]
    wild, _ = txt(res, f"mspgather-nonexistent-x9q._domainkey.{domain}")
    if wild:
        out["wildcard"] = True
        F.append(_f("warning", "DKIM", "Wildcard TXT under _domainkey",
                    "Every selector appears to exist, so selector discovery is unreliable. Check selectors from a real message's DKIM-Signature s= tag."))
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda s: _check_selector(res, domain, s), selectors))
    out["found"] = [r for r in results if r and not (out["wildcard"] and not r.get("cname"))]
    m365_keyed = {e["selector"] for e in out["found"] if e["selector"] in ("selector1", "selector2") and e.get("bits")}
    for e in out["found"]:
        label = f"selector '{e['selector']}'"
        is_m365 = bool(e["cname"]) and (e["cname"].endswith(".onmicrosoft.com") or ".dkim.mail.microsoft" in e["cname"])
        if e["error"] and is_m365 and e["selector"] in ("selector1", "selector2") and m365_keyed:
            F.append(_f("info", "DKIM", f"{label}: standby key for rotation (normal)",
                        f"Microsoft 365 publishes two selectors and signs with one at a time; {', '.join(sorted(m365_keyed))} has the active key."))
        elif e["error"]:
            sev = "warning" if e["cname"] else "info"
            detail = ""
            if is_m365:
                detail = "This is a Microsoft 365 selector CNAME and neither selector has a key, so DKIM signing for this domain is probably not enabled in the Defender portal (Email authentication → DKIM)."
            F.append(_f(sev, "DKIM", f"{label}: {e['error']}", detail))
        elif e["revoked"]:
            F.append(_f("info", "DKIM", f"{label}: key revoked (empty p=)"))
        elif e["bits"] and e["bits"] < 1024:
            F.append(_f("critical", "DKIM", f"{label}: {e['bits']}-bit key is too weak", "Many receivers ignore keys under 1024 bits. Rotate to 2048."))
        elif e["bits"] == 1024:
            F.append(_f("info", "DKIM", f"{label}: 1024-bit key", "Works, but 2048-bit is recommended."))
        elif e["bits"]:
            F.append(_f("ok", "DKIM", f"{label}: {e['bits']}-bit {e['key_type']} key"))
        if e["testing"]:
            F.append(_f("info", "DKIM", f"{label}: test mode (t=y)", "Receivers may treat failures as unsigned."))
    if not out["found"]:
        F.append(_f("warning", "DKIM", f"No DKIM keys found on {len(selectors)} common selectors",
                    "DKIM may still exist on a custom selector. Look at the s= tag in a sent message's DKIM-Signature header and add it as an extra selector."))
    return out


# --------------------------------------------------------------------- MTA-STS
def _sts_match(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return host == pattern


def check_mta_sts(res, domain: str) -> dict:
    out: dict = {"record": None, "policy": None, "policy_raw": None, "findings": []}
    F = out["findings"]
    recs, _ = txt(res, f"_mta-sts.{domain}")
    sts = [r for r in recs if r.lower().replace(" ", "").startswith("v=stsv1")]
    if sts and not any(r.startswith("v=STSv1") for r in sts):
        F.append(_f("critical", "MTA-STS", "MTA-STS record is ignored by senders",
                    f"_mta-sts.{domain} must start with exactly 'v=STSv1' (case-sensitive, no leading space): {sts[0]}"))
    if not sts:
        F.append(_f("info", "MTA-STS", "MTA-STS not configured",
                    "Optional. MTA-STS makes senders require valid TLS to your MX and protects against downgrade attacks."))
        return out
    out["record"] = sts[0]
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    from .netdiag import _safe_get  # public-only, DNS-pinned, size-capped
    try:
        status, body, _meta = _safe_get(url, 64 * 1024, HTTP_TIMEOUT)
    except ValueError as exc:
        msg = str(exc)
        reason = (msg if msg.startswith("Refusing") else
                  f"mta-sts.{domain} doesn't exist in DNS" if "does not resolve" in msg else
                  "its HTTPS certificate isn't valid for this name" if "CERTIFICATE" in msg.upper() or "SSL" in msg.upper() else
                  "the connection timed out" if "timed out" in msg.lower() or "timeout" in msg.lower() else
                  "the connection was refused (nothing answering on port 443)" if "refused" in msg.lower() else
                  "the connection failed")
        F.append(_f("critical", "MTA-STS", "MTA-STS policy cannot be fetched",
                    f"{url}: {reason}. The TXT record exists, so senders that cached an enforce policy may refuse to deliver."))
        return out
    if status != 200:
        F.append(_f("critical", "MTA-STS", f"MTA-STS policy returned HTTP {status}",
                    f"{url}. Redirects are not allowed by RFC 8461."))
        return out
    text = body.decode("utf-8", "replace")
    out["policy_raw"] = text[:4000]
    policy: dict = {"mx": []}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "mx":
                policy["mx"].append(v)
            else:
                policy[k] = v
    out["policy"] = policy
    mode = policy.get("mode", "")
    if policy.get("version") != "STSv1":
        F.append(_f("critical", "MTA-STS", "Policy file missing 'version: STSv1'"))
    if mode not in ("enforce", "testing", "none"):
        F.append(_f("critical", "MTA-STS", f"Invalid policy mode '{mode}'"))
    elif mode == "enforce":
        F.append(_f("ok", "MTA-STS", "MTA-STS in enforce mode"))
    else:
        F.append(_f("info", "MTA-STS", f"MTA-STS in {mode} mode"))
    if "text/plain" not in _meta["content_type"]:
        F.append(_f("warning", "MTA-STS", "Policy not served as text/plain", _meta["content_type"] or "(none)"))
    return out


def check_tlsrpt(res, domain: str) -> dict:
    recs, _ = txt(res, f"_smtp._tls.{domain}")
    rec = next((r for r in recs if r.lower().replace(" ", "").startswith("v=tlsrptv1")), None)
    if rec and not rec.startswith("v=TLSRPTv1"):
        f = _f("warning", "TLS-RPT", "TLS-RPT record is ignored by senders",
               f"_smtp._tls.{domain} must start with exactly 'v=TLSRPTv1' (case-sensitive, no leading space): {rec}")
    else:
        f = (_f("ok", "TLS-RPT", "TLS-RPT configured") if rec else
             _f("info", "TLS-RPT", "TLS-RPT not configured", "Optional. Senders report TLS delivery failures to you."))
    return {"record": rec, "findings": [f]}


def check_bimi(res, domain: str) -> dict:
    recs, _ = txt(res, f"default._bimi.{domain}")
    rec = next((r for r in recs if r.lower().replace(" ", "").startswith("v=bimi1")), None)
    tags = parse_tags(rec)[0] if rec else {}
    findings = []
    if rec:
        findings.append(_f("ok" if tags.get("a") else "info", "BIMI", "BIMI record published",
                           "" if tags.get("a") else "No a= certificate (VMC/CMC). Gmail and Apple require one to show the logo."))
    return {"record": rec, "tags": tags, "findings": findings}


def check_autodiscover(res, domain: str) -> dict:
    cname, _ = resolve(res, f"autodiscover.{domain}", "CNAME")
    srv, _ = resolve(res, f"_autodiscover._tcp.{domain}", "SRV")
    target = cname[0].target.to_text(omit_final_dot=True).lower() if cname else None
    out: dict = {"cname": target, "srv": [r.to_text() for r in srv], "findings": []}
    if target == "autodiscover.outlook.com":
        out["findings"].append(_f("ok", "Autodiscover", "Autodiscover points to Microsoft 365"))
    elif target:
        out["findings"].append(_f("info", "Autodiscover", f"Autodiscover CNAME → {target}",
                                  "If mailboxes are in Microsoft 365 and there's no hybrid server, this should be autodiscover.outlook.com."))
    elif not srv:
        a = addresses(res, f"autodiscover.{domain}")
        out["findings"].append(_f("info", "Autodiscover",
                                  "Autodiscover is an A record" if a else "No Autodiscover record",
                                  "Outlook profile setup may be slow or fail unless the mailbox platform handles discovery."))
    return out


def check_ns(res, domain: str) -> dict:
    rdata, meta = resolve(res, registered_domain(domain), "NS")
    hosts = sorted(r.target.to_text(omit_final_dot=True).lower() for r in rdata)
    dns_host = None
    for pat, name in ((r"cloudflare\.com$", "Cloudflare"), (r"azure-dns\.", "Azure DNS"), (r"awsdns", "AWS Route 53"),
                      (r"domaincontrol\.com$", "GoDaddy"), (r"googledomains\.com$|google\.com$", "Google Cloud DNS"),
                      (r"registrar-servers\.com$", "Namecheap"), (r"nsone\.net$", "NS1"), (r"ultradns", "UltraDNS")):
        if hosts and re.search(pat, hosts[0]):
            dns_host = name
    return {"hosts": hosts, "dns_host": dns_host, "status": meta["status"]}


def check_m365_tenant(domain: str) -> dict:
    """Public, unauthenticated discovery endpoints. Tells you whether the domain
    is verified in an Entra ID tenant and whether sign-in is federated."""
    out: dict = {"tenant_id": None, "namespace_type": None, "federation_brand": None,
                 "auth_url": None, "cloud_instance": None, "error": None}
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            oid = client.get(f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration")
            if oid.status_code == 200:
                data = oid.json()
                m = re.search(r"/([0-9a-f-]{36})/", data.get("issuer", ""))
                out["tenant_id"] = m.group(1) if m else None
                out["cloud_instance"] = data.get("cloud_instance_name")
            realm = client.get("https://login.microsoftonline.com/getuserrealm.srf",
                               params={"login": f"mspgather-probe@{domain}", "json": "1"})
            if realm.status_code == 200:
                rj = realm.json()
                out["namespace_type"] = rj.get("NameSpaceType")
                out["federation_brand"] = rj.get("FederationBrandName")
                out["auth_url"] = rj.get("AuthURL")
    except (httpx.HTTPError, ValueError) as exc:
        out["error"] = str(exc)
    return out


# ----------------------------------------------------------------- orchestrator
def check_domain(domain: str, resolver_name: str | None = None, extra_selectors: list[str] | None = None) -> dict:
    domain = normalize_domain(domain)
    res = make_resolver(resolver_name)
    _, soa_meta = resolve(res, domain, "SOA")
    if soa_meta["status"] == "nxdomain":
        raise ValueError(f"{domain} doesn't exist in DNS: it isn't registered, has expired, or is misspelled. "
                         "Check the spelling, then the registration (Domain Registration tool).")
    selectors = [s.strip().lower() for s in (extra_selectors or []) if re.fullmatch(r"[A-Za-z0-9._-]{1,63}", s.strip())]
    with ThreadPoolExecutor(max_workers=10) as pool:
        jobs = {
            "mx": pool.submit(check_mx, res, domain),
            "spf": pool.submit(analyze_spf, domain, resolver_name),
            "dmarc": pool.submit(check_dmarc, res, domain),
            "dkim": pool.submit(check_dkim, res, domain, selectors),
            "mta_sts": pool.submit(check_mta_sts, res, domain),
            "tls_rpt": pool.submit(check_tlsrpt, res, domain),
            "bimi": pool.submit(check_bimi, res, domain),
            "autodiscover": pool.submit(check_autodiscover, res, domain),
            "ns": pool.submit(check_ns, res, domain),
            "m365": pool.submit(check_m365_tenant, domain),
        }
        r = {k: v.result() for k, v in jobs.items()}

    spf = r["spf"]
    for f in spf["findings"]:
        f.setdefault("area", "SPF")
    findings: list[dict] = []
    for key in ("mx", "spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi", "autodiscover"):
        findings.extend(r[key].get("findings", []))

    # ---- cross checks
    mx, m365 = r["mx"], r["m365"]
    mx_providers = {e["provider"] for e in mx["records"]}
    gateways = sorted({e["provider"] for e in mx["records"] if e["provider_kind"] == "gateway"})
    in_m365 = bool(m365.get("tenant_id")) or r["autodiscover"]["cname"] == "autodiscover.outlook.com"
    includes = set(spf.get("includes", []))

    for prov, needed in PROVIDER_SPF_INCLUDES.items():
        uses = prov in mx_providers or (prov == "Microsoft 365" and in_m365)
        if uses and spf.get("record") and not any(n in includes for n in needed):
            findings.append(_f("warning", "Cross-check", f"{prov} in use but SPF does not include {needed[0]}",
                               f"Mail sent directly from {prov} will fail SPF. Ignore this if all outbound mail is relayed through a gateway that is in SPF."))
    if in_m365 and gateways:
        findings.append(_f("info", "Cross-check", f"Microsoft 365 behind {', '.join(gateways)}",
                           "Mail arrives at Microsoft 365 from the gateway, not the original sender, so:\n"
                           "• Turn on Enhanced Filtering for Connectors (skip listing) on the inbound connector, or EOP judges SPF/DMARC against the gateway's IP.\n"
                           "• Lock the tenant down so it only accepts mail from the gateway's IPs (inbound connector restriction).\n"
                           "• If an outbound connector sends via the gateway, make sure the gateway doesn't route internal recipients back to Microsoft 365, or you get a mail loop."))
    if "Microsoft 365" in mx_providers and m365.get("namespace_type") == "Unknown":
        findings.append(_f("critical", "Cross-check", "MX points to Microsoft 365 but the domain is not in any Entra tenant",
                           "Exchange Online will reject mail for it (550 5.4.1 / 5.7.64). Verify the domain in the tenant or fix the MX."))
    if m365.get("namespace_type") == "Federated":
        findings.append(_f("info", "Microsoft 365", "Domain uses federated sign-in",
                           f"Auth goes to {m365.get('auth_url') or 'an external IdP'}. Sign-in or SMTP AUTH problems may be on the IdP side (e.g. AD FS)."))
    found_m365_dkim = any(e["selector"] in ("selector1", "selector2") and e.get("bits") for e in r["dkim"]["found"])
    if in_m365 and not found_m365_dkim:
        findings.append(_f("warning", "Cross-check", "Microsoft 365 DKIM (selector1/selector2) not active for this domain",
                           "Microsoft signs with the tenant's onmicrosoft.com domain instead. That doesn't align with your From domain, so DMARC relies on SPF alone (and breaks on forwarding)."))
    if r["dmarc"].get("tags", {}).get("p", "").lower() in ("quarantine", "reject") and not r["dkim"]["found"] and spf.get("record") is None:
        findings.append(_f("critical", "Cross-check", "DMARC enforcement with no SPF and no DKIM found", "All mail from this domain will fail DMARC."))
    sts_policy = r["mta_sts"].get("policy")
    if sts_policy and mx["records"]:
        bad = [e["host"] for e in mx["records"] if not any(_sts_match(p, e["host"]) for p in sts_policy["mx"])]
        if bad:
            sev = "critical" if sts_policy.get("mode") == "enforce" else "warning"
            findings.append(_f(sev, "MTA-STS", "MX hosts not covered by the MTA-STS policy: " + ", ".join(bad),
                               "In enforce mode, senders that honour MTA-STS will refuse to deliver to these MX hosts. Common after an MX change."))
    if r["bimi"]["record"] and r["dmarc"].get("tags", {}).get("p", "").lower() not in ("quarantine", "reject"):
        findings.append(_f("warning", "BIMI", "BIMI needs DMARC at quarantine or reject", "Logos won't be displayed with p=none."))

    # A domain that deliberately neither sends nor receives mail (null MX and/or
    # "v=spf1 -all") doesn't need DKIM, report addresses or a mail platform.
    no_inbound = mx.get("null_mx")
    no_outbound = (spf.get("record") or "").lower().split() == ["v=spf1", "-all"]
    parked = no_inbound and no_outbound
    if no_outbound:
        for f in findings:
            if f["area"] == "DMARC" and f["title"] == "No DMARC record":
                f["severity"] = "warning"
                f["detail"] = f'This domain sends no mail (v=spf1 -all). Finish locking it down with: _dmarc.{domain}  TXT  "v=DMARC1; p=reject;"'
    if no_outbound or no_inbound:
        noise = {"Cross-check", "DKIM", "MTA-STS", "TLS-RPT", "Autodiscover"}
        findings = [f for f in findings if not (f["area"] in noise and f["severity"] in ("warning", "info"))
                    and not (f["area"] == "DMARC" and "rua" in f["title"])]
        dmarc_p = r["dmarc"].get("tags", {}).get("p", "").lower()
        if parked:
            findings.insert(0, _f("ok" if dmarc_p == "reject" else "warning", "Domain", "Parked domain",
                                  "Null MX (receives no mail) and v=spf1 -all (sends no mail): correctly locked down against spoofing."
                                  + ("" if dmarc_p == "reject" else " Add a DMARC record with p=reject to finish the lockdown.")))
        elif no_outbound:
            findings.insert(0, _f("info", "SPF", "Domain declares it sends no mail (v=spf1 -all)",
                                  "Any mail claiming to come from this domain fails SPF. If that's wrong, legitimate senders are being blocked."))
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in order}
    platform = None if parked else "Microsoft 365" if in_m365 else next((p for p in mx_providers if p), None)
    return {"domain": domain, "resolver": resolver_name or "system", "summary": summary, "mail_platform": platform,
            "inbound_gateways": gateways, **r, "findings": findings}
