"""Who owns an IP? RDAP registration data, ASN (Team Cymru DNS), reverse DNS,
and recognition of email sending services with the SPF include they need."""
from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

import httpx

from ..core.dns_utils import addresses, fcrdns, is_ip, make_resolver, normalize_domain, txt
from .spf import analyze_spf

RDAP_BOOTSTRAP = "https://rdap.org/ip/{ip}"
HTTP_TIMEOUT = 8.0

# Email services: matched on reverse DNS (most reliable), then ASN, then owner name.
# spf = the include the service documents. None = per-customer, see the service's docs.
SERVICES: list[dict] = [
    {"name": "Microsoft 365 / Exchange Online", "ptr": r"\.outlook\.com$|\.protection\.outlook\.com$", "asn": [8075], "spf": "spf.protection.outlook.com",
     "note": "Microsoft's ASN also covers Azure. An Azure VM is NOT covered by spf.protection.outlook.com; a reverse DNS of *.outlook.com means Exchange Online."},
    {"name": "Google Workspace / Gmail", "ptr": r"^mail-.*\.google\.com$|\.google\.com$", "asn": [], "spf": "_spf.google.com",
     "note": "Google Cloud VMs (*.googleusercontent.com) aren't covered by _spf.google.com."},
    {"name": "Amazon SES", "ptr": r"\.amazonses\.com$", "asn": [], "spf": "amazonses.com",
     "note": "SES normally uses its own MAIL FROM domain. For SPF alignment, set a custom MAIL FROM subdomain in SES."},
    {"name": "SendGrid (Twilio)", "ptr": r"\.sendgrid\.net$", "asn": [11377], "spf": "sendgrid.net", "note": ""},
    {"name": "Mailgun", "ptr": r"\.mailgun\.(net|org)$|mxa\.mailgun|mxb\.mailgun", "asn": [], "spf": "mailgun.org", "note": ""},
    {"name": "Mailchimp", "ptr": r"\.mcsv\.net$|\.rsgsv\.net$|\.mcdlv\.net$", "asn": [], "spf": "servers.mcsv.net", "note": ""},
    {"name": "Mandrill (Mailchimp Transactional)", "ptr": r"\.mandrillapp\.com$", "asn": [], "spf": "spf.mandrillapp.com", "note": ""},
    {"name": "Salesforce", "ptr": r"\.salesforce\.com$|\.exacttarget\.com$", "asn": [14340], "spf": "_spf.salesforce.com",
     "note": "Marketing Cloud (ExactTarget) uses different, account-specific settings."},
    {"name": "Zendesk", "ptr": r"\.zendesk\.com$", "asn": [], "spf": "mail.zendesk.com", "note": ""},
    {"name": "Postmark", "ptr": r"\.mtasv\.net$", "asn": [], "spf": "spf.mtasv.net", "note": "Postmark recommends a custom Return-Path instead of an SPF include."},
    {"name": "SparkPost / Bird", "ptr": r"\.sparkpostmail\.com$", "asn": [], "spf": "sparkpostmail.com", "note": ""},
    {"name": "Brevo (Sendinblue)", "ptr": r"\.sendinblue\.com$|\.brevo\.com$", "asn": [], "spf": "spf.brevo.com", "note": ""},
    {"name": "Mailjet", "ptr": r"\.mailjet\.com$", "asn": [], "spf": "spf.mailjet.com", "note": ""},
    {"name": "Constant Contact", "ptr": r"\.constantcontact\.com$|\.ctctmail\.com$", "asn": [], "spf": "spf.constantcontact.com", "note": ""},
    {"name": "HubSpot", "ptr": r"\.hubspotemail\.net$|\.hubspot\.(com|net)$", "asn": [], "spf": None,
     "note": "HubSpot gives each account its own SPF/DKIM records. Get them from HubSpot → Settings → Domains & URLs."},
    {"name": "Zoho Mail", "ptr": r"\.zoho\.(com|eu|in)$|\.zohomail\.com$", "asn": [], "spf": "zoho.com",
     "note": "Use zoho.eu / zoho.in for those data centres."},
    {"name": "Freshdesk", "ptr": r"\.freshdesk\.com$|\.freshemail\.io$", "asn": [], "spf": "email.freshdesk.com", "note": ""},
    {"name": "Mimecast", "ptr": r"\.mimecast\.com$|\.mimecast-offshore\.com$", "asn": [], "spf": None,
     "note": "The include depends on your Mimecast region, e.g. us._netblocks.mimecast.com or eu._netblocks.mimecast.com."},
    {"name": "Proofpoint", "ptr": r"\.pphosted\.com$|\.ppe-hosted\.com$", "asn": [], "spf": None,
     "note": "Proofpoint Essentials: a1/a2 etc. Proofpoint Enterprise: customer-specific. Check your Proofpoint console."},
    {"name": "Exclaimer (signatures)", "ptr": r"\.exclaimer\.(net|cloud)$", "asn": [], "spf": None,
     "note": "Exclaimer publishes region-specific includes (e.g. spf.eu.exclaimer.net / spf.us.exclaimer.net)."},
    {"name": "CodeTwo (signatures)", "ptr": r"\.codetwo\.(online|com)$", "asn": [], "spf": None,
     "note": "CodeTwo provides a region-specific SPF include in its admin panel."},
]

SPECIAL_RANGES = [
    ("10.0.0.0/8", "Private (RFC 1918)"), ("172.16.0.0/12", "Private (RFC 1918)"), ("192.168.0.0/16", "Private (RFC 1918)"),
    ("100.64.0.0/10", "Carrier-grade NAT (RFC 6598)"), ("127.0.0.0/8", "Loopback"), ("169.254.0.0/16", "Link-local"),
    ("192.0.2.0/24", "Documentation (TEST-NET-1)"), ("198.51.100.0/24", "Documentation (TEST-NET-2)"),
    ("203.0.113.0/24", "Documentation (TEST-NET-3)"), ("224.0.0.0/4", "Multicast"), ("0.0.0.0/8", "Reserved"),
    ("::1/128", "Loopback"), ("fc00::/7", "Unique local (private)"), ("fe80::/10", "Link-local"), ("2001:db8::/32", "Documentation"),
]


def _special(ip: str) -> str | None:
    addr = ipaddress.ip_address(ip)
    for net, label in SPECIAL_RANGES:
        n = ipaddress.ip_network(net)
        if n.version == addr.version and addr in n:
            return label
    return None


def _cymru_key(ip: str) -> tuple[str, str]:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))), "origin.asn.cymru.com"
    return ".".join(reversed(addr.exploded.replace(":", ""))), "origin6.asn.cymru.com"


def asn_lookup(res, ip: str) -> dict | None:
    """Team Cymru IP-to-ASN over DNS: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"."""
    key, zone = _cymru_key(ip)
    recs, _ = txt(res, f"{key}.{zone}")
    if not recs:
        return None
    parts = [p.strip() for p in recs[0].split("|")]
    if len(parts) < 3:
        return None
    asn = parts[0].split()[0]  # multi-origin prefixes list several ASNs
    out = {"asn": int(asn) if asn.isdigit() else None, "prefix": parts[1], "country": parts[2],
           "registry": parts[3] if len(parts) > 3 else None, "allocated": parts[4] if len(parts) > 4 else None, "name": None}
    if out["asn"]:
        names, _ = txt(res, f"AS{out['asn']}.asn.cymru.com")
        if names:
            np = [p.strip() for p in names[0].split("|")]
            out["name"] = np[-1] if len(np) >= 5 else None
    return out


def _vcard(entity: dict) -> dict:
    out: dict = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) < 4:
            continue
        key, val = item[0], item[3]
        if key == "fn":
            out["name"] = val
        elif key == "email":
            out.setdefault("emails", []).append(val)
        elif key == "tel":
            out.setdefault("phones", []).append(val if isinstance(val, str) else str(val))
        elif key == "adr":
            label = (item[1] or {}).get("label")
            if label:
                out["address"] = label.replace("\n", ", ")
            elif isinstance(val, list):
                out["address"] = ", ".join(str(v) for v in val if v and not isinstance(v, list))
    return out


def _walk_entities(entities: list, found: list, depth: int = 0) -> None:
    for e in entities or []:
        found.append({"handle": e.get("handle"), "roles": e.get("roles", []), **_vcard(e)})
        if depth < 3:
            _walk_entities(e.get("entities"), found, depth + 1)


def rdap_lookup(ip: str) -> dict:
    out: dict = {"error": None}
    try:
        r = httpx.get(RDAP_BOOTSTRAP.format(ip=ip), timeout=HTTP_TIMEOUT, follow_redirects=True,
                      headers={"accept": "application/rdap+json"})
        if r.status_code != 200:
            out["error"] = f"RDAP returned HTTP {r.status_code}"
            return out
        data = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        out["error"] = f"RDAP lookup failed: {exc}"
        return out
    out["source"] = str(r.url)
    out["handle"] = data.get("handle")
    out["name"] = data.get("name")
    out["type"] = data.get("type")
    out["country"] = data.get("country")
    out["start"] = data.get("startAddress")
    out["end"] = data.get("endAddress")
    out["cidrs"] = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in data.get("cidr0_cidrs", [])]
    out["parent"] = data.get("parentHandle")
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    out["registered"] = events.get("registration")
    out["updated"] = events.get("last changed")
    remarks = []
    for rm in data.get("remarks", []) or []:
        remarks.extend(d for d in rm.get("description", []) if d)
    out["remarks"] = remarks[:8]
    entities: list[dict] = []
    _walk_entities(data.get("entities"), entities)
    out["entities"] = entities

    def pick(role: str) -> dict | None:
        return next((e for e in entities if role in e["roles"] and (e.get("name") or e.get("emails"))), None)

    out["registrant"] = pick("registrant") or pick("administrative")
    out["abuse"] = pick("abuse")
    if not out["abuse"]:
        emails = [m for e in entities for m in e.get("emails", []) if "abuse" in m.lower()]
        emails += re.findall(r"[\w.+-]*abuse[\w.+-]*@[\w.-]+", " ".join(remarks), re.I)
        if emails:
            out["abuse"] = {"name": None, "emails": list(dict.fromkeys(emails))}
    return out


def identify_service(ptr_names: list[str], asn: dict | None, owner: str | None) -> dict | None:
    for svc in SERVICES:
        if any(re.search(svc["ptr"], p, re.I) for p in ptr_names):
            return {**_svc(svc), "matched_on": "reverse DNS", "confidence": "high"}
    for svc in SERVICES:
        if asn and asn.get("asn") in svc["asn"]:
            return {**_svc(svc), "matched_on": f"ASN {asn['asn']}", "confidence": "medium"}
    return None


def _svc(svc: dict) -> dict:
    return {"name": svc["name"], "spf_include": svc["spf"], "note": svc["note"]}


def ip_lookup(target: str, domain: str | None = None) -> dict:
    target = (target or "").strip().strip("[]")
    if not target:
        raise ValueError("Enter an IP address or host name.")
    res = make_resolver()
    resolved_from = None
    other_ips: list[str] = []
    if is_ip(target):
        ip = str(ipaddress.ip_address(target))
    else:
        if re.fullmatch(r"[\d.]+", target) or (":" in target and re.fullmatch(r"[0-9a-fA-F:]+", target)):
            raise ValueError(f"'{target}' is not a valid IP address.")
        host = normalize_domain(target)
        ips = addresses(res, host)
        if not ips:
            raise ValueError(f"{host} does not resolve to an IP address.")
        ip, other_ips, resolved_from = ips[0], ips[1:], host
    domain = normalize_domain(domain) if domain and domain.strip() else None

    out: dict = {"ip": ip, "version": ipaddress.ip_address(ip).version, "resolved_from": resolved_from,
                 "other_ips": other_ips[:10], "special": _special(ip), "asn": None, "rdap": None, "rdns": None,
                 "service": None, "spf": None, "findings": []}
    F = out["findings"]
    if out["special"]:
        F.append({"severity": "info", "title": f"{ip} is a {out['special']} address",
                  "detail": "It isn't routable on the internet and has no public owner. In headers this is a hop inside someone's own network."})
        return out

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_asn = pool.submit(asn_lookup, res, ip)
        f_rdap = pool.submit(rdap_lookup, ip)
        f_rdns = pool.submit(fcrdns, res, ip)
        f_spf = pool.submit(analyze_spf, domain, None, ip) if domain else None
        out["asn"], out["rdap"], out["rdns"] = f_asn.result(), f_rdap.result(), f_rdns.result()
        spf = f_spf.result() if f_spf else None

    rd = out["rdap"] or {}
    # "GOOGLE - Google LLC, US" -> "Google LLC"
    as_org = re.sub(r",\s*[A-Z]{2}$", "", ((out["asn"] or {}).get("name") or "").split(" - ", 1)[-1]).strip() or None
    candidates = [(rd.get("registrant") or {}).get("name"), as_org, rd.get("name")]
    # Skip registry handles like MNT-GOOG-PROD or NET-8-8-8-0-1 when a real name exists.
    owner = next((c for c in candidates if c and not re.fullmatch(r"[A-Z0-9_-]+", c)), None) or next((c for c in candidates if c), None)
    out["owner"] = owner
    out["service"] = identify_service(out["rdns"]["ptr"], out["asn"], owner)
    svc = out["service"]

    # Mail-sender heuristics only become warnings in a mail context (a domain was
    # given): a web server or a cloud API endpoint without PTR is perfectly normal.
    mail_ctx = bool(domain)
    lvl = "warning" if mail_ctx else "info"
    if_mail = "" if mail_ctx else "If this IP sends email: "
    if not out["rdns"]["ptr"]:
        F.append({"severity": lvl, "title": "No reverse DNS (PTR)",
                  "detail": if_mail + "legitimate mail servers almost always have a PTR, and Gmail and many others reject mail from IPs without one. "
                            "A missing PTR often means a home/dynamic connection, a cloud VM, or a misconfigured server."})
    elif not out["rdns"]["forward_confirmed"]:
        F.append({"severity": "info", "title": "Reverse DNS does not resolve back to this IP",
                  "detail": f"PTR {out['rdns']['ptr'][0]} doesn't forward-confirm (FCrDNS fails). " + (if_mail + "some receivers penalise this." if if_mail else "Some mail receivers penalise this.")})
    if svc:
        F.append({"severity": "info", "title": f"Identified as {svc['name']} ({svc['confidence']} confidence, by {svc['matched_on']})",
                  "detail": svc["note"] or ""})
    asn_name = ((out.get("asn") or {}).get("name") or "").lower()
    hosting = any(h in asn_name for h in ("amazon", "microsoft", "google", "cloudflare", "akamai", "fastly", "github", "digitalocean", "ovh", "hetzner", "linode", "oracle"))
    ptr_text = " ".join(out["rdns"]["ptr"])
    # Words that really indicate end-user access ranges; the bare a-b-c-d pattern only counts on non-hosting networks
    # (load balancers like lb-140-82-113-4.github.com use it too).
    generic = re.search(r"dynamic|dyn\b|dhcp|pool|cable|dsl|broadband|residential|ppp|\bcust|client", ptr_text, re.I) or \
        (not hosting and re.search(r"\d+-\d+-\d+-\d+", ptr_text))
    if generic and not svc:
        F.append({"severity": lvl, "title": "Reverse DNS looks generic (residential or dynamic range)",
                  "detail": if_mail + "mail sent straight from an end-user connection or a bare cloud VM is usually a misconfigured device or app "
                            "(scanner, NAS, line-of-business app) or a compromised machine. It should relay through your mail platform instead."})

    if spf:
        test = spf.get("test") or {}
        out["spf"] = {"domain": domain, "record": spf.get("record"), "result": test.get("result"),
                      "trace": test.get("trace", []), "explanation": test.get("explanation"),
                      "lookup_count": spf.get("lookup_count"), "includes": spf.get("includes", [])}
        result = test.get("result")
        if spf.get("multiple"):
            out["spf"]["multiple"] = True
            out["spf"]["merged"] = spf["merged"]
            F.insert(0, {"severity": "critical", "title": f"{domain} publishes {len(spf['records'])} SPF records, so SPF fails for every sender, including {ip}",
                         "detail": f"Nothing needs adding for this IP: after merging the records into one, {ip} would get '{test.get('after_merge')}'.\n"
                                   f"Merged record: {spf['merged']['record']}\nOpen the SPF Builder for {domain}: it pre-loads the merged record."})
        elif result == "pass":
            F.insert(0, {"severity": "ok", "title": f"{ip} is authorised by {domain}'s SPF",
                         "detail": "Matched: " + " ⟵ ".join(f"{t['domain']}: {t['term']}" for t in test.get("trace", []))})
        else:
            sev = "critical" if result in ("fail", "permerror") else "warning"
            advice = []
            if svc and svc["spf_include"]:
                already = svc["spf_include"] in spf.get("includes", [])
                advice.append(f"{domain}'s SPF already includes {svc['spf_include']}, but this IP still isn't covered. Check the service's current IP ranges or account-specific settings." if already
                              else f"If {svc['name']} legitimately sends for {domain}, add  include:{svc['spf_include']}  to the SPF record. Currently {spf.get('lookup_count')}/10 lookups; this adds at least 1.")
            elif svc:
                advice.append(f"If {svc['name']} legitimately sends for {domain}: {svc['note']}")
            else:
                advice.append(f"Owner: {owner or 'unknown'}. Decide whether this sender is legitimate. If yes, add its SPF include (from the vendor's docs) or ip4:{ip}. "
                              "If not, it's spoofing your domain, which is what DMARC enforcement (quarantine/reject) is for.")
            if spf.get("lookup_count", 0) >= 9:
                advice.append("The record is already at or near the 10-lookup limit. Adding an include may break SPF for everything.")
            F.insert(0, {"severity": sev, "title": f"{ip} is NOT authorised by {domain}'s SPF (result: {result})",
                         "detail": "\n".join(advice)})
    if rd.get("error"):
        F.append({"severity": "info", "title": "Registration (RDAP) data unavailable", "detail": rd["error"]})
    return out
