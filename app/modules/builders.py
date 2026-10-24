"""Fix-it builders: produce a corrected SPF or DMARC record, validated live
against DNS before anyone publishes it."""
from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..core.dns_utils import make_resolver, normalize_domain, registered_domain, resolve, txt
from ..core.http import run
from ..core.providers import provider_for
from .domain import check_dkim, check_dmarc, parse_tags
from .spf import _parse_term, analyze_spf, get_spf_records, merge_records

router = APIRouter()

# Sending services and the SPF include each one documents. Only entries we're
# confident about; every include is also validated live when a record is built
# (a wrong one shows up as "include has no SPF record").
SPF_CATALOG: list[dict] = [
    {"id": "m365", "name": "Microsoft 365 / Exchange Online", "term": "include:spf.protection.outlook.com", "group": "Mail platform"},
    {"id": "google", "name": "Google Workspace", "term": "include:_spf.google.com", "group": "Mail platform"},
    {"id": "zoho", "name": "Zoho Mail (US)", "term": "include:zoho.com", "group": "Mail platform", "note": "Use zoho.eu / zoho.in for those data centres."},
    {"id": "zoho-eu", "name": "Zoho Mail (EU)", "term": "include:zoho.eu", "group": "Mail platform"},
    {"id": "mimecast-us", "name": "Mimecast (US)", "term": "include:us._netblocks.mimecast.com", "group": "Email security gateway"},
    {"id": "mimecast-eu", "name": "Mimecast (EU)", "term": "include:eu._netblocks.mimecast.com", "group": "Email security gateway"},
    {"id": "mimecast-uk", "name": "Mimecast (UK)", "term": "include:_netblocks.mimecast.com", "group": "Email security gateway"},
    {"id": "mimecast-za", "name": "Mimecast (South Africa)", "term": "include:za._netblocks.mimecast.com", "group": "Email security gateway"},
    {"id": "mimecast-au", "name": "Mimecast (Australia)", "term": "include:au._netblocks.mimecast.com", "group": "Email security gateway"},
    {"id": "barracuda", "name": "Barracuda Email Security Service", "term": "include:spf.ess.barracudanetworks.com", "group": "Email security gateway"},
    {"id": "sendgrid", "name": "SendGrid (Twilio)", "term": "include:sendgrid.net", "group": "Bulk / transactional"},
    {"id": "mailgun", "name": "Mailgun", "term": "include:mailgun.org", "group": "Bulk / transactional"},
    {"id": "ses", "name": "Amazon SES", "term": "include:amazonses.com", "group": "Bulk / transactional",
     "note": "Better: configure a custom MAIL FROM subdomain in SES so SPF aligns for DMARC."},
    {"id": "postmark", "name": "Postmark", "term": "include:spf.mtasv.net", "group": "Bulk / transactional",
     "note": "Postmark recommends a custom Return-Path instead."},
    {"id": "sparkpost", "name": "SparkPost / Bird", "term": "include:sparkpostmail.com", "group": "Bulk / transactional"},
    {"id": "mandrill", "name": "Mandrill (Mailchimp Transactional)", "term": "include:spf.mandrillapp.com", "group": "Bulk / transactional"},
    {"id": "mailchimp", "name": "Mailchimp", "term": "include:servers.mcsv.net", "group": "Marketing",
     "note": "Mailchimp sends with its own Return-Path; its domain authentication (DKIM CNAMEs) matters more for DMARC."},
    {"id": "brevo", "name": "Brevo (Sendinblue)", "term": "include:spf.brevo.com", "group": "Marketing"},
    {"id": "mailjet", "name": "Mailjet", "term": "include:spf.mailjet.com", "group": "Marketing"},
    {"id": "constantcontact", "name": "Constant Contact", "term": "include:spf.constantcontact.com", "group": "Marketing"},
    {"id": "salesforce", "name": "Salesforce", "term": "include:_spf.salesforce.com", "group": "CRM / helpdesk"},
    {"id": "zendesk", "name": "Zendesk", "term": "include:mail.zendesk.com", "group": "CRM / helpdesk"},
    {"id": "freshdesk", "name": "Freshdesk", "term": "include:email.freshdesk.com", "group": "CRM / helpdesk"},
]
_CATALOG_BY_TERM = {c["term"]: c for c in SPF_CATALOG}
ALL_QUALIFIERS = {"-all": "Hard fail: unlisted senders fail SPF", "~all": "Soft fail: unlisted senders are suspicious (recommended with DMARC enforcement)",
                  "?all": "Neutral: no assertion (not recommended)"}


def _f(sev: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "title": title, "detail": detail}


def _top_terms(tree: dict) -> list[dict]:
    out = []
    for t in tree.get("terms", []):
        if t["kind"] == "mechanism" and t.get("mechanism") == "all":
            continue
        if t["kind"] == "modifier" and t["name"] != "redirect":
            continue
        cat = _CATALOG_BY_TERM.get(t["raw"].lstrip("+").lower())
        out.append({"raw": t["raw"], "kind": t["kind"], "mechanism": t.get("mechanism") or t.get("name"),
                    "lookup_cost": t.get("lookup_cost", 0), "service": cat["name"] if cat else _guess_service(t),
                    "error": t.get("error") or (t.get("child") or {}).get("error")})
    return out


def _guess_service(t: dict) -> str | None:
    dom = (t.get("domain") or "").lower()
    if not dom:
        return None
    p = provider_for(dom)
    return p["name"] if p else None


# ------------------------------------------------------------------------- SPF
def spf_current(domain: str) -> dict:
    domain = normalize_domain(domain)
    res = make_resolver()
    records, _ = get_spf_records(res, domain)
    current = analyze_spf(domain) if records else None
    tree = (current or {}).get("tree") or {}
    if current and current.get("multiple"):
        # Several records: start from all of them merged, never from an empty record
        # (that would de-authorise every sender).
        tree = analyze_spf(domain, record=current["merged"]["record"])["tree"]
    all_term = next((t["raw"] for t in tree.get("terms", []) if t["kind"] == "mechanism" and t.get("mechanism") == "all"), None)

    # Suggest services the domain evidently uses but SPF doesn't cover.
    suggestions = []
    mx, _ = resolve(res, domain, "MX")
    providers = {(provider_for(r.exchange.to_text(omit_final_dot=True)) or {}).get("name") for r in mx}
    includes = set((current or {}).get("includes", []))
    if "Microsoft 365" in providers and "spf.protection.outlook.com" not in includes:
        suggestions.append({"id": "m365", "reason": "MX points to Microsoft 365"})
    if "Google" in providers and "_spf.google.com" not in includes:
        suggestions.append({"id": "google", "reason": "MX points to Google"})
    return {
        "domain": domain, "record": records[0] if records else None, "multiple": len(records) > 1, "records": records,
        "terms": _top_terms(tree), "all": (all_term or "~all").lstrip("+") if all_term != "+all" else "~all",
        "lookup_count": (current or {}).get("lookup_count", 0),
        "findings": (current or {}).get("findings", []), "catalog": SPF_CATALOG, "all_options": ALL_QUALIFIERS,
        "suggestions": suggestions,
    }


def _normalize_term(raw: str) -> str:
    t = raw.strip()
    if not t:
        return ""
    low = t.lower()
    # Friendly input: a bare IP / range becomes ip4:/ip6:, a bare domain becomes include:
    try:
        net = ipaddress.ip_network(t, strict=False)
        return f"ip{net.version}:{t}"
    except ValueError:
        pass
    if re.fullmatch(r"(?!-)[a-z0-9_.-]+\.[a-z]{2,}", low) and not low.startswith(("include:", "a:", "mx:", "exists:", "ptr")):
        return f"include:{low}"
    return t


def spf_build(domain: str, terms: list[str], all_q: str) -> dict:
    domain = normalize_domain(domain)
    if all_q not in ALL_QUALIFIERS:
        raise ValueError("The 'all' setting must be -all, ~all or ?all. (+all would let anyone send as the domain.)")
    clean: list[str] = []
    errors: list[str] = []
    for raw in terms:
        t = _normalize_term(raw)
        if not t:
            continue
        if t.lower() in ("v=spf1",) or t.lower().lstrip("+-~?") == "all":
            continue
        parsed = _parse_term(t)
        if parsed.get("error"):
            errors.append(f"{t}: {parsed['error']}")
            continue
        if parsed["kind"] == "modifier" and parsed["name"] != "redirect":
            errors.append(f"{t}: unsupported modifier")
            continue
        if parsed["kind"] == "modifier" and parsed["name"] == "redirect":
            errors.append(f"{t}: redirect can't be combined with an 'all' mechanism; use include: instead")
            continue
        if t.lower() not in (c.lower() for c in clean):
            clean.append(t)
    if errors:
        raise ValueError("Invalid SPF terms: " + "; ".join(errors))

    record = " ".join(["v=spf1", *clean, all_q])
    built = analyze_spf(domain, record=record)
    res = make_resolver()
    published, _ = get_spf_records(res, domain)
    # Compare against what's published; several records are compared as their merged union.
    baseline = (published[0] if len(published) == 1 else merge_records(published)) if published else ""
    cur_terms = [t.lower() for t in baseline.split()[1:]]
    new_terms = [t.lower() for t in record.split()[1:]]
    added = [t for t in record.split()[1:] if t.lower() not in cur_terms]
    removed = [t for t in baseline.split()[1:] if t.lower() not in new_terms]

    n = built["lookup_count"]
    terms_out = _top_terms(built["tree"])
    costly = sorted([t for t in terms_out if t["lookup_cost"] > 1], key=lambda t: -t["lookup_cost"])
    broken = [f for f in built["findings"] if f["severity"] == "critical"]
    findings = [f for f in built["findings"] if f["severity"] in ("critical", "warning")]
    pub_all = next((t.lower() for t in baseline.split()[1:] if t.lower().lstrip("+").endswith("all")), None)
    strength = {"-all": 2, "~all": 1, "?all": 0}
    if pub_all in strength and strength[all_q] < strength[pub_all]:
        findings.insert(0, _f("warning", f"This weakens SPF: {pub_all} → {all_q}",
                              "Unlisted senders that fail SPF today would only soft-fail or be neutral. Fine if DMARC is enforcing; otherwise this makes spoofing easier."))

    if n > 10:
        sev = "critical"
        headline = f"Don't publish yet: {n}/10 DNS lookups. Receivers will treat SPF as broken (PermError)."
        sub = "Biggest costs: " + ", ".join(f"{t['raw']} ({t['lookup_cost']})" for t in costly[:4]) + \
              ". Remove services that no longer send, replace a/mx with ip4/ip6, or move marketing senders to a subdomain (e.g. mail.contoso.com)."
    elif broken:
        sev = "critical"
        headline = f"Don't publish yet: {broken[0]['title']}"
        sub = broken[0]["detail"]
    elif n >= 9:
        sev = "warning"
        headline = f"Valid, but at {n}/10 lookups there's almost no headroom"
        sub = "One more vendor include, or a vendor adding a nested include, will break SPF."
    else:
        sev = "ok"
        headline = f"Ready to publish: valid SPF with {n}/10 DNS lookups"
        sub = "Replace the existing SPF TXT record with this one. A domain must have exactly ONE v=spf1 record."
    weak = next((f for f in findings if f["title"].startswith("This weakens")), None)
    if weak and sev == "ok":
        sev = "warning"
        headline = f"Valid ({n}/10 lookups), but {weak['title'][0].lower()}{weak['title'][1:]}"
        sub = weak["detail"]
    if len(published) > 1 and sev in ("ok", "warning") and not weak:
        headline = f"Ready to publish: this merges your {len(published)} SPF records into one ({n}/10 DNS lookups)"
        sub = f"Publish this record and DELETE all {len(published)} existing v=spf1 TXT records. Until then SPF fails for every sender."
    unchanged = len(published) == 1 and published[0].strip().lower() == record.lower()
    if unchanged:
        headline = "No changes: this is the record already published" + ("" if sev == "ok" else f" ({headline[0].lower()}{headline[1:]})")

    chunks = [record[i:i + 255] for i in range(0, len(record), 255)]
    return {
        "domain": domain, "record": record, "severity": sev, "headline": headline, "subline": sub,
        "lookup_count": n, "void_lookups": built["void_lookups"], "networks": len(built["networks"]),
        "terms": terms_out, "findings": findings, "published": published, "added": added, "removed": removed,
        "unchanged": unchanged, "multiple_published": len(published) > 1,
        "dns": {"host": "@", "fqdn": domain, "type": "TXT", "ttl": 3600, "value": record,
                "bind": f'{domain}. 3600 IN TXT ' + " ".join(f'"{c}"' for c in chunks), "chunked": len(chunks) > 1},
    }


# ----------------------------------------------------------------------- DMARC
def _mailto_list(values: list[str]) -> list[str]:
    out = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        addr = v[7:] if v.lower().startswith("mailto:") else v
        addr = addr.split("!")[0]
        if not re.fullmatch(r"[^@\s,;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", addr):
            raise ValueError(f"'{v}' is not a valid report email address")
        out.append(f"mailto:{addr}")
    return list(dict.fromkeys(out))


def _external_auth(res, domain: str, uri: str) -> dict:
    dest = uri[7:].split("@")[-1].lower()
    if registered_domain(dest) == registered_domain(domain):
        return {"uri": uri, "external": False, "authorized": True}
    recs, _ = txt(res, f"{domain}._report._dmarc.{dest}")
    ok = any(r.lower().replace(" ", "").startswith("v=dmarc1") for r in recs)
    return {"uri": uri, "external": True, "authorized": ok, "check": f"{domain}._report._dmarc.{dest}"}


def _canon_dmarc(record: str) -> dict:
    """Tags with defaults removed, so 'pct=100' and no pct compare equal."""
    tags = {k: v.strip().lower().replace(" ", "") for k, v in parse_tags(record)[0].items()}
    defaults = {"pct": "100", "adkim": "r", "aspf": "r", "fo": "0", "rf": "afrf", "ri": "86400"}
    if tags.get("sp") == tags.get("p"):
        tags.pop("sp", None)
    return {k: v for k, v in tags.items() if defaults.get(k) != v}


def dmarc_current(domain: str) -> dict:
    domain = normalize_domain(domain)
    res = make_resolver()
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_dmarc = pool.submit(check_dmarc, res, domain)
        f_spf = pool.submit(analyze_spf, domain)
        f_dkim = pool.submit(check_dkim, res, domain, [])
        dmarc, spf, dkim = f_dmarc.result(), f_spf.result(), f_dkim.result()
    keys = [k for k in dkim["found"] if k.get("bits")]
    spf_ok = bool(spf.get("record")) and spf["lookup_count"] <= 10 and not any(f["severity"] == "critical" for f in spf["findings"])
    sends_mail = (spf.get("record") or "").lower().split() != ["v=spf1", "-all"]
    tags = dmarc.get("tags", {})
    return {
        "domain": domain, "record": dmarc.get("record"), "inherited": dmarc.get("inherited"), "source": dmarc.get("source"),
        "tags": tags,
        "readiness": {"sends_mail": sends_mail, "spf_ok": spf_ok, "spf_record": spf.get("record"), "spf_lookups": spf.get("lookup_count"),
                      "dkim_selectors": [k["selector"] for k in keys], "dkim_ok": bool(keys)},
        "defaults": {
            # A domain that sends no mail can go straight to reject: there's no legitimate mail to break.
            "p": tags.get("p", "none").lower() if tags.get("p", "").lower() in ("none", "quarantine", "reject") else ("none" if sends_mail else "reject"),
            "sp": tags.get("sp", "").lower(), "pct": tags.get("pct", "100"),
            "rua": [u.strip() for u in tags.get("rua", "").split(",") if u.strip()],
            "ruf": [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()],
            "adkim": tags.get("adkim", "r").lower(), "aspf": tags.get("aspf", "r").lower(), "fo": tags.get("fo", "0"),
        },
    }


def dmarc_build(domain: str, p: str, sp: str, pct: int, rua: list[str], ruf: list[str],
                adkim: str, aspf: str, fo: str) -> dict:
    domain = normalize_domain(domain)
    if p not in ("none", "quarantine", "reject"):
        raise ValueError("Policy must be none, quarantine or reject.")
    if sp and sp not in ("none", "quarantine", "reject"):
        raise ValueError("Subdomain policy must be none, quarantine or reject (or blank to inherit p).")
    if not 0 <= int(pct) <= 100:
        raise ValueError("pct must be between 0 and 100.")
    if adkim not in ("r", "s") or aspf not in ("r", "s"):
        raise ValueError("Alignment must be r (relaxed) or s (strict).")
    if not re.fullmatch(r"[01ds](:[01ds])*", fo or "0"):
        raise ValueError("fo must be 0, 1, d, s or a colon-separated combination.")
    rua_l, ruf_l = _mailto_list(rua), _mailto_list(ruf)

    parts = ["v=DMARC1", f"p={p}"]
    if sp and sp != p:
        parts.append(f"sp={sp}")
    if int(pct) != 100:
        parts.append(f"pct={int(pct)}")
    if rua_l:
        parts.append("rua=" + ",".join(rua_l))
    if ruf_l:
        parts.append("ruf=" + ",".join(ruf_l))
    if adkim == "s":
        parts.append("adkim=s")
    if aspf == "s":
        parts.append("aspf=s")
    if ruf_l and fo and fo != "0":
        parts.append(f"fo={fo}")
    record = "; ".join(parts)

    current = dmarc_current(domain)
    rd = current["readiness"]
    res = make_resolver()
    with ThreadPoolExecutor(max_workers=6) as pool:
        auth = list(pool.map(lambda u: _external_auth(res, domain, u), rua_l + ruf_l))

    findings: list[dict] = []
    enforcing = p in ("quarantine", "reject")
    if not rua_l:
        findings.append(_f("warning", "No aggregate report address (rua)",
                           "Without reports you can't see which senders fail, so you can't safely move to enforcement. Add a mailbox or a DMARC reporting service."))
    for a in auth:
        if a["external"] and not a["authorized"]:
            findings.append(_f("warning", f"{a['uri'][7:]} hasn't authorised receiving reports for {domain}",
                               f"Receivers check TXT {a['check']} (must contain v=DMARC1). Most DMARC services publish a wildcard; if yours doesn't, reports will be dropped."))
    if not rd.get("sends_mail", True):
        if p != "reject":
            findings.append(_f("warning", "This domain sends no mail: use p=reject",
                               "Its SPF is v=spf1 -all, so nothing legitimate can fail DMARC. p=reject blocks anyone spoofing it, with no risk."))
    elif enforcing and not rd["dkim_ok"] and not rd["spf_ok"]:
        findings.append(_f("critical", "Neither SPF nor DKIM is working for this domain",
                           f"With p={p}, ALL mail from {domain} would fail DMARC. Fix SPF and enable DKIM first."))
    elif enforcing and not rd["dkim_ok"]:
        findings.append(_f("warning", "No DKIM keys found on common selectors",
                           "DMARC would rely on SPF alone, which breaks whenever mail is forwarded. Enable DKIM signing before enforcing (check a sent message's s= tag if you use a custom selector)."))
    elif enforcing and not rd["spf_ok"]:
        findings.append(_f("warning", "SPF is missing or broken", "DMARC would rely on DKIM alone. Fix SPF with the SPF Builder."))
    if p == "reject" and int(pct) < 100:
        findings.append(_f("info", f"pct={pct} with p=reject", f"The remaining {100 - int(pct)}% of failing mail gets the next policy down (quarantine)."))
    if p != "none" and sp == "none":
        findings.append(_f("warning", "sp=none leaves subdomains unprotected", "Attackers can spoof anything.{0}. Leave sp blank to inherit p, unless subdomains are still being onboarded.".format(domain)))
    if adkim == "s" or aspf == "s":
        findings.append(_f("info", "Strict alignment", "Subdomain senders (e.g. mail." + domain + ") will fail. Relaxed is right for most organisations."))
    cur_p = (current["tags"].get("p") or "").lower()
    rank = {"none": 0, "quarantine": 1, "reject": 2}
    try:
        cur_pct = int(current["tags"].get("pct", "100"))
    except ValueError:
        cur_pct = 100
    if cur_p in rank and rank[p] < rank[cur_p]:
        findings.append(_f("warning", f"This weakens protection: p={cur_p} → p={p}",
                           f"Spoofed mail that {'is rejected' if cur_p == 'reject' else 'goes to junk'} today would be "
                           f"{'delivered' if p == 'none' else 'sent to junk instead of rejected'}. Only do this deliberately, e.g. to troubleshoot a legitimate sender, and plan to restore it."))
    elif cur_p == p and p != "none" and int(pct) < cur_pct:
        findings.append(_f("warning", f"This weakens protection: pct={cur_pct} → pct={pct}",
                           f"{cur_pct - int(pct)}% of failing mail would no longer get p={p}."))
    if cur_p == "none" and p == "reject":
        findings.append(_f("warning", "Jumping straight from p=none to p=reject",
                           "Safer: quarantine at pct=25 → 100 first, watching the aggregate reports for legitimate senders that fail."))
    if ruf_l:
        findings.append(_f("info", "Forensic reports (ruf) requested", "Few receivers send them (privacy), and those that do may include message content."))

    sev = "critical" if any(f["severity"] == "critical" for f in findings) else "warning" if any(f["severity"] == "warning" for f in findings) else "ok"
    stage = {"none": "Monitoring only: nothing is blocked, you collect reports.",
             "quarantine": f"Enforcing: failing mail goes to junk/quarantine ({pct}% of it).",
             "reject": "Full enforcement: failing mail is rejected." if int(pct) == 100 else
                       f"Partial enforcement: {pct}% of failing mail is rejected, the rest is quarantined."}[p]
    if sev == "critical":
        headline = f"Don't publish yet: {next(f['title'] for f in findings if f['severity'] == 'critical')}"
    elif sev == "warning":
        headline = f"Publishable, but check first: {next(f['title'] for f in findings if f['severity'] == 'warning')}"
    else:
        headline = f"Ready to publish: p={p} for {domain}"
    unchanged = bool(current["record"]) and not current["inherited"] and \
        _canon_dmarc(current["record"]) == _canon_dmarc(record)
    if unchanged:
        issue = next((f["title"] for f in findings if f["severity"] == sev), None) if sev != "ok" else None
        headline = "No changes: this matches the published record" + (f", but note: {issue}" if issue else "")
    return {"domain": domain, "record": record, "severity": sev, "headline": headline, "subline": stage,
            "findings": findings, "auth": auth, "current": current["record"], "inherited": current["inherited"],
            "readiness": rd, "unchanged": unchanged,
            "dns": {"host": "_dmarc", "fqdn": f"_dmarc.{domain}", "type": "TXT", "ttl": 3600, "value": record}}


# ---------------------------------------------------------------------- routes
class SpfBuildRequest(BaseModel):
    domain: str = Field(..., max_length=253)
    terms: list[str] = Field(default_factory=list, max_length=60)
    all: str = "~all"


class DmarcBuildRequest(BaseModel):
    domain: str = Field(..., max_length=253)
    p: str = "none"
    sp: str = ""
    pct: int = 100
    rua: list[str] = Field(default_factory=list, max_length=10)
    ruf: list[str] = Field(default_factory=list, max_length=10)
    adkim: str = "r"
    aspf: str = "r"
    fo: str = "0"


@router.get("/api/builder/spf/{domain:path}")
def spf_current_route(domain: str):
    return run(spf_current, domain)


@router.post("/api/builder/spf")
def spf_build_route(body: SpfBuildRequest):
    return run(spf_build, body.domain, body.terms, body.all)


@router.get("/api/builder/dmarc/{domain:path}")
def dmarc_current_route(domain: str):
    return run(dmarc_current, domain)


@router.post("/api/builder/dmarc")
def dmarc_build_route(body: DmarcBuildRequest):
    return run(dmarc_build, body.domain, body.p, body.sp, body.pct, body.rua, body.ruf, body.adkim, body.aspf, body.fo)
