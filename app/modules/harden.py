"""Hardening Plan: a prioritised checklist of the public-facing hardening controls
for a client's domain, each with its status and the exact fix.

Built on Domain Discovery (discover()) plus a handful of extra DNS lookups for
detail it doesn't return (the SPF ending and full findings, DMARC tags and
findings, the mail platform's DKIM selectors, raw CAA, the MTA-STS TXT record).
Everything stays passive: DNS, public registries and the single website visit
discover() already makes. Tenant settings that can't be seen from outside are
listed as manual checks with read-only PowerShell.

plan_from(disc, extra) is a pure function of those inputs, so every control can
be tested offline with synthetic data."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter

from ..core import cmdsafe
from ..core.dns_utils import make_resolver, normalize_domain, registered_domain, resolve, txt
from ..core.http import run
from .discovery import discover
from .domain import _check_selector, check_dmarc, parse_tags
from .spf import analyze_spf

router = APIRouter()

AREAS = [
    {"id": "email-auth", "title": "Email authentication", "desc": "SPF, DKIM and DMARC stop others sending as the domain."},
    {"id": "mail-transport", "title": "Mail transport security", "desc": "How mail reaches the domain: encrypted delivery and filtering."},
    {"id": "domain", "title": "Domain & registrar", "desc": "Keep the domain from expiring, being transferred away or getting rogue certificates."},
    {"id": "dns-hygiene", "title": "DNS hygiene", "desc": "Stale or leaky records in the public DNS zone."},
    {"id": "web", "title": "Website", "desc": "Encryption and security basics for the public website."},
    {"id": "exposure", "title": "Internet exposure", "desc": "Remote access and servers visible from the internet, judged from host names in DNS (nothing is scanned)."},
    {"id": "m365", "title": "Microsoft 365 tenant (verify manually)",
     "desc": "Exchange Online and Entra ID settings that can't be seen from outside. Run the read-only commands to check them."},
]

# ccTLD registries that don't use EPP client transfer locks (transfers use auth codes / registrar tags).
from .netdiag import _NO_CLIENT_LOCK_TLDS as NO_CLIENT_LOCK_TLDS  # one list for every tool
# Certificate issuer (organisation / CA name) → the CAA identifier that CA documents.
CAA_IDS: list[tuple[str, str]] = [
    (r"let'?s encrypt|\bisrg\b", "letsencrypt.org"),
    (r"digicert|geotrust|rapidssl|thawte|symantec", "digicert.com"),
    (r"sectigo|comodo|usertrust|zerossl", "sectigo.com"),
    (r"globalsign", "globalsign.com"),
    (r"google trust services", "pki.goog"),
    (r"\bamazon\b", "amazon.com"),
    (r"starfield", "starfieldtech.com"),
    (r"godaddy", "godaddy.com"),
    (r"entrust", "entrust.net"),
    (r"ssl corporation|\bssl\.com\b", "ssl.com"),
    (r"buypass", "buypass.com"),
]
# Remote-access names served from cloud compute (not a vendor's own service) still need a manual look.
_COMPUTE_SERVICES = {"Azure virtual machine", "AWS load balancer", "Amazon Web Services"}
_LEVEL = {"none": 0, "quarantine": 1, "reject": 2}
_RANK = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
_STATUSES = ("pass", "fail", "warn", "manual", "unknown", "na")
# Tie-break for "fix first" when severity and priority are equal: the most damaging gaps first.
_IMPORTANCE = ["expiry", "dmarc-published", "spf-valid", "spf-all", "spf-lookups", "remote-access", "dangling-cname",
               "private-ips", "dkim", "dmarc-enforced", "selfhosted-mail", "null-mx", "dmarc-rua", "https", "dnssec",
               "transfer-lock", "inbound-filtering", "hsts"]
EXTRA_BUDGET = 9.0  # seconds from the start of the request that the extra lookups may take
# Lockdown DMARC for a domain that sends no mail (subdomains too); the Parked Domain builder publishes the same record.
LOCK_DMARC = "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"
CONNECT_EXO = "Connect to Exchange Online PowerShell first: Connect-ExchangeOnline (ExchangeOnlineManagement module)."
DEFENDER_DKIM = ("Defender portal → Email & collaboration → Policies & rules → Threat policies → "
                 "Email authentication settings → DKIM")


# ------------------------------------------------------------------ helpers
def _g(d, *path, default=None):
    """Nested dict get that tolerates missing or non-dict levels."""
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return default if cur is None else cur


def _clip(s, n: int = 220) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else many or word + 's'}"


def _fix(summary: str, *, tool: str | None = None, params: dict | None = None, label: str | None = None,
         records: list | None = None, commands: list | None = None, steps: list | None = None) -> dict:
    return {"summary": summary, "tool": tool, "params": params if tool else None, "tool_label": label if tool else None,
            "records": records or [], "commands": commands or [], "steps": steps or []}


def _rec(rtype: str, name: str, value: str) -> dict:
    return {"type": rtype, "name": name, "value": value}


def _resolve_cmd(name: str, rtype: str) -> str | None:
    """Resolve-DnsName check for a DNS name we generated or validated (never raw DNS data)."""
    safe = cmdsafe.dns_name(name, "")
    return f"Resolve-DnsName -Name {safe} -Type {rtype} -Server 1.1.1.1" if safe else None


def _int(value, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _mail_server(c) -> str:
    """The mail platform as a phrase that reads well mid-sentence."""
    h = c.mail_host
    if not h or h.startswith("none") or "unclear" in h:
        return "the mail platform"
    if h.startswith(("self-hosted", "third-party", "unknown")) or "(" in h:
        return f"the mail server ({h})"
    return h


class _Controls(list):
    def add(self, cid: str, area: str, title: str, status: str, found: str, why: str, *, priority: int = 2,
            critical: bool = False, optional: bool = False, fix: dict | None = None, short: str | None = None,
            parent: str | None = None) -> None:
        severity = {"pass": "ok", "warn": "warning", "fail": "critical" if critical else "warning"}.get(status, "info")
        c = {"id": cid, "area": area, "title": title, "status": status, "severity": severity, "priority": priority,
             "found": found, "why": why, "optional": optional}
        if fix and status not in ("pass", "na"):
            c["fix"] = fix
        c["_short"], c["_parent"] = short or title[:1].lower() + title[1:], parent
        self.append(c)


# ------------------------------------------------------------------ context
class _Ctx:
    """Everything the controls need, normalised from discover() and the extra lookups."""


def _spf_all_raw(record: str | None) -> str | None:
    """Qualifier of the record's own 'all' (+ - ~ ?), 'redirect' when it defers to a redirect=, else None."""
    if not record:
        return None
    terms = record.split()[1:]
    for t in terms:
        low = t.lower()
        if low.lstrip("+-~?") == "all":
            return low[0] if low[0] in "+-~?" else "+"
    return "redirect" if any(t.lower().startswith("redirect=") for t in terms) else None


def _spf_all_tree(tree: dict) -> tuple[str | None, str | None]:
    """Qualifier of the effective 'all' (following redirect=) and the domain whose record holds it."""
    node, hops = tree, 0
    while isinstance(node, dict) and hops <= 12:
        if hops and node.get("temperror"):
            return "redirect", None
        for t in node.get("terms") or []:
            if t.get("kind") == "mechanism" and t.get("mechanism") == "all" and not t.get("ignored") and not t.get("error"):
                return t.get("qualifier") or "+", node.get("domain")
        node, hops = node.get("redirect"), hops + 1
    return None, None


def _spf_with_all(record: str, new: str = "~all") -> str | None:
    """The published record with its 'all' replaced (or added). None when the ending lives behind a redirect=."""
    terms = record.split()
    for i, t in enumerate(terms[1:], 1):
        if t.lower().lstrip("+-~?") == "all":
            return " ".join([*terms[:i], new, *terms[i + 1:]])
    if any(t.lower().startswith("redirect=") for t in terms):
        return None
    return " ".join([*terms, new])


def _spf_authorises(record: str) -> bool:
    """True if the record lets any server send (anything besides 'all', or a redirect)."""
    for t in record.lower().split()[1:]:
        name = re.split(r"[:/=]", t.lstrip("+-~?"), maxsplit=1)[0]
        if t.startswith("redirect=") or name in ("include", "a", "mx", "ptr", "ip4", "ip6", "exists"):
            return True
    return False


def _dmarc_with(record: str | None, changes: dict, drop: tuple = ()) -> str | None:
    """The published DMARC record with some tags changed. Keeps the owner's own values
    (rua, ruf, ...) so the result is ready to paste; None if the record can't be parsed."""
    if not record:
        return None
    tags, order, errors = parse_tags(record)
    if errors or not order or order[0] != "v" or "p" not in tags:
        return None
    out = []
    for k in dict.fromkeys(order):
        if k in drop:
            continue
        out.append(f"{k}={changes.get(k, tags[k])}")
        if k == "p":
            out += [f"{nk}={nv}" for nk, nv in changes.items() if nk not in tags]
    return "; ".join(out)


def _context(disc: dict, extra: dict, now: datetime) -> _Ctx:
    c = _Ctx()
    c.domain = d = normalize_domain(str(disc.get("domain") or ""))  # strict: safe to interpolate into commands
    c.now = now
    email = disc.get("email") if isinstance(disc.get("email"), dict) else None
    c.email_ok = email is not None
    email = email or {}

    # SPF: the full analysis when the extra lookup worked, else discover()'s summary.
    spf_x = extra.get("spf") if isinstance(extra.get("spf"), dict) and isinstance(extra["spf"].get("tree"), dict) else None
    spf_d = email.get("spf") if isinstance(email.get("spf"), dict) else None
    if spf_x and not spf_x.get("record") and (spf_d or {}).get("record"):
        spf_x = None  # the extra lookup failed transiently; discover() did see the record
    c.spf_known = bool(spf_x or spf_d)
    if spf_x:
        tree = spf_x["tree"]
        c.spf_record, c.spf_lookups = spf_x.get("record"), spf_x.get("lookup_count")
        c.spf_findings = [f for f in spf_x.get("findings") or [] if isinstance(f, dict)]
        c.spf_multiple = bool(spf_x.get("multiple"))
        c.spf_merged = _g(spf_x, "merged", "record")
        c.spf_includes = list(spf_x.get("includes") or [])
        c.spf_temperror = bool(tree.get("temperror")) and not c.spf_record
        c.spf_all, c.spf_all_at = _spf_all_tree(tree)
        if c.spf_all is None and _spf_all_raw(c.spf_record) == "redirect" and not tree.get("redirect"):
            c.spf_all = "redirect"
    else:
        spf_d = spf_d or {}
        c.spf_record, c.spf_lookups = spf_d.get("record"), spf_d.get("lookups")
        c.spf_findings = [f for f in spf_d.get("issues") or [] if isinstance(f, dict)]
        c.spf_multiple = any(re.match(r"\d+ SPF records published", str(f.get("title"))) for f in c.spf_findings)
        c.spf_merged = None
        c.spf_includes = list(spf_d.get("includes") or [])
        c.spf_temperror = not c.spf_record and any(f.get("title") == "Could not look up SPF" for f in c.spf_findings)
        c.spf_all, c.spf_all_at = _spf_all_raw(c.spf_record), None
    if c.spf_multiple and c.spf_merged:
        c.spf_all, c.spf_all_at = _spf_all_raw(c.spf_merged), None
    crit = [str(f.get("title") or "") for f in c.spf_findings if f.get("severity") == "critical"]
    # Lookups over 10 and +all have their own controls.
    c.spf_broken = [t for t in crit if not t.startswith(("No SPF record", "SPF ends in +all", "Too many DNS lookups"))]
    c.spf_ptr = any("'ptr'" in str(f.get("title")) for f in c.spf_findings)

    # DMARC: check_dmarc() adds findings (multiple records, report authorisation) to the record discover() returns.
    dm_x = extra.get("dmarc") if isinstance(extra.get("dmarc"), dict) and "tags" in extra["dmarc"] else None
    dm_d = email.get("dmarc") if isinstance(email.get("dmarc"), dict) else None
    if dm_x and not dm_x.get("record") and (dm_d or {}).get("record"):
        dm_x = None  # same: trust the record discover() found
    c.dmarc_known = bool(dm_x or dm_d)
    src = dm_x or dm_d or {}
    c.dmarc_record, c.dmarc_inherited = src.get("record"), bool(src.get("inherited"))
    c.dmarc_source = (dm_x or {}).get("source") or (registered_domain(d) if c.dmarc_inherited else d)
    dm_titles = [str(f.get("title") or "") for f in (dm_x or {}).get("findings") or [] if isinstance(f, dict)]
    c.dmarc_failed = not c.dmarc_record and "DMARC lookup failed" in dm_titles
    c.dmarc_multiple = "Multiple DMARC records" in dm_titles
    tags, order, _ = parse_tags(c.dmarc_record) if c.dmarc_record else ({}, [], [])
    c.dmarc_tags = tags
    c.dmarc_p = tags.get("sp" if c.dmarc_inherited and "sp" in tags else "p", "").lower()
    c.dmarc_bad_reason = None
    if c.dmarc_record:
        if order and order[0] != "v":
            c.dmarc_bad_reason = "v=DMARC1 isn't the first tag"
        elif c.dmarc_p not in _LEVEL:
            c.dmarc_bad_reason = f"p={tags.get('p', '')!r} isn't none, quarantine or reject" if tags.get("p") else "it has no p= policy"
    c.dmarc_valid = bool(c.dmarc_record) and not c.dmarc_multiple and not c.dmarc_bad_reason
    c.dmarc_rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    c.dmarc_unauth = sorted({m.group(1) for t in dm_titles for m in [re.match(r"External rua destination (\S+) has not", t)] if m})

    # DKIM: keys discover() found, plus the platform selectors looked up directly
    # (which also shows CNAMEs that are published but have no key behind them).
    c.dkim_keys: dict[str, int] = {}
    for k in email.get("dkim") or []:
        if isinstance(k, dict) and k.get("bits"):
            c.dkim_keys[str(k.get("selector"))] = _int(k["bits"], 0)
    sel = extra.get("dkim") if isinstance(extra.get("dkim"), dict) else None
    c.dkim_cname_only = []
    for s, e in (sel or {}).items():
        if not isinstance(e, dict):
            continue
        if e.get("bits"):
            c.dkim_keys.setdefault(s, _int(e["bits"], 0))
        elif e.get("cname") and not e.get("revoked"):
            c.dkim_cname_only.append(s)
    c.dkim_known = "dkim" in email or sel is not None

    # Does the domain send or receive mail?
    c.mx = [m for m in email.get("mx") or [] if isinstance(m, dict)]
    c.null_mx = bool(email.get("null_mx"))
    c.mx_failed = not c.mx and not c.null_mx and extra.get("mx_status") in ("timeout", "servfail", "error")
    c.receives = bool(c.mx) and not c.null_mx
    c.gateways = [str(g) for g in email.get("gateways") or []]
    c.mail_host = str(email.get("mail_host") or _g(disc, "facts", "mail_host") or "")
    rec = (c.spf_record or "").strip().lower()
    c.declares_no_send = rec.split() == ["v=spf1", "-all"]
    if not c.email_ok:
        c.sends = True
    elif c.declares_no_send:
        c.sends = False
    else:
        # No MX and nothing authorised to send: treat as parked. Missing data never counts as parked.
        c.sends = bool(c.receives or c.mx_failed or c.spf_temperror or c.dkim_keys or (rec and _spf_authorises(rec)))
    c.parked = c.email_ok and not c.sends and not c.receives and not c.mx_failed
    if c.parked:
        c.platform = None
    elif c.mail_host in ("Microsoft 365", "Google Workspace"):
        c.platform = c.mail_host
    elif not c.receives:
        inc = set(c.spf_includes)
        c.platform = "Microsoft 365" if "spf.protection.outlook.com" in inc else "Google Workspace" if "_spf.google.com" in inc else None
    else:
        c.platform = c.mail_host or None
    c.mta_sts = email.get("mta_sts")
    c.tls_rpt = email.get("tls_rpt")
    c.mta_sts_txt = _g(extra, "mta_sts_txt", "record") if isinstance(extra.get("mta_sts_txt"), dict) else None

    # Microsoft 365 tenant (Microsoft's own test/consumer realms are not a client tenant).
    ident = disc.get("identity") if isinstance(disc.get("identity"), dict) else {}
    c.tenant_real = bool(ident.get("tenant_id")) and ident.get("idp") not in ("Microsoft (internal)", "Microsoft personal accounts")
    c.m365 = c.tenant_real or c.platform == "Microsoft 365"

    di = disc.get("domain_info") if isinstance(disc.get("domain_info"), dict) else {}
    c.reg = di.get("registration") if isinstance(di.get("registration"), dict) else None
    c.dns_host = di.get("dns_host") or _g(disc, "facts", "dns_host")
    c.caa_disc = di.get("caa") if isinstance(di.get("caa"), list) else None
    c.caa_raw = extra.get("caa") if isinstance(extra.get("caa"), list) else None
    infra = disc.get("infrastructure") if isinstance(disc.get("infrastructure"), dict) else None
    c.hosts = [h for h in infra.get("hosts") or [] if isinstance(h, dict) and h.get("host")] if infra else None
    c.checked = (infra or {}).get("checked")
    c.web = disc.get("website") if isinstance(disc.get("website"), dict) else None
    return c


# ------------------------------------------------------------------ email authentication
def _email_auth(c: _Ctx, C: _Controls) -> None:
    d, A = c.domain, "email-auth"
    spf_tool = {"tool": "spfbuild", "params": {"d": d}, "label": "Open SPF Builder"}
    dmarc_tool = {"tool": "dmarcbuild", "params": {"d": d}, "label": "Open DMARC Builder"}
    parked_tool = {"tool": "parked", "params": {"d": d}, "label": "Lock down a parked domain"}
    check_txt = [_resolve_cmd(d, "TXT")]
    check_dmarc_cmd = [_resolve_cmd(f"_dmarc.{c.dmarc_source}", "TXT")]
    confirm_unused = (f"Confirm nothing sends mail as {d} first (website forms, invoicing, CRM, scanners): "
                      "these records make receivers reject all of it.")
    unknown_spf = _fix("Re-run the check, or inspect SPF directly.", tool="spf", params={"d": d}, label="Open SPF Inspector")

    # --- SPF record
    if not c.sends:
        why = "A domain that sends no mail should publish v=spf1 -all, so every message claiming to come from it fails SPF."
        fix = _fix("Publish v=spf1 -all as the only SPF record.", **parked_tool, records=[_rec("TXT", d, "v=spf1 -all")],
                   commands=check_txt, steps=[confirm_unused, "Replace any other v=spf1 record (only one may exist)."])
        title = "SPF says the domain sends no mail (v=spf1 -all)"
        if c.declares_no_send:
            C.add("spf-valid", A, title, "pass", "Published: v=spf1 -all." + (
                " The domain still receives mail: if anyone sends from it, list those senders instead." if c.receives else ""),
                why, priority=1)
        elif not c.spf_record:
            C.add("spf-valid", A, title, "fail", f"No SPF record: anyone can send as @{d} and SPF can't flag it.", why,
                  priority=1, critical=True, fix=fix, short="no SPF record (v=spf1 -all)")
        else:
            plus = c.spf_all == "+"
            C.add("spf-valid", A, title, "fail", f"Published: {_clip(c.spf_record)}. The domain sends no mail, so it should be v=spf1 -all.",
                  why, priority=1, critical=plus, fix=fix, short="SPF ends in +all" if plus else "SPF isn't v=spf1 -all")
    else:
        why = "SPF lists the servers allowed to send as the domain; without a valid record receivers can't tell real mail from forgeries."
        title = "SPF record is published and valid"
        need = {"Microsoft 365": "spf.protection.outlook.com", "Google Workspace": "_spf.google.com"}.get(c.platform)
        if not c.spf_known:
            C.add("spf-valid", A, title, "unknown", "SPF data isn't available.", why, priority=1, fix=unknown_spf)
        elif c.spf_temperror:
            C.add("spf-valid", A, title, "unknown", "The SPF lookup failed with a DNS error, so SPF couldn't be checked.", why,
                  priority=1, fix=unknown_spf)
        elif not c.spf_record:
            records, steps = [], []
            if need:
                records = [_rec("TXT", d, f"v=spf1 include:{need} ~all")]
                steps.append(f"Add every other service that sends as {d} (website forms, CRM, newsletters) before publishing: "
                             "the SPF Builder checks the 10-lookup limit for you.")
            else:
                steps.append(f"List every server and service that sends as {d}, then build the record in the SPF Builder.")
            steps.append("End the record with ~all (or -all) and publish it as a TXT record on the domain itself.")
            C.add("spf-valid", A, title, "fail", f"No SPF record: receivers can't tell which servers may send as @{d}.", why,
                  priority=1, critical=True, short="no SPF record",
                  fix=_fix("Publish one SPF record listing every service that sends as the domain.", **spf_tool,
                           records=records, commands=check_txt, steps=steps))
        elif c.spf_multiple:
            records = [_rec("TXT", d, c.spf_merged)] if c.spf_merged else []
            C.add("spf-valid", A, title, "fail", "More than one v=spf1 record is published, so SPF fails for every message (PermError).",
                  why, priority=1, critical=True, short="multiple SPF records",
                  fix=_fix("Merge the SPF records into one.", **spf_tool, records=records, commands=check_txt,
                           steps=(["Publish the merged record below and delete the other v=spf1 records."] if records else
                                  ["Merge the records into one in the SPF Builder and delete the others."])))
        elif c.spf_broken:
            C.add("spf-valid", A, title, "fail", "SPF is broken: " + "; ".join(_clip(t, 120) for t in c.spf_broken[:3]) + ".", why,
                  priority=1, critical=True, short="a broken SPF record",
                  fix=_fix("Fix the errors so receivers can evaluate SPF again.", **spf_tool, commands=check_txt,
                           steps=["Open the record in the SPF Builder: it shows each broken include or syntax error.",
                                  "Remove or correct the broken parts, then publish the fixed record."]))
        elif need and not c.gateways and need not in c.spf_includes:
            C.add("spf-valid", A, title, "warn", f"Valid, but it doesn't authorise {c.platform} (include:{need} is missing), "
                  f"so mail sent from {c.platform} fails SPF.", why, priority=1, short=f"SPF doesn't include {c.platform}",
                  fix=_fix(f"Add include:{need} to the SPF record.", tool="spfbuild", params={"d": d, "add": f"include:{need}"},
                           label=f"Add include:{need} in the SPF Builder", commands=check_txt))
        elif c.spf_ptr:
            C.add("spf-valid", A, title, "warn", "Valid, but it uses the deprecated ptr mechanism, which many receivers ignore.", why,
                  priority=3, short="SPF uses the deprecated ptr mechanism",
                  fix=_fix("Replace ptr with ip4/ip6 or include terms.", **spf_tool, commands=check_txt))
        else:
            C.add("spf-valid", A, title, "pass", f"Published: {_clip(c.spf_record)}", why, priority=1)

    # --- SPF lookups
    title = "SPF stays within the 10 DNS-lookup limit"
    why = "Receivers stop after 10 DNS lookups and treat the record as broken, so SPF then fails for all mail."
    n = c.spf_lookups
    if not c.sends:
        C.add("spf-lookups", A, title, "na", "Not needed: the domain sends no mail.", why)
    elif not c.spf_known or c.spf_temperror:
        C.add("spf-lookups", A, title, "unknown", "SPF couldn't be read, so its lookups couldn't be counted.", why, fix=unknown_spf)
    elif not c.spf_record:
        C.add("spf-lookups", A, title, "na", "No SPF record to count yet.", why)
    elif n is None:
        C.add("spf-lookups", A, title, "unknown", "The lookup count isn't available.", why, fix=unknown_spf)
    elif n > 10:
        C.add("spf-lookups", A, title, "fail", f"{n}/10 DNS lookups: receivers stop at 10 and return PermError, so SPF fails for all mail.",
              why, priority=1, critical=True, short="SPF over the 10-lookup limit",
              fix=_fix("Cut the record to 10 lookups or fewer.", **spf_tool, commands=check_txt,
                       steps=["Remove includes for services that no longer send.", "Replace a and mx terms with ip4/ip6 ranges.",
                              "Move marketing or bulk senders to a subdomain with its own SPF record.",
                              "Check the result in the SPF Builder before publishing."]))
    elif n >= 9:
        C.add("spf-lookups", A, title, "warn", f"{n}/10 DNS lookups: one more include (or a vendor adding a nested one) breaks SPF.",
              why, priority=2, short=f"SPF at {n}/10 DNS lookups",
              fix=_fix("Make room before the next sender is added.", **spf_tool, commands=check_txt,
                       steps=["Remove includes for services that no longer send.", "Replace a and mx terms with ip4/ip6 ranges.",
                              "Move marketing or bulk senders to a subdomain with its own SPF record."]))
    else:
        C.add("spf-lookups", A, title, "pass", f"{n}/10 DNS lookups.", why)

    # --- SPF ending
    title = "SPF ends in -all or ~all"
    why = "The ending tells receivers what to do with servers that aren't listed; +all or ?all lets anyone pass."
    q, at = c.spf_all, c.spf_all_at
    via = f" (from redirect={at})" if at and at != d else ""
    if not c.sends:
        C.add("spf-all", A, title, "na", "Covered by v=spf1 -all above.", why)
    elif not c.spf_known or c.spf_temperror:
        C.add("spf-all", A, title, "unknown", "SPF couldn't be read.", why, fix=unknown_spf)
    elif not c.spf_record:
        C.add("spf-all", A, title, "fail", "No SPF record, so nothing tells receivers to flag unlisted servers.", why,
              priority=2, parent="spf-valid", short="no SPF ending",
              fix=_fix("Publish an SPF record ending in ~all (see above).", **spf_tool))
    elif q in ("-", "~"):
        C.add("spf-all", A, title, "pass", f"Ends in {q}all{via}.", why)
    elif q == "redirect":
        C.add("spf-all", A, title, "unknown", "The ending comes from a redirect= target that couldn't be read.", why, fix=unknown_spf)
    else:
        found = {"+": f"Ends in +all{via}: every server on the internet may send as {d}.",
                 "?": f"Ends in ?all{via} (neutral): unlisted servers get no verdict."}.get(q, "No all at the end: unlisted servers get a neutral result.")
        new = _spf_with_all(c.spf_merged if c.spf_multiple and c.spf_merged else c.spf_record) if not via else None
        steps = (["Publish the corrected record below (it only changes the ending).",
                  "~all with DMARC enforcement is the usual choice; -all is stricter but can reject forwarded mail."]
                 if new else [f"Change the ending in the record at {at or d} to ~all or -all."])
        C.add("spf-all", A, title, "fail", found, why, priority=1 if q == "+" else 2, critical=q == "+",
              short={"+": "SPF ends in +all", "?": "SPF ends in ?all"}.get(q, "SPF has no ~all/-all ending"),
              fix=_fix("End the record in ~all or -all.", **spf_tool, records=[_rec("TXT", d, new)] if new else [],
                       commands=check_txt, steps=steps))

    # --- DKIM
    _dkim(c, C)

    # --- DMARC record
    title = "DMARC record is published"
    why = "Without DMARC, receivers have no instruction to stop mail that fakes the domain."
    unknown_dmarc = _fix("Re-run the check, or look at the record in the DMARC Builder.", **dmarc_tool)
    if not c.sends:
        new_fix = _fix("Publish DMARC with p=reject.", **parked_tool, records=[_rec("TXT", f"_dmarc.{d}", LOCK_DMARC)],
                       commands=check_dmarc_cmd, steps=[confirm_unused])
    else:
        new_fix = _fix("Publish a DMARC record: start at p=none with reports, then tighten.", **dmarc_tool,
                       records=[_rec("TXT", f"_dmarc.{d}", "v=DMARC1; p=none")], commands=check_dmarc_cmd,
                       steps=["Add rua=mailto:<a mailbox you monitor, or your DMARC service's address> so reports arrive "
                              "(the DMARC Builder adds it for you).",
                              "After 2–4 weeks of clean reports, move to p=quarantine, then p=reject."])
    if not c.dmarc_known:
        C.add("dmarc-published", A, title, "unknown", "DMARC data isn't available.", why, priority=1, fix=unknown_dmarc)
    elif c.dmarc_failed:
        C.add("dmarc-published", A, title, "unknown", "The DMARC lookup failed with a DNS error.", why, priority=1, fix=unknown_dmarc)
    elif not c.dmarc_record:
        C.add("dmarc-published", A, title, "fail", f"No DMARC record at _dmarc.{d}: nothing tells receivers to stop mail that fakes @{d}.",
              why, priority=1, critical=True, short="no DMARC record", fix=new_fix)
    elif c.dmarc_multiple:
        C.add("dmarc-published", A, title, "fail", "More than one DMARC record is published, so receivers ignore DMARC completely.", why,
              priority=1, critical=True, short="multiple DMARC records",
              fix=_fix("Keep exactly one DMARC record.", **dmarc_tool, commands=check_dmarc_cmd,
                       steps=[f"Delete all but one TXT record at _dmarc.{c.dmarc_source}, merging anything you need (such as rua) into it."]))
    elif c.dmarc_bad_reason:
        C.add("dmarc-published", A, title, "fail", f"The record is invalid ({c.dmarc_bad_reason}), so receivers ignore it: {_clip(c.dmarc_record)}",
              why, priority=1, critical=True, short="an invalid DMARC record",
              fix=_fix("Rebuild the record so receivers accept it.", **dmarc_tool, commands=check_dmarc_cmd))
    elif c.dmarc_inherited:
        C.add("dmarc-published", A, title, "pass", f"Inherited from {c.dmarc_source}: {_clip(c.dmarc_record)}", why, priority=1)
    else:
        C.add("dmarc-published", A, title, "pass", f"Published: {_clip(c.dmarc_record)}", why, priority=1)

    # --- DMARC enforcement
    p, tags = c.dmarc_p, c.dmarc_tags
    pct, testing = _int(tags.get("pct"), 100), tags.get("t", "").strip().lower() == "y"
    rname = f"_dmarc.{c.dmarc_source}"
    if not c.sends:
        title = "DMARC policy is p=reject"
        why = "A domain that sends no mail can safely reject everything that claims to be from it."
    else:
        title = "DMARC is enforced (p=quarantine or p=reject at 100%)"
        why = "Only quarantine or reject stops spoofed mail; p=none just reports it."
    if not c.dmarc_known or c.dmarc_failed:
        C.add("dmarc-enforced", A, title, "unknown", "DMARC couldn't be read.", why, priority=1, fix=unknown_dmarc)
    elif not c.dmarc_valid:
        C.add("dmarc-enforced", A, title, "fail", "Nothing is enforced until a valid DMARC record exists (see above).", why,
              priority=2, parent="dmarc-published", short="DMARC not enforced",
              fix=_fix("Publish a valid DMARC record first, then enforce it.", **(parked_tool if not c.sends else dmarc_tool)))
    elif not c.sends:
        if p == "reject" and pct == 100 and not testing:
            C.add("dmarc-enforced", A, title, "pass", "p=reject: mail claiming to be from the domain is refused.", why, priority=1)
        else:
            new = None if c.dmarc_inherited else (_dmarc_with(c.dmarc_record, {"p": "reject"}, drop=("pct", "t")) or LOCK_DMARC)
            found = (f"p={p}: this domain sends no mail, so it can safely reject everything that claims to be from it." if p != "reject"
                     else f"p=reject, but only for {pct}% of failing mail." if pct != 100 else "p=reject, but in testing mode (t=y).")
            C.add("dmarc-enforced", A, title, "fail" if p != "reject" else "warn", found, why, priority=1,
                  short="DMARC isn't p=reject" if p != "reject" else "DMARC isn't fully enforced",
                  fix=_fix("Set the policy to p=reject.", **parked_tool, records=[_rec("TXT", rname, new)] if new else [],
                           commands=check_dmarc_cmd, steps=[confirm_unused]))
    else:
        def enforce_fix(changes: dict, summary: str, steps: list) -> dict:
            new = None if c.dmarc_inherited else _dmarc_with(c.dmarc_record, changes, drop=("pct", "t"))
            return _fix(summary, **dmarc_tool, records=[_rec("TXT", rname, new)] if new else [], commands=check_dmarc_cmd, steps=steps)
        check_reports = ("Check the aggregate reports first (DMARC Report Analyzer): every legitimate sender must pass SPF or DKIM "
                         "with an aligned domain, or its mail will be junked.")
        if p == "none":
            steps = [check_reports, "Publish the quarantine record below, watch the reports for a few weeks, then change it to p=reject."]
            if not any(u.lower().startswith("mailto:") for u in c.dmarc_rua):
                steps.insert(0, "There's no rua= reporting yet: add it first so you can see what would break.")
            C.add("dmarc-enforced", A, title, "fail", "p=none: monitoring only, so spoofed mail is still delivered.", why, priority=1,
                  short="DMARC is monitoring only (p=none)",
                  fix=enforce_fix({"p": "quarantine"}, "Move to p=quarantine, then p=reject, once every legitimate sender passes.", steps))
        elif pct != 100:
            C.add("dmarc-enforced", A, title, "warn", f"p={p}, but pct={pct}: the policy applies to only {pct}% of failing mail.", why,
                  priority=2, short=f"DMARC applies to only {pct}% of failing mail",
                  fix=enforce_fix({}, f"Apply p={p} to all failing mail (remove pct=).", [check_reports]))
        elif testing:
            C.add("dmarc-enforced", A, title, "warn", f"p={p}, but t=y (DMARCbis testing flag): receivers that support it apply one level lower.",
                  why, priority=2, short="DMARC is in testing mode (t=y)",
                  fix=enforce_fix({}, "Remove the t=y testing flag.", [check_reports]))
        else:
            C.add("dmarc-enforced", A, title, "pass", "p=reject: spoofed mail is refused." if p == "reject" else
                  "p=quarantine: spoofed mail goes to junk. p=reject is the end goal.", why, priority=1)

    # --- DMARC reports
    title = "DMARC aggregate reports (rua) are collected"
    why = "Aggregate reports show who sends as the domain, which is how you find legitimate senders before enforcing."
    mailto = [u[7:] for u in c.dmarc_rua if u.lower().startswith("mailto:")]
    if not c.sends:
        C.add("dmarc-rua", A, title, "na", "Optional for a domain that sends no mail.", why, priority=3)
    elif not c.dmarc_known or c.dmarc_failed:
        C.add("dmarc-rua", A, title, "unknown", "DMARC couldn't be read.", why, fix=unknown_dmarc)
    elif not c.dmarc_valid:
        C.add("dmarc-rua", A, title, "fail", "No valid DMARC record, so no reports.", why, priority=2, parent="dmarc-published",
              short="no DMARC reports", fix=_fix("Add rua= when you publish the DMARC record.", **dmarc_tool))
    elif not mailto:
        C.add("dmarc-rua", A, title, "fail", f"No rua= address: you can't see who sends as @{d}, or what would break when you enforce.", why,
              priority=2, short="no DMARC reports (rua)",
              fix=_fix("Add a rua= reporting address to the DMARC record.", **dmarc_tool, commands=check_dmarc_cmd,
                       steps=["Add rua=mailto:<a mailbox you monitor, or a DMARC reporting service's address> to the record.",
                              "Upload the reports you receive to the DMARC Report Analyzer to see every sender."]))
    elif c.dmarc_unauth:
        dests = ", ".join(c.dmarc_unauth)
        C.add("dmarc-rua", A, title, "warn", f"Reports go to {dests}, which hasn't published the authorisation record, so many receivers won't send them.",
              why, priority=2, short="DMARC reports aren't authorised",
              fix=_fix("Have the report destination authorise reports for this domain.", **dmarc_tool,
                       steps=[f"Ask the owner of {dests} to publish TXT {c.dmarc_source}._report._dmarc.<their domain> "
                              "\"v=DMARC1\" (DMARC services usually do this automatically), or send reports to an address in your own domain."]))
    else:
        C.add("dmarc-rua", A, title, "pass", "Reports go to " + ", ".join(_clip(m, 80) for m in mailto[:3]) + ".", why)

    # --- Subdomain policy
    title = "Subdomain policy (sp=) is not weaker than p="
    why = "Spoofers use made-up subdomains (like invoices.example) when the subdomain policy is weaker than the main one."
    sp = tags.get("sp", "").strip().lower()
    if not c.dmarc_known or c.dmarc_failed:
        C.add("dmarc-sp", A, title, "unknown", "DMARC couldn't be read.", why, priority=3, optional=True)
    elif not c.dmarc_valid:
        C.add("dmarc-sp", A, title, "na", "No valid DMARC record yet.", why, priority=3, optional=True)
    elif c.dmarc_inherited:
        C.add("dmarc-sp", A, title, "na", f"{d} inherits {c.dmarc_source}'s subdomain policy.", why, priority=3, optional=True)
    elif not sp:
        C.add("dmarc-sp", A, title, "pass", f"No sp= tag, so subdomains get p={p}.", why, priority=3, optional=True)
    elif sp not in _LEVEL or _LEVEL[sp] < _LEVEL.get(p, 0):
        found = (f"sp={sp} isn't a valid policy, so receivers ignore it." if sp not in _LEVEL else
                 f"sp={sp} is weaker than p={p}: made-up subdomains like invoices.{d} are easier to spoof.")
        new = _dmarc_with(c.dmarc_record, {"sp": p})
        C.add("dmarc-sp", A, title, "warn", found, why, priority=3, optional=True, short=f"sp={p} for subdomains",
              fix=_fix(f"Set sp={p} (or remove sp= so subdomains inherit p=).", **dmarc_tool,
                       records=[_rec("TXT", f"_dmarc.{d}", new)] if new else [], commands=check_dmarc_cmd,
                       steps=["Subdomains that send mail need to pass SPF/DKIM themselves (or get their own DMARC record) before you tighten sp=."]))
    else:
        C.add("dmarc-sp", A, title, "pass", f"sp={sp}.", why, priority=3, optional=True)


def _dkim(c: _Ctx, C: _Controls) -> None:
    d, A = c.domain, "email-auth"
    plat = c.platform if c.platform in ("Microsoft 365", "Google Workspace") else None
    title = {"Microsoft 365": "DKIM signing is on for Microsoft 365 (selector1/selector2)",
             "Google Workspace": "DKIM signing is on for Google Workspace (google selector)"}.get(plat, "DKIM signing is set up")
    why = "DKIM signs each message so DMARC can pass even when mail is forwarded; without it DMARC relies on SPF alone."
    recheck = {"tool": "domain", "params": {"d": d}, "label": "Re-check in Domain Health"}
    if not c.sends:
        C.add("dkim", A, title, "na", "Not needed: the domain sends no mail.", why)
        return
    if not c.dkim_known:
        C.add("dkim", A, title, "unknown", "DKIM data isn't available.", why, fix=_fix("Re-run the check.", **recheck))
        return
    keys = c.dkim_keys
    sels = ("selector1", "selector2") if plat == "Microsoft 365" else ("google",) if plat == "Google Workspace" else tuple(keys)
    mine = {s: keys[s] for s in sels if s in keys}
    others = sorted(s for s in keys if s not in mine)
    keys_txt = ", ".join(f"{s} ({b}-bit)" for s, b in sorted(mine.items()))
    get_cfg = f"Get-DkimSigningConfig -Identity {d} | Format-List Selector1CNAME,Selector2CNAME,Enabled"
    enable = f"Set-DkimSigningConfig -Identity {d} -Enabled $true"
    if mine:
        if max(mine.values()) >= 2048:
            C.add("dkim", A, title, "pass", f"Keys published: {keys_txt}.", why, priority=1)
            return
        if plat == "Microsoft 365":
            fix = _fix("Rotate to a 2048-bit key.", commands=[f"Get-DkimSigningConfig -Identity {d} | Format-List Selector1KeySize,Selector2KeySize,Enabled",
                                                              f"Rotate-DkimSigningConfig -Identity {d} -KeySize 2048"],
                       steps=[CONNECT_EXO, "Run the rotation: Microsoft publishes the new key on the other selector and switches signing to it "
                              "automatically (it can take a few days). Nothing changes in DNS."])
        elif plat == "Google Workspace":
            fix = _fix("Replace the key with a 2048-bit one.", steps=[
                "Google Admin console → Apps → Google Workspace → Gmail → Authenticate email.",
                f"Generate a new 2048-bit record for {d} (a new selector prefix avoids a gap while DNS updates).",
                "Publish the TXT record it shows, then click Start authentication."])
        else:
            fix = _fix("Generate a 2048-bit key in the sending platform and publish it.", **recheck)
        C.add("dkim", A, title, "warn", f"Signing key is only {max(mine.values())}-bit: {keys_txt}. 2048-bit is recommended.", why,
              priority=3, short="a 1024-bit DKIM key", fix=fix)
        return
    if plat == "Microsoft 365":
        cnames = [s for s in c.dkim_cname_only if s in ("selector1", "selector2")]
        if cnames:
            C.add("dkim", A, title, "fail", f"The {'/'.join(cnames)} CNAMEs are published, but there's no key behind them: "
                  "DKIM signing isn't turned on in Microsoft 365.", why, priority=1, short="Microsoft 365 DKIM signing is off",
                  fix=_fix("Turn on DKIM signing: the CNAMEs are already published.", commands=[get_cfg, enable],
                           steps=[CONNECT_EXO, "Check that Selector1CNAME and Selector2CNAME match the published records.",
                                  f"Turn signing on with the second command (or {DEFENDER_DKIM})."]))
            return
        fix = _fix("Publish the two DKIM CNAMEs from Microsoft 365, then turn signing on.",
                   commands=[get_cfg, enable, f"New-DkimSigningConfig -DomainName {d} -Enabled $true"],
                   steps=[CONNECT_EXO, "Run the first command to get the two CNAME values for this domain.",
                          f"Publish selector1._domainkey.{d} and selector2._domainkey.{d} as CNAMEs pointing to the Selector1CNAME "
                          "and Selector2CNAME values.",
                          f"Once both resolve, turn signing on with the second command (or {DEFENDER_DKIM}).",
                          "If the first command returns nothing, the domain has no DKIM config yet: create it with the third command, "
                          "then run the first command again for the CNAME values."])
        if c.gateways:
            # A filtering gateway often signs outbound mail with its own selector.
            C.add("dkim", A, title, "warn", "No Microsoft 365 keys at selector1/selector2" +
                  (f", but DKIM keys exist on {', '.join(others[:4])}" if others else "") +
                  f". Mail routed out through {', '.join(c.gateways)} may be signed there; mail sent straight from Microsoft 365 isn't.",
                  why, priority=2, short="no Microsoft 365 DKIM signing", fix=fix)
        else:
            C.add("dkim", A, title, "fail", "No DKIM keys at selector1/selector2: Microsoft 365 signs with the onmicrosoft.com domain instead, "
                  "which doesn't align with DMARC.", why, priority=1, short="no Microsoft 365 DKIM signing", fix=fix)
        return
    if plat == "Google Workspace":
        found = "No DKIM key at google._domainkey" + (f" (keys exist on {', '.join(others[:4])}; a custom Google selector prefix is possible)."
                                                       if others else ", Google Workspace's default selector. Unless a custom selector prefix is "
                                                       "in use, Gmail signs with a gappssmtp.com key that doesn't align with DMARC.")
        C.add("dkim", A, title, "warn" if others else "fail", found, why, priority=1, short="no Google Workspace DKIM key",
              fix=_fix("Generate a DKIM key in Google Workspace, publish it, then start authentication.", steps=[
                  "Google Admin console → Apps → Google Workspace → Gmail → Authenticate email.",
                  f"Select {d} and generate a new record with a 2048-bit key (selector prefix: google).",
                  f"Publish the TXT record it shows at google._domainkey.{d}.",
                  "Back in the Admin console, click Start authentication (DNS can take up to 48 hours to update)."]))
        return
    C.add("dkim", A, title, "warn", "No DKIM key found on the common selectors. A custom selector is possible: check the s= tag in a sent "
          "message's DKIM-Signature header.", why, priority=2, short="no DKIM key found",
          fix=_fix("Turn on DKIM signing in the mail platform and every sending service.", **recheck,
                   steps=[f"Turn on DKIM on {_mail_server(c)} and in each service that sends as {d}, and publish the key "
                          "each one gives you (2048-bit where offered).",
                          "If a key already exists on a custom selector, enter it in Domain Health to check it."]))


# ------------------------------------------------------------------ mail transport
def _transport(c: _Ctx, C: _Controls) -> None:
    d, A = c.domain, "mail-transport"
    sts_tool = {"tool": "mtasts", "params": {"d": d}, "label": "Set up MTA-STS"}

    if c.parked:
        title = "Null MX says the domain accepts no mail"
        why = "A null MX (0 .) tells other servers the domain accepts no mail, so they don't try to deliver or bounce to it."
        if c.null_mx:
            C.add("null-mx", A, title, "pass", "Null MX (0 .) is published.", why)
        else:
            C.add("null-mx", A, title, "fail", "No MX record: senders fall back to the domain's address record, or retry and bounce.", why,
                  priority=2, short="no null MX",
                  fix=_fix("Publish a null MX record.", tool="parked", params={"d": d}, label="Lock down a parked domain",
                           records=[_rec("MX", d, "0 .")], commands=[_resolve_cmd(d, "MX")],
                           steps=["Publish it as the only MX record (priority 0, target a single dot)."]))

    na = None if c.receives else ("The MX lookup failed, so this couldn't be checked." if c.mx_failed else
                                  "The domain receives no mail (no MX record)." if not c.null_mx else "The domain receives no mail (null MX).")
    na_status = "unknown" if c.mx_failed or not c.email_ok else "na"
    if not c.email_ok:
        na = "Mail DNS records couldn't be read."

    # --- MTA-STS
    title = "MTA-STS is in enforce mode"
    why = "MTA-STS makes sending servers insist on an encrypted, verified connection to your MX, which blocks downgrade attacks."
    sts_id = c.now.strftime("%Y%m%d%H%M%S")
    sts_txt = [_rec("TXT", f"_mta-sts.{d}", f"v=STSv1; id={sts_id}")]
    mx_hosts = [h for h in (cmdsafe.dns_name(str(m.get("host") or ""), "") for m in c.mx) if h]
    if na:
        C.add("mta-sts", A, title, na_status, na, why, priority=3, optional=True)
    elif c.mta_sts == "enforce":
        C.add("mta-sts", A, title, "pass", "Policy is in enforce mode.", why, priority=3, optional=True)
    elif c.mta_sts:
        C.add("mta-sts", A, title, "warn", "Policy mode is none: MTA-STS is switched off." if c.mta_sts == "none" else
              f"Policy is in {c.mta_sts} mode: senders report problems but still deliver over unverified connections.",
              why, priority=3, optional=True, short="MTA-STS in enforce mode",
              fix=_fix("Switch the policy to mode: enforce.", **sts_tool, records=sts_txt, commands=[_resolve_cmd(f"_mta-sts.{d}", "TXT")],
                       steps=[f"Check the TLS-RPT reports are clean, then change mode to enforce in https://mta-sts.{d}/.well-known/mta-sts.txt.",
                              "Publish the TXT record below with a new id so senders fetch the new policy."]))
    else:
        broken = bool(c.mta_sts_txt)
        steps = [f"Host the policy at https://mta-sts.{d}/.well-known/mta-sts.txt over HTTPS with a valid certificate for mta-sts.{d}.",
                 "List every MX host in it (" + ", ".join(f"mx: {h}" for h in mx_hosts[:6]) + "), with mode: testing and max_age: 86400 to start."
                 if mx_hosts else "List every MX host in it, with mode: testing and max_age: 86400 to start.",
                 "Publish the TXT record below; change its id whenever the policy changes.",
                 "Add TLS-RPT (next check), and switch to mode: enforce once the reports are clean."]
        if broken:
            steps = [f"Make https://mta-sts.{d}/.well-known/mta-sts.txt load over HTTPS with a valid certificate (no redirects), "
                     "or delete the _mta-sts TXT record."] + steps[1:]
        C.add("mta-sts", A, title, "warn" if broken else "fail",
              f"The _mta-sts TXT record is published, but the policy file at https://mta-sts.{d}/.well-known/mta-sts.txt couldn't be fetched "
              "or is invalid." if broken else "Not configured: senders deliver even if the connection to your MX can't be encrypted or verified.",
              why, priority=2 if broken else 3, optional=True, short="a working MTA-STS policy" if broken else "MTA-STS",
              fix=_fix("Fix the MTA-STS policy file." if broken else "Publish an MTA-STS policy (testing mode first).", **sts_tool,
                       records=sts_txt, commands=[_resolve_cmd(f"_mta-sts.{d}", "TXT")], steps=steps))

    # --- TLS-RPT
    title = "TLS-RPT reporting is published"
    why = "TLS-RPT sends you reports when other servers can't deliver to you securely."
    if na:
        C.add("tls-rpt", A, title, na_status, na, why, priority=3, optional=True)
    elif c.tls_rpt:
        C.add("tls-rpt", A, title, "pass", f"Published at _smtp._tls.{d}.", why, priority=3, optional=True)
    else:
        C.add("tls-rpt", A, title, "fail", f"No _smtp._tls.{d} record: you won't hear about failed secure deliveries.", why,
              priority=3, optional=True, short="TLS-RPT",
              fix=_fix("Publish a TLS-RPT record.", **sts_tool, commands=[_resolve_cmd(f"_smtp._tls.{d}", "TXT")],
                       steps=[f"Publish TXT _smtp._tls.{d} with \"v=TLSRPTv1; rua=mailto:<a mailbox you monitor, or your reporting service's address>\"."]))

    # --- Inbound filtering
    title = "Inbound mail passes through a known filtering service"
    why = "Unfiltered inbound mail means phishing and malware land straight in mailboxes."
    mailbox = next((str(m.get("provider")) for m in c.mx if m.get("provider_kind") == "mailbox" and m.get("provider")), None)
    if na:
        C.add("inbound-filtering", A, title, na_status, na, why)
    elif c.gateways:
        named = c.platform and not c.platform.startswith(("unknown", "Microsoft 365 or"))
        C.add("inbound-filtering", A, title, "pass", f"Filtered by {', '.join(c.gateways)}" + (f" before {c.platform}." if named else "."), why)
    elif c.platform == "Microsoft 365":
        C.add("inbound-filtering", A, title, "pass", "Microsoft 365 built-in filtering (Exchange Online Protection).", why)
    elif c.platform == "Google Workspace":
        C.add("inbound-filtering", A, title, "pass", "Google Workspace built-in filtering.", why)
    elif mailbox:
        C.add("inbound-filtering", A, title, "pass", f"{mailbox} built-in filtering.", why)
    else:
        server = _mail_server(c)
        C.add("inbound-filtering", A, title, "manual", f"No known filtering service found in front of {server}.", why,
              fix=_fix("Find out what filters spam, phishing and malware for this mail server.",
                       steps=[f"Ask what filters inbound mail for {server}: filtering on the server itself, or the hosting provider's?",
                              "A self-run server with no filtering service is a common phishing route: add a filtering gateway or move "
                              "mailboxes to a platform with built-in protection."]))


# ------------------------------------------------------------------ domain & registrar
def _caa_from_issuer(issuer: str) -> list[str]:
    low = issuer.lower()
    return list(dict.fromkeys(ca for rx, ca in CAA_IDS if re.search(rx, low)))[:2]


def _registrar(c: _Ctx) -> str:
    return str((c.reg or {}).get("registrar") or "the registrar").rstrip(".")


def _domain(c: _Ctx, C: _Controls) -> None:
    d, A = c.domain, "domain"
    whois = {"tool": "whois", "params": {"d": d}, "label": "Open Domain Registration"}
    reg, registrar = c.reg, _registrar(c)
    tld = registered_domain(d).rsplit(".", 1)[-1]
    no_rdap = reg is None or reg.get("rdap_available") is False
    unknown_reg = _fix("Check the registration at the registrar or the registry's WHOIS.", **whois)

    # --- Transfer lock
    title = "Registrar transfer lock is on"
    why = "A transfer lock stops the domain being moved to another registrar by a fraudulent or mistaken request."
    statuses = [str(s) for s in (reg or {}).get("statuses") or []]
    if tld in NO_CLIENT_LOCK_TLDS:
        C.add("transfer-lock", A, title, "na", f"The .{tld} registry doesn't use EPP transfer locks; transfers are authorised with an "
              "auth code or registrar tag instead.", why)
    elif no_rdap or not statuses:
        C.add("transfer-lock", A, title, "unknown", "Registration status isn't available (the registry doesn't publish RDAP, or the lookup failed).",
              why, fix=unknown_reg)
    elif any(s in ("clientTransferProhibited", "serverTransferProhibited") for s in statuses):
        C.add("transfer-lock", A, title, "pass", "Locked: " + ", ".join(s for s in statuses if s.endswith("TransferProhibited")) + ".", why)
    else:
        C.add("transfer-lock", A, title, "fail", "No clientTransferProhibited status: the domain can be moved to another registrar with just its auth code.",
              why, priority=2, short="no registrar transfer lock",
              fix=_fix("Turn on the registrar's transfer lock.", **whois,
                       steps=[f"Log in to {registrar} and turn on Domain lock / Transfer lock for {d}.",
                              "While you're there, make sure the account belongs to the company and has MFA."]))

    # --- Expiry
    title = "Registration is more than 60 days from expiry"
    why = "If the registration lapses, email and the website stop and the name can be lost."
    days = (reg or {}).get("days_left")
    expires = _g(reg, "events", "expires")
    when = f" ({expires})" if expires else ""
    renew = _fix(f"Renew {d} and turn on auto-renew.", **whois,
                 steps=[f"Log in to {registrar}, renew {d} and turn on auto-renew.", "Check the payment card on the account is valid.",
                        "Make sure the registrar account belongs to the company (not a former employee or provider) and has MFA."])
    if not isinstance(days, int):
        C.add("expiry", A, title, "unknown", "No expiry date available (the registry doesn't publish it, or the lookup failed).", why, fix=unknown_reg)
    elif days < 0:
        C.add("expiry", A, title, "fail", f"Expired {_plural(-days, 'day')} ago{when}.", why, priority=1, critical=True,
              short="the domain registration has expired", fix=renew)
    elif days < 30:
        C.add("expiry", A, title, "fail", f"Expires in {_plural(days, 'day')}{when}.", why, priority=1, critical=True,
              short=f"the domain expires in {_plural(days, 'day')}", fix=renew)
    elif days <= 60:
        C.add("expiry", A, title, "warn", f"Expires in {days} days{when}.", why, priority=2, short=f"the domain expires in {days} days", fix=renew)
    else:
        C.add("expiry", A, title, "pass", f"Expires in {days} days{when}.", why)

    # --- DNSSEC
    title = "DNSSEC is signed and validating"
    why = "DNSSEC signs DNS answers so resolvers can detect forged records."
    headline = str((reg or {}).get("headline") or "")
    dnssec_fix = _fix("Turn on DNSSEC signing at the DNS host, then publish the DS record at the registrar.", **whois,
                      commands=[_resolve_cmd(d, "DS")],
                      steps=[f"Turn on DNSSEC at the DNS host ({c.dns_host or 'whoever hosts the zone'}).",
                             f"Add the DS record it gives you at {registrar} (often automatic when the registrar also hosts DNS).",
                             "Before moving DNS hosting later, remove the DS first, or the domain stops resolving."])
    if reg is None:
        C.add("dnssec", A, title, "unknown", "DNSSEC status isn't available (the registration lookup failed).", why, priority=3,
              optional=True, fix=unknown_reg)
    elif reg.get("severity") == "critical" and "dnssec" in headline.lower():
        C.add("dnssec", A, title, "fail", headline, why, priority=1, short="broken DNSSEC",
              fix=_fix("Fix DNSSEC: remove the DS at the registrar, then re-sign and publish the new DS.", **whois,
                       commands=[_resolve_cmd(d, "DS"), _resolve_cmd(d, "DNSKEY")],
                       steps=[f"Fastest fix: remove the DS record at {registrar} (turns DNSSEC off) and wait for its TTL to expire.",
                              "Re-enable signing at the DNS host and publish the new DS record."]))
    elif reg.get("dnssec"):
        C.add("dnssec", A, title, "pass", "Signed, and validating resolvers accept it.", why, priority=3, optional=True)
    else:
        C.add("dnssec", A, title, "fail", "Not signed.", why, priority=3, optional=True, short="DNSSEC", fix=dnssec_fix)

    # --- CAA
    title = "CAA records restrict who can issue certificates"
    why = "CAA records limit which certificate authorities may issue certificates for the domain and its subdomains."
    if c.caa_raw is not None:
        issuers = [str(r.get("value") or "").split(";")[0].strip() for r in c.caa_raw if str(r.get("tag")).lower() in ("issue", "issuewild")]
        has = bool(issuers)
    elif c.caa_disc is not None:
        issuers, has = [str(i) for i in c.caa_disc], bool(c.caa_disc)
    else:
        issuers, has = [], None
    if has is None:
        C.add("caa", A, title, "unknown", "CAA records couldn't be read.", why, priority=3, optional=True)
    elif has:
        allowed = sorted({i for i in issuers if i})
        C.add("caa", A, title, "pass", ("Only these CAs may issue: " + ", ".join(allowed) + "." if allowed else
                                        "No CA may issue certificates (issue \";\")."), why, priority=3, optional=True)
    else:
        C.add("caa", A, title, "fail", "No CAA records: any public CA may issue a certificate for the domain.", why,
              priority=3, optional=True, short="CAA records", fix=_caa_fix(c))


def _caa_fix(c: _Ctx) -> dict:
    d = c.domain
    issuer = str(_g(c.web, "tls", "cert", "issuer") or "")
    cas = _caa_from_issuer(issuer) if issuer else []
    org = re.search(r"(?:^|,)O=((?:[^,\\]|\\.)+)", issuer)
    steps = []
    if cas:
        steps.append(f"Inferred from the website certificate ({_clip(org.group(1) if org else issuer, 60)}).")
    elif c.parked and not _g(c.web, "url"):
        cas = [";"]
        steps.append("No website answered, so this record forbids every CA from issuing. Replace it if the domain ever needs a certificate.")
    else:
        cas = ["letsencrypt.org", "digicert.com"]
        steps.append("Template: replace these with the CAs that actually issue your certificates.")
    if cas != [";"]:
        steps.append(f"Add an issue line for every CA that issues certificates for {d} or any subdomain (website, mail, VPN, remote "
                     "access, SaaS custom domains), or their renewals will fail.")
    cdn = [str(x) for x in _g(c.web, "cdn", default=[]) or []]
    if cdn:
        steps.append(f"The website is served through {', '.join(cdn)}, which may renew its certificates from other CAs: "
                     "check its CAA guidance before publishing.")
    return _fix("Publish CAA records for the CAs you use.", tool="dns", params={"n": d, "type": "CAA"}, label="Check CAA in DNS Lookup",
                records=[_rec("CAA", d, f'0 issue "{ca}"') for ca in cas], steps=steps)


# ------------------------------------------------------------------ DNS hygiene
def _host_cmds(c: _Ctx, hosts: list[dict], rtype: str) -> list[str]:
    """Resolve-DnsName checks for discovered host names (which are always <label>.<domain>)."""
    out = []
    for h in hosts[:6]:
        name = str(h.get("host") or "")
        if name.endswith("." + c.domain):
            cmd = _resolve_cmd(name, rtype)
            if cmd:
                out.append(cmd)
    return out


def _hygiene(c: _Ctx, C: _Controls) -> None:
    d, A = c.domain, "dns-hygiene"
    where = c.dns_host or "the DNS host"
    checked = f"the {c.checked} common host names checked" if c.checked else "the common host names checked"

    title = "No dangling CNAMEs (subdomain takeover)"
    why = "A CNAME pointing at a name nobody owns can be claimed by an attacker to serve content on your subdomain."
    if c.hosts is None:
        C.add("dangling-cname", A, title, "unknown", "Host names couldn't be checked.", why, priority=1)
    else:
        dang = [h for h in c.hosts if h.get("kind") == "dangling"]
        if dang:
            pairs = "; ".join(f"{h['host']} → {h.get('cname')}" for h in dang[:8])
            C.add("dangling-cname", A, title, "fail", f"{pairs} (target doesn't resolve).", why, priority=1, critical=True,
                  short=f"a dangling CNAME ({dang[0]['host']})" if len(dang) == 1 else f"{len(dang)} dangling CNAMEs",
                  fix=_fix("Delete the dangling records.", commands=_host_cmds(c, dang, "CNAME"),
                           steps=[f"Delete {'this CNAME' if len(dang) == 1 else 'these CNAMEs'} at {where}: " + pairs + ".",
                                  "If the service is still in use, recreate it at the provider first, then point the record at the new target."]))
        else:
            C.add("dangling-cname", A, title, "pass", f"None of {checked} point at a missing target.", why, priority=1)

    title = "No private (internal) IP addresses in public DNS"
    why = "Internal addresses in public DNS reveal the internal network layout and usually mean internal records leaked into the public zone."
    if c.hosts is None:
        C.add("private-ips", A, title, "unknown", "Host names couldn't be checked.", why)
    else:
        priv = [h for h in c.hosts if h.get("kind") == "private"]
        if priv:
            pairs = "; ".join(f"{h['host']} → {', '.join(str(i) for i in (h.get('ips') or [])[:2])}" for h in priv[:8])
            C.add("private-ips", A, title, "fail", pairs + ".", why, priority=2, critical=True,
                  short=f"internal IPs in public DNS ({priv[0]['host']})" if len(priv) == 1 else "internal IPs in public DNS",
                  fix=_fix("Remove internal addresses from the public zone.", commands=_host_cmds(c, priv, "A"),
                           steps=[f"Delete these records from the public zone at {where}; keep them in internal (split-brain) DNS only."]))
        else:
            C.add("private-ips", A, title, "pass", f"None of {checked} resolve to a private address.", why)

    title = "No legacy Skype for Business records"
    why = "Skype for Business Online was retired in July 2021; records still pointing at its hosts are dead clutter in the zone."
    if c.hosts is None:
        C.add("legacy-sfb", A, title, "unknown", "Host names couldn't be checked.", why, priority=3, optional=True)
    else:
        old = [h for h in c.hosts if h.get("label") in ("lyncdiscover", "sip")
               and re.search(r"(^|\.)(webdir|sipdir)\.online\.lync\.com$", str(h.get("cname") or ""))]
        if old:
            pairs = "; ".join(f"{h['host']} → {h.get('cname')}" for h in old)
            C.add("legacy-sfb", A, title, "manual", f"{pairs}: retired Skype for Business Online hosts.", why, priority=3, optional=True,
                  fix=_fix("Remove the lyncdiscover and sip records if the organisation is Teams-only.", commands=_host_cmds(c, old, "CNAME"),
                           steps=["Confirm nobody still uses Skype for Business (Online was retired; Teams doesn't need these records).",
                                  f"Delete the lyncdiscover and sip CNAMEs at {where}."]))
        else:
            C.add("legacy-sfb", A, title, "pass", "No lyncdiscover/sip records point at Skype for Business Online.", why, priority=3, optional=True)


# ------------------------------------------------------------------ website
def _web(c: _Ctx, C: _Controls) -> None:
    d, A, w = c.domain, "web", c.web
    full = str(_g(w, "url", default=""))
    try:
        parts = urlsplit(full)
        site = parts.hostname  # raises on a malformed host
    except ValueError:
        parts, site = None, None
    url = f"{parts.scheme}://{site}/" if parts and site else full  # the site, without long paths or queries
    no_site = f"No website answered at https://{d}, https://www.{d} or http://{d}."
    host = cmdsafe.dns_name(site or "", "")
    # Commands only name the client's own domain; -L follows redirects to wherever the site lives.
    own = host if host and (host == d or host.endswith("." + d)) else d
    curl = [f"curl.exe -sIL https://{own}/"]
    http_tool = {"tool": "http", "params": {"u": url or d}, "label": "Open HTTP Inspector"}

    title = "Website is served over HTTPS"
    why = "Without HTTPS, visitors' data travels unencrypted and browsers mark the site 'Not secure'."
    cert = _g(w, "tls", "cert", default={}) or {}
    days = cert.get("days_left") if isinstance(cert.get("days_left"), int) else None
    problem = None
    if w and w.get("severity") == "critical" and "certificate" in str(w.get("headline") or "").lower():
        problem = str(w.get("headline"))
    elif days is not None and days < 0:
        problem = f"The certificate on {url} has expired."
    elif cert.get("hostname_match") is False:
        problem = f"The certificate on {url} doesn't match the host name."
    if w is None:
        C.add("https", A, title, "unknown", "The website check didn't run.", why)
    elif not url:
        C.add("https", A, title, "na", no_site, why)
    elif not w.get("https"):
        C.add("https", A, title, "fail", f"{url} is served over plain HTTP.", why, priority=2, short="website not on HTTPS",
              fix=_fix("Install a certificate and redirect HTTP to HTTPS.", **http_tool,
                       steps=["Get a certificate (most hosts offer free Let's Encrypt certificates) and serve the site over HTTPS.",
                              "Redirect every http:// request to https://."]))
    elif problem:
        C.add("https", A, title, "fail", problem, why, priority=1, short="a website certificate error",
              fix=_fix("Replace the website certificate.", tool="tls", params={"h": host or d}, label="Open SSL/TLS Checker",
                       steps=["Renew or replace the certificate so it's valid, trusted and covers the host name; include the intermediate certificates."]))
    elif days is not None and days < 14:
        C.add("https", A, title, "warn", f"{url} works, but its certificate expires in {_plural(days, 'day')}.", why, priority=1,
              short=f"the website certificate expires in {_plural(days, 'day')}",
              fix=_fix("Renew the certificate (and check why automatic renewal hasn't happened).", tool="tls", params={"h": host or d},
                       label="Open SSL/TLS Checker"))
    else:
        C.add("https", A, title, "pass", f"{url} is served over HTTPS" + (f" (certificate valid for {days} more days)." if days is not None else "."), why)

    title = "HSTS (Strict-Transport-Security) is set"
    why = "HSTS tells browsers to always use HTTPS, so a network attacker can't downgrade visitors to plain HTTP."
    hsts_steps = ["Add the response header Strict-Transport-Security: max-age=31536000.",
                  "Start with a short max-age (e.g. 300) to test, and add includeSubDomains only once every subdomain serves HTTPS.",
                  "On a CDN it's a setting (Cloudflare: SSL/TLS → Edge Certificates → HSTS); on IIS, the site's HSTS settings or an HTTP response header."]
    if w is None:
        C.add("hsts", A, title, "unknown", "The website check didn't run.", why, priority=3)
    elif not url:
        C.add("hsts", A, title, "na", no_site, why, priority=3)
    elif not w.get("https"):
        C.add("hsts", A, title, "fail", "Needs HTTPS first.", why, priority=3, parent="https", short="no HSTS",
              fix=_fix("Serve the site over HTTPS, then add HSTS.", **http_tool, steps=hsts_steps))
    elif w.get("hsts"):
        C.add("hsts", A, title, "pass", f"{url} sends a Strict-Transport-Security header.", why, priority=3)
    else:
        C.add("hsts", A, title, "fail", f"{url} doesn't send a Strict-Transport-Security header.", why, priority=3, short="no HSTS on the website",
              fix=_fix("Send the Strict-Transport-Security header.", **http_tool, commands=curl, steps=hsts_steps))

    title = "security.txt is published (RFC 9116)"
    why = "security.txt tells researchers where to report a vulnerability instead of posting it publicly."
    expires = (c.now + timedelta(days=364)).strftime("%Y-%m-%dT00:00:00Z")  # RFC 9116: less than a year ahead
    contact = f"Contact: mailto:security@{d}"
    if w is None:
        C.add("security-txt", A, title, "unknown", "The website check didn't run.", why, priority=3, optional=True)
    elif w.get("security_txt"):
        C.add("security-txt", A, title, "pass", f"https://{d}/.well-known/security.txt has a Contact field.", why, priority=3, optional=True)
    elif not url:
        C.add("security-txt", A, title, "na", no_site, why, priority=3, optional=True)
    else:
        C.add("security-txt", A, title, "fail", f"No security.txt with a Contact field at https://{d}/.well-known/security.txt.", why,
              priority=3, optional=True,
              short="security.txt",
              fix=_fix("Publish a security.txt file.",
                       commands=[f"@('{contact}', 'Expires: {expires}') | Set-Content -Path .\\security.txt -Encoding ascii"],
                       steps=[f"Create a plain-text file called security.txt with two lines, \"{contact}\" and \"Expires: {expires}\" "
                              "(the command writes it for you).",
                              f"Upload it so it's served at https://{d}/.well-known/security.txt.",
                              "Use a mailbox someone monitors, and renew Expires before it passes (RFC 9116)."]))


# ------------------------------------------------------------------ internet exposure
def _where(h: dict) -> str:
    ip = next((str(i) for i in h.get("ips") or [] if ":" not in str(i)), None)
    owner = h.get("owner") or h.get("service")
    return f"{h['host']}" + (f" → {ip}" if ip else "") + (f" ({owner})" if owner else "")


def _exposure(c: _Ctx, C: _Controls) -> None:
    A = "exposure"
    if c.hosts is None:
        for cid, title in (("remote-access", "No Remote Desktop / RD Gateway host names on an office connection"),
                           ("vpn", "VPN and firewall portals have MFA and current firmware"),
                           ("selfhosted-mail", "No self-hosted mail or Outlook on the web on an office connection")):
            C.add(cid, A, title, "unknown", "Host names couldn't be checked.", "Internet-facing servers are the most common way in.")
        return
    checked = f"{c.checked} common host names checked" if c.checked else "common host names checked"

    title = "No Remote Desktop / RD Gateway host names on an office connection"
    why = "Remote Desktop and RD Gateway exposed to the internet are a top ransomware entry point."
    remote = [h for h in c.hosts if h.get("area") == "remote" and h.get("kind") not in ("dangling", "private")]
    office = [h for h in remote if h.get("kind") == "onprem"]
    selfrun = [h for h in remote if h.get("kind") in ("own", "unknown", "cloud")
               or (h.get("kind") == "saas" and h.get("service") in _COMPUTE_SERVICES)]
    ip_tool = {}
    first = next((h for h in office + selfrun if any(":" not in str(i) for i in h.get("ips") or [])), None)
    if first:
        ip = cmdsafe.ip(next(str(i) for i in first["ips"] if ":" not in str(i)))
        if ip:
            ip_tool = {"tool": "ip", "params": {"t": ip}, "label": "Look up the IP's owner"}
    steps = ["Ask what each name is: RD Web Access, RD Gateway, or a firewall port-forward to Remote Desktop (TCP 3389)?",
             "Don't publish Remote Desktop directly: put it behind a VPN or zero-trust access with MFA, or move to Azure Virtual Desktop / Windows 365.",
             "If an RD Gateway must stay, enforce MFA on it and keep the server patched."]
    if office:
        C.add("remote-access", A, title, "fail", "; ".join(_where(h) for h in office[:6]) + ": remote-access names on an office internet connection.",
              why, priority=1, critical=True,
              short=f"remote access on the office connection ({office[0]['host']})" if len(office) == 1 else
              f"{len(office)} remote-access names on the office connection",
              fix=_fix("Take Remote Desktop off the internet, or put it behind MFA.", **ip_tool, steps=steps))
    elif selfrun:
        C.add("remote-access", A, title, "manual", "; ".join(_where(h) for h in selfrun[:6]) + ": remote-access names on servers they "
              "run themselves (not a vendor's service). Confirm what they are and that MFA protects them.", why, priority=2,
              fix=_fix("Confirm what these remote-access names are and that MFA protects them.", **ip_tool, steps=steps))
    else:
        C.add("remote-access", A, title, "pass", f"No remote-access names point at an office connection ({checked}).", why, priority=1)

    title = "VPN and firewall portals have MFA and current firmware"
    why = "VPN and firewall portals are heavily targeted; MFA and current firmware are what keep them safe."
    vpn = [h for h in c.hosts if h.get("area") == "vpn" and h.get("kind") in ("onprem", "own", "unknown", "cloud") and not h.get("service")]
    if vpn:
        C.add("vpn", A, title, "manual", "; ".join(f"{_where(h)}: {h.get('purpose')}" for h in vpn[:6]) + ".", why,
              fix=_fix("Check MFA and firmware on each VPN / firewall portal.",
                       steps=["Confirm the VPN portal requires MFA for every user.",
                              "Check the appliance firmware against the vendor's security advisories (VPN appliances are a favourite target).",
                              "Make sure the firewall's management interface isn't reachable from the internet."]))
    else:
        C.add("vpn", A, title, "na", f"No VPN or firewall host names found ({checked}).", why)

    title = "No self-hosted mail or Outlook on the web (OWA) on an office connection"
    why = "On-premises Exchange and webmail on the internet have had several critical, mass-exploited vulnerabilities."
    mail = [h for h in c.hosts if (h.get("area") == "mail" or h.get("label") == "autodiscover") and h.get("kind") not in ("dangling", "private")]
    office = [h for h in mail if h.get("kind") == "onprem"]
    mx_office = c.mail_host.startswith("self-hosted on-premises")
    # Only the Exchange-specific names: webmail.* on an unclassified network is usually shared-hosting webmail.
    maybe = [h for h in mail if h.get("label") in ("owa", "exchange") and h.get("kind") in ("own", "unknown")]
    steps = ["Find out what runs there (Exchange Server? which version and update?).",
             "If mailboxes are already in the cloud, take the on-premises server off the internet or decommission it.",
             "If it must stay: install the latest Cumulative Update and Security Update, and publish it only through a reverse proxy or WAF."]
    if office or mx_office:
        items = [_where(h) for h in office[:6]]
        mx0 = str(c.mx[0].get("host") or "") if c.mx else ""
        if mx_office and not any(h["host"] == mx0 for h in office):
            items.append(f"MX {mx0 or 'host'} ({c.mail_host.split('(', 1)[-1].rstrip(')')})")
        C.add("selfhosted-mail", A, title, "fail", "; ".join(items) + ": mail server names on an office internet connection.", why,
              priority=1, short=f"self-hosted mail on the office connection ({office[0]['host']})" if office else "self-hosted mail on the office connection",
              fix=_fix("Retire or lock down the internet-facing mail server.", steps=steps))
    elif maybe:
        C.add("selfhosted-mail", A, title, "manual", "; ".join(_where(h) for h in maybe[:6]) + ": possibly on-premises Exchange / webmail.", why,
              fix=_fix("Confirm whether on-premises Exchange / webmail is still running.", steps=steps))
    else:
        C.add("selfhosted-mail", A, title, "pass", f"No mail server names point at an office connection ({checked}).", why, priority=1)


# ------------------------------------------------------------------ Microsoft 365 (manual)
def _m365(c: _Ctx, C: _Controls) -> None:
    if not c.m365:
        return
    A, d = "m365", c.domain
    found = "Tenant setting: not visible from outside. Run the read-only check."
    exo_note = "" if c.platform == "Microsoft 365" else f" Mail for {d} isn't hosted in Exchange Online, so this matters for the tenant's other domains."
    exo_pri = 2 if c.platform == "Microsoft 365" else 3
    checks = [
        ("m365-mfa", "MFA is enforced (security defaults or Conditional Access)", 2,
         "Most Microsoft 365 account takeovers start with a stolen or sprayed password that MFA would have stopped.",
         ["Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Format-List IsEnabled",
          "Get-MgIdentityConditionalAccessPolicy | Format-List DisplayName,State"],
         ["Connect first: Connect-MgGraph -Scopes Policy.Read.All (Microsoft Graph PowerShell).",
          "IsEnabled True means security defaults are on (MFA for everyone).",
          "If it's False, a Conditional Access policy with State 'enabled' must require MFA for all users; report-only policies don't enforce anything."],
         "Confirm MFA is enforced for every user."),
        ("m365-smtp-auth", "SMTP AUTH is disabled org-wide", exo_pri,
         "SMTP AUTH accepts a plain password and can't do MFA, so it's a favourite for password spraying.",
         ["Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled"],
         [CONNECT_EXO, "Expected: SmtpClientAuthenticationDisabled : True.",
          "If it's False, move scanners and apps that sign in to smtp.office365.com to a connector or OAuth, then run "
          "Set-TransportConfig -SmtpClientAuthenticationDisabled $true.",
          "A mailbox that still needs it can be excepted with Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false."],
         "Turn off SMTP AUTH for the organisation." + exo_note),
        ("m365-auto-forward", "Automatic forwarding to external addresses is blocked", exo_pri,
         "Attackers who take over a mailbox set up silent forwarding to an outside address to keep reading mail.",
         ["Get-HostedOutboundSpamFilterPolicy | Format-List Name,AutoForwardingMode"],
         [CONNECT_EXO, "Expected: AutoForwardingMode Off (Automatic means Microsoft's default, which also blocks it) on every policy.",
          "To block it: Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off. Give users who really need "
          "forwarding a separate policy scoped to them."],
         "Block automatic external forwarding." + exo_note),
        ("m365-audit-log", "Unified audit log is on", 2,
         "Without the unified audit log you can't investigate a compromised account.",
         ["Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled"],
         [CONNECT_EXO + " (In Security & Compliance PowerShell this value always shows False.)", "Expected: True.",
          "To turn it on: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true."],
         "Confirm the unified audit log is recording."),
        ("m365-preset-policies", "Preset security policies (Standard or Strict) are applied", exo_pri,
         "Microsoft's Standard and Strict presets apply its recommended anti-phishing, anti-spam and anti-malware settings and keep them current.",
         ["Get-EOPProtectionPolicyRule | Format-List Name,State", "Get-ATPProtectionPolicyRule | Format-List Name,State"],
         [CONNECT_EXO, "Expected: Standard Preset Security Policy (or Strict) with State Enabled in both lists.",
          "The second list only exists with Defender for Office 365 (Business Premium, E5 or the add-on).",
          "To apply: Defender portal → Email & collaboration → Policies & rules → Threat policies → Preset security policies."],
         "Apply the Standard or Strict preset security policy." + exo_note),
    ]
    if c.gateways and c.platform == "Microsoft 365":
        gw = ", ".join(c.gateways)
        checks.append(("m365-gateway", f"Mail can't bypass {gw} (connector restriction and Enhanced Filtering)", 2,
                       "If the tenant accepts mail from anywhere, attackers can skip the gateway's filtering by sending straight to Microsoft 365.",
                       ["Get-InboundConnector | Format-List Name,Enabled,SenderIPAddresses,RestrictDomainsToIPAddresses,EFSkipLastIP,EFSkipIPs"],
                       [CONNECT_EXO,
                        f"Expected: an inbound connector for {gw} with RestrictDomainsToIPAddresses True (or a certificate restriction, or a mail "
                        "flow rule rejecting mail that didn't come from the gateway), so mail that skips the gateway is refused.",
                        "Enhanced Filtering for Connectors: EFSkipLastIP True or EFSkipIPs listing the gateway's IPs, so Microsoft judges "
                        "SPF and DMARC on the real sender rather than on the gateway."],
                       f"Make sure mail can only reach the tenant through {gw}."))
    checks.append(("m365-external-tag", "External sender tagging is on in Outlook", 3,
                   "An 'External' tag in Outlook helps users spot impersonation from outside the organisation.",
                   ["Get-ExternalInOutlook"],
                   [CONNECT_EXO, "Expected: Enabled : True.", "To turn it on: Set-ExternalInOutlook -Enabled $true (it can take a day or two to show in Outlook)."],
                   "Turn on external sender tagging." + exo_note))
    for cid, title, pri, why, commands, steps, summary in checks:
        C.add(cid, A, title, "manual", found, why, priority=pri, fix=_fix(summary, commands=commands, steps=steps))


# ------------------------------------------------------------------ plan
def _issue_key(x: dict) -> tuple:
    imp = _IMPORTANCE.index(x["id"]) if x["id"] in _IMPORTANCE else len(_IMPORTANCE)
    return _RANK[x["severity"]], x["priority"], 0 if x["status"] == "fail" else 1, imp


def plan_from(disc: dict, extra: dict | None = None, now: datetime | None = None) -> dict:
    """Build the hardening plan from a discover() result plus optional extra lookups
    (keys: spf, dmarc, dkim, caa, mx_status, mta_sts_txt). Pure: no network."""
    now = now or datetime.now(timezone.utc)
    c = _context(disc if isinstance(disc, dict) else {}, extra if isinstance(extra, dict) else {}, now)
    C = _Controls()
    for section in (_email_auth, _transport, _domain, _hygiene, _web, _exposure, _m365):
        section(c, C)
    for x in C:
        if "fix" in x:
            x["fix"]["commands"] = [cmd for cmd in x["fix"]["commands"] if cmd]

    counts = {s: sum(1 for x in C if x["status"] == s) for s in _STATUSES}
    total = counts["pass"] + counts["fail"] + counts["warn"]
    req = [x for x in C if not x["optional"]]
    rp, rf, rw = (sum(1 for x in req if x["status"] == s) for s in ("pass", "fail", "warn"))
    score = int(100 * (rp + 0.5 * rw) / (rp + rf + rw) + 0.5) if rp + rf + rw else None
    # Overall = worst evaluated, non-optional control. Manual, unknown and n/a checks are always
    # "info" and would otherwise hide a fully passing domain.
    evaluated = [x["severity"] for x in req if x["status"] in ("pass", "fail", "warn")]
    severity = min(evaluated, key=_RANK.get) if evaluated else "info"

    failing = {x["id"] for x in C if x["status"] in ("fail", "warn")}
    issues = sorted((x for x in req if x["status"] in ("fail", "warn") and x["_parent"] not in failing), key=_issue_key)
    optional = sorted((x for x in C if x["optional"] and x["status"] in ("fail", "warn")), key=_issue_key)
    d = c.domain
    lead = f"{d} is a parked domain and passes" if c.parked else f"{d} passes"
    if not total:
        headline = f"Couldn't evaluate the hardening checks for {d}."
    elif issues:
        headline = f"{lead} {counts['pass']} of {_plural(total, 'hardening check')}. Fix first: {', '.join(x['_short'] for x in issues[:2])}."
    elif optional:
        headline = (f"{lead} {counts['pass']} of {_plural(total, 'hardening check')}, including every required one. "
                    f"Optional next: {', '.join(x['_short'] for x in optional[:2])}.")
    else:
        headline = f"{lead} all {_plural(total, 'hardening check')}."
    sub = ["Public DNS, registry and website data only."]
    if c.m365:
        sub.append("Tenant settings are listed as manual checks.")
    if c.parked:
        sub.append("Checked as a parked domain: it neither sends nor receives mail.")
    elif not c.sends:
        sub.append("The domain declares it sends no mail (v=spf1 -all).")
    elif c.email_ok and not c.receives and not c.mx_failed:
        sub.append("The domain has no MX record, so it receives no mail.")
    if counts["unknown"]:
        sub.append(f"{_plural(counts['unknown'], 'check')} couldn't be completed.")

    controls = [{k: v for k, v in x.items() if not k.startswith("_")} for x in C]
    used = {x["area"] for x in controls}
    return {"domain": d, "generated": now.isoformat(timespec="seconds"), "severity": severity, "headline": headline,
            "subline": " ".join(sub), "summary": {**counts, "total": total, "score": score},
            "sends_mail": bool(c.sends), "receives_mail": bool(c.receives), "mail_platform": c.platform,
            "areas": [dict(a) for a in AREAS if a["id"] in used], "controls": controls}


# ------------------------------------------------------------------ extra lookups (DNS only)
def _platform_dkim(res, domain: str) -> dict:
    """The fixed selectors of the big mail platforms, including CNAMEs that have no key behind them."""
    return {s: _check_selector(res, domain, s) for s in ("selector1", "selector2", "google")}


def _caa(res, domain: str) -> list[dict] | None:
    rd, meta = resolve(res, domain, "CAA")
    if meta["status"] in ("timeout", "servfail", "error"):
        return None
    dec = lambda v: v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)  # noqa: E731
    return [{"flags": r.flags, "tag": dec(r.tag).lower(), "value": dec(r.value)} for r in rd]


def _mx_status(res, domain: str) -> str:
    return resolve(res, domain, "MX")[1]["status"]


def _mta_sts_txt(res, domain: str) -> dict | None:
    recs, meta = txt(res, f"_mta-sts.{domain}")
    if meta["status"] in ("timeout", "servfail", "error"):
        return None
    return {"record": next((r for r in recs if r.lower().replace(" ", "").startswith("v=stsv1")), None)}


def build_plan(domain: str) -> dict:
    domain = normalize_domain(domain)
    if domain.startswith("www.") and domain.count(".") >= 2:
        domain = domain[4:]  # people paste the website address
    started = time.monotonic()
    res = make_resolver()
    pool = ThreadPoolExecutor(max_workers=6)
    try:
        jobs = {"spf": pool.submit(analyze_spf, domain), "dmarc": pool.submit(check_dmarc, res, domain),
                "dkim": pool.submit(_platform_dkim, res, domain), "caa": pool.submit(_caa, res, domain),
                "mx_status": pool.submit(_mx_status, res, domain), "mta_sts_txt": pool.submit(_mta_sts_txt, res, domain)}
        disc = discover(domain, ct=False)  # ValueError (e.g. NXDOMAIN) -> 400
        extra = {}
        for key, fut in jobs.items():
            try:
                extra[key] = fut.result(timeout=max(0.1, started + EXTRA_BUDGET - time.monotonic()))
            except Exception:  # noqa: BLE001 - a missing source becomes "unknown", never a 500
                extra[key] = None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return plan_from(disc, extra)


@router.get("/api/harden/{domain:path}")
def harden_route(domain: str):
    result = run(build_plan, domain)
    try:  # lets the page save the plan, like Domain Discovery; the plan never depends on it
        from ..core import workspace
        result["result_id"] = workspace.remember("hardening", result["domain"], result)
    except Exception:  # noqa: BLE001 - saving is optional
        pass
    return result
