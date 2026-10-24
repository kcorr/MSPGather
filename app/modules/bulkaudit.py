"""Bulk Domain Audit: the email-security basics for a list of client domains in
one table (mail platform, SPF, DMARC, DKIM, MTA-STS, DNSSEC, expiry, sign-in,
grade). The browser sends small batches so each request stays well under the
proxy / worker time limits and rows appear as they finish."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..core.dns_utils import make_resolver, normalize_domain, registered_domain
from ..core.http import run
from .discovery import _posture
from .domain import check_dkim, check_dmarc, check_m365_tenant, check_mta_sts, check_mx, check_tlsrpt
from .netdiag import domain_registration
from .spf import analyze_spf

router = APIRouter()

MAX_DOMAINS = 50          # per audit (the browser splits these into batches)
MAX_BATCH = 8             # per request
DOMAIN_BUDGET = 18.0      # seconds per domain; all domains in a batch run in parallel
WORKERS = 48

# _posture() items that need the website / infrastructure scan from Domain
# Discovery. The bulk audit skips those scans and scores email security only.
_NON_EMAIL_ITEMS = {"Website HTTPS", "Exposed remote access"}


class NormalizeRequest(BaseModel):
    text: str = Field(..., max_length=20_000)


class AuditRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=MAX_BATCH)


def _split(text: str) -> list[str]:
    return [t for t in re.split(r"[\s,;]+", text or "") if t.strip()]


def _clean(value: str) -> str:
    d = normalize_domain(value)
    if d.startswith("www.") and d.count(".") >= 2:
        d = d[4:]  # people paste the website address
    return d


def normalize_list(text: str) -> dict:
    tokens = _split(text)
    if not tokens:
        raise ValueError("Enter at least one domain (one per line, or comma separated).")
    domains: list[dict] = []
    invalid: list[dict] = []
    seen: set[str] = set()
    dupes = 0
    for t in tokens:
        try:
            d = _clean(t)
        except ValueError as exc:
            invalid.append({"input": t[:100], "error": str(exc)})
            continue
        if d in seen:
            dupes += 1
            continue
        seen.add(d)
        domains.append({"input": t[:200], "domain": d})
    truncated = max(0, len(domains) - MAX_DOMAINS)
    return {"domains": domains[:MAX_DOMAINS], "invalid": invalid, "duplicates": dupes, "truncated": truncated,
            "max": MAX_DOMAINS, "batch_size": 6}


# ----------------------------------------------------------------- per domain
def _mail_platform(domain: str, mx: dict, tenant: dict | None, spf: dict | None, dkim: dict | None) -> dict:
    """Simplified version of Domain Discovery's mail host logic (MX first,
    then tenant / SPF / DKIM evidence when a gateway hides the mailbox)."""
    records = mx.get("records") or []
    gateways = sorted({e["provider"] for e in records if e.get("provider_kind") == "gateway"})
    mailbox = [e["provider"] for e in records if e.get("provider") and e.get("provider_kind") != "gateway"]
    in_m365 = bool((tenant or {}).get("tenant_id")) or "Microsoft 365" in mailbox
    includes = (spf or {}).get("includes") or []
    sels = {k["selector"] for k in (dkim or {}).get("found", []) if k.get("bits")}
    if mx.get("null_mx"):
        host = "None (null MX)"
    elif not records:
        host = "None (no MX)"
    elif "Microsoft 365" in mailbox:
        host = "Microsoft 365"
    elif "Google" in mailbox:
        host = "Google Workspace"
    elif mailbox:
        host = mailbox[0]
    elif gateways:
        ms = 2 * ("spf.protection.outlook.com" in includes) + 2 * bool(sels & {"selector1", "selector2"}) + bool((tenant or {}).get("tenant_id"))
        gg = 2 * ("_spf.google.com" in includes) + 2 * ("google" in sels)
        host = "Microsoft 365" if ms > gg else "Google Workspace" if gg > ms else "Unknown mailbox"
    else:
        first = records[0]["host"]
        host = "Self-hosted" if registered_domain(first) == registered_domain(domain) else f"Other ({registered_domain(first)})"
    return {"host": host, "gateways": gateways, "in_m365": in_m365, "mx": [e["host"] for e in records[:4]]}


def _grade(spf, dmarc, dkim, mta_sts, tls_rpt, reg, mx, gateways, in_m365) -> dict:
    """Domain Discovery's _posture() weights, email items only: website and
    exposed-remote-access items are dropped and the percentage recomputed."""
    full = _posture(spf or {}, dmarc or {}, dkim or {}, mta_sts or {}, tls_rpt or {}, reg, None, mx or {}, gateways, in_m365,
                    {"hosts": []})
    items = [i for i in full["items"] if i["label"] not in _NON_EMAIL_ITEMS]
    score = sum(i["points"] for i in items)
    total = sum(i["max"] for i in items) or 1
    pct = round(100 * score / total)
    grade = "A" if pct >= 90 else "B" if pct >= 80 else "C" if pct >= 65 else "D" if pct >= 50 else "F"
    return {"grade": grade, "score": pct, "items": items}


def audit_domain(pool: ThreadPoolExecutor, domain: str, deadline: float) -> dict:
    res = make_resolver()
    t0 = time.monotonic()
    jobs = {
        "mx": pool.submit(check_mx, res, domain),
        "spf": pool.submit(analyze_spf, domain),
        "dmarc": pool.submit(check_dmarc, res, domain),
        "dkim": pool.submit(check_dkim, res, domain, []),
        "mta_sts": pool.submit(check_mta_sts, res, domain),
        "tls_rpt": pool.submit(check_tlsrpt, res, domain),
        "tenant": pool.submit(check_m365_tenant, domain),
        "reg": pool.submit(domain_registration, domain),
    }
    r: dict = {}
    errors: dict[str, str] = {}
    timed_out: list[str] = []
    for k, fut in jobs.items():
        try:
            r[k] = fut.result(timeout=max(0.05, deadline - time.monotonic()))
        except FutureTimeout:
            fut.cancel()
            r[k] = None
            timed_out.append(k)
        except Exception as exc:  # noqa: BLE001 - one failing check must not sink the row
            r[k] = None
            errors[k] = str(exc)[:200] or exc.__class__.__name__
    return _row(domain, r, errors, timed_out, round((time.monotonic() - t0) * 1000))


def _row(domain: str, r: dict, errors: dict, timed_out: list[str], ms: int) -> dict:
    mx, spf, dmarc, dkim, sts, tls_rpt, tenant, reg = (r.get(k) for k in ("mx", "spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "tenant", "reg"))
    row: dict = {"domain": domain, "elapsed_ms": ms, "errors": errors, "timed_out": timed_out, "exists": True}
    problems: list[dict] = []

    def prob(col, sev, text):
        problems.append({"col": col, "severity": sev, "text": text})

    if mx and mx.get("status") == "nxdomain":
        row["exists"] = False
        prob("domain", "critical", f"{domain} does not exist in DNS")

    # Mail platform
    if mx:
        mp = _mail_platform(domain, mx, tenant, spf, dkim)
        row["mail"] = mp
        if mx.get("status") in ("timeout", "servfail", "error"):
            prob("mail", "warning", "MX lookup failed")
        elif not mx.get("records") and not mx.get("null_mx") and row["exists"]:
            prob("mail", "warning", "No MX records")
    else:
        mp = {"host": None, "gateways": [], "in_m365": bool((tenant or {}).get("tenant_id")), "mx": []}
        row["mail"] = mp

    # Parked: deliberately neither receives (null MX) nor sends (v=spf1 -all) mail.
    no_mx = bool(mx) and (mx.get("null_mx") or (not mx.get("records") and mx.get("status") in ("ok", "noanswer")))
    parked = no_mx and ((spf or {}).get("record") or "").lower().split() == ["v=spf1", "-all"]
    row["parked"] = parked
    if parked:
        mp["host"] = "None (parked domain)"
        problems[:] = [p for p in problems if p["col"] != "mail"]

    # SPF
    if spf:
        crit = [f["title"] for f in spf.get("findings", []) if f["severity"] == "critical"]
        all_t = next((t["raw"] for t in (spf.get("tree") or {}).get("terms", []) if t.get("mechanism") == "all"), None)
        row["spf"] = {"record": spf.get("record"), "lookups": spf.get("lookup_count"), "valid": bool(spf.get("record")) and not crit,
                      "broken": crit[0] if crit and spf.get("record") else None, "all": all_t}
        if not spf.get("record"):
            if row["exists"]:
                prob("spf", "critical", "No SPF record")
        elif crit:
            prob("spf", "critical", f"Broken SPF: {crit[0]}")
        elif (spf.get("lookup_count") or 0) >= 9:
            prob("spf", "warning", f"{spf.get('lookup_count')}/10 DNS lookups: close to the limit")
        elif all_t in (None, "+all", "?all") and not (spf.get("tree") or {}).get("redirect"):
            prob("spf", "warning", f"SPF ends {all_t or 'without an all mechanism'}: doesn't block other senders")
    else:
        row["spf"] = None

    # DMARC
    if dmarc:
        tags = dmarc.get("tags") or {}
        policy_key = "sp" if dmarc.get("inherited") and "sp" in tags else "p"
        p = (tags.get(policy_key) or "").lower() or None
        row["dmarc"] = {"record": bool(dmarc.get("record")), "policy": p, "pct": tags.get("pct"), "t": (tags.get("t") or "").lower() or None,
                        "np": tags.get("np"), "inherited": dmarc.get("inherited"), "rua": bool(tags.get("rua"))}
        if row["exists"]:
            if not dmarc.get("record"):
                prob("dmarc", "critical", "No DMARC record: the domain can be spoofed")
            elif p not in ("quarantine", "reject"):
                prob("dmarc", "critical" if p != "none" else "warning",
                     "p=none: monitoring only, spoofed mail is delivered" if p == "none" else "Invalid DMARC policy")
            elif tags.get("pct") not in (None, "100") or row["dmarc"]["t"] == "y":
                prob("dmarc", "warning", "Policy only partly applied (pct below 100 or t=y testing)")
    else:
        row["dmarc"] = None

    # DKIM
    if dkim:
        keys = [k for k in dkim.get("found", []) if k.get("bits")]
        row["dkim"] = {"selectors": [k["selector"] for k in keys], "weak": [k["selector"] for k in keys if k["bits"] < 1024]}
        if row["exists"] and not (mx or {}).get("null_mx") and not parked:
            if not keys:
                prob("dkim", "warning", "No DKIM key on common selectors")
            elif row["dkim"]["weak"]:
                prob("dkim", "critical", "DKIM key under 1024 bits")
    else:
        row["dkim"] = None

    # MTA-STS
    if sts:
        crit = [f["title"] for f in sts.get("findings", []) if f["severity"] == "critical"]
        row["mta_sts"] = {"mode": (sts.get("policy") or {}).get("mode"), "record": bool(sts.get("record")), "broken": crit[0] if crit else None}
        if crit:
            prob("mta_sts", "critical", crit[0])
    else:
        row["mta_sts"] = None

    # Registration / DNSSEC
    if reg:
        live = ((reg.get("dnssec") or {}).get("live") or {})
        dnssec = "signed" if live.get("validated") else "broken" if live.get("ds") else "unsigned"
        row["dnssec"] = dnssec
        if dnssec == "broken":
            prob("dnssec", "critical", "DS record published but the zone doesn't validate: validating resolvers fail to resolve it")
        row["registration"] = {"days_left": reg.get("days_left"), "expires": (reg.get("events") or {}).get("expires"),
                               "registrar": (reg.get("registrar") or {}).get("name"), "registered": reg.get("registered"),
                               "rdap_available": reg.get("rdap_available")}
        days = reg.get("days_left")
        if days is not None:
            if days < 7:
                prob("expiry", "critical", f"Registration {'expired' if days < 0 else 'expires'} in {days} days")
            elif days < 30:
                prob("expiry", "warning", f"Registration expires in {days} days")
        if reg.get("registered") is False and row["exists"]:
            prob("expiry", "warning", "Registry has no RDAP record")
    else:
        row["dnssec"] = None
        row["registration"] = None

    # Sign-in
    if tenant:
        ns = tenant.get("namespace_type")
        row["signin"] = {"namespace": ns, "tenant_id": tenant.get("tenant_id"), "brand": tenant.get("federation_brand"),
                         "auth_url": tenant.get("auth_url"), "error": tenant.get("error")}
    else:
        row["signin"] = None

    if row["exists"] and mx is not None and not parked:
        row["grade"] = _grade(spf, dmarc, dkim, sts, tls_rpt, reg, mx, mp["gateways"], mp["in_m365"])
        if row["grade"]["grade"] in ("D", "F"):
            prob("grade", "warning" if row["grade"]["grade"] == "D" else "critical", f"Email security grade {row['grade']['grade']}")
    else:
        row["grade"] = None
    for k in timed_out:
        prob(k if k not in ("reg", "tenant") else ("expiry" if k == "reg" else "signin"), "info", f"{k} check timed out")
    row["problems"] = problems
    return row


def audit_batch(domains: list[str]) -> dict:
    clean: list[str] = []
    rows: list[dict] = []
    for d in domains:
        try:
            c = _clean(d)
        except ValueError as exc:
            rows.append({"domain": d[:100], "invalid": True, "error": str(exc), "problems": []})
            continue
        if c not in clean:
            clean.append(c)
    t0 = time.monotonic()
    deadline = t0 + DOMAIN_BUDGET
    pool = ThreadPoolExecutor(max_workers=min(WORKERS, 8 * max(1, len(clean))))
    try:
        # One outer thread per domain collects that domain's checks from the shared pool.
        with ThreadPoolExecutor(max_workers=max(1, len(clean))) as outer:
            futs = [outer.submit(audit_domain, pool, d, deadline) for d in clean]
            for d, f in zip(clean, futs):
                try:
                    rows.append(f.result())
                except Exception as exc:  # noqa: BLE001
                    rows.append({"domain": d, "error": str(exc)[:200], "problems": [{"col": "domain", "severity": "warning", "text": "Audit failed"}]})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return {"rows": rows, "elapsed_ms": round((time.monotonic() - t0) * 1000), "budget_s": DOMAIN_BUDGET}


@router.post("/api/bulk/normalize")
def bulk_normalize(req: NormalizeRequest):
    return run(normalize_list, req.text)


@router.post("/api/bulk/audit")
def bulk_audit(req: AuditRequest):
    return run(audit_batch, req.domains)
