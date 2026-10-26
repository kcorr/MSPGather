"""DNS blocklist (DNSBL / URIBL) checks for IPs and domains.

Every list is first asked about its own test entry (RFC 5782: 127.0.0.2, or the list's
test domain). Lists that refuse the resolver MSPGather uses often answer "not listed"
for everything (Spamhaus through Google DNS, for example), so a list whose test entry
doesn't come back listed is reported as "couldn't check", never as clean.

Spamhaus' public mirrors are free only for low-volume, non-commercial use and refuse
public resolvers. Set SPAMHAUS_DQS_KEY to query through the Data Query Service instead."""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from ..core.dns_utils import addresses, fcrdns, is_ip, make_resolver, normalize_domain, resolve, txt

IP_LISTS = [
    {"zone": "zen.spamhaus.org", "name": "Spamhaus ZEN", "ipv6": True, "info": "https://check.spamhaus.org/"},
    {"zone": "b.barracudacentral.org", "name": "Barracuda BRBL", "info": "https://www.barracudacentral.org/lookups"},
    {"zone": "bl.spamcop.net", "name": "SpamCop", "info": "https://www.spamcop.net/bl.shtml"},
    {"zone": "psbl.surriel.com", "name": "PSBL", "info": "https://psbl.org/"},
    {"zone": "bl.mailspike.net", "name": "Mailspike", "info": "https://mailspike.org/"},
    {"zone": "dnsbl-1.uceprotect.net", "name": "UCEPROTECT L1", "info": "https://www.uceprotect.net/en/rblcheck.php"},
    {"zone": "dnsbl-2.uceprotect.net", "name": "UCEPROTECT L2 (whole range)", "info": "https://www.uceprotect.net/en/rblcheck.php", "range": True},
    {"zone": "dnsbl.dronebl.org", "name": "DroneBL", "info": "https://dronebl.org/lookup"},
    {"zone": "bl.blocklist.de", "name": "blocklist.de", "info": "https://www.blocklist.de/en/search.html"},
    {"zone": "rbl.interserver.net", "name": "InterServer", "info": "https://rbl.interserver.net/"},
    {"zone": "dnsbl.spfbl.net", "name": "SPFBL", "info": "https://spfbl.net/en/dnsbl/"},
    {"zone": "truncate.gbudb.net", "name": "GBUdb Truncate", "info": "https://www.gbudb.com/"},
    {"zone": "all.s5h.net", "name": "s5h.net", "info": "https://www.usenix.org.uk/content/rbl.html"},
]
DOMAIN_LISTS = [
    {"zone": "dbl.spamhaus.org", "name": "Spamhaus DBL", "info": "https://check.spamhaus.org/", "test": "dbltest.com"},
    {"zone": "multi.surbl.org", "name": "SURBL", "info": "https://surbl.org/surbl-analysis", "test": "test.surbl.org"},
    {"zone": "multi.uribl.com", "name": "URIBL", "info": "https://admin.uribl.com/", "test": "test.uribl.com"},
]
# Removed as defunct: ix.dnsbl.manitu.net (NiX Spam, closed January 2025), db.wpbl.info (WPBL, closed 2023).

log = logging.getLogger("mspgather.blacklist")
DQS_KEY = os.environ.get("SPAMHAUS_DQS_KEY", "").strip()
if DQS_KEY and not re.fullmatch(r"[A-Za-z0-9]{16,64}", DQS_KEY):
    log.warning("SPAMHAUS_DQS_KEY doesn't look like a Spamhaus DQS key; ignoring it.")
    DQS_KEY = ""
_DQS_ZONES = {"zen.spamhaus.org": "zen.dq.spamhaus.net", "dbl.spamhaus.org": "dbl.dq.spamhaus.net"}
CANARY_TTL = 600
_canary_cache: dict[tuple[str, str], tuple[float, str | None]] = {}
_canary_lock = threading.Lock()

SPAMHAUS_ZEN = {
    "127.0.0.2": "SBL: Spamhaus verified spam source", "127.0.0.3": "SBL CSS: snowshoe / low-reputation sender",
    "127.0.0.4": "XBL: compromised / infected host", "127.0.0.5": "XBL", "127.0.0.6": "XBL", "127.0.0.7": "XBL",
    "127.0.0.9": "SBL DROP: hijacked netblock",
    "127.0.0.10": "PBL (ISP): dynamic/end-user range that shouldn't send direct-to-MX",
    "127.0.0.11": "PBL (Spamhaus): end-user range that shouldn't send direct-to-MX",
}
SPAMHAUS_DBL = {
    "127.0.1.2": "Spam domain", "127.0.1.4": "Phishing domain", "127.0.1.5": "Malware domain", "127.0.1.6": "Botnet C&C domain",
    "127.0.1.102": "Abused legit domain (spam)", "127.0.1.103": "Abused redirector", "127.0.1.104": "Abused legit (phish)",
    "127.0.1.105": "Abused legit (malware)", "127.0.1.106": "Abused legit (botnet C&C)",
}
SPFBL = {"127.0.0.2": "Bad reputation", "127.0.0.3": "Suspicious / doubtful reputation",
         "127.0.0.4": "End-user or non-mail IP (policy listing)"}
# Policy listings say "this IP shouldn't send mail directly", not "this IP sent spam".
# They only matter for IPs that deliver straight to other people's MX.
POLICY_CODES = {"zen.spamhaus.org": {"127.0.0.10", "127.0.0.11"}, "dnsbl.spfbl.net": {"127.0.0.4"}}
REFUSED = {
    "127.255.255.252": "Query refused: typo in DNSBL name",
    "127.255.255.254": "Query refused: you're querying through a public/open resolver (Google, Cloudflare, …). Spamhaus needs your own resolver or a DQS key.",
    "127.255.255.255": "Query refused: query limit exceeded",
    "127.0.1.255": "Query refused: IP queried against a domain list",
}


def _reverse_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split(".")))
    return ".".join(reversed(addr.exploded.replace(":", "")))


def _zone(lst: dict) -> tuple[str, str]:
    """(zone to query, zone to show). A DQS key is part of the query name, so it's never shown."""
    dq = _DQS_ZONES.get(lst["zone"])
    if DQS_KEY and dq:
        return f"{DQS_KEY}.{dq}", f"{dq} (DQS)"
    return lst["zone"], lst["zone"]


def _refusal(codes: list[str], lst: dict, is_domain: bool) -> str | None:
    refused = [REFUSED[c] for c in codes if c in REFUSED]
    if refused:
        return refused[0]
    # URIBL / SURBL answer 127.0.0.1 when they block the querying resolver.
    if is_domain and lst["zone"] in ("multi.uribl.com", "multi.surbl.org") and codes == ["127.0.0.1"]:
        return "Query refused (public resolver or rate limit)"
    return None


def _canary(res, resolver_key: str, lst: dict, is_domain: bool) -> str | None:
    """None if the list answers its own test entry through this resolver, otherwise why its
    answers can't be trusted. Cached per resolver and list for a few minutes."""
    qzone, _ = _zone(lst)
    ck = (resolver_key, qzone)
    now = time.monotonic()
    with _canary_lock:
        hit = _canary_cache.get(ck)
        if hit and hit[0] > now:
            return hit[1]
    test = lst.get("test") or "2.0.0.127"
    rdata, meta = resolve(res, f"{test}.{qzone}", "A", fallback=False)
    codes = [r.address for r in rdata]
    transient = False
    if meta["status"] in ("timeout", "error"):
        why, transient = f"The list didn't answer through the {resolver_key} resolver ({meta['status']}).", True
    elif meta["status"] == "servfail":
        why = f"Query refused or failing: the list returns SERVFAIL through the {resolver_key} resolver."
    elif _refusal(codes, lst, is_domain):
        why = _refusal(codes, lst, is_domain)
    elif not codes:
        why = (f"Query refused or filtered: the list's own test entry didn't come back listed through the {resolver_key} resolver, "
               "so a 'not listed' answer can't be trusted. Public resolvers (Google, Cloudflare, Quad9) are often refused.")
    else:
        why = None
    if why and lst["zone"] in _DQS_ZONES and not DQS_KEY and "DQS" not in why:
        why += (" Spamhaus needs your own recursive resolver or a Data Query Service key (SPAMHAUS_DQS_KEY); "
                "its free tiers are for non-commercial use.")
    with _canary_lock:
        _canary_cache[ck] = (now + (60 if transient else CANARY_TTL), why)
    return why


def _unusable(lst: dict, why: str) -> dict:
    return {"list": lst["name"], "zone": _zone(lst)[1], "info": lst["info"], "listed": False, "policy": False,
            "codes": [], "meaning": None, "reason": None, "error": why, "unusable": True}


def _query(res, lst: dict, key: str, is_domain: bool) -> dict:
    qzone, shown = _zone(lst)
    name = f"{key}.{qzone}"
    rdata, meta = resolve(res, name, "A", fallback=False)
    out = {"list": lst["name"], "zone": shown, "info": lst["info"], "listed": False, "policy": False, "codes": [],
           "meaning": None, "reason": None, "error": None}
    if meta["status"] in ("timeout", "servfail", "error"):
        out["error"] = meta["error"] or meta["status"]
        return out
    codes = [r.address for r in rdata]
    if not codes:
        return out
    refusal = _refusal(codes, lst, is_domain)
    if refusal:
        out["error"] = refusal
        return out
    out["codes"] = codes
    if set(codes) <= POLICY_CODES.get(lst["zone"], set()):
        out["policy"] = True
    else:
        out["listed"] = True
    table = {"dbl.spamhaus.org": SPAMHAUS_DBL, "zen.spamhaus.org": SPAMHAUS_ZEN, "dnsbl.spfbl.net": SPFBL}.get(lst["zone"], {})
    meanings = [table[c] for c in codes if c in table]
    out["meaning"] = "; ".join(meanings) or None
    reasons, _ = txt(res, name, fallback=False)
    out["reason"] = reasons[0] if reasons else None
    if lst.get("range"):
        out["meaning"] = (out["meaning"] or "") + " Your provider's IP range is listed, not necessarily your IP."
    return out


def check_target(target: str, resolver_name: str | None = None) -> dict:
    target = (target or "").strip()
    if not target:
        raise ValueError("Enter an IP address or domain.")
    res = make_resolver(resolver_name, timeout=3.0, lifetime=5.0)
    checks: list[dict] = []
    jobs = []
    roles: dict[str, str] = {}
    if is_ip(target):
        target = target.strip("[]")
        ips, domain = [target], None
    else:
        domain = normalize_domain(target)
        ips = []
        mx, _ = resolve(res, domain, "MX")
        for r in sorted(mx, key=lambda r: r.preference)[:3]:
            host = r.exchange.to_text(omit_final_dot=True)
            for ip in addresses(res, host):
                if ipaddress.ip_address(ip).version == 4 and ip not in ips:
                    ips.append(ip)
                    roles[ip] = f"MX {host}"
        for ip in addresses(res, domain):
            if ipaddress.ip_address(ip).version == 4 and ip not in ips:
                ips.append(ip)
                roles[ip] = "Domain A record (web server, usually not a mail sender)"
        ips = ips[:6]

    resolver_key = resolver_name or "system"
    with ThreadPoolExecutor(max_workers=24) as pool:
        # Which lists can be trusted through this resolver: each is asked about its own test entry.
        wanted = ([(lst, True) for lst in DOMAIN_LISTS] if domain else []) + ([(lst, False) for lst in IP_LISTS] if ips else [])
        futures = {lst["zone"]: pool.submit(_canary, res, resolver_key, lst, is_dom) for lst, is_dom in wanted}
        canary = {zone: fut.result() for zone, fut in futures.items()}
        if domain:
            for lst in DOMAIN_LISTS:
                why = canary.get(lst["zone"])
                jobs.append(("domain", domain, None if why else pool.submit(_query, res, lst, domain, True), lst, why))
        for ip in ips:
            v6 = ipaddress.ip_address(ip).version == 6
            for lst in IP_LISTS:
                if v6 and not lst.get("ipv6"):
                    continue
                why = canary.get(lst["zone"])
                jobs.append(("ip", ip, None if why else pool.submit(_query, res, lst, _reverse_ip(ip), False), lst, why))
        rdns = {ip: pool.submit(fcrdns, res, ip) for ip in ips}
        for kind, subject, fut, lst, why in jobs:
            checks.append({"kind": kind, "subject": subject, **(fut.result() if fut else _unusable(lst, why))})
        reverse = {ip: f.result() for ip, f in rdns.items()}

    targets = []
    for subject in ([domain] if domain else []) + ips:
        rows = [c for c in checks if c["subject"] == subject]
        targets.append({
            "subject": subject, "kind": "domain" if subject == domain else "ip",
            "role": roles.get(subject, "Domain name" if subject == domain else "IP address"),
            "listed": sum(1 for r in rows if r["listed"]), "policy": sum(1 for r in rows if r["policy"]),
            "errors": sum(1 for r in rows if r["error"]),
            "checked": len(rows), "rdns": reverse.get(subject), "results": rows,
        })
    skipped = sorted({c["list"] for c in checks if c.get("unusable")})
    notes = []
    if skipped:
        notes.append(f"{len(skipped)} list{'s' if len(skipped) > 1 else ''} couldn't be used through the {resolver_key} resolver "
                     f"({', '.join(skipped)}): their own test entries didn't answer correctly, so they're shown as unknown, not clean. "
                     "Run MSPGather on a network with its own recursive resolver for complete results.")
    if not DQS_KEY:
        notes.append("Spamhaus is queried through its public mirrors, which are free only for low-volume, non-commercial use. "
                     "For client work, set SPAMHAUS_DQS_KEY (Spamhaus Data Query Service).")
    return {"input": target, "resolver": resolver_key, "targets": targets, "notes": notes, "dqs": bool(DQS_KEY),
            "listed_total": sum(t["listed"] for t in targets)}
