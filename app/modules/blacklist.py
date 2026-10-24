"""DNS blocklist (DNSBL / URIBL) checks for IPs and domains."""
from __future__ import annotations

import ipaddress
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
    {"zone": "ix.dnsbl.manitu.net", "name": "NiX Spam", "info": "https://www.nixspam.net/"},
    {"zone": "dnsbl.dronebl.org", "name": "DroneBL", "info": "https://dronebl.org/lookup"},
    {"zone": "bl.blocklist.de", "name": "blocklist.de", "info": "https://www.blocklist.de/en/search.html"},
    {"zone": "rbl.interserver.net", "name": "InterServer", "info": "https://rbl.interserver.net/"},
    {"zone": "dnsbl.spfbl.net", "name": "SPFBL", "info": "https://spfbl.net/en/dnsbl/"},
    {"zone": "db.wpbl.info", "name": "WPBL", "info": "http://www.wpbl.info/"},
    {"zone": "truncate.gbudb.net", "name": "GBUdb Truncate", "info": "https://www.gbudb.com/"},
    {"zone": "all.s5h.net", "name": "s5h.net", "info": "https://www.usenix.org.uk/content/rbl.html"},
]
DOMAIN_LISTS = [
    {"zone": "dbl.spamhaus.org", "name": "Spamhaus DBL", "info": "https://check.spamhaus.org/"},
    {"zone": "multi.surbl.org", "name": "SURBL", "info": "https://surbl.org/surbl-analysis"},
    {"zone": "multi.uribl.com", "name": "URIBL", "info": "https://admin.uribl.com/"},
]

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


def _query(res, lst: dict, key: str, is_domain: bool) -> dict:
    name = f"{key}.{lst['zone']}"
    rdata, meta = resolve(res, name, "A", fallback=False)
    out = {"list": lst["name"], "zone": lst["zone"], "info": lst["info"], "listed": False, "policy": False, "codes": [],
           "meaning": None, "reason": None, "error": None}
    if meta["status"] in ("timeout", "servfail", "error"):
        out["error"] = meta["error"] or meta["status"]
        return out
    codes = [r.address for r in rdata]
    if not codes:
        return out
    refused = [REFUSED[c] for c in codes if c in REFUSED]
    # URIBL / SURBL answer 127.0.0.1 when they block the querying resolver.
    if refused or (is_domain and lst["zone"] in ("multi.uribl.com", "multi.surbl.org") and codes == ["127.0.0.1"]):
        out["error"] = refused[0] if refused else "Query refused (public resolver or rate limit)"
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

    with ThreadPoolExecutor(max_workers=24) as pool:
        if domain:
            for lst in DOMAIN_LISTS:
                jobs.append(("domain", domain, pool.submit(_query, res, lst, domain, True)))
        for ip in ips:
            v6 = ipaddress.ip_address(ip).version == 6
            for lst in IP_LISTS:
                if v6 and not lst.get("ipv6"):
                    continue
                jobs.append(("ip", ip, pool.submit(_query, res, lst, _reverse_ip(ip), False)))
        rdns = {ip: pool.submit(fcrdns, res, ip) for ip in ips}
        for kind, subject, fut in jobs:
            checks.append({"kind": kind, "subject": subject, **fut.result()})
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
    return {"input": target, "resolver": resolver_name or "system", "targets": targets,
            "listed_total": sum(t["listed"] for t in targets)}
