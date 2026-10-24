"""DNS lookup compared across resolvers and the zone's authoritative servers.
This answers 'has my change propagated?' and 'is someone serving stale data?'."""
from __future__ import annotations

import os

import dns.reversename
from concurrent.futures import ThreadPoolExecutor

from ..core.dns_utils import (DOH_ENDPOINTS, PUBLIC_RESOLVERS, addresses, is_ip, make_resolver,
                              normalize_domain, resolve)

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "SRV", "PTR", "CAA", "DS", "DNSKEY"]


def _fmt(rtype: str, r) -> str:
    if rtype == "TXT":
        return b"".join(r.strings).decode("utf-8", "replace")
    if rtype == "MX":
        return f"{r.preference} {r.exchange.to_text(omit_final_dot=True)}"
    return r.to_text().rstrip(".")


def _find_zone(res, name: str) -> tuple[str | None, list[str]]:
    labels = name.split(".")
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        rdata, meta = resolve(res, zone, "NS")
        if rdata:
            return zone, sorted(r.target.to_text(omit_final_dot=True) for r in rdata)
        if meta["status"] in ("timeout", "servfail"):
            break
    return None, []


_ANSWERED = ("ok", "nxdomain", "noanswer")
_NAMES = {"cloudflare": "Cloudflare", "google": "Google", "quad9": "Quad9", "doh-cloudflare": "Cloudflare (DoH)", "doh-google": "Google (DoH)"}
GEO_TTL = 300  # A/AAAA answers this short-lived that differ between resolvers are load balancing, not stale caches


def _local_label() -> str:
    return "the local resolver (Docker DNS)" if os.path.exists("/.dockerenv") else "the local resolver"


def _label(source: str) -> str:
    if source == "system":
        return _local_label()
    if source.startswith("auth: "):
        return source[6:]
    return _NAMES.get(source, source)


def _join(names: list[str]) -> str:
    names = list(dict.fromkeys(names))
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _ttl_phrase(ttl: int | None) -> str:
    if ttl is None:
        return "TTL unknown"
    if ttl < 90:
        return f"TTL {ttl}s"
    if ttl < 5400:
        return f"TTL {ttl}s, about {round(ttl / 60)} min"
    return f"TTL {ttl}s, about {round(ttl / 3600)} h"


def _value_phrase(records: tuple) -> str:
    def cut(v: str) -> str:
        return v if len(v) <= 100 else v[:97] + "…"
    if not records:
        return "no records"
    if len(records) == 1:
        return f"`{cut(records[0])}`"
    if len(records) <= 3 and sum(len(r) for r in records) <= 140:
        return ", ".join(f"`{cut(r)}`" for r in records)
    return f"{len(records)} records (`{cut(records[0])}`, …)"


def _same(n: int, results: list[dict]) -> str:
    if n == len(results):
        return f"same on all {n} sources"
    if n == 2:
        return f"same on both sources that answered, of {len(results)} queried"
    return f"same on all {n} sources that answered, of {len(results)} queried"


def _f(sev: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "title": title, "detail": detail}


def _verdict(qname: str, rtype: str, zone: str | None, ns_hosts: list[str], results: list[dict]) -> dict:
    """One plain answer: what the record is, whether everyone agrees, and if not, who is behind and for how long."""
    F: list[dict] = []
    answered = [r for r in results if r["status"] in _ANSWERED]
    failed = [r for r in results if r["status"] not in _ANSWERED]
    zone_txt = (f"zone {zone} · {len(ns_hosts)} authoritative server{'s' if len(ns_hosts) != 1 else ''}" if zone
                else "no parent zone found")

    if not answered:
        st = {r["status"] for r in results}
        if st == {"servfail"}:
            F.append(_f("critical", "Every resolver returned SERVFAIL",
                        "The resolvers couldn't get a usable answer from the zone's servers. The usual causes are broken DNSSEC (check Domain Registration "
                        "for the DS record) or authoritative servers that are down or refusing queries."))
            head = f"{qname} can't be resolved: SERVFAIL from every source (often broken DNSSEC or unreachable name servers)"
        else:
            F.append(_f("critical", "No source answered", "; ".join(sorted({f"{_label(r['source'])}: {r['error'] or r['status']}" for r in results}))[:400]))
            head = f"No DNS source answered for {qname} ({', '.join(sorted(st))})"
        return {"severity": "critical", "headline": head, "subline": f"{rtype} {qname} · {zone_txt}", "findings": F}

    # The local resolver alone returning nothing while everyone else has records is a quirk of this server, not of the zone.
    others = [r for r in answered if r["source"] != "system"]
    local = next((r for r in results if r["source"] == "system"), None)
    if (local and local["status"] in ("noanswer", "timeout", "servfail", "error") and others
            and all(r["status"] == "ok" and r["records"] for r in others)):
        if rtype == "AAAA":
            F.append(_f("info", f"{_local_label()[0].upper() + _local_label()[1:]} returns no IPv6 answers",
                        "Every other source returns AAAA records, so the records exist. The MSPGather server's own DNS doesn't return them "
                        "(Docker Desktop's DNS proxy is known to answer every AAAA query with NOANSWER). Nothing to fix in the zone."))
        else:
            F.append(_f("info", f"{_local_label()[0].upper() + _local_label()[1:]} returns no answer ({local['status']})",
                        f"Every other source has the {rtype} records, so the zone is fine. It's a limitation of the MSPGather server's own DNS path "
                        "(container DNS proxies can drop some record types, large responses or DNS over TCP). Other MSPGather checks fall back to "
                        "DNS-over-HTTPS automatically."))
        compare = others
    else:
        compare = answered
    # Classic DNS (port 53) failing everywhere while DoH works: a transport problem on this server's network, not a propagation one.
    classic = [r for r in results if not r["source"].startswith("doh")]
    doh_ok = [r for r in results if r["source"].startswith("doh") and r["status"] == "ok" and r["records"]]
    transport = bool(doh_ok and classic and not any(r["records"] for r in classic))
    if transport:
        F = [f for f in F if not f["title"].startswith(_local_label()[0].upper())]
        F.append(_f("info", "Only DNS-over-HTTPS got an answer; normal DNS (port 53) from this server didn't",
                    f"Every port-53 query ({', '.join(sorted({r['status'] for r in classic}))}) failed while DoH returned the records, so the records exist. "
                    "Something on the MSPGather server's network (firewall, ISP, VPN or the Docker DNS proxy) is dropping large DNS responses or blocking "
                    "DNS over TCP. Large TXT records like SPF are the usual victims. Other MSPGather checks fall back to DoH automatically."))
        compare = [r for r in results if r["source"].startswith("doh") and r["status"] in _ANSWERED]
    else:
        skipped = [r for r in failed if not (r["source"] == "system" and compare is others)]
        by_status: dict = {}
        for r in skipped:
            by_status.setdefault(r["status"], []).append(_label(r["source"]))
        for st, names in by_status.items():
            F.append(_f("info", f"{_join(names)} didn't answer ({st})",
                        "Compared the sources that did answer. A single timeout is usually transient; rerun the lookup."))

    sets = {tuple(r["records"]) for r in compare}
    statuses = {r["status"] for r in compare}
    n = len(compare)
    auth = [r for r in compare if r["authoritative"]]
    auth_sets = {tuple(r["records"]) for r in auth}

    # ---- everyone agrees
    if len(sets) == 1:
        recs = next(iter(sets))
        if statuses == {"nxdomain"}:
            sub = (f"The zone {zone} exists, but this name has no records of any type. Check the spelling." if zone else
                   "No parent zone exists either: the domain isn't registered or isn't delegated. Check the spelling.")
            return {"severity": "info", "headline": f"{qname} does not exist (NXDOMAIN everywhere)", "subline": sub, "findings": F}
        if not recs:
            return {"severity": "info", "headline": f"{qname} exists but has no {rtype} record ({_same(n, results)})",
                    "subline": f"{rtype} {qname} · {zone_txt}", "findings": F}
        return {"severity": "ok", "headline": f"{rtype} for {qname}: {_value_phrase(recs)} ({_same(n, results)})",
                "subline": f"{zone_txt} · {_ttl_phrase(max((r['ttl'] or 0) for r in compare) or None)}", "findings": F}

    # ---- authoritative servers disagree among themselves
    if len(auth_sets) > 1:
        F.insert(0, _f("warning", "The authoritative name servers disagree",
                       "The zone isn't in sync between its own servers (a zone-transfer problem or a half-finished DNS migration). Resolvers get a different "
                       "answer depending on which server they ask. Fix the zone on the DNS host; waiting won't help."))
        by = {}
        for r in auth:
            by.setdefault(tuple(r["records"]), []).append(_label(r["source"]))
        F.append(_f("info", "Answers per authoritative server", "; ".join(f"{_join(v)}: {_value_phrase(k)}" for k, v in by.items())))
        return {"severity": "warning", "headline": f"The authoritative servers for {zone or qname} give different {rtype} answers for {qname}",
                "subline": f"{rtype} {qname} · {zone_txt}", "findings": F}

    # ---- A/AAAA answers that differ but are short-lived and each a clean answer: geo-DNS / CDN load balancing
    if rtype in ("A", "AAAA") and statuses == {"ok"} and all(r["records"] for r in compare) and max((r["ttl"] or 0) for r in compare) <= GEO_TTL:
        ref = next(iter(auth_sets)) if auth_sets else tuple(compare[0]["records"])
        F.append(_f("ok", "Different addresses from different resolvers: normal load balancing",
                    f"Every source got a clean answer with a short TTL (≤ {GEO_TTL}s). CDNs and geo-DNS hand out addresses near the resolver that asks, "
                    "so differing sets are expected and are not stale data."))
        return {"severity": "ok", "headline": (f"{rtype} for {qname}: {_value_phrase(ref)}. Answers vary by resolver, which is normal geo-DNS / "
                                               f"CDN load balancing ({_ttl_phrase(min((r['ttl'] or 0) for r in compare))})"),
                "subline": f"{zone_txt} · {len(sets)} different answer sets across {n} sources", "findings": F}

    # ---- propagation: compare caches with what the authoritative servers say now
    if auth_sets:
        truth = next(iter(auth_sets))
        truth_status = auth[0]["status"]
        behind = [r for r in compare if not r["authoritative"] and tuple(r["records"]) != truth]
        if behind:
            names = _join([_label(r["source"]) for r in behind])
            ttl = max((r["ttl"] or 0) for r in behind) or None
            neg = all(r["status"] in ("nxdomain", "noanswer") for r in behind)
            verb = "serve" if len(behind) > 1 else "serves"
            if truth_status == "ok" and neg:
                head = f"Not fully propagated: {names} still {'say' if len(behind) > 1 else 'says'} there is no {rtype} record (cached negative answer)"
                wait = "once the negative cache expires (the zone's SOA minimum TTL, often 5 min to 1 h)"
            elif truth_status != "ok":
                head = f"Not fully propagated: {names} still {verb} a {rtype} record that the authoritative servers no longer have ({_ttl_phrase(ttl)})"
                wait = f"within {_ttl_phrase(ttl).split(', ')[-1].replace('TTL ', '')}" if ttl else "when its cache expires"
            else:
                head = f"Not fully propagated: {names} still {verb} the old value ({_ttl_phrase(ttl)})"
                wait = f"within {_ttl_phrase(ttl).split(', ')[-1].replace('TTL ', '')}" if ttl else "when its cache expires"
            F.insert(0, _f("warning", f"{names} {'are' if len(behind) > 1 else 'is'} behind the authoritative servers",
                           f"Authoritative answer: {_value_phrase(truth) if truth else 'no record'}. Cached elsewhere: "
                           + "; ".join(f"{_label(r['source'])}: {_value_phrase(tuple(r['records'])) if r['records'] else r['status']}" for r in behind)
                           + f". This fixes itself {wait}; nothing to change in the zone."))
            return {"severity": "warning", "headline": head,
                    "subline": f"Authoritative: {_value_phrase(truth) if truth else truth_status} · {len(compare) - len(behind)} of {n} sources up to date · {zone_txt}",
                    "findings": F}

    # ---- no authoritative reference (zone not found): just report the split
    by: dict = {}
    for r in compare:
        by.setdefault(tuple(r["records"]) if r["records"] else (r["status"],), []).append(_label(r["source"]))
    F.insert(0, _f("warning", "Sources disagree and the authoritative servers couldn't be queried",
                   "; ".join(f"{_join(v)}: {_value_phrase(k)}" for k, v in by.items())))
    return {"severity": "warning", "headline": f"Sources give {len(sets)} different {rtype} answers for {qname}",
            "subline": f"{rtype} {qname} · {zone_txt}", "findings": F}


def lookup(name: str, rtype: str = "A") -> dict:
    rtype = (rtype or "A").upper()
    if rtype not in RECORD_TYPES:
        raise ValueError(f"Unsupported record type {rtype}")
    raw = (name or "").strip()
    if rtype == "PTR" and is_ip(raw):
        qname = dns.reversename.from_address(raw.strip("[]")).to_text(omit_final_dot=True)
    elif is_ip(raw):
        qname = dns.reversename.from_address(raw.strip("[]")).to_text(omit_final_dot=True)
        rtype = "PTR"
    else:
        qname = normalize_domain(raw)

    base = make_resolver("system")
    zone, ns_hosts = _find_zone(base, qname if rtype != "PTR" else qname)
    sources: list[tuple[str, object]] = [("system", make_resolver("system"))]
    sources += [(n, make_resolver(n)) for n in [*PUBLIC_RESOLVERS, *DOH_ENDPOINTS]]
    from ..core.outbound import refusal
    for host in ns_hosts[:4]:
        ips = [i for i in addresses(base, host) if not refusal(i, allow_private=False)]
        if ips:
            sources.append((f"auth: {host}", make_resolver(nameservers=ips[:2], timeout=3.0, lifetime=5.0)))

    def run(item):
        label, res = item
        rdata, meta = resolve(res, qname, rtype, fallback=False)
        return {"source": label, "authoritative": label.startswith("auth:"), "status": meta["status"],
                "ttl": meta["ttl"], "error": meta["error"], "records": sorted(_fmt(rtype, r) for r in rdata)}

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(run, sources))

    answers = {tuple(r["records"]) for r in results if r["status"] in ("ok", "nxdomain", "noanswer")}
    auth = [r for r in results if r["authoritative"] and r["status"] in ("ok", "nxdomain", "noanswer")]
    auth_answers = {tuple(r["records"]) for r in auth}
    for r in results:
        r["matches_authoritative"] = (tuple(r["records"]) in auth_answers) if auth_answers else None
    verdict = _verdict(qname, rtype, zone, ns_hosts, results)
    # Notes are kept for older frontends; the findings carry the same text with a severity.
    notes = [f"{f['title']}. {f['detail']}".strip() for f in verdict["findings"] if f["severity"] != "ok"]
    return {"name": qname, "type": rtype, "zone": zone, "nameservers": ns_hosts, "consistent": len(answers) <= 1,
            "results": results, "notes": notes, **verdict}
