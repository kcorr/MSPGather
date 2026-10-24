"""SPF expansion, lookup counting and evaluation (RFC 7208)."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter

from ..core.dns_utils import make_resolver, normalize_domain, resolve, txt

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
MAX_LOOKUPS = 10
MAX_VOID = 2
MAX_DEPTH = 12

RESULT_HELP = {
    "pass": "The IP is authorised to send for this domain.",
    "fail": "The domain explicitly says this IP is NOT authorised (-all). Receivers may reject.",
    "softfail": "The IP is probably not authorised (~all). Usually accepted but marked suspicious; fails DMARC SPF alignment.",
    "neutral": "The domain makes no assertion about this IP (?all or no 'all').",
    "none": "The domain has no SPF record.",
    "permerror": "The SPF record is broken (too many lookups, syntax error, missing include target). Receivers treat this like a failure.",
    "temperror": "A DNS error stopped evaluation. Receivers usually defer or treat as neutral.",
}


def _finding(sev: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "title": title, "detail": detail}


class _Ctx:
    def __init__(self, resolver):
        self.resolver = resolver
        self.lookups = 0
        self.void = 0
        self.findings: list[dict] = []
        self.networks: list[dict] = []
        self.includes: list[str] = []
        self.ptr_used = False


def get_spf_records(resolver, domain: str) -> tuple[list[str], dict]:
    records, meta = txt(resolver, domain)
    return [r.strip() for r in records if re.match(r"(?i)^v=spf1(\s|$)", r.strip())], meta


def _expand_macros(spec: str, domain: str) -> tuple[str, bool]:
    """Expand the domain-only macros. Returns (spec, fully_expanded)."""
    if "%" not in spec:
        return spec, True
    out = (spec.replace("%{d}", domain).replace("%{o}", domain)
           .replace("%%", "%").replace("%_", " ").replace("%-", "%20"))
    return out, "%{" not in out


def _parse_dual_cidr(s: str) -> tuple[int, int] | None:
    m = re.fullmatch(r"(?:/(\d{1,2}))?(?://(\d{1,3}))?", s)
    if not m:
        return None
    c4 = int(m.group(1)) if m.group(1) else 32
    c6 = int(m.group(2)) if m.group(2) else 128
    if c4 > 32 or c6 > 128:
        return None
    return c4, c6


def _split_domain_cidr(arg: str) -> tuple[str | None, str]:
    """':example.com/24//64' -> ('example.com', '/24//64');  '/24' -> (None, '/24')"""
    if arg.startswith(":"):
        body = arg[1:]
        idx = body.find("/")
        return (body, "") if idx < 0 else (body[:idx], body[idx:])
    return None, arg


def _parse_term(raw: str) -> dict:
    t: dict = {"raw": raw}
    m = re.fullmatch(r"([a-zA-Z][a-zA-Z0-9_.\-]*)=(.*)", raw)
    if m:
        t.update(kind="modifier", name=m.group(1).lower(), value=m.group(2))
        return t
    qualifier, body = "+", raw
    if body[0] in QUALIFIERS:
        qualifier, body = body[0], body[1:]
    name = re.split(r"[:/]", body, maxsplit=1)[0].lower()
    arg = body[len(name):]
    t.update(kind="mechanism", qualifier=qualifier, result=QUALIFIERS[qualifier], mechanism=name)
    if name not in MECHANISMS:
        t["error"] = f"Unknown mechanism '{name or raw}'"
        return t
    if name in ("ip4", "ip6"):
        if not arg.startswith(":") or len(arg) < 2:
            t["error"] = f"'{raw}' is missing an address"
            return t
        value = arg[1:]
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            t["error"] = f"'{value}' is not a valid {name} address/range"
            return t
        if (net.version == 4) != (name == "ip4"):
            t["error"] = f"'{value}' is not an {'IPv4' if name == 'ip4' else 'IPv6'} address"
            return t
        t["networks"] = [str(net)]
        if "/" in value:
            try:
                ipaddress.ip_network(value, strict=True)
            except ValueError:
                t["note"] = f"Host bits set; treated as {net}"
    elif name in ("a", "mx"):
        dom, cidr = _split_domain_cidr(arg)
        if dom == "":
            t["error"] = f"'{raw}' has ':' but no domain after it"
            return t
        parsed = _parse_dual_cidr(cidr)
        if parsed is None:
            t["error"] = f"Invalid CIDR length in '{raw}'"
            return t
        t["domain"] = dom
        t["cidr4"], t["cidr6"] = parsed
    elif name in ("include", "exists"):
        if not arg.startswith(":") or len(arg) < 2:
            t["error"] = f"'{name}' requires a domain"
            return t
        t["domain"] = arg[1:]
    elif name == "ptr":
        t["domain"] = arg[1:] if arg.startswith(":") else None
    elif name == "all" and arg:
        t["error"] = f"'all' takes no argument ('{raw}')"
    return t


def _nets_for(ips: list[str], c4: int, c6: int) -> list[str]:
    nets = []
    for ip in ips:
        prefix = c4 if ipaddress.ip_address(ip).version == 4 else c6
        nets.append(str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)))
    return nets


def _record_networks(ctx: _Ctx, nets: list[str], domain: str, raw: str) -> None:
    for n in nets:
        ctx.networks.append({"network": n, "source": domain, "mechanism": raw})


def _expand(ctx: _Ctx, domain: str, depth: int, chain: list[str], override: str | None = None) -> dict:
    """Expand an SPF record. override = evaluate this record text for the root
    domain instead of the one in DNS (used by the SPF Builder)."""
    node: dict = {"domain": domain, "record": None, "terms": [], "error": None, "redirect": None}
    if depth > MAX_DEPTH:
        node["error"] = "Maximum include depth exceeded"
        node["permerror"] = True
        return node
    if domain in chain:
        node["error"] = "Include loop: " + " → ".join([*chain, domain])
        node["permerror"] = True
        ctx.findings.append(_finding("critical", "SPF include loop", node["error"]))
        return node

    if override is not None and depth == 0:
        records, meta = [override.strip()], {"status": "ok", "error": None}
    else:
        records, meta = get_spf_records(ctx.resolver, domain)
    if meta["status"] in ("timeout", "servfail", "error"):
        node["error"] = f"DNS error: {meta['error'] or meta['status']}"
        node["temperror"] = True
        return node
    if not records:
        if depth > 0 and meta["status"] in ("nxdomain", "noanswer"):
            ctx.void += 1
        node["error"] = "No SPF record found" + (" (domain does not exist)" if meta["status"] == "nxdomain" else "")
        node["none"] = True
        return node
    if len(records) > 1:
        node["error"] = f"{len(records)} SPF records published; receivers return PermError"
        node["records"] = records
        node["record"] = records[0]
        node["permerror"] = True
        ctx.findings.append(_finding(
            "critical", f"Multiple SPF records at {domain}",
            "Only one v=spf1 TXT record is allowed. Merge them into a single record:\n" + "\n".join(records)))
        return node

    record = records[0]
    node["record"] = record
    sub_chain = [*chain, domain]
    seen_all = False

    for raw in record.split()[1:]:
        term = _parse_term(raw)
        node["terms"].append(term)
        if term.get("error"):
            node["permerror"] = True
            ctx.findings.append(_finding("critical", f"SPF syntax error at {domain}", term["error"]))
            continue
        if term["kind"] == "modifier":
            continue
        if seen_all:
            term["ignored"] = True
            continue
        name = term["mechanism"]
        before = ctx.lookups
        if name in LOOKUP_MECHANISMS:
            ctx.lookups += 1
            term["lookups"] = 1
        term["lookup_cost"] = ctx.lookups - before

        if name == "all":
            seen_all = True
        elif name in ("ip4", "ip6"):
            _record_networks(ctx, term["networks"], domain, raw)
        elif name == "include":
            target, ok = _expand_macros(term["domain"], domain)
            if not ok:
                term["note"] = "Uses sender-dependent macros; cannot be expanded without a message"
                continue
            target = target.lower().rstrip(".")
            ctx.includes.append(target)
            child = _expand(ctx, target, depth + 1, sub_chain)
            term["child"] = child
            term["lookup_cost"] = ctx.lookups - before  # this include plus everything nested under it
            if child.get("none"):
                ctx.findings.append(_finding(
                    "critical", f"include:{target} has no SPF record",
                    f"Referenced from {domain}. An include with no SPF record is a PermError, which breaks SPF for "
                    "every message. Remove it or fix the target (often a vendor that changed their include name)."))
            elif child.get("temperror"):
                ctx.findings.append(_finding("warning", f"DNS error resolving include:{target}", child["error"]))
        elif name in ("a", "mx"):
            host, ok = _expand_macros(term.get("domain") or domain, domain)
            if not ok:
                term["note"] = "Uses sender-dependent macros; not evaluated"
                continue
            ips: list[str] = []
            if name == "a":
                for rtype in ("A", "AAAA"):
                    rdata, _ = resolve(ctx.resolver, host, rtype)
                    ips.extend(r.address for r in rdata)
                if not ips:
                    ctx.void += 1
            else:
                rdata, _ = resolve(ctx.resolver, host, "MX")
                if not rdata:
                    ctx.void += 1
                exchanges = [r.exchange.to_text(omit_final_dot=True) for r in rdata]
                term["exchanges"] = exchanges
                if len(exchanges) > 10:
                    node["permerror"] = True
                    ctx.findings.append(_finding("critical", f"mx mechanism at {domain} returns more than 10 MX hosts",
                                                 "RFC 7208 limits an mx mechanism to 10 MX names."))
                for ex in exchanges[:10]:
                    for rtype in ("A", "AAAA"):
                        rr, _ = resolve(ctx.resolver, ex, rtype)
                        ips.extend(r.address for r in rr)
            term["resolved"] = ips
            term["networks"] = _nets_for(ips, term["cidr4"], term["cidr6"])
            _record_networks(ctx, term["networks"], domain, raw)
        elif name == "ptr":
            ctx.ptr_used = True
            term["note"] = "Deprecated (RFC 7208 §5.5); slow and unreliable. Not evaluated."
        elif name == "exists":
            host, ok = _expand_macros(term["domain"], domain)
            if not ok:
                term["note"] = "Uses sender-dependent macros; not evaluated"
                continue
            rdata, _ = resolve(ctx.resolver, host, "A")
            term["exists"] = bool(rdata)

    redirect = next((t for t in node["terms"] if t["kind"] == "modifier" and t["name"] == "redirect"), None)
    if redirect:
        if seen_all:
            redirect["ignored"] = True
            redirect["note"] = "Ignored because the record contains 'all'"
        else:
            before = ctx.lookups
            ctx.lookups += 1
            redirect["lookup_cost"] = 1
            target, ok = _expand_macros(redirect["value"], domain)
            if ok:
                target = target.lower().rstrip(".")
                ctx.includes.append(target)
                node["redirect"] = _expand(ctx, target, depth + 1, sub_chain)
                redirect["lookup_cost"] = ctx.lookups - before
                if node["redirect"].get("none"):
                    ctx.findings.append(_finding("critical", f"redirect={target} has no SPF record",
                                                 "A redirect to a domain without SPF is a PermError."))
    return node


def evaluate(tree: dict, ip: str) -> tuple[str, list[dict]]:
    trace: list[dict] = []
    return _eval(tree, ipaddress.ip_address(ip), trace), trace


def _eval(node: dict, addr, trace: list[dict]) -> str:
    if node.get("temperror"):
        return "temperror"
    if node.get("none"):
        return "none"
    if node.get("permerror"):
        trace.append({"domain": node["domain"], "term": "(record)", "result": "permerror"})
        return "permerror"
    for t in node["terms"]:
        if t["kind"] != "mechanism" or t.get("ignored"):
            continue
        m = t["mechanism"]
        matched = False
        if m in ("ip4", "ip6", "a", "mx"):
            matched = any(addr in ipaddress.ip_network(n) for n in t.get("networks", [])
                          if ipaddress.ip_network(n).version == addr.version)
        elif m == "include":
            child = t.get("child")
            if child is None:
                continue
            child_trace: list[dict] = []
            r = _eval(child, addr, child_trace)
            if r == "pass":
                trace.extend(child_trace)  # keep only the path that matched
                matched = True
            elif r in ("permerror", "none"):
                trace.append({"domain": node["domain"], "term": t["raw"], "result": "permerror"})
                return "permerror"
            elif r == "temperror":
                return "temperror"
        elif m == "exists":
            matched = bool(t.get("exists"))
        elif m == "all":
            matched = True
        if matched:
            trace.append({"domain": node["domain"], "term": t["raw"], "result": t["result"]})
            return t["result"]
    if node.get("redirect"):
        r = _eval(node["redirect"], addr, trace)
        return "permerror" if r == "none" else r
    trace.append({"domain": node["domain"], "term": "(no match, no 'all')", "result": "neutral"})
    return "neutral"


def merge_records(records: list[str]) -> str:
    """Combine several published v=spf1 records into one: every mechanism once,
    in first-seen order, ending with the strictest 'all' found."""
    terms: list[str] = []
    strictest = None
    rank = {"-all": 3, "~all": 2, "?all": 1, "all": 0, "+all": 0}
    for rec in records:
        for t in rec.split()[1:]:
            low = t.lower()
            if low.lstrip("+-~?") == "all":
                if strictest is None or rank.get(low, 0) > rank.get(strictest, 0):
                    strictest = low if low != "all" else "+all"
                continue
            if low.startswith(("redirect=", "exp=")):
                continue
            if low not in (x.lower() for x in terms):
                terms.append(t)
    if strictest in (None, "+all"):
        strictest = "~all"  # never propose +all
    return " ".join(["v=spf1", *terms, strictest])


def _analyze_multiple(domain: str, resolver_name: str | None, ip: str | None, tree: dict, ctx: _Ctx) -> dict:
    """More than one SPF record = PermError for every message. Report that once,
    clearly, and evaluate the merged record the domain should publish instead."""
    records = tree["records"]
    merged = merge_records(records)
    mctx = _Ctx(make_resolver(resolver_name))
    mtree = _expand(mctx, domain, 0, [], override=merged)
    over = mctx.lookups > MAX_LOOKUPS
    detail = (f"Receivers treat {len(records)} v=spf1 records as a permanent error, so SPF fails for EVERY sender until only one remains.\n"
              "Published:\n" + "\n".join(f"  {r}" for r in records) +
              f"\n\nPublish this single record instead ({mctx.lookups}/{MAX_LOOKUPS} DNS lookups) and delete the others:\n  {merged}"
              + ("\n\nThe merged record is over the 10-lookup limit, so remove senders that no longer send before publishing." if over else ""))
    findings = [_finding("critical", f"{len(records)} SPF records published: SPF fails for every sender", detail)]
    findings += [f for f in mctx.findings if f["severity"] == "critical"]
    seen: set[str] = set()
    networks = [n for n in mctx.networks if not (n["network"] in seen or seen.add(n["network"]))]
    result = {
        "domain": domain, "record": records[0], "records": records, "multiple": True, "tree": tree,
        "merged": {"record": merged, "lookups": mctx.lookups, "over_limit": over},
        "lookup_count": mctx.lookups, "lookup_limit": MAX_LOOKUPS, "void_lookups": mctx.void,
        "includes": mctx.includes, "networks": networks, "findings": findings,
    }
    if ip:
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"'{ip}' is not a valid IP address") from exc
        after, after_trace = evaluate(mtree, ip)
        result["test"] = {"ip": ip, "result": "permerror", "trace": [{"domain": domain, "term": "(multiple SPF records)", "result": "permerror"}],
                          "explanation": RESULT_HELP["permerror"] + f" After merging the records, this IP would get: {after}.",
                          "after_merge": after, "after_merge_trace": after_trace}
    return result


def analyze_spf(domain: str, resolver_name: str | None = None, ip: str | None = None,
                record: str | None = None) -> dict:
    """record: evaluate this proposed record instead of the published one."""
    domain = normalize_domain(domain)
    ctx = _Ctx(make_resolver(resolver_name))
    tree = _expand(ctx, domain, 0, [], override=record)
    findings: list[dict] = []

    if tree.get("records") and len(tree["records"]) > 1 and record is None:
        return _analyze_multiple(domain, resolver_name, ip, tree, ctx)

    if tree.get("none"):
        findings.append(_finding(
            "critical", "No SPF record",
            f"{domain} publishes no v=spf1 record. Receivers cannot verify senders and DMARC can only pass via DKIM. "
            "If the domain sends no mail, publish \"v=spf1 -all\"."))
    elif tree.get("temperror"):
        findings.append(_finding("warning", "Could not look up SPF", tree["error"]))
    else:
        all_term = next((t for t in tree["terms"] if t["kind"] == "mechanism"
                         and t.get("mechanism") == "all" and not t.get("ignored")), None)
        if all_term:
            q = all_term["qualifier"]
            if q == "+":
                findings.append(_finding("critical", "SPF ends in +all",
                                         "+all authorises the entire internet to send as this domain. Change it to ~all or -all."))
            elif q == "?":
                findings.append(_finding("warning", "SPF ends in ?all (neutral)",
                                         "Neutral gives receivers no guidance. Use ~all (with DMARC enforcement) or -all."))
            elif q == "~":
                findings.append(_finding("info", "SPF ends in ~all (softfail)",
                                         "Fine when DMARC is at quarantine/reject. Use -all if you want SPF itself to be strict."))
            else:
                findings.append(_finding("ok", "SPF ends in -all (hard fail)"))
        elif not tree.get("redirect"):
            findings.append(_finding("warning", "SPF has no 'all' mechanism or redirect",
                                     "Without an 'all' the default result is neutral for unlisted senders."))
        after_all = [t["raw"] for t in tree["terms"] if t.get("ignored") and t["kind"] == "mechanism"]
        if after_all:
            findings.append(_finding("warning", "Mechanisms after 'all' are ignored",
                                     "These never get evaluated: " + " ".join(after_all)))

    if ctx.lookups > MAX_LOOKUPS:
        findings.append(_finding(
            "critical", f"Too many DNS lookups: {ctx.lookups}/{MAX_LOOKUPS} (PermError)",
            "Receivers stop at 10 lookups and return PermError, so SPF fails for ALL mail. Remove unused includes, "
            "replace a/mx with ip4/ip6, move marketing senders to a subdomain, or use SPF flattening."))
    elif ctx.lookups >= 8:
        findings.append(_finding("warning", f"Close to the lookup limit: {ctx.lookups}/{MAX_LOOKUPS}",
                                 "One more vendor include may break SPF. Vendors can also add nested lookups without notice."))
    elif not tree.get("none"):
        findings.append(_finding("ok", f"DNS lookups: {ctx.lookups}/{MAX_LOOKUPS}"))
    if ctx.void > MAX_VOID:
        findings.append(_finding("critical", f"Too many void lookups: {ctx.void}/{MAX_VOID}",
                                 "Lookups that return no data (dead includes, a/mx with no records) count separately; over 2 is a PermError."))
    if ctx.ptr_used:
        findings.append(_finding("warning", "SPF uses the deprecated 'ptr' mechanism",
                                 "Many receivers ignore it. Replace with ip4/ip6 or include."))
    dupes = [d for d, c in Counter(ctx.includes).items() if c > 1]
    if dupes:
        findings.append(_finding("warning", "Duplicate includes", "Included more than once (wastes lookups): " + ", ".join(dupes)))
    if tree.get("record") and len(tree["record"]) > 450:
        findings.append(_finding("info", f"Long SPF record ({len(tree['record'])} chars)",
                                 "Very long TXT answers may need TCP fallback. Some old resolvers handle this badly."))

    seen: set[str] = set()
    networks = []
    for n in ctx.networks:
        if n["network"] not in seen:
            seen.add(n["network"])
            networks.append(n)

    result = {
        "domain": domain,
        "record": tree.get("record"),
        "tree": tree,
        "lookup_count": ctx.lookups,
        "lookup_limit": MAX_LOOKUPS,
        "void_lookups": ctx.void,
        "includes": ctx.includes,
        "networks": networks,
        "findings": ctx.findings + findings,
    }
    if ip:
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"'{ip}' is not a valid IP address") from exc
        res, trace = evaluate(tree, ip)
        result["test"] = {"ip": ip, "result": res, "trace": trace, "explanation": RESULT_HELP.get(res, "")}
    return result
