"""Shared DNS helpers used by every diagnostic module."""
from __future__ import annotations

import ipaddress
import os
import logging
import re
import threading
from typing import Any

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename
import httpx

PUBLIC_RESOLVERS: dict[str, list[str]] = {
    "cloudflare": ["1.1.1.1", "1.0.0.1"],
    "google": ["8.8.8.8", "8.8.4.4"],
    "quad9": ["9.9.9.9", "149.112.112.112"],
}
DOH_ENDPOINTS: dict[str, str] = {
    "doh-cloudflare": "https://cloudflare-dns.com/dns-query",
    "doh-google": "https://dns.google/dns-query",
}
DEFAULT_RESOLVER = os.environ.get("DEFAULT_RESOLVER", "system")
log = logging.getLogger("mspgather.dns")
# Many networks (and Docker Desktop's DNS proxy) drop large DNS answers or block
# TCP/53, which makes big TXT records (SPF!) silently disappear. When a classic
# query fails or comes back empty, retry over DNS-over-HTTPS.
DOH_FALLBACK = os.environ.get("DOH_FALLBACK", "true").lower() not in ("0", "false", "no", "off")
_FALLBACK_ON_EMPTY = {"TXT", "MX", "NS", "SRV", "CAA", "DNSKEY", "DS", "PTR"}
_http = httpx.Client(timeout=6.0, headers={"accept": "application/dns-message"})


class DohResolver:
    """Minimal DNS-over-HTTPS resolver (RFC 8484, wire format)."""

    def __init__(self, url: str):
        self.url = url

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$")

# Second-level labels that sit under a ccTLD (co.uk, com.au, ...). A heuristic,
# not a full public suffix list, but good enough for grouping mail hosts.
_SLD = {"co", "com", "net", "org", "gov", "ac", "edu", "ltd", "plc", "sch", "nhs", "or", "ne", "go", "gob", "mil"}


def resolver_names() -> list[str]:
    return ["system", *PUBLIC_RESOLVERS, *DOH_ENDPOINTS]


def make_resolver(name: str | None = None, nameservers: list[str] | None = None,
                  timeout: float = 3.0, lifetime: float = 8.0):
    name = name or DEFAULT_RESOLVER
    if name in DOH_ENDPOINTS and not nameservers:
        return DohResolver(DOH_ENDPOINTS[name])
    if nameservers:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = list(nameservers)
    elif name in PUBLIC_RESOLVERS:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = list(PUBLIC_RESOLVERS[name])
    else:
        r = dns.resolver.Resolver()
        r._mspg_system = True  # eligible for learned DoH routing
    r.timeout = timeout
    r.lifetime = lifetime
    return r


def resolve(resolver, name: str, rtype: str, fallback: bool = True) -> tuple[list[Any], dict]:
    """Resolve and never raise. Returns (rdata list, meta) where meta.status is
    one of ok | nxdomain | noanswer | servfail | timeout | error.
    fallback=False disables the DoH retry (DNSBLs, resolver comparisons)."""
    if isinstance(resolver, DohResolver):
        return _resolve_doh(resolver.url, name, rtype)
    learn = fallback and DOH_FALLBACK and getattr(resolver, "_mspg_system", False)
    # Learned once per process: this resolver drops IPv6 answers or large answers,
    # so go straight to DoH instead of paying a timeout on every query.
    if learn and ((rtype == "AAAA" and _system_drops_aaaa(resolver)) or (rtype == "TXT" and _LEARNED["drops_big_txt"])):
        rdata2, meta2 = _resolve_doh(DOH_ENDPOINTS["doh-cloudflare"], name, rtype)
        if meta2["status"] in ("ok", "nxdomain", "noanswer"):
            meta2["via"] = "doh-learned"
            return rdata2, meta2
    rdata, meta = _resolve_classic(resolver, name, rtype)
    if fallback and DOH_FALLBACK and (meta["status"] in ("timeout", "servfail", "error")
                                      or (meta["status"] == "noanswer" and rtype in _FALLBACK_ON_EMPTY)):
        rdata2, meta2 = _resolve_doh(DOH_ENDPOINTS["doh-cloudflare"], name, rtype)
        if rdata2 or meta2["status"] in ("nxdomain", "noanswer") and meta["status"] != "noanswer":
            meta2["via"] = "doh-fallback"
            meta2["classic_status"] = meta["status"]
            if learn and rtype == "TXT" and rdata2 and meta["status"] in ("noanswer", "timeout"):
                _LEARNED["drops_big_txt"] = True
                log.info("System resolver dropped a TXT answer that DoH returned; using DoH first for TXT from now on.")
            return rdata2, meta2
    return rdata, meta


_LEARNED = {"drops_aaaa": None, "drops_big_txt": False}
_LEARN_LOCK = threading.Lock()


def _system_drops_aaaa(resolver) -> bool:
    """Docker Desktop's DNS proxy (127.0.0.11) can return NOANSWER for every AAAA
    query. Probe a well-known dual-stack name once to find out."""
    if _LEARNED["drops_aaaa"] is None:
        with _LEARN_LOCK:
            if _LEARNED["drops_aaaa"] is None:
                rd, meta = _resolve_classic(resolver, "dns.google", "AAAA")
                _LEARNED["drops_aaaa"] = (not rd and meta["status"] in ("noanswer", "timeout", "servfail"))
                if _LEARNED["drops_aaaa"]:
                    log.info("System resolver returns no IPv6 (AAAA) answers; using DoH for AAAA lookups.")
    return bool(_LEARNED["drops_aaaa"])


def _resolve_doh(url: str, name: str, rtype: str) -> tuple[list[Any], dict]:
    meta: dict[str, Any] = {"name": name, "type": rtype, "status": "ok", "ttl": None, "error": None, "via": "doh"}
    try:
        q = dns.message.make_query(dns.name.from_text(name), rtype)
        resp = _http.post(url, content=q.to_wire(), headers={"content-type": "application/dns-message"})
        resp.raise_for_status()
        msg = dns.message.from_wire(resp.content)
    except (httpx.HTTPError, dns.exception.DNSException, ValueError) as exc:
        meta["status"] = "timeout" if isinstance(exc, httpx.TimeoutException) else "error"
        meta["error"] = f"DoH: {exc}"
        return [], meta
    rcode = msg.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        meta["status"] = "nxdomain"
        return [], meta
    if rcode != dns.rcode.NOERROR:
        meta["status"] = "servfail"
        meta["error"] = f"DoH: {dns.rcode.to_text(rcode)}"
        return [], meta
    want = dns.rdatatype.from_text(rtype)
    sets = [rr for rr in msg.answer if rr.rdtype == want]
    if not sets:
        meta["status"] = "noanswer"
        return [], meta
    meta["ttl"] = sets[0].ttl
    meta["canonical"] = sets[0].name.to_text(omit_final_dot=True)
    return [r for rr in sets for r in rr], meta


def _resolve_classic(resolver: dns.resolver.Resolver, name: str, rtype: str) -> tuple[list[Any], dict]:
    meta: dict[str, Any] = {"name": name, "type": rtype, "status": "ok", "ttl": None, "error": None}
    try:
        ans = resolver.resolve(dns.name.from_text(name), rtype, search=False)
        meta["ttl"] = ans.rrset.ttl if ans.rrset is not None else None
        meta["canonical"] = ans.canonical_name.to_text(omit_final_dot=True)
        return list(ans), meta
    except dns.resolver.NXDOMAIN:
        meta["status"] = "nxdomain"
    except dns.resolver.NoAnswer:
        meta["status"] = "noanswer"
    except dns.resolver.NoNameservers as exc:
        meta["status"] = "servfail"
        meta["error"] = str(exc)
    except dns.exception.Timeout:
        meta["status"] = "timeout"
        meta["error"] = "DNS query timed out"
    except (dns.exception.DNSException, ValueError) as exc:
        meta["status"] = "error"
        meta["error"] = str(exc)
    return [], meta


def txt(resolver, name: str, fallback: bool = True) -> tuple[list[str], dict]:
    rdata, meta = resolve(resolver, name, "TXT", fallback)
    return [b"".join(r.strings).decode("utf-8", "replace") for r in rdata], meta


def addresses(resolver, host: str) -> list[str]:
    out: list[str] = []
    for rtype in ("A", "AAAA"):
        rdata, _ = resolve(resolver, host, rtype)
        out.extend(r.address for r in rdata)
    return out


def ptr(resolver, ip: str) -> list[str]:
    try:
        rev = dns.reversename.from_address(ip).to_text()
    except (dns.exception.SyntaxError, ValueError):
        return []
    rdata, _ = resolve(resolver, rev, "PTR")
    return [r.target.to_text(omit_final_dot=True).lower() for r in rdata]


def fcrdns(resolver, ip: str) -> dict:
    """Forward-confirmed reverse DNS: PTR exists and that name resolves back to the IP."""
    names = ptr(resolver, ip)
    confirmed = any(ip in addresses(resolver, n) for n in names[:3])
    return {"ip": ip, "ptr": names, "forward_confirmed": confirmed}


def normalize_domain(value: str) -> str:
    """Accept user-ish input (URLs, email addresses, trailing dots) and return a DNS name."""
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    v = v.split("/")[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    v = v.strip(".<> ")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"'{value}' is not a valid domain name") from exc
    if not _DOMAIN_RE.match(v):
        raise ValueError(f"'{value}' is not a valid domain name")
    return v


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]


def is_private_ip(value: str) -> bool:
    """RFC 1918 / CGNAT / loopback / link-local: addresses that are internal to a network."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in n for n in _INTERNAL_NETS if n.version == ip.version)


def registered_domain(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
