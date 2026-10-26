"""RDAP through the IANA bootstrap registry (RFC 9224).

Lookups go straight to the registry that is authoritative for a TLD or IP block, instead
of through a third-party redirector (rdap.org is run by one volunteer and allows 10
requests per 10 seconds). The bootstrap files are cached for a day, each registry gets at
most a few concurrent requests, and a registry that answers 429 is left alone until its
Retry-After has passed. rdap.org is only used when the bootstrap can't be loaded.

Registry data comes with terms: Verisign forbids high-volume automated querying, and ARIN
doesn't allow its data to be used for marketing. Keep lookups to what a task needs."""
from __future__ import annotations

import ipaddress
import threading
import time

import httpx

from .. import __version__

BOOTSTRAP = {"dns": "https://data.iana.org/rdap/dns.json",
             "ipv4": "https://data.iana.org/rdap/ipv4.json",
             "ipv6": "https://data.iana.org/rdap/ipv6.json"}
FALLBACK = {"dns": "https://rdap.org/domain/{q}", "ipv4": "https://rdap.org/ip/{q}", "ipv6": "https://rdap.org/ip/{q}"}
UA = f"MSPGather/{__version__} (+https://github.com/kcorr/MSPGather)"
BOOTSTRAP_TTL = 86400
PER_HOST = 4

_boot: dict[str, tuple[float, list]] = {}
_backoff: dict[str, float] = {}
_host_sem: dict[str, threading.BoundedSemaphore] = {}
_lock = threading.Lock()


def services(kind: str) -> list | None:
    """The bootstrap service list for 'dns', 'ipv4' or 'ipv6' (cached), or None if unavailable."""
    now = time.monotonic()
    with _lock:
        hit = _boot.get(kind)
        if hit and now - hit[0] < BOOTSTRAP_TTL:
            return hit[1]
    try:
        r = httpx.get(BOOTSTRAP[kind], timeout=8.0, headers={"user-agent": UA}, trust_env=False)
        r.raise_for_status()
        svc = r.json().get("services") or []
    except (httpx.HTTPError, ValueError, AttributeError):
        with _lock:
            stale = _boot.get(kind)
        return stale[1] if stale else None
    with _lock:
        _boot[kind] = (now, svc)
    return svc


def _pick(urls: list[str]) -> str:
    https = [u for u in urls if u.lower().startswith("https://")]
    u = (https or urls)[0]
    return u if u.endswith("/") else u + "/"


def base_url(kind: str, query: str, svc: list | None = None) -> str | None:
    """The registry's RDAP base URL for a domain (kind 'dns') or an IP, from the bootstrap."""
    svc = services(kind) if svc is None else svc
    if not svc:
        return None
    best: tuple | None = None
    if kind == "dns":
        q = query.lower().rstrip(".")
        for entries, urls in svc:
            for e in entries:
                e = str(e).lower()
                if (q == e or q.endswith("." + e)) and urls and (best is None or len(e) > len(best[0])):
                    best = (e, urls)
    else:
        ip = ipaddress.ip_address(query)
        for entries, urls in svc:
            for e in entries:
                try:
                    net = ipaddress.ip_network(str(e), strict=False)
                except ValueError:
                    continue
                if net.version == ip.version and ip in net and urls and (best is None or net.prefixlen > best[0].prefixlen):
                    best = (net, urls)
    return _pick(best[1]) if best else None


def url_for(kind: str, query: str) -> str | None:
    """The record's URL; None when the bootstrap says nobody publishes RDAP for it (e.g. .de)."""
    svc = services(kind)
    if svc is None:
        return FALLBACK[kind].format(q=query)
    base = base_url(kind, query, svc)
    return base + ("domain/" if kind == "dns" else "ip/") + query if base else None


def ip_kind(ip: str) -> str:
    return "ipv6" if ipaddress.ip_address(ip).version == 6 else "ipv4"


def get(kind: str, query: str, timeout: float = 10.0) -> httpx.Response:
    """GET the RDAP record. A registry we were told to back off from gets a synthetic 429."""
    url = url_for(kind, query)
    if url is None:  # no RDAP service for this TLD / block
        return httpx.Response(404, request=httpx.Request("GET", BOOTSTRAP[kind]))
    host = httpx.URL(url).host
    now = time.monotonic()
    with _lock:
        if _backoff.get(host, 0) > now:
            return httpx.Response(429, request=httpx.Request("GET", url))
        sem = _host_sem.setdefault(host, threading.BoundedSemaphore(PER_HOST))
    with sem:
        r = httpx.get(url, timeout=timeout, follow_redirects=True, trust_env=False,
                      headers={"accept": "application/rdap+json, application/json", "user-agent": UA})
    if r.status_code == 429:
        try:
            wait = min(600, max(10, int(r.headers.get("retry-after", "60"))))
        except ValueError:
            wait = 60
        with _lock:
            _backoff[host] = time.monotonic() + wait
    return r
