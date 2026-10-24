"""Microsoft 365 tools:

* Autodiscover Walkthrough: reproduces the order Outlook (and Microsoft's Remote
  Connectivity Analyzer) tries Autodiscover endpoints and tests each one from
  the server: DNS, TCP, TLS certificate, HTTP status and response type.
* Endpoint Connectivity: a read-only PowerShell collector the engineer runs on
  the affected machine, an analyzer for its JSON output (TLS inspection, blocked
  endpoints, slow handshakes, WinHTTP/WinINET proxy mismatch, odd DNS), and a
  server-side quick check of the same endpoints for comparison.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlsplit

from cryptography import x509
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from ..core.dns_utils import is_private_ip, make_resolver, normalize_domain, resolve
from ..core.http import run
from .domain import check_m365_tenant
from .smtp_test import _cert_info

router = APIRouter()

STEP_TIMEOUT = 8.0          # hard budget per Autodiscover step
CONNECT_TIMEOUT = 5.0
MAX_BODY = 64 * 1024        # we only need a snippet to classify the response
UA = "Microsoft Office/16.0 (Windows NT 10.0; MSPGather Autodiscover test)"
ADX_REQUEST = ('<?xml version="1.0" encoding="utf-8"?>'
               '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
               '<Request><EMailAddress>{email}</EMailAddress>'
               '<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
               '</AcceptableResponseSchema></Request></Autodiscover>')
REG_PATH = r"HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover"
REG_POLICY_PATH = r"HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover"
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _f(sev: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "title": title, "detail": detail}


# ===================================================================== network
def _unsafe_reason(ip: str) -> str | None:
    """Why we refuse to connect to this address (outbound safety), or None."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "not an IP address"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast:
        return "multicast"
    if a.is_unspecified:
        return "unspecified (0.0.0.0)"
    if a.is_reserved:
        return "reserved"
    if is_private_ip(ip) or a.is_private or (a.version == 4 and a in _CGNAT):
        return "private (internal network)"
    return None


def _resolve_host(res, host: str) -> dict:
    t0 = time.monotonic()
    a, meta = resolve(res, host, "A")
    aaaa, meta6 = resolve(res, host, "AAAA")
    addrs = [r.address for r in a] + [r.address for r in aaaa]
    status = "ok" if addrs else (meta["status"] if meta["status"] != "ok" else meta6["status"])
    canonical = meta.get("canonical") or meta6.get("canonical")
    return {"status": status, "addresses": addrs,
            "cname": canonical if canonical and canonical.lower().rstrip(".") != host.lower() else None,
            "ms": round((time.monotonic() - t0) * 1000), "error": meta.get("error")}


def _cert_summary(der: bytes, host: str) -> dict:
    info = _cert_info(der, host)
    cert = x509.load_der_x509_certificate(der)

    def attr(name, oid):
        v = name.get_attributes_for_oid(oid)
        return v[0].value if v else None
    info.update({
        "thumbprint": hashlib.sha1(der).hexdigest().upper(),  # noqa: S324 - matches Windows "Thumbprint"
        "subject_cn": attr(cert.subject, NameOID.COMMON_NAME),
        "issuer_cn": attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_o": attr(cert.issuer, NameOID.ORGANIZATION_NAME),
    })
    return info


def _connect(res, host: str, port: int, deadline: float, out: dict) -> socket.socket | None:
    """DNS + safety check + TCP connect. Fills out[dns|ip|tcp_ms|error|outcome]."""
    dns_r = _resolve_host(res, host)
    out["dns"] = dns_r
    if not dns_r["addresses"]:
        out["outcome"] = "dns_" + (dns_r["status"] if dns_r["status"] in ("nxdomain", "noanswer", "timeout", "servfail") else "error")
        out["error"] = {"nxdomain": "Name does not exist (NXDOMAIN)", "noanswer": "No A/AAAA record"}.get(dns_r["status"], f"DNS {dns_r['status']}")
        return None
    unsafe = {ip: _unsafe_reason(ip) for ip in dns_r["addresses"]}
    out["unsafe"] = {ip: r for ip, r in unsafe.items() if r}
    safe = [ip for ip, r in unsafe.items() if not r]
    if not safe:
        out["outcome"] = "private"
        out["error"] = "Resolves only to " + ", ".join(f"{ip} ({r})" for ip, r in unsafe.items()) + ". Not tested."
        return None
    ip = next((i for i in safe if ":" not in i), safe[0])  # prefer IPv4
    out["ip"] = ip
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((ip, port), timeout=max(0.5, min(CONNECT_TIMEOUT, deadline - time.monotonic())))
    except (socket.timeout, TimeoutError):
        out["outcome"], out["error"] = "tcp_timeout", f"TCP {port} timed out (no answer, packets dropped)"
        return None
    except ConnectionRefusedError:
        out["outcome"], out["error"] = "tcp_refused", f"TCP {port} refused (nothing listening)"
        return None
    except OSError as exc:
        out["outcome"], out["error"] = "tcp_error", f"TCP {port}: {exc.strerror or exc}"
        return None
    out["tcp_ms"] = round((time.monotonic() - t0) * 1000)
    return sock


def _tls(sock: socket.socket, res, host: str, port: int, deadline: float, out: dict):
    """TLS handshake with full verification; on a certificate error, reconnect
    without verification so we can still show what the server presents."""
    t0 = time.monotonic()
    sock.settimeout(max(0.5, deadline - time.monotonic()))
    trust_error = None
    try:
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    except ssl.SSLCertVerificationError as exc:
        trust_error = exc.verify_message or str(exc)
        sock.close()
        sock = socket.create_connection((out["ip"], port), timeout=max(0.5, min(CONNECT_TIMEOUT, deadline - time.monotonic())))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock.settimeout(max(0.5, deadline - time.monotonic()))
        tls = ctx.wrap_socket(sock, server_hostname=host)
    out["tls_ms"] = round((time.monotonic() - t0) * 1000)
    der = tls.getpeercert(binary_form=True)
    cert = _cert_summary(der, host) if der else None
    out["tls"] = {"version": tls.version(), "cipher": (tls.cipher() or [None])[0], "trusted": trust_error is None,
                  "trust_error": trust_error, "certificate": cert}
    return tls


def _read_http(sock, deadline: float) -> tuple[int, str, dict, bytes]:
    buf = b""
    head_end = -1
    while len(buf) < MAX_BODY:
        sock.settimeout(max(0.2, deadline - time.monotonic()))
        try:
            chunk = sock.recv(16384)
        except (socket.timeout, TimeoutError):
            if head_end >= 0:
                break
            raise
        if not chunk:
            break
        buf += chunk
        if head_end < 0:
            head_end = buf.find(b"\r\n\r\n")
        if head_end >= 0 and len(buf) - head_end > 8192:
            break
    if head_end < 0:
        head_end = buf.find(b"\r\n\r\n")
    if head_end < 0:
        raise ValueError("No HTTP response (not a web server?)")
    lines = buf[:head_end].decode("iso-8859-1").split("\r\n")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)", lines[0])
    if not m:
        raise ValueError(f"Not an HTTP response: {lines[0][:80]}")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower()
            headers[k] = f"{headers[k]}, {v.strip()}" if k in headers else v.strip()
    return int(m.group(1)), m.group(2), headers, buf[head_end + 4:]


_EXCHANGE_HEADERS = ("x-feserver", "x-owa-version", "x-calculatedbetarget", "x-beserver", "x-diaginfo", "x-ms-diagnostics")


def _classify(status: int, headers: dict, body: bytes) -> str:
    ctype = headers.get("content-type", "").lower()
    low = body[:8192].lower()
    if 300 <= status < 400:
        return "redirect"
    if status == 401:
        exch = any(h in headers for h in _EXCHANGE_HEADERS) or "microsoft-iis" in headers.get("server", "").lower() \
            or "microsoft-httpapi" in headers.get("server", "").lower()
        return "auth_exchange" if exch else "auth_other"
    if status == 200 and b"<autodiscover" in low:
        return "autodiscover_xml"
    if status == 200 and ("json" in ctype or low.lstrip().startswith(b"{")):
        return "json"
    if status == 200 and ("html" in ctype or b"<html" in low or b"<!doctype" in low):
        return "html"
    if status == 200:
        return "other_200"
    if status >= 500:
        return "server_error"
    return "rejected"


def _http_step(res, scheme: str, host: str, path: str, method: str = "GET", body: str | None = None,
               timeout: float = STEP_TIMEOUT) -> dict:
    port = 443 if scheme == "https" else 80
    url = f"{scheme}://{host}{path}"
    out: dict = {"url": url, "host": host, "method": method, "dns": None, "ip": None, "tcp_ms": None, "tls_ms": None,
                 "tls": None, "http": None, "outcome": None, "error": None}
    deadline = time.monotonic() + timeout
    t0 = time.monotonic()
    sock = _connect(res, host, port, deadline, out)
    if sock is None:
        out["total_ms"] = round((time.monotonic() - t0) * 1000)
        return out
    try:
        if scheme == "https":
            try:
                sock = _tls(sock, res, host, port, deadline, out)
            except (ssl.SSLError, OSError) as exc:
                out["outcome"] = "tls_timeout" if isinstance(exc, (socket.timeout, TimeoutError)) else "tls_error"
                out["error"] = f"TLS handshake failed: {exc}"
                return out
        data = body.encode() if body else b""
        req = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n"
               + (f"Content-Type: text/xml; charset=utf-8\r\nContent-Length: {len(data)}\r\n" if method == "POST" else "")
               + "\r\n").encode() + data
        sock.settimeout(max(0.5, deadline - time.monotonic()))
        t1 = time.monotonic()
        sock.sendall(req)
        status, reason, headers, rbody = _read_http(sock, deadline)
        kind = _classify(status, headers, rbody)
        out["http"] = {"status": status, "reason": reason, "ms": round((time.monotonic() - t1) * 1000),
                       "server": headers.get("server"), "content_type": headers.get("content-type"),
                       "location": headers.get("location"), "www_authenticate": headers.get("www-authenticate"),
                       "exchange_headers": {h: headers[h][:120] for h in _EXCHANGE_HEADERS + ("request-id", "x-powered-by") if h in headers},
                       "kind": kind, "body_snippet": rbody[:600].decode("utf-8", "replace")}
        out["outcome"] = "http"
    except (socket.timeout, TimeoutError):
        out["outcome"], out["error"] = "http_timeout", "Connected, but no HTTP response before the timeout"
    except (OSError, ValueError) as exc:
        out["outcome"], out["error"] = "http_error", str(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass
        out["total_ms"] = round((time.monotonic() - t0) * 1000)
    return out


# =========================================================== AUTODISCOVER WALK
def _parse_target(target: str) -> tuple[str, str, bool]:
    t = (target or "").strip().strip("<>").strip()
    if not t:
        raise ValueError("Enter an email address or a domain.")
    if len(t) > 320:
        raise ValueError("Input is too long.")
    if "@" in t and "://" not in t:
        local, _, dom = t.rpartition("@")
        if not _EMAIL_RE.match(local):
            raise ValueError(f"'{t}' is not a valid email address.")
        domain = normalize_domain(dom)
        return f"{local}@{domain}", domain, True
    domain = normalize_domain(t)
    return f"mspgather-probe@{domain}", domain, False


def _cert_problem(step: dict) -> str | None:
    """Plain-English certificate problem a user would be prompted about, or None."""
    tls = step.get("tls") or {}
    cert = tls.get("certificate")
    if not cert:
        return None
    names = ", ".join(cert["san"][:4] or [cert.get("subject_cn") or cert["subject"]])
    if cert["expired"]:
        return f"the certificate expired on {cert['not_after'][:10]}"
    if not cert["hostname_match"]:
        return f"the certificate is for {names}, not {step['host']}"
    if not tls.get("trusted"):
        return f"the certificate is not trusted ({tls.get('trust_error')})"
    return None


def _assess_http(step: dict, kind_of_step: str) -> dict:
    """Turn a raw probe into {state, summary, detail}. States:
    answers | fails_fast | slow | cert_prompt | cred_prompt | redirect | private."""
    o = step["outcome"]
    host = step["host"]
    if o in ("dns_nxdomain", "dns_noanswer"):
        return {"state": "fails_fast", "summary": "No DNS record", "detail": "Outlook skips this step instantly. That's fine."}
    if o and o.startswith("dns_"):
        return {"state": "slow", "summary": f"DNS lookup failed ({o[4:]})", "detail": "Outlook waits for DNS here before moving on."}
    if o == "private":
        return {"state": "slow", "summary": "Resolves to an internal IP", "detail":
                f"{step['error']} Off the corporate network (or over VPN with split DNS) Outlook cannot reach it and waits for a timeout here."}
    if o == "tcp_timeout":
        return {"state": "slow", "summary": "Connection times out", "detail":
                f"{host} resolves to {step['ip']} but nothing answers on port {443 if step['url'].startswith('https') else 80}. "
                "Outlook waits here (often 10+ seconds) before trying the next step: slow profile setup."}
    if o in ("tcp_refused", "tcp_error"):
        return {"state": "fails_fast", "summary": "Connection refused", "detail": f"{step['error']}. Outlook moves on immediately. That's fine."}
    if o in ("tls_error", "tls_timeout"):
        return {"state": "fails_fast" if o == "tls_error" else "slow", "summary": "TLS handshake failed", "detail": step["error"]}
    if o in ("http_timeout", "http_error"):
        return {"state": "slow" if o == "http_timeout" else "fails_fast", "summary": "No usable HTTP response", "detail": step["error"]}
    problem = _cert_problem(step) if step["url"].startswith("https") else None
    if problem:
        kind_txt = "Certificate expired" if "expired" in problem else ("Certificate name mismatch" if "not " + host in problem else "Certificate not trusted")
        return {"state": "cert_prompt", "summary": kind_txt, "detail":
                f"{host} answers on HTTPS but {problem}. Outlook shows the user a security warning (\"The name on the security certificate is invalid or does not match the name of the site\") and profile setup stalls."}
    h = step["http"]
    st, kind = h["status"], h["kind"]
    if kind == "auth_exchange":
        return {"state": "answers", "summary": f"HTTP 401: authentication required (Exchange)", "detail":
                "This is a GOOD sign: a real Exchange Autodiscover endpoint answers anonymous requests with 401 and asks for credentials. Outlook signs in here and gets its settings."}
    if kind == "autodiscover_xml":
        return {"state": "answers", "summary": f"HTTP {st}: Autodiscover XML response", "detail": "The endpoint returns Autodiscover XML. Outlook can use it."}
    if kind == "auth_other":
        return {"state": "cred_prompt", "summary": f"HTTP 401 from a non-Exchange server", "detail":
                f"{host} asks for a password but does not look like Exchange (server: {h.get('server') or 'unknown'}). Users get an unexpected credential prompt."}
    if kind == "redirect":
        loc = h.get("location") or "(no Location header)"
        if kind_of_step == "http_redirect":
            if (urlsplit(loc).hostname or "").lower() == host.lower():
                return {"state": "fails_fast", "summary": f"HTTP {st}: plain HTTP→HTTPS upgrade to the same host", "detail":
                        "This is a generic website redirect back to https://" + host + " (the step above), not an Autodiscover redirect. Outlook gains nothing here."}
            if loc.lower().startswith("https://") and "autodiscover" in loc.lower():
                return {"state": "answers", "summary": f"HTTP {st} redirect to {loc}", "detail":
                        "This is how the HTTP redirect method should work. Outlook follows it (it may ask the user once to allow the redirect)."}
            return {"state": "fails_fast", "summary": f"HTTP {st} redirect to {loc}", "detail": "The redirect does not point to an HTTPS Autodiscover URL, so Outlook ignores it."}
        return {"state": "redirect", "summary": f"HTTP {st} redirect to {loc}", "detail":
                "An HTTPS endpoint redirecting elsewhere is unusual for Autodiscover. If the target is the company website, this step won't produce settings and Outlook moves on."}
    if kind == "html":
        return {"state": "fails_fast", "summary": f"HTTP {st}: web page (HTML)", "detail":
                "A website answers instead of Autodiscover. Outlook discards the HTML and moves on. Harmless because the certificate is valid."}
    if kind == "server_error":
        return {"state": "fails_fast", "summary": f"HTTP {st}: server error", "detail": "Server error on the Autodiscover URL. If this is your Exchange server, check its Autodiscover virtual directory and app pool."}
    return {"state": "fails_fast", "summary": f"HTTP {st} {h.get('reason') or ''}".strip(), "detail": "No Autodiscover service at this URL. Outlook moves on."}


def _ms_host(name: str | None) -> bool:
    return bool(name) and bool(re.search(r"(^|\.)(outlook\.com|office365\.com|office\.com|onmicrosoft\.com|microsoft\.com|"
                                          r"outlook\.office365\.com|protection\.outlook\.com)$", name.lower().rstrip(".")))


def _m365_direct(email: str) -> dict:
    """Microsoft 365 answers per mailbox; it may redirect to itself (another
    address/namespace) before answering. Follow those like Outlook does, but
    never to another host (that's the "not in Exchange Online" answer)."""
    res = make_resolver()
    path = f"/autodiscover/autodiscover.json/v1.0/{quote(email, safe='@')}?Protocol=Autodiscoverv1"
    hops = []
    deadline = time.monotonic() + STEP_TIMEOUT
    while True:
        step = _http_step(res, "https", "outlook.office365.com", path, timeout=max(1.0, deadline - time.monotonic()))
        h = step.get("http")
        loc = (h or {}).get("location") or ""
        u = urlsplit(loc)
        if h and 300 <= h["status"] < 400 and (u.hostname or "").lower() == "outlook.office365.com" and len(hops) < 5 \
                and time.monotonic() < deadline - 1:
            hops.append(loc)
            path = u.path + (f"?{u.query}" if u.query else "")
            continue
        break
    step["internal_redirects"] = hops
    step["json"] = None
    h = step.get("http")
    if h and h["kind"] == "json":
        try:
            step["json"] = json.loads(h["body_snippet"])
        except ValueError:
            pass
    return step


def _assess_direct(step: dict, tenant: dict) -> dict:
    h = step.get("http")
    if not h:
        return {"state": "slow", "summary": "Could not reach outlook.office365.com", "detail": step.get("error") or ""}
    url = (step.get("json") or {}).get("Url")
    if h["status"] == 200 and url:
        consumer = "login.live.com" in (tenant.get("auth_url") or "")
        if consumer:
            return {"state": "fails_fast", "summary": "Consumer (Outlook.com / Microsoft account) domain", "detail":
                    f"Microsoft answers with {url}, but this domain belongs to consumer Microsoft accounts, not a Microsoft 365 tenant."}
        if not tenant.get("tenant_id"):
            return {"state": "fails_fast", "summary": f"Generic answer ({url})", "detail":
                    "Microsoft returns its default URL, but the domain is not verified in any Microsoft 365 tenant, so the mailbox is not in Exchange Online."}
        return {"state": "answers", "summary": f"Microsoft 365 hosts this mailbox → {url}", "detail":
                "Outlook for Windows (Microsoft 365 Apps) uses this \"Direct Connect\" answer and skips the steps below."}
    if 300 <= h["status"] < 400:
        loc = h.get("location") or ""
        target = urlsplit(loc).hostname or loc
        return {"state": "fails_fast", "summary": f"Not in Exchange Online: redirects to {target}", "detail":
                f"Microsoft 365 does not host this mailbox and sends Outlook to {target}. Normal for on-premises Exchange, hybrid (mailbox on-prem) or non-Microsoft mail. Outlook continues with the steps below."}
    return {"state": "fails_fast", "summary": f"HTTP {h['status']}", "detail": h.get("body_snippet", "")[:200]}


def _srv_step(res, domain: str) -> dict:
    name = f"_autodiscover._tcp.{domain}"
    rdata, meta = resolve(res, name, "SRV")
    recs = [{"priority": r.priority, "weight": r.weight, "port": r.port, "target": r.target.to_text(omit_final_dot=True)}
            for r in sorted(rdata, key=lambda r: (r.priority, -r.weight))]
    step: dict = {"name": name, "status": meta["status"], "records": recs}
    if not recs:
        step["assess"] = {"state": "fails_fast", "summary": "No SRV record", "detail": "Outlook skips this step. Fine; SRV is a last resort."}
        return step
    top = recs[0]
    sub: dict = {"url": f"https://{top['target']}", "host": top["target"], "ip": None}
    ok = _connect(res, top["target"], top["port"] or 443, time.monotonic() + 5, sub)
    if ok:
        ok.close()
        step["assess"] = {"state": "answers", "summary": f"→ {top['target']}:{top['port']}", "detail":
                          "Outlook uses this target as a last resort (after asking the user to allow the redirect)."}
    else:
        step["assess"] = {"state": "fails_fast", "summary": f"→ {top['target']}:{top['port']} (unreachable)", "detail": sub.get("error") or ""}
    return step


def _dns_step(res, domain: str) -> dict:
    host = f"autodiscover.{domain}"
    cname, meta = resolve(res, host, "CNAME")
    target = cname[0].target.to_text(omit_final_dot=True).lower() if cname else None
    a = _resolve_host(res, host)
    out = {"host": host, "cname": target, "addresses": a["addresses"], "status": a["status"] if not target else "ok"}
    if target == "autodiscover.outlook.com":
        out["meaning"], out["platform"] = "CNAME to autodiscover.outlook.com: Microsoft 365 (the documented value).", "m365"
    elif target and _ms_host(target):
        out["meaning"], out["platform"] = f"CNAME to {target}: a Microsoft 365 host, but not the documented autodiscover.outlook.com.", "m365_nonstandard"
    elif target:
        out["meaning"], out["platform"] = f"CNAME to {target}: a non-Microsoft host (on-premises Exchange, hosted Exchange or another mail platform).", "other"
    elif a["addresses"]:
        out["meaning"], out["platform"] = f"A record ({', '.join(a['addresses'][:3])}): usually an on-premises or hosted Exchange server.", "a_record"
    else:
        out["meaning"], out["platform"] = "No autodiscover record.", "none"
    return out


# MX suffixes of mail platforms that are clearly not Exchange: Outlook adds those accounts without Exchange Autodiscover.
_NON_EXCHANGE_MX = [
    (("google.com", "googlemail.com"), "Google Workspace / Gmail"),
    (("zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zoho.jp", "zohomail.com"), "Zoho Mail"),
    (("messagingengine.com",), "Fastmail"),
    (("protonmail.ch",), "Proton Mail"),
    (("mail.icloud.com",), "iCloud Mail"),
    (("yahoodns.net",), "Yahoo Mail"),
    (("secureserver.net",), "GoDaddy email"),
    (("titan.email",), "Titan Mail"),
]


def _non_exchange_platform(mx: list[str]) -> str | None:
    """Name of the non-Exchange platform when every MX belongs to one, else None."""
    hosts = [m.strip(".").lower() for m in mx if m and m != "."]
    if not hosts:
        return None
    for suffixes, name in _NON_EXCHANGE_MX:
        if all(any(h == s or h.endswith("." + s) for s in suffixes) for h in hosts):
            return name
    return None


def autodiscover_walk(target: str) -> dict:
    email, domain, real_email = _parse_target(target)
    res = make_resolver()
    adx = ADX_REQUEST.format(email=email)
    with ThreadPoolExecutor(max_workers=8) as pool:
        j = {
            "direct": pool.submit(_m365_direct, email),
            "root": pool.submit(_http_step, res, "https", domain, "/autodiscover/autodiscover.xml", "POST", adx),
            "sub": pool.submit(_http_step, res, "https", f"autodiscover.{domain}", "/autodiscover/autodiscover.xml", "POST", adx),
            "redir": pool.submit(_http_step, res, "http", f"autodiscover.{domain}", "/autodiscover/autodiscover.xml", "GET"),
            "srv": pool.submit(_srv_step, res, domain),
            "dns": pool.submit(_dns_step, res, domain),
            "tenant": pool.submit(check_m365_tenant, domain),
            "root_dns": pool.submit(resolve, res, domain, "SOA"),
            "mx": pool.submit(resolve, res, domain, "MX"),
        }
        r = {k: v.result() for k, v in j.items()}
    tenant, dns_info = r["tenant"], r["dns"]
    soa, soa_meta = r["root_dns"]
    mx = [m.exchange.to_text(omit_final_dot=True).lower() for m in r["mx"][0]]
    no_mail = not mx or all(m in ("", ".") for m in mx)

    steps = [
        {"id": "direct", "label": "Microsoft 365 Direct Connect", "target": "https://outlook.office365.com/autodiscover/autodiscover.json",
         "probe": r["direct"], "assess": _assess_direct(r["direct"], tenant), "reg": "ExcludeExplicitO365Endpoint"},
        {"id": "root", "label": "Root domain (HTTPS)", "target": f"https://{domain}/autodiscover/autodiscover.xml",
         "probe": r["root"], "assess": _assess_http(r["root"], "https"), "reg": "ExcludeHttpsRootDomain"},
        {"id": "sub", "label": "autodiscover subdomain (HTTPS)", "target": f"https://autodiscover.{domain}/autodiscover/autodiscover.xml",
         "probe": r["sub"], "assess": _assess_http(r["sub"], "https"), "reg": "ExcludeHttpsAutoDiscoverDomain"},
        {"id": "redir", "label": "HTTP redirect method", "target": f"http://autodiscover.{domain}/autodiscover/autodiscover.xml",
         "probe": r["redir"], "assess": _assess_http(r["redir"], "http_redirect"), "reg": "ExcludeHttpRedirect"},
        {"id": "srv", "label": "SRV record", "target": f"_autodiscover._tcp.{domain}",
         "probe": r["srv"], "assess": r["srv"]["assess"], "reg": "ExcludeSrvRecord"},
    ]
    # A Microsoft 365 front door presenting its own certificate for a customer name on
    # autodiscover.<domain> is normal: Outlook falls through to the HTTP redirect, which
    # Microsoft answers. Don't call that a problem.
    sub_step = steps[2]
    if dns_info["platform"] in ("m365", "m365_nonstandard") and sub_step["assess"]["state"] in ("cert_prompt", "fails_fast", "slow")             and sub_step["probe"]["outcome"] in ("tcp_refused", "tcp_error", "tcp_timeout", "http", "tls_error"):
        sub_step["assess"] = {"state": "fails_fast", "summary": "Microsoft 365 does not answer HTTPS here (expected)", "detail":
                              f"autodiscover.{domain} is a CNAME to Microsoft 365, which does not serve HTTPS for customer names on this host "
                              f"({sub_step['probe'].get('error') or 'Microsoft certificate'}). Outlook moves on to the HTTP redirect step, which Microsoft answers. Expected behaviour."}

    findings: list[dict] = []
    steps_out = []
    for s in steps:
        steps_out.append({k: s[k] for k in ("id", "label", "target", "assess", "reg")} | {"probe": s["probe"]})

    exists = soa_meta["status"] != "nxdomain"
    cloud = steps[0]["assess"]["state"] == "answers"
    fallback = steps[1:]
    first_ok = next((s for s in fallback if s["assess"]["state"] == "answers"), None)
    first_ok_i = fallback.index(first_ok) if first_ok else len(fallback)
    blocking = [s for s in fallback[:first_ok_i] if s["assess"]["state"] in ("cert_prompt", "cred_prompt", "slow")]
    later_bad = [s for s in fallback[first_ok_i + 1:] if s["assess"]["state"] in ("cert_prompt", "cred_prompt")]
    plat = dns_info["platform"]
    # Only when nothing answers: if the provider does publish Autodiscover (Fastmail does), the normal verdict applies.
    non_exchange = None if cloud or first_ok else _non_exchange_platform(mx)
    on_prem_exchange =(sub_step["assess"]["state"] == "answers" and plat in ("a_record", "other"))

    def problem_text(s: dict) -> str:
        st = s["assess"]["state"]
        u = s["target"].split("/autodiscover/")[0]
        if st == "cert_prompt":
            why = _cert_problem(s["probe"]) or "the certificate is invalid"
            return f"Outlook will hit {u} and get a certificate error ({why}). Users see certificate prompts and slow setup."
        if st == "cred_prompt":
            return f"Outlook will hit {u}, a non-Exchange server that asks for a password. Users get unexpected credential prompts."
        return f"Outlook waits for {u} to time out before moving on. Profile setup and Autodiscover refreshes are slow."

    # ------------------------------------------------------------ verdict
    if not exists:
        sev, title = "critical", f"{domain} does not exist in public DNS (NXDOMAIN). Check the spelling of the email address."
        sub = "No Autodiscover endpoint can exist for a domain that doesn't resolve."
    elif cloud:
        if blocking or later_bad:
            s = (blocking or later_bad)[0]
            sev = "warning"
            title = f"Microsoft 365 answers for {email if real_email else domain}, but " + problem_text(s)[0].lower() + problem_text(s)[1:]
            sub = ("Outlook for Windows normally uses Direct Connect and skips this, but Outlook for Mac, mobile apps, older Outlook "
                   "and any client with Direct Connect disabled walk the classic order and hit it.")
        elif plat not in ("m365", "m365_nonstandard"):
            sev = "warning"
            title = (f"Microsoft 365 hosts {email if real_email else domain}, but autodiscover.{domain} "
                     + ("does not exist" if plat == "none" else "points somewhere else") + ". Only Outlook for Windows will find the mailbox reliably.")
            sub = "Outlook for Mac, mobile apps and third-party clients need autodiscover.<domain> → autodiscover.outlook.com."
        else:
            sev, title = "ok", f"Autodiscover is healthy: Microsoft 365 answers for {email if real_email else domain} and autodiscover.{domain} points to Microsoft 365."
            sub = "Outlook will find the mailbox quickly with no prompts."
    elif non_exchange:
        sev = "info"
        title = (f"Not an Exchange/Microsoft 365 mailbox: {domain} mail is hosted by {non_exchange}. Outlook adds these accounts with its built-in "
                 f"{'Google' if non_exchange.startswith('Google') else 'IMAP'} setup, not Autodiscover.")
        sub = (f"MX: {', '.join(mx[:2])}. Microsoft 365 doesn't host this address, and no Exchange Autodiscover is expected. "
               + ("Add it in Outlook as a Google account (sign in with Google)." if non_exchange.startswith("Google")
                  else f"Use {non_exchange}'s IMAP/SMTP settings if Outlook can't detect them."))
    else:
        if blocking and first_ok:
            sev, title = "critical", problem_text(blocking[0])
            sub = f"After that, Outlook finds the mailbox via {first_ok['label'].lower()}."
        elif blocking and not no_mail:
            sev = "critical"
            title = f"No Autodiscover endpoint answers for {domain}. Outlook cannot set up the profile automatically."
            sub = "On the way: " + problem_text(blocking[0])
        elif not first_ok and no_mail:
            sev = "info"
            title = f"{domain} receives no email ({'null MX' if mx else 'no MX record'}), so there is no Autodiscover to find."
            sub = "Check the email address: is this the right domain?"
        elif not first_ok:
            sev = "critical"
            title = f"No Autodiscover endpoint answers for {domain}. Outlook cannot find the mailbox server automatically."
            sub = steps[0]["assess"]["summary"] + ". Every fallback step fails."
        else:
            sev = "ok" if not later_bad else "warning"
            title = f"Autodiscover works: Outlook finds the mailbox via {first_ok['label'].lower()} ({urlsplit(first_ok['target']).hostname or first_ok['target']})."
            sub = steps[0]["assess"]["summary"] + "."

    # ------------------------------------------------------------ findings
    a0 = steps[0]["assess"]
    findings.append(_f("ok" if cloud else "info", f"Microsoft 365 Direct Connect: {a0['summary']}", a0["detail"]))
    for s in fallback:
        st = s["assess"]["state"]
        sev_f = {"cert_prompt": "critical", "cred_prompt": "critical", "slow": "warning", "answers": "ok"}.get(st)
        if sev_f in ("critical", "warning") and cloud:
            sev_f = "warning"
        elif sev_f in ("critical", "warning") and non_exchange:
            sev_f = "info"  # Outlook doesn't rely on Exchange Autodiscover for these accounts
        if sev_f:
            findings.append(_f(sev_f, f"{s['label']}: {s['assess']['summary']}", s["assess"]["detail"]))
    if plat == "m365":
        findings.append(_f("ok", f"autodiscover.{domain} is a CNAME to autodiscover.outlook.com", "The documented Microsoft 365 record."))
    elif plat == "m365_nonstandard":
        findings.append(_f("info", dns_info["meaning"], "Microsoft documents autodiscover.outlook.com as the CNAME target. Change it if clients misbehave."))
    elif cloud and plat == "a_record":
        findings.append(_f("warning", f"autodiscover.{domain} is an A record ({', '.join(dns_info['addresses'][:3])}) but the mailbox is in Microsoft 365",
                           "Likely a leftover from an on-premises Exchange server. Replace it with a CNAME to autodiscover.outlook.com, unless you still run Exchange hybrid and intentionally point Autodiscover on-prem."))
    elif cloud and plat == "other":
        findings.append(_f("warning", f"autodiscover.{domain} points to {dns_info['cname']}, not Microsoft 365",
                           "Expected only in Exchange hybrid. For cloud-only tenants, change it to a CNAME to autodiscover.outlook.com."))
    elif cloud and plat == "none":
        findings.append(_f("warning", f"No autodiscover.{domain} record", "Create a CNAME autodiscover → autodiscover.outlook.com."))
    if cloud and on_prem_exchange and real_email:
        findings.append(_f("warning", "Microsoft 365 claims this mailbox, but autodiscover DNS points to an on-premises Exchange server",
                           "If this user's mailbox is really on-premises (hybrid), Outlook builds a cloud profile against an empty Exchange Online mailbox. "
                           "Usually caused by an Exchange Online licence on an on-prem user. Fix the licence, or set ExcludeExplicitO365Endpoint=1 on affected clients."))
    if not real_email and exists:
        findings.append(_f("info", f"Tested with a placeholder address ({email})",
                           "Enter a real mailbox address to see exactly how Microsoft 365 answers for that user (hybrid tenants answer per mailbox)."))
    for s in fallback + steps[:1]:
        cert = ((s["probe"].get("tls") or {}) if isinstance(s["probe"], dict) else {}).get("certificate")
        if cert and s["assess"]["state"] == "answers" and not cert["expired"] and cert["days_left"] < 30:
            findings.append(_f("warning", f"{s['label']}: certificate expires in {cert['days_left']} days", cert["not_after"][:10]))

    # ------------------------------------------------------------ fixes
    steps_fix: list[dict] = []
    root_bad = steps[1]["assess"]["state"] in ("cert_prompt", "cred_prompt", "slow")
    if root_bad:
        slow_root = steps[1]["assess"]["state"] == "slow"
        steps_fix.append({"title": f"Make Outlook skip https://{domain}" if slow_root else f"Stop https://{domain} from answering Autodiscover", "detail":
                          (f"Port 443 on {domain} silently drops connections, so Outlook waits for a timeout. Ask whoever runs that IP to reject (or serve a valid certificate) instead of dropping. "
                           if slow_root else f"Best fix: ask whoever hosts the website to return 404 for /autodiscover/ with a valid certificate for {domain}. ")
                          + 
                          "If that's not possible, tell Outlook to skip the root domain with the ExcludeHttpsRootDomain registry value "
                          "(per user, or push it with Group Policy Preferences / Intune). Outlook 2016, 2019, 2021 and Microsoft 365 Apps all use the 16.0 key.",
                          "commands": [f'$k = "{REG_PATH}"\nif (-not (Test-Path $k)) {{ New-Item -Path $k | Out-Null }}\n'
                                       'New-ItemProperty -Path $k -Name ExcludeHttpsRootDomain -Value 1 -PropertyType DWord -Force | Out-Null']})
    if cloud and plat in ("none", "a_record", "other") and not on_prem_exchange:
        steps_fix.append({"title": f"Point autodiscover.{domain} to Microsoft 365", "detail":
                          "In the public DNS zone: CNAME  autodiscover  →  autodiscover.outlook.com  (TTL 3600). Delete any A record with the same name first. Then verify:",
                          "commands": [f"Resolve-DnsName autodiscover.{domain} -Type CNAME -Server 1.1.1.1"]})
    if cloud and plat in ("a_record", "other"):
        steps_fix.append({"title": "Remove stale on-premises Autodiscover (SCP) for domain-joined PCs", "detail":
                          "If an old Exchange server is still in Active Directory, domain-joined Outlook clients query its Service Connection Point (SCP) "
                          "before anything else and can get certificate prompts or an on-prem profile. List SCP records, then either clear them on the Exchange server "
                          "or set ExcludeScpLookup=1 on clients.",
                          "commands": ['$cfg = (Get-ADRootDSE).configurationNamingContext\n'
                                       'Get-ADObject -SearchBase $cfg -LDAPFilter "(&(objectClass=serviceConnectionPoint)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596))" -Properties serviceBindingInformation | Select-Object DistinguishedName, serviceBindingInformation',
                                       "# On the Exchange server (Exchange Management Shell), only if it no longer serves mailboxes:\n"
                                       "Get-ClientAccessService | Set-ClientAccessService -AutoDiscoverServiceInternalUri $null",
                                       f'$k = "{REG_PATH}"\nif (-not (Test-Path $k)) {{ New-Item -Path $k | Out-Null }}\n'
                                       'New-ItemProperty -Path $k -Name ExcludeScpLookup -Value 1 -PropertyType DWord -Force | Out-Null']})
    if cloud and on_prem_exchange and real_email:
        steps_fix.append({"title": "If the mailbox is on-premises: stop Outlook using Microsoft 365 Direct Connect", "detail":
                          "First remove the Exchange Online licence / duplicate cloud mailbox if one was created by mistake. As a client-side workaround:",
                          "commands": [f'$k = "{REG_PATH}"\nif (-not (Test-Path $k)) {{ New-Item -Path $k | Out-Null }}\n'
                                       'New-ItemProperty -Path $k -Name ExcludeExplicitO365Endpoint -Value 1 -PropertyType DWord -Force | Out-Null']})
    if not cloud and not first_ok and exists and not no_mail and not non_exchange:
        steps_fix.append({"title": "Publish an Autodiscover endpoint", "detail":
                          "Microsoft 365: CNAME autodiscover → autodiscover.outlook.com. On-premises Exchange: an A/CNAME record for autodiscover.<domain> to the Exchange "
                          "server with a certificate that includes autodiscover.<domain>. Other platforms (hosted Exchange, Google, IMAP): follow the provider's guidance."})
    if non_exchange and exists:
        steps_fix.append({"title": f"Add the account in Outlook as {'a Google' if non_exchange.startswith('Google') else 'an IMAP'} account", "detail":
                          ("New Outlook and Outlook for Windows (Microsoft 365 Apps) detect Gmail / Google Workspace addresses and open Google's sign-in. "
                           "If Outlook asks for a password instead, choose the Google option on the account type screen."
                           if non_exchange.startswith("Google") else
                           f"Choose IMAP when Outlook asks for the account type and enter {non_exchange}'s IMAP and SMTP server settings from the provider's help pages.")})
    elif (steps_fix or sev in ("critical", "warning")) and exists and not no_mail:
        steps_fix.append({"title": "Confirm from the user's PC", "detail":
                          "Hold Ctrl, right-click the Outlook icon in the system tray → Test E-mail AutoConfiguration (untick Guessmart). The Log tab shows each URL Outlook tried. "
                          "Also check for existing Exclude* / PreferLocalXML values that change the order:",
                          "commands": [f'Get-ItemProperty "{REG_PATH}", "{REG_POLICY_PATH}" -ErrorAction SilentlyContinue | Format-List Exclude*, Prefer*']})

    return {
        "input": target, "email": email, "domain": domain, "real_email": real_email, "domain_exists": exists,
        "severity": sev, "headline": title, "subline": sub,
        "in_m365": cloud, "tenant": tenant, "mx": mx, "autodiscover_dns": dns_info,
        "steps": steps_out, "findings": findings, "fixes": steps_fix,
        "order_note": ("Outlook's order (Microsoft 365 Apps): 0) SCP lookup in Active Directory (domain-joined PCs only, not testable from here) "
                       "1) Microsoft 365 Direct Connect 2) https://<domain> 3) https://autodiscover.<domain> 4) HTTP redirect 5) SRV record. "
                       "Outlook stops at the first step that answers. Each step can be skipped with the registry value shown."),
    }


# =================================================== ENDPOINT CONNECTIVITY (M365)
M365_ENDPOINTS = [
    ("login.microsoftonline.com", "Entra ID sign-in"),
    ("device.login.microsoftonline.com", "Device sign-in / PRT"),
    ("aadcdn.msftauth.net", "Sign-in page content"),
    ("enterpriseregistration.windows.net", "Device registration (Entra join)"),
    ("outlook.office365.com", "Exchange Online"),
    ("outlook.office.com", "Outlook on the web"),
    ("autodiscover-s.outlook.com", "Autodiscover"),
    ("graph.microsoft.com", "Microsoft Graph"),
    ("teams.microsoft.com", "Teams"),
]
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def _norm_tenant(tenant: str | None) -> str | None:
    t = (tenant or "").strip().lower()
    if not t:
        return None
    t = re.sub(r"^https?://", "", t).split("/")[0]
    t = re.sub(r"(-my|-admin)?\.sharepoint\.com$", "", t)
    t = re.sub(r"\.onmicrosoft\.com$", "", t)
    if not _TENANT_RE.match(t):
        raise ValueError("Tenant name should be the part before .sharepoint.com / .onmicrosoft.com, e.g. 'contoso'.")
    return t


def endpoint_list(tenant: str | None) -> list[tuple[str, str]]:
    eps = list(M365_ENDPOINTS)
    if tenant:
        eps.append((f"{tenant}.sharepoint.com", "SharePoint / OneDrive"))
    return eps


# Product signatures in the issuer of an intercepted certificate. Each pattern
# matches the vendor's default CA names / organisation. Order matters.
INSPECTION_VENDORS: list[tuple[str, str]] = [
    (r"fortinet|fortigate|\bFGT|fortiproxy", "Fortinet FortiGate"),
    (r"palo alto|paloalto|pan-os", "Palo Alto Networks"),
    (r"zscaler", "Zscaler"),
    (r"netskope", "Netskope"),
    (r"cisco umbrella|opendns", "Cisco Umbrella"),
    (r"\bcisco\b", "Cisco (Firepower / Secure Web Appliance)"),
    (r"sophos", "Sophos"),
    (r"watchguard|fireware", "WatchGuard"),
    (r"sonicwall|dpi-ssl", "SonicWall"),
    (r"check ?point", "Check Point"),
    (r"forcepoint|websense", "Forcepoint"),
    (r"barracuda", "Barracuda"),
    (r"blue ?coat|proxysg", "Broadcom / Blue Coat ProxySG"),
    (r"iboss", "iboss"),
    (r"cloudflare", "Cloudflare Zero Trust Gateway"),
    (r"menlo", "Menlo Security"),
    (r"lightspeed", "Lightspeed Systems"),
    (r"securly", "Securly"),
    (r"untangle", "Untangle / Arista Edge"),
    (r"squid", "Squid proxy"),
    (r"kaspersky", "Kaspersky (antivirus HTTPS scanning)"),
    (r"\beset\b", "ESET (antivirus SSL filter)"),
    (r"avast|\bavg\b", "Avast / AVG (antivirus Web Shield)"),
    (r"bitdefender", "Bitdefender (antivirus HTTPS scanning)"),
    (r"norton", "Norton (antivirus HTTPS scanning)"),
    (r"trend ?micro", "Trend Micro"),
    (r"mcafee|skyhigh", "McAfee / Skyhigh"),
    (r"fiddler", "Fiddler (debugging proxy)"),
    (r"mitmproxy|charles proxy|burp", "A debugging proxy (mitmproxy / Charles / Burp)"),
]
# Organisations whose CAs legitimately issue certificates for Microsoft 365 hosts.
EXPECTED_ISSUER_ORGS = re.compile(r"microsoft|digicert|globalsign|sectigo|entrust|geotrust|baltimore|cybertrust|verisign|thawte|"
                                  r"comodo|go ?daddy|amazon|let'?s encrypt|google trust|identrust|usertrust|isrg", re.I)


def _dn_attr(dn: str, key: str) -> str | None:
    m = re.search(rf"(?:^|,)\s*{key}\s*=\s*(\"[^\"]*\"|[^,]*)", dn or "", re.I)
    return m.group(1).strip().strip('"') if m else None


def inspection_vendor(issuer: str | None, chain: list[str] | None = None) -> tuple[bool, str | None]:
    """(intercepted?, product name or description). issuer is a DN string in
    .NET ("CN=x, O=y") or RFC 4514 ("CN=x,O=y") form."""
    if not issuer:
        return False, None
    text = " | ".join([issuer] + list(chain or []))
    for pat, name in INSPECTION_VENDORS:
        if re.search(pat, text, re.I):
            return True, name
    org = _dn_attr(issuer, "O") or ""
    cn = _dn_attr(issuer, "CN") or issuer
    if EXPECTED_ISSUER_ORGS.search(org) or EXPECTED_ISSUER_ORGS.search(cn):
        return False, None
    return True, f"a private or unknown CA ({cn}{', ' + org if org else ''})"


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _num(v):
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


def _ip_issue(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.is_loopback or a.is_unspecified:
        return "sinkhole"
    if a.version == 4 and a in _CGNAT:
        return "cgnat"
    if is_private_ip(ip) or a.is_link_local:  # RFC 1918 etc. (not ipaddress.is_private: that includes documentation ranges)
        return "private"
    return None


def analyze_endpoints(eps: list[dict], where: str, proxy_used: bool = False) -> dict:
    """Shared per-endpoint analysis for the collector JSON and the server check.
    Each endpoint: {host, purpose, dns{ok,addresses,cnames,ms,error}, tcp{ok,ms,ip,error},
    tls{ok,ms,protocol,subject,issuer,thumbprint,chain,error}, proxied{used,proxy,status,ms,issuer,error}}."""
    rows, inspected, blocked, slow, dns_bad, ok_count = [], [], [], [], [], 0
    for e in eps:
        host = str(e.get("host") or "?")
        if e.get("skipped"):
            rows.append({"host": host, "purpose": e.get("purpose"), "addresses": [], "cnames": [], "dns_ms": None, "tcp_ms": None,
                         "tls_ms": None, "ip": None, "protocol": None, "issuer": None, "subject": None, "thumbprint": None,
                         "chain": [], "proxied": None, "problems": [f"Not tested: {e.get('skipped')}"], "status": "skip", "vendor": None})
            continue
        dns_ = e.get("dns") or {}
        tcp = e.get("tcp") or {}
        tls = e.get("tls") or {}
        px = e.get("proxied") or {}
        addrs = [str(a) for a in _as_list(dns_.get("addresses"))]
        row = {"host": host, "purpose": e.get("purpose"), "addresses": addrs, "cnames": [str(c) for c in _as_list(dns_.get("cnames"))],
               "dns_ms": _num(dns_.get("ms")), "tcp_ms": _num(tcp.get("ms")), "tls_ms": _num(tls.get("ms")),
               "ip": tcp.get("ip"), "protocol": tls.get("protocol"), "issuer": tls.get("issuer"), "subject": tls.get("subject"),
               "thumbprint": tls.get("thumbprint"), "chain": [str(c) for c in _as_list(tls.get("chain"))],
               "proxied": px if px.get("used") else None, "problems": [], "status": "ok", "vendor": None}
        ip_issues = {a: _ip_issue(a) for a in addrs if _ip_issue(a)}
        if not dns_.get("ok") and not addrs:
            row["problems"].append("DNS failed" + (f": {dns_.get('error')}" if dns_.get("error") else ""))
            if not (px.get("used") and px.get("status")):
                dns_bad.append((host, "does not resolve", "tenant" if host.endswith(".sharepoint.com") else "fail", dns_.get("error")))
                row["status"] = "warn" if host.endswith(".sharepoint.com") else "bad"
        elif ip_issues:
            kinds = set(ip_issues.values())
            label = "a sinkhole address (0.0.0.0 / 127.x)" if "sinkhole" in kinds else (
                "a CGNAT 100.64.x address" if kinds == {"cgnat"} else "a private IP")
            dns_bad.append((host, f"resolves to {label}: {', '.join(ip_issues)}", "sinkhole" if "sinkhole" in kinds else "private", None))
            row["problems"].append(f"Resolves to {label}")
            row["status"] = "bad" if "sinkhole" in kinds else "warn"
        # TLS inspection: direct handshake, or the certificate seen through the proxy.
        seen = [(tls.get("issuer"), row["chain"], "direct")] + ([(px.get("issuer"), [], "via proxy")] if px.get("used") else [])
        for issuer, chain, path in seen:
            hit, vendor = inspection_vendor(issuer, chain)
            if hit:
                inspected.append({"host": host, "vendor": vendor, "issuer": issuer, "path": path})
                row["vendor"] = vendor
                row["problems"].append("TLS intercepted" + (" (via proxy)" if path != "direct" else ""))
                row["status"] = "bad"
                break
        direct_ok = bool(tcp.get("ok")) and bool(tls.get("ok"))
        proxy_ok = bool(px.get("used")) and px.get("status") not in (None, "", 0) and not px.get("error")
        if addrs and not direct_ok:
            err = tls.get("error") if tcp.get("ok") else tcp.get("error")
            stage = "TLS handshake" if tcp.get("ok") else "TCP 443"
            if proxy_ok or (proxy_used and px.get("used") and not px.get("error")):
                row["problems"].append(f"Direct {stage} failed (works via proxy)")
            else:
                blocked.append({"host": host, "stage": stage, "error": err})
                row["problems"].append(f"{stage} failed: {err or 'no answer'}")
                row["status"] = "bad"
        elif px.get("used") and px.get("error") and not direct_ok:
            blocked.append({"host": host, "stage": "proxy", "error": px.get("error")})
        tls_ms = row["tls_ms"]
        if direct_ok and tls_ms is not None and tls_ms > 500:
            slow.append((host, tls_ms))
            row["problems"].append("Slow handshake")
            if row["status"] == "ok":
                row["status"] = "warn"
        if row["status"] == "ok":
            ok_count += 1
        rows.append(row)

    findings: list[dict] = []
    if inspected:
        by_vendor: dict[str, list[dict]] = {}
        for i in inspected:
            by_vendor.setdefault(i["vendor"], []).append(i)
        for vendor, items in by_vendor.items():
            hosts = [i["host"] for i in items]
            findings.append(_f("critical", f"TLS inspection by {vendor} on {len(hosts)} of {len(rows)} endpoints",
                               f"{', '.join(hosts)} present a certificate issued by \"{_dn_attr(items[0]['issuer'], 'CN') or items[0]['issuer']}\" instead of a Microsoft/DigiCert certificate. "
                               "Decrypting Microsoft 365 traffic breaks token binding, device registration, Teams media and Outlook connectivity, and Microsoft does not support it. "
                               "Exclude Microsoft 365 endpoints from SSL inspection."))
    if blocked:
        findings.append(_f("critical", f"{len(blocked)} endpoint(s) unreachable from {where}",
                           "; ".join(f"{b['host']} ({b['stage']}: {b['error'] or 'no answer'})" for b in blocked)
                           + ". A firewall, web filter or missing route is blocking HTTPS to Microsoft 365."))
    priv = [d for d in dns_bad if d[2] == "private"]
    if len(priv) > 1:
        dns_bad = [d for d in dns_bad if d[2] != "private"] + [
            (f"{len(priv)} endpoints ({', '.join(d[0] for d in priv[:4])}{' …' if len(priv) > 4 else ''})", "resolve to private IPs", "private", None)]
    for host, what, kind, err in dns_bad:
        sev = "critical" if kind in ("sinkhole", "fail") else "warning"
        detail = {"sinkhole": "A DNS filter or hosts-file entry is blocking it.",
                  "private": "Expected only if you use a split-DNS private endpoint, Zscaler Private Access or a VPN that rewrites DNS. Otherwise check the hosts file and DNS forwarders.",
                  "tenant": f"DNS error: {err or 'no answer'}. Most likely the tenant name is wrong (it's the part before .sharepoint.com, see SharePoint admin center). If it is right, DNS for Microsoft 365 is being blocked.",
                  }.get(kind, f"DNS error: {err or 'no answer'}. Check the DNS servers this machine uses (ipconfig /all) and whether a DNS filter blocks Microsoft 365.")
        findings.append(_f(sev, f"{host} {what}", detail))
    if slow:
        findings.append(_f("warning", f"Slow TLS handshakes (> 500 ms) to {len(slow)} endpoint(s)",
                           ", ".join(f"{h} {ms:.0f} ms" for h, ms in slow)
                           + ". Typical is under 150 ms. Causes: TLS inspection, an overloaded proxy/firewall, VPN hairpinning or a far-away Microsoft front door (DNS resolver in another region)."))
    if not findings:
        findings.append(_f("ok", f"All {len(rows)} endpoints reachable with genuine certificates",
                           "DNS, TCP 443 and TLS handshakes succeeded, with certificates from Microsoft's public CAs."))
    return {"rows": rows, "inspected": inspected, "blocked": blocked, "slow": slow, "dns_bad": dns_bad,
            "ok_count": ok_count, "findings": findings}


_VENDOR_FIX = {
    "Fortinet FortiGate": "FortiGate: in the SSL/SSH Inspection profile used by the policy, add Microsoft 365 to 'Exempt from SSL Inspection' "
                          "(the Internet Service Database entries for Microsoft Office 365, or an address group built from the FQDNs below).",
    "Zscaler": "Zscaler: in the Microsoft 365 configuration, enable Microsoft's recommended One Click configuration, which bypasses SSL inspection for Microsoft 365 'Optimize' and 'Allow' traffic.",
    "Palo Alto Networks": "Palo Alto: add a Decryption policy rule with action 'No Decrypt' for Microsoft 365 destinations (an EDL fed from the Microsoft 365 endpoints web service, or the FQDNs below), above the decrypt rule.",
    "Netskope": "Netskope: add the Microsoft 365 domains to an SSL Do Not Decrypt policy / steering bypass.",
    "Sophos": "Sophos Firewall: add an SSL/TLS inspection rule with action 'Don't decrypt' for Microsoft 365 destinations, above the decrypt rule.",
}


def _proxy_analysis(px: dict, rows: list[dict]) -> tuple[list[dict], list[dict], dict]:
    winhttp_raw = str(px.get("winhttp_raw") or "")
    winhttp_direct = px.get("winhttp_direct")
    if winhttp_direct is None:
        winhttp_direct = "direct access" in winhttp_raw.lower() or not winhttp_raw
    winhttp_proxy = px.get("winhttp_proxy") or None
    wi = px.get("wininet") or {}
    wi_static = bool(int(_num(wi.get("proxy_enable")) or 0)) and bool(wi.get("proxy_server"))
    wi_pac = wi.get("autoconfig_url") or None
    wi_auto = bool(wi.get("auto_detect"))
    wininet_on = wi_static or bool(wi_pac)
    effective = str(px.get("system_proxy_for_login") or "")
    effective_proxy = effective if effective and effective.upper() != "DIRECT" and "login.microsoftonline.com" not in effective.lower() else None
    summary = {
        "winhttp": "Direct" if winhttp_direct else f"Proxy {winhttp_proxy or '(set)'}",
        "wininet": ("PAC " + wi_pac) if wi_pac else (f"Proxy {wi.get('proxy_server')}" if wi_static else ("Auto-detect (WPAD)" if wi_auto else "Direct")),
        "effective": effective_proxy or "Direct",
    }
    findings, fixes = [], []
    direct_broken = [r["host"] for r in rows if r["tcp_ms"] is None and r["addresses"]]
    if (wininet_on or effective_proxy) and winhttp_direct:
        broken = bool(direct_broken)
        findings.append(_f("critical" if broken else "warning",
                           "Proxy set for WinINET (user apps) but WinHTTP is direct",
                           f"Outlook, Teams and browsers use the WinINET proxy ({summary['wininet']}), while Windows services that use WinHTTP "
                           "(device registration / Entra join, Windows Update, Office licensing and some background tasks running as SYSTEM) go direct. "
                           + (f"Direct connections fail here ({', '.join(direct_broken[:4])}), so those services cannot reach Microsoft 365."
                              if broken else "Direct connections work from this network, so this only matters if direct access gets blocked (or off this network).")))
        if wi_static:
            fixes.append({"title": "Give WinHTTP the same proxy as WinINET (run as administrator)",
                          "detail": "Copies the user's static proxy into WinHTTP. 'netsh winhttp import' does not copy PAC files; for a PAC set the proxy explicitly.",
                          "commands": ["netsh winhttp import proxy source=ie", "netsh winhttp show proxy"]})
        else:
            fixes.append({"title": "Configure WinHTTP explicitly (run as administrator)",
                          "detail": "WinHTTP cannot use the user's PAC setting. Point it at the proxy the PAC returns for Microsoft 365 (replace proxy.contoso.com:8080 below), or allow those services direct out through the firewall.",
                          "commands": ['netsh winhttp set proxy proxy-server="proxy.contoso.com:8080" bypass-list="<local>;*.contoso.com"', "netsh winhttp show proxy"]})
    elif not winhttp_direct and not wininet_on and not effective_proxy:
        broken = bool(direct_broken)
        findings.append(_f("critical" if broken else "warning",
                           f"WinHTTP uses a proxy ({winhttp_proxy or 'set'}) but WinINET (Outlook/Teams) is direct",
                           "User apps go direct while system services go through the proxy. "
                           + (f"Direct connections fail here ({', '.join(direct_broken[:4])}), so Outlook and Teams cannot connect."
                              if broken else "Direct works from this network, but traffic paths (and inspection) differ between apps.")))
        fixes.append({"title": "Align WinHTTP with the user setting", "detail": "If the proxy is no longer used, reset WinHTTP; otherwise configure the same proxy for users (GPO / Intune).",
                      "commands": ["netsh winhttp reset proxy", "netsh winhttp show proxy"]})
    elif not winhttp_direct and (wininet_on or effective_proxy):
        findings.append(_f("info", "Both WinHTTP and WinINET use a proxy", f"WinHTTP: {winhttp_proxy or 'set'}; WinINET: {summary['wininet']}. Check they point at the same proxy."))
    if wi_auto and not wi_pac and not wi_static:
        wpad = _as_list(px.get("wpad_dns"))
        findings.append(_f("info", "'Automatically detect settings' (WPAD) is on" + (f"; wpad resolves to {', '.join(map(str, wpad))}" if wpad else "; no wpad host found"),
                           "Auto-detect adds a delay on every new network and can silently pick up a proxy. Disable it if you don't use WPAD."))
    env = px.get("env") or {}
    if any(env.get(k) for k in ("http_proxy", "https_proxy")):
        findings.append(_f("info", "HTTP(S)_PROXY environment variables set", f"{env}. Some tools (PowerShell 7, CLIs) use these instead of the Windows proxy."))
    return findings, fixes, summary


def _extract_json(raw: str) -> dict:
    text = (raw or "").lstrip("\ufeff")
    m = re.search(r"BEGIN MSPGATHER M365 NETWORK-+\s*(.*?)\s*-+END MSPGATHER M365 NETWORK", text, re.S)
    blob = m.group(1) if m else text
    start, end = blob.find("{"), blob.rfind("}")
    if start < 0 or end < start:
        raise ValueError("No JSON found. Paste everything between the BEGIN and END lines the script printed.")
    try:
        data = json.loads(blob[start:end + 1])
    except ValueError as exc:
        raise ValueError(f"The pasted JSON is incomplete or damaged ({exc}). Copy the whole block again.") from exc
    if not isinstance(data, dict) or "endpoints" not in data:
        raise ValueError("This JSON is not from the MSPGather Microsoft 365 collector (no 'endpoints').")
    return data


def _inspection_fixes(vendors: list[str]) -> list[dict]:
    steps = [{"title": "Exclude Microsoft 365 from TLS/SSL inspection",
              "detail": "Microsoft's network guidance: send 'Optimize' and 'Allow' category endpoints direct and do not decrypt them. "
                        "The current list is published at https://aka.ms/o365ip (Microsoft 365 URLs and IP address ranges, also as a web service). "
                        + " ".join(_VENDOR_FIX[v] for v in vendors if v in _VENDOR_FIX),
              "commands": ['$id = [guid]::NewGuid()\n'
                           '$eps = Invoke-RestMethod "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$id"\n'
                           "$eps | Where-Object { $_.category -in 'Optimize','Allow' } | ForEach-Object { $_.urls } | Sort-Object -Unique"]}]
    if any("antivirus" in v.lower() for v in vendors):
        steps.append({"title": "Turn off HTTPS scanning in the endpoint antivirus", "detail":
                      "The interception happens on the PC itself (antivirus web protection). Disable HTTPS/SSL scanning or exclude Microsoft 365 domains in its policy."})
    steps.append({"title": "Re-run the collector", "detail": "After the exclusion, the issuer should be a Microsoft or DigiCert CA (e.g. 'Microsoft Azure RSA TLS Issuing CA', 'DigiCert ...')."})
    return steps


def analyze_collector(raw: str) -> dict:
    data = _extract_json(raw)
    eps = [e for e in _as_list(data.get("endpoints")) if isinstance(e, dict)]
    if not eps:
        raise ValueError("The collector output has no endpoint results.")
    px = data.get("proxy") or {}
    machine = str(data.get("computer") or "this machine")
    eff = str(px.get("system_proxy_for_login") or "")
    proxy_used = bool(eff) and eff.upper() != "DIRECT" and "login.microsoftonline.com" not in eff.lower()
    a = analyze_endpoints(eps, machine, proxy_used)
    pfind, pfix, psum = _proxy_analysis(px, a["rows"])
    findings = a["findings"] + pfind
    hosts_file = [str(h) for h in _as_list(data.get("hosts_file"))]
    if hosts_file:
        findings.append(_f("warning", f"Hosts file has {len(hosts_file)} Microsoft-related entr{'y' if len(hosts_file) == 1 else 'ies'}",
                           "; ".join(hosts_file[:5]) + ". Hosts-file overrides pin Microsoft 365 names to fixed IPs that go stale. Remove them (C:\\Windows\\System32\\drivers\\etc\\hosts)."))

    n = len(a["rows"])
    insp = a["inspected"]
    fixes: list[dict] = []
    if insp:
        vendors = list(dict.fromkeys(i["vendor"] for i in insp))
        hosts = [i["host"] for i in insp]
        lead = "login.microsoftonline.com" if "login.microsoftonline.com" in hosts else hosts[0]
        rest = len(hosts) - 1
        sev = "critical"
        title = (f"TLS inspection by {' and '.join(vendors)} is intercepting {lead}"
                 + (f" and {rest} other Microsoft 365 endpoint{'s' if rest > 1 else ''}" if rest else "") + ".")
        sub = "Exclude Microsoft 365 'Optimize' and 'Allow' endpoints from SSL inspection (https://aka.ms/o365ip). Sign-in, device registration, Outlook and Teams break or degrade while traffic is decrypted."
        fixes += _inspection_fixes(vendors)
    elif a["blocked"]:
        hs = [b["host"] for b in a["blocked"]]
        sev = "critical"
        title = f"{machine} cannot reach {len(hs)} Microsoft 365 endpoint{'s' if len(hs) > 1 else ''}: {', '.join(hs[:3])}{' …' if len(hs) > 3 else ''}."
        sub = "HTTPS (TCP 443) to these hosts is blocked or timing out. Allow the Microsoft 365 endpoints (https://aka.ms/o365ip) on the firewall / web filter."
        fixes.append({"title": "Allow Microsoft 365 endpoints outbound on TCP 443", "detail":
                      "Allow at least the 'Optimize' and 'Allow' categories from https://aka.ms/o365ip on the firewall, web filter and any proxy. Then test from the PC:",
                      "commands": [f"Test-NetConnection {hs[0]} -Port 443"]})
    elif any(f["severity"] == "critical" for f in findings):
        top = next(f for f in findings if f["severity"] == "critical")
        sev, title, sub = "critical", top["title"] + ".", top["detail"]
    elif any(f["severity"] == "warning" for f in findings):
        top = next(f for f in findings if f["severity"] == "warning")
        sev, title, sub = "warning", top["title"] + ".", top["detail"]
    else:
        sev = "ok"
        title = f"{machine} reaches all {n} Microsoft 365 endpoints with genuine Microsoft certificates and fast handshakes."
        sub = "No TLS inspection, no blocked endpoints, proxy settings consistent. Look elsewhere (account, licence, client) for the issue."
    if a["slow"] and not insp:
        fixes.append({"title": "Find what slows the handshakes", "detail":
                      "Compare with the server-side check below. If only this site is slow, look at the firewall/proxy CPU, VPN split tunnelling (send Microsoft 365 'Optimize' traffic outside the VPN) and which DNS resolver the PC uses."})
    fixes += pfix
    for host, what, kind, _err in a["dns_bad"]:
        fixes.append({"title": f"Check why {host} {what}", "detail": "Compare the answer from the PC's DNS server with a public resolver:",
                      "commands": [f"Resolve-DnsName {host}\nResolve-DnsName {host} -Server 1.1.1.1"]})
        break
    pub = data.get("public_ip") or {}
    return {
        "severity": sev, "headline": title, "subline": sub, "findings": findings, "fixes": fixes,
        "machine": {"computer": data.get("computer"), "user": data.get("user"), "os": data.get("os"), "ps_version": data.get("ps_version"),
                    "collected_utc": data.get("collected_utc"), "tenant": data.get("tenant"), "duration_s": data.get("duration_s"),
                    "public_ip": pub.get("ip"), "public_ip_source": pub.get("source")},
        "proxy": psum, "proxy_raw": px, "hosts_file": hosts_file,
        "rows": a["rows"], "ok_count": a["ok_count"], "total": n,
    }


def _server_endpoint(res, host: str, purpose: str) -> dict:
    out: dict = {"url": f"https://{host}", "host": host, "ip": None}
    deadline = time.monotonic() + STEP_TIMEOUT
    t0 = time.monotonic()
    e = {"host": host, "purpose": purpose, "dns": {}, "tcp": {}, "tls": {}}
    sock = _connect(res, host, 443, deadline, out)
    d = out.get("dns") or {}
    e["dns"] = {"ok": bool(d.get("addresses")), "addresses": d.get("addresses", []), "cnames": [d["cname"]] if d.get("cname") else [],
                "ms": d.get("ms"), "error": None if d.get("addresses") else out.get("error")}
    if sock is None:
        e["tcp"] = {"ok": False, "ip": out.get("ip"), "error": out.get("error")}
        return e
    e["tcp"] = {"ok": True, "ms": out.get("tcp_ms"), "ip": out.get("ip")}
    try:
        tls = _tls(sock, res, host, 443, deadline, out)
        tls.close()
        c = out["tls"]["certificate"] or {}
        e["tls"] = {"ok": True, "ms": out.get("tls_ms"), "protocol": out["tls"]["version"], "subject": c.get("subject"),
                    "issuer": c.get("issuer"), "thumbprint": c.get("thumbprint"), "not_after": c.get("not_after"),
                    "trusted": out["tls"]["trusted"], "trust_error": out["tls"]["trust_error"], "chain": []}
    except (ssl.SSLError, OSError) as exc:
        e["tls"] = {"ok": False, "error": str(exc)}
    e["total_ms"] = round((time.monotonic() - t0) * 1000)
    return e


def server_check(tenant: str | None) -> dict:
    tenant = _norm_tenant(tenant)
    res = make_resolver()
    eps = endpoint_list(tenant)
    with ThreadPoolExecutor(max_workers=len(eps)) as pool:
        results = list(pool.map(lambda hp: _server_endpoint(res, *hp), eps))
    a = analyze_endpoints(results, "the MSPGather server")
    n = len(a["rows"])
    if a["inspected"]:
        sev, title = "critical", f"The MSPGather server's own network intercepts TLS ({a['inspected'][0]['vendor']}). Its results are not a clean baseline."
    elif a["blocked"]:
        sev, title = "warning", f"The MSPGather server cannot reach {len(a['blocked'])} of {n} endpoints."
    elif a["slow"]:
        sev, title = "info", f"The MSPGather server reaches all {n} endpoints; {len(a['slow'])} handshake(s) are slow from here."
    else:
        sev, title = "ok", f"From the MSPGather server, all {n} Microsoft 365 endpoints answer with genuine certificates."
    return {"severity": sev, "headline": title,
            "subline": "Measured from the MSPGather server, NOT the user's machine. Use it as a baseline: compare issuers and timings with the collector results.",
            "findings": a["findings"], "rows": a["rows"], "ok_count": a["ok_count"], "total": n, "tenant": tenant}


# ------------------------------------------------------------------ collector
COLLECTOR_PS1 = r'''# MSPGather - Microsoft 365 endpoint connectivity collector
# READ-ONLY: changes no settings. Windows PowerShell 5.1+, no modules. Runs < 60 s.
# Run as the affected user (not elevated) so the user's proxy settings are captured.
$Tenant = '__TENANT__'
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
$started = Get-Date
$deadline = $started.AddSeconds(50)
$Endpoints = @(
__ENDPOINTS__
)

# ---------------------------------------------------------------- proxy settings
$px = [ordered]@{}
$wh = ''
try { $wh = (& netsh.exe winhttp show proxy 2>&1 | Out-String).Trim() } catch { $wh = "error: $($_.Exception.Message)" }
$px.winhttp_raw = $wh
$px.winhttp_direct = $null
$px.winhttp_proxy = $null
$px.winhttp_bypass = $null
$px.winhttp_source = 'netsh'
# WinHTTP settings from the registry (language-independent): flags at byte 8, then length-prefixed proxy and bypass strings
try {
  $whv = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name WinHttpSettings -ErrorAction Stop).WinHttpSettings
  $px.winhttp_source = 'registry'
  $plen = [BitConverter]::ToInt32($whv, 12)
  if ($plen -gt 0) {
    $px.winhttp_direct = $false
    $px.winhttp_proxy = [Text.Encoding]::ASCII.GetString($whv, 16, $plen)
    $blen = [BitConverter]::ToInt32($whv, 16 + $plen)
    if ($blen -gt 0) { $px.winhttp_bypass = [Text.Encoding]::ASCII.GetString($whv, 20 + $plen, $blen) }
  } else { $px.winhttp_direct = $true }
} catch { $px.winhttp_direct = $true; $px.winhttp_source = 'registry (no WinHttpSettings value = direct)' }
$isKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$wi = [ordered]@{ proxy_enable = 0; proxy_server = $null; proxy_override = $null; autoconfig_url = $null; auto_detect = $false; flags = $null }
try {
  $p = Get-ItemProperty -Path $isKey -ErrorAction Stop
  if ($null -ne $p.ProxyEnable) { $wi.proxy_enable = [int]$p.ProxyEnable }
  $wi.proxy_server = $p.ProxyServer
  $wi.proxy_override = $p.ProxyOverride
  $wi.autoconfig_url = $p.AutoConfigURL
  $c = Get-ItemProperty -Path "$isKey\Connections" -Name DefaultConnectionSettings -ErrorAction SilentlyContinue
  if ($c -and $c.DefaultConnectionSettings.Length -gt 8) {
    $flags = [int]$c.DefaultConnectionSettings[8]
    $wi.flags = $flags
    $wi.auto_detect = (($flags -band 8) -eq 8)
  }
} catch {}
$px.wininet = $wi
$pol = $null
try { $pol = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop).ProxySettingsPerUser } catch {}
$px.proxy_settings_per_user_policy = $pol
try {
  $u = New-Object System.Uri('https://login.microsoftonline.com/')
  $sp = [System.Net.WebRequest]::GetSystemWebProxy()
  $eff = $sp.GetProxy($u)
  if ($eff.AbsoluteUri -eq $u.AbsoluteUri) { $px.system_proxy_for_login = 'DIRECT' } else { $px.system_proxy_for_login = $eff.AbsoluteUri }
} catch { $px.system_proxy_for_login = "error: $($_.Exception.Message)" }
$px.env = [ordered]@{ http_proxy = $env:HTTP_PROXY; https_proxy = $env:HTTPS_PROXY; no_proxy = $env:NO_PROXY }
$wpad = @()
try { $wpad = @([System.Net.Dns]::GetHostAddresses('wpad') | ForEach-Object { $_.IPAddressToString }) } catch {}
$px.wpad_dns = $wpad
$useProxy = ($px.system_proxy_for_login -ne 'DIRECT' -and $px.system_proxy_for_login -notlike 'error*')

# ---------------------------------------------------------------- hosts file
$hostsLines = @()
try {
  $hostsLines = @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction Stop | Where-Object {
    $_ -notmatch '^\s*#' -and $_ -match '(microsoft|office|outlook|sharepoint|msft|live\.com|windows\.net|skype|lync|teams|azure)' } | ForEach-Object { $_.Trim() })
} catch {}

# ---------------------------------------------------------------- endpoint tests
$results = @()
foreach ($ep in $Endpoints) {
  $h = $ep[0]
  $r = [ordered]@{ host = $h; purpose = $ep[1] }
  $addrs = $null
  if ((Get-Date) -gt $deadline) { $r.skipped = 'time budget reached'; $results += $r; continue }
  # DNS (system resolver, includes the hosts file)
  $dns = [ordered]@{ ok = $false; addresses = @(); cnames = @(); ms = $null; error = $null }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    $addrs = [System.Net.Dns]::GetHostAddresses($h)
    $dns.addresses = @($addrs | ForEach-Object { $_.IPAddressToString })
    $dns.ok = ($dns.addresses.Count -gt 0)
  } catch { $dns.error = $_.Exception.InnerException.Message; if (-not $dns.error) { $dns.error = $_.Exception.Message } }
  $dns.ms = $sw.ElapsedMilliseconds
  if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    try { $dns.cnames = @(Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'CNAME' } | ForEach-Object { $_.NameHost }) } catch {}
  }
  $r.dns = $dns
  # TCP 443 + TLS handshake (direct, bypassing any proxy)
  $tcp = [ordered]@{ ok = $false; ms = $null; ip = $null; error = $null }
  $tls = [ordered]@{ ok = $false; ms = $null; protocol = $null; cipher = $null; subject = $null; issuer = $null; thumbprint = $null; not_after = $null; chain = @(); chain_valid = $null; chain_status = $null; error = $null }
  $ip = $null
  if ($dns.ok) { $ip = @($addrs | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0]; if (-not $ip) { $ip = $addrs[0] } }
  if ($ip) {
    $tcp.ip = $ip.IPAddressToString
    $client = New-Object System.Net.Sockets.TcpClient($ip.AddressFamily)
    try {
      $sw = [Diagnostics.Stopwatch]::StartNew()
      $ar = $client.BeginConnect($ip, 443, $null, $null)
      if ($ar.AsyncWaitHandle.WaitOne(3000, $false) -and $client.Connected) {
        $client.EndConnect($ar)
        $tcp.ok = $true
        $tcp.ms = $sw.ElapsedMilliseconds
        $client.ReceiveTimeout = 4000
        $client.SendTimeout = 4000
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, ({ $true } -as [System.Net.Security.RemoteCertificateValidationCallback]))
        try {
          $sw = [Diagnostics.Stopwatch]::StartNew()
          $ssl.AuthenticateAsClient($h, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
          $tls.ms = $sw.ElapsedMilliseconds
          $tls.ok = $true
          $tls.protocol = [string]$ssl.SslProtocol
          $tls.cipher = [string]$ssl.CipherAlgorithm
          $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
          $tls.subject = $cert.Subject
          $tls.issuer = $cert.Issuer
          $tls.thumbprint = $cert.Thumbprint
          $tls.not_after = $cert.NotAfter.ToUniversalTime().ToString('o')
          $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
          $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
          $tls.chain_valid = $chain.Build($cert)
          $tls.chain = @($chain.ChainElements | ForEach-Object { $_.Certificate.Subject })
          $tls.chain_status = (@($chain.ChainStatus | ForEach-Object { [string]$_.Status }) -join ', ')
        } catch {
          $tls.error = $_.Exception.Message
          if ($_.Exception.InnerException) { $tls.error = $_.Exception.InnerException.Message }
        } finally { $ssl.Dispose() }
      } else {
        $tcp.error = 'TCP 443 timed out (3 s)'
      }
    } catch {
      $tcp.error = $_.Exception.Message
      if ($_.Exception.InnerException) { $tcp.error = $_.Exception.InnerException.Message }
    } finally { $client.Close() }
  }
  $r.tcp = $tcp
  $r.tls = $tls
  # HTTPS through the system (WinINET) proxy, when one applies to this URL
  $pr = [ordered]@{ used = $false }
  if ($useProxy) {
    try {
      $uri = New-Object System.Uri("https://$h/")
      $sysProxy = [System.Net.WebRequest]::GetSystemWebProxy()
      $proxyUri = $sysProxy.GetProxy($uri)
      if ($proxyUri.AbsoluteUri -ne $uri.AbsoluteUri) {
        $pr.used = $true
        $pr.proxy = $proxyUri.AbsoluteUri
        $req = [System.Net.HttpWebRequest]::Create($uri)
        $req.Method = 'GET'
        $req.Timeout = 6000
        $req.AllowAutoRedirect = $false
        $req.Proxy = $sysProxy
        $req.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
          $resp = $req.GetResponse()
          $pr.status = [int]$resp.StatusCode
          $resp.Close()
        } catch [System.Net.WebException] {
          if ($_.Exception.Response) { $pr.status = [int]$_.Exception.Response.StatusCode; $_.Exception.Response.Close() } else { $pr.error = $_.Exception.Message }
        }
        $pr.ms = $sw.ElapsedMilliseconds
        if ($req.ServicePoint.Certificate) {
          $pc = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($req.ServicePoint.Certificate)
          $pr.issuer = $pc.Issuer
          $pr.subject = $pc.Subject
          $pr.thumbprint = $pc.Thumbprint
        }
      }
    } catch { $pr.error = $_.Exception.Message }
  }
  $r.proxied = $pr
  $results += $r
}

# ---------------------------------------------------------------- public IP
$pub = [ordered]@{ ip = $null; source = 'api.ipify.org (public echo service, via the system proxy)'; error = $null }
try { $pub.ip = (Invoke-RestMethod -Uri 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 5).ToString().Trim() } catch { $pub.error = $_.Exception.Message }

$os = $null
try { $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | ForEach-Object { "$($_.Caption) $($_.Version)" }) } catch {}
$out = [ordered]@{
  tool = 'mspgather-m365-collector'
  version = 1
  collected_utc = (Get-Date).ToUniversalTime().ToString('o')
  computer = $env:COMPUTERNAME
  user = "$env:USERDOMAIN\$env:USERNAME"
  os = $os
  ps_version = $PSVersionTable.PSVersion.ToString()
  tenant = $Tenant
  duration_s = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
  public_ip = $pub
  proxy = $px
  hosts_file = $hostsLines
  endpoints = $results
}
$json = $out | ConvertTo-Json -Depth 6
$block = "-----BEGIN MSPGATHER M365 NETWORK-----`r`n$json`r`n-----END MSPGATHER M365 NETWORK-----"
Write-Output $block
try { $block | Set-Clipboard -ErrorAction Stop; Write-Host "`r`nCopied to the clipboard. Paste it into MSPGather > Microsoft 365 > Endpoint Connectivity." -ForegroundColor Green } catch {}
'''


def collector_script(tenant: str | None) -> dict:
    tenant = _norm_tenant(tenant)
    lines = ",\n".join(f"  @('{h}', '{p}')" for h, p in endpoint_list(tenant))
    script = COLLECTOR_PS1.replace("__TENANT__", tenant or "").replace("__ENDPOINTS__", lines)
    return {"tenant": tenant, "script": script, "endpoints": [h for h, _ in endpoint_list(tenant)]}


# ====================================================================== routes
class RawText(BaseModel):
    raw: str = Field(..., max_length=2_000_000)


@router.get("/api/m365/autodiscover")
def autodiscover_route(target: str = Query(..., max_length=320)):
    return run(autodiscover_walk, target)


@router.get("/api/m365/net/script")
def net_script(tenant: str | None = Query(None, max_length=200)):
    return run(collector_script, tenant)


@router.post("/api/m365/net/analyze")
def net_analyze(body: RawText):
    return run(analyze_collector, body.raw)


@router.get("/api/m365/net/server")
def net_server(tenant: str | None = Query(None, max_length=200)):
    return run(server_check, tenant)
