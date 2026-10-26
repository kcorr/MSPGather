"""DNS & Network diagnostics: SSL/TLS checker, port check, domain registration
(RDAP + live DNS/DNSSEC) and HTTP inspector. The subnet calculator is pure
client-side JS (static/tools/network.js).

Every analysis returns {severity, headline, subline, findings, steps, ...}:
the UI shows the verdict first, then findings, then the fix, then details."""
from __future__ import annotations

import hashlib
import html
import ipaddress
import re
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import httpx
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID
from fastapi import APIRouter, Query

from ..core.dns_utils import addresses, is_ip, make_resolver, normalize_domain, registered_domain, resolve
from ..core.http import run
from .ipinfo import _vcard
from .smtp_test import DEFAULT_HELO, _cert_info

router = APIRouter()
from .. import __version__ as _VERSION
UA = f"MSPGather/{_VERSION} (network diagnostics)"
SEV_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def _f(sev: str, title: str, detail: str = "", headline: str | None = None) -> dict:
    out = {"severity": sev, "title": title, "detail": detail}
    if headline:
        out["headline"] = headline
    return out


def _worst(findings: list[dict]) -> str:
    return min((f["severity"] for f in findings), key=lambda s: SEV_ORDER.get(s, 9), default="ok")


def _pick_headline(findings: list[dict], fallback: str) -> tuple[str, str]:
    """Severity + headline of the most severe finding that carries a headline."""
    sev = _worst(findings)
    for s in ("critical", "warning", "info", "ok"):
        for f in findings:
            if f["severity"] == s and f.get("headline"):
                # Minor info findings don't turn a healthy verdict blue; only an info headline does.
                return (s if sev == "info" else sev), f["headline"]
    return ("ok" if sev == "info" else sev), fallback


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _in_days(days: int) -> str:
    if days == 0:
        return "today"
    return f"in {_plural(days, 'day')}" if days > 0 else f"{_plural(-days, 'day')} ago"


# ====================================================================== outbound safety
_METADATA = [ipaddress.ip_network(n) for n in ("169.254.169.254/32", "100.100.100.200/32", "fd00:ec2::254/128")]
_ZERO_NET = ipaddress.ip_network("0.0.0.0/8")


def _unwrap(ip):
    if ip.version == 6:
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
        if ip.teredo:
            return ip.teredo[1]
    return ip


def _refusal(ip_str: str, allow_private: bool) -> str | None:
    """Why we won't connect to this address, or None if it's allowed."""
    from ..core.outbound import ALLOW_PRIVATE_TARGETS, denied_networks
    allow_private = allow_private and ALLOW_PRIVATE_TARGETS
    ip = _unwrap(ipaddress.ip_address(ip_str.split("%")[0]))
    if any(ip.version == n.version and ip in n for n in _METADATA):
        return "it's a cloud metadata service address"
    if any(ip.version == n.version and ip in n for n in denied_networks()):
        return "it's the container host's gateway or a denied network (MSPGATHER_DENY_NETS)"
    if ip.is_loopback:
        return "it's a loopback address (the MSPGather server itself)"
    if ip.is_link_local:
        return "it's a link-local address (169.254.x.x / fe80::), which includes cloud metadata services"
    if ip.is_multicast:
        return "it's a multicast address"
    if ip.is_unspecified or (ip.version == 4 and ip in _ZERO_NET):
        return "it's an unspecified (0.x.x.x / ::) address"
    if ip.is_reserved or (ip.version == 6 and ip.is_site_local):
        return "it's a reserved address"
    if not allow_private and not ip.is_global:
        return "it's a private/internal address (RFC 1918, CGNAT or similar); this tool only fetches public URLs"
    return None


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$")


def _clean_host(host: str) -> str:
    host = host.strip().strip(".").lower()
    if is_ip(host):
        return str(ipaddress.ip_address(host.strip("[]")))
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"'{host}' is not a valid host name.") from exc
    if not _HOST_RE.match(host):
        raise ValueError(f"'{host}' is not a valid host name or IP address.")
    return host


def _parse_host_port(value: str) -> tuple[str, int | None]:
    v = (value or "").strip()
    if not v:
        raise ValueError("Enter a host name or IP address.")
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v, flags=re.I)
    v = v.split("/")[0].split("?")[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    port = None
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", v)
    if m:
        host, port = m.group(1), m.group(2)
    elif v.count(":") == 1:
        host, port = v.split(":")
    else:
        host = v  # plain name, IPv4, or bare IPv6
    if port is not None:
        if not str(port).isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError(f"'{port}' is not a valid port (1-65535).")
        port = int(port)
    return _clean_host(host), port


def _getaddrinfo(host: str, timeout: float = 4.0) -> list[str]:
    ex = ThreadPoolExecutor(1)
    try:
        infos = ex.submit(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM).result(timeout=timeout)
        return list(dict.fromkeys(i[4][0] for i in infos))
    except (OSError, FutureTimeout):
        return []
    finally:
        ex.shutdown(wait=False)


def _resolve_safe(host: str, allow_private: bool) -> list[str]:
    """Resolve and refuse unsafe targets. IPv4 first. Raises ValueError."""
    if is_ip(host):
        ips = [host]
    else:
        ips = addresses(make_resolver(), host)
        if not ips:
            ips = _getaddrinfo(host)  # internal / single-label names via the OS resolver
        if not ips:
            raise ValueError(f"{host} does not resolve to an IP address (checked DNS from the MSPGather server).")
    for ip in ips:
        reason = _refusal(ip, allow_private)
        if reason:
            raise ValueError(f"Refusing to connect to {host}" + (f" ({ip})" if ip != host else "") + f": {reason}.")
    return sorted(dict.fromkeys(ips), key=lambda a: ":" in a)


# ====================================================================== SSL / TLS checker
TLS_PROTOCOLS: dict[str, dict] = {
    "https": {"label": "HTTPS", "port": 443, "mode": "tls", "http": True},
    "tls": {"label": "Generic TLS", "port": 443, "mode": "tls"},
    "smtp": {"label": "SMTP STARTTLS", "port": 25, "mode": "smtp"},
    "submission": {"label": "SMTP submission STARTTLS", "port": 587, "mode": "smtp"},
    "imap": {"label": "IMAP STARTTLS", "port": 143, "mode": "imap"},
    "pop3": {"label": "POP3 STARTTLS", "port": 110, "mode": "pop3"},
    "smtps": {"label": "SMTPS (implicit TLS)", "port": 465, "mode": "tls"},
    "imaps": {"label": "IMAPS (implicit TLS)", "port": 993, "mode": "tls"},
    "pop3s": {"label": "POP3S (implicit TLS)", "port": 995, "mode": "tls"},
    "ldaps": {"label": "LDAPS", "port": 636, "mode": "tls"},
    "rdp": {"label": "RDP (TLS)", "port": 3389, "mode": "rdp"},
}
_AUTO_BY_PORT = {25: "smtp", 587: "submission", 143: "imap", 110: "pop3", 465: "smtps", 993: "imaps", 995: "pop3s",
                 636: "ldaps", 3269: "ldaps", 3389: "rdp", 443: "https", 8443: "https", 4443: "https", 10443: "https"}
TLS_VERSIONS = [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
                ("TLS 1.2", ssl.TLSVersion.TLSv1_2), ("TLS 1.3", ssl.TLSVersion.TLSv1_3)]
TLS_TIMEOUT = 8.0

# RDP negotiation (MS-RDPBCGR 2.2.1.1 / 2.2.1.2)
RDP_PROTOCOLS = {0: "Standard RDP Security (no TLS)", 1: "TLS", 2: "CredSSP / NLA", 8: "CredSSP with Early User Auth"}
RDP_FAILURES = {
    1: "SSL_REQUIRED_BY_SERVER: the server requires TLS.",
    2: "SSL_NOT_ALLOWED_BY_SERVER: the server is set to Standard RDP Security only, no TLS.",
    3: "SSL_CERT_NOT_ON_SERVER: the server has no certificate configured for RDP.",
    4: "INCONSISTENT_FLAGS: the server rejected the requested protocol flags.",
    5: "HYBRID_REQUIRED_BY_SERVER: the server requires Network Level Authentication (CredSSP).",
    6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER: the server requires TLS with user authentication.",
}


class _ProtoError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class _Lines:
    def __init__(self, sock):
        self.sock, self.buf = sock, b""

    def line(self) -> str:
        while b"\n" not in self.buf:
            if len(self.buf) > 16384:
                raise _ProtoError("proto", "Server sent an over-long line.")
            chunk = self.sock.recv(4096)
            if not chunk:
                raise _ProtoError("proto", "Server closed the connection before TLS started.")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.rstrip(b"\r").decode("utf-8", "replace")


def _recv_exact(sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise _ProtoError("proto", "Server closed the connection during RDP negotiation.")
        data += chunk
    return data


def _smtp_reply(r: _Lines) -> tuple[int, list[str]]:
    lines: list[str] = []
    while len(lines) < 200:
        ln = r.line()
        lines.append(ln)
        if len(ln) < 4 or ln[3] != "-":
            break
    code = int(lines[-1][:3]) if lines[-1][:3].isdigit() else 0
    return code, lines


def _rdp_negotiate(sock, requested: int) -> dict:
    """Send an X.224 Connection Request with RDP_NEG_REQ; return the server's choice."""
    neg_req = struct.pack("<BBHI", 1, 0, 8, requested)
    x224 = bytes([14, 0xE0, 0, 0, 0, 0, 0])
    sock.sendall(struct.pack(">BBH", 3, 0, 4 + len(x224) + len(neg_req)) + x224 + neg_req)
    hdr = _recv_exact(sock, 4)
    if hdr[0] != 3:
        raise _ProtoError("not-rdp", "This port didn't answer like an RDP server (no TPKT reply to the X.224 connection request).")
    length = struct.unpack(">H", hdr[2:4])[0]
    if not 7 <= length - 4 <= 512:
        raise _ProtoError("not-rdp", "Unexpected RDP connection confirm length.")
    body = _recv_exact(sock, length - 4)
    if (body[1] & 0xF0) != 0xD0:
        raise _ProtoError("not-rdp", "The server didn't send an X.224 Connection Confirm.")
    neg = body[7:]
    if len(neg) >= 8:
        typ, flags, _ln, val = struct.unpack("<BBHI", neg[:8])
        if typ == 2:
            return {"selected": val, "flags": flags}
        if typ == 3:
            return {"failure": val}
    return {"selected": 0, "legacy": True}


def _prelude(sock, mode: str, rdp_request: int = 3) -> dict:
    """Protocol-specific steps before the TLS handshake (STARTTLS / RDP negotiation)."""
    info: dict = {}
    if mode == "tls":
        return info
    if mode == "rdp":
        neg = _rdp_negotiate(sock, rdp_request)
        info["rdp"] = neg
        if "failure" in neg:
            raise _ProtoError("rdp-failure", "RDP server refused the negotiation: " +
                              RDP_FAILURES.get(neg["failure"], f"failure code {neg['failure']}."))
        if neg["selected"] == 0:
            raise _ProtoError("rdp-no-tls", "The RDP server only offers Standard RDP Security (no TLS, no NLA).")
        return info
    r = _Lines(sock)
    if mode == "smtp":
        code, lines = _smtp_reply(r)
        info["banner"] = lines[0]
        if code != 220:
            raise _ProtoError("proto", f"SMTP server greeted with: {lines[0][:200]}")
        sock.sendall(f"EHLO {DEFAULT_HELO}\r\n".encode())
        code, caps = _smtp_reply(r)
        if code != 250:
            raise _ProtoError("proto", f"EHLO rejected: {caps[-1][:200]}")
        if not any(c[4:].strip().upper().startswith("STARTTLS") for c in caps):
            raise _ProtoError("no-starttls", "The SMTP server doesn't offer STARTTLS.")
        sock.sendall(b"STARTTLS\r\n")
        code, lines = _smtp_reply(r)
        if code != 220:
            raise _ProtoError("no-starttls", f"STARTTLS refused: {lines[-1][:200]}")
    elif mode == "imap":
        greet = r.line()
        info["banner"] = greet
        if not greet.upper().startswith(("* OK", "* PREAUTH")):
            raise _ProtoError("proto", f"IMAP server greeted with: {greet[:200]}")
        sock.sendall(b"a1 STARTTLS\r\n")
        for _ in range(50):
            ln = r.line()
            if ln.lower().startswith("a1 "):
                if not ln[3:].upper().startswith("OK"):
                    raise _ProtoError("no-starttls", f"STARTTLS refused: {ln[:200]}")
                break
        else:
            raise _ProtoError("proto", "No reply to STARTTLS.")
    elif mode == "pop3":
        greet = r.line()
        info["banner"] = greet
        if not greet.startswith("+OK"):
            raise _ProtoError("proto", f"POP3 server greeted with: {greet[:200]}")
        sock.sendall(b"STLS\r\n")
        ln = r.line()
        if not ln.startswith("+OK"):
            raise _ProtoError("no-starttls", f"STLS refused: {ln[:200]}")
    return info


def _ctx(verify: bool = False, version: ssl.TLSVersion | None = None, ciphers: str = "DEFAULT:@SECLEVEL=0") -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # we check the name ourselves; this context only judges the chain
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(ciphers)  # SECLEVEL=0: so we can see (and report) weak servers instead of failing
    ctx.minimum_version = version or ssl.TLSVersion.TLSv1
    if version:
        ctx.maximum_version = version
    return ctx


def _http_probe(ss, host_header: str) -> dict:
    """One GET / over the established TLS socket, headers only (for HSTS)."""
    try:
        ss.settimeout(5)
        ss.sendall((f"GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {UA}\r\nAccept: */*\r\n"
                    "Connection: close\r\n\r\n").encode())
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 32768:
            chunk = ss.recv(4096)
            if not chunk:
                break
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace").split("\r\n")
        if not head or not head[0].startswith("HTTP/"):
            return {"error": "No HTTP response"}
        headers: dict[str, str] = {}
        for ln in head[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers.setdefault(k.strip().lower(), v.strip())
        return {"status_line": head[0][:200], "server": headers.get("server"), "hsts": headers.get("strict-transport-security"),
                "location": headers.get("location")}
    except (OSError, ssl.SSLError) as exc:
        return {"error": str(exc)}


def _session(ip: str, host: str, port: int, mode: str, ctx: ssl.SSLContext, rdp_request: int = 3,
             http_host: str | None = None) -> dict:
    t0 = time.monotonic()
    sock = socket.create_connection((ip, port), timeout=TLS_TIMEOUT)
    try:
        out: dict = {"connect_ms": round((time.monotonic() - t0) * 1000)}
        out.update(_prelude(sock, mode, rdp_request))
        t1 = time.monotonic()
        ss = ctx.wrap_socket(sock, server_hostname=None if is_ip(host) else host)
        out["handshake_ms"] = round((time.monotonic() - t1) * 1000)
        out["version"] = ss.version()
        name, _proto, bits = ss.cipher() or (None, None, None)
        out["cipher"], out["bits"] = name, bits
        try:
            out["chain"] = [c.public_bytes(2) for c in ss._sslobj.get_unverified_chain() or []]  # 2 = ENCODING_DER
        except AttributeError:
            out["chain"] = [ss.getpeercert(binary_form=True)]
        if ctx.verify_mode == ssl.CERT_REQUIRED:
            try:
                out["verified_chain"] = [c.public_bytes(2) for c in ss._sslobj.get_verified_chain() or []]
            except AttributeError:
                out["verified_chain"] = []
        if http_host:
            out["http"] = _http_probe(ss, http_host)
        try:
            ss.close()
        except OSError:
            pass
        return out
    finally:
        sock.close()


def _conn_error(exc: Exception, host: str, port: int) -> tuple[str, str]:
    """(short reason, plain explanation) for a failed connection."""
    if isinstance(exc, _ProtoError):
        return exc.kind, str(exc)
    if isinstance(exc, ConnectionRefusedError):
        return "refused", f"Connection refused: {host} answered, but nothing is listening on port {port} (or a firewall rejected it)."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout", f"No answer from {host}:{port} within {TLS_TIMEOUT:.0f}s: a firewall is dropping the traffic, or the host is offline."
    if isinstance(exc, ssl.SSLError):
        return "tls", f"TLS handshake failed: {exc.reason or exc}"
    return "error", f"Connection failed: {exc}"


def _probe_version(ip, host, port, mode, label, version) -> dict:
    try:
        s = _session(ip, host, port, mode, _ctx(version=version, ciphers="ALL:@SECLEVEL=0"))
        return {"version": label, "accepted": True, "cipher": s.get("cipher")}
    except ssl.SSLError as exc:
        reason = exc.reason or str(exc)
        if "NO_PROTOCOLS_AVAILABLE" in str(reason).upper():  # our own OpenSSL can't offer this version
            return {"version": label, "accepted": None, "detail": "Not testable from this server's OpenSSL build."}
        return {"version": label, "accepted": False, "detail": str(reason)}
    except (OSError, _ProtoError) as exc:
        return {"version": label, "accepted": None, "detail": _conn_error(exc, host, port)[1]}


def _name_attr(name: x509.Name, oid) -> str | None:
    vals = name.get_attributes_for_oid(oid)
    return vals[0].value if vals else None


def _short_name(name: x509.Name) -> str:
    return _name_attr(name, NameOID.ORGANIZATION_NAME) or _name_attr(name, NameOID.COMMON_NAME) or name.rfc4514_string()


def _ca_name(name: x509.Name) -> str:
    cn, org = _name_attr(name, NameOID.COMMON_NAME), _name_attr(name, NameOID.ORGANIZATION_NAME)
    if cn and org and org.lower() not in cn.lower():
        return f"{cn} ({org})"
    return cn or org or name.rfc4514_string()


def _cert_details(der: bytes, host: str) -> dict:
    cert = x509.load_der_x509_certificate(der)
    info = _cert_info(der, host)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key = {"type": "RSA", "bits": pub.key_size, "text": f"RSA {pub.key_size}-bit"}
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key = {"type": "ECDSA", "bits": pub.curve.key_size, "text": f"ECDSA {pub.curve.name} ({pub.curve.key_size}-bit)"}
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key = {"type": "Ed25519", "bits": 256, "text": "Ed25519"}
    elif isinstance(pub, ed448.Ed448PublicKey):
        key = {"type": "Ed448", "bits": 456, "text": "Ed448"}
    elif isinstance(pub, dsa.DSAPublicKey):
        key = {"type": "DSA", "bits": pub.key_size, "text": f"DSA {pub.key_size}-bit"}
    else:
        key = {"type": "unknown", "bits": None, "text": "unknown"}
    try:
        h = cert.signature_hash_algorithm
        sig_hash = h.name if h else None
    except UnsupportedAlgorithm:
        sig_hash = None
    ip_sans: list[str] = []
    try:
        ip_sans = [str(a) for a in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                   .get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    eku: list[str] | None = None
    try:
        eku = [o.dotted_string for o in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except x509.ExtensionNotFound:
        pass
    ca_issuers: list[str] = []
    try:
        for d in cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value:
            if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS and isinstance(d.access_location, x509.UniformResourceIdentifier):
                ca_issuers.append(d.access_location.value)
    except x509.ExtensionNotFound:
        pass
    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        pass
    now = datetime.now(timezone.utc)
    hostname_match = info["hostname_match"]
    if is_ip(host):
        hostname_match = host in ip_sans
    info.update({
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "subject_short": _ca_name(cert.subject),
        "issuer_short": _short_name(cert.issuer),
        "issuer_ca": _ca_name(cert.issuer),
        "ip_san": ip_sans,
        "hostname_match": hostname_match,
        "not_yet_valid": cert.not_valid_before_utc > now,
        "validity_days": (cert.not_valid_after_utc - cert.not_valid_before_utc).days,
        "key": key,
        "signature": cert.signature_algorithm_oid._name,
        "signature_hash": sig_hash,
        "sha1": hashlib.sha1(der).hexdigest().upper(),
        "sha256": hashlib.sha256(der).hexdigest().upper(),
        "eku_server_auth": None if eku is None else (ExtendedKeyUsageOID.SERVER_AUTH.dotted_string in eku
                                                     or "2.5.29.37.0" in eku),
        "ca_issuers": ca_issuers,
        "is_ca": is_ca,
    })
    return info


_STORE: dict | None = None
_STORE_LOCK = threading.Lock()


def _trust_store() -> dict[bytes, x509.Certificate]:
    """Subject (DER) -> root certificate, from the system trust store."""
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = {}
            paths = ssl.get_default_verify_paths()
            for path in filter(None, (paths.cafile, paths.openssl_cafile)):
                try:
                    pem = open(path, "rb").read()
                except OSError:
                    continue
                for block in re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", pem, re.S):
                    try:
                        c = x509.load_pem_x509_certificate(block)
                        _STORE[c.subject.public_bytes()] = c
                    except ValueError:
                        continue
                if _STORE:
                    break
        return _STORE


def _fetch_aia(url: str) -> dict:
    """Download the issuer certificate the leaf points to (AIA caIssuers), with SSRF checks."""
    try:
        status, body, _ = _safe_get(url, max_bytes=65536, timeout=5.0)
    except ValueError as exc:
        return {"url": url, "error": str(exc)}
    if status != 200:
        return {"url": url, "error": f"HTTP {status}"}
    certs: list[x509.Certificate] = []
    for loader in (lambda b: [x509.load_der_x509_certificate(b)], lambda b: [x509.load_pem_x509_certificate(b)],
                   pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
        try:
            certs = loader(body)
            if certs:
                break
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
    if not certs:
        return {"url": url, "error": "Couldn't parse the downloaded certificate."}
    c = certs[0]
    return {"url": url, "subject": c.subject.rfc4514_string(), "subject_short": _ca_name(c.subject),
            "issuer": c.issuer.rfc4514_string(), "issuer_in_store": c.issuer.public_bytes() in _trust_store()}


def tls_check(target: str, protocol: str = "auto") -> dict:
    host, port = _parse_host_port(target)
    protocol = (protocol or "auto").lower()
    if protocol == "auto":
        protocol = _AUTO_BY_PORT.get(port or 443, "tls")
    if protocol not in TLS_PROTOCOLS:
        raise ValueError(f"Unknown protocol '{protocol}'.")
    proto = TLS_PROTOCOLS[protocol]
    port = port or proto["port"]
    mode = proto["mode"]
    ips = _resolve_safe(host, allow_private=True)
    ip = ips[0]
    hostport = f"{host}:{port}"
    http_host = (host if port == 443 else f"{host}:{port}") if proto.get("http") else None

    out: dict = {"host": host, "port": port, "ip": ip, "other_ips": ips[1:], "protocol": protocol,
                 "protocol_label": proto["label"], "findings": [], "steps": [], "chain": [], "versions": []}
    F = out["findings"]
    with ThreadPoolExecutor(8) as ex:
        main_f = ex.submit(_session, ip, host, port, mode, _ctx(), 3, http_host)
        ver_f = ex.submit(_session, ip, host, port, mode, _ctx(verify=True))
        probes = [ex.submit(_probe_version, ip, host, port, mode, lbl, v) for lbl, v in TLS_VERSIONS]
        nla_f = ex.submit(_rdp_nla_required, ip, port) if mode == "rdp" else None
        try:
            main = main_f.result()
        except ssl.SSLError:
            try:  # server may only speak ciphers outside DEFAULT (3DES, RC4…)
                main = _session(ip, host, port, mode, _ctx(ciphers="ALL:COMPLEMENTOFALL:@SECLEVEL=0"), 3, http_host)
            except (OSError, _ProtoError) as exc:
                main = exc
        except (OSError, _ProtoError) as exc:
            main = exc
        try:
            verify = {"ok": True, "res": ver_f.result()}
        except ssl.SSLCertVerificationError as exc:
            verify = {"ok": False, "code": exc.verify_code, "message": exc.verify_message or str(exc)}
        except (OSError, _ProtoError) as exc:
            verify = {"ok": None, "message": _conn_error(exc, host, port)[1]}
        out["versions"] = [p.result() for p in probes]
        nla = nla_f.result() if nla_f else None

    if isinstance(main, Exception):
        kind, msg = _conn_error(main, host, port)
        out["error"] = msg
        if kind == "no-starttls":
            F.append(_f("critical", "STARTTLS is not available", msg + " Mail to or from this server travels unencrypted, "
                        "and senders that require TLS will refuse to deliver.",
                        headline=f"{hostport} doesn't offer STARTTLS. Connections to it are not encrypted."))
            out["steps"].append({"title": "Enable TLS on the mail server",
                                 "detail": "On Exchange, the receive connector needs a certificate with the server's FQDN assigned to SMTP.",
                                 "commands": ["Get-ExchangeCertificate | Format-List Thumbprint, Subject, NotAfter, Services",
                                              "Enable-ExchangeCertificate -Thumbprint <THUMBPRINT> -Services SMTP"]})
        elif kind == "rdp-no-tls":
            F.append(_f("critical", "RDP server only supports Standard RDP Security", msg + " That legacy mode has no server "
                        "authentication and no NLA, so it's open to man-in-the-middle attacks and pre-login exploits.",
                        headline=f"{hostport} only offers legacy RDP security (no TLS, no NLA)."))
            out["steps"].append({"title": "Require TLS and NLA for RDP",
                                 "detail": "Set the security layer to TLS (2) and require Network Level Authentication, then reconnect.",
                                 "commands": ["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name SecurityLayer -Value 2",
                                              "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"]})
        elif kind in ("refused", "timeout"):
            F.append(_f("critical", "Could not connect", msg, headline=f"Can't reach {hostport}: {'connection refused' if kind == 'refused' else 'no response (filtered)'}."))
            out["steps"].append({"title": "Check reachability from a client network",
                                 "commands": [f"Test-NetConnection -ComputerName {host} -Port {port}"]})
        elif kind == "tls":
            F.append(_f("critical", "TLS handshake failed", msg + " The server may only support protocols or ciphers that are too old (SSL 3.0, export ciphers), or it isn't a TLS service.",
                        headline=f"TLS handshake with {hostport} fails: {msg.split(': ', 1)[-1]}."))
        else:
            F.append(_f("critical", "Could not start TLS", msg, headline=f"{hostport}: {msg}"))
        out["severity"], out["headline"] = _pick_headline(F, f"TLS check of {hostport} failed.")
        out["subline"] = f"{proto['label']} · {ip}"
        return out

    out["negotiated"] = {"version": main.get("version"), "cipher": main.get("cipher"), "bits": main.get("bits"),
                         "connect_ms": main.get("connect_ms"), "handshake_ms": main.get("handshake_ms")}
    out["banner"] = main.get("banner")
    chain_der = main.get("chain") or []
    certs = [x509.load_der_x509_certificate(d) for d in chain_der]
    out["chain"] = [_cert_details(d, host) for d in chain_der]
    if not certs:
        F.append(_f("critical", "Server sent no certificate", "", headline=f"{hostport} sent no certificate."))
        out["severity"], out["headline"] = _pick_headline(F, "")
        return out
    leaf, L = certs[0], out["chain"][0]
    for i, c in enumerate(out["chain"]):
        c["position"] = "leaf" if i == 0 else ("root (self-signed)" if c["self_signed"] else "intermediate")
    store = _trust_store()
    leaf_name = host if (L["hostname_match"] and not is_ip(host)) else (L["subject_cn"] or (L["san"][0] if L["san"] else host))
    issuer_name = L["issuer_short"]
    is_rdp = mode == "rdp"
    days = L["days_left"]

    # --- expiry
    if L["expired"]:
        F.append(_f("critical", f"Certificate expired {_in_days(days)}", f"Expired {L['not_after'][:10]}. Every client rejects it.",
                    headline=f"Certificate for {leaf_name} expired {_in_days(days)} ({issuer_name}). Renew and install it now."))
    elif L["not_yet_valid"]:
        F.append(_f("critical", "Certificate is not valid yet", f"Valid from {L['not_before'][:19]}Z. Check the server clock or wait.",
                    headline=f"Certificate for {leaf_name} isn't valid until {L['not_before'][:10]}."))
    elif days < 7:
        F.append(_f("critical", f"Certificate expires {_in_days(days)}", f"Expires {L['not_after'][:10]}.",
                    headline=f"Certificate for {leaf_name} expires {_in_days(days)} ({issuer_name}). Renew now."))
    elif days < 30:
        F.append(_f("warning", f"Certificate expires {_in_days(days)}", f"Expires {L['not_after'][:10]}. Renew before then and install it on every server that uses it.",
                    headline=f"Certificate for {leaf_name} expires {_in_days(days)} ({issuer_name}). Schedule the renewal."))
    else:
        F.append(_f("ok", f"Certificate valid for {days} more days", f"Expires {L['not_after'][:10]}."))
    for c in out["chain"][1:]:
        if c["expired"]:
            F.append(_f("critical", f"Chain certificate '{c['subject_short']}' has expired",
                        f"Expired {c['not_after'][:10]}. The server is sending an old intermediate; replace it with the current one from the CA.",
                        headline=f"Server sends an expired intermediate certificate ({c['subject_short']}). Clients will reject the chain."))
        elif not c["self_signed"] and 0 <= c["days_left"] < 30:
            F.append(_f("warning", f"Intermediate '{c['subject_short']}' expires {_in_days(c['days_left'])}",
                        "Install the CA's replacement intermediate before then."))

    # --- chain completeness & trust
    issuer_in_chain = any(c.subject == leaf.issuer for c in certs[1:])
    leaf_self_signed = L["self_signed"]
    missing = None
    if not leaf_self_signed and not issuer_in_chain and leaf.issuer.public_bytes() not in store:
        missing = {"issuer": leaf.issuer.rfc4514_string(), "issuer_short": _ca_name(leaf.issuer), "aia": None}
        if L["ca_issuers"]:
            missing["aia"] = _fetch_aia(L["ca_issuers"][0])
    out["missing_intermediate"] = missing
    trust = {"verified": verify["ok"], "code": verify.get("code"), "message": verify.get("message"), "path": []}
    if verify["ok"]:
        vc = verify["res"].get("verified_chain") or []
        trust["path"] = [_ca_name(x509.load_der_x509_certificate(d).subject) for d in vc]
    out["trust"] = trust
    vcode = verify.get("code")
    if missing and (verify["ok"] is False or verify["ok"] is None):
        aia = missing.get("aia") or {}
        detail = (f"The server sends only the certificate for {leaf_name}, not the intermediate '{missing['issuer_short']}' that "
                  "signed it. Desktop browsers usually cope (they fetch or cache it), but Java, Android, Python, curl, "
                  "older Outlook/ActiveSync clients and many appliances fail with 'unable to get local issuer certificate'.")
        if aia.get("subject"):
            detail += f" The missing certificate is '{aia['subject_short']}', downloadable from {aia['url']}."
        F.append(_f("critical", "Intermediate certificate is missing", detail,
                    headline="Server doesn't send the intermediate certificate. Mobile and Java clients will fail."))
        cmds = []
        if aia.get("url"):
            cmds.append(f'Invoke-WebRequest -Uri "{aia["url"]}" -OutFile "$env:TEMP\\intermediate.crt"')
            cmds.append('Import-Certificate -FilePath "$env:TEMP\\intermediate.crt" -CertStoreLocation Cert:\\LocalMachine\\CA')
        out["steps"].append({"title": "Install the intermediate certificate on the server",
                             "detail": "Windows/IIS/Exchange: import it into the Intermediate Certification Authorities store, then restart the service (or rebind the certificate). "
                                       "Appliances, nginx, Apache, firewalls and load balancers: upload the 'full chain' / 'CA bundle' file from the CA together with the certificate.",
                             "commands": cmds})
    elif leaf_self_signed:
        if is_rdp:
            F.append(_f("warning", "Self-signed RDP certificate", "This is the Windows default. Clients get a certificate warning "
                        "unless you deploy a certificate from your internal CA (GPO: Remote Desktop certificate template).",
                        headline=f"RDP on {hostport} uses the default self-signed certificate. Users will see a certificate warning."))
        else:
            F.append(_f("critical", "Certificate is self-signed", "No client trusts it unless it was installed on that client. "
                        "Replace it with a certificate from a public CA (or your internal CA for internal-only services).",
                        headline=f"Certificate on {hostport} is self-signed. Clients will show a trust warning or refuse to connect."))
    elif verify["ok"] is False and vcode in (19, 20, 2, 21):
        top = certs[-1]
        F.append(_f("critical" if not is_rdp else "warning", "Chain ends at a CA that isn't publicly trusted",
                    f"The chain ends at '{_short_name(top.issuer if not top.issuer == top.subject else top.subject)}', which isn't in the public trust store. "
                    "That's expected for an internal (AD CS) CA on domain-joined machines; anyone else (phones, partners, the internet) gets a trust error.",
                    headline=f"Certificate on {hostport} is issued by a private CA ({issuer_name}). Only machines that trust that CA will accept it."))
    elif verify["ok"] is False:
        if vcode not in (9, 10):  # expiry is reported above
            F.append(_f("critical", "Certificate chain doesn't verify", f"OpenSSL says: {verify.get('message')}",
                        headline=f"Certificate on {hostport} is not trusted: {verify.get('message')}."))
    elif verify["ok"]:
        F.append(_f("ok", "Chain is complete and trusted", "Verified against the system trust store: " + " → ".join(reversed(trust["path"]))))
    else:
        F.append(_f("info", "Couldn't run a second (verifying) connection", verify.get("message") or ""))

    # --- name
    names = L["san"] + L["ip_san"] or ([L["subject_cn"]] if L["subject_cn"] else [])
    if not L["hostname_match"]:
        shown = ", ".join(names[:6]) + (f" (+{len(names) - 6} more)" if len(names) > 6 else "")
        if is_ip(host):
            F.append(_f("warning", "Certificate doesn't list this IP address", f"You connected by IP. The certificate is for: {shown}. "
                        "Clients that connect by name will be fine if that name is listed; test with the host name clients use."))
        else:
            F.append(_f("warning" if is_rdp else "critical", f"Certificate doesn't cover {host}",
                        f"The certificate is for: {shown}. Clients connecting to {host} get a name mismatch error. "
                        "Reissue it with this name in the Subject Alternative Names, or point clients at a covered name.",
                        headline=f"Certificate doesn't cover {host} (it's for {', '.join(names[:3]) or 'another name'}). Clients will show a name mismatch error."))
    else:
        F.append(_f("ok", f"Certificate covers {host}", ""))

    # --- crypto strength
    for i, (c, cd) in enumerate(zip(certs, out["chain"])):
        if i > 0 and cd["self_signed"]:
            continue  # a root's self-signature doesn't matter
        who = "Certificate" if i == 0 else f"Intermediate '{cd['subject_short']}'"
        if cd["key"]["type"] == "RSA" and cd["key"]["bits"] < 2048:
            F.append(_f("critical", f"{who} uses a weak {cd['key']['bits']}-bit RSA key", "Modern clients reject RSA keys under 2048 bits. Reissue with RSA 2048+ or ECDSA.",
                        headline=f"{who} uses a {cd['key']['bits']}-bit RSA key. Modern clients reject it."))
        if cd["signature_hash"] in ("sha1", "md5"):
            F.append(_f("critical", f"{who} is signed with {cd['signature_hash'].upper()}", "SHA-1/MD5 signatures are rejected by current browsers and OSes. Reissue it (SHA-256).",
                        headline=f"{who} is signed with {cd['signature_hash'].upper()}. Modern clients reject it."))
    if L["eku_server_auth"] is False:
        F.append(_f("warning", "Certificate isn't valid for server authentication", "Its Extended Key Usage doesn't include Server Authentication, so TLS clients may reject it. Reissue from a web server / computer template."))
    if verify["ok"] and L["validity_days"] > 398 and L["not_before"] >= "2020-09-01" and not is_rdp:
        F.append(_f("info", f"Validity period is {L['validity_days']} days", "Public CAs can't issue certificates valid for more than 398 days; this one is probably from a private CA that is trusted here, or an exception."))

    # --- chain hygiene
    if len(certs) > 1:
        ordered = all(certs[i].issuer == certs[i + 1].subject for i in range(len(certs) - 1))
        if not ordered and not missing:
            F.append(_f("info", "Chain is sent out of order or has extra certificates", "Most clients cope, but some strict ones (older Java, embedded devices) don't. Send leaf → intermediate(s) in order."))
        if out["chain"][-1]["self_signed"]:
            F.append(_f("info", "Server also sends the root certificate", "Harmless but unnecessary: clients use their own copy of the root."))

    # --- protocol versions
    acc = {v["version"]: v["accepted"] for v in out["versions"]}
    legacy = [v for v in ("TLS 1.0", "TLS 1.1") if acc.get(v)]
    if legacy:
        F.append(_f("warning", f"Server accepts {' and '.join(legacy)}", "These are deprecated (RFC 8996) and fail PCI DSS and most security scans. "
                    "Disable them unless you still have clients that need them (Windows 7 without updates, old Android, old appliances).",
                    headline=f"Certificate is fine, but {hostport} still accepts {' and '.join(legacy)}. Disable the legacy protocols."))
        if acc.get("TLS 1.2") or acc.get("TLS 1.3"):  # never suggest disabling the only protocol it speaks
            cmds = []
            for v in legacy:
                base = f"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\{v}\\Server"
                cmds.append(f"$k = '{base}'\nNew-Item $k -Force | Out-Null\n"
                            "New-ItemProperty $k -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null\n"
                            "New-ItemProperty $k -Name DisabledByDefault -Value 1 -PropertyType DWord -Force | Out-Null")
            out["steps"].append({"title": f"Disable {' and '.join(legacy)} on the server",
                                 "detail": "Windows Server (Schannel): run these, then reboot. On appliances and load balancers, change the TLS/SSL profile instead.",
                                 "commands": cmds})
    if acc.get("TLS 1.2") is False and acc.get("TLS 1.3") is False:
        F.append(_f("critical", "Server supports neither TLS 1.2 nor TLS 1.3", "Current clients (and Microsoft 365) require TLS 1.2+. Enable TLS 1.2.",
                    headline=f"{hostport} doesn't support TLS 1.2 or 1.3. Modern clients can't connect."))
        base = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server"
        out["steps"].append({"title": "Enable TLS 1.2 on the server (before disabling anything)",
                             "detail": "Windows Server 2008 R2/2012 (Schannel): run these, then reboot. Appliances: update the firmware / TLS profile.",
                             "commands": [f"$k = '{base}'\nNew-Item $k -Force | Out-Null\n"
                                          "New-ItemProperty $k -Name Enabled -Value 1 -PropertyType DWord -Force | Out-Null\n"
                                          "New-ItemProperty $k -Name DisabledByDefault -Value 0 -PropertyType DWord -Force | Out-Null"]})
    elif acc.get("TLS 1.3"):
        F.append(_f("ok", "TLS 1.3 supported", ""))
    neg = out["negotiated"]
    cipher = neg.get("cipher") or ""
    if re.search(r"RC4|3DES|DES-CBC|NULL|EXPORT|MD5", cipher):
        F.append(_f("warning", f"Weak cipher negotiated: {cipher}", "Disable RC4/3DES/NULL/EXPORT cipher suites on the server."))

    # --- protocol-specific
    if http_host:
        h = main.get("http") or {}
        out["http"] = h
        if h.get("hsts"):
            m = re.search(r"max-age=\"?(\d+)", h["hsts"], re.I)
            age = int(m.group(1)) if m else 0
            F.append(_f("ok" if age >= 15552000 else "info", "HSTS is enabled" if age else "HSTS header present but max-age is 0",
                        f"Strict-Transport-Security: {h['hsts']}" + ("" if age >= 15552000 or not age else " (max-age under 180 days is weaker than recommended)")))
        elif not h.get("error"):
            F.append(_f("info", "No HSTS header", "Strict-Transport-Security tells browsers to always use HTTPS for this site. Optional, but recommended for public sites."))
    if is_rdp:
        rdp = main.get("rdp") or {}
        sel = rdp.get("selected")
        out["rdp"] = {"selected": RDP_PROTOCOLS.get(sel, str(sel)), "nla_required": nla}
        if nla is True:
            F.append(_f("ok", "Network Level Authentication (NLA) is required", "Users must authenticate before a Windows session is created, which blocks pre-login attacks."))
        elif nla is False:
            F.insert(0, _f("warning", "NLA (Network Level Authentication) is not required",
                        "The server accepts RDP with plain TLS, so anyone who can reach it gets a Windows logon screen without authenticating first. That exposes it to pre-authentication exploits and password spraying.",
                        headline=f"RDP on {hostport} doesn't require Network Level Authentication (NLA)."))
            out["steps"].append({"title": "Require NLA for RDP",
                                 "commands": ["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"]})
        if ipaddress.ip_address(ip).is_global:
            F.append(_f("critical", "RDP is reachable from the internet", f"{ip} is a public address. Exposed RDP is a top ransomware entry point. Put it behind a VPN or an RD Gateway with MFA.",
                        headline=f"RDP is exposed to the internet on {ip}. Exposed RDP is a top ransomware entry point."))
        if leaf_self_signed or not verify["ok"]:
            out["steps"].append({"title": "See which certificate RDP is using",
                                 "detail": "Compare the thumbprint with the one shown below. To use a CA-issued certificate, put its thumbprint here.",
                                 "commands": ["Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting | Select-Object TerminalName, SSLCertificateSHA1Hash",
                                              "$ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter \"TerminalName='RDP-tcp'\"; "
                                              "Set-CimInstance -InputObject $ts -Property @{SSLCertificateSHA1Hash='<THUMBPRINT>'}"]})

    if any(f["severity"] in ("critical", "warning") and ("expire" in f["title"].lower()) for f in F):
        out["steps"].insert(0, {"title": "Renew the certificate and install it everywhere it's used",
                                "detail": f"Find the current certificate on Windows servers by its thumbprint ({L['sha1']}). "
                                          "Remember load balancers, firewalls/VPN appliances, Exchange, RD Gateway and ADFS often hold their own copy.",
                                "commands": [f"Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Thumbprint -eq '{L['sha1']}' | Format-List Subject, Issuer, NotAfter, Thumbprint",
                                             "Get-ChildItem Cert:\\LocalMachine\\My | Where-Object NotAfter -lt (Get-Date).AddDays(30) | Format-List Subject, NotAfter, Thumbprint"]})
    if any(f["severity"] == "critical" and "doesn't cover" in f["title"] for f in F):
        out["steps"].append({"title": "Reissue the certificate with the right name",
                             "detail": f"Add {host} to the Subject Alternative Names when you request the new certificate (CN alone is ignored by modern clients)."})

    sev, headline = _pick_headline(F, "")
    if not headline:
        best = neg.get("version") or "TLS"
        headline = (f"Certificate for {leaf_name} is valid and trusted. Expires {_in_days(days)} ({issuer_name}), {best}."
                    if verify["ok"] else f"Certificate for {leaf_name} expires {_in_days(days)} ({issuer_name}).")
    out["severity"], out["headline"] = sev, headline
    out["subline"] = " · ".join(filter(None, [proto["label"], f"{host}:{port}", ip if ip != host else None,
                                              f"negotiated {neg.get('version')} {cipher}".strip()]))
    return out


def _rdp_nla_required(ip: str, port: int) -> bool | None:
    """Ask for TLS only (no CredSSP). HYBRID_REQUIRED_BY_SERVER = NLA is enforced."""
    try:
        sock = socket.create_connection((ip, port), timeout=TLS_TIMEOUT)
        try:
            neg = _rdp_negotiate(sock, 1)
        finally:
            sock.close()
    except (OSError, _ProtoError):
        return None
    if neg.get("failure") in (5, 6):
        return True
    if neg.get("selected") == 1:
        return False
    return None


# ====================================================================== safe HTTP fetch
def _pinned_send(url: str, ip: str, verify: bool, timeout: float, max_bytes: int):
    from ..core.outbound import read_capped
    """GET url but connect to the pre-checked IP (no second DNS lookup = no DNS rebinding)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    ip_host = f"[{ip}]" if ":" in ip else ip
    netloc = ip_host + (f":{parts.port}" if parts.port else "")
    pinned = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
    host_header = (f"[{host}]" if ":" in host else host) + (f":{parts.port}" if parts.port else "")
    ext = {"sni_hostname": host} if parts.scheme == "https" and not is_ip(host) else {}
    client = httpx.Client(verify=verify, follow_redirects=False, trust_env=False, http2=False,
                          timeout=httpx.Timeout(timeout, connect=min(timeout, 6.0)))
    t0 = time.monotonic()
    try:
        req = client.build_request("GET", pinned, headers={"Host": host_header, "User-Agent": UA, "Accept": "*/*",
                                                           "Accept-Encoding": "gzip, deflate"}, extensions=ext)
        resp = client.send(req, stream=True)
        ttfb = (time.monotonic() - t0) * 1000
        tls = None
        try:
            so = resp.extensions["network_stream"].get_extra_info("ssl_object")
            if so is not None:
                der = so.getpeercert(True)
                tls = {"version": so.version(), "cipher": (so.cipher() or [None])[0]}
                if der:
                    ci = _cert_info(der, host)
                    tls["cert"] = {"subject": ci["subject"], "issuer": ci["issuer"], "days_left": ci["days_left"],
                                   "not_after": ci["not_after"], "hostname_match": ci["hostname_match"]}
        except (KeyError, AttributeError, ValueError):
            pass
        try:
            body, truncated = read_capped(resp, max_bytes, t0 + timeout * 2)
        except httpx.HTTPError:
            body, truncated = b"", True
        total = (time.monotonic() - t0) * 1000
        resp.close()
        return resp, body, {"ttfb_ms": round(ttfb), "total_ms": round(total), "tls": tls, "truncated": truncated,
                            "content_type": resp.headers.get("content-type", "")}
    finally:
        client.close()


def _safe_get(url: str, max_bytes: int, timeout: float) -> tuple[int, bytes, dict]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Only http:// and https:// URLs are supported.")
    ip = _resolve_safe(_clean_host(parts.hostname), allow_private=False)[0]
    try:
        resp, body, meta = _pinned_send(url, ip, True, timeout, max_bytes)
    except httpx.HTTPError as exc:
        raise ValueError(f"Fetch failed: {exc}") from exc
    return resp.status_code, body, meta


# ====================================================================== port check
PORT_NAMES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPCbind", 123: "NTP", 135: "RPC endpoint mapper", 137: "NetBIOS name", 138: "NetBIOS datagram",
    139: "NetBIOS session (SMB)", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos password change",
    465: "SMTPS", 500: "IKE (IPsec VPN)", 587: "SMTP submission", 593: "RPC over HTTP", 636: "LDAPS", 853: "DNS over TLS",
    993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "Microsoft SQL Server", 1723: "PPTP VPN", 2375: "Docker API (unencrypted)",
    3268: "Global Catalog", 3269: "Global Catalog (TLS)", 3306: "MySQL", 3389: "RDP", 4443: "HTTPS alt / VPN portal",
    4500: "IPsec NAT-T", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)", 6379: "Redis",
    8080: "HTTP alt", 8443: "HTTPS alt / management", 9389: "AD Web Services", 10443: "HTTPS alt / SSL VPN", 27017: "MongoDB",
}
UDP_USUALLY = {53: "DNS", 123: "NTP", 161: "SNMP", 500: "IKE", 1194: "OpenVPN", 4500: "IPsec NAT-T"}
EXPOSED_CRITICAL = {
    3389: "Exposed RDP is a top ransomware entry point (password spraying, pre-auth exploits).",
    445: "SMB on the internet is how WannaCry-style worms spread, and it leaks NTLM hashes.",
    139: "NetBIOS/SMB should never be reachable from the internet.",
    135: "RPC endpoint mapper exposed to the internet enables remote Windows attacks.",
    5985: "WinRM gives remote PowerShell. Exposed, it's a brute-force and lateral movement target.",
    5986: "WinRM gives remote PowerShell. Exposed, it's a brute-force and lateral movement target.",
    23: "Telnet sends passwords in clear text.",
    1433: "Database servers should not be reachable from the internet.",
    3306: "Database servers should not be reachable from the internet.",
    5432: "Database servers should not be reachable from the internet.",
    5900: "VNC is frequently brute-forced and often has weak or no passwords.",
    6379: "Redis has no authentication by default and is routinely hijacked.",
    27017: "MongoDB instances on the internet are routinely wiped and ransomed.",
    2375: "An open Docker API gives full control of the host.",
}
EXPOSED_WARNING = {
    21: "FTP sends credentials in clear text. Use SFTP/FTPS.",
    22: "SSH is fine when keys-only and patched, but it's constantly brute-forced. Restrict source IPs if you can.",
    389: "LDAP from the internet exposes the directory. Should be internal only.",
    636: "LDAPS from the internet exposes the directory. Should be internal only.",
    3268: "Global Catalog should be internal only.", 3269: "Global Catalog should be internal only.",
    88: "Kerberos from the internet suggests a domain controller is exposed.",
    464: "Kerberos password change from the internet suggests a domain controller is exposed.",
    1723: "PPTP is an obsolete, broken VPN protocol. Replace it.",
    161: "SNMP exposed to the internet leaks device details.",
}
_EGRESS: dict = {"ip": None, "at": 0.0}


def _egress_ip() -> str | None:
    """Public IP this server's TCP connections come from (Cloudflare trace; Google DNS as a fallback)."""
    if time.monotonic() - _EGRESS["at"] < 600:
        return _EGRESS["ip"]
    ip = None
    try:
        r = httpx.get("https://1.1.1.1/cdn-cgi/trace", timeout=3.0, headers={"user-agent": UA})
        m = re.search(r"^ip=(\S+)$", r.text, re.M)
        if m and is_ip(m.group(1)):
            _EGRESS.update(ip=m.group(1), at=time.monotonic())
            return m.group(1)
    except httpx.HTTPError:
        pass
    try:
        q = dns.message.make_query("o-o.myaddr.l.google.com", "TXT")
        r = dns.query.udp(q, "216.239.32.10", timeout=2.5)
        for rr in r.answer:
            for rd in rr:
                val = b"".join(rd.strings).decode()
                if is_ip(val):
                    ip = val
    except Exception:  # noqa: BLE001 - cosmetic only
        ip = None
    _EGRESS.update(ip=ip, at=time.monotonic())
    return ip


def _parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for part in re.split(r"[,\s;]+", (value or "").strip()):
        if not part:
            continue
        m = re.match(r"^(\d+)(?:-(\d+))?$", part)
        if not m:
            raise ValueError(f"'{part}' is not a port or range (use e.g. 80,443,8000-8010).")
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= a <= 65535 and 1 <= b <= 65535) or b < a:
            raise ValueError(f"'{part}' is not a valid port range (1-65535).")
        if b - a > 64:
            raise ValueError("Maximum 64 ports per check.")
        ports.extend(range(a, b + 1))
    ports = list(dict.fromkeys(ports))
    if not ports:
        raise ValueError("Enter at least one port.")
    if len(ports) > 64:
        raise ValueError(f"Maximum 64 ports per check ({len(ports)} given).")
    return ports


# 5 s, not 3 s: Linux retransmits an unanswered SYN after ~1 s and ~3 s, so a 3 s cap turns a host that answers the
# second retransmit (~3.1 s) into a false "filtered". Probes still run in parallel, so the whole check stays ~5 s.
PORT_TIMEOUT = 5.0


def _probe_port(ip: str, port: int, timeout: float = PORT_TIMEOUT) -> dict:
    out = {"port": port, "service": PORT_NAMES.get(port), "state": None, "ms": None, "banner": None, "error": None}
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
        out["ms"] = round((time.monotonic() - t0) * 1000)
        out["state"] = "open"
        try:  # passive banner grab: send nothing, read what the service volunteers
            s.settimeout(1.0)
            data = s.recv(256)
            if data:
                printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
                if printable < len(data) * 0.8:
                    out["banner"] = f"(binary data, {len(data)} bytes)"
                else:
                    text = "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in data.decode("utf-8", "replace"))
                    out["banner"] = text.strip()[:256] or None
        except OSError:
            pass
    except ConnectionRefusedError:
        out["ms"] = round((time.monotonic() - t0) * 1000)
        out["state"] = "closed"
    except (socket.timeout, TimeoutError):
        out["state"] = "filtered"
    except OSError as exc:
        out["ms"] = round((time.monotonic() - t0) * 1000)
        out["state"] = "unreachable"
        out["error"] = exc.strerror or str(exc)
    finally:
        s.close()
    return out


def _svc(p: dict) -> str:
    return f"{p['port']} ({p['service']})" if p["service"] else str(p["port"])


def port_check(target: str, ports: str) -> dict:
    host, port_in_host = _parse_host_port(target)
    plist = _parse_ports(ports if (ports or "").strip() else str(port_in_host or ""))
    ips = _resolve_safe(host, allow_private=True)
    ip = ips[0]
    public = ipaddress.ip_address(ip).is_global
    with ThreadPoolExecutor(max_workers=min(64, len(plist)) + 1) as ex:
        egress_f = ex.submit(_egress_ip)
        results = list(ex.map(lambda p: _probe_port(ip, p), plist))
        egress = egress_f.result()
    by_state = {s: [r for r in results if r["state"] == s] for s in ("open", "closed", "filtered", "unreachable")}
    F: list[dict] = []
    steps: list[dict] = []
    who = host if host == ip else f"{host} ({ip})"

    exposed_crit = [r for r in by_state["open"] if public and r["port"] in EXPOSED_CRITICAL]
    exposed_warn = [r for r in by_state["open"] if public and r["port"] in EXPOSED_WARNING]
    for r in exposed_crit:
        F.append(_f("critical", f"{_svc(r)} is open to the internet", EXPOSED_CRITICAL[r["port"]] +
                    " Close it at the firewall, or allow only known source IPs / put it behind a VPN or gateway with MFA."))
    for r in exposed_warn:
        F.append(_f("warning", f"{_svc(r)} is open to the internet", EXPOSED_WARNING[r["port"]]))
    if exposed_crit:
        names = ", ".join(_svc(r) for r in exposed_crit[:3]) + (" and more" if len(exposed_crit) > 3 else "")
        verb = "is" if len(exposed_crit) == 1 else "are"
        first = exposed_crit[0]["port"]
        reason = EXPOSED_CRITICAL[first].split(" (")[0].rstrip(".")
        F[0]["headline"] = f"{names} {verb} OPEN to the internet on {ip}. {reason}."
        steps.append({"title": "Close the exposed port at the edge firewall",
                      "detail": "Remove the NAT/port-forward rule, or restrict it to known source IPs. Then re-run this check. On the Windows host you can see which firewall rules allow it:",
                      "commands": [f"Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Get-NetFirewallPortFilter | Where-Object LocalPort -eq {first}"]})
        if first == 3389:
            steps.append({"title": "Check for brute-force attempts", "detail": "Failed logons (4625) from unknown IPs mean it's already being attacked.",
                          "commands": ["Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 | Format-Table TimeCreated, Message -Wrap"]})

    udp_hits = [p for p in plist if p in UDP_USUALLY]
    if udp_hits:
        F.append(_f("info", f"Ports {', '.join(map(str, udp_hits))} are normally UDP",
                    "This check uses TCP only. UDP can't be tested this way (no handshake, a silent drop and an open port look the same), "
                    "so a closed or filtered result here says nothing about UDP. IPsec IKE (500) and NAT-T (4500) are UDP; OpenVPN is usually UDP 1194."))

    n = len(results)
    if len(by_state["open"]) == n and n >= 8:
        F.append(_f("info", "Every port answered as open", "When every port is open, a firewall or proxy may be accepting all connections on the host's behalf (SYN proxy / tarpit). The banners help tell real services apart."))

    for r in by_state["unreachable"]:
        F.append(_f("warning", f"{_svc(r)}: network unreachable", f"{r['error']}. The MSPGather server has no route to {ip}, or a router sent ICMP unreachable."))

    def single_phrase(r: dict) -> str:
        return {"open": f"Port {_svc(r)} is open on {who}, answered in {r['ms']} ms.",
                "closed": f"Port {_svc(r)} is closed on {who}: the host answered, but nothing is listening (or a firewall rejects it).",
                "filtered": f"Port {_svc(r)} is filtered on {who}: no response in {PORT_TIMEOUT:.0f}s. A firewall is dropping it, or the host is offline.",
                "unreachable": f"Port {_svc(r)} can't be reached on {who}: network unreachable."}[r["state"]]

    if exposed_crit:
        pass
    elif n == 1:
        r = results[0]
        F.append(_f({"open": "ok", "closed": "warning", "filtered": "warning", "unreachable": "warning"}[r["state"]],
                    f"{_svc(r)}: {r['state']}", "", headline=single_phrase(r)))
    elif not by_state["open"] and len(by_state["filtered"]) == n:
        F.append(_f("warning", "Nothing answered", "Every port timed out. The host is down, the address is wrong, or a firewall drops everything from this network.",
                    headline=f"Nothing answered on {who}: all {n} ports are filtered (no response). The host is down or a firewall drops everything from here."))
    elif not by_state["open"]:
        F.append(_f("warning", "No ports open", "", headline=f"None of the {n} ports are open on {who} ({len(by_state['closed'])} closed, {len(by_state['filtered'])} filtered)."))
    else:
        opened = ", ".join(_svc(r) for r in by_state["open"][:6]) + (" …" if len(by_state["open"]) > 6 else "")
        rest = n - len(by_state["open"])
        F.append(_f("ok" if not rest else "info", f"{len(by_state['open'])} of {n} ports open", "",
                    headline=f"{len(by_state['open'])} of {n} ports open on {who}: {opened}." + (f" {rest} closed or filtered." if rest else "")))
    if by_state["filtered"] or by_state["closed"]:
        steps.append({"title": "Compare from inside the network",
                      "detail": "Run this from a machine on the same LAN as the server. If it's open there but not here, the edge firewall/NAT is the problem; if it's closed there too, the service isn't listening.",
                      "commands": [f"Test-NetConnection -ComputerName {ip} -Port {(by_state['filtered'] or by_state['closed'])[0]['port']}",
                                   "Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, OwningProcess"]})

    sev, headline = _pick_headline(F, f"Checked {n} ports on {who}.")
    if exposed_warn and not exposed_crit:
        names = ", ".join(_svc(r) for r in exposed_warn[:3])
        one = len(exposed_warn) == 1
        headline += f" {names} {'is' if one else 'are'} reachable from the internet; restrict {'it' if one else 'them'} if you can."
    return {"host": host, "ip": ip, "other_ips": ips[1:], "public": public, "egress_ip": egress, "results": results,
            "counts": {k: len(v) for k, v in by_state.items()}, "findings": F, "steps": steps, "severity": sev, "headline": headline,
            "subline": f"Tested FROM the MSPGather server's network" + (f" ({egress})" if egress else "") +
                       f" to {ip}" + (" (public address)" if public else " (private address)") + ". Results can differ from inside the client's network."}


# ====================================================================== domain registration (RDAP)
EPP_STATUS: dict[str, tuple[str, str, str]] = {
    # key: (severity, display name, plain-English meaning)
    "ok": ("ok", "ok", "Normal state: no pending operations or restrictions."),
    "active": ("ok", "active", "Normal state: the domain is active."),
    "clienthold": ("critical", "clientHold", "The REGISTRAR has suspended the domain: it is removed from DNS and does NOT resolve. Usual causes: unpaid renewal, failed registrant email verification (ICANN), or an abuse complaint. Contact the registrar."),
    "serverhold": ("critical", "serverHold", "The REGISTRY has suspended the domain: it does NOT resolve. Usually legal/abuse action or a registry-level issue. The registrar has to resolve it with the registry."),
    "redemptionperiod": ("critical", "redemptionPeriod", "The domain expired and has been deleted. It doesn't resolve. The registrar can still restore it, usually for a restoration fee, for about 30 days."),
    "pendingdelete": ("critical", "pendingDelete", "The domain is about to be purged (typically within 5 days) and released for anyone to register. It normally can no longer be restored."),
    "pendingrestore": ("warning", "pendingRestore", "A restore out of redemption has been requested and is waiting to complete."),
    "inactive": ("warning", "inactive", "No name servers are delegated, so the domain does not resolve."),
    "autorenewperiod": ("info", "autoRenewPeriod", "The registry auto-renewed the domain at expiry. The registrar can still delete it during this grace period (typically up to 45 days) if the renewal isn't paid."),
    "renewperiod": ("info", "renewPeriod", "Recently renewed (renewal grace period)."),
    "addperiod": ("info", "addPeriod", "Newly registered (within the add grace period)."),
    "transferperiod": ("info", "transferPeriod", "Recently transferred to a new registrar (grace period)."),
    "pendingtransfer": ("warning", "pendingTransfer", "A transfer to another registrar is in progress. If nobody requested this, contact the registrar immediately: it may be a hijack attempt."),
    "pendingrenew": ("info", "pendingRenew", "A renewal request is being processed."),
    "pendingupdate": ("info", "pendingUpdate", "An update request is being processed."),
    "pendingcreate": ("info", "pendingCreate", "The registration request is being processed."),
    "clienttransferprohibited": ("ok", "clientTransferProhibited", "Transfer lock (set by the registrar): the domain can't be moved to another registrar until it's unlocked. Protects against hijacking."),
    "servertransferprohibited": ("ok", "serverTransferProhibited", "Transfer lock set by the registry."),
    "clientdeleteprohibited": ("ok", "clientDeleteProhibited", "Deletion lock set by the registrar."),
    "serverdeleteprohibited": ("ok", "serverDeleteProhibited", "Deletion lock set by the registry."),
    "clientupdateprohibited": ("info", "clientUpdateProhibited", "Update lock set by the registrar: changes (including name servers) are blocked until it's removed. Remember this when moving DNS hosting."),
    "serverupdateprohibited": ("info", "serverUpdateProhibited", "Update lock set by the registry: changes (including name servers) need the registry's help (registry lock)."),
    "clientrenewprohibited": ("warning", "clientRenewProhibited", "The registrar is blocking renewal. Common on domains the registrar itself holds or lists for sale (registrar inventory, expired-domain auctions); also used during disputes or before deletion. If a client owns this domain, it can't be renewed until the registrar lifts it."),
    "serverrenewprohibited": ("warning", "serverRenewProhibited", "The registry is blocking renewal, for example during a dispute or legal hold, or as part of a registry lock. If it isn't lifted the domain can't be renewed."),
}
# ccTLD registries that don't use EPP client transfer locks (transfers use auth codes / registrar tags instead).
_NO_CLIENT_LOCK_TLDS = {"uk", "de", "eu", "nl", "au", "nz", "ch", "at", "be", "fr", "se", "no", "dk", "fi", "jp"}
_DOH_URLS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query")


def _rdap_tlds() -> set[str] | None:
    """TLDs with an RDAP service, from IANA's bootstrap file (cached for a day)."""
    from ..core import rdap
    svc = rdap.services("dns")
    return {str(t).lower() for entries, _ in svc for t in entries} if svc else None


def _doh(name: str, rtype: str, cd: bool = False) -> dict:
    """Raw DoH query with DNSSEC OK; cd=True disables validation (to inspect broken zones)."""
    q = dns.message.make_query(dns.name.from_text(name), rtype, want_dnssec=True)
    if cd:
        q.flags |= dns.flags.CD
    want = dns.rdatatype.from_text(rtype)
    last = "error"
    for url in _DOH_URLS:
        try:
            r = httpx.post(url, content=q.to_wire(), timeout=6.0,
                           headers={"content-type": "application/dns-message", "accept": "application/dns-message"})
            r.raise_for_status()
            m = dns.message.from_wire(r.content)
            return {"rcode": dns.rcode.to_text(m.rcode()), "ad": bool(m.flags & dns.flags.AD),
                    "answers": [rd for rr in m.answer if rr.rdtype == want for rd in rr], "via": url}
        except Exception as exc:  # noqa: BLE001 - try the next DoH server
            last = str(exc)
    return {"rcode": "ERROR", "ad": False, "answers": [], "error": last}


def _dnssec_live(domain: str) -> dict:
    with ThreadPoolExecutor(4) as ex:
        ds_f = ex.submit(_doh, domain, "DS", True)
        key_f = ex.submit(_doh, domain, "DNSKEY", True)
        val_f = ex.submit(_doh, domain, "SOA", False)
        raw_f = ex.submit(_doh, domain, "SOA", True)
        ds, keys, val, raw = ds_f.result(), key_f.result(), val_f.result(), raw_f.result()
    ds_tags = sorted({d.key_tag for d in ds["answers"]})
    key_tags = sorted({dns.dnssec.key_id(k) for k in keys["answers"]})
    return {"ds": [d.to_text() for d in ds["answers"]], "ds_tags": ds_tags,
            "dnskey_count": len(keys["answers"]), "dnskey_tags": key_tags,
            "ds_matches_key": bool(set(ds_tags) & set(key_tags)) if ds_tags and key_tags else None,
            "validated": val["ad"], "validating_rcode": val["rcode"], "raw_rcode": raw["rcode"],
            "error": ds.get("error") if ds["rcode"] == "ERROR" else None}


def _rdap_fetch(domain: str) -> tuple[int | None, dict | None, str | None, str | None]:
    from ..core import rdap  # straight to the registry via IANA's bootstrap
    try:
        r = rdap.get("dns", domain, timeout=10.0)
    except httpx.HTTPError as exc:
        return None, None, None, f"RDAP lookup failed: {exc}"
    data = None
    try:
        data = r.json() if r.status_code == 200 else None
    except ValueError:
        return r.status_code, None, str(r.url), "RDAP server returned something that isn't JSON."
    return r.status_code, data, str(r.url), None


def _ev_date(v: str | None) -> str | None:
    return v[:10] if v else None


def _days_until(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except ValueError:
        return None


def _live_ns(res, domain: str) -> tuple[list[str], dict]:
    """NS records with DNSSEC checking disabled, so a broken DNSSEC chain doesn't hide the delegation."""
    r = _doh(domain, "NS", cd=True)
    if r["rcode"] == "ERROR":
        rd, meta = resolve(res, domain, "NS")
        return sorted({x.target.to_text(omit_final_dot=True).lower() for x in rd}), meta
    names = sorted({x.target.to_text(omit_final_dot=True).lower() for x in r["answers"]})
    status = {"NOERROR": "ok" if names else "noanswer", "NXDOMAIN": "nxdomain"}.get(r["rcode"], "servfail")
    return names, {"status": status, "error": None if status != "servfail" else f"DNS returned {r['rcode']}"}


def domain_registration(value: str) -> dict:
    if not (value or "").strip():
        raise ValueError("Enter a domain name.")
    name = normalize_domain(value)
    domain = registered_domain(name)
    tld = domain.rsplit(".", 1)[-1]
    res = make_resolver()
    with ThreadPoolExecutor(4) as ex:
        rdap_f = ex.submit(_rdap_fetch, domain)
        boot_f = ex.submit(_rdap_tlds)
        ns_f = ex.submit(_live_ns, res, domain)
        sec_f = ex.submit(_dnssec_live, domain)
        status, data, source, err = rdap_f.result()
        tlds = boot_f.result()
        (live_ns, ns_meta), live_sec = ns_f.result(), sec_f.result()
    F: list[dict] = []
    steps: list[dict] = []
    out: dict = {"domain": domain, "input": name, "tld": tld, "rdap_source": source, "findings": F, "steps": steps,
                 "live_ns": live_ns, "live_ns_status": ns_meta["status"], "dnssec": {"live": live_sec}}
    if name != domain:
        out["note"] = f"Checked the registered domain {domain} (you entered {name})."
    has_rdap = tlds is None or tld in tlds

    if data is None:
        dns_exists = ns_meta["status"] in ("ok", "noanswer")
        if status == 404 and has_rdap and tlds is not None:
            out["registered"] = False
            if dns_exists:
                F.append(_f("warning", "RDAP has no record, but DNS answers", "The registry returned 'not found', yet the domain resolves. RDAP data may lag for brand-new registrations.",
                            headline=f"The registry has no RDAP record for {domain}, but it resolves in DNS."))
            else:
                F.append(_f("info", f"{domain} is not registered", "The registry has no record of it and it doesn't exist in DNS. It may be available to register (check for typos first).",
                            headline=f"{domain} is not registered (the registry has no record and DNS says it doesn't exist)."))
        elif not has_rdap or status == 404:
            out["rdap_available"] = False
            F.append(_f("info", f"The .{tld} registry doesn't publish RDAP", "Registration data (registrar, expiry, status) isn't available over RDAP for this TLD. Check the registry's WHOIS instead (link below). Live DNS checks below still apply.",
                        headline=f"The .{tld} registry doesn't publish RDAP; check the registry's WHOIS for {domain}." if dns_exists else
                        f"{domain} doesn't exist in DNS, and the .{tld} registry doesn't publish RDAP. Check the registry's WHOIS."))
            out["whois_link"] = f"https://www.iana.org/domains/root/db/{tld}.html"
        else:
            F.append(_f("warning", "RDAP lookup failed", err or f"RDAP returned HTTP {status}.", headline=f"Couldn't get registration data for {domain}: {err or f'RDAP returned HTTP {status}'}."))
        _dnssec_findings(out, F, steps, domain, None)
        if out.get("registered") is not False:
            _ns_findings(F, domain, None, live_ns, ns_meta)
        out["severity"], out["headline"] = _pick_headline(F, f"Checked {domain}.")
        out["subline"] = "Registration data: " + ("not available over RDAP" if out.get("rdap_available") is False else "registry RDAP") + " · live DNS checked over DNS-over-HTTPS"
        return out

    out["registered"] = True
    out["rdap_available"] = True
    # --- registrar
    registrar: dict = {}
    for e in data.get("entities") or []:
        if "registrar" in (e.get("roles") or []):
            registrar = {"name": _vcard(e).get("name") or e.get("handle"), "iana_id": None, "abuse": None, "url": None}
            for pid in e.get("publicIds") or []:
                if "iana" in str(pid.get("type", "")).lower():
                    registrar["iana_id"] = pid.get("identifier")
            for ln in e.get("links") or []:
                if ln.get("rel") in ("about", "self") and str(ln.get("href", "")).startswith("http") and "rdap" not in ln.get("href", ""):
                    registrar["url"] = ln.get("href")
            for sub in e.get("entities") or []:
                if "abuse" in (sub.get("roles") or []):
                    registrar["abuse"] = _vcard(sub)
            break
    out["registrar"] = registrar
    reg_name = registrar.get("name") or "unknown registrar"
    # --- dates
    events = {str(e.get("eventAction", "")).lower(): e.get("eventDate") for e in data.get("events") or []}
    expires = events.get("expiration") or events.get("registrar expiration")
    out["events"] = {"registered": _ev_date(events.get("registration")), "updated": _ev_date(events.get("last changed")),
                     "expires": _ev_date(expires), "transferred": _ev_date(events.get("transfer")),
                     "rdap_updated": _ev_date(events.get("last update of rdap database"))}
    days = _days_until(expires)
    out["days_left"] = days
    # --- statuses
    statuses = []
    keys = set()
    for s in data.get("status") or []:
        k = re.sub(r"[^a-z]", "", str(s).lower())
        keys.add(k)
        sev, label, meaning = EPP_STATUS.get(k, ("info", str(s), "Not in the knowledge base. See icann.org/epp for registry-specific codes."))
        statuses.append({"code": label, "raw": s, "severity": sev, "meaning": meaning})
    out["statuses"] = statuses
    if "clienthold" in keys or "serverhold" in keys:
        who = "registry" if "serverhold" in keys else "registrar"
        F.append(_f("critical", f"Domain is on hold ({'serverHold' if who == 'registry' else 'clientHold'}): suspended, NOT resolving",
                    EPP_STATUS["serverhold" if who == "registry" else "clienthold"][2],
                    headline=f"{domain} is suspended by the {who} ({'serverHold' if who == 'registry' else 'clientHold'}): it does not resolve. Contact {reg_name}."))
        steps.append({"title": f"Contact {reg_name}", "detail": "Ask why the domain is on hold. Check the registrant contact's mailbox for an ICANN verification email or an unpaid invoice."})
    if "redemptionperiod" in keys or "pendingdelete" in keys:
        k = "pendingdelete" if "pendingdelete" in keys else "redemptionperiod"
        F.append(_f("critical", f"Domain expired and is being deleted ({EPP_STATUS[k][1]})", EPP_STATUS[k][2],
                    headline=f"{domain} has EXPIRED and is about to be lost ({EPP_STATUS[k][1]}). Contact {reg_name} to restore it now."))
        steps.append({"title": f"Restore the domain through {reg_name} immediately", "detail": "Redemption restores cost extra and take time; once pendingDelete ends the name is released to the public."})
    registry_lock = {"serverdeleteprohibited", "servertransferprohibited", "serverupdateprohibited", "serverrenewprohibited"} <= keys
    reg_short = reg_name.rstrip(".")
    status_headlines = {
        "pendingTransfer": f"A transfer of {domain} to another registrar is in progress (pendingTransfer). If nobody requested it, contact {reg_short} now.",
        "inactive": f"{domain} has no name servers delegated (inactive), so it does not resolve.",
        "clientRenewProhibited": f"Renewal of {domain} is blocked (clientRenewProhibited) by {reg_short}. Usual for registrar-held or for-sale domains; "
                                 "if a client owns it, ask the registrar to lift it.",
        "serverRenewProhibited": f"Renewal of {domain} is blocked by the registry (serverRenewProhibited).",
        "pendingRestore": f"{domain} is being restored after expiry (pendingRestore).",
    }
    for st in statuses:
        if st["severity"] in ("warning",) and st["code"] in status_headlines:
            if st["code"] == "serverRenewProhibited" and registry_lock:
                F.append(_f("info", "Registry lock: all server*Prohibited statuses are set (including serverRenewProhibited)",
                            "The registry has frozen the domain against changes, transfer, deletion and renewal by the registrar. That's a deliberate "
                            "high-security registry lock; changes (and renewals) go through the registry's unlock process."))
                continue
            F.append(_f("warning", f"Status {st['code']}", st["meaning"], headline=status_headlines[st["code"]]))
    if days is not None:
        exp = out["events"]["expires"]
        if days < 0:
            F.append(_f("critical", f"Registration expired {_in_days(days)} ({exp})", "Renew it at the registrar right away; email and websites stop when the registrar parks or suspends it.",
                        headline=f"{domain} expired {_in_days(days)} (registrar: {reg_name}). Renew it now."))
        elif days < 7:
            F.append(_f("critical", f"Registration expires {_in_days(days)} ({exp})", "Renew now. Auto-renew status isn't published in RDAP, so check the registrar account and payment card.",
                        headline=f"{domain} expires {_in_days(days)} (registrar: {reg_name}). Renew it now."))
        elif days < 30:
            F.append(_f("warning", f"Registration expires {_in_days(days)} ({exp})", "Auto-renew status isn't published in RDAP. Check the registrar account and that the payment card is valid.",
                        headline=f"{domain} expires {_in_days(days)} (registrar: {reg_name}). Auto-renew status unknown, so check the registrar account."))
        else:
            F.append(_f("ok", f"Registration valid until {exp} ({days} days)", ""))
        if days < 30:
            steps.append({"title": f"Log in to {reg_name} and renew {domain}", "detail": "Confirm auto-renew is on and the payment method is valid. If nobody knows the registrar login, the abuse/support contact below can help with account recovery."})
    else:
        F.append(_f("info", "No expiry date published", "This registry doesn't publish the expiry date in RDAP."))
    locked = bool(keys & {"clienttransferprohibited", "servertransferprohibited"})
    no_epp_locks = tld in _NO_CLIENT_LOCK_TLDS
    out["transfer_lock"] = ("on" if locked else "not used by this registry" if no_epp_locks else
                            "off (normal for many ccTLDs)" if len(tld) == 2 else "off")
    if not locked and not keys & {"redemptionperiod", "pendingdelete"}:
        if no_epp_locks:
            F.append(_f("info", f"No transfer-lock status (normal for .{tld})",
                        f"The .{tld} registry doesn't use EPP client transfer locks; transfers are authorised another way (a transfer/auth code or registrar tag change). Nothing to fix."))
        elif len(tld) == 2:
            F.append(_f("info", "No transfer-lock status (clientTransferProhibited / serverTransferProhibited)",
                        f"Many country-code registries don't use this status. If the .{tld} registrar offers a 'domain lock' option, turn it on."))
        else:
            F.append(_f("info", "Transfer lock is off (no clientTransferProhibited)",
                        "Without a transfer lock the domain is easier to hijack via a fraudulent transfer. Enable 'Domain lock' at the registrar."))

    rdap_ns = sorted({str(n.get("ldhName", "")).lower().rstrip(".") for n in data.get("nameservers") or [] if n.get("ldhName")})
    out["rdap_ns"] = rdap_ns
    _ns_findings(F, domain, rdap_ns, live_ns, ns_meta)
    sec = data.get("secureDNS") or {}
    out["dnssec"]["rdap_signed"] = sec.get("delegationSigned")
    _dnssec_findings(out, F, steps, domain, sec.get("delegationSigned"))

    if not any(f["severity"] in ("critical", "warning") for f in F):
        exp_txt = f"Expires {_in_days(days)} ({out['events']['expires']})" if days is not None else "No expiry date published"
        F.append(_f("ok", "", "", headline=f"{domain} is registered and healthy. {exp_txt} at {reg_name.rstrip('.')}."))
    out["severity"], out["headline"] = _pick_headline(F, f"{domain} is registered at {reg_name}.")
    # The headline must name the problem the severity is about: if the worst finding carries no headline, use its title.
    worst = [f for f in F if f["severity"] == out["severity"] and f["title"]]
    if out["severity"] in ("critical", "warning") and worst and not any(f.get("headline") for f in worst):
        out["headline"] = f"{domain}: {worst[0]['title'][0].lower() + worst[0]['title'][1:]}."
    F[:] = [f for f in F if f["title"]]  # headline-only entries
    out["subline"] = " · ".join(filter(None, [f"Registrar: {reg_name}", f"Created {out['events']['registered']}" if out["events"]["registered"] else None,
                                              f"Expires {out['events']['expires']}" if out["events"]["expires"] else None]))
    return out


def _ns_findings(F: list, domain: str, rdap_ns: list[str] | None, live_ns: list[str], meta: dict) -> None:
    if meta["status"] == "nxdomain":
        F.append(_f("critical", f"{domain} doesn't exist in DNS (NXDOMAIN)", "The TLD has no delegation for it: expired, on hold, not registered, or no name servers set.",
                    headline=f"{domain} does not resolve (NXDOMAIN at the TLD)."))
        return
    if not live_ns:
        if meta["status"] in ("servfail", "timeout", "error"):
            F.append(_f("warning", f"Live NS lookup failed ({meta['status']})", meta.get("error") or "The name servers may be down or DNSSEC may be broken."))
        return
    if rdap_ns is None or not rdap_ns:
        return
    if set(rdap_ns) != set(live_ns):
        only_reg = sorted(set(rdap_ns) - set(live_ns))
        only_live = sorted(set(live_ns) - set(rdap_ns))
        F.append(_f("warning", "Name servers at the registry don't match the zone's NS records",
                    ("Only at registry: " + ", ".join(only_reg) + ". " if only_reg else "") +
                    ("Only in the zone: " + ", ".join(only_live) + ". " if only_live else "") +
                    "Resolvers use the registry's list to find the zone. A mismatch is typical mid-migration; if it persists, "
                    "some resolvers will get different (or stale) answers. Update the name servers at the registrar to match the DNS host."))
    else:
        F.append(_f("ok", "Registry name servers match the live NS records", ", ".join(live_ns)))


def _dnssec_findings(out: dict, F: list, steps: list, domain: str, rdap_signed: bool | None) -> None:
    live = out["dnssec"]["live"]
    if out.get("registered") is False:
        return
    confirmed = " Confirmed: validating resolvers return SERVFAIL for it right now." if live["validating_rcode"] == "SERVFAIL" else ""
    has_ds, has_key = bool(live["ds"]), live["dnskey_count"] > 0
    broken_validation = live["validating_rcode"] == "SERVFAIL" and live["raw_rcode"] in ("NOERROR", "NXDOMAIN")
    cmds = [f"Resolve-DnsName {domain} -Type DS -Server 1.1.1.1 -DnssecOk", f"Resolve-DnsName {domain} -Type DNSKEY -Server 1.1.1.1 -DnssecOk"]
    if has_ds and not has_key:
        F.append(_f("critical", "DNSSEC broken: DS record at the registry but the zone has no DNSKEY",
                    "The parent says the zone is signed, but the zone isn't. Every validating resolver (Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9, most ISPs) returns SERVFAIL, so the domain, its website and email fail for a large share of the internet. Typical cause: DNS hosting was moved without removing DS first." + confirmed,
                    headline=f"DNSSEC is broken for {domain}: the registry has a DS record but the zone isn't signed. Validating resolvers can't resolve it."))
    elif has_ds and has_key and live["ds_matches_key"] is False:
        F.append(_f("critical", "DNSSEC broken: the DS at the registry doesn't match any DNSKEY",
                    f"DS key tags {live['ds_tags']} vs DNSKEY tags {live['dnskey_tags']}. Validating resolvers return SERVFAIL. Usually a key rollover where the registrar's DS wasn't updated." + confirmed,
                    headline=f"DNSSEC is broken for {domain}: the DS record at the registry doesn't match the zone's keys. Validating resolvers can't resolve it."))
    elif broken_validation:
        F.append(_f("critical", "DNSSEC validation fails (SERVFAIL)", "Without validation the zone answers fine; with validation it fails. Signatures are expired or invalid, so validating resolvers can't resolve the domain.",
                    headline=f"DNSSEC validation fails for {domain}: validating resolvers return SERVFAIL, so the domain is unreachable for many users."))
    elif has_ds and live["validated"]:
        F.append(_f("ok", "DNSSEC is enabled and validates", f"DS key tag(s) {live['ds_tags']} match the zone's DNSKEY."))
    elif has_key and not has_ds:
        F.append(_f("info", "Zone is signed but DNSSEC isn't active", "The zone has DNSKEY records but no DS at the registry, so resolvers don't validate it. Harmless; add the DS at the registrar to turn DNSSEC on."))
    elif not has_ds and not has_key:
        F.append(_f("info", "DNSSEC is not enabled", "Optional. It protects against DNS spoofing, but must be managed carefully when changing DNS hosts."))
    if any(f["severity"] == "critical" and "DNSSEC" in f["title"] for f in F):
        steps.append({"title": "Fix DNSSEC at the registrar", "detail": "Fastest fix: remove the DS record at the registrar (DNSSEC off), wait for the DS TTL to expire, then re-enable signing at the DNS host and publish the new DS. Verify:",
                      "commands": cmds})
    if rdap_signed is True and not has_ds:
        F.append(_f("info", "RDAP says the delegation is signed, but no DS record was found live", "Recent change or a lookup problem; re-check later."))
    elif rdap_signed is False and has_ds:
        F.append(_f("info", "Live DS record found, but RDAP says the delegation isn't signed", "The registry's RDAP data may lag behind DNS."))


# ====================================================================== HTTP inspector
SEC_HEADERS = [("strict-transport-security", "HSTS (Strict-Transport-Security)"), ("content-security-policy", "Content-Security-Policy"),
               ("x-frame-options", "X-Frame-Options"), ("x-content-type-options", "X-Content-Type-Options"), ("referrer-policy", "Referrer-Policy")]
CLOUDFLARE_5XX = {
    520: "Cloudflare 520: the origin returned an empty, unknown or unexpected response.",
    521: "Cloudflare 521: the origin web server refused the connection (down, or firewall blocking Cloudflare's IPs).",
    522: "Cloudflare 522: Cloudflare timed out connecting to the origin.",
    523: "Cloudflare 523: the origin is unreachable (DNS or routing problem at the origin).",
    524: "Cloudflare 524: the origin accepted the connection but took too long (100s) to respond.",
    525: "Cloudflare 525: the TLS handshake between Cloudflare and the origin failed.",
    526: "Cloudflare 526: the origin certificate is invalid (Full (strict) SSL mode).",
}
REDIRECTS = (301, 302, 303, 307, 308)


def _detect_cdn(headers: list[tuple[str, str]]) -> list[dict]:
    h = {}
    for k, v in headers:
        h.setdefault(k.lower(), v)
    cookies = " ".join(v for k, v in headers if k.lower() == "set-cookie").lower()
    server = h.get("server", "").lower()
    via = h.get("via", "").lower()
    found = []

    def add(name, evidence):
        found.append({"name": name, "evidence": evidence})
    if "cf-ray" in h or server == "cloudflare":
        add("Cloudflare", "cf-ray header" if "cf-ray" in h else "Server: cloudflare")
    if any(k.startswith("x-akamai") for k in h) or "akamai-grn" in h or server.startswith("akamai"):
        add("Akamai", "Akamai headers")
    if "x-azure-ref" in h:
        add("Azure Front Door / Azure CDN", "x-azure-ref header")
    if "x-amz-cf-id" in h or "cloudfront" in via:
        add("AWS CloudFront", "x-amz-cf-id header" if "x-amz-cf-id" in h else "Via: CloudFront")
    if "x-fastly-request-id" in h or h.get("x-served-by", "").startswith("cache-"):
        add("Fastly", "x-fastly-request-id / x-served-by headers")
    if "x-iinfo" in h or "incap_ses" in cookies or "visid_incap" in cookies or "imperva" in h.get("x-cdn", "").lower():
        add("Imperva (Incapsula)", "x-iinfo header / incap cookies")
    if "microsoft-azure-application-gateway" in server:
        add("Azure Application Gateway", "Server header")
    return found


def _is_cert_error(exc: BaseException) -> str | None:
    e: BaseException | None = exc
    for _ in range(6):
        if e is None:
            break
        if isinstance(e, ssl.SSLCertVerificationError):
            return e.verify_message or str(e)
        e = e.__cause__ or e.__context__
    s = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in s:
        m = re.search(r"certificate verify failed: ([^(]+)", s)
        return m.group(1).strip() if m else s
    return None


def _http_hop(url: str, ip: str, timeout: float) -> dict:
    hop: dict = {"url": url, "ip": ip}
    t0 = time.monotonic()
    try:
        resp, body, meta = _pinned_send(url, ip, True, timeout, 512 * 1024)
    except httpx.HTTPError as exc:
        cert_err = _is_cert_error(exc)
        if not cert_err:
            if isinstance(exc, httpx.TimeoutException):
                phase = {"ConnectTimeout": "connecting", "ReadTimeout": "waiting for the response", "WriteTimeout": "sending the request",
                         "PoolTimeout": "waiting for a connection"}.get(type(exc).__name__, "waiting")
                hop["error"] = f"Timed out after {time.monotonic() - t0:.1f}s {phase} ({type(exc).__name__})"
            else:
                hop["error"] = str(exc) or type(exc).__name__
            return hop
        hop["cert_error"] = cert_err
        try:
            resp, body, meta = _pinned_send(url, ip, False, timeout, 512 * 1024)
        except httpx.HTTPError as exc2:
            hop["error"] = str(exc2) or type(exc2).__name__
            return hop
    headers = [(k, v) for k, v in resp.headers.multi_items()]
    hop.update({"status": resp.status_code, "reason": resp.reason_phrase, "http_version": resp.http_version,
                "location": resp.headers.get("location"), "server": resp.headers.get("server"),
                "content_type": resp.headers.get("content-type"), "headers": headers, "bytes": len(body), **meta})
    if "html" in (hop["content_type"] or "").lower():
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            hop["title"] = re.sub(r"\s+", " ", html.unescape(m.group(1).decode("utf-8", "replace"))).strip()[:200]
    return hop


def _normalize_url(value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ValueError("Enter a URL.")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        v = "http://" + v
    parts = urlsplit(v)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parts.hostname:
        raise ValueError(f"'{value}' is not a valid URL.")
    if parts.username or parts.password:
        raise ValueError("URLs with credentials aren't supported (this tool never sends credentials).")
    try:
        parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in '{value}'.") from exc
    host = _clean_host(parts.hostname)
    netloc = (f"[{host}]" if ":" in host else host) + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def http_inspect(url: str) -> dict:
    start = _normalize_url(url)
    deadline = time.monotonic() + 22
    hops: list[dict] = []
    F: list[dict] = []
    steps: list[dict] = []
    seen: list[str] = []
    current = start
    loop = too_many = False
    while True:
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            hops.append({"url": current, "error": "Redirect to a non-HTTP URL", "blocked": True})
            break
        if current in seen:
            loop = True
            break
        seen.append(current)
        try:
            ip = _resolve_safe(_clean_host(parts.hostname), allow_private=False)[0]
        except ValueError as exc:
            if not hops:
                raise
            hops.append({"url": current, "error": str(exc), "blocked": True})
            break
        remaining = deadline - time.monotonic()
        if remaining < 1:
            hops.append({"url": current, "error": "Stopped: the whole check exceeded its time budget."})
            break
        hop = _http_hop(current, ip, min(10.0, remaining))
        hops.append(hop)
        if hop.get("error") or hop.get("status") not in REDIRECTS or not hop.get("location"):
            break
        if len(hops) > 10:
            too_many = True
            break
        current = urljoin(current, hop["location"].strip())
        try:
            current = _normalize_url(current)
        except ValueError as exc:
            hops.append({"url": current, "error": str(exc), "blocked": True})
            break

    final = hops[-1]
    final_url = final["url"]
    chain_txt = " → ".join(h["url"] for h in hops)
    redirects = len(hops) - 1
    if loop:
        F.append(_f("critical", "Redirect loop", f"The chain comes back to {current}. Browsers show ERR_TOO_MANY_REDIRECTS. Common cause: the site redirects HTTP→HTTPS while a CDN/proxy talks to the origin over HTTP (e.g. Cloudflare 'Flexible' SSL), or two rules undo each other.",
                    headline=f"Redirect loop: {' → '.join(seen[-3:])} → {current}. Browsers show 'too many redirects'."))
    if too_many:
        F.append(_f("critical", "More than 10 redirects", "Browsers give up after about 20; most clients far sooner. Simplify the redirect rules.",
                    headline=f"{start} redirects more than 10 times. Clients will give up."))
    for h in hops:
        if h.get("blocked"):
            F.append(_f("critical", "Redirect to a refused address", f"{h['url']}: {h['error']}",
                        headline=f"{start} redirects to {h['url']}. Stopped there: {h['error'].split(': ', 1)[-1].rstrip('.')}."))
        elif h.get("cert_error"):
            F.append(_f("critical", f"Certificate error on {urlsplit(h['url']).hostname}", f"{h['cert_error']}. Browsers show a full-page warning and most apps refuse to connect. Open the SSL/TLS Checker for the full chain.",
                        headline=f"{h['url']} has a certificate error ({h['cert_error'].rstrip('.')}). Browsers will block it."))
        elif h.get("error") and not h.get("blocked"):
            F.append(_f("critical", f"Request to {h['url']} failed", h["error"],
                        headline=f"{h['url']} doesn't respond: {h['error']}."))
    for i in range(1, len(hops)):
        if hops[i - 1]["url"].startswith("https://") and hops[i]["url"].startswith("http://"):
            F.append(_f("warning", f"Redirect downgrades from HTTPS to HTTP (hop {i})", f"{hops[i - 1]['url']} → {hops[i]['url']}. Traffic after this point is unencrypted, and browsers may warn.",
                        headline=f"The redirect chain drops from HTTPS to plain HTTP at {hops[i]['url']}. Traffic after that point is unencrypted."))
    status = final.get("status")
    if status is not None:
        server = final.get("server")
        cdn = _detect_cdn(final.get("headers") or [])
        secs = (final.get("ttfb_ms") or 0) / 1000
        pretty = f"{status} {final.get('reason') or ''}".strip()
        if status >= 500:
            detail = CLOUDFLARE_5XX.get(status) if any(c["name"] == "Cloudflare" for c in cdn) else None
            F.append(_f("critical", f"Server error {pretty}", detail or "The web server or application behind it is failing. Check the application/web server logs (IIS: %SystemDrive%\\inetpub\\logs\\LogFiles; App Pool status).",
                        headline=f"{final_url} returns {pretty}" + (f" ({detail.split(': ', 1)[1].rstrip('.')})" if detail else ". The site or its backend is failing") + "."))
        elif status >= 400:
            hint = {401: "Authentication is required.", 403: "Access is forbidden: permissions, IP restrictions, or a WAF/CDN blocking the request.",
                    404: "The page doesn't exist at this path.", 429: "Rate limited."}.get(status, "")
            if cdn and status in (403, 429):
                hint += f" {cdn[0]['name']} is in front of this site, so it may be the WAF that blocks automated requests like this one."
            F.append(_f("warning", f"Client error {pretty}", hint, headline=f"{final_url} returns {pretty}." + (f" {hint}" if hint else "")))
        elif status in REDIRECTS and not loop and not too_many:
            F.append(_f("warning", f"Redirect without a usable Location ({pretty})", "The server says the content moved but doesn't say where, so browsers stop here. Fix the redirect rule.",
                        headline=f"{final_url} returns {pretty} without a usable Location header, so clients can't follow the redirect."))
        if start.startswith("http://") and not any(h["url"].startswith("https://") for h in hops):
            F.append(_f("warning", "No redirect to HTTPS", "The site is served over plain HTTP. Passwords and cookies travel unencrypted, and browsers mark it 'Not secure'. Add an HTTP→HTTPS redirect.",
                        headline=f"{start} doesn't redirect to HTTPS. The site is served unencrypted." if status < 400 else None))
        elif start.startswith("http://") and final_url.startswith("https://"):
            F.append(_f("ok", "HTTP redirects to HTTPS", ""))
        if redirects > 3 and not loop and not too_many:
            F.append(_f("info", f"{redirects} redirects", "Each redirect adds a round trip. Point links straight at the final URL where you can."))
        if secs > 3:
            F.append(_f("warning", f"Slow first byte: {secs:.1f}s", "Time to first byte includes connect + TLS + server think time. Over 3s usually means a slow application, database, or an overloaded server.",
                        headline=f"{final_url} is slow: the server took {secs:.1f}s to start responding." if status < 400 else None))
        tls = final.get("tls") or {}
        if tls.get("cert") and 0 <= tls["cert"]["days_left"] < 30 and not final.get("cert_error"):
            F.append(_f("warning" if tls["cert"]["days_left"] >= 7 else "critical", f"Certificate expires {_in_days(tls['cert']['days_left'])}",
                        "Renew it soon. Open the SSL/TLS Checker for details.",
                        headline=f"{final_url} works, but its certificate expires {_in_days(tls['cert']['days_left'])}."))
        if tls.get("version") in ("TLSv1", "TLSv1.1"):
            F.append(_f("warning", f"Negotiated {tls['version']}", "Deprecated TLS version."))
        hdr = {k.lower() for k, _ in final.get("headers") or []}
        if final_url.startswith("https://") and status < 400:
            missing = [label for key, label in SEC_HEADERS if key not in hdr]
            present = [label for key, label in SEC_HEADERS if key in hdr]
            if missing:
                F.append(_f("info", f"Security headers missing: {', '.join(missing)}", "Hardening headers. Not required for the site to work; they matter for security scans and clickjacking/XSS protection." + (f" Present: {', '.join(present)}." if present else "")))
            else:
                F.append(_f("ok", "All common security headers present", ", ".join(present)))
        for c in cdn:
            F.append(_f("info", f"Served through {c['name']}", f"Detected from {c['evidence']}. Errors and blocks may come from the CDN/WAF edge rather than the origin server."))
        if status < 300 and not any(f.get("headline") and f["severity"] in ("critical", "warning") for f in F):
            via = f" via {cdn[0]['name']}" if cdn else ""
            if redirects:
                F.append(_f("ok", "", "", headline=f"{start} redirects to {final_url} and loads fine ({pretty}, {secs:.1f}s{via})."))
            else:
                F.append(_f("ok", "", "", headline=f"{final_url} loads fine ({pretty} in {secs:.1f}s{via})."))
    host0 = urlsplit(start).hostname
    if any(f["severity"] in ("critical", "warning") for f in F):
        steps.append({"title": "Reproduce from a client", "detail": "Shows each redirect and the response headers. curl.exe ships with Windows 10/11.",
                      "commands": [f"curl.exe -sSIL --max-redirs 10 \"{start}\""]})
    if start.startswith("http://") and not any(h["url"].startswith("https://") for h in hops) and status is not None:
        steps.append({"title": "Add an HTTP → HTTPS redirect", "detail": "IIS: URL Rewrite rule or 'Require SSL' with an HTTP redirect site; Azure App Service: HTTPS Only = On; Cloudflare: Always Use HTTPS."})
    if loop:
        steps.append({"title": "Break the loop", "detail": "If a CDN/proxy is in front: set its SSL mode to 'Full (strict)' so it talks HTTPS to the origin, or make the origin trust the X-Forwarded-Proto header before redirecting."})
    sev, headline = _pick_headline(F, f"Inspected {start}.")
    F[:] = [f for f in F if f["title"]]  # headline-only entries
    return {"start": start, "final_url": final_url, "hops": hops, "redirects": redirects, "findings": F, "steps": steps,
            "severity": sev, "headline": headline, "host": host0,
            "subline": f"{redirects} redirect{'s' if redirects != 1 else ''} · fetched FROM the MSPGather server · body capped at 512 KB, no cookies"}


# ====================================================================== routes
@router.get("/api/net/tls")
def tls_route(host: str = Query(..., max_length=300), protocol: str = "auto"):
    return run(tls_check, host, protocol)


@router.get("/api/net/ports")
def ports_route(host: str = Query(..., max_length=300), ports: str = Query("", max_length=1000)):
    return run(port_check, host, ports)


@router.get("/api/net/whois")
def whois_route(domain: str = Query(..., max_length=300)):
    return run(domain_registration, domain)


@router.get("/api/net/http")
def http_route(url: str = Query(..., max_length=2000)):
    return run(http_inspect, url)
