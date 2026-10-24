"""Live SMTP conversation test: banner, EHLO, STARTTLS, certificate, and an
optional MAIL FROM / RCPT TO probe (never sends DATA)."""
from __future__ import annotations

import os
import re
import smtplib
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from ..core.dns_utils import is_ip, make_resolver, normalize_domain, resolve
from ..core.outbound import resolve_safe
from ..core.providers import provider_for

DEFAULT_HELO = os.environ.get("SMTP_HELO", "mspgather.diagnostics.local")
TLS_MODES = ("starttls", "implicit", "none")


def _f(sev: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "title": title, "detail": detail}


def _host_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return "." in host and host.split(".", 1)[1] == pattern[2:]
    return host == pattern


def _cert_info(der: bytes, host: str) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    cns = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    names = sans or cns
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "san": sans[:50],
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "expired": not_after < now,
        "self_signed": cert.issuer == cert.subject,
        "hostname_match": any(_host_matches(host, n) for n in names),
        "serial": format(cert.serial_number, "x"),
    }


def _decode(msg) -> str:
    return msg.decode("utf-8", "replace") if isinstance(msg, bytes) else str(msg)


def _verify_chain(host: str, ip: str, port: int, tls_mode: str, helo: str, timeout: float) -> str | None:
    """Second connection with full verification. Returns None if trusted, else the reason.
    Connects to the already-checked IP; the host name is used for SNI and name matching."""
    ctx = ssl.create_default_context()
    try:
        if tls_mode == "implicit":
            s = smtplib.SMTP_SSL(timeout=timeout, local_hostname=helo, context=ctx)
            s._host = host
            s.connect(ip, port)
        else:
            s = smtplib.SMTP(timeout=timeout, local_hostname=helo)
            s._host = host
            s.connect(ip, port)
            s.ehlo()
            s.starttls(context=ctx)
        try:
            s.quit()
        except smtplib.SMTPException:
            pass
        return None
    except ssl.SSLCertVerificationError as exc:
        return exc.verify_message or str(exc)
    except (OSError, smtplib.SMTPException) as exc:
        return f"Could not re-verify: {exc}"


def _test_host(host: str, port: int, tls_mode: str, helo: str, mail_from: str | None,
               rcpt_to: str | None, timeout: float) -> dict:
    transcript: list[dict] = []
    out: dict = {"host": host, "port": port, "tls_mode": tls_mode, "provider": (provider_for(host) or {}).get("name"),
                 "connected": False, "banner": None, "ehlo": [], "starttls_offered": None, "tls": None,
                 "mail_from": None, "rcpt_to": None, "timings_ms": {}, "error": None, "findings": [],
                 "transcript": transcript}
    F = out["findings"]

    def log(direction: str, text: str):
        transcript.append({"dir": direction, "text": text})

    # Outbound safety: resolve once, refuse unsafe targets, then connect to that exact IP.
    try:
        ip = resolve_safe(host, allow_private=True)[0]
    except ValueError as exc:
        out["error"] = str(exc)
        F.append(_f("critical", "Refused to connect", str(exc)))
        return out
    out["ip"] = ip

    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    smtp = None
    t0 = time.monotonic()
    try:
        if tls_mode == "implicit":
            smtp = smtplib.SMTP_SSL(timeout=timeout, local_hostname=helo, context=unverified)
        else:
            smtp = smtplib.SMTP(timeout=timeout, local_hostname=helo)
        smtp._host = host  # used as TLS SNI name; only set by the constructor otherwise
        log("C", f"(connect {host} [{ip}]:{port})")
        code, msg = smtp.connect(ip, port)
        out["timings_ms"]["connect"] = round((time.monotonic() - t0) * 1000)
        out["connected"] = True
        out["banner"] = f"{code} {_decode(msg)}"
        log("S", out["banner"])
        if code != 220:
            F.append(_f("critical", f"Server greeted with {code}", _decode(msg)))

        t1 = time.monotonic()
        log("C", f"EHLO {helo}")
        code, msg = smtp.ehlo()
        log("S", f"{code} {_decode(msg)}")
        out["timings_ms"]["ehlo"] = round((time.monotonic() - t1) * 1000)
        if code != 250:
            F.append(_f("warning", f"EHLO rejected ({code})", "Server may only support HELO, or it rejected our HELO name."))
            log("C", f"HELO {helo}")
            code, msg = smtp.helo()
            log("S", f"{code} {_decode(msg)}")
        out["ehlo"] = _decode(msg).splitlines()[1:]

        if tls_mode == "implicit" and isinstance(smtp.sock, ssl.SSLSocket):
            out["tls"] = _tls_details(smtp.sock, host)
        elif tls_mode == "starttls":
            out["starttls_offered"] = smtp.has_extn("starttls")
            if out["starttls_offered"]:
                t2 = time.monotonic()
                log("C", "STARTTLS")
                code, msg = smtp.starttls(context=unverified)
                log("S", f"{code} {_decode(msg)}")
                out["timings_ms"]["starttls"] = round((time.monotonic() - t2) * 1000)
                out["tls"] = _tls_details(smtp.sock, host)
                log("C", f"EHLO {helo}")
                code, msg = smtp.ehlo()
                log("S", f"{code} {_decode(msg)}")
                out["ehlo"] = _decode(msg).splitlines()[1:]
            else:
                F.append(_f("critical" if port == 25 else "warning", "STARTTLS not offered",
                            "Mail to this server travels unencrypted. Senders that require TLS (MTA-STS enforce, TLS-enforced connectors) will fail. "
                            "If STARTTLS should be there, a firewall doing SMTP inspection may be stripping it (look for 'XXXXXXXA' in the EHLO response)."))
                if any("XXXX" in l for l in out["ehlo"]):
                    F.append(_f("critical", "EHLO extensions are masked (XXXXXXXA)",
                                "A firewall (Cisco ASA/FTD ESMTP inspection or similar) is rewriting the SMTP session. Disable ESMTP inspection on it."))

        if mail_from is not None:
            log("C", f"MAIL FROM:<{mail_from}>")
            code, msg = smtp.mail(mail_from)
            out["mail_from"] = {"code": code, "message": _decode(msg)}
            log("S", f"{code} {_decode(msg)}")
            if code >= 400:
                F.append(_f("critical" if code >= 500 else "warning", f"MAIL FROM rejected ({code})", _decode(msg)))
            elif rcpt_to:
                log("C", f"RCPT TO:<{rcpt_to}>")
                code, msg = smtp.rcpt(rcpt_to)
                out["rcpt_to"] = {"code": code, "message": _decode(msg)}
                log("S", f"{code} {_decode(msg)}")
                if code >= 500:
                    F.append(_f("critical", f"Recipient rejected ({code})", _decode(msg)))
                elif code >= 400:
                    F.append(_f("warning", f"Recipient deferred ({code})", _decode(msg) + " (greylisting or a temporary policy)"))
                else:
                    F.append(_f("ok", f"Recipient accepted ({code})", "Note: some servers accept every recipient and bounce later (catch-all or no recipient validation)."))
            log("C", "RSET")
            smtp.rset()
        log("C", "QUIT")
        smtp.quit()
    except (socket.timeout, TimeoutError):
        out["error"] = f"Timed out after {timeout:.0f}s"
        F.append(_f("critical", "Connection timed out",
                    f"No response from {host}:{port}. Either a firewall drops the traffic, or outbound port {port} is blocked from where this tool runs "
                    "(many ISPs, Azure and AWS block outbound 25)."))
    except ConnectionRefusedError:
        out["error"] = "Connection refused"
        F.append(_f("critical", "Connection refused", f"{host} is reachable but nothing is listening on port {port}."))
    except ssl.SSLError as exc:
        out["error"] = f"TLS error: {exc}"
        F.append(_f("critical", "TLS handshake failed", str(exc)))
    except smtplib.SMTPServerDisconnected as exc:
        out["error"] = f"Server disconnected: {exc}"
        F.append(_f("critical", "Server dropped the connection", str(exc) + " The server may be blocking our IP or HELO name."))
    except (smtplib.SMTPException, OSError, ValueError) as exc:
        out["error"] = str(exc)
        F.append(_f("critical", "SMTP error", str(exc)))
    finally:
        try:
            if smtp and smtp.sock:
                smtp.close()
        except OSError:
            pass
    out["timings_ms"]["total"] = round((time.monotonic() - t0) * 1000)

    tls = out.get("tls")
    if tls and tls.get("certificate"):
        cert = tls["certificate"]
        reason = _verify_chain(host, out["ip"], port, tls_mode, helo, timeout)
        tls["trusted"] = reason is None
        tls["trust_error"] = reason
        if cert["expired"]:
            F.append(_f("critical", "Certificate has expired", f"Expired {cert['not_after']}. Senders that verify (MTA-STS, DANE, TLS-enforced connectors) will fail."))
        elif cert["days_left"] < 21:
            F.append(_f("warning", f"Certificate expires in {cert['days_left']} days", cert["not_after"]))
        if not cert["hostname_match"]:
            F.append(_f("warning", f"Certificate name does not match {host}",
                        "Names on cert: " + ", ".join(cert["san"][:8] or [cert["subject"]]) +
                        ". Fine for opportunistic TLS, but MTA-STS enforce and Exchange Online TLS-enforced connectors will fail."))
        if reason and cert["hostname_match"] and not cert["expired"]:
            F.append(_f("warning", "Certificate chain not trusted", reason))
        if tls.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
            F.append(_f("warning", f"Old protocol negotiated: {tls['version']}", "Exchange Online requires TLS 1.2+."))
        if not any(f["severity"] in ("critical", "warning") for f in F):
            F.append(_f("ok", f"TLS OK: {tls.get('version')} {tls.get('cipher')}"))
    return out


def _tls_details(sock: ssl.SSLSocket, host: str) -> dict:
    der = sock.getpeercert(binary_form=True)
    cipher = sock.cipher()
    return {"version": sock.version(), "cipher": cipher[0] if cipher else None, "bits": cipher[2] if cipher else None,
            "certificate": _cert_info(der, host) if der else None}


def smtp_test(target: str, port: int = 25, tls_mode: str = "starttls", helo: str | None = None,
              mail_from: str | None = None, rcpt_to: str | None = None, resolve_mx: bool = True,
              timeout: float = 12.0) -> dict:
    target = (target or "").strip()
    if not target:
        raise ValueError("Enter a host name, IP address or domain.")
    if tls_mode not in TLS_MODES:
        raise ValueError(f"tls_mode must be one of {TLS_MODES}")
    if not 1 <= int(port) <= 65535:
        raise ValueError("Invalid port")
    helo = (helo or DEFAULT_HELO).strip()
    for label, value in (("HELO name", helo), ("MAIL FROM", mail_from), ("RCPT TO", rcpt_to)):
        if value and (re.search(r"[\x00-\x1f\x7f]", value) or len(value) > 320):
            raise ValueError(f"{label} contains control characters or is too long.")
    if not re.fullmatch(r"[A-Za-z0-9.\-\[\]:]{1,255}", helo):
        raise ValueError("HELO name must be a host name or address literal.")
    if is_ip(target):
        resolve_safe(target.strip("[]"), allow_private=True)  # refuse loopback / metadata etc. up front (400)
    hosts: list[str]
    mx_used = False
    if is_ip(target):
        hosts = [target.strip("[]")]
    else:
        target = normalize_domain(target)
        hosts = [target]
        if resolve_mx:
            rdata, _ = resolve(make_resolver(), target, "MX")
            if rdata and all(r.exchange.to_text() == "." for r in rdata):
                raise ValueError(f"{target} publishes a null MX (RFC 7505): it deliberately accepts no mail, so there is no mail server to test.")
            mx = [r.exchange.to_text(omit_final_dot=True) for r in sorted(rdata, key=lambda r: r.preference)
                  if r.exchange.to_text() != "."]
            if mx:
                hosts, mx_used = mx[:5], True
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda h: _test_host(h, int(port), tls_mode, helo, mail_from, rcpt_to, timeout), hosts))
    return {"target": target, "port": int(port), "tls_mode": tls_mode, "helo": helo, "resolved_mx": mx_used, "results": results}
