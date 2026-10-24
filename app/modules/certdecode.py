"""Certificate & CSR Decoder: paste PEM / base64 DER / PKCS#7 certificates and CSRs, get a plain-English
read-out, chain order and completeness, CSR <-> certificate key match and an optional hostname check.

Decoding is fully offline. The only network call is the optional "fetch missing intermediate" step
(/api/cert/fetch), which downloads an AIA caIssuers URL with the shared outbound-safety rules.

Private keys are refused before anything is parsed, and never echoed, logged or stored.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID
from fastapi import APIRouter
from pydantic import BaseModel

from ..core.http import run
from ..core import cmdsafe
from ..core.outbound import resolve_safe
from .netdiag import _ca_name, _clean_host, _f, _in_days, _name_attr, _pick_headline, _pinned_send, _plural, _trust_store

router = APIRouter()

MAX_TEXT = 200_000
FETCH_TIMEOUT = 8.0
FETCH_MAX = 65536

PRIVATE_KEY_MSG = ("That text contains a private key, so it was not read. Never paste private keys into any website or "
                   "tool; this tool doesn't need it. Paste only the certificate (-----BEGIN CERTIFICATE-----) and/or the "
                   "CSR (-----BEGIN CERTIFICATE REQUEST-----). If the key has been shared anywhere, treat it as "
                   "compromised: re-key and re-issue the certificate.")
PFX_MSG = ("That looks like a PFX / PKCS#12 file, which contains the private key, so it was not read. Never paste PFX "
           "files or their passwords into any website or tool. Export just the certificate instead: "
           "openssl pkcs12 -in cert.pfx -nokeys -out cert.pem (run locally), or in certlm.msc: "
           "Export > 'No, do not export the private key' > Base-64 encoded X.509 (.CER).")
_PRIVATE_RE = re.compile(r"PRIVATE[\s_-]*KEY|PuTTY-User-Key-File|Private-Lines\s*:|BEGIN\s+PKCS12|BEGIN\s+PFX", re.I)
_PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 #]+?)-----(.*?)-----END \1-----", re.S)
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")

EKU_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "Server Authentication",
    ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "Client Authentication",
    ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "Code Signing",
    ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "Secure Email (S/MIME)",
    ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: "Time Stamping",
    ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "OCSP Signing",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
}
UPN_OID = "1.3.6.1.4.1.311.20.2.3"
KU_NAMES = [("digital_signature", "Digital Signature"), ("content_commitment", "Non-Repudiation"),
            ("key_encipherment", "Key Encipherment"), ("data_encipherment", "Data Encipherment"),
            ("key_agreement", "Key Agreement"), ("key_cert_sign", "Certificate Signing"), ("crl_sign", "CRL Signing")]


# ====================================================================== parsing helpers
def _key_info(pub) -> dict:
    if isinstance(pub, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": pub.key_size, "text": f"RSA {pub.key_size}-bit"}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"type": "ECDSA", "bits": pub.curve.key_size, "text": f"ECDSA {pub.curve.name} ({pub.curve.key_size}-bit)"}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519", "bits": 256, "text": "Ed25519"}
    if isinstance(pub, ed448.Ed448PublicKey):
        return {"type": "Ed448", "bits": 456, "text": "Ed448"}
    if isinstance(pub, dsa.DSAPublicKey):
        return {"type": "DSA", "bits": pub.key_size, "text": f"DSA {pub.key_size}-bit"}
    return {"type": "unknown", "bits": None, "text": "unknown key type"}


def _spki(obj) -> bytes:
    return obj.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _sig(obj) -> tuple[str, str | None]:
    name = getattr(obj.signature_algorithm_oid, "_name", None) or obj.signature_algorithm_oid.dotted_string
    try:
        h = obj.signature_hash_algorithm
        return name, (h.name if h else None)
    except UnsupportedAlgorithm:
        return name, None


def _der_utf8(raw: bytes) -> str | None:
    """Decode a DER string TLV (UTF8String / IA5String / PrintableString) as used inside a UPN otherName."""
    try:
        if len(raw) < 2 or raw[0] not in (0x0C, 0x16, 0x13, 0x1E):
            return None
        n, off = raw[1], 2
        if n & 0x80:
            k = n & 0x7F
            n, off = int.from_bytes(raw[2:2 + k], "big"), 2 + k
        val = raw[off:off + n]
        return val.decode("utf-16-be" if raw[0] == 0x1E else "utf-8", "replace")
    except (IndexError, ValueError):
        return None


def _sans(exts: x509.Extensions) -> dict | None:
    try:
        san = exts.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    upn = []
    for o in san.get_values_for_type(x509.OtherName):
        if o.type_id.dotted_string == UPN_OID:
            v = _der_utf8(o.value)
            if v:
                upn.append(v)
    return {"dns": san.get_values_for_type(x509.DNSName), "ip": [str(a) for a in san.get_values_for_type(x509.IPAddress)],
            "email": san.get_values_for_type(x509.RFC822Name), "upn": upn,
            "uri": san.get_values_for_type(x509.UniformResourceIdentifier)}


def _key_usage(exts: x509.Extensions) -> list[str] | None:
    try:
        ku = exts.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None
    out = [label for attr, label in KU_NAMES if getattr(ku, attr)]
    if ku.key_agreement:
        if ku.encipher_only:
            out.append("Encipher Only")
        if ku.decipher_only:
            out.append("Decipher Only")
    return out


def _eku(exts: x509.Extensions) -> list[dict] | None:
    try:
        return [{"oid": o.dotted_string, "name": EKU_NAMES.get(o.dotted_string, o.dotted_string)}
                for o in exts.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except x509.ExtensionNotFound:
        return None


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> str | None:
    """'ok' if parent's key signed child, 'name' if only the names line up (wrong/re-keyed parent), None if unrelated."""
    if child.issuer != parent.subject:
        return None
    try:
        child.verify_directly_issued_by(parent)
        return "ok"
    except InvalidSignature:
        return "name"
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # Can't check the signature (unusual algorithm); fall back to the key identifiers.
        try:
            aki = child.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
            ski = parent.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            return "ok" if aki == ski else "name"
        except x509.ExtensionNotFound:
            return "ok"


def _cert_dict(cert: x509.Certificate, source: str) -> dict:
    der = cert.public_bytes(serialization.Encoding.DER)
    exts = cert.extensions
    now = datetime.now(timezone.utc)
    sig, sig_hash = _sig(cert)
    eku = _eku(exts)
    is_ca, path_len = False, None
    try:
        bc = exts.get_extension_for_class(x509.BasicConstraints).value
        is_ca, path_len = bc.ca, bc.path_length
    except x509.ExtensionNotFound:
        pass
    ca_issuers, ocsp = [], []
    try:
        for d in exts.get_extension_for_class(x509.AuthorityInformationAccess).value:
            if isinstance(d.access_location, x509.UniformResourceIdentifier):
                if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    ca_issuers.append(d.access_location.value)
                elif d.access_method == AuthorityInformationAccessOID.OCSP:
                    ocsp.append(d.access_location.value)
    except x509.ExtensionNotFound:
        pass
    crl = []
    try:
        for dp in exts.get_extension_for_class(x509.CRLDistributionPoints).value:
            for n in dp.full_name or []:
                if isinstance(n, x509.UniformResourceIdentifier):
                    crl.append(n.value)
    except x509.ExtensionNotFound:
        pass
    self_issued = cert.issuer == cert.subject
    self_signed = self_issued and _issued_by(cert, cert) == "ok"
    na, nb = cert.not_valid_after_utc, cert.not_valid_before_utc
    sans = _sans(exts)
    cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
    return {
        "source": source,
        "label": cn or (sans["dns"][0] if sans and sans["dns"] else None) or _ca_name(cert.subject),
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
        "subject_cn": cn, "subject_short": _ca_name(cert.subject), "issuer_short": _ca_name(cert.issuer),
        "san": sans, "serial": format(cert.serial_number, "x").upper().zfill(2),
        "not_before": _iso(nb), "not_after": _iso(na), "days_left": (na - now).days,
        "expired": na < now, "not_yet_valid": nb > now, "validity_days": (na - nb).days,
        "key": _key_info(cert.public_key()), "signature": sig, "signature_hash": sig_hash,
        "key_usage": _key_usage(exts), "eku": eku,
        "server_auth": None if eku is None else any(e["oid"] in (ExtendedKeyUsageOID.SERVER_AUTH.dotted_string, "2.5.29.37.0") for e in eku),
        "is_ca": is_ca, "path_length": path_len, "ca_issuers": ca_issuers, "ocsp": ocsp, "crl": crl,
        "sha1": hashlib.sha1(der).hexdigest().upper(), "sha256": hashlib.sha256(der).hexdigest().upper(),
        "self_signed": self_signed, "self_issued": self_issued, "version": cert.version.name,
    }


def _csr_dict(csr: x509.CertificateSigningRequest, source: str) -> dict:
    sig, sig_hash = _sig(csr)
    try:
        valid = csr.is_signature_valid
    except (UnsupportedAlgorithm, ValueError):
        valid = None
    try:
        exts = csr.extensions
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        exts = x509.Extensions([])
    cn = _name_attr(csr.subject, NameOID.COMMON_NAME)
    sans = _sans(exts)
    try:
        key = _key_info(csr.public_key())
    except (ValueError, UnsupportedAlgorithm):
        key = {"type": "unknown", "bits": None, "text": "unknown key type"}
    return {"source": source, "label": cn or (sans["dns"][0] if sans and sans["dns"] else None) or csr.subject.rfc4514_string(),
            "subject": csr.subject.rfc4514_string(), "subject_cn": cn, "san": sans, "key": key,
            "signature": sig, "signature_hash": sig_hash, "signature_valid": valid,
            "key_usage": _key_usage(exts), "eku": _eku(exts)}


# ====================================================================== input splitting
def _b64(body: str) -> bytes:
    lines = [ln for ln in body.strip().splitlines() if ":" not in ln]  # drop RFC 1421 headers
    data = re.sub(r"\s+", "", "".join(lines))
    return base64.b64decode(data + "=" * (-len(data) % 4), validate=True)


def _looks_pkcs12(der: bytes) -> bool:
    """PFX = SEQUENCE { INTEGER 3, ContentInfo ... }. Checked structurally, never parsed."""
    if len(der) < 8 or der[0] != 0x30:
        return False
    n = der[1]
    off = 2 + (n & 0x7F if n & 0x80 else 0)
    return der[off:off + 3] == b"\x02\x01\x03" and der[off + 3:off + 4] == b"\x30"


def _split(text: str) -> tuple[list[tuple[x509.Certificate, str]], list[tuple[x509.CertificateSigningRequest, str]], list[dict], bool]:
    """Returns (certs, csrs, input problems, all_from_pkcs7)."""
    certs: list[tuple[x509.Certificate, str]] = []
    csrs: list[tuple[x509.CertificateSigningRequest, str]] = []
    problems: list[dict] = []
    p7_only = True
    blocks = list(_PEM_RE.finditer(text))
    if blocks:
        for n, m in enumerate(blocks, 1):
            label, body = m.group(1).strip(), m.group(2)
            src = f"PEM block {n} ({label})"
            try:
                der = _b64(body)
            except (binascii.Error, ValueError):
                problems.append(_f("warning", f"Block {n} ({label}) isn't valid base64", "The text between the BEGIN and END lines "
                                   "is damaged (often from copying out of an email or a PDF). Re-export the file."))
                continue
            try:
                if label in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
                    certs.append((x509.load_der_x509_certificate(der), src))
                    p7_only = False
                elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
                    csrs.append((x509.load_der_x509_csr(der), src))
                elif label in ("PKCS7", "PKCS #7 SIGNED DATA", "CMS"):
                    for c in pkcs7.load_der_pkcs7_certificates(der):
                        certs.append((c, f"PKCS#7 block {n}"))
                elif label == "PUBLIC KEY":
                    problems.append(_f("info", f"Block {n} is a bare public key", "A public key on its own has no name, issuer "
                                       "or dates. Paste the certificate or CSR it belongs to instead."))
                elif label == "X509 CRL":
                    problems.append(_f("info", f"Block {n} is a certificate revocation list (CRL)", "CRLs aren't decoded by this tool. "
                                       "Run locally: openssl crl -in file.crl -noout -text"))
                else:
                    problems.append(_f("info", f"Block {n} ({label}) isn't a certificate or CSR", "It was skipped."))
            except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
                problems.append(_f("warning", f"Block {n} ({label}) couldn't be parsed",
                                   f"{str(exc)[:200]}. The data may be truncated or not really a {label.lower()}."))
        return certs, csrs, problems, p7_only and bool(certs)

    raw = text.strip()
    compact = re.sub(r"\s+", "", raw)
    if not _B64_RE.match(raw) or any(" " in ln.strip() for ln in raw.splitlines()) or len(compact) < 100:
        if re.search(r"Certificate:\s*\n\s*Data:", raw) or "Serial Number:" in raw:
            raise ValueError("That looks like the text output of 'openssl x509 -text' or certutil, not the certificate itself. "
                             "Paste the PEM block (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----) instead.")
        raise ValueError("No certificate or CSR found. Paste PEM text (-----BEGIN CERTIFICATE----- / -----BEGIN CERTIFICATE "
                         "REQUEST----- / -----BEGIN PKCS7-----) or a base64 .cer/.csr without headers. Binary DER files: "
                         "convert first with certutil -encode file.cer file.pem.")
    try:
        der = _b64(raw)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("That text isn't valid base64, so it can't be a certificate or CSR.") from exc
    if _looks_pkcs12(der):
        raise ValueError(PFX_MSG)
    for kind, loader in (("cert", x509.load_der_x509_certificate), ("csr", x509.load_der_x509_csr),
                         ("p7", pkcs7.load_der_pkcs7_certificates)):
        try:
            obj = loader(der)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
        if kind == "cert":
            return [(obj, "base64 DER")], [], [], False
        if kind == "csr":
            return [], [(obj, "base64 DER")], [], False
        if obj:
            return [(c, "PKCS#7 (base64 DER)") for c in obj], [], [], True
    raise ValueError("That base64 text decodes, but it isn't a certificate, a CSR or a PKCS#7 bundle.")


# ====================================================================== hostname check
def _norm_host(value: str) -> str:
    v = (value or "").strip()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v, flags=re.I).split("/")[0].split("?")[0]
    if v.startswith("["):
        v = v[1:].split("]")[0]
    elif v.count(":") == 1:
        v = v.split(":")[0]
    if not v:
        raise ValueError("Enter a host name to check, e.g. vpn.contoso.com.")
    return _clean_host(v)


def _wild_match(host: str, pattern: str) -> bool:
    """RFC 6125 / browser rules: exact match, or '*.' as the whole left-most label covering exactly one label."""
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if "*" not in pattern:
        return host == pattern
    if not pattern.startswith("*.") or "*" in pattern[2:] or pattern[2:].count(".") < 1:
        return False  # partial (w*.contoso.com) or too-broad (*.com) wildcards aren't honoured by browsers
    head, _, rest = host.partition(".")
    return bool(head) and rest == pattern[2:]


def _host_check(host: str, names: dict | None, cn: str | None) -> dict:
    dns = (names or {}).get("dns") or []
    ips = (names or {}).get("ip") or []
    out = {"host": host, "covered": False, "matched_by": None, "cn_only": False, "note": None}
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        hit = next((a for a in ips if ipaddress.ip_address(a) == ip), None)
        out.update(covered=bool(hit), matched_by=f"IP SAN {hit}" if hit else None)
        if not hit:
            out["note"] = "IP addresses only match an IP Address SAN entry; DNS names and the CN don't count."
        return out
    hit = next((n for n in dns if _wild_match(host, n)), None)
    if hit:
        out.update(covered=True, matched_by=f"SAN {hit}")
        if hit.startswith("*."):
            out["note"] = f"{hit} covers one level only: {host} yes, but not {hit[2:]} itself or deeper names like a.{host}."
        return out
    if not dns and cn and _wild_match(host, cn):
        out.update(cn_only=True, note="The name is only in the Common Name (CN) and there is no SAN list. Chrome, Edge, "
                   "Firefox and Safari ignore the CN, so they reject this certificate (NET::ERR_CERT_COMMON_NAME_INVALID).")
        return out
    near = [n for n in dns if n.startswith("*.") and (host == n[2:] or host.endswith("." + n[2:]))]
    if near:
        out["note"] = (f"{near[0]} covers exactly one label in front of {near[0][2:]}, so it doesn't cover {host}. "
                       f"Add {host} as its own SAN.")
    return out


# ====================================================================== analysis
def _all_names(names: dict | None) -> list[str]:
    n = names or {}
    return [*(n.get("dns") or []), *(n.get("ip") or [])]


def decode(text: str, host: str = "") -> dict:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Paste a certificate, a chain, a CSR or a PKCS#7 (.p7b) file.")
    # Refuse private keys before ANY parsing; the message never includes the input.
    if _PRIVATE_RE.search(text):
        raise ValueError(PRIVATE_KEY_MSG)
    if len(text) > MAX_TEXT:
        raise ValueError(f"That's {len(text) // 1000} KB of text; the limit is {MAX_TEXT // 1000} KB. Paste just the certificates or CSR.")
    host_n = _norm_host(host) if host and host.strip() else None

    pairs, csr_pairs, problems, p7_only = _split(text)
    if not pairs and not csr_pairs:
        msg = f"{problems[0]['title']}: {problems[0]['detail']}" if problems else "No certificate or CSR found."
        raise ValueError(f"{msg} Nothing else to decode: paste a certificate (-----BEGIN CERTIFICATE-----) or a CSR (-----BEGIN CERTIFICATE REQUEST-----).")

    F: list[dict] = list(problems)
    steps: list[dict] = []
    # --- de-duplicate certificates (same DER pasted twice)
    seen: dict[str, int] = {}
    certs: list[x509.Certificate] = []
    info: list[dict] = []
    for c, src in pairs:
        d = _cert_dict(c, src)
        if d["sha256"] in seen:
            F.append(_f("info", f"'{d['label']}' was pasted twice", "The duplicate was ignored. Remove it from the chain file."))
            continue
        seen[d["sha256"]] = len(certs)
        d["index"] = len(certs)
        certs.append(c)
        info.append(d)

    out: dict = {"certs": info, "chain": [], "csr": None, "other_csrs": 0, "match": None, "host_check": None,
                 "missing": None, "fixed_chain_pem": None, "pkcs7": p7_only, "findings": F, "steps": steps}
    store = _trust_store()
    headline_name = None
    leaf_i = None

    # ------------------------------------------------------------------ chain
    if certs:
        n = len(certs)
        parent = {}
        for i in range(n):
            cands = [(j, _issued_by(certs[i], certs[j])) for j in range(n) if j != i and not info[i]["self_issued"]]
            cands = [(j, r) for j, r in cands if r]
            if cands:
                parent[i] = sorted(cands, key=lambda t: t[1] != "ok")[0]
        children = {j for j, _ in parent.values()}
        leaves = [i for i in range(n) if i not in children]
        leaf_i = next((i for i in leaves if not info[i]["is_ca"]), leaves[0] if leaves else 0)
        path, i = [leaf_i], leaf_i
        while i in parent and parent[i][0] not in path:
            if parent[i][1] == "name":
                c, p = info[i], info[parent[i][0]]
                F.append(_f("critical", f"'{p['label']}' has the right name but did NOT sign '{c['label']}'",
                            "The issuer names match but the signature doesn't verify, so this is a different (older or re-keyed) "
                            "CA certificate with the same name. Get the current intermediate from the CA (use the AIA link).",
                            headline=f"The chain you pasted has the wrong '{p['label']}' certificate: its key didn't sign '{c['label']}'."))
            i = parent[i][0]
            path.append(i)
        out["chain"] = path
        for pos, k in enumerate(path):
            info[k]["role"] = ("leaf" if not info[k]["is_ca"] else "CA certificate") if pos == 0 else (
                "root (self-signed)" if info[k]["self_signed"] else "intermediate")
            info[k]["chain_pos"] = pos
        for k in range(n):
            info[k].setdefault("role", "not part of this chain")
        L, leaf = info[leaf_i], certs[leaf_i]
        top_i = path[-1]
        top, T = certs[top_i], info[top_i]
        days = L["days_left"]
        kind = "CA certificate" if L["is_ca"] else "Certificate"
        name = L["label"]
        if host_n:
            hc = _host_check(host_n, L["san"], L["subject_cn"])
            out["host_check"] = hc
            if hc["covered"]:
                name = host_n
        headline_name = name
        prefix = f"{kind} for {name}"
        valid_txt = (f"{prefix} expires today" if days == 0 else f"{prefix} is valid for {_plural(days, 'more day')}")

        # --- leaf validity
        if L["expired"]:
            F.append(_f("critical", f"Certificate expired {_in_days(days)}", f"Expired {L['not_after'][:10]}. Every client rejects it; renew it with the CA.",
                        headline=f"{prefix} expired {_in_days(days)} ({L['not_after'][:10]})."))
        elif L["not_yet_valid"]:
            F.append(_f("critical", "Certificate is not valid yet", f"Valid from {L['not_before'][:19]}Z. Check the clock on the server and clients, or wait.",
                        headline=f"{prefix} isn't valid until {L['not_before'][:10]}."))
        elif days < 7:
            F.append(_f("critical", f"Certificate expires {_in_days(days)}", f"Expires {L['not_after'][:10]}. Renew now.",
                        headline=f"{prefix} expires {_in_days(days)}. Renew now."))
        elif days < 30:
            F.append(_f("warning", f"Certificate expires {_in_days(days)}", f"Expires {L['not_after'][:10]}. Renew it and install it everywhere it's used.",
                        headline=f"{prefix} expires {_in_days(days)}. Schedule the renewal."))
        else:
            F.append(_f("ok", f"Valid for {_plural(days, 'more day')}", f"{L['not_before'][:10]} to {L['not_after'][:10]}, issued by {L['issuer_short']}."))

        # --- hostname check
        hc = out["host_check"]
        if hc:
            if hc["covered"]:
                F.append(_f("ok", f"Covers {host_n}", f"Matched by {hc['matched_by']}." + (f" {hc['note']}" if hc["note"] else "")))
            else:
                names = _all_names(L["san"])
                F.append(_f("critical", f"Does NOT cover {host_n}",
                            (hc["note"] + " " if hc["note"] else "") + (f"Names in the certificate: {', '.join(names[:15])}{' …' if len(names) > 15 else ''}."
                                                                        if names else "The certificate has no SAN list at all."),
                            headline=(f"{kind} for {host_n} has the name only in the CN (no SAN list), so browsers reject it."
                                      if hc["cn_only"] else f"{kind} for {L['label']} does NOT cover {host_n}.")))
                steps.append({"title": f"Re-issue the certificate with {host_n} in the SAN list",
                              "detail": "Create a new CSR that lists every name clients use (SAN entries), then have the CA re-issue (most CAs re-issue free during the term).",
                              "commands": [f'openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out request.csr -subj "/CN={cmdsafe.dns_name(host_n)}" '
                                           f'-addext "subjectAltName={",".join("DNS:" + cmdsafe.dns_name(x) for x in dict.fromkeys([host_n, *(L["san"] or {}).get("dns", [])[:10]]))}"']})

        # --- leaf properties
        if not L["is_ca"]:
            if not L["san"] or not _all_names(L["san"]):
                F.append(_f("warning", "No Subject Alternative Names (SAN)", "Browsers only look at the SAN list and ignore the CN, so "
                            "this certificate fails in Chrome, Edge, Firefox and Safari for every name."))
            if L["server_auth"] is False:
                sev = "warning" if host_n else "info"
                F.append(_f(sev, "Not valid for Server Authentication (TLS)",
                            f"Its Extended Key Usage is {', '.join(e['name'] for e in L['eku'])}. It can't be used for a web server, "
                            "VPN, RDP or LDAPS certificate; request one from a template/product that includes Server Authentication."))
            elif L["server_auth"]:
                F.append(_f("ok", "Usable for Server Authentication (TLS)", "Extended Key Usage includes Server Authentication."))
        if L["key"]["type"] == "RSA" and (L["key"]["bits"] or 0) < 2048:
            F.append(_f("critical", f"Weak key: {L['key']['text']}", "Keys under 2048 bits are rejected by modern clients and every public CA. Re-key with 2048 or more."))
        if L["signature_hash"] in ("sha1", "md5"):
            F.append(_f("critical", f"Signed with {L['signature_hash'].upper()}", "SHA-1/MD5 signatures are rejected by modern browsers and Windows. Re-issue with SHA-256."))
        if L["self_signed"] and not L["is_ca"]:
            F.append(_f("warning", "Self-signed certificate", "Nobody vouches for it, so clients show a trust warning unless it's installed in "
                        "their Trusted Root store. Fine for a lab or a single internal appliance; use a CA-issued certificate otherwise."))

        # --- intermediates / roots
        for k in path[1:]:
            c = info[k]
            if c["expired"]:
                F.append(_f("critical", f"{c['role'].capitalize()} '{c['label']}' has expired",
                            f"Expired {c['not_after'][:10]}. Replace it with the CA's current version (download it from the AIA link in the certificate it signed).",
                            headline=f"{valid_txt}, but the chain you pasted contains an expired {'root' if c['self_signed'] else 'intermediate'} '{c['label']}'."))
            elif not c["self_signed"] and 0 <= c["days_left"] < 30:
                F.append(_f("warning", f"Intermediate '{c['label']}' expires {_in_days(c['days_left'])}", "Get the CA's replacement intermediate before then."))
            if c["signature_hash"] in ("sha1", "md5") and not c["self_signed"]:
                F.append(_f("warning", f"Intermediate '{c['label']}' is signed with {c['signature_hash'].upper()}", "Modern clients reject SHA-1 intermediates."))

        missing = None
        if T["self_signed"]:
            in_store = top.subject.public_bytes() in store
            if top_i != leaf_i:
                if in_store:
                    F.append(_f("info", f"The root '{T['label']}' is included (not needed)",
                                "Clients already have this root in their trust store and ignore the copy the server sends; it only makes "
                                "every handshake bigger. Leave it out of the chain file (leaf + intermediates only)."))
                else:
                    F.append(_f("info", f"Private / internal root '{T['label']}'",
                                "This root isn't in the public trust store, so it's an internal CA (e.g. AD CS). Clients trust it only if "
                                "it's deployed to their Trusted Root store (Group Policy, Intune, or certutil -addstore Root)."))
        elif top.issuer.public_bytes() in store:
            if n > 1 or top_i != leaf_i:
                F.append(_f("ok", "Chain is complete", f"It ends at '{T['label']}', which is signed by '{T['issuer_short']}', a root in the public trust store."))
            else:
                F.append(_f("ok", "Issued directly by a trusted root", f"'{L['issuer_short']}' is in the public trust store, so no intermediate is needed."))
        else:
            missing = {"issuer": top.issuer.rfc4514_string(), "issuer_short": _ca_name(top.issuer),
                       "aia_url": (T["ca_issuers"] or [None])[0], "below": T["label"]}
            out["missing"] = missing
            aia_txt = f" Download it from the AIA (Authority Information Access) URL {missing['aia_url']}, or use 'Fetch missing intermediate' below." if missing["aia_url"] else \
                " The certificate has no AIA download URL; get it from the CA's website or the issuing CA server."
            if n == 1:
                F.append(_f("info", f"Issuer '{missing['issuer_short']}' wasn't pasted",
                            "That's fine for decoding. When you install it, the server must also send this intermediate, or Java, "
                            "Android, curl and many appliances fail with 'unable to get local issuer certificate'." + aia_txt))
            elif top_i == leaf_i:
                F.append(_f("critical", f"Missing intermediate '{missing['issuer_short']}'",
                            f"'{T['label']}' was issued by '{missing['issuer_short']}', which isn't in what you pasted and isn't a root "
                            "in the public trust store. A server using this chain breaks Java, Android, curl and many appliances "
                            "('unable to get local issuer certificate')." + aia_txt,
                            headline=f"{valid_txt}, but the chain you pasted is missing the intermediate '{missing['issuer_short']}'."))
            else:
                # The chain reaches a CA whose issuer is unknown: usually a private root (AD CS), sometimes another intermediate.
                missing["likely_root"] = True
                F.append(_f("warning", f"Chain doesn't reach a trusted root: '{missing['issuer_short']}' is not included",
                            f"'{T['label']}' was issued by '{missing['issuer_short']}', which isn't in what you pasted and isn't in the "
                            "public trust store. If it's your internal root CA, that's normal: servers don't need to send it, but every "
                            "client must have it in Trusted Root. If it's another intermediate, add it to the chain." + aia_txt,
                            headline=f"{valid_txt}, but the chain stops at '{T['label']}': its issuer '{missing['issuer_short']}' "
                                     "isn't included or publicly trusted (internal root CA, or a missing intermediate)."))
            if missing["aia_url"] and missing.get("likely_root"):
                steps.append({"title": f"Make sure clients trust '{missing['issuer_short']}'",
                              "detail": "If it's an internal root, deploy it by Group Policy/Intune, or on one machine (elevated):",
                              "commands": [f'Invoke-WebRequest -Uri {cmdsafe.ps_quote(cmdsafe.url(missing["aia_url"]) or "http://<AIA URL from the certificate>")} -OutFile issuer.crt',
                                           "certutil -addstore Root issuer.crt"]})
            elif missing["aia_url"]:
                steps.append({"title": f"Get the missing intermediate '{missing['issuer_short']}'",
                              "detail": "Download it from the AIA URL (or use 'Fetch missing intermediate' below), convert it to PEM if it's DER, "
                                        "and append it after the certificate it signed. On Windows/IIS, installing it in the Intermediate store is enough.",
                              "commands": [f'Invoke-WebRequest -Uri {cmdsafe.ps_quote(cmdsafe.url(missing["aia_url"]) or "http://<AIA URL from the certificate>")} -OutFile intermediate.crt',
                                           "openssl x509 -inform der -in intermediate.crt -out intermediate.pem",
                                           "certutil -addstore CA intermediate.crt"]})

        # --- order
        in_paste = [k for k in range(n) if k in path]
        wrong_order = not p7_only and len(path) > 1 and in_paste != path
        if wrong_order:
            order = " → ".join(f"{p + 1}. {info[k]['label']}" for p, k in enumerate(path))
            F.append(_f("warning", "Certificates are in the wrong order",
                        f"The correct order is leaf first, then each issuer: {order}. nginx, Apache, HAProxy and most firewalls/appliances "
                        "send the file as-is, and a misordered chain fails on strict clients. Windows/IIS builds the chain itself and doesn't care.",
                        headline=f"{valid_txt}, but the chain is in the wrong order (the server certificate must come first)."))
        elif p7_only and len(path) > 1:
            F.append(_f("info", "PKCS#7 (.p7b) bundle", "A .p7b has no meaningful order; the chain below was rebuilt by matching issuers. "
                        "On Windows, open the .p7b to install, or certutil -addstore CA bundle.p7b for the intermediates."))
        unrelated = [k for k in range(n) if k not in path]
        if unrelated:
            F.append(_f("warning", f"{_plural(len(unrelated), 'certificate')} not part of this chain",
                        f"{', '.join(repr(info[k]['label']) for k in unrelated)}: not an issuer of '{L['label']}'. A chain file should contain "
                        "only the server certificate and its own intermediates; extra certificates confuse some servers."))
        root_included = T["self_signed"] and top_i != leaf_i and top.subject.public_bytes() in store
        if (wrong_order or unrelated or root_included or len(pairs) != n) and len(path) > 1:
            keep = [k for k in path if not (info[k]["self_signed"] and k != leaf_i and certs[k].subject.public_bytes() in store)]
            out["fixed_chain_pem"] = "".join(_pem(certs[k]) for k in keep)
            steps.append({"title": "Use the chain in the correct order",
                          "detail": "Leaf first, then intermediates; publicly trusted root left out. Copy the 'Corrected chain' block below into fullchain.pem, or build it yourself:",
                          "commands": ["Get-Content cert.pem, intermediate.pem | Set-Content fullchain.pem   # PowerShell",
                                       "cat cert.pem intermediate.pem > fullchain.pem   # Linux / macOS"]})
        out["subline"] = f"Issued by {L['issuer_short']} · {L['not_before'][:10]} to {L['not_after'][:10]} · {L['key']['text']}"

    # ------------------------------------------------------------------ CSR
    if csr_pairs:
        csr, src = csr_pairs[0]
        C = _csr_dict(csr, src)
        out["csr"], out["other_csrs"] = C, len(csr_pairs) - 1
        if len(csr_pairs) > 1:
            F.append(_f("info", f"{len(csr_pairs)} CSRs pasted", "Only the first one was decoded and compared."))
        cname = C["label"]
        if C["signature_valid"] is False:
            F.append(_f("critical", "CSR signature is invalid", "The request was altered or damaged after it was created, so a CA will reject it. Generate it again.",
                        headline=f"The CSR for {cname} is damaged: its signature doesn't verify."))
        elif C["signature_valid"]:
            F.append(_f("ok", "CSR signature is valid", "It was signed by the private key that matches its public key, and hasn't been altered."))
        if not C["san"] or not _all_names(C["san"]):
            F.append(_f("warning", "CSR has no Subject Alternative Names (SAN)",
                        "Public CAs usually add the CN as a SAN for you, but internal AD CS templates don't, and browsers ignore the CN. "
                        "Include every name in the SAN list.",
                        headline=None if certs else f"CSR for {cname} has no SAN names. Browsers will reject a certificate issued from it unless the CA adds them."))
            if C["subject_cn"]:
                steps.append({"title": "Create the CSR with SAN names", "detail": "Run locally where the private key will live (openssl 1.1.1+):",
                              "commands": [f'openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out request.csr -subj "/CN={cmdsafe.dns_name(C["subject_cn"])}" '
                                           f'-addext "subjectAltName=DNS:{cmdsafe.dns_name(C["subject_cn"])}"']})
        if C["key"]["type"] == "RSA" and (C["key"]["bits"] or 0) < 2048:
            F.append(_f("critical", f"CSR key is too small ({C['key']['text']})", "Public CAs refuse keys under 2048 bits. Generate a new key and CSR with 2048 or more.",
                        headline=None if certs else f"CSR for {cname} uses a key that is too small ({C['key']['text']}): CAs will refuse it."))
        if C["signature_hash"] in ("sha1", "md5"):
            F.append(_f("warning", f"CSR is signed with {C['signature_hash'].upper()}", "Some CAs reject SHA-1 requests. Regenerate it with SHA-256 (openssl req -sha256, or certreq with HashAlgorithm = sha256)."))
        if host_n and not certs:
            hc = _host_check(host_n, C["san"], C["subject_cn"])
            out["host_check"] = hc
            if hc["covered"]:
                F.append(_f("ok", f"The CSR requests {host_n}", f"Matched by {hc['matched_by']}."))
            else:
                F.append(_f("warning", f"The CSR does not request {host_n}", (hc["note"] or "") + " Add it to the SAN list before submitting.",
                            headline=f"The CSR for {cname} doesn't include {host_n}."))

        # --- CSR <-> certificate
        if certs:
            csr_key = _spki(csr)
            hit = next((k for k in range(len(certs)) if _spki(certs[k]) == csr_key), None)
            L = info[leaf_i]
            if hit == leaf_i:
                out["match"] = {"matches": True, "cert_index": hit}
                F.append(_f("ok", "This certificate matches the CSR", "Same public key, so it pairs with the private key that created the CSR.",
                            headline=None))
                extra = sorted(set(_all_names(C["san"])) - set(_all_names(L["san"])))
                if extra:
                    F.append(_f("info", "Names requested but not issued", f"The CSR asked for {', '.join(extra)}, but the certificate doesn't include them."))
                steps.append({"title": "Install it on the machine that created the CSR",
                              "detail": "On Windows, accepting the certificate re-attaches the private key held with the pending request. If the cert then shows no key icon, repair the link.",
                              "commands": ["certreq -accept cert.cer", f"certutil -repairstore my {L['serial']}"]})
                steps.append({"title": "Need a PFX for another server or firewall?",
                              "detail": "Run this LOCALLY on the machine that holds key.pem; the private key never needs to leave it.",
                              "commands": ["openssl pkcs12 -export -in cert.pem -inkey key.pem -certfile chain.pem -out cert.pfx"]})
            else:
                out["match"] = {"matches": False, "cert_index": hit}
                F.append(_f("critical", "Does NOT match: it was issued for a different key/request",
                            "The certificate's public key isn't the one in the CSR, so the private key you have won't work with it. "
                            "Either it was issued from another CSR (a re-key, another server, or a colleague's request), or the wrong file was downloaded."
                            + (f" It does match '{info[hit]['label']}' in what you pasted." if hit is not None else ""),
                            headline=f"This certificate does NOT match your CSR: it was issued for a different key/request."))
                steps.append({"title": "Find the matching key, or re-issue",
                              "detail": "Compare the key hashes locally; the pair that matches belongs together. On Windows, look for the pending request on the server where the CSR was made. If the key is gone, re-key the certificate at the CA with your current CSR.",
                              "commands": ["openssl x509 -in cert.pem -noout -pubkey | openssl sha256",
                                           "openssl req -in request.csr -noout -pubkey | openssl sha256",
                                           "Get-ChildItem Cert:\\LocalMachine\\REQUEST | Format-List Subject, Thumbprint, NotBefore"]})
        if not certs:
            out["subline"] = f"Certificate request · {C['key']['text']} · {C['signature']}"
            headline_name = cname

    # ------------------------------------------------------------------ verdict
    if certs:
        L = info[leaf_i]
        days = L["days_left"]
        kind = "CA certificate" if L["is_ca"] else "Certificate"
        base = (f"{kind} for {headline_name} expires today" if days == 0 else f"{kind} for {headline_name} is valid for {_plural(days, 'more day')}")
        if out["match"] and out["match"]["matches"]:
            fallback = base + " and matches your CSR."
        elif len(out["chain"]) > 1 and not out["missing"]:
            fallback = base + "; the chain is complete and in the right order."
        else:
            fallback = base + f" (issued by {L['issuer_short']})."
    else:
        C = out["csr"]
        names = _all_names(C["san"])
        fallback = f"CSR for {headline_name} looks good: {C['key']['text']}, {_plural(len(names), 'name')} requested."
    out["severity"], out["headline"] = _pick_headline(F, fallback)
    if out["match"] and not out["match"]["matches"]:  # the question they came with wins over everything else
        out["severity"], out["headline"] = "critical", "This certificate does NOT match your CSR: it was issued for a different key/request."

    # facts
    if certs:
        L = info[leaf_i]
        out["facts"] = [["Expires", L["not_after"][:10]], ["Issuer", L["issuer_short"]], ["Key", L["key"]["text"]],
                        ["Names", str(len(_all_names(L["san"])))], ["Certificates", str(len(certs))]]
        if out["match"]:
            out["facts"].append(["CSR match", "yes" if out["match"]["matches"] else "NO"])
    else:
        C = out["csr"]
        out["facts"] = [["Key", C["key"]["text"]], ["Names", str(len(_all_names(C["san"])))],
                        ["Signature", "valid" if C["signature_valid"] else "invalid" if C["signature_valid"] is False else "unknown"]]
    steps.append({"title": "Inspect locally",
                  "detail": "Same information from the command line (Windows certutil or OpenSSL):",
                  "commands": (["openssl x509 -in cert.pem -noout -text", "certutil -dump cert.cer"] if certs else []) +
                              (["openssl req -in request.csr -noout -text -verify", "certutil -dump request.csr"] if csr_pairs else [])})
    return out


# ====================================================================== fetch missing intermediate
def fetch_intermediate(url: str) -> dict:
    url = (url or "").strip()
    if not url or len(url) > 2048:
        raise ValueError("Give the AIA (CA Issuers) URL to fetch.")
    for _hop in range(3):  # follow at most 2 redirects, re-checking every hop
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("Only http:// and https:// URLs can be fetched.")
        if parts.username or parts.password:
            raise ValueError("URLs with credentials aren't fetched.")
        ip = resolve_safe(_clean_host(parts.hostname), allow_private=False)[0]
        try:
            resp, body, meta = _pinned_send(url, ip, True, FETCH_TIMEOUT, FETCH_MAX + 1)
        except httpx.HTTPError as exc:
            raise ValueError(f"Couldn't download {url}: {exc.__class__.__name__}.") from exc
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
            url = urljoin(url, resp.headers["location"])
            continue
        if resp.status_code != 200:
            raise ValueError(f"{url} returned HTTP {resp.status_code}.")
        if meta.get("truncated") or len(body) > FETCH_MAX:
            raise ValueError(f"{url} returned more than {FETCH_MAX // 1024} KB, which is too big for a CA certificate.")
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
            raise ValueError(f"Downloaded {url}, but it isn't a certificate.")
        return {"url": url, "certs": [{"subject": c.subject.rfc4514_string(), "subject_short": _ca_name(c.subject),
                                       "issuer_short": _ca_name(c.issuer), "not_after": _iso(c.not_valid_after_utc)} for c in certs],
                "pem": "".join(_pem(c) for c in certs)}
    raise ValueError("Too many redirects.")


# ====================================================================== routes
class DecodeRequest(BaseModel):
    # Loosely typed on purpose: a pydantic validation error (422) would echo the input, which could hold a key.
    # decode() validates type and size itself.
    text: Any = ""
    host: Any = ""


class FetchRequest(BaseModel):
    url: Any = ""


@router.post("/api/cert/decode")
def decode_route(body: DecodeRequest):
    host = body.host if isinstance(body.host, str) else ""
    return run(decode, body.text, host[:300])


@router.post("/api/cert/fetch")
def fetch_route(body: FetchRequest):
    return run(fetch_intermediate, body.url[:4096] if isinstance(body.url, str) else "")
