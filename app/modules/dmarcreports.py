"""DMARC aggregate report (RFC 7489 "feedback" XML) and TLS-RPT (RFC 8460 JSON)
analyzer. Answers: who sends mail as this domain, which legitimate senders
fail DMARC (and how to fix each one), what is spoofing, and is the domain
ready for p=quarantine / p=reject?

Uploads arrive as base64 inside a JSON body (no multipart). Everything is
decompressed with a running byte budget (zip/gzip bomb protection), and any
XML with a DOCTYPE or ENTITY declaration is refused before it is parsed.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import io
import ipaddress
import json
import math
import re
import zipfile
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..core.dns_utils import is_ip, make_resolver, ptr, registered_domain, resolve, txt
from ..core.http import run
from ..core.providers import provider_for
from .ipinfo import SERVICES, asn_lookup, identify_service

router = APIRouter()

MAX_FILE_BYTES = 10 * 1024 * 1024         # each uploaded file (after base64 decoding)
MAX_TOTAL_BYTES = 60 * 1024 * 1024        # everything decompressed, all files together
MAX_DOCUMENTS = 300                       # XML / JSON report documents per request
MAX_FILES = 300
MAX_ZIP_ENTRIES = 2000
LOOKUP_TOP_IPS = 60                       # reverse DNS / ASN only for the busiest IPs
LOOKUP_DEADLINE = 10.0                    # seconds for all sender lookups together
CHUNK = 64 * 1024


# Size limits are checked in code rather than with Field(max_length=...): a
# pydantic 422 echoes the whole oversized input back in the error response.
class UploadFile(BaseModel):
    name: str = "upload"
    data_b64: str


class ReportRequest(BaseModel):
    files: list[UploadFile] = Field(default_factory=list)
    text: str = ""
    domain: str | None = None


@router.post("/api/dmarcreport/analyze")
def dmarcreport_analyze(body: ReportRequest):
    return run(analyze_reports, [(f.name, f.data_b64) for f in body.files], body.text, body.domain)


# =================================================================== extraction
class _Budget:
    def __init__(self) -> None:
        self.left = MAX_TOTAL_BYTES
        self.docs = 0

    def take(self, n: int) -> None:
        self.left -= n
        if self.left < 0:
            raise ValueError(
                f"Refused: the upload decompresses to more than {MAX_TOTAL_BYTES // (1024 * 1024)} MB. "
                "That's the zip/gzip-bomb safety limit. Real aggregate reports are small, so upload fewer files at a time.")

    def doc(self) -> None:
        self.docs += 1
        if self.docs > MAX_DOCUMENTS:
            raise ValueError(f"Refused: more than {MAX_DOCUMENTS} report documents in one request. Upload them in batches.")


def _read_capped(stream, budget: _Budget) -> bytes:
    out = bytearray()
    while True:
        chunk = stream.read(CHUNK)
        if not chunk:
            return bytes(out)
        budget.take(len(chunk))
        out += chunk


def _gunzip(data: bytes, budget: _Budget) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        return _read_capped(gz, budget)


def _safe_zip_name(name: str) -> bool:
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n) or any(part == ".." for part in n.split("/")):
        return False
    return bool(re.search(r"\.(xml|json|gz)$", n, re.I))


def _extract(name: str, data: bytes, budget: _Budget, docs: list, problems: list, depth: int = 0) -> None:
    """Turn one uploaded blob into documents: (label, bytes)."""
    if data[:2] == b"\x1f\x8b":
        try:
            inner = _gunzip(data, budget)
        except (OSError, EOFError, zlib.error) as exc:
            problems.append({"name": name, "reason": f"Not a valid gzip file ({exc.__class__.__name__})."})
            return
        if depth < 1 and (inner[:2] == b"\x1f\x8b" or inner[:4] == b"PK\x03\x04"):
            _extract(name, inner, budget, docs, problems, depth + 1)
            return
        budget.doc()
        docs.append((name, inner))
        return
    if data[:4] == b"PK\x03\x04":
        if depth >= 1:
            problems.append({"name": name, "reason": "Nested archive ignored."})
            return
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            infos = zf.infolist()
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            problems.append({"name": name, "reason": f"Not a valid zip file ({exc})."})
            return
        used = 0
        for info in infos[:MAX_ZIP_ENTRIES]:
            if info.is_dir():
                continue
            label = f"{name} → {info.filename}"
            if not _safe_zip_name(info.filename):
                problems.append({"name": label, "reason": "Skipped: not an .xml/.json/.gz entry, or an unsafe path."})
                continue
            if info.flag_bits & 0x1:
                problems.append({"name": label, "reason": "Skipped: the entry is encrypted."})
                continue
            try:
                with zf.open(info) as fh:
                    inner = _read_capped(fh, budget)
            except ValueError:
                raise
            except (zipfile.BadZipFile, OSError, EOFError, zlib.error, NotImplementedError, RuntimeError) as exc:
                problems.append({"name": label, "reason": f"Could not decompress ({exc})."})
                continue
            used += 1
            _extract(label, inner, budget, docs, problems, depth + 1)
        if len(infos) > MAX_ZIP_ENTRIES:
            problems.append({"name": name, "reason": f"Only the first {MAX_ZIP_ENTRIES} entries were read."})
        if not used and not any(p["name"].startswith(name) for p in problems):
            problems.append({"name": name, "reason": "The zip contains no .xml, .json or .gz files."})
        return
    budget.doc()
    docs.append((name, data))


def _decode_b64(name: str, s: str) -> bytes:
    s = s.strip()
    if s.startswith("data:") and "," in s[:200]:
        s = s.split(",", 1)[1]
    try:
        data = base64.b64decode(re.sub(r"\s+", "", s), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{name}: the file data is not valid base64.") from exc
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"{name} is {len(data) / 1048576:.1f} MB. The limit is {MAX_FILE_BYTES // 1048576} MB per file.")
    return data


def _to_text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


_DTD_RX = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.I)


# ===================================================================== parsing
def _strip_ns(root: ET.Element) -> ET.Element:
    for e in root.iter():
        if isinstance(e.tag, str) and "}" in e.tag:
            e.tag = e.tag.split("}", 1)[1]
    return root


def _t(node: ET.Element | None, path: str) -> str:
    if node is None:
        return ""
    found = node.find(path)
    return (found.text or "").strip() if found is not None and found.text else ""


def _int(v: str, default: int = 0) -> int:
    try:
        return max(0, int(float(v)))
    except (TypeError, ValueError):
        return default


def _iso(epoch: int | None) -> str | None:
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _parse_dmarc(label: str, text: str) -> dict:
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1)
    try:
        root = _strip_ns(ET.fromstring(body))
    except ET.ParseError as exc:
        raise ValueError(f"Malformed XML ({exc}).") from exc
    if root.tag != "feedback":
        raise ValueError(f"Not a DMARC aggregate report (root element is <{root.tag}>, expected <feedback>).")
    meta = root.find("report_metadata")
    pol = root.find("policy_published")
    rep = {
        "file": label,
        "org": _t(meta, "org_name") or "(unknown reporter)",
        "email": _t(meta, "email"),
        "report_id": _t(meta, "report_id"),
        "begin": _int(_t(meta, "date_range/begin")) or None,
        "end": _int(_t(meta, "date_range/end")) or None,
        "errors": [e.text.strip() for e in (meta.findall("error") if meta is not None else []) if e.text and e.text.strip()],
        "policy": {k: _t(pol, k).lower() for k in ("domain", "adkim", "aspf", "p", "sp", "pct", "fo", "np", "testing")},
        "records": [],
    }
    for rec in root.findall("record"):
        row = rec.find("row")
        pe = row.find("policy_evaluated") if row is not None else None
        ids = rec.find("identifiers")
        auth = rec.find("auth_results")
        reasons = []
        for r in (pe.findall("reason") if pe is not None else []):
            reasons.append({"type": _t(r, "type").lower(), "comment": _t(r, "comment")})
        rep["records"].append({
            "ip": _t(row, "source_ip"),
            "count": _int(_t(row, "count")),
            "disposition": (_t(pe, "disposition") or "none").lower(),
            "dkim_eval": (_t(pe, "dkim") or "fail").lower(),
            "spf_eval": (_t(pe, "spf") or "fail").lower(),
            "reasons": reasons,
            "header_from": _t(ids, "header_from").lower(),
            "envelope_from": _t(ids, "envelope_from").lower(),
            "dkim": [{"domain": _t(d, "domain").lower(), "selector": _t(d, "selector"), "result": (_t(d, "result") or "none").lower()}
                     for d in (auth.findall("dkim") if auth is not None else [])],
            "spf": [{"domain": _t(s, "domain").lower(), "scope": (_t(s, "scope") or "mfrom").lower(), "result": (_t(s, "result") or "none").lower()}
                    for s in (auth.findall("spf") if auth is not None else [])],
        })
    if not rep["policy"]["domain"]:
        hf = Counter(r["header_from"] for r in rep["records"] if r["header_from"])
        rep["policy"]["domain"] = hf.most_common(1)[0][0] if hf else ""
    return rep


def _parse_tlsrpt(label: str, text: str) -> dict:
    try:
        d = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON ({exc.msg} at line {exc.lineno}).") from exc
    if not isinstance(d, dict) or "policies" not in d:
        raise ValueError("JSON but not a TLS-RPT report (no \"policies\" array).")
    dr = d.get("date-range") or {}
    out = {"file": label, "org": str(d.get("organization-name") or "(unknown reporter)"), "report_id": str(d.get("report-id") or ""),
           "start": str(dr.get("start-datetime") or "") or None, "end": str(dr.get("end-datetime") or "") or None,
           "contact": str(d.get("contact-info") or ""), "policies": []}
    for p in d.get("policies") or []:
        if not isinstance(p, dict):
            continue
        pol = p.get("policy") or {}
        summ = p.get("summary") or {}
        fails = []
        for f in p.get("failure-details") or []:
            if not isinstance(f, dict):
                continue
            fails.append({"type": str(f.get("result-type") or "unknown").lower(), "count": _int(f.get("failed-session-count")),
                          "mx": str(f.get("receiving-mx-hostname") or "").lower().rstrip("."), "receiving_ip": str(f.get("receiving-ip") or ""),
                          "sending_ip": str(f.get("sending-mta-ip") or ""), "info": str(f.get("additional-information") or "")[:300],
                          "code": str(f.get("failure-reason-code") or "")[:200]})
        mx = pol.get("mx-host") or []
        out["policies"].append({
            "type": str(pol.get("policy-type") or "unknown").lower(),
            "domain": str(pol.get("policy-domain") or "").lower(),
            "mx_hosts": [str(x) for x in mx] if isinstance(mx, list) else [str(mx)],
            "policy_string": [str(x) for x in (pol.get("policy-string") or [])][:20],
            "success": _int(summ.get("total-successful-session-count")),
            "failure": _int(summ.get("total-failure-session-count")),
            "failures": fails,
        })
    return out


# ============================================================ sender knowledge
SERVICE_BY_NAME = {s["name"]: s for s in SERVICES}

# Domains that show up as DKIM d= or envelope-from when a platform sends with
# its own identity instead of the customer's. registered domain -> service name
# (names match app/modules/ipinfo.py SERVICES so the SPF include is reused).
REPORT_DOMAINS = {
    "mcsv.net": "Mailchimp", "mcdlv.net": "Mailchimp", "rsgsv.net": "Mailchimp",
    "mandrillapp.com": "Mandrill (Mailchimp Transactional)",
    "sendgrid.net": "SendGrid (Twilio)",
    "amazonses.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "sparkpostmail.com": "SparkPost / Bird",
    "mtasv.net": "Postmark",
    "sendinblue.com": "Brevo (Sendinblue)", "brevo.com": "Brevo (Sendinblue)",
    "mailjet.com": "Mailjet",
    "hubspotemail.net": "HubSpot",
    "zendesk.com": "Zendesk",
    "salesforce.com": "Salesforce", "exacttarget.com": "Salesforce",
    "onmicrosoft.com": "Microsoft 365 / Exchange Online",
    "gappssmtp.com": "Google Workspace / Gmail",
    "constantcontact.com": "Constant Contact",
    "freshdesk.com": "Freshdesk",
    "zoho.com": "Zoho Mail", "zohomail.com": "Zoho Mail",
}

# How to make each platform sign DKIM with the customer's own domain.
DKIM_FIX = {
    "Mailchimp": "Authenticate {d} in Mailchimp (Domains settings): it gives you CNAME records (k2/k3._domainkey) so campaigns are signed with d={d} instead of Mailchimp's domain.",
    "Mandrill (Mailchimp Transactional)": "Add {d} as a sending domain in Mandrill and publish the DKIM record it shows, so mail is signed with d={d}.",
    "SendGrid (Twilio)": "In SendGrid → Settings → Sender Authentication → Authenticate Your Domain, add {d} and publish the CNAMEs. That gives a custom DKIM signature and a custom return-path, so both DKIM and SPF align.",
    "Amazon SES": "Verify {d} in SES with Easy DKIM (3 CNAME records), and optionally set a custom MAIL FROM subdomain so SPF aligns too.",
    "Mailgun": "Send from a Mailgun domain that is {d} (or a subdomain of it) and publish the DKIM TXT record Mailgun shows for it.",
    "SparkPost / Bird": "Add {d} as a sending domain in SparkPost and publish its DKIM record.",
    "Postmark": "Add {d} as a Sender Signature/domain in Postmark and publish its DKIM record (and the custom Return-Path CNAME for SPF alignment).",
    "Brevo (Sendinblue)": "Authenticate {d} in Brevo (Senders, Domains & Dedicated IPs → Domains) and publish the DKIM record it gives you.",
    "Mailjet": "Authenticate {d} in Mailjet's domain settings and publish the DKIM record it shows.",
    "HubSpot": "Connect {d} as an email sending domain in HubSpot (Settings → Domains & URLs) and publish the DKIM CNAMEs it shows.",
    "Zendesk": "Turn on digital signatures for {d} in Zendesk (Channels → Email) and publish the DKIM CNAMEs it shows.",
    "Salesforce": "Create a DKIM key for {d} in Salesforce Setup (DKIM Keys), publish the CNAMEs, then activate it.",
    "Microsoft 365 / Exchange Online": "Enable DKIM for {d} in Microsoft Defender (Email authentication → DKIM). Until then Microsoft signs with the tenant's onmicrosoft.com domain, which doesn't align.",
    "Google Workspace / Gmail": "Turn on DKIM for {d} in the Google Admin console (Apps → Google Workspace → Gmail → Authenticate email), publish the google._domainkey TXT record, then click Start authentication.",
    "Constant Contact": "Set up DKIM for {d} in Constant Contact's account settings and publish the records it shows.",
    "Freshdesk": "Configure DKIM for {d} in Freshdesk's email settings and publish the records it shows.",
    "Zoho Mail": "Add a DKIM selector for {d} in the Zoho Mail admin console, publish the TXT record it shows and verify it.",
}

M365_COMMANDS = [
    "Connect-ExchangeOnline",
    "New-DkimSigningConfig -DomainName {d} -Enabled $false   # skip if it already exists",
    "Get-DkimSigningConfig -Identity {d} | Format-List Selector1CNAME, Selector2CNAME",
    "# publish selector1._domainkey and selector2._domainkey as CNAMEs to those values, then:",
    "Set-DkimSigningConfig -Identity {d} -Enabled $true",
]

FORWARD_REASONS = {"forwarded", "mailing_list", "trusted_forwarder"}

REPORTER_NAMES = [
    (r"google", "Google"), (r"outlook|microsoft|hotmail", "Microsoft"), (r"yahoo|aol|oath", "Yahoo / AOL"),
    (r"comcast", "Comcast"), (r"mail\.ru", "Mail.ru"), (r"yandex", "Yandex"), (r"zoho", "Zoho"),
    (r"apple|icloud", "Apple iCloud"), (r"fastmail", "Fastmail"), (r"proton", "Proton"), (r"gmx|web\.de|1&1|ionos", "GMX / WEB.DE / IONOS"),
    (r"cloudflare", "Cloudflare"), (r"mimecast", "Mimecast"), (r"proofpoint", "Proofpoint"), (r"t-online", "T-Online"),
]


def _reporter(org: str) -> str:
    for rx, name in REPORTER_NAMES:
        if re.search(rx, org, re.I):
            return name
    return org


def _aligned(a: str, b: str, mode: str) -> bool:
    if not a or not b:
        return False
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b if mode == "s" else registered_domain(a) == registered_domain(b)


def _lookup_ip(res, ip: str) -> dict:
    out: dict = {"ptr": None, "asn": None, "as_name": None}
    try:
        names = ptr(res, ip)
        out["ptr"] = names[0] if names else None
        a = asn_lookup(res, ip)
        if a:
            out["asn"], out["as_name"] = a.get("asn"), a.get("name")
    except Exception:  # noqa: BLE001 - a lookup failure just leaves the IP unidentified
        pass
    return out


def _lookups(ips: list[str]) -> dict[str, dict]:
    res = make_resolver(None, timeout=2.5, lifetime=5.0)
    todo = []
    out: dict[str, dict] = {}
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            special = None if addr.is_global else "Documentation / private / reserved address (not looked up)"
        except ValueError:
            special = "Invalid address"
        if special:
            out[ip] = {"ptr": None, "asn": None, "as_name": None, "special": special}
        else:
            todo.append(ip)
    pool = ThreadPoolExecutor(max_workers=16)
    futs = {pool.submit(_lookup_ip, res, ip): ip for ip in todo}
    done, _ = wait(futs, timeout=LOOKUP_DEADLINE)
    for f in futs:
        out[futs[f]] = f.result() if f in done else {"ptr": None, "asn": None, "as_name": None, "timeout": True}
    pool.shutdown(wait=False, cancel_futures=True)
    return out


def _domain_context(domain: str) -> dict:
    """The policy domain's own MX platform and SPF includes (one lookup each)."""
    res = make_resolver(None, timeout=2.5, lifetime=5.0)
    ctx: dict = {"mx_providers": [], "spf": None, "spf_includes": []}
    with ThreadPoolExecutor(max_workers=2) as pool:
        mx_f = pool.submit(resolve, res, domain, "MX")
        txt_f = pool.submit(txt, res, domain)
        mx, _ = mx_f.result()
        txts, _ = txt_f.result()
    for r in mx:
        try:
            prov = provider_for(r.exchange.to_text(omit_final_dot=True))
        except AttributeError:
            prov = None
        if prov and prov["name"] not in ctx["mx_providers"]:
            ctx["mx_providers"].append(prov["name"])
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if spf:
        ctx["spf"] = spf[0]
        ctx["spf_includes"] = [m.lower() for m in re.findall(r"\binclude:(\S+)", spf[0], re.I)]
    return ctx


def _platform_used(service: str, ctx: dict) -> bool:
    """Does the domain itself use this mailbox platform (MX or SPF)?"""
    svc = SERVICE_BY_NAME.get(service) or {}
    inc = svc.get("spf")
    if inc and inc in ctx["spf_includes"]:
        return True
    if service.startswith("Microsoft 365"):
        return "Microsoft 365" in ctx["mx_providers"]
    if service.startswith("Google"):
        return "Google" in ctx["mx_providers"]
    return False


# ==================================================================== analysis
def _identify(ip: str, recs: list[dict], look: dict | None, domain: str) -> dict:
    """Who is this IP? Uses reverse DNS / ASN (if looked up) plus the domains the
    report itself shows (DKIM d=, envelope from)."""
    look = look or {}
    ptr_name = look.get("ptr")
    ident: dict = {"name": None, "kind": None, "via": None, "spf_include": None, "own": False}
    # Reverse DNS only: an ASN match alone (e.g. Microsoft's AS8075) also covers
    # cloud VMs (Azure, AWS EC2) that anyone can rent, so it proves nothing.
    svc = identify_service([ptr_name] if ptr_name else [], None, None)
    if svc:
        ident.update(name=svc["name"], via=svc["matched_on"], spf_include=svc["spf_include"], kind="sender", known=True)
    if not ident["name"]:
        report_doms = Counter()
        for r in recs:
            for d in r["dkim"]:
                if d["domain"]:
                    report_doms[registered_domain(d["domain"])] += r["count"]
            for s in r["spf"]:
                if s["domain"]:
                    report_doms[registered_domain(s["domain"])] += r["count"]
            if r["envelope_from"]:
                report_doms[registered_domain(r["envelope_from"])] += r["count"]
        for dom, _ in report_doms.most_common():
            if dom in REPORT_DOMAINS:
                name = REPORT_DOMAINS[dom]
                ident.update(name=name, via=f"report shows {dom}", spf_include=(SERVICE_BY_NAME.get(name) or {}).get("spf"), kind="sender", known=True)
                break
    if not ident["name"] and ptr_name:
        prov = provider_for(ptr_name)
        if prov and re.search(r"\.(amazonaws\.com|compute\.internal)$", ptr_name, re.I):
            ident.update(name="Amazon AWS (cloud server)", via="reverse DNS")   # EC2: rentable by anyone
        elif prov:
            ident.update(name=prov["name"], via="reverse DNS", kind=prov["kind"], known=True)
    if ptr_name and registered_domain(ptr_name) == registered_domain(domain):
        ident["own"] = True
        if not ident["name"]:
            ident.update(name=f"{registered_domain(domain)} own server", via="reverse DNS", known=True)
    if ident["name"] and (ident["name"].startswith("Microsoft 365") or ident["name"].startswith("Google")):
        ident["kind"] = "mailbox"
    elif ident["name"] in ("Yahoo", "Apple iCloud", "Fastmail", "Proton Mail", "Zoho Mail"):
        ident["kind"] = "mailbox"
    if not ident["name"]:
        if ptr_name:
            ident.update(name=registered_domain(ptr_name), via="reverse DNS")
        elif look.get("as_name"):
            ident.update(name=look["as_name"], via=f"ASN {look.get('asn')}")
    return ident


def _record_category(r: dict, ident: dict, ip_passes: bool, domain: str, pol: dict, ctx: dict) -> str:
    """aligned | forwarding | legit_failing | spoofing"""
    passed = r["dkim_eval"] == "pass" or r["spf_eval"] == "pass"
    raw_spf_pass = any(s["result"] == "pass" for s in r["spf"])
    own_dkim = [d for d in r["dkim"] if _aligned(d["domain"], r["header_from"] or domain, "r")]
    forward_reason = any(x["type"] in FORWARD_REASONS or "arc=pass" in x["comment"].lower() for x in r["reasons"])
    known = bool(ident.get("known"))
    platform_mailbox = known and ident.get("kind") == "mailbox" and not _platform_used(ident.get("name") or "", ctx) and not ident.get("own")
    if passed:
        # DKIM survived but SPF broke: classic forwarding, harmless.
        if r["dkim_eval"] == "pass" and not raw_spf_pass and (forward_reason or platform_mailbox or not known):
            return "forwarding"
        return "aligned"
    if forward_reason:
        return "forwarding"
    if own_dkim and all(d["result"] != "pass" for d in own_dkim) and (platform_mailbox or not known) and not ip_passes:
        # Our own signature was present but broke in transit (list footer, subject tag).
        return "forwarding"
    if platform_mailbox and _aligned(r["envelope_from"], domain, "r"):
        return "forwarding"
    if ident.get("own") or ip_passes or (known and not platform_mailbox):
        return "legit_failing"
    if any(d["result"] == "pass" and _aligned(d["domain"], domain, "r") for d in r["dkim"]):
        return "legit_failing"   # signed by us, but alignment mode (strict) made it fail
    return "spoofing"


def _fix_for(sender: dict, domain: str, pol: dict, ctx: dict) -> dict:
    """Plain-English fix for a legitimate sender that fails DMARC."""
    name = sender["name"]
    svc_name = sender.get("service") or name
    d = domain
    dkim_doms = [x for x, _ in sender["dkim_domains"].most_common()]
    env_doms = [x for x, _ in sender["envelope_domains"].most_common()]
    adkim, aspf = pol.get("adkim") or "r", pol.get("aspf") or "r"
    why, fix, link, commands, short = [], [], None, [], []
    own_sigs = [x for x in dkim_doms if _aligned(x, d, "r")]
    foreign_sigs = [x for x in dkim_doms if not _aligned(x, d, "r")]
    dkim_pass_own = sender["dkim_raw_pass_own"]
    if foreign_sigs and not own_sigs:
        why.append(f"it signs DKIM with d={foreign_sigs[0]}, not {d}")
        short.append(f"it signs with d={foreign_sigs[0]}")
    elif own_sigs and not dkim_pass_own:
        sel = sender["selectors"].most_common(1)[0][0] if sender["selectors"] else "?"
        why.append(f"its DKIM signature for d={own_sigs[0]} (selector {sel}) fails")
        short.append(f"its DKIM signature (s={sel}) fails")
    elif own_sigs and dkim_pass_own and adkim == "s":
        why.append(f"it signs with d={own_sigs[0]}, which doesn't match {d} exactly and the policy uses strict DKIM alignment (adkim=s)")
        short.append("strict alignment (adkim=s) rejects its subdomain signature")
    elif not dkim_doms:
        why.append("it doesn't DKIM-sign at all")
        short.append("it isn't DKIM-signed")
    env = env_doms[0] if env_doms else ""
    if env and not _aligned(env, d, aspf):
        why.append(f"its envelope sender (Return-Path) is {env}, so SPF can't align")
    elif env and sender["spf_raw_fail"]:
        why.append(f"{sender['ips'][0] if sender['ips'] else 'its IP'} isn't authorised in the SPF record of {env}")
        short.append(f"it isn't in the SPF record of {env}")

    if svc_name in DKIM_FIX and not (own_sigs and dkim_pass_own and adkim == "s"):
        fix.append(DKIM_FIX[svc_name].format(d=d))
        if svc_name.startswith("Microsoft 365"):
            commands = [c.format(d=d) for c in M365_COMMANDS]
    elif own_sigs and not dkim_pass_own:
        fix.append(f"Check that the DKIM public key for that selector is published at <selector>._domainkey.{registered_domain(own_sigs[0])} and matches the key the server signs with.")
    elif own_sigs and adkim == "s":
        fix.append("Relax DKIM alignment to adkim=r (the default) in the DMARC record, or sign with the exact From domain.")
    else:
        fix.append(f"Configure DKIM signing for {d} on this sender (most platforms call it 'domain authentication').")
    include = sender.get("spf_include")
    if env and _aligned(env, d, aspf) and sender["spf_raw_fail"]:
        target = registered_domain(env) if env.endswith(registered_domain(d)) else env
        if include and include not in ctx["spf_includes"]:
            fix.append(f"Add include:{include} to the SPF record of {target}.")
            link = {"tool": "spfbuild", "params": {"d": target, "add": f"include:{include}"}, "text": f"Add include:{include} in the SPF Builder →"}
        elif include:
            fix.append(f"include:{include} is already in the SPF record of {target}, yet this IP fails SPF. Check the record for errors (over 10 DNS lookups, a second SPF record, a typo).")
            link = {"tool": "spf", "params": {"d": target}, "text": f"Check {target} in SPF Inspector →"}
        elif sender.get("own") and len(sender["ips"]) <= 3:
            ip = sender["ips"][0]
            term = f"ip6:{ip}" if ":" in ip else f"ip4:{ip}"
            fix.append(f"Add {term} to the SPF record of {target}.")
            link = {"tool": "spfbuild", "params": {"d": target, "add": term}, "text": f"Add {term} in the SPF Builder →"}
    return {"why": why, "short": short[0] if short else "it fails SPF and DKIM alignment", "fix": fix, "link": link, "commands": commands}


_UNKNOWN_NAMES = {"spoofing": "Unknown sources", "forwarding": "Unknown forwarders / mailing lists",
                  "aligned": "Unidentified senders (passing)", "legit_failing": "Unidentified senders"}


def _analyze_dmarc(reports: list[dict], want_domain: str | None) -> dict:
    by_domain: dict[str, list[dict]] = defaultdict(list)
    for rep in reports:
        by_domain[rep["policy"]["domain"] or "(unknown)"].append(rep)
    volumes = {d: sum(r["count"] for rep in reps for r in rep["records"]) for d, reps in by_domain.items()}
    domains = sorted(volumes, key=lambda d: -volumes[d])
    domain = (want_domain or "").lower().strip().rstrip(".")
    if domain not in by_domain:
        domain = domains[0]
    reps = by_domain[domain]
    reps.sort(key=lambda r: r["end"] or 0)
    pol = dict(reps[-1]["policy"])
    policies_seen = sorted({f"p={r['policy']['p'] or '?'}" + (f"; pct={r['policy']['pct']}" if r["policy"]["pct"] not in ("", "100") else "") for r in reps})

    records = [r for rep in reps for r in rep["records"] if r["count"] > 0]
    total = sum(r["count"] for r in records)
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_ip[r["ip"]].append(r)
    ip_vol = {ip: sum(r["count"] for r in rs) for ip, rs in by_ip.items()}
    ranked = sorted(ip_vol, key=lambda ip: -ip_vol[ip])
    ctx_pool = ThreadPoolExecutor(max_workers=1)
    ctx_f = ctx_pool.submit(_domain_context, domain) if domain != "(unknown)" else None
    looked = _lookups([ip for ip in ranked[:LOOKUP_TOP_IPS] if is_ip(ip)])
    try:
        ctx = ctx_f.result(timeout=8) if ctx_f else None
    except Exception:  # noqa: BLE001 - DNS trouble just means less context
        ctx = None
    ctx_pool.shutdown(wait=False)
    ctx = ctx or {"mx_providers": [], "spf": None, "spf_includes": []}

    ip_rows, senders = [], {}
    cat_vol = Counter()
    for rank, ip in enumerate(ranked):
        rs = by_ip[ip]
        look = looked.get(ip)
        ident = _identify(ip, rs, look, domain)
        if not ident["name"]:
            ident["unidentified"] = True
        # SPF-aligned pass = this IP is authorised by the domain itself (DKIM passes
        # alone don't prove that: forwarders relay DKIM-signed mail too).
        ip_passes = any(r["spf_eval"] == "pass" for r in rs)
        counts = Counter()
        for r in rs:
            cat = _record_category(r, ident, ip_passes, domain, pol, ctx)
            counts[cat] += r["count"]
            cat_vol[cat] += r["count"]
            name = ident["name"] if ident.get("known") or (ident["name"] and cat not in ("spoofing", "forwarding")) else _UNKNOWN_NAMES[cat]
            key = (name, cat)
            s = senders.get(key)
            if not s:
                s = senders[key] = {"name": name, "category": cat, "service": ident["name"] if ident["name"] in SERVICE_BY_NAME else None,
                                    "spf_include": ident.get("spf_include"), "own": ident.get("own"), "via": ident.get("via") if name == ident["name"] else None,
                                    "count": 0, "pass": 0, "spf_aligned": 0, "dkim_aligned": 0, "ips": [], "ipset": set(), "dkim_domains": Counter(),
                                    "selectors": Counter(), "envelope_domains": Counter(), "header_from": Counter(), "dispositions": Counter(),
                                    "dkim_raw_pass_own": False, "spf_raw_fail": False}
            if ip not in s["ipset"]:
                s["ipset"].add(ip)
                s["ips"].append(ip)
            n = r["count"]
            s["count"] += n
            s["pass"] += n if (r["dkim_eval"] == "pass" or r["spf_eval"] == "pass") else 0
            s["spf_aligned"] += n if r["spf_eval"] == "pass" else 0
            s["dkim_aligned"] += n if r["dkim_eval"] == "pass" else 0
            for dk in r["dkim"]:
                if dk["domain"]:
                    s["dkim_domains"][dk["domain"]] += n
                if dk["selector"]:
                    s["selectors"][dk["selector"]] += n
                if dk["result"] == "pass" and _aligned(dk["domain"], domain, "r"):
                    s["dkim_raw_pass_own"] = True
            env = r["envelope_from"] or next((x["domain"] for x in r["spf"] if x["scope"] == "mfrom" and x["domain"]), "")
            if env:
                s["envelope_domains"][env] += n
            if r["spf"] and not any(x["result"] == "pass" for x in r["spf"]):
                s["spf_raw_fail"] = True
            s["header_from"][r["header_from"]] += n
            s["dispositions"][r["disposition"]] += n
        spf_raw = Counter(x["result"] for r in rs for x in r["spf"])
        dkim_raw = [f"d={x['domain']} s={x['selector'] or '?'}: {x['result']}" for x in
                    {(x["domain"], x["selector"], x["result"]): x for r in rs for x in r["dkim"]}.values()]
        main_cat = counts.most_common(1)[0][0]
        ip_rows.append({
            "ip": ip, "count": ip_vol[ip], "ptr": (look or {}).get("ptr"), "as_name": (look or {}).get("as_name"),
            "special": (look or {}).get("special"), "looked_up": look is not None, "sender": ident["name"] if ident.get("known") else _UNKNOWN_NAMES[main_cat], "category": main_cat,
            "categories": dict(counts), "pass": sum(r["count"] for r in rs if r["dkim_eval"] == "pass" or r["spf_eval"] == "pass"),
            "spf_aligned": sum(r["count"] for r in rs if r["spf_eval"] == "pass"),
            "dkim_aligned": sum(r["count"] for r in rs if r["dkim_eval"] == "pass"),
            "spf_raw": dict(spf_raw), "dkim_raw": dkim_raw[:6],
            "disposition": dict(_sum_by(rs, "disposition")),
            "header_from": sorted({r["header_from"] for r in rs if r["header_from"]})[:4],
            "envelope_from": sorted({r["envelope_from"] for r in rs if r["envelope_from"]})[:4],
            "reasons": sorted({x["type"] + (f" ({x['comment']})" if x["comment"] else "") for r in rs for x in r["reasons"]})[:4],
        })

    # ---- per-sender output with fixes
    sender_list = []
    for s in senders.values():
        fix = _fix_for(s, domain, pol, ctx) if s["category"] == "legit_failing" else None
        sender_list.append({
            "name": s["name"], "category": s["category"], "via": s["via"], "count": s["count"], "pass": s["pass"],
            "spf_aligned": s["spf_aligned"], "dkim_aligned": s["dkim_aligned"], "ips": s["ips"][:20], "ip_count": len(s["ips"]),
            "dkim_domains": [f"{k}" for k, _ in s["dkim_domains"].most_common(4)],
            "selectors": [k for k, _ in s["selectors"].most_common(4)],
            "envelope_from": [k for k, _ in s["envelope_domains"].most_common(4)],
            "header_from": [k for k, _ in s["header_from"].most_common(3) if k],
            "dispositions": dict(s["dispositions"]), "fix": fix,
        })
    order = {"legit_failing": 0, "spoofing": 1, "forwarding": 2, "aligned": 3}
    sender_list.sort(key=lambda x: (order[x["category"]], -x["count"]))

    # ---- readiness
    passing = sum(s["pass"] for s in sender_list)   # everything that passed DMARC, forwarders included
    fwd_fail = sum(s["count"] - s["pass"] for s in sender_list if s["category"] == "forwarding")
    legit_fail = cat_vol["legit_failing"]
    spoof = cat_vol["spoofing"]
    legit_total = passing + legit_fail
    fail_pct = (legit_fail / legit_total * 100) if legit_total else 0.0
    pass_pct = 100 - fail_pct if legit_total else 0.0
    spoof_ips = sum(s["ip_count"] for s in sender_list if s["category"] == "spoofing")
    failing_legit = [s for s in sender_list if s["category"] == "legit_failing"]
    p = pol.get("p") or "none"
    ready_reject = legit_total > 0 and fail_pct < 1.0
    ready_quar = legit_total > 0 and fail_pct < 5.0

    begin = min((r["begin"] for r in reps if r["begin"]), default=None)
    end = max((r["end"] for r in reps if r["end"]), default=None)
    days = round((end - begin) / 86400, 1) if begin and end else None

    # ---- verdict
    def _who(lst, n=2):
        """ "(Mailchimp, 198.51.100.7) fails DMARC because it signs with d=mcsv.net" """
        where = lambda s: s["ips"][0] if s["ip_count"] == 1 else f"{s['ip_count']} IPs"
        if len(lst) == 1:
            s = lst[0]
            return f"({s['name']}, {where(s)}) fails DMARC because {s['fix']['short']}"
        parts = [f"{s['name']}, {where(s)}: {s['fix']['short']}" for s in lst[:n]]
        return "fails DMARC (" + "; ".join(parts) + (f"; +{len(lst) - n} more" if len(lst) > n else "") + ")"

    spoof_txt = f"{spoof:,} spoofed message{'s' if spoof != 1 else ''} from {spoof_ips} IP{'s' if spoof_ips != 1 else ''}"
    if total == 0:
        sev, head = "info", f"The reports for {domain} contain no messages"
    elif legit_total == 0:
        sev = "warning" if p == "none" else "info"
        head = (f"No legitimate mail seen for {domain}: all {total:,} messages fail DMARC from unrecognised sources. "
                + ("If the domain really sends no mail, p=reject is safe; otherwise its senders aren't set up yet" if p != "reject" else "p=reject is blocking all of it"))
    elif p == "reject":
        if legit_fail and fail_pct >= 0.1:
            sev = "critical"
            head = f"p=reject is blocking legitimate mail: {_pf(fail_pct, True)}% of it {_who(failing_legit)}"
        else:
            sev = "ok"
            head = f"p=reject is working: {_pf(pass_pct)}% of legitimate mail passes" + (f"; {spoof_txt} were blocked" if spoof else "")
    elif p == "quarantine":
        if legit_fail and fail_pct >= 0.1:
            sev = "critical"
            head = f"p=quarantine is junking legitimate mail: {_pf(fail_pct, True)}% of it {_who(failing_legit)}"
        else:
            sev = "ok"
            head = f"Ready for p=reject: {_pf(pass_pct)}% of legitimate mail passes" + (f"; {spoof_txt} would be blocked instead of junked" if spoof else "")
    else:
        if ready_reject:
            sev = "ok"
            head = f"Ready for p=reject: {_pf(pass_pct)}% of legitimate mail passes" + (f"; {spoof_txt} would be blocked" if spoof else "")
        elif ready_quar:
            sev = "warning"
            head = f"Ready for p=quarantine, not yet p=reject: {_pf(fail_pct, True)}% of legitimate mail {_who(failing_legit)}"
        else:
            sev = "warning"
            head = f"Not ready for p=reject: {_pf(fail_pct, True)}% of legitimate mail {_who(failing_legit)}"
    sub = (f"{total:,} messages for {domain} from {len(ranked)} source IPs in {len(reps)} report{'s' if len(reps) != 1 else ''}"
           + (f", {fmt_date(begin)} to {fmt_date(end)}" if begin and end else "") + f". Published policy: p={p}"
           + (f", pct={pol['pct']}" if pol.get("pct") not in ("", "100", None) else "") + ".")

    # ---- findings
    F: list[dict] = []
    for s in failing_legit:
        sevf = "critical" if p in ("quarantine", "reject") else "warning"
        share = s["count"] - s["pass"]
        F.append({"severity": sevf, "title": f"{s['name']}: {share:,} legitimate messages fail DMARC" + (f" ({s['ips'][0]})" if s["ip_count"] == 1 else f" from {s['ip_count']} IPs"),
                  "detail": ("It fails because " + " and ".join(s["fix"]["why"]) + ". " if s["fix"]["why"] else "") + " ".join(s["fix"]["fix"])})
    if spoof:
        F.append({"severity": "ok" if p == "reject" else "warning" if p == "none" else "info",
                  "title": f"{spoof_txt} (unknown sources failing both SPF and DKIM)",
                  "detail": ("They were rejected by receivers honouring p=reject." if p == "reject" else
                             "They were sent to junk/quarantine." if p == "quarantine" else
                             "With p=none they were delivered as normal. Moving to p=quarantine or p=reject stops them.")
                  + " Check the IPs in the table below: if one of them is actually yours, it's a legitimate sender that needs SPF/DKIM."})
    fwd = [s for s in sender_list if s["category"] == "forwarding"]
    if fwd:
        names = ", ".join(sorted({s["name"] for s in fwd})[:4])
        F.append({"severity": "info", "title": f"{sum(s['count'] for s in fwd):,} forwarded / mailing-list messages ({names})",
                  "detail": "SPF breaks when mail is forwarded; DKIM usually survives. " +
                            (f"{fwd_fail:,} of them also lost DKIM (lists that edit the subject or footer); receivers that trust ARC (Authenticated Received Chain) usually still deliver these. This isn't something you fix in your DNS."
                             if fwd_fail else "All of them still passed DMARC via DKIM: harmless.")})
    if p == "none":
        F.append({"severity": "info", "title": "Policy is p=none (monitoring only)",
                  "detail": "Receivers deliver failing mail normally and just send you these reports. Fix the failing legitimate senders, then move to p=quarantine and later p=reject."})
    if pol.get("pct") not in ("", "100", None) and p != "none":
        F.append({"severity": "info", "title": f"pct={pol['pct']}: the policy only applies to {pol['pct']}% of failing mail",
                  "detail": "The rest is treated one step softer (quarantine → none, reject → quarantine). Raise to 100 once the reports are clean."})
    if pol.get("sp") and pol["sp"] != p:
        F.append({"severity": "info", "title": f"Subdomains use sp={pol['sp']} (main domain p={p})", "detail": "Mail from subdomains follows the sp= policy."})
    if len(policies_seen) > 1:
        F.append({"severity": "info", "title": "The policy changed during this period: " + ", ".join(policies_seen),
                  "detail": "Different reports saw different published policies. The newest one is used for the verdict."})
    if days is not None and days < 7:
        F.append({"severity": "info", "title": f"Only {days:g} days of data",
                  "detail": "Senders like monthly newsletters or invoicing runs may not appear yet. Collect at least 2–4 weeks before moving to reject."})
    if total and total < 100:
        F.append({"severity": "info", "title": f"Low volume ({total} messages)", "detail": "Small samples can hide occasional senders. Collect more reports before enforcing."})
    errs = [e for r in reps for e in r["errors"]]
    if errs:
        F.append({"severity": "info", "title": "Reporters included error notes", "detail": "; ".join(errs[:3])[:400]})
    timeouts = sum(1 for v in looked.values() if v.get("timeout"))
    if timeouts:
        F.append({"severity": "info", "title": f"Reverse DNS/ASN lookups timed out for {timeouts} IP{'s' if timeouts != 1 else ''}", "detail": "Those IPs are labelled from report data only. Run again to retry."})
    if len(ranked) > LOOKUP_TOP_IPS:
        F.append({"severity": "info", "title": f"Only the top {LOOKUP_TOP_IPS} of {len(ranked)} source IPs were looked up",
                  "detail": "The rest are grouped from report data (DKIM d=, envelope sender) or labelled 'Other sources'."})

    # ---- steps
    steps = []
    for s in failing_legit[:6]:
        steps.append({"title": f"Fix {s['name']}" + (f" ({s['ips'][0]})" if s["ip_count"] == 1 else ""),
                      "detail": " ".join(s["fix"]["fix"]), "link": s["fix"]["link"], "commands": s["fix"]["commands"]})
    if p == "none":
        nxt = "p=quarantine" if not ready_reject else "p=quarantine, then p=reject"
        steps.append({"title": f"Move to {nxt}" if ready_quar else "After fixing the senders above, collect another 1–2 weeks of reports",
                      "detail": "Step through the rollout (quarantine 25% → 100% → reject) and re-check these reports at each stage.",
                      "link": {"tool": "dmarcbuild", "params": {"d": domain}, "text": "Open the DMARC Builder →"}})
    elif p == "quarantine" and ready_reject:
        steps.append({"title": "Move to p=reject", "detail": "Legitimate mail passes, so rejecting is safe.",
                      "link": {"tool": "dmarcbuild", "params": {"d": domain}, "text": "Open the DMARC Builder →"}})

    reporters: dict[str, dict] = {}
    for r in reps:
        name = _reporter(r["org"])
        x = reporters.setdefault(name, {"name": name, "orgs": set(), "reports": 0, "messages": 0, "pass": 0})
        x["orgs"].add(r["org"])
        x["reports"] += 1
        x["messages"] += sum(rec["count"] for rec in r["records"])
        x["pass"] += sum(rec["count"] for rec in r["records"] if rec["dkim_eval"] == "pass" or rec["spf_eval"] == "pass")
    reporter_list = sorted(({**v, "orgs": sorted(v["orgs"])} for v in reporters.values()), key=lambda v: -v["messages"])

    dmarc_pass = sum(r["count"] for r in records if r["dkim_eval"] == "pass" or r["spf_eval"] == "pass")
    return {
        "domain": domain, "severity": sev, "headline": head, "subline": sub,
        "domains": [{"domain": d, "messages": volumes[d], "reports": len(by_domain[d])} for d in domains],
        "policy": pol, "policies_seen": policies_seen,
        "date_begin": _iso(begin), "date_end": _iso(end), "days": days,
        "totals": {"messages": total, "ips": len(ranked), "dmarc_pass": dmarc_pass,
                   "dmarc_pass_pct": round(dmarc_pass / total * 100, 1) if total else 0,
                   "aligned": cat_vol["aligned"], "forwarding": cat_vol["forwarding"], "forwarding_failing": fwd_fail,
                   "legit_failing": legit_fail, "spoofing": spoof, "spoofing_ips": spoof_ips},
        "readiness": {"legit_total": legit_total, "legit_pass": passing, "legit_fail": legit_fail,
                      "legit_pass_pct": float(_pf(pass_pct)), "legit_fail_pct": float(_pf(fail_pct, True)),
                      "ready_quarantine": ready_quar, "ready_reject": ready_reject},
        "domain_context": ctx,
        "findings": F, "steps": steps, "senders": sender_list, "ips": ip_rows[:300], "ips_total": len(ip_rows),
        "reporters": reporter_list,
        "reports": [{"org": r["org"], "report_id": r["report_id"], "begin": _iso(r["begin"]), "end": _iso(r["end"]),
                     "p": r["policy"]["p"], "records": len(r["records"]), "messages": sum(x["count"] for x in r["records"]), "file": r["file"]}
                    for r in reps][:300],
    }


def _pf(x: float, up: bool = False) -> str:
    """Percent for headlines: never round 99.96 up to 100 or 0.04 down to 0."""
    if x <= 0:
        return "0"
    if x >= 100:
        return "100"
    v = math.ceil(x * 10) / 10 if up else math.floor(x * 10) / 10
    return f"{v:g}"


def _sum_by(rs: list[dict], key: str) -> Counter:
    c = Counter()
    for r in rs:
        c[r[key]] += r["count"]
    return c


def fmt_date(epoch: int | None) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d") if epoch else "?"


# ===================================================================== TLS-RPT
TLS_RESULTS = {
    "starttls-not-supported": ("critical", "The receiving MX doesn't offer STARTTLS, so the sender couldn't encrypt the connection. Enable TLS on the mail server or gateway."),
    "certificate-host-mismatch": ("critical", "The MX certificate doesn't cover the MX host name the sender connected to. Reissue it with the MX name in the SAN list, or point MX at a name the certificate covers."),
    "certificate-expired": ("critical", "The MX certificate has expired. Renew it on the mail server / gateway and check auto-renewal."),
    "certificate-not-trusted": ("critical", "The MX certificate isn't trusted: it's self-signed, from a private CA, or the intermediate certificate is missing. Install a publicly trusted certificate with its full chain."),
    "validation-failure": ("warning", "A general certificate/TLS validation failure that doesn't fit the other categories. Check the additional information in the report and test the MX with the TLS checker."),
    "tlsa-invalid": ("critical", "DANE: the TLSA record in DNS doesn't match the MX certificate. Update the TLSA record before (or right after) every certificate change."),
    "dnssec-invalid": ("critical", "DANE: DNSSEC validation failed for the MX or TLSA records, so DANE couldn't be used. Check the DNSSEC chain (DS / DNSKEY)."),
    "dane-required": ("critical", "The sender requires DANE but no usable TLSA records were found for the MX."),
    "sts-policy-fetch-error": ("warning", "The sender couldn't download the MTA-STS policy from https://mta-sts.<domain>/.well-known/mta-sts.txt (DNS, HTTPS certificate, or HTTP error). Check that the policy URL loads with a valid certificate."),
    "sts-policy-invalid": ("warning", "The MTA-STS policy file was downloaded but couldn't be parsed. Check its syntax (version: STSv1, mode, mx, max_age)."),
    "sts-webpki-invalid": ("warning", "The certificate on the mta-sts.<domain> web server isn't valid, so the MTA-STS policy couldn't be fetched securely. Fix the HTTPS certificate on that host."),
}


def _analyze_tlsrpt(reps: list[dict]) -> dict:
    pols: dict[tuple, dict] = {}
    types: Counter = Counter()
    mx_fail: Counter = Counter()
    samples: dict[str, dict] = {}
    for rep in reps:
        for p in rep["policies"]:
            key = (p["domain"], p["type"])
            x = pols.setdefault(key, {"domain": p["domain"], "type": p["type"], "success": 0, "failure": 0, "mx_hosts": set(), "reporters": set(), "mode": None})
            x["success"] += p["success"]
            x["failure"] += p["failure"]
            x["mx_hosts"].update(p["mx_hosts"])
            x["reporters"].add(rep["org"])
            for line in p["policy_string"]:
                m = re.match(r"\s*mode\s*:\s*(\w+)", line, re.I)
                if m:
                    x["mode"] = m.group(1).lower()
            for f in p["failures"]:
                types[f["type"]] += f["count"]
                if f["mx"]:
                    mx_fail[f["mx"]] += f["count"]
                samples.setdefault(f["type"], f)
    success = sum(x["success"] for x in pols.values())
    failure = sum(x["failure"] for x in pols.values())
    total = success + failure
    fail_pct = failure / total * 100 if total else 0
    domains = sorted({k[0] for k in pols if k[0]})
    F = []
    for t, n in types.most_common():
        sev, text = TLS_RESULTS.get(t, ("warning", "Not in the knowledge base. See RFC 8460 section 4.3 and the additional information field."))
        smp = samples.get(t) or {}
        extra = f" Example: MX {smp['mx']}" if smp.get("mx") else ""
        extra += f" ({smp['info']})" if smp.get("info") else ""
        F.append({"severity": sev, "title": f"{t}: {n:,} failed sessions", "detail": text + extra})
    for x in pols.values():
        if x["type"] == "sts" and x["failure"]:
            if x["mode"] == "enforce":
                F.append({"severity": "critical", "title": f"MTA-STS is in enforce mode for {x['domain']}: {x['failure']:,} sessions were refused, not just reported",
                          "detail": "Senders that honour MTA-STS won't fall back to unencrypted delivery, so that mail was delayed and will bounce if the problem isn't fixed. If you can't fix the MX quickly, switch the policy to mode: testing."})
            elif x["mode"] == "testing":
                F.append({"severity": "info", "title": f"MTA-STS is in testing mode for {x['domain']}: failed sessions were still delivered",
                          "detail": "Fix the failures above before switching to mode: enforce, or this mail will start bouncing."})
    if any(k[1] == "no-policy-found" for k in pols):
        F.append({"severity": "info", "title": "No MTA-STS or DANE policy found by some senders",
                  "detail": "Sessions were still counted, but nothing forces senders to require TLS. Publish MTA-STS (testing mode first) to enforce encrypted delivery."})
    if total == 0:
        sev, head = "info", "The TLS-RPT reports contain no sessions"
    elif failure == 0:
        sev, head = "ok", f"All {success:,} TLS sessions to {', '.join(domains[:3]) or 'the domain'} succeeded"
    else:
        top = types.most_common(1)[0][0] if types else "unspecified"
        sev = "critical" if fail_pct >= 5 or TLS_RESULTS.get(top, ("warning",))[0] == "critical" and fail_pct >= 1 else "warning"
        head = f"{failure:,} of {total:,} TLS sessions ({fail_pct:.1f}%) to {', '.join(domains[:3]) or 'the domain'} failed, mostly {top}"
    starts = sorted(r["start"] for r in reps if r["start"])
    ends = sorted(r["end"] for r in reps if r["end"])
    return {
        "severity": sev, "headline": head,
        "subline": f"{len(reps)} TLS-RPT report{'s' if len(reps) != 1 else ''} from {len({r['org'] for r in reps})} reporter(s)"
                   + (f", {starts[0][:10]} to {ends[-1][:10]}" if starts and ends else "") + ".",
        "totals": {"success": success, "failure": failure, "fail_pct": round(fail_pct, 1)},
        "policies": [{**x, "mx_hosts": sorted(x["mx_hosts"]), "reporters": sorted(x["reporters"])} for x in
                     sorted(pols.values(), key=lambda v: -(v["success"] + v["failure"]))],
        "failure_types": [{"type": t, "count": n, "explain": TLS_RESULTS.get(t, (None, "Not in the knowledge base."))[1]} for t, n in types.most_common()],
        "mx_failures": [{"mx": m, "count": n} for m, n in mx_fail.most_common(20)],
        "findings": F,
        "domains": domains,
        "reports": [{"org": r["org"], "report_id": r["report_id"], "start": r["start"], "end": r["end"], "file": r["file"],
                     "success": sum(p["success"] for p in r["policies"]), "failure": sum(p["failure"] for p in r["policies"])} for r in reps][:300],
    }


# ================================================================ orchestrator
def analyze_reports(files: list[tuple[str, str]], text: str = "", domain: str | None = None) -> dict:
    if len(files) > MAX_FILES:
        raise ValueError(f"Refused: {len(files)} files. Upload at most {MAX_FILES} per request.")
    if len(text or "") > MAX_FILE_BYTES:
        raise ValueError(f"The pasted text is over {MAX_FILE_BYTES // 1048576} MB. Upload it as a file (gzip it first) instead.")
    for name, b64 in files:
        if len(b64) > MAX_FILE_BYTES * 4 // 3 + 1024:
            raise ValueError(f"{(name or 'upload')[:100]} is over {MAX_FILE_BYTES // 1048576} MB. The limit is {MAX_FILE_BYTES // 1048576} MB per file.")
    files = [((name or "upload")[:255], b64) for name, b64 in files]
    domain = (domain or "")[:253] or None
    budget = _Budget()
    raw: list[tuple[str, bytes]] = []
    for name, b64 in files:
        data = _decode_b64(name or "upload", b64)
        if data:
            raw.append((name or "upload", data))
    if text and text.strip():
        t = text.strip()
        if t.startswith("{") or t.startswith("["):
            raw.append(("pasted JSON", t.encode("utf-8")))
        else:
            parts = [p for p in re.split(r"(?=<\?xml)", t) if p.strip()]
            for i, part in enumerate(parts):
                raw.append((f"pasted XML{f' #{i + 1}' if len(parts) > 1 else ''}", part.encode("utf-8")))
    if not raw:
        raise ValueError("Nothing to analyze. Drop DMARC aggregate reports (.xml, .xml.gz, .zip) or TLS-RPT reports (.json, .json.gz), or paste report XML.")
    total_upload = 0
    for _, data in raw:
        total_upload += len(data)
    if total_upload > MAX_TOTAL_BYTES:
        raise ValueError(f"Refused: {total_upload / 1048576:.1f} MB uploaded; the limit is {MAX_TOTAL_BYTES // 1048576} MB per request.")

    docs: list[tuple[str, bytes]] = []
    problems: list[dict] = []
    for name, data in raw:
        if not (data[:2] == b"\x1f\x8b" or data[:4] == b"PK\x03\x04"):
            budget.take(len(data))
        _extract(name, data, budget, docs, problems)

    dmarc_reps, tls_reps = [], []
    seen: set = set()
    dupes = 0
    for label, data in docs:
        txt_ = _to_text(data).lstrip("﻿").strip()
        if not txt_:
            problems.append({"name": label, "reason": "Empty file."})
            continue
        if _DTD_RX.search(txt_):
            problems.append({"name": label, "reason": "Refused: contains a <!DOCTYPE> or <!ENTITY> declaration. DMARC reports never need one, and they can be used for XML entity attacks."})
            continue
        try:
            if txt_[0] in "{[":
                rep = _parse_tlsrpt(label, txt_)
                key = ("tls", rep["org"], rep["report_id"]) if rep["report_id"] else None
                if key and key in seen:
                    dupes += 1
                    continue
                if key:
                    seen.add(key)
                tls_reps.append(rep)
            elif txt_[0] == "<":
                rep = _parse_dmarc(label, txt_)
                key = ("dmarc", rep["org"], rep["report_id"]) if rep["report_id"] else None
                if key and key in seen:
                    dupes += 1
                    continue
                if key:
                    seen.add(key)
                dmarc_reps.append(rep)
            else:
                problems.append({"name": label, "reason": "Not XML or JSON (unrecognised file content)."})
        except ValueError as exc:
            problems.append({"name": label, "reason": str(exc)})

    if not dmarc_reps and not tls_reps:
        detail = "; ".join(f"{p['name']}: {p['reason']}" for p in problems[:5])
        raise ValueError("No usable DMARC or TLS-RPT reports found." + (f" {detail}" if detail else ""))

    return {
        "inputs": {"files": len(raw), "documents": len(docs), "dmarc_reports": len(dmarc_reps), "tls_reports": len(tls_reps),
                   "duplicates": dupes, "problems": problems[:100],
                   "decompressed_mb": round((MAX_TOTAL_BYTES - budget.left) / 1048576, 2)},
        "dmarc": _analyze_dmarc(dmarc_reps, domain) if dmarc_reps else None,
        "tlsrpt": _analyze_tlsrpt(tls_reps) if tls_reps else None,
    }
