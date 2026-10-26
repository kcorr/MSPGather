"""Hardening builders.

MTA-STS & TLS-RPT Builder: the policy file, the _mta-sts and _smtp._tls records,
hosting steps and a testing -> enforce rollout, checked against the domain's MX
hosts and any published policy.

Parked Domain Lockdown: for domains that send and receive no mail, which of null
MX, SPF -all, DMARC reject and a DKIM revocation are in place, and the exact
records to publish, for one domain or up to 20.

Both are passive: DNS lookups, plus the MTA-STS policy fetch that check_mta_sts()
already does safely. Nothing connects to a mail server.
"""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field, field_validator

from ..core.dns_utils import addresses, is_ip, make_resolver, normalize_domain, registered_domain, resolve, txt
from ..core.http import run
from ..core.providers import provider_for
from .builders import _external_auth, _mailto_list
from .bulkaudit import _clean
from .domain import _dmarc_record, _sts_match, check_mta_sts, check_mx, parse_tags
from .spf import _parse_term, get_spf_records

router = APIRouter()

TTL = 3600
_FAILED = ("timeout", "servfail", "error")


def _f(sev: str, area: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "area": area, "title": title, "detail": detail}


def _count(n: int, one: str, many: str | None = None) -> str:
    """_count(1, "record") -> "1 record", _count(3, "record") -> "3 records"."""
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _join(items: list[str]) -> str:
    """["a"] -> "a", ["a", "b", "c"] -> "a, b and c"."""
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _first(items: list[str], n: int = 3) -> str:
    """The first n items, plus "and 2 more"."""
    return _join(items[:n] + ([f"{len(items) - n} more"] if len(items) > n else []))


def _bind_txt(fqdn: str, value: str) -> str:
    """Zone-file TXT line. Values over 255 characters are split into several quoted strings."""
    chunks = [value[i:i + 255] for i in range(0, len(value), 255)] or [""]
    quoted = " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)
    return f"{fqdn}. {TTL} IN TXT {quoted}"


def _is_hostname(host: str) -> bool:
    try:
        return bool(host) and not is_ip(host) and normalize_domain(host) == host.lower().rstrip(".")
    except ValueError:
        return False


def _age_text(seconds: int) -> str:
    """604800 -> "7 days" (rounded, for display)."""
    if seconds >= 31_536_000:
        years = round(seconds / 31_557_600, 1)
        return f"about {years:g} year{'' if years == 1 else 's'}"
    for size, unit in ((86_400, "day"), (3_600, "hour"), (60, "minute")):
        if seconds >= size:
            n = round(seconds / size, 1)
            return f"{n:g} {unit}{'' if n == 1 else 's'}"
    return _count(seconds, "second")


# ======================================================================== MTA-STS
STS_MODES = ("testing", "enforce", "none")
STS_MAX_AGE_LIMIT = 31_557_600   # RFC 8461 section 3.2: about a year
STS_ENFORCE_MIN_AGE = 86_400     # under a day, enforce protects little (see sts_policy_review)
STS_DEFAULT_AGE = {"testing": 86_400, "enforce": 604_800, "none": 86_400}
STS_MAX_RUA = 5
# Wildcards a mail provider documents for its customers' MX hosts. Used only when every
# MX host matches; otherwise the policy lists each MX host by name, which always works.
STS_WILDCARDS = [
    {"provider": "Microsoft 365", "pattern": "*.mail.protection.outlook.com",
     "source": "the pattern Microsoft documents for Exchange Online (microsoft.com's own policy uses it too)"},
]
_LOCAL_PART = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}")
_URL_CHARS = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+=%]+")


def _sts_uri(value: str) -> str:
    """One TLS-RPT report destination: mailto:<address> or an https:// URL (RFC 8460)."""
    m = re.match(r"([A-Za-z][A-Za-z0-9+.-]*):", value)
    scheme = m.group(1).lower() if m else None
    if scheme == "https":
        rest = value[m.end():]
        if not rest.startswith("//") or len(value) > 500 or not _URL_CHARS.fullmatch(value):
            raise ValueError(f"'{value}' is not a valid https:// report URL (no spaces, commas or semicolons).")
        try:
            parts = urlsplit("https:" + rest)
            host, user, password = parts.hostname or "", parts.username, parts.password
        except ValueError as exc:
            raise ValueError(f"'{value}' is not a valid https:// report URL.") from exc
        if user is not None or password is not None:
            raise ValueError(f"'{value}': don't put a user name or password in the report URL.")
        if not _is_hostname(host):
            raise ValueError(f"'{value}' needs a valid host name, like https://tlsrpt.example.com/report.")
        return "https:" + rest
    if scheme == "mailto" or (scheme is None and "@" in value):
        local, _, dom = (value[m.end():] if scheme else value).rpartition("@")
        if not local or not _LOCAL_PART.fullmatch(local) or "." not in dom or not _is_hostname(dom):
            raise ValueError(f"'{value}' is not a valid report email address.")
        return f"mailto:{local}@{dom.lower()}"
    if scheme == "http":
        raise ValueError(f"'{value}': TLS-RPT report URLs must use https://.")
    raise ValueError(f"'{value}' isn't a report destination: use an email address (mailto:) or an https:// URL.")


def sts_rua(value: str | list[str] | None) -> list[str]:
    """TLS-RPT rua destinations from user input (comma/space separated, or a list).
    A bare email address becomes mailto:. Raises ValueError with a human message."""
    items = value if isinstance(value, (list, tuple)) else re.split(r"[,;\s]+", value or "")
    out = list(dict.fromkeys(_sts_uri(str(v).strip()) for v in items if str(v).strip()))
    if len(out) > STS_MAX_RUA:
        raise ValueError(f"Use at most {STS_MAX_RUA} TLS-RPT report destinations.")
    return out


def sts_inputs(mode: str | None, max_age: str | int | None, rua: str | list[str] | None) -> tuple[str | None, int | None, list[str] | None]:
    """Validate the builder options. None means "not given": keep what's published, or use the default."""
    m = (mode or "").strip().lower() or None
    if m is not None and m not in STS_MODES:
        raise ValueError("Mode must be testing, enforce or none.")
    age = None
    if max_age is not None and str(max_age).strip() != "":
        s = str(max_age).strip()
        if not re.fullmatch(r"\d{1,10}", s):
            raise ValueError("max_age must be a whole number of seconds, for example 604800 (one week).")
        age = int(s)
        if age > STS_MAX_AGE_LIMIT:
            raise ValueError(f"max_age can be at most {STS_MAX_AGE_LIMIT} seconds (about a year), the RFC 8461 maximum.")
    given = any(str(v).strip() for v in rua) if isinstance(rua, (list, tuple)) else bool((rua or "").strip())
    return m, age, (sts_rua(rua) if given else None)


def _fields(record: str) -> list[str]:
    parts = [p.strip() for p in record.split(";")]
    while parts and not parts[-1]:
        parts.pop()  # a trailing ";" is allowed
    return parts


def parse_sts_record(record: str) -> dict:
    """Check an _mta-sts TXT record against RFC 8461 section 3.1: "v=STSv1; id=<1-32 letters/digits>"."""
    parts = _fields(record)
    errors: list[str] = []
    if not parts or parts[0] != "v=STSv1":
        loose = bool(parts) and parts[0].replace(" ", "").lower() == "v=stsv1"
        errors.append("It must start with exactly v=STSv1 (case-sensitive, no spaces)." if loose else "It must start with v=STSv1.")
    fields: dict[str, str] = {}
    for p in parts[1:]:
        if not p:
            continue
        key, sep, value = p.partition("=")
        if not sep:
            errors.append(f"'{p}' is not a key=value field.")
            continue
        if key != key.strip() or value != value.strip():
            errors.append(f"'{p}': no spaces around '='.")
        fields[key.strip()] = value.strip()
    sid = fields.get("id")
    if sid is None:
        errors.append("The field name must be lowercase: id=..." if any(k.lower() == "id" for k in fields) else "The id= field is missing.")
    elif not re.fullmatch(r"[A-Za-z0-9]{1,32}", sid):
        errors.append(f"id={sid} is invalid: use 1 to 32 letters and digits only (no dashes, dots, colons or spaces).")
    return {"id": sid, "fields": fields, "errors": errors, "valid": not errors}


def parse_tlsrpt_record(record: str) -> dict:
    """Check a _smtp._tls TXT record against RFC 8460 section 3: "v=TLSRPTv1; rua=<mailto: or https: URIs>"."""
    parts = _fields(record)
    errors: list[str] = []
    if not parts or parts[0] != "v=TLSRPTv1":
        loose = bool(parts) and parts[0].replace(" ", "").lower() == "v=tlsrptv1"
        errors.append("It must start with exactly v=TLSRPTv1 (case-sensitive, no spaces)." if loose else "It must start with v=TLSRPTv1.")
    rua: list[str] = []
    has_rua = False
    for p in parts[1:]:
        key, sep, value = p.partition("=")
        if sep and key.strip() == "rua":
            has_rua = True
            for uri in (u.strip() for u in value.split(",")):
                if uri.lower().startswith(("mailto:", "https:")):
                    rua.append(uri)
                elif uri:
                    errors.append(f"Report destination '{uri}' must start with mailto: or https:.")
    if not has_rua:
        errors.append("The rua= field (where reports go) is missing.")
    elif not rua and not errors:
        errors.append("rua= lists no report destination.")
    return {"rua": rua, "errors": errors, "valid": not errors}


def _valid_sts_pattern(p: str) -> bool:
    """An mx value: a host name, optionally starting with "*." (RFC 8461 section 3.2)."""
    return _is_hostname(p[2:] if p.startswith("*.") else p)


def sts_policy_review(policy: dict, hosts: list[str]) -> dict:
    """Findings for a fetched policy (check_mta_sts()['policy']) against the current MX hosts.
    Version and mode problems are already reported by check_mta_sts()."""
    F: list[dict] = []
    mode = (policy.get("mode") or "").strip()
    raw_age = policy.get("max_age")
    age = int(raw_age.strip()) if raw_age is not None and re.fullmatch(r"\d{1,10}", raw_age.strip()) else None
    if raw_age is None:
        F.append(_f("critical", "MTA-STS", "The policy has no max_age line", "max_age is required (RFC 8461). Senders may reject the whole policy."))
    elif age is None:
        F.append(_f("critical", "MTA-STS", f"max_age '{raw_age}' isn't a whole number of seconds", "Senders may reject the whole policy."))
    elif age > STS_MAX_AGE_LIMIT:
        F.append(_f("warning", "MTA-STS", f"max_age {age} is above the RFC 8461 maximum ({STS_MAX_AGE_LIMIT})",
                    "Some senders may treat the policy as invalid. Use 31557600 (about a year) or less."))
    elif mode == "enforce" and age < STS_ENFORCE_MIN_AGE:
        F.append(_f("warning", "MTA-STS", f"max_age {age} ({_age_text(age)}) is too short for enforce mode",
                    "Senders keep the policy for max_age seconds. When it expires and an attacker can block the policy fetch, senders deliver "
                    "without MTA-STS. RFC 8461 expects weeks or more; 604800 (one week) is a common choice."))
    patterns = [p.strip().lower().rstrip(".") for p in policy.get("mx", []) if p.strip()]
    invalid = [p for p in patterns if not _valid_sts_pattern(p)]
    good = [p for p in patterns if p not in invalid]
    if invalid:
        F.append(_f("warning", "MTA-STS", "Invalid mx value in the policy: " + ", ".join(invalid),
                    "Each mx value is a host name, optionally starting with *. to match exactly one label (e.g. *.mail.protection.outlook.com)."))
    uncovered = [h for h in hosts if not any(_sts_match(p, h) for p in good)]
    stale = [p for p in good if hosts and not any(_sts_match(p, h) for h in hosts)]
    if mode in ("testing", "enforce") and not good:
        F.append(_f("critical", "MTA-STS", "The policy lists no valid mx hosts",
                    "In enforce mode senders refuse every MX host; in testing mode every delivery is reported as a failure."))
    elif uncovered and mode == "enforce":
        F.append(_f("critical", "MTA-STS", f"The enforce policy doesn't cover MX host{'s' if len(uncovered) > 1 else ''} {_join(uncovered)}: "
                    "senders that honour MTA-STS refuse to deliver there",
                    "Mail from those senders queues and eventually bounces. Common after an MX change. "
                    "The policy below lists every MX host; publish it with a new id."))
    elif uncovered and mode == "testing":
        F.append(_f("warning", "MTA-STS", f"The policy doesn't cover MX host{'s' if len(uncovered) > 1 else ''} {_join(uncovered)}",
                    "In testing mode those deliveries are only reported as failures, but switching to enforce now would block them. "
                    "The policy below lists every MX host."))
    if stale:
        F.append(_f("info", "MTA-STS", f"Policy mx value{'s' if len(stale) > 1 else ''} matching no current MX host: {', '.join(stale)}",
                    "Left over from an old provider? Remove it the next time you change the policy, unless you're about to move MX there."))
    return {"findings": F, "mode": mode, "max_age": age, "patterns": patterns, "patterns_ok": good, "invalid": invalid,
            "uncovered": uncovered, "stale": stale}


def sts_mx_patterns(hosts: list[str]) -> dict:
    """mx lines for a new policy: the provider's documented wildcard when every MX host
    matches it, otherwise each MX host by name."""
    hosts = list(dict.fromkeys(h.lower().rstrip(".") for h in hosts if h))
    for w in STS_WILDCARDS:
        if hosts and all(_sts_match(w["pattern"], h) for h in hosts):
            return {"patterns": [w["pattern"]], "wildcard": w}
    return {"patterns": hosts, "wildcard": None}


def build_sts_policy(mode: str, max_age: int, patterns: list[str]) -> str:
    """The mta-sts.txt policy file (RFC 8461 section 3.2), CRLF line endings."""
    lines = ["version: STSv1", f"mode: {mode}", *(f"mx: {p}" for p in patterns), f"max_age: {max_age}"]
    return "\r\n".join(lines) + "\r\n"


def sts_id(now: datetime | None = None) -> str:
    """A new policy id: the UTC time as YYYYMMDDHHMMSS (letters and digits only, as RFC 8461 requires)."""
    return (now or datetime.now(timezone.utc)).strftime("%Y%m%d%H%M%S")


def sts_hosting(domain: str, dns: dict | None = None) -> dict:
    host = f"mta-sts.{domain}"
    url = f"https://{host}/.well-known/mta-sts.txt"
    return {
        "host": host, "url": url, "dns": dns,
        "requirements": [
            f"Serve the file at exactly {url} (HTTPS on port 443).",
            f"Use a publicly trusted certificate valid for {host} (a *.{domain} wildcard certificate works too). "
            "If the certificate isn't valid, senders can't fetch the policy and carry on as if there were none.",
            "Return HTTP 200 with Content-Type: text/plain. No redirects: senders don't follow them (RFC 8461), not even to the same file.",
            f"Create {host} in DNS (A/AAAA, or a CNAME to your web host) and check the URL loads before you publish the _mta-sts record.",
        ],
        "options": [
            "Any static website host that supports a custom domain with HTTPS, for example Azure Static Web Apps, "
            "GitHub Pages with a custom domain, or Cloudflare.",
            f"A web server you already run (IIS, nginx, Apache) with a site for {host} and a certificate for it.",
            f"A hosted MTA-STS service (several DMARC and email security vendors offer one), usually with a CNAME for {host}.",
        ],
        "caveats": ["Some static site generators skip folders whose names start with a dot, such as .well-known. "
                    "Open the URL after uploading to make sure the file is really served."],
        "verify": [f"curl -sS -D - {url}", f"nslookup -type=TXT _mta-sts.{domain}", f"nslookup -type=TXT _smtp._tls.{domain}"],
    }


def sts_rollout(domain: str, stage: str, tlsrpt_ok: bool) -> list[dict]:
    here = {"off": "testing" if tlsrpt_ok else "tlsrpt", "testing": "watch", "enforce": "changes"}.get(stage)
    steps = [
        ("tlsrpt", "Publish the TLS-RPT record first",
         f"_smtp._tls.{domain} asks senders to email you a daily report of TLS successes and failures, so you have data before anything is enforced."),
        ("testing", "Host the policy in testing mode, then publish the _mta-sts record",
         "Upload the policy file and check the URL loads (curl command above) before publishing the _mta-sts TXT record. "
         "In testing mode senders report failures but still deliver. 86400 (one day) is a sensible max_age while testing."),
        ("watch", "Watch the TLS-RPT reports for at least 2 weeks",
         "Every MX host must offer STARTTLS with a publicly trusted certificate for its MX host name. Failure types to look for: "
         "starttls-not-supported, certificate-host-mismatch, certificate-expired, certificate-not-trusted, validation-failure, "
         "sts-policy-fetch-error, sts-policy-invalid, sts-webpki-invalid."),
        ("enforce", "Switch to enforce and publish a new id",
         "Senders that honour MTA-STS then refuse to deliver to an MX host without valid TLS. "
         "Raise max_age to at least 604800 (one week); the maximum is 31557600 (about a year)."),
        ("changes", "Every policy change needs a new id",
         "Senders that have the policy cached fetch it again only when the _mta-sts id changes (or their copy expires). "
         "Before changing MX hosts (new provider or gateway), add the new hosts to the policy and publish a new id; remove the old ones after the move."),
    ]
    return [{"id": i, "title": t, "detail": d, "current": i == here} for i, t, d in steps]


def sts_removal(domain: str, old_age: int | None) -> list[dict]:
    """RFC 8461 section 8.3: how to switch MTA-STS off cleanly."""
    wait = f"{old_age} seconds ({_age_text(old_age)})" if old_age else "the previous policy's max_age"
    return [
        {"id": "none", "title": "Publish the mode: none policy and a new id", "current": False,
         "detail": "Senders that fetch it stop applying MTA-STS to this domain."},
        {"id": "wait", "title": "Wait until cached policies expire", "current": False,
         "detail": f"Senders may keep the previous policy for its max_age: {wait} after this change. Allow some extra time."},
        {"id": "remove", "title": "Then delete the _mta-sts TXT record and the policy file", "current": False,
         "detail": f"The mta-sts.{domain} web host can go too if nothing else uses it. TLS-RPT is a separate record: keep it or remove it as you like."},
    ]


def _sts_policy_host(res, domain: str) -> dict:
    name = f"mta-sts.{domain}"
    cname, _ = resolve(res, name, "CNAME")
    ips = addresses(res, name)
    return {"name": name, "cname": cname[0].target.to_text(omit_final_dot=True) if cname else None, "addresses": ips[:6], "resolves": bool(ips)}


def _sts_current(domain: str, mx: dict, sts: dict, sts_txt: tuple, rpt_txt: tuple, host: dict) -> dict:
    """Shape the raw lookups into the input of mtasts_plan()."""
    hosts = [{"host": e["host"], "preference": e["preference"], "provider": e["provider"], "cname": e["cname"],
              "resolves": bool(e["ips"]), "ip_literal": is_ip(e["host"])} for e in mx.get("records", [])]
    (sts_records, sts_meta), (rpt_records, rpt_meta) = sts_txt, rpt_txt
    return {
        "mx": {"status": mx["status"], "null_mx": mx["null_mx"], "hosts": hosts, "providers": mx.get("providers", []),
               "findings": [f for f in mx["findings"] if f["severity"] in ("critical", "warning")] if hosts else []},
        "sts_txt": {"status": sts_meta["status"], "records": sts_records,
                    "sts": [r for r in sts_records if r.replace(" ", "").lower().startswith("v=stsv1")]},
        "policy": {"url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt", "fetched": sts.get("policy") is not None,
                   "policy": sts.get("policy"), "raw": sts.get("policy_raw"),
                   "findings": [f for f in sts.get("findings", []) if f["severity"] in ("critical", "warning")]},
        "tlsrpt": {"status": rpt_meta["status"], "records": rpt_records,
                   "rpt": [r for r in rpt_records if r.replace(" ", "").lower().startswith("v=tlsrptv1")]},
        "policy_host": host,
    }


def _sts_view(current: dict, review: dict | None, new_patterns: list[str] | None, rpt: dict) -> dict:
    """What's published now, for the details section."""
    pol = current["policy"]
    cur = review["patterns_ok"] if review else []
    return {
        "mx": [{**h, "covered": any(_sts_match(p, h["host"]) for p in cur) if review else None,
                "covered_new": any(_sts_match(p, h["host"]) for p in new_patterns) if new_patterns is not None else None}
               for h in current["mx"]["hosts"]],
        "mx_status": current["mx"]["status"], "null_mx": current["mx"]["null_mx"],
        "sts_records": current["sts_txt"]["records"],
        "policy": {"url": pol["url"], "fetched": pol["fetched"], "raw": pol["raw"],
                   "mode": review["mode"] if review else None, "mx": review["patterns"] if review else [],
                   "max_age": review["max_age"] if review else None,
                   "max_age_text": _age_text(review["max_age"]) if review and review["max_age"] is not None else None},
        "tlsrpt": rpt,
        "policy_host": current.get("policy_host"),
    }


def mtasts_plan(domain: str, current: dict, mode: str | None = None, max_age: int | None = None,
                rua: list[str] | None = None, now: datetime | None = None) -> dict:
    """Findings, the generated policy and records, hosting steps and rollout, from the
    current state. No network, so it's unit-tested with hand-made `current` dicts."""
    mxc = current["mx"]
    hosts = [h["host"] for h in mxc["hosts"] if not h["ip_literal"]]
    ip_hosts = [h["host"] for h in mxc["hosts"] if h["ip_literal"]]
    F: list[dict] = [dict(f) for f in mxc.get("findings", [])]

    # ---- the _mta-sts TXT record
    stx = current["sts_txt"]
    sts_like = stx["sts"]
    sts_parsed = parse_sts_record(sts_like[0]) if len(sts_like) == 1 else None
    txt_ok = bool(sts_parsed and sts_parsed["valid"])
    cur_id = sts_parsed["id"] if txt_ok else None
    if len(sts_like) > 1:
        F.append(_f("critical", "MTA-STS", f"{len(sts_like)} _mta-sts TXT records",
                    "Senders ignore MTA-STS when more than one v=STSv1 record exists. Keep exactly one: the record below."))
    elif sts_parsed and not txt_ok:
        F.append(_f("critical", "MTA-STS", "The _mta-sts TXT record is invalid",
                    " ".join(sts_parsed["errors"]) + " Senders ignore an invalid record, so MTA-STS is effectively off."))
    elif not sts_like and stx["status"] in _FAILED:
        F.append(_f("warning", "MTA-STS", "Couldn't read the _mta-sts TXT record", f"The DNS lookup failed ({stx['status']}). Try again."))

    # ---- the policy file (check_mta_sts() only fetches it when the TXT record exists)
    pol = current["policy"]
    host_dns = current.get("policy_host") or {}
    for f in pol["findings"]:
        f = dict(f)
        if f["title"] == "MTA-STS policy cannot be fetched" and host_dns and not host_dns.get("resolves"):
            f["detail"] = f"{f['detail']} {host_dns['name']} doesn't resolve in DNS, so there's no web server to fetch it from."
        F.append(f)
    cur_policy = pol["policy"] if pol["fetched"] else None
    review = sts_policy_review(cur_policy, hosts) if cur_policy else None
    if review:
        F.extend(review["findings"])
    cur_mode = review["mode"] if review and review["mode"] in STS_MODES else None
    cur_age = review["max_age"] if review else None
    if not sts_like:
        stage = "off"
    elif len(sts_like) > 1 or not txt_ok or not cur_policy or not cur_mode or cur_policy.get("version") != "STSv1" or cur_age is None:
        stage = "broken"
    else:
        stage = cur_mode
    if stage == "off":
        F.append(_f("info", "MTA-STS", "MTA-STS isn't set up",
                    "Without it, a sending server delivers unencrypted if an attacker strips STARTTLS, and doesn't check your MX certificates."))
    elif stage == "testing":
        F.append(_f("info", "MTA-STS", "The policy is in testing mode",
                    "Senders report TLS failures (through TLS-RPT) but still deliver. Switch to enforce when the reports are clean."))
    elif stage == "enforce":
        F.append(_f("ok", "MTA-STS", "The policy is in enforce mode"))
    elif stage == "none":
        F.append(_f("info", "MTA-STS", "The policy mode is none: MTA-STS is switched off", "This is how a domain opts out (RFC 8461 section 8.3)."))

    # ---- the TLS-RPT record
    rtx = current["tlsrpt"]
    rpt_like = rtx["rpt"]
    rpt_parsed = parse_tlsrpt_record(rpt_like[0]) if len(rpt_like) == 1 else None
    rpt_ok = bool(rpt_parsed and rpt_parsed["valid"])
    cur_rua = rpt_parsed["rua"] if rpt_ok else []
    if len(rpt_like) > 1:
        F.append(_f("warning", "TLS-RPT", f"{len(rpt_like)} TLS-RPT records",
                    "Senders ignore TLS-RPT when more than one v=TLSRPTv1 record exists, so no reports arrive. Keep one."))
    elif rpt_parsed and not rpt_ok:
        F.append(_f("warning", "TLS-RPT", "The TLS-RPT record is invalid", " ".join(rpt_parsed["errors"]) + " Senders ignore it, so no reports arrive."))
    elif not rpt_like and rtx["status"] in _FAILED:
        F.append(_f("warning", "TLS-RPT", "Couldn't read the TLS-RPT record", f"The DNS lookup failed ({rtx['status']}). Try again."))
    elif not rpt_like:
        F.append(_f("warning" if stage != "off" else "info", "TLS-RPT", "No TLS-RPT record",
                    "TLS-RPT asks large senders such as Google and Microsoft to email you a daily report of TLS successes and failures. "
                    "Without it, testing mode tells you nothing and enforce failures go unnoticed."))
    else:
        F.append(_f("ok", "TLS-RPT", "TLS-RPT reports go to " + ", ".join(cur_rua)))
    rpt_view = {"records": rtx["records"], "record": rpt_like[0] if len(rpt_like) == 1 else None, "rua": cur_rua, "valid": rpt_ok,
                "errors": rpt_parsed["errors"] if rpt_parsed else []}

    # ---- nothing for MTA-STS to protect?
    stop = None
    if mxc["status"] in _FAILED:
        stop = ("critical", f"Couldn't read the MX records for {domain}",
                "The MX lookup failed, and an MTA-STS policy has to list every MX host. Try again in a moment.")
    elif mxc["null_mx"]:
        stop = ("info", f"{domain} accepts no mail (null MX), so it doesn't need MTA-STS",
                "MTA-STS protects mail coming in to your MX hosts. To finish locking down a domain that doesn't use mail, use Parked Domain Lockdown.")
    elif not mxc["hosts"]:
        stop = ("warning", f"{domain} has no MX records, so there's nothing for MTA-STS to protect",
                "Publish the MX records first. If the domain shouldn't receive mail, lock it down with Parked Domain Lockdown instead.")
    elif not hosts:
        stop = ("critical", "Every MX record points to an IP address, which an MTA-STS policy can't list",
                "MX records must name a host. Change them to host names first.")
    if stop:
        sev, headline, sub = stop
        return {"domain": domain, "severity": sev, "headline": headline, "subline": sub, "stage": stage, "inputs": None,
                "current": _sts_view(current, review, None, rpt_view),
                "findings": [f for f in F if f["severity"] in ("critical", "warning")],
                "generated": {"buildable": False, "reason": sub}, "rollout": []}

    # ---- settings: what the engineer chose, else what's published, else the defaults
    mode = mode or cur_mode or "testing"
    if max_age is None:
        max_age = cur_age if (cur_age is not None and cur_mode == mode and cur_age <= STS_MAX_AGE_LIMIT) else STS_DEFAULT_AGE[mode]
    placeholder = rua is None and not cur_rua
    if rua is None:
        rua = cur_rua or [f"mailto:tls-reports@{domain}"]

    # ---- the policy: keep the published mx lines when they already cover every MX host
    if review and review["patterns_ok"] and not review["uncovered"]:
        patterns, source, wildcard = review["patterns_ok"], "current", None
    else:
        gen = sts_mx_patterns(hosts)
        patterns, wildcard = gen["patterns"], gen["wildcard"]
        source = "wildcard" if wildcard else "hosts"
    text = build_sts_policy(mode, max_age, patterns)
    cur_all = review["patterns"] if review else []
    unchanged = bool(review) and cur_policy.get("version") == "STSv1" and cur_mode == mode and cur_age == max_age and set(cur_all) == set(patterns)
    added = [p for p in patterns if p not in cur_all] if review else []
    removed = [p for p in cur_all if p not in patterns] if review else []
    policy_status = "correct" if unchanged else "update" if cur_policy else "missing"

    # ---- the _mta-sts record: a new id whenever the policy changes
    if unchanged and txt_ok:
        new_id, sts_status = cur_id, "correct"
    else:
        moment = now or datetime.now(timezone.utc)
        new_id = sts_id(moment)
        if new_id == cur_id:
            new_id = sts_id(moment + timedelta(seconds=1))
        sts_status = "missing" if not sts_like else "update" if txt_ok else "conflicting"
    sts_value = sts_like[0] if sts_status == "correct" else f"v=STSv1; id={new_id}"

    # ---- the TLS-RPT record
    if not rpt_like:
        rpt_status = "missing"
    elif not rpt_ok:
        rpt_status = "conflicting"
    else:
        rpt_status = "correct" if {u.lower() for u in cur_rua} == {u.lower() for u in rua} else "update"
    rpt_value = rpt_like[0] if rpt_status == "correct" else "v=TLSRPTv1; rua=" + ",".join(rua)

    records = [
        {"id": "tlsrpt", "label": "TLS-RPT record", "host": "_smtp._tls", "fqdn": f"_smtp._tls.{domain}", "type": "TXT", "ttl": TTL,
         "value": rpt_value, "bind": _bind_txt(f"_smtp._tls.{domain}", rpt_value), "status": rpt_status, "current": rtx["records"],
         "why": "Asks senders to email a daily report of TLS successes and failures to the rua address.",
         "note": {"correct": None, "missing": "Add this as a new TXT record.",
                  "update": "Replace the existing v=TLSRPTv1 record with this one (keep only one).",
                  "conflicting": "Replace the existing record(s) with this one: " + " ".join(rpt_view["errors"] or ["only one v=TLSRPTv1 record is allowed."])}[rpt_status]},
        {"id": "sts", "label": "MTA-STS record", "host": "_mta-sts", "fqdn": f"_mta-sts.{domain}", "type": "TXT", "ttl": TTL,
         "value": sts_value, "bind": _bind_txt(f"_mta-sts.{domain}", sts_value), "status": sts_status, "current": stx["records"],
         "why": "Tells senders this domain has an MTA-STS policy. The id must change every time the policy file changes.",
         "note": {"correct": "The policy hasn't changed, so keep the current id.",
                  "missing": "Publish this last, once the policy URL loads.",
                  "update": f"Replace the current record (id={cur_id}): the policy changes, so senders need a new id to fetch it again.",
                  "conflicting": "Replace the existing record(s) with this one."}[sts_status]},
    ]

    # ---- things to check before publishing
    G: list[dict] = []
    if ip_hosts:
        G.append(_f("critical" if mode == "enforce" else "warning", "MX", f"MX record points to an IP address: {', '.join(ip_hosts)}",
                    "An MTA-STS policy can only list host names, so under enforce senders couldn't deliver there. Change the MX record to a host name first."))
    for h in mxc["hosts"]:
        if h.get("cname"):
            G.append(_f("warning", "MX", f"MX host {h['host']} is an alias (CNAME) for {h['cname']}",
                        f"MTA-STS checks the certificate against the MX host name, so the server must present a certificate valid for {h['host']}. "
                        f"A certificate for {h['cname']} alone doesn't match. Check before enforcing."))
    if mode == "enforce":
        if max_age < STS_ENFORCE_MIN_AGE:
            G.append(_f("warning", "MTA-STS", f"max_age {max_age} ({_age_text(max_age)}) is short for enforce mode",
                        "When a cached policy expires and the fetch can be blocked, senders deliver without MTA-STS. Use at least 86400; 604800 (one week) is common."))
        if cur_mode not in ("testing", "enforce") or stage == "broken":
            G.append(_f("warning", "MTA-STS", "This goes straight to enforce without a testing period",
                        "If an MX host lacks STARTTLS or a valid certificate, senders that honour MTA-STS stop delivering to it. "
                        "Safer: publish in testing mode with TLS-RPT, read 2+ weeks of reports, then enforce."))
        elif cur_mode == "testing":
            G.append(_f("info", "MTA-STS", "Before enforcing, check the TLS-RPT reports",
                        "Every MX host should show successful TLS sessions and no failures for at least 2 weeks."))
    elif mode == "testing" and cur_mode == "enforce":
        G.append(_f("warning", "MTA-STS", "This weakens protection: enforce → testing",
                    "Senders would deliver even when TLS fails. Fine while troubleshooting a delivery problem; plan to switch back."))
    elif mode == "none":
        if cur_policy and cur_mode != "none":
            G.append(_f("info", "MTA-STS", "Retiring MTA-STS (RFC 8461 section 8.3)",
                        "Publish this mode: none policy with a new id, keep both until every policy senders may have cached has expired, "
                        "then delete the _mta-sts record and the policy file (steps below)."))
        elif not cur_policy:
            G.append(_f("info", "MTA-STS", "mode: none is only for retiring a published policy",
                        "There's no policy to switch off. Choose Testing to start using MTA-STS."))
    if mode != "none" and stage != "enforce":
        known = {h.get("provider") for h in mxc["hosts"]} <= {"Microsoft 365", "Google"}
        G.append(_f("info", "MX", "Not checked here: STARTTLS and certificates on the MX hosts",
                    "This builder only reads DNS and the policy file. Every MX host must offer STARTTLS with a publicly trusted certificate valid "
                    "for its MX host name" + (" (Microsoft 365 and Google MX hosts do)" if known else "")
                    + ": confirm it in the TLS-RPT reports (testing mode) or with the SMTP test before enforcing."))
    if placeholder:
        G.append(_f("info", "TLS-RPT", f"{rua[0][7:]} is a suggested report address",
                    "Create that mailbox (a shared mailbox is fine) or enter your TLS-RPT reporting service's address before publishing. "
                    "Expect about one report a day from each large sender."))
    if source == "wildcard" and not unchanged:
        G.append(_f("info", "MTA-STS", f"The policy uses {wildcard['pattern']}",
                    f"Every MX host matches it, and it's {wildcard['source']}. Listing the exact MX host name instead also works."))
    elif source == "current" and not unchanged:
        G.append(_f("info", "MTA-STS", "Keeps the mx lines of the published policy", "They already cover every MX host."))

    # ---- verdict
    changes: list[str] = []
    if review:
        if cur_mode != mode:
            changes.append(f"switch from {cur_mode or 'an invalid mode'} to {mode}")
        if cur_age != max_age:
            changes.append(f"max_age {cur_age if cur_age is not None else '(invalid)'} → {max_age}")
        if added:
            changes.append("add mx " + ", ".join(added))
        if removed:
            changes.append("remove mx " + ", ".join(removed))
    elif sts_like:
        changes.append(f"serve the policy file at {pol['url']}")
    if sts_status != "correct":
        changes.append("publish a new _mta-sts id" if policy_status != "correct" else "fix the _mta-sts record")
    if rpt_status == "missing":
        changes.append("add the TLS-RPT record")
    elif rpt_status != "correct":
        changes.append("update the TLS-RPT record")
    crit_now = [f for f in F if f["severity"] == "critical"]
    check = [f for f in G if f["severity"] in ("critical", "warning")]
    all_correct = policy_status == sts_status == rpt_status == "correct"
    pending = sum(1 for r in records if r["status"] != "correct")
    if crit_now:
        first = crit_now[0]
        sev = "critical"
        if first["area"] == "MX":  # check_mx() titles are just "MX <host>"; the detail is the sentence
            headline = f"{domain}: {first['detail'].rstrip('.') or first['title']}"
            sub = "Fix the MX records first: mail is affected whether or not MTA-STS is used. The records below list every current MX host."
        else:
            headline = f"{domain}: {first['title']}"
            sub = f"{first['detail']} The corrected policy and records are below.".strip()
    elif any(f["severity"] == "critical" for f in check):
        first = next(f for f in check if f["severity"] == "critical")
        sev, headline, sub = "critical", f"Don't publish yet: {first['title']}", first["detail"]
    elif all_correct:
        sev = "warning" if check else "ok" if mode == "enforce" else "info"
        headline = f"No changes needed: MTA-STS is in {mode} mode and covers every MX host"
        sub = {"testing": "Senders report failures but still deliver. When 2+ weeks of TLS-RPT reports are clean, choose Enforce below.",
               "enforce": "Senders that honour MTA-STS deliver only over verified TLS. Remember: every policy change needs a new id.",
               "none": "MTA-STS is switched off. Once the previous policy's max_age has passed, you can delete the _mta-sts record and the policy file."}[mode]
        if check:
            sub += f" Also check: {check[0]['title']}."
    elif stage == "off":
        sev = "warning" if check else "info"
        start = "to go straight to enforce mode" if mode == "enforce" else "to start in testing mode" if mode == "testing" else "in mode: none"
        headline = f"{domain} doesn't use MTA-STS yet: host the policy file and publish {_count(pending, 'DNS record')} {start}"
        sub = ("MTA-STS makes sending servers insist on encrypted, certificate-checked delivery to your MX hosts, which blocks downgrade attacks. "
               "Start in testing mode with TLS-RPT reports for 2+ weeks, then enforce.")
        if check:
            sub = f"Check first: {check[0]['title']}. " + sub
    else:
        sev = "warning" if check else "ok"
        headline = f"Publishable, but check first: {check[0]['title']}" if check else "Ready to publish: " + _join(changes)
        sub = ("Changes: " + _join(changes) + ". " if check else "") + (
            "Upload the new policy file first, then publish the new _mta-sts id." if policy_status != "correct"
            else "The policy file stays as it is.")

    return {
        "domain": domain, "severity": sev, "headline": headline, "subline": sub, "stage": stage,
        "inputs": {"mode": mode, "max_age": max_age, "max_age_text": _age_text(max_age), "rua": rua, "rua_placeholder": placeholder},
        "current": _sts_view(current, review, patterns, rpt_view),
        "findings": F,
        "generated": {
            "buildable": True, "findings": G, "changes": changes,
            "policy": {"text": text, "url": pol["url"], "mode": mode, "max_age": max_age, "mx": patterns, "source": source,
                       "wildcard_provider": wildcard["provider"] if wildcard else None, "added": added, "removed": removed,
                       "status": policy_status,
                       "note": {"correct": "This is the policy you publish now: nothing to upload.",
                                "update": "Replace the published file with this one, then publish the new _mta-sts id.",
                                "missing": "Upload this before publishing the _mta-sts record."}[policy_status]},
            "records": records,
            "hosting": sts_hosting(domain, current.get("policy_host")),
        },
        "rollout": sts_removal(domain, cur_age) if mode == "none" else sts_rollout(domain, stage, rpt_ok),
    }


def mtasts_build(domain: str, mode: str | None = None, max_age: str | int | None = None, rua: str | list[str] | None = None) -> dict:
    mode_in, age_in, rua_in = sts_inputs(mode, max_age, rua)  # bad input fails before any lookup
    domain = _clean(domain)
    res = make_resolver()
    with ThreadPoolExecutor(max_workers=5) as pool:
        f_mx = pool.submit(check_mx, res, domain)
        f_sts = pool.submit(check_mta_sts, res, domain)
        f_txt = pool.submit(txt, res, f"_mta-sts.{domain}")
        f_rpt = pool.submit(txt, res, f"_smtp._tls.{domain}")
        f_host = pool.submit(_sts_policy_host, res, domain)
        mx = f_mx.result()
        current = _sts_current(domain, mx, f_sts.result(), f_txt.result(), f_rpt.result(), f_host.result())
    if mx["status"] == "nxdomain":
        raise ValueError(f"{domain} doesn't exist in DNS: it isn't registered, has expired, or is misspelled.")
    return mtasts_plan(domain, current, mode_in, age_in, rua_in)


# ================================================================ Parked lockdown
LOCK_MAX_DOMAINS = 20
LOCK_BUDGET = 12.0      # seconds for a whole multi-domain request; domains run in parallel
LOCK_WORKERS = 48
LOCK_MAX_RUA = 5
LOCK_SPF = "v=spf1 -all"
LOCK_DKIM = "v=DKIM1; p="
# A selector nobody uses: if it returns a TXT record, *._domainkey (or a broader wildcard) is answering.
LOCK_PROBE = "mspgather-lockdown-probe"
LOCK_STATUS = {
    "locked": ("ok", "Locked down"),
    "partial": ("warning", "Partially locked down"),
    "open": ("warning", "Not locked down"),
    "receives_mail": ("critical", "Receives mail"),
    "sends_mail": ("critical", "Sends mail"),
    "unknown": ("warning", "Couldn't check"),
    "not_found": ("warning", "Doesn't exist"),
    "invalid": ("warning", "Invalid name"),
}
LOCK_NAMES = {"mx": "null MX", "spf": "SPF", "dmarc": "DMARC", "dkim": "DKIM revocation"}


def lock_rua(value: str | list[str] | None) -> list[str]:
    """DMARC aggregate report addresses (comma/space separated, or a list) as mailto: URIs."""
    items = value if isinstance(value, (list, tuple)) else re.split(r"[,;\s]+", value or "")
    out = _mailto_list([str(v) for v in items if str(v).strip()])
    if len(out) > LOCK_MAX_RUA:
        raise ValueError(f"Use at most {LOCK_MAX_RUA} DMARC report addresses.")
    return out


def lock_dmarc_value(rua: list[str] | None = None) -> str:
    return "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s" + ("; rua=" + ",".join(rua) if rua else "")


def lock_records(domain: str, rua: list[str] | None = None) -> list[dict]:
    """The four lockdown records, ready to publish."""
    dmarc = lock_dmarc_value(rua)
    return [
        {"id": "mx", "label": "Null MX", "host": "@", "fqdn": domain, "type": "MX", "priority": 0, "value": ".", "ttl": TTL, "optional": False,
         "bind": f"{domain}. {TTL} IN MX 0 .",
         "why": "Says the domain accepts no mail (RFC 7505), so senders give up straight away. It must be the only MX record."},
        {"id": "spf", "label": "SPF", "host": "@", "fqdn": domain, "type": "TXT", "priority": None, "value": LOCK_SPF, "ttl": TTL, "optional": False,
         "bind": _bind_txt(domain, LOCK_SPF),
         "why": "No server may send mail as this domain. A domain can have only one v=spf1 record, so replace any existing one."},
        {"id": "dmarc", "label": "DMARC", "host": "_dmarc", "fqdn": f"_dmarc.{domain}", "type": "TXT", "priority": None, "value": dmarc, "ttl": TTL,
         "optional": False, "bind": _bind_txt(f"_dmarc.{domain}", dmarc),
         "why": "Receivers reject mail that fails SPF and DKIM, which for this domain is all of it, subdomains included (sp=reject)."},
        {"id": "dkim", "label": "DKIM revocation (optional)", "host": "*._domainkey", "fqdn": f"*._domainkey.{domain}", "type": "TXT", "priority": None,
         "value": LOCK_DKIM, "ttl": TTL, "optional": True, "bind": _bind_txt(f"*._domainkey.{domain}", LOCK_DKIM),
         "why": "An empty key means revoked, so any DKIM signature claiming this domain fails. Selectors that exist keep working. "
                "Skip it if your DNS host doesn't support wildcard records."},
    ]


def lock_assess_mx(status: str, mx: list[tuple[int, str]], implicit: list[str] | None = None) -> dict:
    """mx: (preference, exchange) pairs as published; "." is the null MX."""
    current = [f"{p} {h}" for p, h in mx]
    real = [h for _, h in mx if h != "."]
    if not mx and status in _FAILED:
        return {"status": "unknown", "current": [], "receives": None, "hosts": [], "note": f"The MX lookup failed ({status})."}
    if real:
        providers = list(dict.fromkeys(p["name"] for p in map(provider_for, real) if p))
        note = f"Mail for this domain goes to {_first(real)}" + (f" ({', '.join(providers)})" if providers else "") + "."
        if len(real) < len(mx):
            note += " A null MX must be the only MX record (RFC 7505)."
        return {"status": "conflicting", "current": current, "receives": True, "hosts": real, "note": note}
    if mx:
        note = None
        if len(mx) > 1:
            note = "The null MX is published more than once; one is enough."
        elif mx[0][0] != 0:
            note = f"RFC 7505 says the null MX preference is 0 (this one is {mx[0][0]})."
        return {"status": "correct", "current": current, "receives": False, "hosts": [], "note": note}
    ips = implicit or []
    note = (f"No MX, so senders try the domain's own address instead ({_first(ips)}). A null MX tells them it accepts no mail." if ips
            else "No MX and no address record, so nothing can be delivered, but nothing says so either. A null MX does (RFC 7505).")
    return {"status": "missing", "current": [], "receives": False, "hosts": [], "note": note}


def lock_assess_spf(status: str, records: list[str]) -> dict:
    """records: the v=spf1 TXT records at the apex."""
    if not records and status in _FAILED:
        return {"status": "unknown", "current": [], "sends": None, "senders": [], "note": f"The SPF (TXT) lookup failed ({status})."}
    if not records:
        return {"status": "missing", "current": [], "sends": False, "senders": [], "note": None}
    senders: list[str] = []
    for rec in records:
        for term in rec.split()[1:]:
            t = _parse_term(term)
            if (t["kind"] == "modifier" and t["name"] == "redirect") or (t["kind"] == "mechanism" and t.get("mechanism") != "all"):
                senders.append(term)
    senders = list(dict.fromkeys(senders))
    if len(records) > 1:
        return {"status": "conflicting", "current": records, "sends": bool(senders), "senders": senders,
                "note": f"{len(records)} SPF records: receivers treat SPF as broken (PermError). Keep only v=spf1 -all."}
    rec = records[0]
    if senders:
        return {"status": "conflicting", "current": records, "sends": True, "senders": senders,
                "note": "It authorises senders: " + ", ".join(senders[:6]) + (" …" if len(senders) > 6 else "") + "."}
    alls = [t.lower() for t in rec.split()[1:] if t.lower().lstrip("+-~?") == "all"]
    last = alls[-1] if alls else None
    if last == "-all":
        exact = " ".join(rec.lower().split()) == LOCK_SPF
        return {"status": "correct", "current": records, "sends": False, "senders": [],
                "note": None if exact else "Same effect as v=spf1 -all."}
    note = {"~all": "~all only soft-fails mail from other servers, which is often still delivered.",
            "?all": "?all makes no statement about other servers.",
            "+all": "+all lets ANY server pass SPF as this domain.",
            "all": "all (the same as +all) lets ANY server pass SPF as this domain."}.get(last or "", "It has no all mechanism, so other servers get a neutral result.")
    return {"status": "conflicting", "current": records, "sends": False, "senders": [], "note": note}


def _lock_dmarc_problems(tags: dict) -> list[tuple[str, str]]:
    """What keeps a DMARC record from locking the domain down, as (short, explanation) pairs."""
    p = (tags.get("p") or "").strip().lower()
    out = []
    if p != "reject":
        out.append((f"it's p={p or '(missing)'}", {"none": "p=none only monitors: spoofed mail is still delivered",
                                                   "quarantine": "p=quarantine sends spoofed mail to junk instead of rejecting it"}.get(
                                                       p, f"p={p or '(missing)'} isn't a valid policy")))
    sp = (tags.get("sp") or "").strip().lower()
    if sp and sp != "reject":
        out.append((f"sp={sp}", f"sp={sp} leaves subdomains less protected than reject"))
    pct = (tags.get("pct") or "100").strip()
    if pct != "100":
        out.append((f"pct={pct}", f"pct={pct} applies the policy to only part of the failing mail"))
    if (tags.get("t") or "").strip().lower() == "y":
        out.append(("t=y", "t=y (testing) makes receivers apply the policy one level lower"))
    return out


def lock_assess_dmarc(status: str, records: list[str], inherited: tuple[str, list[str]] | None = None,
                      rua: list[str] | None = None) -> dict:
    """records: v=DMARC1 records at _dmarc.<domain>. inherited: (organisational domain,
    its records) when a subdomain has none of its own."""
    if not records and not inherited and status in _FAILED:
        return {"status": "unknown", "current": [], "problems": [], "note": f"The DMARC lookup failed ({status})."}
    if len(records) > 1:
        return {"status": "conflicting", "current": records, "problems": ["multiple records"],
                "note": f"{len(records)} DMARC records: receivers ignore DMARC entirely when there's more than one."}
    if records:
        tags = parse_tags(records[0])[0]
        found = _lock_dmarc_problems(tags)
        if found:
            note = "; ".join(long for _, long in found) + "."
            if tags.get("rua") and (tags.get("p") or "").strip().lower() in ("none", "quarantine"):
                note += (" Reports are being collected, so someone may be watching this domain's mail: "
                         "check them for legitimate senders before switching to reject.")
            return {"status": "conflicting", "current": records, "problems": [short for short, _ in found], "note": note}
        diffs = []
        if (tags.get("adkim", "r").strip().lower(), tags.get("aspf", "r").strip().lower()) != ("s", "s"):
            diffs.append("relaxed alignment")
        missing = [u for u in (rua or []) if u.lower() not in tags.get("rua", "").lower()]
        if missing:
            diffs.append("reports don't go to " + ", ".join(u[7:] for u in missing))
        note = f"Same lockdown effect as the recommended record (it differs only in: {'; '.join(diffs)}). Replacing it is optional." if diffs else None
        return {"status": "correct", "current": records, "problems": [], "note": note}
    if inherited:
        org, recs = inherited
        tags = parse_tags(recs[0])[0]
        key = "sp" if "sp" in tags else "p"
        problems = [s for s, _ in _lock_dmarc_problems({"p": tags.get(key, ""), "pct": tags.get("pct", "100"), "t": tags.get("t", "")})]
        if not problems:
            return {"status": "correct", "current": [], "problems": [],
                    "note": f"No record of its own, but it inherits {key}=reject from {org}. Publishing its own record is optional."}
        return {"status": "missing", "current": [], "problems": problems, "note": f"No record of its own; it inherits {key}={tags.get(key) or '?'} from {org}."}
    return {"status": "missing", "current": [], "problems": [], "note": None}


def lock_assess_dkim(status: str, records: list[str]) -> dict:
    """records: what a nonexistent selector returns (a *._domainkey wildcard, if any)."""
    if not records and status in _FAILED:
        return {"status": "unknown", "current": [], "note": f"The lookup failed ({status})."}
    if not records:
        return {"status": "missing", "current": [], "note": None}
    keys = [r for r in records if "p=" in r.replace(" ", "")]
    if not keys:
        return {"status": "conflicting", "current": records,
                "note": "A wildcard TXT record answers for every DKIM selector, but it isn't a DKIM key (a broader wildcard such as *.<domain> can cause this)."}
    if not re.sub(r"\s+", "", parse_tags(keys[0])[0].get("p", "")):
        return {"status": "correct", "current": records, "note": None}
    return {"status": "conflicting", "current": records,
            "note": "A wildcard DKIM key is published, so every selector returns a real public key. Replace it with an empty key (p=) to revoke."}


def lock_status(mx: dict, spf: dict, dmarc: dict) -> str:
    if mx.get("receives"):
        return "receives_mail"
    if spf.get("sends"):
        return "sends_mail"
    required = (mx["status"], spf["status"], dmarc["status"])
    if "unknown" in required:
        return "unknown"
    if all(s == "correct" for s in required):
        return "locked"
    return "partial" if "correct" in required else "open"


def _lock_findings(domain: str, s: dict, auth: list[dict], in_use: bool) -> list[dict]:
    """Per-record findings. in_use: the domain receives or sends mail, so the lockdown
    records are not the fix and the advice is about the domain as a mail domain."""
    mx, spf, dmarc, dkim = s["mx"], s["spf"], s["dmarc"], s["dkim"]
    F: list[dict] = []
    if mx["status"] == "correct":
        F.append(_f("ok", "MX", "Null MX is in place", mx.get("note") or ""))
    elif mx["status"] == "missing":
        F.append(_f("info", "MX", "No MX records",
                    "Don't add a null MX while it still sends mail: some receivers reject mail from a domain with a null MX.") if in_use
                 else _f("warning", "MX", "No null MX", f"{mx['note']} Publish a null MX (MX 0 .) to finish the lockdown."))
    elif mx["status"] == "conflicting":
        F.append(_f("critical", "MX", f"The domain receives mail: MX points to {_first(mx['hosts'], 2)}",
                    f"{mx['note']} A null MX would stop all of its inbound mail, so it isn't safe to lock down as it is."))
    else:
        F.append(_f("warning", "MX", "Couldn't read the MX records", mx["note"]))

    if spf["status"] == "correct":
        F.append(_f("ok", "SPF", "SPF is v=spf1 -all", spf.get("note") or ""))
    elif spf.get("sends"):
        F.append(_f("critical", "SPF", "SPF authorises senders: " + _first(spf["senders"], 4),
                    "Something may still send mail as this domain. v=spf1 -all and DMARC p=reject would make that mail fail. "
                    "Check the DMARC aggregate reports for legitimate senders before changing anything."))
    elif spf["status"] == "missing":
        F.append(_f("warning", "SPF", "No SPF record",
                    "If the domain sends mail, publish SPF listing its senders (SPF Builder). v=spf1 -all is only for a domain that sends nothing." if in_use
                    else "Publish v=spf1 -all: mail claiming to be from this domain then fails SPF everywhere."))
    elif spf["status"] == "conflicting":
        F.append(_f("warning", "SPF", "SPF isn't v=spf1 -all", spf["note"]))
    else:
        F.append(_f("warning", "SPF", "Couldn't read the SPF record", spf["note"]))

    if dmarc["status"] == "correct":
        F.append(_f("ok", "DMARC", "DMARC is p=reject", dmarc.get("note") or ""))
    elif dmarc["status"] == "missing":
        F.append(_f("warning", "DMARC", "No DMARC record", (f"{dmarc['note']} " if dmarc.get("note") else "") + (
            "Start with p=none and a report address (DMARC Builder), then move to reject once the reports are clean. "
            "p=reject straight away is only safe for a domain that sends nothing." if in_use
            else "Publish p=reject: receivers then reject mail that fails SPF and DKIM, which for a domain that sends nothing is all of it.")))
    elif dmarc["status"] == "conflicting":
        multiple = dmarc["problems"] == ["multiple records"]
        F.append(_f("critical" if multiple else "warning", "DMARC",
                    "More than one DMARC record" if multiple else f"DMARC isn't at reject ({dmarc['problems'][0]})", dmarc["note"]))
    else:
        F.append(_f("warning", "DMARC", "Couldn't read the DMARC record", dmarc["note"]))

    if dkim["status"] == "correct":
        F.append(_f("ok", "DKIM", "DKIM keys are revoked (*._domainkey)"))
    elif dkim["status"] == "missing" and not in_use:
        F.append(_f("info", "DKIM", "No DKIM revocation record (optional)",
                    "SPF -all and DMARC p=reject already block spoofing. The *._domainkey record also makes any DKIM signature for this domain fail as revoked."))
    elif dkim["status"] == "conflicting":
        F.append(_f("warning", "DKIM", "Unexpected wildcard under _domainkey", dkim["note"]))
    elif dkim["status"] == "unknown":
        F.append(_f("info", "DKIM", "Couldn't check for a DKIM wildcard", dkim["note"]))

    for a in auth:
        if a.get("external") and not a.get("authorized"):
            dest = a["uri"][7:].split("@")[-1]
            F.append(_f("warning", "DMARC", f"{dest} hasn't authorised DMARC reports for {domain}",
                        f"Receivers check TXT {a['check']} (it must contain v=DMARC1) and drop the reports without it. "
                        f"To accept reports for all your domains at once, publish TXT *._report._dmarc.{dest} \"v=DMARC1\" in the {dest} zone."))
    return F


def _lock_headline(domain: str, status: str, s: dict, todo: list[dict]) -> tuple[str, str]:
    mx, spf, dmarc, dkim = s["mx"], s["spf"], s["dmarc"], s["dkim"]
    if status == "receives_mail":
        return (f"Don't lock down {domain}: it receives mail (MX: {_first(mx['hosts'], 2)})",
                "A null MX would stop all inbound mail, and SPF -all with DMARC reject would make any mail it sends fail. "
                "If it really shouldn't receive mail, move its users and mail off it and remove the MX records first.")
    if status == "sends_mail":
        return (f"Don't lock down {domain} yet: its SPF authorises senders ({_first(spf['senders'])})",
                "SPF -all and DMARC p=reject would make mail from those senders fail, and some receivers reject mail from a domain with a null MX. "
                "Confirm nothing legitimate sends as this domain (the DMARC aggregate reports show who does), then remove them and lock it down.")
    if status == "locked":
        return (f"{domain} is locked down: it accepts no mail, and receivers reject mail that claims to be from it",
                "Null MX, SPF -all and DMARC p=reject are in place." + (" So is the optional DKIM revocation." if dkim["status"] == "correct"
                                                                         else " Optional: add the DKIM revocation record below."))
    if status == "unknown":
        failed = [LOCK_NAMES[k] for k in ("mx", "spf", "dmarc") if s[k]["status"] == "unknown"]
        return f"Couldn't check {domain} completely: the {_join(failed)} lookup failed", "DNS didn't answer in time. Try again in a moment."
    names = _join([LOCK_NAMES[r["id"]] for r in todo])
    if status == "partial":
        head = f"{domain} is partly locked down: publish {_count(len(todo), 'more record')} ({names})"
    else:
        head = f"{domain} isn't locked down: nothing tells receivers to reject mail that spoofs it"
    sub = ["Receivers that check DMARC already reject spoofed mail." if dmarc["status"] == "correct"
           else "Without DMARC p=reject, receivers have no instruction to reject spoofed mail."]
    if mx["status"] != "correct":
        sub.append("A null MX tells senders the domain accepts no mail.")
    if status == "open":
        sub.append(f"Publish the {_count(len(todo), 'record')} below ({names}); the DKIM revocation is optional.")
    return head, " ".join(sub)


def lock_plan(domain: str, mx: dict, spf: dict, dmarc: dict, dkim: dict, rua: list[str] | None = None,
              auth: list[dict] | None = None) -> dict:
    """Status, verdict, findings and records for one domain, from the assessed records. No network."""
    status = lock_status(mx, spf, dmarc)
    sev, label = LOCK_STATUS[status]
    safe = status in ("locked", "partial", "open")
    states = {"mx": mx, "spf": spf, "dmarc": dmarc, "dkim": dkim}
    records = lock_records(domain, rua)
    for r in records:
        st = states[r["id"]]
        r.update(status=st["status"], current=st.get("current", []), note=st.get("note"))
        r["action"] = ("none" if st["status"] == "correct" else "check" if status == "unknown" else "hold" if not safe
                       else "add" if st["status"] == "missing" else "replace" if st["status"] == "conflicting" else "check")
    todo = [r for r in records if r["action"] in ("add", "replace") and not r["optional"]]
    headline, sub = _lock_headline(domain, status, states, todo)
    return {"domain": domain, "status": status, "status_label": label, "severity": sev, "headline": headline, "subline": sub,
            "safe": safe, "records": records, "findings": _lock_findings(domain, states, auth or [], status in ("receives_mail", "sends_mail")),
            "todo": [r["id"] for r in todo], "in_place": sum(1 for k in ("mx", "spf", "dmarc") if states[k]["status"] == "correct"),
            "rua": rua or [], "rua_auth": auth or []}


def _lock_mx(res, domain: str) -> dict:
    rdata, meta = resolve(res, domain, "MX")
    pairs = sorted((r.preference, "." if r.exchange.to_text() == "." else r.exchange.to_text(omit_final_dot=True).lower()) for r in rdata)
    implicit = addresses(res, domain) if not pairs and meta["status"] in ("ok", "noanswer") else []
    return {"status": meta["status"], "pairs": pairs, "implicit": implicit}


def _lock_dmarc(res, domain: str) -> dict:
    records, meta = _dmarc_record(res, domain)
    org = registered_domain(domain)
    inherited = None
    if not records and org != domain and meta["status"] not in _FAILED:
        org_records, _ = _dmarc_record(res, org)
        inherited = (org, org_records) if org_records else None
    return {"status": meta["status"], "records": records, "inherited": inherited}


def _lock_domain(pool: ThreadPoolExecutor, domain: str, rua: list[str], deadline: float) -> dict:
    """Run one domain's lookups on the shared pool, waiting no later than the deadline."""
    res = make_resolver()
    t0 = time.monotonic()
    jobs = {"mx": pool.submit(_lock_mx, res, domain), "spf": pool.submit(get_spf_records, res, domain),
            "dmarc": pool.submit(_lock_dmarc, res, domain), "dkim": pool.submit(txt, res, f"{LOCK_PROBE}._domainkey.{domain}")}
    auth_jobs = [pool.submit(_external_auth, res, domain, u) for u in rua]
    got: dict = {}
    late: list[str] = []
    for key, fut in jobs.items():
        try:
            got[key] = fut.result(timeout=max(0.05, deadline - time.monotonic()))
        except FutureTimeout:
            fut.cancel()
            late.append(key)
        except Exception:  # noqa: BLE001 - a failed lookup counts as "couldn't check", it must not sink the domain
            late.append(key)
    auth = []
    for fut in auth_jobs:
        try:
            auth.append(fut.result(timeout=max(0.05, deadline - time.monotonic())))
        except Exception:  # noqa: BLE001 - the authorisation check is advisory
            fut.cancel()
    mxr = got.get("mx") or {"status": "timeout", "pairs": [], "implicit": []}
    if mxr["status"] == "nxdomain":
        return {"domain": domain, "status": "not_found", "status_label": LOCK_STATUS["not_found"][1], "severity": LOCK_STATUS["not_found"][0],
                "headline": f"{domain} doesn't exist in DNS", "subline": "", "safe": False, "records": [], "findings": [], "todo": [],
                "elapsed_ms": round((time.monotonic() - t0) * 1000), "timed_out": late}
    spf_records, spf_meta = got.get("spf") or ([], {"status": "timeout"})
    dm = got.get("dmarc") or {"status": "timeout", "records": [], "inherited": None}
    dk_records, dk_meta = got.get("dkim") or ([], {"status": "timeout"})
    plan = lock_plan(domain, lock_assess_mx(mxr["status"], mxr["pairs"], mxr["implicit"]), lock_assess_spf(spf_meta["status"], spf_records),
                     lock_assess_dmarc(dm["status"], dm["records"], dm["inherited"], rua), lock_assess_dkim(dk_meta["status"], dk_records),
                     rua, auth)
    plan["elapsed_ms"] = round((time.monotonic() - t0) * 1000)
    plan["timed_out"] = late
    return plan


def lock_check(domain: str, rua: str | list[str] | None = "") -> dict:
    """Parked Domain Lockdown for one domain."""
    rua_list = lock_rua(rua)
    domain = _clean(domain)
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        result = _lock_domain(pool, domain, rua_list, time.monotonic() + 15.0)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    if result["status"] == "not_found":
        raise ValueError(f"{domain} doesn't exist in DNS: it isn't registered, has expired, or is misspelled. "
                         "If it's meant to be a defensive registration, check it at the registrar.")
    return result


def _lock_row(r: dict) -> dict:
    """One summary row for the multi-domain table."""
    status = r.get("status", "unknown")
    sev, label = LOCK_STATUS[status]
    return {"domain": r["domain"], "status": status, "label": label, "severity": sev, "headline": r.get("headline") or r.get("error") or label,
            "safe": r.get("safe", False), "records": r.get("records", []), "todo": r.get("todo", []),
            "problems": [f for f in r.get("findings", []) if f["severity"] in ("critical", "warning")],
            "rua_auth": r.get("rua_auth", []), "error": r.get("error"), "timed_out": r.get("timed_out", [])}


def lock_bulk_summary(rows: list[dict]) -> dict:
    """Verdict, counts and findings for a multi-domain run. No network."""
    by: dict[str, list[str]] = {}
    for r in rows:
        by.setdefault(r["status"], []).append(r["domain"])
    n = sum(1 for r in rows if r["status"] != "invalid")
    need = by.get("partial", []) + by.get("open", [])
    receives, sends = by.get("receives_mail", []), by.get("sends_mail", [])
    to_publish = sum(len(r["todo"]) for r in rows if r["status"] in ("partial", "open"))
    names = lambda lst: ", ".join(lst[:6]) + (f" and {len(lst) - 6} more" if len(lst) > 6 else "")  # noqa: E731

    F: list[dict] = []
    if receives:
        F.append(_f("critical", "MX", f"{_count(len(receives), 'domain receives', 'domains receive')} mail: {names(receives)}",
                    "They have real MX records, so they aren't parked. A null MX would stop their inbound mail: leave them out of the lockdown."))
    if sends:
        F.append(_f("critical", "SPF", f"{_count(len(sends), 'domain sends', 'domains send')} mail: {names(sends)}",
                    "Their SPF records authorise senders. SPF -all and DMARC reject would make that mail fail. Check the DMARC aggregate reports first."))
    if need:
        F.append(_f("warning", "Lockdown", f"{_count(len(need), 'domain needs', 'domains need')} records: {names(need)}",
                    f"{_count(to_publish, 'record')} to publish in all. They're listed per domain below and in the CSV."))
    if by.get("not_found"):
        F.append(_f("warning", "Domain", f"{_count(len(by['not_found']), 'domain does', 'domains do')}n't exist in DNS: {names(by['not_found'])}",
                    "Not registered, expired or misspelled. If they're defensive registrations, check them at the registrar: "
                    "an expired domain can be registered by someone else."))
    if by.get("unknown"):
        F.append(_f("warning", "DNS", f"Couldn't check {_count(len(by['unknown']), 'domain')}: {names(by['unknown'])}",
                    "Some DNS lookups timed out or failed. Run the check again."))
    if by.get("invalid"):
        F.append(_f("warning", "Input", f"{_count(len(by['invalid']), 'invalid name')} skipped: {names(by['invalid'])}"))
    no_dkim = [r["domain"] for r in rows if r["safe"] and any(x["id"] == "dkim" and x["status"] == "missing" for x in r["records"])]
    if no_dkim:
        F.append(_f("info", "DKIM", f"{_count(len(no_dkim), 'domain')} without the optional DKIM revocation: {names(no_dkim)}"))
    unauth = sorted({a["uri"][7:].split("@")[-1] for r in rows for a in r.get("rua_auth", []) if a.get("external") and not a.get("authorized")})
    if unauth:
        F.append(_f("warning", "DMARC", f"{_join(unauth)} {'hasn' if len(unauth) == 1 else 'haven'}'t authorised DMARC reports for some of these domains",
                    "Receivers drop reports sent to another domain unless that domain authorises them. To accept reports for all your domains at once, publish "
                    + _join([f'TXT *._report._dmarc.{d} "v=DMARC1" in the {d} zone' for d in unauth]) + "."))
    if by.get("locked"):
        F.append(_f("ok", "Lockdown", f"{_count(len(by['locked']), 'domain is', 'domains are')} locked down: {names(by['locked'])}"))

    if n and len(by.get("locked", [])) == n:
        headline = "The domain is locked down" if n == 1 else f"All {n} domains are locked down"
    else:
        parts = []
        if need:
            parts.append(f"{len(need)} of {n} need{'s' if len(need) == 1 else ''} records ({_count(to_publish, 'record')} to publish)")
        if receives:
            parts.append(f"{len(receives)} receive{'s' if len(receives) == 1 else ''} mail")
        if sends:
            parts.append(f"{len(sends)} send{'s' if len(sends) == 1 else ''} mail")
        if by.get("not_found"):
            parts.append(f"{len(by['not_found'])} do{'es' if len(by['not_found']) == 1 else ''}n't exist")
        if by.get("unknown"):
            parts.append(f"{len(by['unknown'])} couldn't be checked")
        if by.get("locked"):
            parts.append(f"{len(by['locked'])} {'is' if len(by['locked']) == 1 else 'are'} already locked down")
        headline = _join(parts) or "No valid domains to check"
        headline = headline[0].upper() + headline[1:]
    sev = ("critical" if receives or sends else "warning" if need or by.get("unknown") or by.get("not_found") or by.get("invalid")
           else "ok" if n else "warning")
    sub = ("Domains that receive or send mail aren't parked: leave them out of the lockdown. " if receives or sends else "") + (
        "Publish the records for each domain below, then run this again to confirm." if need else "")
    return {"severity": sev, "headline": headline, "subline": sub.strip(), "findings": F, "to_publish": to_publish,
            "counts": {k: len(v) for k, v in by.items()}}


def lock_bulk(domains: list[str], rua: str | list[str] | None = "") -> dict:
    """Parked Domain Lockdown for up to LOCK_MAX_DOMAINS domains, checked in parallel."""
    tokens = [t for item in domains for t in re.split(r"[\s,;]+", item or "") if t]
    if not tokens:
        raise ValueError("Enter at least one domain (one per line, or separated by commas or spaces).")
    if len(tokens) > 10 * LOCK_MAX_DOMAINS:
        raise ValueError(f"Up to {LOCK_MAX_DOMAINS} domains at a time.")
    rua_list = lock_rua(rua)
    clean: list[str] = []
    invalid: list[dict] = []
    dupes = 0
    for t in tokens:
        try:
            d = _clean(t)
        except ValueError as exc:
            invalid.append({"domain": t[:100], "status": "invalid", "error": str(exc)})
            continue
        if d in clean:
            dupes += 1
        else:
            clean.append(d)
    if len(clean) > LOCK_MAX_DOMAINS:
        raise ValueError(f"Up to {LOCK_MAX_DOMAINS} domains at a time: this list has {len(clean)}. Split it into smaller batches.")
    t0 = time.monotonic()
    rows: list[dict] = []
    if clean:
        deadline = t0 + LOCK_BUDGET
        pool = ThreadPoolExecutor(max_workers=min(LOCK_WORKERS, (4 + len(rua_list)) * len(clean)))
        try:
            # One outer thread per domain collects that domain's lookups from the shared pool.
            with ThreadPoolExecutor(max_workers=len(clean)) as outer:
                futures = [outer.submit(_lock_domain, pool, d, rua_list, deadline) for d in clean]
                for d, fut in zip(clean, futures):
                    try:
                        rows.append(_lock_row(fut.result()))
                    except Exception as exc:  # noqa: BLE001 - one failing domain must not sink the batch
                        rows.append(_lock_row({"domain": d, "status": "unknown", "error": str(exc)[:200] or exc.__class__.__name__}))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
    rows += [_lock_row(i) for i in invalid]
    return {**lock_bulk_summary(rows), "rows": rows, "rua": rua_list, "duplicates": dupes, "max": LOCK_MAX_DOMAINS,
            "elapsed_ms": round((time.monotonic() - t0) * 1000)}


# ========================================================================= routes
class LockBulkRequest(BaseModel):
    # No min_length: an empty list gets lock_bulk()'s human message instead of a validation error.
    domains: list[str] = Field(default_factory=list, max_length=200)
    rua: str | list[str] = ""

    @field_validator("domains", mode="before")
    @classmethod
    def _accept_one_string(cls, value):
        return [value] if isinstance(value, str) else value


@router.get("/api/builder/mtasts/{domain:path}")
def mtasts_route(domain: str, mode: str | None = Query(None, max_length=20), max_age: str | None = Query(None, max_length=20),
                 rua: str | None = Query(None, max_length=2000)):
    return run(mtasts_build, domain, mode, max_age, rua)


@router.get("/api/builder/parked/{domain:path}")
def parked_route(domain: str, rua: str = Query("", max_length=2000)):
    return run(lock_check, domain, rua)


@router.post("/api/builder/parked")
def parked_bulk_route(body: LockBulkRequest):
    return run(lock_bulk, body.domains, body.rua)
