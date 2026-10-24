"""Message header analysis: hop chain, delays, TLS, authentication, Microsoft 365
anti-spam stamps, identity alignment, and mail-loop diagnosis."""
from __future__ import annotations

import email
import email.policy
import email.utils
import ipaddress
import re
from collections import Counter
from datetime import datetime, timezone
from email.header import decode_header, make_header

from ..core.dns_utils import is_private_ip, registered_domain
from ..core import cmdsafe
from ..core.providers import provider_for, zone_for
from .spf import analyze_spf

# ----------------------------------------------------------- Microsoft 365 maps
SFV = {
    "BLK": "Blocked: sender is on the recipient's Blocked Senders list",
    "NSPM": "Not spam",
    "SFE": "Allowed: sender is on the recipient's Safe Senders list",
    "SKA": "Allowed: on the anti-spam policy allowed senders/domains list",
    "SKB": "Spam: on the anti-spam policy blocked senders/domains list",
    "SKI": "Intra-organisation message, spam filtering skipped",
    "SKN": "Filtering skipped: marked non-spam before filtering (e.g. a mail flow rule set SCL -1)",
    "SKQ": "Released from quarantine",
    "SKS": "Marked as spam before filtering (e.g. by a mail flow rule)",
    "SPM": "Marked as spam by spam filtering",
}
CAT = {
    "AMP": "Anti-malware", "BULK": "Bulk", "DIMP": "Domain impersonation", "FTBP": "Anti-malware common attachments filter",
    "GIMP": "Mailbox intelligence impersonation", "HPHSH": "High confidence phishing", "HPHISH": "High confidence phishing",
    "HSPM": "High confidence spam", "INTOS": "Intra-organisation phishing", "MALW": "Malware", "NONE": "None",
    "OSPM": "Outbound spam", "PHSH": "Phishing", "SAP": "Safe Attachments", "SPM": "Spam", "SPOOF": "Spoofing",
    "UIMP": "User impersonation",
}
IPV = {"CAL": "Connecting IP is on the connection filter IP Allow List (filtering skipped)",
       "NLI": "IP not on any reputation list"}
DIR = {"INB": "Inbound", "OUT": "Outbound", "INT": "Intra-org"}
AUTH_AS = {
    "Anonymous": "External, unauthenticated sender",
    "Internal": "Sent from inside the organisation (authenticated)",
    "Partner": "Arrived via an inbound partner connector (TLS/IP-scoped)",
    "External": "Authenticated external (e.g. a connector that trusts the sender)",
}
COMPAUTH_CLASS = {
    "0": "Failed (explicit: DMARC failed with a reject/quarantine policy)",
    "1": "Passed",
    "2": "Soft-passed",
    "3": "Not checked",
    "4": "Bypassed (e.g. allowed by policy or a trusted source)",
    "6": "Failed (implicit authentication)",
    "7": "Passed (implicit authentication)",
    "9": "Neutral",
}

AUTO_PREFIX_RE = re.compile(
    r"(?i)\b(re|fw|fwd|aw|wg|sv|antw|tr|automatic reply|auto(?:matic)?[ -]?(?:reply|response)|out of (?:the )?office|"
    r"undeliverable|undelivered|delivery status notification(?: \(failure\))?|returned mail|mail delivery failed)\s*:")


def _f(sev: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "title": title, "detail": detail}


def _unfold(v: str) -> str:
    return re.sub(r"\s+", " ", v or "").strip()


def _decode(v: str) -> str:
    try:
        return _unfold(str(make_header(decode_header(v))))
    except Exception:  # malformed encoded-words are common in pasted headers
        return _unfold(v)


def _prepare(raw: str) -> str:
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    # Pasted from a web UI with every line indented: dedent.
    non_empty = [l for l in lines if l.strip()]
    if non_empty and all(l[:1] in (" ", "\t") for l in non_empty):
        lines = [l.lstrip() for l in lines]
    # Skip anything before the first "Name: value" line (e.g. Outlook's
    # "Microsoft Mail Internet Headers Version 2.0").
    start = next((i for i, l in enumerate(lines) if re.match(r"^[!-9;-~]+:", l)), None)
    if start is None:
        raise ValueError("No headers found. Paste the full internet headers (lines like 'Received: ...').")
    return "\n".join(lines[start:])


def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    s = re.sub(r"\([^)]*\)", "", s).strip()
    s = re.sub(r"(\d{1,2}:\d{2}:\d{2})\.\d+", r"\1", s)
    try:
        dt = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ips_in(text: str) -> list[str]:
    out = []
    for tok in re.split(r"[\s()\[\]=,;]+", text):
        tok = tok.strip(".")
        if tok.lower().startswith("ipv6:"):
            tok = tok[5:]
        if not tok or (":" not in tok and "." not in tok):
            continue
        try:
            ip = str(ipaddress.ip_address(tok))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def parse_received(value: str) -> dict:
    v = _unfold(value)
    main, date_part = (v.rsplit(";", 1) if ";" in v else (v, None))
    hop: dict = {"raw": v, "from_host": None, "from_ip": None, "helo": None, "by_host": None,
                 "with": None, "via": None, "id": None, "for": None, "tls": False,
                 "tls_version": None, "cipher": None, "timestamp": None}
    from_m = re.search(r"\bfrom\s+([^\s(;]+)", main, re.I)
    by_m = re.search(r"\bby\s+([^\s(;]+)", main, re.I)
    with_m = re.search(r"\bwith\s+(Microsoft SMTP Server|[^\s(;]+)", main, re.I)
    via_m = re.search(r"\bvia\s+([A-Za-z][\w ]*?Transport|[^\s(;]+)", main, re.I)
    id_m = re.search(r"\bid\s+<?([^\s;>]+)>?", main, re.I)
    for_m = re.search(r"\bfor\s+<?([^\s;>]+@[^\s;>]+)>?", main, re.I)
    if from_m:
        hop["from_host"] = from_m.group(1).strip("[]").lower()
        section = main[from_m.end(): by_m.start()] if by_m and by_m.start() > from_m.end() else main[from_m.end():]
        ips = _ips_in(section) or _ips_in(from_m.group(1))
        hop["from_ip"] = ips[0] if ips else None
        helo = re.search(r"\b(?:HELO|EHLO|helo=)\s*([^\s)\]]+)", section, re.I)
        hop["helo"] = helo.group(1) if helo else None
    if by_m:
        hop["by_host"] = by_m.group(1).strip("[]").lower()
    if with_m:
        hop["with"] = with_m.group(1)
    if via_m:
        hop["via"] = via_m.group(1)
    if id_m:
        hop["id"] = id_m.group(1)
    if for_m:
        hop["for"] = for_m.group(1)
    tv = re.search(r"(TLS ?v?1[._]?[0-3]|TLSv1(?:\.[0-3])?|SSLv3)", main, re.I)
    if tv:
        hop["tls_version"] = tv.group(1).upper().replace("_", ".").replace(" ", "").replace("TLSV", "TLS")
    ci = re.search(r"cipher[= ]([A-Z0-9_\-]+)", main, re.I)
    if ci:
        hop["cipher"] = ci.group(1)
    proto = (hop["with"] or "").upper()
    hop["tls"] = bool(tv) or proto in {"ESMTPS", "ESMTPSA", "SMTPS", "UTF8SMTPS", "UTF8SMTPSA", "LMTPS", "HTTPS"}
    ts = _parse_date(date_part)
    hop["timestamp"] = ts
    hop["date_raw"] = date_part.strip() if date_part else None
    return hop


def parse_auth_results(value: str) -> dict:
    v = _unfold(value)
    parts = v.split(";")
    # Exchange Online omits the authserv-id and starts straight with "spf=...".
    if re.match(r"^\s*[a-z][a-z0-9\-]*\s*=\s*[a-z]+\b", parts[0], re.I) and not re.match(r"^\s*[\w.-]+\s*$", parts[0]):
        out: dict = {"authserv_id": "", "results": []}
    else:
        out = {"authserv_id": parts.pop(0).strip(), "results": []}
    for p in parts:
        p = p.strip()
        m = re.match(r"([a-z][a-z0-9\-]*)\s*=\s*([a-z]+)\s*(.*)", p, re.I | re.S)
        if not m:
            continue
        method, result, rest = m.group(1).lower(), m.group(2).lower(), m.group(3)
        props = {k.lower(): val.strip('"') for k, val in re.findall(r"([a-z]+\.[a-z\-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)", rest, re.I)}
        reason = re.search(r"reason\s*=\s*(\"[^\"]*\"|\S+)", rest, re.I)
        action = re.search(r"action\s*=\s*(\S+)", rest, re.I)
        comment = re.search(r"\(([^)]*)\)", rest)
        out["results"].append({
            "method": method, "result": result, "props": props,
            "reason": reason.group(1).strip('"') if reason else None,
            "action": action.group(1) if action else None,
            "comment": comment.group(1) if comment else None,
        })
    return out


def _kv_semicolon(value: str) -> dict:
    out = {}
    for part in _unfold(value).split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip().upper()] = v.strip()
    return out


def _addr(value: str | None) -> tuple[str, str]:
    if not value:
        return "", ""
    name, addr = email.utils.parseaddr(value)
    return name, addr.lower()


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def _visits(positions: list[int]) -> int:
    """Number of separate visits: consecutive positions count as one stay."""
    if not positions:
        return 0
    return 1 + sum(1 for a, b in zip(positions, positions[1:]) if b - a > 1)


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


# --------------------------------------------------------------------- analysis
def analyze_headers(raw: str, live: bool = True) -> dict:
    """live=True allows DNS lookups (SPF check of the original sender IP)."""
    msg = email.message_from_string(_prepare(raw), policy=email.policy.compat32)
    headers = [(k, _unfold(str(v))) for k, v in msg.items()]
    if not headers:
        raise ValueError("No headers found.")
    H: dict[str, list[str]] = {}
    for k, v in headers:
        H.setdefault(k.lower(), []).append(v)

    def first(name: str) -> str | None:
        vals = H.get(name.lower())
        return vals[0] if vals else None

    findings: list[dict] = []
    subject = _decode(first("subject") or "")
    from_name, from_addr = _addr(_decode(first("from") or ""))
    _, return_path = _addr(first("return-path"))
    _, reply_to = _addr(_decode(first("reply-to") or ""))
    _, sender = _addr(first("sender"))
    date_hdr = _parse_date(first("date"))
    from_domain = _domain_of(from_addr)

    # ---- hops (Received headers are newest first; present them oldest first)
    received = H.get("received", [])
    hops = [parse_received(v) for v in reversed(received)]
    prev = date_hdr
    for i, h in enumerate(hops):
        h["index"] = i + 1
        h["delay_seconds"] = (h["timestamp"] - prev).total_seconds() if h["timestamp"] and prev else None
        if h["timestamp"]:
            prev = h["timestamp"]
        h["by_provider"] = (provider_for(h["by_host"]) or {}).get("name")
        h["from_provider"] = (provider_for(h["from_host"]) or {}).get("name")
        h["zone"] = zone_for(h["by_host"] or h["from_host"])
        h["from_private"] = bool(h["from_ip"] and is_private_ip(h["from_ip"]))

    stamps = [h["timestamp"] for h in hops if h["timestamp"]]
    total_transit = (stamps[-1] - stamps[0]).total_seconds() if len(stamps) >= 2 else None

    if not received:
        findings.append(_f("warning", "No Received headers",
                           "You may have pasted only part of the headers. In Outlook use File → Properties → Internet headers; "
                           "in OWA/new Outlook use … → View → View message details."))

    # ---- delays
    for h in hops:
        d = h["delay_seconds"]
        if d is None:
            continue
        where = f"hop {h['index']} ({h['from_host'] or '?'} → {h['by_host'] or '?'})"
        if d > 3600:
            findings.append(_f("critical", f"Delay of {_human(d)} at {where}",
                               "Over an hour usually means the previous server queued the message: the next hop was unreachable, "
                               "it was greylisted or throttled, or it was held for moderation/quarantine."))
        elif d > 300:
            findings.append(_f("warning", f"Delay of {_human(d)} at {where}",
                               "Common causes: greylisting, throttling, a slow content scan, or retries after a temporary 4xx error."))
        elif d < -120:
            findings.append(_f("info", f"Negative delay ({_human(d)}) at {where}",
                               "The clocks on these servers disagree. Timing analysis around this hop is unreliable."))
    if date_hdr and stamps and (stamps[0] - date_hdr).total_seconds() > 86400:
        findings.append(_f("info", "First hop is more than a day after the Date header",
                           "The message sat in an outbox, was resent, or the sending client's clock is wrong."))

    # ---- TLS
    for h in hops:
        if not h["tls"] and h["from_ip"] and not h["from_private"] and h["with"] and \
                h["with"].upper() in ("SMTP", "ESMTP", "ESMTPA") and zone_for(h["from_host"]) != h["zone"]:
            findings.append(_f("warning", f"Hop {h['index']} between organisations without TLS",
                               f"{h['from_host']} → {h['by_host']} used {h['with']} (no STARTTLS). The content crossed the internet in clear text."))

    # ---- loop analysis
    loop = _loop_analysis(hops, H, subject)
    findings.extend(loop.pop("findings"))

    # ---- authentication
    auth_results = []
    for name in ("authentication-results", "authentication-results-original"):
        for v in H.get(name, []):
            ar = parse_auth_results(v)
            ar["header"] = "Authentication-Results" if name == "authentication-results" else "Authentication-Results-Original"
            auth_results.append(ar)
    arc_results = [parse_auth_results(re.sub(r"^\s*i\s*=\s*\d+\s*;", "", v)) for v in H.get("arc-authentication-results", [])]
    dkim_sigs = []
    for v in H.get("dkim-signature", []):
        tags = dict((k.strip().lower(), val.strip()) for k, val in
                    (p.split("=", 1) for p in v.split(";") if "=" in p))
        dkim_sigs.append({"d": tags.get("d", "").lower(), "s": tags.get("s"), "a": tags.get("a"),
                          "h": tags.get("h"), "t": tags.get("t")})
    received_spf = H.get("received-spf", [])

    ms = _microsoft(H)
    spf_path = _spf_path(hops, H, ms, live)
    if spf_path:
        findings.append(_f(spf_path["severity"], spf_path["title"], spf_path["detail"]))

    primary = auth_results[0] if auth_results else None
    if primary:
        for r in primary["results"]:
            if r["method"] == "spf" and spf_path and any(ip in spf_path["bad_ips"] for ip in _ips_in(r.get("comment") or "")):
                continue  # explained by the SPF path diagnosis
            if r["method"] in ("spf", "dkim", "dmarc") and r["result"] in ("fail", "softfail", "permerror", "temperror", "none"):
                sev = "critical" if r["method"] == "dmarc" and r["result"] == "fail" else "warning"
                findings.append(_f(sev, f"{r['method'].upper()} {r['result']} (per {primary['authserv_id'] or 'receiver'})",
                                   _auth_explain(r)))
            if r["method"] == "compauth":
                cls = COMPAUTH_CLASS.get((r["reason"] or "x")[0], "Unknown reason class")
                r["explain"] = f"reason {r['reason']}: {cls}"
                if r["result"] in ("fail", "softpass", "none"):
                    findings.append(_f("warning" if r["result"] != "fail" else "critical",
                                       f"Microsoft composite authentication: {r['result']} (reason {r['reason']})",
                                       cls + ". EOP uses compauth to decide on spoof/junk. Fix the sender's SPF/DKIM/DMARC, "
                                       "or for a trusted third party add a spoof allow entry in the Tenant Allow/Block List."))

    # ---- Microsoft 365 stamps
    if ms:
        findings.extend(ms.pop("findings"))

    # ---- identity alignment
    dkim_domains = sorted({s["d"] for s in dkim_sigs if s["d"]})
    alignment = {
        "from": from_addr, "from_display": from_name, "return_path": return_path, "reply_to": reply_to,
        "sender": sender, "dkim_domains": dkim_domains,
        "spf_domain": next((r["props"].get("smtp.mailfrom") for r in (primary or {}).get("results", []) if r["method"] == "spf"), None),
    }
    org_from = registered_domain(from_domain) if from_domain else ""
    if reply_to and from_domain and registered_domain(_domain_of(reply_to)) != org_from:
        findings.append(_f("warning", f"Reply-To ({reply_to}) is a different domain than From",
                           "Replies go somewhere other than the apparent sender. This is a classic BEC/phishing pattern; legitimate for some marketing and ticketing systems."))
    if from_name and re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", from_name):
        shown = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", from_name).group(0).lower()
        if shown != from_addr:
            findings.append(_f("warning", "Display name contains a different email address",
                               f"Shows '{shown}' but the real sender is {from_addr}. Common spoofing trick."))
    if return_path and from_domain and registered_domain(_domain_of(return_path)) != org_from:
        findings.append(_f("info", f"Envelope sender (Return-Path) domain differs from From ({_domain_of(return_path)})",
                           "SPF cannot align for DMARC, so DMARC must pass via an aligned DKIM signature. Normal for ESPs/bulk senders."))
    if dkim_sigs and from_domain and not any(registered_domain(d) == org_from for d in dkim_domains):
        findings.append(_f("info", "No DKIM signature aligned with the From domain",
                           f"Signed by {', '.join(dkim_domains)}, not {from_domain}. DMARC can pass only through aligned SPF."))
    if return_path == "" and "return-path" in H:
        findings.append(_f("info", "Null envelope sender (<>)", "This is a bounce, NDR, or other automatic notification."))

    bulk = _bulk_sender(H, hops, primary, dkim_sigs)
    if bulk and bulk["failed"]:
        findings.append(_f("warning", bulk["headline"], bulk["detail"]))

    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    providers_seen = []
    for h in hops:
        for host in (h["from_host"], h["by_host"]):
            p = provider_for(host)
            if p and p not in providers_seen:
                providers_seen.append(p)

    for h in hops:
        h["timestamp"] = _iso(h["timestamp"])

    return {
        "summary": {
            "subject": subject, "from": _decode(first("from") or ""), "to": _decode(first("to") or ""),
            "cc": _decode(first("cc") or ""), "date": first("date"), "message_id": first("message-id"),
            "return_path": first("return-path"), "reply_to": first("reply-to"),
            "network_message_id": first("x-ms-exchange-organization-network-message-id") or first("x-ms-exchange-crosstenant-network-message-id"),
            "hop_count": len(hops), "total_transit_seconds": total_transit,
            "total_transit": _human(total_transit) if total_transit is not None else None,
        },
        "loop": loop,
        "spf_path": spf_path,
        "hops": hops,
        "providers": providers_seen,
        "authentication": {"results": auth_results, "arc": arc_results, "arc_sets": len(H.get("arc-seal", [])),
                           "dkim_signatures": dkim_sigs, "received_spf": received_spf},
        "microsoft": ms,
        "alignment": alignment,
        "bulk_sender": bulk,
        "findings": findings,
        "headers": [{"name": k, "value": v} for k, v in headers],
    }


def _bulk_sender(H: dict, hops: list[dict], primary: dict | None, dkim_sigs: list[dict]) -> dict | None:
    """Checklist of the bulk-sender requirements published by the major mailbox
    providers (Gmail, Yahoo, Outlook.com), for messages that look like bulk mail."""
    reasons = []
    lu = (H.get("list-unsubscribe") or [None])[0]
    if lu:
        reasons.append("List-Unsubscribe header")
    prec = ((H.get("precedence") or [""])[0] or "").strip().lower()
    if prec in ("bulk", "list"):
        reasons.append(f"Precedence: {prec}")
    if H.get("list-id"):
        reasons.append("List-Id header")
    esps = []
    for h in hops:
        for host in (h["from_host"], h["by_host"]):
            p = provider_for(host)
            if p and p["kind"] == "sender" and p["name"] not in esps:
                esps.append(p["name"])
    if esps:
        reasons.append("sent through " + ", ".join(esps))
    if not reasons:
        return None

    items: list[dict] = []

    def item(key, label, status, why):
        items.append({"key": key, "label": label, "status": status, "detail": why})

    results = (primary or {}).get("results", [])
    by = (primary or {}).get("authserv_id") or "the receiver"

    def auth(method):
        return [r for r in results if r["method"] == method]

    for method, label, why_pass, why_fail in (
            ("spf", "SPF passes", "The sending IP is authorised by the envelope domain's SPF record.",
             "Bulk senders must pass SPF for the envelope (Return-Path) domain."),
            ("dkim", "DKIM passes", "The message carries a valid DKIM signature.",
             "Bulk senders must DKIM-sign their mail; a failing or missing signature also makes DMARC depend on SPF alone.")):
        rs = auth(method)
        if not primary:
            item(method, label, "unknown", "No Authentication-Results header to read the receiver's verdict from.")
        elif any(r["result"] == "pass" for r in rs):
            dom = next((r["props"].get("smtp.mailfrom") or r["props"].get("header.d") or r["props"].get("header.i")
                        for r in rs if r["result"] == "pass"), None)
            item(method, label, "pass", why_pass.rstrip(".") + (f" ({dom}, per {by})." if dom else f" (per {by})."))
        else:
            item(method, label, "fail", f"{method.upper()}={rs[0]['result'] if rs else 'not recorded'} per {by}. {why_fail}")
    rs = auth("dmarc")
    if not primary:
        item("dmarc", "DMARC passes (aligned)", "unknown", "No Authentication-Results header to read the receiver's verdict from.")
    elif any(r["result"] == "pass" for r in rs):
        dom = next((r["props"].get("header.from") for r in rs if r["result"] == "pass"), None)
        item("dmarc", "DMARC passes (aligned)", "pass",
             f"SPF or DKIM passed for a domain aligned with the From domain{f' ({dom})' if dom else ''}, per {by}.")
    else:
        item("dmarc", "DMARC passes (aligned)", "fail",
             f"DMARC={rs[0]['result'] if rs else 'not recorded'} per {by}. Bulk senders need a DMARC record and mail that passes it "
             "with SPF or DKIM aligned to the From domain.")

    uris = re.findall(r"<\s*([^>]+?)\s*>", lu or "")
    https = [u for u in uris if u.lower().startswith("https://")]
    mailto = [u for u in uris if u.lower().startswith("mailto:")]
    # Only an ESP in the route: may be transactional mail (receipts, password
    # resets), which doesn't need an unsubscribe link.
    esp_only = not (lu or prec in ("bulk", "list") or H.get("list-id"))
    na = "Not needed for transactional mail (receipts, password resets, alerts); required for marketing and newsletters."
    if not lu and esp_only:
        item("list_unsubscribe", "List-Unsubscribe header present", "na", "No List-Unsubscribe header. " + na)
    elif not lu:
        item("list_unsubscribe", "List-Unsubscribe header present", "fail",
             "No List-Unsubscribe header, so mail clients can't show an unsubscribe button and recipients press 'Report spam' instead.")
    elif https or mailto:
        kinds = (["https"] if https else []) + (["mailto"] if mailto else [])
        item("list_unsubscribe", "List-Unsubscribe header present", "pass", f"Has {' and '.join(kinds)} unsubscribe URI(s).")
    else:
        item("list_unsubscribe", "List-Unsubscribe header present", "fail",
             "The header exists but has no <https://…> or <mailto:…> URI that mail clients can use.")

    lup = ((H.get("list-unsubscribe-post") or [""])[0] or "").strip()
    one_click = re.sub(r"\s+", "", lup).lower() == "list-unsubscribe=one-click"
    signed = any("list-unsubscribe" in (s.get("h") or "").lower() for s in dkim_sigs)
    if not one_click and esp_only:
        item("one_click", "One-click unsubscribe (RFC 8058)", "na", "No List-Unsubscribe-Post header. " + na)
    elif not one_click:
        item("one_click", "One-click unsubscribe (RFC 8058)", "fail",
             ("List-Unsubscribe-Post is present but isn't 'List-Unsubscribe=One-Click'." if lup else
              "No 'List-Unsubscribe-Post: List-Unsubscribe=One-Click' header.")
             + " Gmail and Yahoo require one-click unsubscribe from bulk senders.")
    elif not https:
        item("one_click", "One-click unsubscribe (RFC 8058)", "fail",
             "List-Unsubscribe-Post is set, but one-click needs an https:// URI in List-Unsubscribe (mailto alone doesn't work).")
    elif dkim_sigs and not signed:
        item("one_click", "One-click unsubscribe (RFC 8058)", "warning",
             "One-click is set up, but no DKIM signature covers List-Unsubscribe (h= tag). RFC 8058 requires the signature to include both headers.")
    else:
        item("one_click", "One-click unsubscribe (RFC 8058)", "pass", "List-Unsubscribe-Post: List-Unsubscribe=One-Click with an https URI.")

    cross = _handoffs(hops)
    hop = hops[cross[0]] if cross else None
    if not hop:
        item("tls", "Sending hop used TLS", "unknown", "Couldn't identify the hop where the sender handed the message to another organisation.")
    elif hop["tls"]:
        item("tls", "Sending hop used TLS", "pass",
             f"Hop {hop['index']} ({hop['from_host'] or hop['from_ip']} → {hop['by_host']}) used {hop['tls_version'] or hop['with'] or 'TLS'}.")
    else:
        item("tls", "Sending hop used TLS", "fail",
             f"Hop {hop['index']} ({hop['from_host'] or hop['from_ip']} → {hop['by_host']}) used {hop['with'] or 'SMTP'} without TLS. "
             "Major mailbox providers require bulk mail to be sent over TLS.")

    failed = [i for i in items if i["status"] in ("fail", "warning")]
    short = {"spf": "SPF not passing", "dkim": "DKIM not passing", "dmarc": "DMARC not passing",
             "list_unsubscribe": "no usable List-Unsubscribe", "one_click": "no one-click unsubscribe (RFC 8058)",
             "tls": "sent without TLS"}
    hard = [i for i in failed if i["status"] == "fail"]
    unknown = [i for i in items if i["status"] == "unknown"]
    if not failed and unknown:
        headline = (f"No bulk-sender problems found, but {len(unknown)} of {len(items)} checks couldn't be verified from these headers"
                    + (" (no Authentication-Results)" if not primary else ""))
    elif not failed:
        headline = "This bulk message meets the major mailbox providers' bulk-sender requirements"
    elif len(hard) == 1 and hard[0]["key"] == "one_click":
        headline = ("This bulk message misses one-click unsubscribe (RFC 8058); Gmail and Yahoo require it from bulk senders "
                    "(Gmail: around 5,000+ messages a day to its users).")
    elif not hard:
        headline = "This bulk message meets the bulk-sender requirements, with one caveat: " + failed[0]["detail"]
    else:
        headline = (f"This bulk message fails {len(hard)} of {len(items)} bulk-sender requirements: "
                    + ", ".join(short[i["key"]] for i in hard)
                    + ". Major mailbox providers (Gmail, Yahoo, Outlook.com) require these from bulk senders.")
    detail = ("Looks like bulk mail because of: " + ", ".join(reasons) + ". "
              "Gmail, Yahoo and Outlook.com require bulk senders to authenticate (SPF, DKIM, aligned DMARC), use TLS and offer easy unsubscribe; "
              "mail that misses them is junked, throttled or rejected. Fix it in the sending platform (ESP).")
    return {"reasons": reasons, "esps": esps, "items": items, "failed": [i["key"] for i in failed],
            "headline": headline, "detail": detail}


def _human(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    neg = seconds < 0
    s = abs(int(round(seconds)))
    if s < 60:
        out = f"{s}s"
    elif s < 3600:
        out = f"{s // 60}m {s % 60}s"
    elif s < 86400:
        out = f"{s // 3600}h {(s % 3600) // 60}m"
    else:
        out = f"{s // 86400}d {(s % 86400) // 3600}h"
    return f"-{out}" if neg else out


def _auth_explain(r: dict) -> str:
    m, res = r["method"], r["result"]
    bits = []
    if r.get("comment"):
        bits.append(r["comment"].rstrip(".") + ".")
    if m == "spf":
        dom = r["props"].get("smtp.mailfrom", "?")
        bits.append(f"The sending IP is not authorised by the SPF record of {dom}. If mail passed through a forwarder, "
                    "gateway or signature service, SPF is checked against THAT server's IP. Check with the SPF Inspector.")
    elif m == "dkim":
        bits.append("The signature didn't verify. Common causes: the message was modified in transit (disclaimer, signature service, "
                    "link rewriting, gateway banner), a wrong or rotated public key, or no signature at all.")
    elif m == "dmarc":
        dom = r["props"].get("header.from", "?")
        bits.append(f"Neither SPF nor DKIM passed while ALIGNED with the From domain ({dom}). "
                    + (f"Receiver action: {r['action']}. " if r.get("action") else "")
                    + "Make sure every legitimate sender either signs DKIM with your domain or uses a Return-Path in your domain.")
    return " ".join(bits)


def _microsoft(H: dict) -> dict | None:
    fopa = (H.get("x-forefront-antispam-report") or [None])[0]
    mas = (H.get("x-microsoft-antispam") or [None])[0]
    auth_as = (H.get("x-ms-exchange-organization-authas") or [None])[0]
    if not (fopa or mas or auth_as or any(k.startswith("x-ms-exchange") for k in H)):
        return None
    out: dict = {"fields": [], "findings": []}

    def add(label, value, meaning=""):
        if value not in (None, ""):
            out["fields"].append({"field": label, "value": value, "meaning": meaning})

    if fopa:
        fp = _kv_semicolon(fopa)
        out["forefront"] = fp
        add("CIP (connecting IP)", fp.get("CIP"), "The IP that connected to EOP. SPF and connection filtering are judged on this.")
        add("CTRY", fp.get("CTRY"), "Country of the connecting IP")
        add("H (HELO)", fp.get("H"), "HELO/EHLO string of the connecting server")
        add("PTR", fp.get("PTR"), "Reverse DNS of the connecting IP")
        add("SFV", fp.get("SFV"), SFV.get(fp.get("SFV", ""), ""))
        add("CAT", fp.get("CAT"), CAT.get(fp.get("CAT", ""), "Protection policy that was applied"))
        add("IPV", fp.get("IPV"), IPV.get(fp.get("IPV", ""), ""))
        add("SCL", fp.get("SCL"), _scl(fp.get("SCL")))
        add("DIR", fp.get("DIR"), DIR.get(fp.get("DIR", ""), ""))
        add("SFTY", fp.get("SFTY"), "Safety tip / impersonation indicator was applied" if fp.get("SFTY") else "")
        add("SRV", fp.get("SRV"), "BULK = marked as bulk by spam filtering" if fp.get("SRV") == "BULK" else "")
        add("LANG", fp.get("LANG"), "Detected language")
        sfv, cat = fp.get("SFV", ""), fp.get("CAT", "")
        if sfv in ("SPM", "SKS", "SKB", "BLK") or cat in ("SPM", "HSPM", "PHSH", "HPHSH", "HPHISH", "MALW", "SPOOF", "BULK", "DIMP", "UIMP", "GIMP"):
            findings_sev = "critical" if cat in ("PHSH", "HPHSH", "HPHISH", "MALW") else "warning"
            out["findings"].append(_f(findings_sev, f"Microsoft 365 verdict: {CAT.get(cat, cat) or 'Spam'} (SFV:{sfv})",
                                      SFV.get(sfv, "") + ". Check the anti-spam/anti-phish policy, Tenant Allow/Block List, "
                                      "and use Threat Explorer with the Network Message ID to see the detection technology."))
        if sfv == "SKN" or fp.get("SCL") == "-1":
            out["findings"].append(_f("info", "Spam filtering bypassed (SCL -1)",
                                      "A mail flow rule or allow entry set SCL -1. Phish/malware filters still apply, but spam doesn't. Make sure the rule isn't too broad."))
        if fp.get("IPV") == "CAL":
            out["findings"].append(_f("warning", "Connecting IP is on the connection filter IP Allow List",
                                      "Spam filtering is skipped for everything from this IP. Use this only for trusted sources; prefer Enhanced Filtering for gateways."))
    if mas:
        bcl = re.search(r"BCL:(\d+)", mas)
        if bcl:
            add("BCL", bcl.group(1), _bcl(int(bcl.group(1))))
            if int(bcl.group(1)) >= 7:
                out["findings"].append(_f("info", f"High bulk complaint level (BCL {bcl.group(1)})",
                                          "Junked or quarantined if above the policy's bulk threshold (default 7)."))
    if auth_as:
        add("AuthAs", auth_as, AUTH_AS.get(auth_as, ""))
    for hdr, label in (("x-ms-exchange-organization-authsource", "AuthSource"),
                       ("x-ms-exchange-organization-messagedirectionality", "Directionality"),
                       ("x-ms-exchange-crosstenant-id", "Tenant ID"),
                       ("x-ms-exchange-crosstenant-authas", "CrossTenant AuthAs"),
                       ("x-ms-exchange-transport-crosstenantheadersstamped", "Delivered on mailbox server"),
                       ("x-ms-exchange-organization-scl", "Org SCL"),
                       ("x-ms-publictraffictype", "Traffic type"),
                       ("x-ms-exchange-inbox-rules-loop", "Inbox rule loop marker"),
                       ("x-ms-exchange-generated-message-source", "Generated by"),
                       ("x-ms-exchange-organization-generated-message-source", "Generated by (org)")):
        vals = H.get(hdr)
        if vals:
            add(label, ", ".join(dict.fromkeys(vals)))
    if H.get("x-ms-exchange-skiplistedinternetsender") or H.get("x-ms-exchange-externaloriginalinternetsender"):
        out["enhanced_filtering"] = True
        add("Enhanced Filtering", "Active", "EOP looked past the gateway to the original sender IP")
    return out


def _scl(v: str | None) -> str:
    try:
        n = int(v or "")
    except ValueError:
        return ""
    if n == -1:
        return "Bypassed spam filtering (trusted/allowed)"
    if n <= 1:
        return "Not spam"
    if n <= 6:
        return "Spam (Junk folder by default)"
    return "High confidence spam"


def _bcl(n: int) -> str:
    if n == 0:
        return "Not from a bulk sender"
    if n <= 3:
        return "Bulk sender with few complaints"
    if n <= 7:
        return "Bulk sender with a mixed number of complaints"
    return "Bulk sender with a high number of complaints"


SPF_EVAL_HEADERS = ("authentication-results", "authentication-results-original", "arc-authentication-results")
_NOT_PASS = ("fail", "softfail", "neutral", "none", "permerror", "temperror")


def _spf_evaluations(H: dict) -> list[dict]:
    """Every SPF verdict recorded in the headers, with the IP it was judged against.
    Exchange Online keeps earlier verdicts in ARC-Authentication-Results and
    Authentication-Results-Original when a message passes through it twice."""
    evals: list[dict] = []
    for name in SPF_EVAL_HEADERS:
        for v in H.get(name, []):
            arc_i = None
            m = re.match(r"^\s*i\s*=\s*(\d+)\s*;", v)
            if m:
                arc_i, v = int(m.group(1)), v[m.end():]
            ar = parse_auth_results(v)
            dmarc = next((r for r in ar["results"] if r["method"] == "dmarc"), None)
            policy = re.search(r"\bp=(\w+)", (dmarc or {}).get("comment") or "")
            for r in ar["results"]:
                if r["method"] != "spf":
                    continue
                ips = _ips_in(r.get("comment") or "")
                evals.append({"header": name, "arc_i": arc_i, "authserv": ar["authserv_id"], "result": r["result"],
                              "ip": ips[0] if ips else None, "mailfrom": r["props"].get("smtp.mailfrom"),
                              "dmarc": dmarc["result"] if dmarc else None,
                              "dmarc_policy": policy.group(1).lower() if policy else None})
    for v in H.get("received-spf", []):
        res = re.match(r"\s*(\w+)", v)
        ip = re.search(r"client-ip=([0-9a-fA-F:.]+)", v) or re.search(r"(?:use of|designates?|permitted sender\)?)\s+([0-9a-fA-F:.]{3,})", v)
        if res and ip:
            evals.append({"header": "received-spf", "arc_i": None, "authserv": "", "result": res.group(1).lower(),
                          "ip": ip.group(1).strip("."), "mailfrom": None, "dmarc": None, "dmarc_policy": None})
    return evals


def _handoffs(hops: list[dict]) -> list[int]:
    """Indexes of hops where the message crossed from one organisation/platform
    to another over a public IP."""
    out = []
    for i, h in enumerate(hops):
        if not h["from_ip"] or h["from_private"]:
            continue
        try:
            addr = ipaddress.ip_address(h["from_ip"])
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local:
            continue
        if h["from_host"] and zone_for(h["from_host"]) != h["zone"]:
            out.append(i)
    return out


def _spf_path(hops: list[dict], H: dict, ms: dict | None, live: bool) -> dict | None:
    """Detect SPF being judged against an intermediary (gateway, signature service,
    forwarder) instead of the server the message actually came from."""
    evals = _spf_evaluations(H)
    cross = _handoffs(hops)
    if not cross or not evals:
        return None
    origin_i = cross[0]
    origin = hops[origin_i]
    by_ip = {h["from_ip"]: i for i, h in enumerate(hops) if h["from_ip"]}
    bad: dict[str, dict] = {}
    for e in evals:
        idx = by_ip.get(e["ip"])
        if e["ip"] and idx is not None and idx > origin_i and e["result"] in _NOT_PASS:
            bad.setdefault(e["ip"], {**e, "hop": idx + 1})
    if not bad:
        return None
    bad = dict(sorted(bad.items(), key=lambda kv: kv[1]["hop"]))  # route order

    mailfrom = next((e["mailfrom"] for e in evals if e["mailfrom"]), None)
    mailfrom_domain = mailfrom.rsplit("@", 1)[-1].lower() if mailfrom else None
    chain = []
    for i in cross:
        h = hops[i]
        p = provider_for(h["from_host"])
        chain.append({
            "hop": i + 1, "ip": h["from_ip"], "host": h["from_host"], "from_org": zone_for(h["from_host"]),
            "to_org": h["zone"], "to_host": h["by_host"], "kind": p["kind"] if p else None, "is_origin": i == origin_i,
            "spf": [{"result": e["result"], "by": e["authserv"] or e["header"], "header": e["header"]}
                    for e in evals if e["ip"] == h["from_ip"]],
        })

    live_result = None
    # Never live-check documentation addresses (samples, redacted headers) against real domains.
    _doc = ("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:")
    if live and mailfrom_domain and not str(origin["from_ip"]).lower().startswith(_doc):
        try:
            s = analyze_spf(mailfrom_domain, None, origin["from_ip"])
            live_result = {"domain": mailfrom_domain, "ip": origin["from_ip"], "result": s["test"]["result"],
                           "trace": s["test"]["trace"], "record": s.get("record")}
        except ValueError:
            live_result = None
    earliest_arc = min((e for e in evals if e["arc_i"]), key=lambda e: e["arc_i"], default=None)

    final_dmarc = next((e["dmarc"] for e in evals if e["header"] == "authentication-results" and e["dmarc"]), None)
    policy = next((e["dmarc_policy"] for e in evals if e["dmarc_policy"]), None)
    allow_listed = [_kv_semicolon(v).get("CIP") for k in ("x-forefront-antispam-report", "x-forefront-antispam-report-untrusted")
                    for v in H.get(k, []) if _kv_semicolon(v).get("IPV") == "CAL"]
    allow_listed = [ip for ip in dict.fromkeys(allow_listed) if ip]

    culprits = [f"{chain_item['from_org']} ({ip})" for ip in bad for chain_item in chain if chain_item["ip"] == ip]
    severity = "critical" if final_dmarc in ("fail", "permerror") else "warning"
    title = "Microsoft 365 is checking SPF against " + ", ".join(culprits) + ", not the real sender"

    lines = [f"The message left the sender's platform ({chain[0]['from_org']}) from {origin['from_ip']} at hop {origin_i + 1}. "
             "That's the IP SPF should be judged against."]
    if live_result:
        res = live_result["result"]
        if res == "pass":
            lines.append(f"Checked live: {origin['from_ip']} PASSES SPF for {mailfrom_domain} right now. The sender is configured correctly; "
                         "every non-pass below is caused by the hand-offs on the receiving side.")
        else:
            lines.append(f"Checked live: {origin['from_ip']} gets '{res}' for {mailfrom_domain}, so the sender ALSO has an SPF problem. Fix both.")
    if earliest_arc and earliest_arc["result"] == "pass":
        lines.append(f"ARC confirms it: the first ARC set (i={earliest_arc['arc_i']}, {earliest_arc['authserv']}) recorded spf=pass.")
    lines.append("Instead, Exchange Online judged SPF against the server that handed it the message:")
    for ip, e in bad.items():
        org = next(c["from_org"] for c in chain if c["ip"] == ip)
        lines.append(f"  • {ip} ({org}, hop {e['hop']}) → spf={e['result']}")
    lines.append("")
    lines.append("Why it matters: without Enhanced Filtering, Defender can never trust SPF for ANY inbound message on this route. "
                 + (f"DMARC passed here only because the sender DKIM-signs. " if final_dmarc == "pass" else "")
                 + "Senders that don't DKIM-sign, or whose signature the gateway breaks (banners, link rewriting, disclaimers), fail DMARC"
                 + (f", and this sender publishes p={policy}" if policy else "")
                 + ". Spoof intelligence, compauth and sender reputation are also built on the gateway's IP instead of the real sender's.")
    fixes = []
    for ip in bad:
        org = next(c["from_org"] for c in chain if c["ip"] == ip)
        fixes.append(f"Enable Enhanced Filtering for Connectors on the inbound connector that receives mail from {org} ({ip}). "
                     "Defender portal → Email & collaboration → Policies & rules → Threat policies → Enhanced filtering → select the connector → "
                     "'Automatically detect and skip the last IP address' (or 'Skip these IP addresses' with the gateway's IPs). Apply to all recipients, not just a test group.")
    commands = ["Get-InboundConnector | Format-List Name,ConnectorType,SenderIPAddresses,EFSkipLastIP,EFSkipIPs,EFUsers,EFTestMode",
                'Set-InboundConnector -Identity "<connector name>" -EFSkipLastIP $true -EFUsers $null']
    if allow_listed:
        fixes.append("These IPs are on the connection filter IP Allow List (IPV:CAL): " + ", ".join(allow_listed) +
                     ". That skips spam filtering (SCL -1) but does nothing for SPF/DMARC. Once Enhanced Filtering is on, remove them so EOP filters this mail properly.")
        commands.append("Get-HostedConnectionFilterPolicy | Format-List Name,IPAllowList")
    if not any(k in H for k in ("x-ms-exchange-skiplistedinternetsender", "x-ms-exchange-externaloriginalinternetsender")):
        lines.append("\nNo Enhanced Filtering marker (X-MS-Exchange-SkipListedInternetSender) was found in these headers.")

    return {"severity": severity, "title": title, "detail": "\n".join(lines), "fixes": fixes, "commands": commands,
            "origin": {"hop": origin_i + 1, "ip": origin["from_ip"], "host": origin["from_host"], "org": chain[0]["from_org"]},
            "live_check": live_result, "mailfrom_domain": mailfrom_domain, "chain": chain,
            "bad_ips": list(bad), "allow_listed": allow_listed, "dmarc_policy": policy}


def _loop_analysis(hops: list[dict], H: dict, subject: str) -> dict:
    findings: list[dict] = []
    causes: list[dict] = []
    score = 0
    n = len(hops)

    # Hop count
    if n >= 25:
        score += 3
        findings.append(_f("critical", f"{n} Received hops",
                           "Close to or over typical hop limits (Sendmail 25, Postfix 50, Exchange returns 5.4.14 'Hop count exceeded'). "
                           "Normal mail has 3-12 hops."))
    elif n >= 15:
        score += 1
        findings.append(_f("warning", f"{n} Received hops (unusually long)",
                           "Normal mail has 3-12 hops. Look for repeated servers in the route below."))

    # Same receiving host visited in separate stays
    positions: dict[str, list[int]] = {}
    for i, h in enumerate(hops):
        if h["by_host"]:
            positions.setdefault(h["by_host"], []).append(i)
    repeated = {host: _visits(pos) for host, pos in positions.items() if _visits(pos) >= 2}
    if repeated:
        worst = max(repeated.values())
        score += 3 if worst >= 3 else 2
        findings.append(_f("critical" if worst >= 3 else "warning", "The same server received the message more than once",
                           "\n".join(f"{host}: {v} separate visits" for host, v in sorted(repeated.items(), key=lambda x: -x[1]))))

    # Organisation / provider ping-pong
    zones = [h["zone"] for h in hops if h["zone"]]
    collapsed: list[str] = []
    for z in zones:
        if not collapsed or collapsed[-1] != z:
            collapsed.append(z)
    reentries = {z: c for z, c in Counter(collapsed).items() if c >= 2}
    # A platform like Microsoft 365 legitimately appears several times (sender's
    # tenant, recipient's tenant, re-injection after a gateway or signature
    # service). A loop is the SAME hand-off happening again: A → B ... A → B.
    transitions = Counter(zip(collapsed, collapsed[1:]))
    repeated_handoffs = {f"{a} → {b}": c for (a, b), c in transitions.items() if c >= 2}
    if repeated_handoffs:
        worst = max(repeated_handoffs.values())
        score += 3
        findings.append(_f("critical", "The same hand-off happened more than once: " +
                           ", ".join(f"{t} ({c}×)" for t, c in repeated_handoffs.items()),
                           "Route: " + " → ".join(collapsed) + "\nThe message keeps going back and forth between the same systems."))
        causes.extend(_ping_pong_causes(collapsed, reentries, hops))
    elif reentries:
        findings.append(_f("info", "Message passed through " + ", ".join(f"{z} ({c}×)" for z, c in reentries.items()),
                           "Route: " + " → ".join(collapsed) + "\nNo hand-off repeats, so this isn't a loop. This is normal when the sender and "
                           "recipient are both on the same platform, or when mail is routed out to a gateway/signature service and back."))

    # Header markers
    rules_loop = H.get("x-ms-exchange-inbox-rules-loop", [])
    if rules_loop:
        uniq = list(dict.fromkeys(v.lower() for v in rules_loop))
        score += 3 if len(rules_loop) >= 2 else 1
        findings.append(_f("critical" if len(rules_loop) >= 2 else "info",
                           "Forwarded or redirected by an inbox rule (X-MS-Exchange-Inbox-Rules-Loop)",
                           "Rule owner(s): " + ", ".join(uniq) + (". Multiple markers mean several rules forward to each other." if len(rules_loop) >= 2 else "")))
        owner = next((u for u in uniq if cmdsafe.email(u, "")), "user@contoso.com")
        causes.append({
            "title": "Inbox rule / mailbox forwarding",
            "detail": f"Mailbox {', '.join(uniq)} has a rule that forwards or redirects mail. If the target forwards back (another rule, an alias, or an external forward), the message loops until Exchange stops it.",
            "commands": [f"Get-InboxRule -Mailbox {cmdsafe.ps_quote(owner)} | Where-Object {{ $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo }} | Format-List Name,Enabled,ForwardTo,RedirectTo,ForwardAsAttachmentTo",
                         f"Get-Mailbox {cmdsafe.ps_quote(owner)} | Format-List ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward"],
        })
    delivered_to = [v.lower() for v in H.get("delivered-to", []) + H.get("x-original-to", [])]
    dt_dupes = [a for a, c in Counter(delivered_to).items() if c >= 2]
    if dt_dupes:
        score += 3
        findings.append(_f("critical", "Same Delivered-To address appears more than once", ", ".join(dt_dupes) +
                           ". Postfix/Gmail-style systems use this to detect forwarding loops (\"mail forwarding loop for …\")."))
        causes.append({"title": "Alias / forward pointing back to itself",
                       "detail": f"{', '.join(dt_dupes)} forwards (via alias, .forward, Gmail forwarding or a hosted mail rule) to an address that eventually forwards back.",
                       "commands": []})
    if H.get("x-loop"):
        score += 1
        findings.append(_f("info", "X-Loop header present: " + ", ".join(H["x-loop"]),
                           "Stamped by ticketing systems, list managers and procmail to stop loops. A system that sees its own X-Loop value should drop the message."))

    # Auto-reply ping-pong
    prefixes = AUTO_PREFIX_RE.findall(subject or "")
    auto_submitted = (H.get("auto-submitted") or [""])[0].lower()
    is_auto = bool(auto_submitted and auto_submitted != "no") or bool(H.get("x-autoreply") or H.get("x-autorespond"))
    if len(prefixes) >= 3:
        score += 2
        findings.append(_f("warning", f"Subject has {len(prefixes)} reply/auto-reply prefixes",
                           f"'{subject}'. Two systems are probably replying to each other automatically."))
        causes.append({
            "title": "Auto-reply ping-pong",
            "detail": "Two automatic responders (out-of-office, ticketing system, shared mailbox auto-reply, transport rule reply) keep answering each other. "
                      "Well-behaved responders don't reply to messages with Auto-Submitted, Precedence: bulk/junk/list, or X-Auto-Response-Suppress.",
            "commands": ["Create a mail flow rule: if the subject or headers contain the ticket system's marker AND the message is an auto-reply (header Auto-Submitted matches 'auto-replied'), then delete the message",
                         "Get-MailboxAutoReplyConfiguration <mailbox> | Format-List AutoReplyState,ExternalAudience"],
        })
    if is_auto:
        findings.append(_f("info", f"Automatic message (Auto-Submitted: {auto_submitted or 'x-autoreply'})",
                           "Generated by an autoresponder, rule, or system rather than a person."))
        if prefixes:
            score += 1

    gen = H.get("x-ms-exchange-generated-message-source", []) + H.get("x-ms-exchange-organization-generated-message-source", [])
    if gen:
        findings.append(_f("info", "Generated by Exchange: " + ", ".join(dict.fromkeys(gen)),
                           "Exchange created this message itself (e.g. Mailbox Rules Agent = inbox rule, journal, or an NDR)."))

    if repeated and not causes:
        host = max(repeated, key=repeated.get)
        causes.append({
            "title": f"Routing points back to {host}",
            "detail": "The same server keeps receiving the message, so its next hop (MX, smart host or connector) leads back to it. "
                      "Check the smart host on send connectors, the MX of the recipient domain, and any relay settings on that server.",
            "commands": ["Get-SendConnector | Format-List Name,AddressSpaces,SmartHosts,DNSRoutingEnabled  # Exchange on-prem",
                         "Get-OutboundConnector | Format-List Name,RecipientDomains,SmartHosts,IsTransportRuleScoped,RouteAllMessagesViaOnPremises  # Exchange Online"],
        })

    verdict = "likely" if score >= 3 else "possible" if score >= 1 else "none"
    label = {"likely": "Mail loop likely", "possible": "Possible loop indicators", "none": "No loop indicators"}[verdict]
    return {"verdict": verdict, "label": label, "score": score, "route": collapsed, "repeated_hosts": repeated,
            "repeated_handoffs": repeated_handoffs,
            "likely_causes": causes, "findings": findings}


def _ping_pong_causes(collapsed: list[str], reentries: dict[str, int], hops: list[dict]) -> list[dict]:
    causes: list[dict] = []
    zones = set(collapsed)
    kinds = {}
    for h in hops:
        for host in (h["by_host"], h["from_host"]):
            p = provider_for(host)
            if p:
                kinds[p["name"]] = p["kind"]
    m365 = "Microsoft 365" in zones
    gateways = [z for z in zones if kinds.get(z) == "gateway"]
    sigs = [z for z in zones if kinds.get(z) == "signature"]
    onprem = [z for z in reentries if z not in kinds and not re.match(r"^\d", z)]
    heavy = True  # only called when a hand-off repeats

    if m365 and sigs:
        s = sigs[0]
        causes.append({
            "title": f"Signature service loop (Microsoft 365 ↔ {s})",
            "detail": f"A transport rule routes mail to the {s} outbound connector, and {s} sends it back. If the rule has no exception for mail "
                      f"that already came back (the header {s} stamps, or the connector's IP), every return trip triggers the rule again.",
            "commands": ["Get-TransportRule | Where-Object { $_.RouteMessageOutboundConnector } | Format-List Name,State,Priority,RouteMessageOutboundConnector,ExceptIfHeaderContainsMessageHeader,ExceptIfSenderIpRanges",
                         "Get-OutboundConnector | Format-List Name,IsTransportRuleScoped,SmartHosts,Enabled"],
        })
    if m365 and gateways and heavy:
        g = gateways[0]
        causes.append({
            "title": f"Connector / routing loop between Microsoft 365 and {g}",
            "detail": f"Microsoft 365 sends the message to {g}, and {g} sends it straight back. Typical causes:\n"
                      f"1. An outbound connector sends ALL domains (*) to {g}, and {g} treats the recipient domain as internal and delivers it back to Microsoft 365.\n"
                      f"2. The accepted domain is Internal Relay in Microsoft 365 (so unknown recipients go out the connector) and {g} routes that domain back to Microsoft 365.\n"
                      f"3. The recipient is a mail user/contact whose external address is in one of your own domains.\n"
                      f"4. The MX for the recipient domain points at {g}, but {g}'s delivery route for the domain is wrong (points to itself or to a different tenant).",
            "commands": ["Get-OutboundConnector | Format-List Name,Enabled,RecipientDomains,SmartHosts,IsTransportRuleScoped,UseMXRecord",
                         "Get-AcceptedDomain | Format-Table Name,DomainName,DomainType",
                         "Get-Recipient <recipient address> | Format-List RecipientTypeDetails,ExternalEmailAddress,PrimarySmtpAddress",
                         "Get-MessageTraceV2 -RecipientAddress <recipient> -StartDate (Get-Date).AddHours(-6) | Format-Table Received,SenderAddress,Status,FromIP,ToIP"],
        })
    if m365 and onprem and heavy:
        o = onprem[0]
        causes.append({
            "title": f"Hybrid routing loop between Microsoft 365 and {o}",
            "detail": "The message bounces between Exchange Online and on-premises. Typical causes:\n"
                      "1. The accepted domain is Internal Relay on BOTH sides, so each forwards unknown recipients to the other.\n"
                      "2. The recipient is a mail user in one environment and a mail user in the other (no actual mailbox anywhere), e.g. after a failed migration or deprovisioning.\n"
                      "3. targetAddress / RemoteRoutingAddress points to the wrong domain (should be @tenant.mail.onmicrosoft.com).\n"
                      "4. Centralized Mail Transport is on and the on-prem send connector routes the domain back to Exchange Online.",
            "commands": ["Get-AcceptedDomain | Format-Table Name,DomainType   # run on both sides",
                         "Get-RemoteMailbox <user> | Format-List RemoteRoutingAddress,PrimarySmtpAddress   # on-prem",
                         "Get-Recipient <user> | Format-List RecipientTypeDetails,ExternalEmailAddress   # Exchange Online",
                         "Get-OutboundConnector | Format-List Name,RouteAllMessagesViaOnPremises,SmartHosts"],
        })
    if not causes and heavy:
        a, b = collapsed[0], collapsed[1] if len(collapsed) > 1 else collapsed[0]
        causes.append({
            "title": f"Routing loop between {a} and {b}",
            "detail": "Each system thinks the other is responsible for the recipient. Check MX records, smart hosts, relay/forwarding settings and accepted domains on both systems.",
            "commands": [],
        })
    return causes
