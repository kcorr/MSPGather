"""Security triage: suspicious-link analysis and lookalike-domain monitoring.

Defensive tools for an MSP's own clients:
  * URL Analyzer: unwraps security-gateway links offline (Safe Links, Proofpoint,
    Barracuda, ...), analyses the real destination statically, enriches it with
    domain age (RDAP), DNS and hosting owner, and optionally (opt-in) discovers
    the redirect chain with SSRF-safe requests.
  * Lookalike Domains: generates typo / look-alike variants of a client's domain
    and checks which are registered, which can send/receive mail, and how new
    they are.

Nothing here executes page content. Bodies are capped and discarded except the
<title> and a couple of derived yes/no signals.
"""
from __future__ import annotations

import base64
import binascii
import html
import ipaddress
import quopri
import re
import socket
import ssl
import string
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from ..core.dns_utils import addresses, is_ip, make_resolver, normalize_domain, registered_domain, resolve
from ..core import rdap
from ..core.http import run
from .ipinfo import asn_lookup, ip_lookup
from .smtp_test import _cert_info

router = APIRouter()

HTTP_TIMEOUT = 8.0
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
MAX_URLS = 25
MAX_HOPS = 10
BODY_CAP = 64 * 1024


# =============================================================== knowledge base
# Brands commonly impersonated in phishing, with the registered domains they
# actually own. Only first-party domains: customer-hosted platforms (azurewebsites.net,
# blob.core.windows.net, github.io ...) are in USER_CONTENT_HOSTS instead.
BRANDS: list[dict] = [
    {"name": "Microsoft", "tokens": ["microsoft", "microsoftonline", "office365", "microsoft365", "outlook", "onedrive",
                                     "sharepoint", "hotmail", "msonline"],
     "domains": ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "office.net", "outlook.com",
                 "live.com", "live.net", "hotmail.com", "msn.com", "sharepoint.com", "onedrive.com", "onmicrosoft.com",
                 "microsoft365.com", "windows.com", "windowsupdate.com", "azure.com", "msft.net", "msauth.net",
                 "msftauth.net", "aka.ms", "1drv.ms", "bing.com", "skype.com", "xbox.com", "cloud.microsoft",
                 "static.microsoft", "microsoftstore.com", "sharepointonline.com"]},
    {"name": "DocuSign", "tokens": ["docusign"], "domains": ["docusign.com", "docusign.net"]},
    {"name": "PayPal", "tokens": ["paypal"], "domains": ["paypal.com", "paypal.me", "paypalobjects.com"]},
    {"name": "Adobe", "tokens": ["adobe"], "domains": ["adobe.com", "adobe.io", "adobelogin.com"]},
    {"name": "Dropbox", "tokens": ["dropbox"], "domains": ["dropbox.com", "dropboxusercontent.com", "db.tt"]},
    {"name": "Google", "tokens": ["google", "gmail"], "domains": ["google.com", "gmail.com", "googleusercontent.com", "gstatic.com",
                                                                   "googleapis.com", "youtube.com", "goo.gl", "g.co", "forms.gle"]},
    {"name": "Apple", "tokens": ["apple", "icloud", "itunes"], "domains": ["apple.com", "icloud.com", "itunes.com", "me.com", "mzstatic.com"]},
    {"name": "Amazon", "tokens": ["amazon"], "domains": ["amazon.com", "media-amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca"]},
    {"name": "Netflix", "tokens": ["netflix"], "domains": ["netflix.com"]},
    {"name": "LinkedIn", "tokens": ["linkedin"], "domains": ["linkedin.com", "lnkd.in", "licdn.com"]},
    {"name": "Meta (Facebook / Instagram / WhatsApp)", "tokens": ["facebook", "instagram", "whatsapp"],
     "domains": ["facebook.com", "fb.com", "fb.me", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net", "meta.com"]},
    {"name": "DHL", "tokens": ["dhl"], "domains": ["dhl.com", "dhl.de"]},
    {"name": "FedEx", "tokens": ["fedex"], "domains": ["fedex.com"]},
    {"name": "USPS", "tokens": ["usps"], "domains": ["usps.com"]},
    {"name": "Wells Fargo", "tokens": ["wellsfargo"], "domains": ["wellsfargo.com"]},
    {"name": "Chase", "tokens": ["chase"], "domains": ["chase.com"]},
    {"name": "Bank of America", "tokens": ["bankofamerica"], "domains": ["bankofamerica.com"]},
    {"name": "Zoom", "tokens": ["zoom"], "domains": ["zoom.us", "zoom.com", "zoomgov.com"]},
    {"name": "WeTransfer", "tokens": ["wetransfer"], "domains": ["wetransfer.com", "we.tl"]},
    {"name": "Intuit / QuickBooks", "tokens": ["quickbooks"], "domains": ["intuit.com", "quickbooks.com"]},
    {"name": "Okta", "tokens": ["okta"], "domains": ["okta.com", "oktacdn.com", "okta-emea.com", "oktapreview.com"]},
    {"name": "Coinbase", "tokens": ["coinbase"], "domains": ["coinbase.com"]},
    {"name": "Salesforce", "tokens": ["salesforce"], "domains": ["salesforce.com", "force.com"]},
    {"name": "Citrix / ShareFile", "tokens": ["citrix", "sharefile"], "domains": ["citrix.com", "sharefile.com", "citrixdata.com"]},
    {"name": "Slack", "tokens": ["slack"], "domains": ["slack.com", "slack-edge.com", "slack-redir.net"]},
    {"name": "GitHub", "tokens": ["github"], "domains": ["github.com"]},
    {"name": "Yahoo", "tokens": ["yahoo"], "domains": ["yahoo.com", "yahoo.net", "yimg.com"]},
    {"name": "IRS", "tokens": ["irs"], "domains": ["irs.gov"]},
]
_BRAND_BY_DOMAIN = {d: b["name"] for b in BRANDS for d in b["domains"]}

# Legitimate services where anyone can publish content, so they are regularly used
# to host phishing pages, forms or lure documents. Matched on host suffix.
USER_CONTENT_HOSTS: list[tuple[str, str]] = [
    ("forms.office.com", "Microsoft Forms"), ("forms.microsoft.com", "Microsoft Forms"), ("sway.office.com", "Microsoft Sway"),
    ("sway.cloud.microsoft", "Microsoft Sway"), ("1drv.ms", "OneDrive share link"), ("onedrive.live.com", "OneDrive (personal)"),
    ("sharepoint.com", "SharePoint / OneDrive for Business"),
    ("docs.google.com", "Google Docs / Forms / Drawings"), ("forms.gle", "Google Forms short link"), ("sites.google.com", "Google Sites"),
    ("drive.google.com", "Google Drive"), ("storage.googleapis.com", "Google Cloud Storage"), ("firebaseapp.com", "Firebase Hosting"),
    ("web.app", "Firebase Hosting"), ("appspot.com", "Google App Engine"), ("azurewebsites.net", "Azure App Service"),
    ("web.core.windows.net", "Azure Storage static website"), ("blob.core.windows.net", "Azure Blob Storage"),
    ("azureedge.net", "Azure CDN"), ("github.io", "GitHub Pages"), ("githubusercontent.com", "GitHub user content"),
    ("netlify.app", "Netlify"), ("vercel.app", "Vercel"), ("pages.dev", "Cloudflare Pages"), ("workers.dev", "Cloudflare Workers"),
    ("r2.dev", "Cloudflare R2 storage"), ("trycloudflare.com", "Cloudflare quick tunnel"), ("herokuapp.com", "Heroku"),
    ("glitch.me", "Glitch"), ("ngrok.io", "ngrok tunnel"), ("ngrok-free.app", "ngrok tunnel"), ("amazonaws.com", "AWS-hosted (S3 / EC2 / etc.)"),
    ("dropbox.com", "Dropbox"), ("dropboxusercontent.com", "Dropbox"), ("wetransfer.com", "WeTransfer"), ("we.tl", "WeTransfer"),
    ("jotform.com", "Jotform"), ("typeform.com", "Typeform"), ("formstack.com", "Formstack"), ("wufoo.com", "Wufoo"),
    ("123formbuilder.com", "123FormBuilder"), ("surveymonkey.com", "SurveyMonkey"), ("canva.com", "Canva"), ("notion.site", "Notion public page"),
    ("webflow.io", "Webflow"), ("wixsite.com", "Wix"), ("weebly.com", "Weebly"), ("godaddysites.com", "GoDaddy Website Builder"),
    ("square.site", "Square Online"), ("000webhostapp.com", "000webhost"), ("blogspot.com", "Blogger"), ("ipfs.io", "IPFS gateway"),
    ("dweb.link", "IPFS gateway"), ("docsend.com", "DocSend"), ("box.com", "Box"), ("framer.app", "Framer"), ("framer.website", "Framer"),
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "t.ly", "tiny.cc", "bl.ink", "lnkd.in", "s.id", "qrco.de", "aka.ms", "1drv.ms", "forms.gle", "we.tl", "shorte.st", "adf.ly",
}

# TLDs that abuse reports (Spamhaus, Interisle) repeatedly rank high. Plenty of
# legitimate sites use them too, so this is a weak signal only.
SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "link", "online", "site", "website", "shop", "cfd", "sbs", "icu", "cyou", "buzz", "rest", "monster",
    "quest", "lol", "bond", "beauty", "hair", "makeup", "skin", "gq", "ml", "cf", "tk", "ga", "work", "support", "country",
    "kim", "stream", "download", "review", "win", "bid", "loan", "men", "party", "date", "faith", "racing", "cricket",
    "science", "accountant", "live", "today", "zip", "mov",
}

RISKY_EXT = {
    "exe": "a Windows program", "scr": "a screensaver (program)", "msi": "an installer", "bat": "a batch script", "cmd": "a batch script",
    "ps1": "a PowerShell script", "vbs": "a VBScript", "js": "a script", "jse": "a script", "wsf": "a script", "hta": "an HTML application",
    "lnk": "a shortcut", "iso": "a disk image", "img": "a disk image", "vhd": "a disk image", "zip": "an archive", "rar": "an archive",
    "7z": "an archive", "html": "an HTML file", "htm": "an HTML file", "shtml": "an HTML file", "svg": "an SVG image (can contain script)",
    "one": "a OneNote file", "docm": "a macro-enabled document", "xlsm": "a macro-enabled workbook", "apk": "an Android app",
}

# Characters from other scripts that render like Latin letters (confusables).
CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l",
    "һ": "h", "ԛ": "q", "ԝ": "w", "к": "k", "ү": "y",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "υ": "u", "χ": "x",
    # Latin look-alikes
    "ı": "i", "ł": "l", "ɑ": "a", "ɡ": "g", "ɩ": "i",
}
_STRONG_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}

PARKING_NS = ("sedoparking.com", "parkingcrew.net", "bodis.com", "above.com", "dan.com", "afternic.com", "hugedomains.com")
# Mail/DNS infrastructure only brand-protection registrars use for their clients' defensive registrations.
BRAND_PROTECTION_INFRA = ("markmonitor.com", "cscdns.net")
BRAND_PROTECTION_REGISTRARS = ("markmonitor", "csc corporate domains", "com laude", "safenames", "brandsight", "lexsynergy",
                               "corporation service company", "godaddy corporate domains", "corsearch")
# Display names for the matches above (registrar substring or infrastructure suffix).
_BP_NAMES = {"markmonitor": "MarkMonitor", "markmonitor.com": "MarkMonitor", "csc corporate domains": "CSC", "corporation service company": "CSC",
             "cscdns.net": "CSC", "com laude": "Com Laude", "safenames": "Safenames", "brandsight": "Brandsight", "lexsynergy": "Lexsynergy",
             "godaddy corporate domains": "GoDaddy Corporate Domains", "corsearch": "Corsearch"}

_URL_RE = re.compile(r"""(?:\b(?:https?|ftp)://|\bwww\.)[^\s<>"'`]+""", re.I)
_SCHEME_RE = re.compile(r"""\b(?:javascript|vbscript|data):[^\s<>"'`]+""", re.I)


# ===================================================================== helpers
def defang(url: str | None) -> str | None:
    """hxxps://example[.]com/path: safe to paste in tickets and chats."""
    if not url:
        return url
    m = re.match(r"^([a-z][a-z0-9+.-]*):(//)?", url, re.I)
    if not m:
        return url.replace(".", "[.]")
    scheme, rest = m.group(1), url[m.end():]
    if not m.group(2):
        return f"{scheme}[:]{rest[:300]}{'…' if len(rest) > 300 else ''}"
    auth = re.match(r"[^/?#]*", rest).group(0)
    return f"{re.sub(r'^http', 'hxxp', scheme, flags=re.I)}://{auth.replace('.', '[.]')}{rest[len(auth):]}"


def defang_domain(d: str | None) -> str | None:
    return d.replace(".", "[.]") if d else d


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


_DOC_NETS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")


def _public_ip(ip: str) -> tuple[bool, str]:
    """True if the address is a normal internet address we may connect to."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False, "not an IP address"
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if str(a) == "169.254.169.254":
        return False, "cloud metadata endpoint"
    if a.is_loopback:
        return False, "loopback"
    if a.is_link_local:
        return False, "link-local"
    if a.is_multicast:
        return False, "multicast"
    if a.is_unspecified:
        return False, "unspecified"
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return False, "carrier-grade NAT (private)"
    if any(a in ipaddress.ip_network(n) for n in _DOC_NETS if ipaddress.ip_network(n).version == a.version):
        return False, "documentation range, not used on the internet"
    if a.is_private:
        return False, "private (internal network)"
    if a.is_reserved or not a.is_global:
        return False, "reserved / not publicly routable"
    return True, ""


def _decode_ip_host(host: str) -> str | None:
    """Hosts like 3232235777, 0x7f000001 or 0177.0.0.1 are IPs in disguise."""
    if is_ip(host):
        return str(ipaddress.ip_address(host.strip("[]")))
    if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}", host, re.I):
        try:
            return socket.inet_ntoa(socket.inet_aton(host))
        except OSError:
            return None
    return None


def _script_of(ch: str) -> str | None:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    first = name.split(" ")[0]
    if first in ("DIGIT", "HYPHEN-MINUS", "LOW", "FULL"):
        return None
    if first in ("CJK", "HIRAGANA", "KATAKANA"):
        return "CJK"
    return first


def _skeleton(text: str) -> str:
    """Map look-alike characters to the Latin letters they imitate."""
    out = []
    for ch in text:
        if ch in CONFUSABLES:
            out.append(CONFUSABLES[ch])
            continue
        base = unicodedata.normalize("NFKD", ch)
        base = "".join(c for c in base if not unicodedata.combining(c))
        out.append(base or ch)
    return "".join(out)


def _osa(a: str, b: str, cap: int = 2) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent transposition)."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


_DIGIT_SWAPS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("4", "a"), ("7", "t")]


def _normalize_lookalike(label: str) -> str:
    s = label.lower()
    for a, b in _DIGIT_SWAPS:
        s = s.replace(a, b)
    return s


def _registered_phrase(days: int | None, created: str | None) -> str:
    if days is None:
        return ""
    if days <= 0:
        return "registered today"
    if days < 60:
        return f"registered {days} day{'s' if days != 1 else ''} ago"
    if days < 365:
        return f"registered {days // 30} months ago"
    return f"registered {(created or '')[:4]}"


def _domain_age_phrase(days: int | None) -> str:
    if days is None:
        return ""
    if days <= 0:
        return "registered today"
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''} old"
    if days < 730:
        return f"{days // 30} months old"
    return f"{days // 365} years old"


# ========================================================================= RDAP
def _vcard(entity: dict) -> dict:
    out: dict = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) < 4:
            continue
        if item[0] == "fn" and item[3]:
            out["name"] = item[3]
        elif item[0] == "org" and item[3] and "name" not in out:
            out["name"] = item[3] if isinstance(item[3], str) else str(item[3])
        elif item[0] == "email" and item[3]:
            out.setdefault("emails", []).append(item[3])
    return out


def domain_rdap(domain: str, timeout: float = HTTP_TIMEOUT) -> dict:
    """Registration data for a domain, straight from its registry (IANA RDAP bootstrap)."""
    out: dict = {"domain": domain, "error": None, "created": None, "age_days": None, "expires": None, "updated": None,
                 "registrar": None, "registrant": None, "abuse_emails": [], "status": [], "nameservers": [], "source": None}
    try:
        r = rdap.get("dns", domain, timeout=timeout)
    except httpx.HTTPError as exc:
        out["error"] = f"RDAP lookup failed: {type(exc).__name__}"
        return out
    out["source"] = str(r.url)
    if r.status_code == 404:
        out["error"] = "No registration record found (the domain may not be registered, or its registry doesn't publish RDAP)."
        out["not_found"] = True
        return out
    if r.status_code != 200:
        out["error"] = f"RDAP returned HTTP {r.status_code}" + (" (rate limited, try again shortly)" if r.status_code == 429 else "")
        return out
    try:
        data = r.json()
    except ValueError:
        out["error"] = "RDAP returned something that isn't JSON"
        return out
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
    created = _parse_dt(events.get("registration"))
    out["created"] = created.isoformat() if created else None
    out["age_days"] = (_now() - created).days if created else None
    out["expires"] = events.get("expiration")
    out["updated"] = events.get("last changed")
    out["status"] = data.get("status", []) or []
    out["nameservers"] = [str(n.get("ldhName", "")).lower().rstrip(".") for n in data.get("nameservers", []) or [] if n.get("ldhName")]
    for e in data.get("entities", []) or []:
        roles = e.get("roles", []) or []
        vc = _vcard(e)
        if "registrar" in roles:
            out["registrar"] = vc.get("name") or e.get("handle")
            for sub in e.get("entities", []) or []:
                if "abuse" in (sub.get("roles") or []):
                    out["abuse_emails"].extend(_vcard(sub).get("emails", []))
        elif "registrant" in roles and vc.get("name"):
            nm = vc["name"]
            if not re.search(r"redacted|privacy|withheld|not disclosed|data protected|proxy", nm, re.I):
                out["registrant"] = nm
        if "abuse" in roles:
            out["abuse_emails"].extend(vc.get("emails", []))
    out["abuse_emails"] = list(dict.fromkeys(out["abuse_emails"]))[:3]
    return out


# ===================================================================== unwrapping
def _qparam(url: str, *names: str) -> str | None:
    """Query parameter (decoded), case-insensitive name match."""
    q = urlsplit(url).query
    wanted = {n.lower() for n in names}
    for k, v in parse_qsl(q, keep_blank_values=True):
        if k.lower() in wanted and v:
            return v
    return None


_V3_RE = re.compile(r"v3/__(?P<url>.+?)__;(?P<enc>[^!]*)!")
_V3_TOKEN = re.compile(r"\*(\*.)?")
_V3_RUN = {c: i + 2 for i, c in enumerate(string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_")}


def decode_proofpoint_v3(url: str) -> str | None:
    """Proofpoint URL Defense v3. Characters Proofpoint couldn't leave in the URL
    are replaced by '*' (one character) or '**X' (a run of N characters, X encodes N)
    and stored, base64url-encoded, after '__;'."""
    m = _V3_RE.search(url)
    if not m:
        return None
    encoded = unquote(m.group("url"))
    enc = m.group("enc")
    try:
        dec = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)).decode("utf-8") if enc else ""
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    out, pos, marker = [], 0, 0
    for t in _V3_TOKEN.finditer(encoded):
        out.append(encoded[pos:t.start()])
        tok = t.group(0)
        if tok == "*":
            n = 1
        else:
            n = _V3_RUN.get(tok[-1])
            if n is None:
                return None
        if marker + n > len(dec):
            return None
        out.append(dec[marker:marker + n])
        marker += n
        pos = t.end()
    out.append(encoded[pos:])
    return "".join(out)


def _decode_proofpoint_v2(url: str) -> str | None:
    m = re.search(r"(?:^|&)u=([^&]+)", urlsplit(url).query)
    if not m:
        return None
    return unquote(m.group(1).translate(str.maketrans("-_", "%/")))


def _unwrap_once(url: str) -> tuple[str | None, str | None, str | None]:
    """Returns (inner_url, wrapper_name, opaque_note). inner_url None = not a wrapper."""
    try:
        p = urlsplit(url)
    except ValueError:
        return None, None, None
    host = (p.hostname or "").lower()
    path = p.path or ""
    if re.search(r"(^|\.)safelinks\.protection\.(outlook\.com|office365\.us)$", host):
        return _qparam(url, "url"), "Microsoft Safe Links", None
    if host == "statics.teams.cdn.office.net" and "safelinks" in path.lower():
        return _qparam(url, "url"), "Microsoft Safe Links (Teams)", None
    if host == "urldefense.proofpoint.com" and path.startswith("/v1/"):
        return _qparam(url, "u"), "Proofpoint URL Defense v1", None
    if host == "urldefense.proofpoint.com" and path.startswith("/v2/"):
        return _decode_proofpoint_v2(url), "Proofpoint URL Defense v2", None
    if host in ("urldefense.com", "urldefense.us") and path.startswith("/v3/"):
        return decode_proofpoint_v3(url), "Proofpoint URL Defense v3", None
    if host == "linkprotect.cudasvc.com":
        return _qparam(url, "a"), "Barracuda Link Protection", None
    if re.search(r"(^|\.)google\.[a-z]{2,3}(\.[a-z]{2})?$", host) and path == "/url":
        return _qparam(url, "q", "url"), "Google redirect", None
    if re.search(r"(^|\.)google\.[a-z]{2,3}(\.[a-z]{2})?$", host) and path.startswith("/amp/s/"):
        return "https://" + path[len("/amp/s/"):] + (f"?{p.query}" if p.query else ""), "Google AMP link", None
    if re.search(r"(^|\.)(outlook\.office\.com|outlook\.office365\.com|outlook\.live\.com)$", host) and "redir" in path.lower():
        return _qparam(url, "url"), "Outlook redirector", None
    if host.endswith((".trendmicro.com", ".trendmicro.eu")) and "/wis/clicktime/" in path:
        return _qparam(url, "url"), "Trend Micro Time-of-Click", None
    if host in ("l.facebook.com", "lm.facebook.com") and path == "/l.php":
        return _qparam(url, "u"), "Facebook outbound link", None
    if host.endswith("linkedin.com") and path.startswith("/redir/redirect"):
        return _qparam(url, "url"), "LinkedIn outbound link", None
    if host == "slack-redir.net":
        return _qparam(url, "url"), "Slack outbound link", None
    if host.endswith("youtube.com") and path == "/redirect":
        return _qparam(url, "q"), "YouTube outbound link", None
    if host == "secure-web.cisco.com":
        last = unquote(path.rsplit("/", 1)[-1])
        if re.match(r"https?://", last, re.I):
            return last, "Cisco Secure Email link", None
    if re.search(r"(^|\.)protection\.sophos\.com$", host):
        u = _qparam(url, "u")
        if u:
            try:
                dec = base64.b64decode(u + "=" * (-len(u) % 4)).decode("utf-8")
                if re.match(r"https?://", dec, re.I):
                    return dec, "Sophos Time-of-Click", None
            except (binascii.Error, UnicodeDecodeError, ValueError):
                pass
    if re.fullmatch(r"protect(-[a-z0-9]+)?\.mimecast\.com", host) or host.endswith("mimecastprotect.com"):
        return None, "Mimecast URL Protect", ("Mimecast links are opaque: the real destination is stored at Mimecast and can only "
                                               "be found by following the link (use Follow redirects) or by looking the click up in the Mimecast console.")
    return None, None, None


def unwrap(url: str) -> dict:
    layers: list[dict] = []
    opaque = None
    current = url
    for _ in range(8):
        inner, name, note = _unwrap_once(current)
        if note:
            opaque = {"wrapper": name, "note": note}
            break
        if not inner or inner == current:
            if name and not inner:
                layers.append({"wrapper": name, "from": current, "to": None, "error": "Couldn't decode the original URL from this wrapper."})
            break
        inner = html.unescape(inner.strip())
        layers.append({"wrapper": name, "from": current, "from_defanged": defang(current), "to": inner, "to_defanged": defang(inner)})
        current = inner
    return {"final": current, "layers": layers, "opaque": opaque}


# ===================================================================== extraction
def _refang(text: str) -> str:
    t = re.sub(r"\bhxxp(s?)", r"http\1", text, flags=re.I)
    t = re.sub(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*\.\s*\}", ".", t, flags=re.I)
    return t.replace("[:]", ":").replace("[://]", "://")


def _clean_tail(u: str) -> str:
    u = u.rstrip()
    while u:
        last = u[-1]
        if last in ".,;:!?'\"*":
            u = u[:-1]
            continue
        pairs = {")": "(", "]": "[", "}": "{", ">": "<"}
        if last in pairs and u.count(last) > u.count(pairs[last]):
            u = u[:-1]
            continue
        break
    return u


def extract_urls(text: str) -> list[str]:
    text = text or ""
    if re.search(r"=\r?\n|=3D", text):
        try:
            text = quopri.decodestring(text.encode("utf-8", "replace")).decode("utf-8", "replace")
        except (ValueError, binascii.Error):
            pass
    text = _refang(text)
    found: list[str] = []
    for m in _URL_RE.finditer(text):
        u = _clean_tail(html.unescape(m.group(0)))
        if u.lower().startswith("www."):
            u = "http://" + u
        found.append(u)
    for m in _SCHEME_RE.finditer(text):
        if not any(m.group(0) in f for f in found):
            found.append(_clean_tail(m.group(0)))
    if not found:
        token = text.strip()
        if token and not re.search(r"\s", token) and "." in token and re.match(r"^[\w.-]+\.[a-z]{2,}([/:?#].*)?$", token, re.I):
            found.append("http://" + token)
    return list(dict.fromkeys(found))


# ===================================================================== static analysis
def _brand_tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _brand_hits(text: str) -> list[dict]:
    """Brands mentioned in text: exact tokens, plus 1-edit typos and digit/letter swaps."""
    hits: dict[str, dict] = {}
    tokens = _brand_tokens(text)
    joined = text.lower()
    norm_tokens = [_normalize_lookalike(t) for t in tokens]
    for b in BRANDS:
        for tok in b["tokens"]:
            short = len(tok) < 6
            if len(tok) >= 7:
                hit = any(tok in t for t in tokens)
            elif len(tok) == 6:
                hit = any(t.startswith(tok) or t.endswith(tok) for t in tokens)
            else:
                hit = tok in tokens
            if hit:
                hits.setdefault(b["name"], {"brand": b["name"], "token": tok, "how": "exact"})
                continue
            if b["name"] in hits:
                continue
            if short:
                continue
            # micros0ft, rnicrosoft, paypa1
            swapped = next((tokens[i] for i, nt in enumerate(norm_tokens) if tok in nt), None)
            if swapped and tok not in joined:
                hits[b["name"]] = {"brand": b["name"], "token": tok, "how": "swap", "seen": swapped}
                continue
            # micosoft, microsfot, microsoftt (one edit away)
            for t in tokens:
                for size in (len(tok) - 1, len(tok), len(tok) + 1):
                    if size < 5 or size > len(t):
                        continue
                    for i in range(0, len(t) - size + 1):
                        w = t[i:i + size]
                        if w != tok and _osa(w, tok, 1) == 1:
                            hits[b["name"]] = {"brand": b["name"], "token": tok, "how": "typo", "seen": w}
                            break
                    if b["name"] in hits:
                        break
                if b["name"] in hits:
                    break
    return list(hits.values())


def _find(sev: str, title: str, detail: str, w: int = 0, tag: str | None = None) -> dict:
    return {"severity": sev, "title": title, "detail": detail, "w": w, "tag": tag}


def _b64_emails(s: str) -> list[str]:
    out = []
    for tok in re.findall(r"[A-Za-z0-9+/_-]{12,}={0,2}", s):
        t = tok.rstrip("=")
        try:
            dec = base64.urlsafe_b64decode(t.replace("+", "-").replace("/", "_") + "=" * (-len(t) % 4)).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        m = re.fullmatch(r"\s*([\w.+'-]+@[\w-]+(\.[\w-]+)+)\s*", dec)
        if m:
            out.append(m.group(1))
    return list(dict.fromkeys(out))


def static_analysis(url: str) -> dict:
    out: dict = {"url": url, "defanged": defang(url), "scheme": None, "host": None, "host_unicode": None, "domain": None,
                 "ip": None, "port": None, "path": None, "query_length": 0, "brand": None, "user_content": None,
                 "sharepoint_tenant": None, "shortener": False, "findings": [], "embedded_urls": []}
    F = out["findings"]
    m = re.match(r"^([a-z][a-z0-9+.-]*):", url, re.I)
    scheme = (m.group(1).lower() if m else "")
    out["scheme"] = scheme
    if scheme in ("javascript", "vbscript", "data"):
        F.append(_find("critical", f"This is a {scheme}: link, not a web address",
                       f"{scheme}: links run code or embed a whole page inside the link itself. Legitimate emails never need them; "
                       "they're used to smuggle phishing pages past link scanners.", 80, f"using a {scheme}: link that carries its own content"))
        return out
    if scheme not in ("http", "https", "ftp"):
        F.append(_find("warning", f"Unusual link type ({scheme or 'none'}:)", "Only http/https links can be analysed.", 20))
        return out
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        F.append(_find("warning", "The link is malformed", "Browsers may interpret it differently from scanners, a trick used to evade filtering.", 25))
        return out
    raw_host = (p.hostname or "").strip(".")
    out["port"] = port
    out["path"] = p.path
    out["query_length"] = len(p.query)
    if not raw_host:
        F.append(_find("warning", "The link has no host name", "", 20))
        return out

    # --- user-info trick: https://microsoft.com@evil.example/
    if "@" in p.netloc:
        fake = p.netloc.rsplit("@", 1)[0]
        F.append(_find("critical", f"Text before '@' hides the real destination: it goes to {raw_host}, not {fake}",
                       f"Everything before @ in a web address is a user name and is ignored for navigation. Writing '{fake}@' "
                       "makes the link look like it goes somewhere it doesn't.", 70, f"disguised as {fake}"))

    # --- IP hosts (plain or obfuscated)
    ip = _decode_ip_host(raw_host)
    if ip:
        out["ip"] = ip
        out["host"] = ip
        out["domain"] = ip
        pub, why = _public_ip(ip)
        if not is_ip(raw_host):
            F.append(_find("critical", f"The host is an IP address written in disguise ({raw_host} = {ip})",
                           "Encoding an IP as a number or hex hides where the link goes. There's no legitimate reason for this in email.", 70,
                           "using a disguised IP address"))
        elif not pub:
            F.append(_find("warning", f"Links to a non-public address ({ip}: {why})",
                           "A link in an email to an internal address is unusual. It may target devices on the recipient's network.", 30))
        else:
            F.append(_find("warning", f"Links to a bare IP address ({ip}) instead of a name",
                           "Legitimate services almost always use a domain name. Bare IPs are common for throwaway phishing and malware servers.", 35))
        out["host_unicode"] = ip
    else:
        try:
            host = raw_host.encode("idna").decode("ascii").lower() if not raw_host.isascii() else raw_host.lower()
        except UnicodeError:
            host = raw_host.lower()
        out["host"] = host
        out["domain"] = registered_domain(host)
        labels = host.split(".")
        uni_labels = []
        for lab in labels:
            if lab.startswith("xn--"):
                try:
                    uni_labels.append(lab.encode("ascii").decode("idna"))
                except UnicodeError:
                    uni_labels.append(lab)
            else:
                uni_labels.append(lab)
        host_u = ".".join(uni_labels)
        out["host_unicode"] = host_u
        domain = out["domain"]
        dom_label = domain.split(".")[0]

        # --- punycode / homoglyphs
        idn_brand = None
        if host_u != host:
            scripts = {s for s in (_script_of(c) for c in host_u if not c.isascii()) if s}
            if any(c.isascii() and c.isalpha() for c in host_u):
                scripts.add("LATIN")
            skel = _skeleton(host_u)
            mixed = "LATIN" in scripts and scripts & _STRONG_SCRIPTS or len(scripts & _STRONG_SCRIPTS) > 1
            all_mapped = skel.isascii() and skel != host_u
            brand_skel = _brand_hits(skel)
            if all_mapped:
                sev = "critical"
                idn_brand = brand_skel[0]["brand"] if brand_skel else None
                alpha = ", ".join(sorted(s.title() for s in scripts if s != "LATIN"))
                F.append(_find(sev, f"Look-alike letters: {host} displays as '{host_u}', which looks like '{skel}'",
                               f"The name uses {', '.join(sorted(s.title() for s in scripts if s != 'LATIN'))} characters that look identical to Latin letters "
                               f"(an IDN homoglyph attack). In a browser it may read as {skel}." +
                               (f" That imitates {brand_skel[0]['brand']}." if brand_skel else ""), 80,
                               f"which displays as '{host_u}', imitating {skel} with look-alike {alpha} letters"))
            elif mixed:
                F.append(_find("critical", f"Mixed alphabets in the name: '{host_u}' ({host})",
                               "Mixing Latin with Cyrillic/Greek letters in one name is a classic homoglyph trick to imitate a real domain.", 70,
                               "mixing alphabets to imitate another name"))
            else:
                F.append(_find("info", f"Internationalised domain name: '{host_u}' ({host})",
                               f"Uses {', '.join(sorted(s.title() for s in scripts))} characters. Normal for non-English sites; suspicious if the sender is English-speaking.", 5))

        # --- brand impersonation
        owner = _BRAND_BY_DOMAIN.get(domain)
        if owner:
            out["brand"] = owner
        else:
            sub = host[: -len(domain)].rstrip(".") if host != domain else ""
            reg_hits = [] if idn_brand else _brand_hits(_skeleton(".".join(uni_labels[-len(domain.split(".")):])) if host_u != host else dom_label)
            exact_label_brand = None
            for h in reg_hits:
                b = next(x for x in BRANDS if x["name"] == h["brand"])
                if dom_label in b["tokens"] and h["how"] == "exact":
                    exact_label_brand = h["brand"]
            if exact_label_brand:
                F.append(_find("info", f"{domain} uses {exact_label_brand}'s exact name on a different ending",
                               f"Possibly {exact_label_brand}'s own regional domain, but it isn't in the list of domains known to belong to them. "
                               "Check the registration date and owner below.", 15))
            else:
                for h in reg_hits:
                    if h["how"] == "exact":
                        F.append(_find("warning", f"Uses the {h['brand']} name, but {domain} isn't one of their domains",
                                       f"Attackers register domains like {h['token']}-login or secure-{h['token']} to look official. "
                                       f"{h['brand']} uses its own domains (e.g. {next(x for x in BRANDS if x['name'] == h['brand'])['domains'][0]}).", 45,
                                       f"imitating {h['brand']}"))
                    else:
                        seen = h.get("seen") or dom_label
                        F.append(_find("critical", f"{domain} imitates {h['brand']} with a misspelling ('{seen}' vs '{h['token']}')",
                                       "Swapped, missing or look-alike characters (0 for o, rn for m, 1 for l) are how typosquatting domains fool readers.", 70,
                                       f"imitating {h['brand']}"))
            if sub:
                full_brand_domain = next((d for d in sorted(_BRAND_BY_DOMAIN, key=len, reverse=True)
                                          if re.search(rf"(^|\.){re.escape(d)}(\.|$)", sub)), None)
                if full_brand_domain:
                    full_brand_domain = sub[: sub.index(full_brand_domain) + len(full_brand_domain)]
                    F.append(_find("critical", f"Starts with '{full_brand_domain}' but the real domain is {domain}",
                                   f"The host is {host}. Only the last part ({domain}) decides who owns the site; '{full_brand_domain}' "
                                   "at the front is decoration to fool the reader.", 75, f"disguised as {full_brand_domain}"))
                else:
                    for h in _brand_hits(sub):
                        if not any(f["tag"] == f"imitating {h['brand']}" for f in F):
                            F.append(_find("warning", f"'{h['brand']}' appears in the subdomain, but the site is {domain}",
                                           f"Anyone who owns {domain} can create {sub}.{domain}. A brand name there proves nothing.", 40,
                                           f"imitating {h['brand']}"))
            # path / query mentions (weak)
            path_hits = [h for h in _brand_hits(unquote(p.path or "")) if h["how"] == "exact"]
            for h in path_hits[:1]:
                if not any((f["tag"] or "").endswith(h["brand"]) for f in F):
                    F.append(_find("info", f"Mentions {h['brand']} in the path, but the site is {domain}",
                                   f"Common in phishing kits (/{h['token']}/login.php), also in harmless links. Weak signal on its own.", 10))

        # --- subdomain depth
        sub_labels = len(labels) - len(domain.split("."))
        if sub_labels >= 4:
            F.append(_find("warning", f"Unusually deep host name ({sub_labels} levels before {domain})",
                           "Long chains of subdomains push the real domain out of view on phones.", 20))

        # --- user-content / free hosting
        uc = next(((suf, name) for suf, name in USER_CONTENT_HOSTS if host == suf or host.endswith("." + suf)), None)
        if uc:
            out["user_content"] = uc[1]
            if uc[0] == "sharepoint.com":
                tenant = re.sub(r"-my$", "", labels[0]) if sub_labels >= 1 else None
                out["sharepoint_tenant"] = tenant
                F.append(_find("info", f"File shared from the '{tenant}' Microsoft 365 tenant" if tenant else "SharePoint / OneDrive link",
                               "SharePoint is a legitimate Microsoft service, but attackers share lure documents from compromised or trial tenants. "
                               "Check that the tenant name matches the organisation the email claims to come from.", 5))
            else:
                F.append(_find("info", f"Hosted on {uc[1]} ({uc[0]})",
                               f"{uc[1]} is a legitimate service, but anyone can publish content there and it is often used for phishing pages, forms or "
                               "lure files. Judge it by who created the content, not by the domain.", 10, None))

        # --- shorteners
        if domain in SHORTENERS or host in SHORTENERS:
            out["shortener"] = True
            F.append(_find("info", f"URL shortener ({host}): the destination is hidden",
                           "Turn on Follow redirects to see where it leads (it contacts the shortener, not the final site, until the hops are checked).", 15,
                           "behind a URL shortener"))

        # --- TLD
        tld = labels[-1]
        if tld in ("zip", "mov"):
            F.append(_find("warning", f"The .{tld} ending can be mistaken for a file name",
                           f"'{host}' reads like a downloaded file. These endings are used to make links look like attachments.", 25))
        elif tld in SUSPICIOUS_TLDS:
            F.append(_find("info", f".{tld} is frequently used for abuse",
                           "Abuse reports rank this ending high for phishing. Plenty of legitimate sites use it too; weak signal on its own.", 10))

    # --- scheme / port
    if scheme == "http":
        F.append(_find("info", "Not encrypted (http://)", "Sign-in pages should always use https.", 3))
    if port and port not in (80, 443):
        F.append(_find("info", f"Uses a non-standard port ({port})", "Unusual for public websites; common for ad-hoc servers.", 8))

    # --- path: file type
    ext = (p.path or "").rsplit(".", 1)[-1].lower() if "." in (p.path or "").rsplit("/", 1)[-1] else ""
    if ext in RISKY_EXT:
        sev = "info" if ext in ("html", "htm", "shtml") else "warning"
        F.append(_find(sev, f"Downloads or opens {RISKY_EXT[ext]} (.{ext})",
                       "Links that deliver programs, scripts, disk images or archives are a common malware route." if sev == "warning" else
                       "Static .html pages on file hosts are often stand-alone phishing pages.", 25 if sev == "warning" else 5,
                       f"delivering {RISKY_EXT[ext]}" if sev == "warning" else None))

    # --- victim tracking: email addresses in the query/fragment
    tail = unquote(p.query or "") + " " + unquote(p.fragment or "")
    plain = list(dict.fromkeys(re.findall(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}", tail, re.I)))
    b64 = [e for e in _b64_emails((p.query or "") + " " + (p.fragment or "")) if e not in plain]
    if b64:
        F.append(_find("warning", f"Contains the recipient's email address, base64-encoded ({', '.join(b64[:3])})",
                       "Phishing kits embed the victim's address so the fake sign-in page is pre-filled and the attacker can track who clicked.", 40,
                       "personalised with the recipient's encoded email address"))
    elif plain:
        F.append(_find("info", f"Contains an email address ({', '.join(plain[:3])})",
                       "Normal for unsubscribe and marketing links. On a sign-in page it means the link was personalised for the recipient.", 8))
    if len(p.query or "") > 400:
        F.append(_find("info", f"Very long query string ({len(p.query)} characters)", "Often tracking data; sometimes used to hide the real parameters.", 3))

    # --- embedded URLs (possible open redirects)
    for k, v in parse_qsl(p.query or "", keep_blank_values=True):
        if re.match(r"https?://", v, re.I) and v != url:
            out["embedded_urls"].append({"param": k, "url": v, "defanged": defang(v)})
    if out["embedded_urls"]:
        e = out["embedded_urls"][0]
        F.append(_find("info", f"Carries another address in parameter '{e['param']}': {e['defanged']}",
                       "This is often a redirect. Attackers abuse redirects on trusted sites so the first domain looks safe. Analyse that address too.", 10))
    return out


# ===================================================================== enrichment
def _tls_info(host: str, ip: str, port: int = 443, timeout: float = 5.0) -> dict:
    """TLS handshake only (no HTTP request): who issued the certificate and when."""
    out: dict = {"connected": False, "error": None, "verified": None, "verify_error": None, "cert": None}
    for verify in (True, False):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    der = s.getpeercert(binary_form=True)
            out["connected"] = True
            out["verified"] = verify
            if der:
                c = _cert_info(der, host)
                issuer_o = re.search(r"(?:^|,)O=([^,]+)", c["issuer"])
                issuer_cn = re.search(r"(?:^|,)CN=([^,]+)", c["issuer"])
                c["issuer_name"] = (issuer_o or issuer_cn).group(1) if (issuer_o or issuer_cn) else c["issuer"]
                nb = _parse_dt(c["not_before"])
                c["age_days"] = (_now() - nb).days if nb else None
                out["cert"] = c
            return out
        except ssl.SSLCertVerificationError as exc:
            out["verify_error"] = exc.verify_message or str(exc)
            continue
        except (OSError, ssl.SSLError, ValueError) as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"[:200]
            return out
    return out


def enrich(domain: str, host: str, scheme: str, port: int | None) -> dict:
    """RDAP age, DNS A/MX, hosting owner and TLS certificate for a host. No HTTP requests."""
    res = make_resolver(timeout=3.0, lifetime=5.0)
    out: dict = {"domain": domain, "host": host, "rdap": None, "a": [], "mx": [], "dns_status": None, "hosting": None, "tls": None}

    def dns_part():
        a, meta = resolve(res, host, "A")
        out["dns_status"] = meta["status"]
        out["a"] = [r.address for r in a][:8]
        if not out["a"]:
            aaaa, m6 = resolve(res, host, "AAAA")
            out["a"] = [r.address for r in aaaa][:8]
            if out["a"]:
                out["dns_status"] = "ok"
        mx, _ = resolve(res, domain, "MX")
        out["mx"] = [f"{r.preference} {r.exchange.to_text(omit_final_dot=True)}" for r in sorted(mx, key=lambda r: r.preference)][:6]

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_rdap = pool.submit(domain_rdap, domain)
        f_dns = pool.submit(dns_part)
        f_dns.result()
        pub_ip = next((ip for ip in out["a"] if _public_ip(ip)[0]), None)
        f_host = pool.submit(ip_lookup, pub_ip) if pub_ip else None
        f_tls = pool.submit(_tls_info, host, pub_ip, port or 443) if pub_ip and scheme == "https" else None
        out["rdap"] = f_rdap.result()
        if f_host:
            try:
                h = f_host.result()
                asn = h.get("asn") or {}
                out["hosting"] = {"ip": pub_ip, "owner": h.get("owner"), "asn": asn.get("asn"), "as_name": asn.get("name"),
                                  "country": (h.get("rdap") or {}).get("country") or asn.get("country"),
                                  "ptr": ((h.get("rdns") or {}).get("ptr") or [None])[0]}
            except Exception as exc:  # noqa: BLE001 - enrichment must never break the result
                out["hosting"] = {"ip": pub_ip, "error": str(exc)}
        out["tls"] = f_tls.result() if f_tls else None
    if out["a"] and not pub_ip:
        out["internal_only"] = True
    return out


def _ip_enrich(ip: str) -> dict:
    out: dict = {"domain": ip, "host": ip, "rdap": None, "a": [ip], "mx": [], "dns_status": "ok", "hosting": None, "tls": None}
    if not _public_ip(ip)[0]:
        return out
    try:
        h = ip_lookup(ip)
        asn = h.get("asn") or {}
        out["hosting"] = {"ip": ip, "owner": h.get("owner"), "asn": asn.get("asn"), "as_name": asn.get("name"),
                          "country": (h.get("rdap") or {}).get("country") or asn.get("country"), "ptr": ((h.get("rdns") or {}).get("ptr") or [None])[0]}
    except Exception as exc:  # noqa: BLE001
        out["hosting"] = {"ip": ip, "error": str(exc)}
    return out


def _enrichment_findings(st: dict, en: dict) -> list[dict]:
    F: list[dict] = []
    if not en or st.get("ip"):
        return F
    rd = en.get("rdap") or {}
    domain = st["domain"]
    age = rd.get("age_days")
    if age is not None:
        created = (rd.get("created") or "")[:10]
        if age < 30:
            F.append(_find("critical", f"{domain} was {_registered_phrase(age, created)} ({created})",
                           "Brand-new domains are the strongest single phishing signal: attackers register them days before a campaign.", 60,
                           None))
        elif age < 90:
            F.append(_find("warning", f"{domain} is only {age} days old (registered {created})",
                           "Recently registered domains are disproportionately used for phishing.", 30))
        elif age < 365:
            F.append(_find("info", f"{domain} was registered under a year ago ({created})", "Young domains deserve extra caution.", 10))
    status = en.get("dns_status")
    if status == "nxdomain" and st.get("brand"):
        F.append(_find("info", f"{st['host']} doesn't exist",
                       f"{domain} belongs to {st['brand']}, but this particular host name (e.g. a tenant or site) doesn't exist, so the link can't load.", 0))
    elif status == "nxdomain":
        F.append(_find("warning", f"{st['host']} doesn't exist in DNS (anymore)",
                       "The domain may already have been taken down, or it was never registered. The link can't load, but the email was still a lure if "
                       "other signals point that way.", 15))
    elif en.get("internal_only"):
        F.append(_find("warning", f"{st['host']} resolves only to internal addresses ({', '.join(en['a'][:3])})",
                       "Public sites don't do this. It may target devices on the recipient's network.", 25))
    if rd.get("status") and any("hold" in s.lower() for s in rd["status"]):
        F.append(_find("warning", f"The registry has suspended {domain} ({', '.join(s for s in rd['status'] if 'hold' in s.lower())})",
                       "Registries put domains on hold after abuse reports, so it was probably reported as malicious.", 30))
    tls = en.get("tls") or {}
    cert = tls.get("cert") or {}
    if tls.get("connected") and tls.get("verified") is False:
        F.append(_find("warning", f"The certificate isn't trusted ({tls.get('verify_error') or 'verification failed'})",
                       "Browsers show a warning; legitimate business sites almost never have invalid certificates.", 20))
    if cert.get("age_days") is not None and cert["age_days"] < 3 and (age is None or age < 365):
        F.append(_find("info", f"Certificate issued {cert['age_days']} day(s) ago by {cert.get('issuer_name')}",
                       "Fresh certificates are normal (they renew every few months) but fit a newly set-up phishing site.", 5))
    return F


# ===================================================================== follow redirects
def _defensive_registration(en: dict | None) -> dict | None:
    """Signs that a domain is a brand owner's defensive registration: brand-protection registrar and/or
    NS/MX on brand-protection infrastructure, registered over a year ago. Same signals the Lookalike tool uses."""
    if not en:
        return None
    rd = en.get("rdap") or {}
    reg_l = (rd.get("registrar") or "").lower()
    by_registrar = next((b for b in BRAND_PROTECTION_REGISTRARS if b in reg_l), None)
    hosts = [m.split()[-1].lower() for m in en.get("mx") or []] + [n.lower() for n in rd.get("nameservers") or []]
    infra = next((suf for h in hosts for suf in BRAND_PROTECTION_INFRA if h == suf or h.endswith("." + suf)), None)
    age = rd.get("age_days")
    if not (by_registrar or infra):
        return None
    if age is None and not (by_registrar and infra):
        return None
    if age is not None and age < 365:
        return None
    return {"company": _BP_NAMES.get(by_registrar or infra, rd.get("registrar") or infra), "by_registrar": bool(by_registrar),
            "infra": bool(infra), "year": (rd.get("created") or "")[:4] or None, "registrar": rd.get("registrar")}


_STRONG_TAGS = ("personalised with the recipient's encoded email address", "hosting a page with a password box")


def _apply_defensive(item: dict) -> None:
    """Downgrade a brand-typo finding when the domain is evidently the brand's own defensive registration
    and nothing else about the link is strongly suspicious."""
    F = item["findings"]
    typo = next((f for f in F if (f.get("tag") or "").startswith("imitating ") and f["severity"] == "critical"
                 and " with a misspelling " in f["title"]), None)
    if not typo:
        return
    dfn = _defensive_registration(item.get("enrichment"))
    if not dfn:
        return
    others = [f for f in F if f is not typo]
    if any(f["severity"] == "critical" or f.get("tag") in _STRONG_TAGS for f in others):
        return
    brand = typo["tag"][len("imitating "):]
    how = []
    if dfn["by_registrar"]:
        how.append(f"registrar {dfn['registrar']}")
    if dfn["infra"]:
        how.append(f"name/mail servers on {dfn['company']}'s parking infrastructure")
    typo.update(severity="warning", w=20, tag=None,
                title=f"{typo['title'].split(' imitates ')[0]} is a typo of {brand}, but it was registered defensively by a brand-protection company ({dfn['company']})",
                detail=f"Brand owners pay companies like {dfn['company']} to register misspellings of their name so attackers can't. Evidence: "
                       f"{' and '.join(how)}" + (f", registered since {dfn['year']}" if dfn["year"] else "") +
                       f". Probably {brand}'s own. Still check where the link redirects and who sent the email.")
    item["defensive"] = {**dfn, "brand": brand}


def _check_target(url: str, res) -> tuple[str | None, str | None]:
    """Return (ip to connect to, None) or (None, refusal reason). Applied at EVERY hop."""
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return None, "malformed URL"
    if p.scheme not in ("http", "https"):
        return None, f"not an http(s) URL ({p.scheme}:)"
    host = (p.hostname or "").strip(".")
    if not host:
        return None, "no host"
    if port and port not in (80, 443) and port < 1024:
        return None, f"port {port} is not a web port"
    ip = _decode_ip_host(host)
    ips = [ip] if ip else []
    if not ip:
        try:
            ascii_host = host.encode("idna").decode("ascii") if not host.isascii() else host
        except UnicodeError:
            return None, "invalid host name"
        if ascii_host.lower() in ("localhost",) or ascii_host.lower().endswith((".localhost", ".local", ".internal", ".lan")):
            return None, f"{host} is an internal name"
        ips = addresses(res, ascii_host)
        if not ips:
            return None, f"{host} does not resolve"
    for a in ips:
        ok, why = _public_ip(a)
        if not ok:
            if a == host or ip:
                return None, f"{host} is a {why} address; refused for safety"
            return None, f"{host} resolves to {a} ({why}); refused for safety"
    v4 = [a for a in ips if ":" not in a]
    return (v4 or ips)[0], None


def _fetch(method: str, url: str, ip: str) -> dict:
    """One request to a pre-validated IP (DNS pinned, so a rebinding answer can't redirect us internally)."""
    p = urlsplit(url)
    host = p.hostname or ""
    try:
        ascii_host = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        ascii_host = host
    ip_netloc = f"[{ip}]" if ":" in ip else ip
    default_port = 443 if p.scheme == "https" else 80
    if p.port and p.port != default_port:
        ip_netloc += f":{p.port}"
    target = urlunsplit((p.scheme, ip_netloc, p.path or "/", p.query, ""))
    headers = {"Host": ascii_host + (f":{p.port}" if p.port and p.port != default_port else ""), "User-Agent": UA,
               "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.8"}
    ext = {"sni_hostname": ascii_host} if p.scheme == "https" and not is_ip(ascii_host) else {}
    out: dict = {"status": None, "location": None, "content_type": None, "server": None, "body": b""}
    # Fresh client per request: no cookie jar carried between hops, no env proxies, no auth.
    with httpx.Client(verify=False, follow_redirects=False, timeout=httpx.Timeout(HTTP_TIMEOUT), trust_env=False) as c:
        with c.stream(method, target, headers=headers, extensions=ext) as r:
            out["status"] = r.status_code
            out["location"] = r.headers.get("location")
            out["content_type"] = r.headers.get("content-type")
            out["server"] = r.headers.get("server")
            if method == "GET" and not (300 <= r.status_code < 400):
                from ..core.outbound import read_capped
                out["body"], _ = read_capped(r, BODY_CAP, time.monotonic() + HTTP_TIMEOUT * 2)
    return out


def _page_signals(body: bytes, content_type: str | None) -> dict:
    """Read the capped body once for a few yes/no signals, then it's discarded."""
    sig: dict = {"title": None, "meta_refresh": None, "password_field": False, "uses_js_redirect": False}
    if not body or (content_type and "html" not in content_type.lower() and "text" not in content_type.lower()):
        return sig
    text = body.decode("utf-8", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        sig["title"] = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:200] or None
    for tag in re.findall(r"<meta\b[^>]*>", text, re.I):
        if re.search(r"http-equiv\s*=\s*[\"']?refresh", tag, re.I):
            c = re.search(r"content\s*=\s*[\"']?\s*\d*\s*;?\s*url\s*=\s*['\"]?([^\"'>\s]+)", tag, re.I)
            if c:
                sig["meta_refresh"] = html.unescape(c.group(1))
                break
    sig["password_field"] = bool(re.search(r"<input\b[^>]*type\s*=\s*[\"']?password", text, re.I))
    sig["uses_js_redirect"] = bool(re.search(r"(window|document|top|self)\.location(\.href)?\s*=|location\.(replace|assign)\s*\(", text))
    return sig


def follow_redirects(url: str, budget: float = 25.0) -> dict:
    res = make_resolver(timeout=3.0, lifetime=5.0)
    deadline = time.monotonic() + budget
    hops: list[dict] = []
    current = url
    final_signals: dict = {}
    stopped = None
    seen: set[str] = set()
    for n in range(1, MAX_HOPS + 2):
        if n > MAX_HOPS:
            stopped = f"Stopped after {MAX_HOPS} hops (redirect limit)."
            break
        if time.monotonic() > deadline:
            stopped = "Stopped: time limit reached."
            break
        hop: dict = {"n": n, "url": current, "defanged": defang(current), "method": None, "status": None, "ip": None,
                     "via": "start" if n == 1 else hops[-1].get("next_kind"), "error": None, "refused": None}
        hops.append(hop)
        ip, refusal = _check_target(current, res)
        if refusal:
            hop["refused"] = refusal
            stopped = f"Refused to connect: {refusal}."
            break
        hop["ip"] = ip
        try:
            r = None
            try:
                r = _fetch("HEAD", current, ip)
                hop["method"] = "HEAD"
            except httpx.HTTPError:
                r = None
            if r is None or not (300 <= (r["status"] or 0) < 400 and r["location"]):
                r = _fetch("GET", current, ip)
                hop["method"] = "GET" if hop["method"] is None else "HEAD → GET"
        except httpx.TimeoutException:
            hop["error"] = "Timed out (8s)"
            stopped = "Stopped: the server didn't answer in time."
            break
        except (httpx.HTTPError, OSError, ValueError) as exc:
            hop["error"] = f"{type(exc).__name__}: {str(exc)[:150]}"
            stopped = "Stopped: connection failed."
            break
        hop["status"] = r["status"]
        hop["server"] = r["server"]
        hop["content_type"] = r["content_type"]
        nxt = None
        if 300 <= r["status"] < 400 and r["location"]:
            nxt = urljoin(current, r["location"].strip())
            hop["next_kind"] = f"HTTP {r['status']}"
        else:
            sig = _page_signals(r["body"], r["content_type"])
            r["body"] = b""
            hop["title"] = sig["title"]
            final_signals = sig
            if sig["meta_refresh"]:
                nxt = urljoin(current, sig["meta_refresh"])
                hop["next_kind"] = "meta refresh"
        if not nxt:
            break
        if not re.match(r"https?://", nxt, re.I):
            hops.append({"n": n + 1, "url": nxt, "defanged": defang(nxt), "refused": "not an http(s) address; not followed", "via": hop.get("next_kind")})
            stopped = "Stopped: the redirect points to a non-web address."
            break
        if nxt in seen:
            stopped = "Stopped: redirect loop."
            break
        seen.add(current)
        current = nxt
    last = next((h for h in reversed(hops) if h.get("status") and not h.get("refused")), None)
    return {"hops": hops, "final_url": hops[-1]["url"] if hops else url, "final_defanged": defang(hops[-1]["url"]) if hops else defang(url),
            "landed": bool(last and last is hops[-1] and not (300 <= (last.get("status") or 0) < 400)),
            "final_status": last.get("status") if last else None, "title": final_signals.get("title"),
            "password_field": final_signals.get("password_field", False), "uses_js_redirect": final_signals.get("uses_js_redirect", False),
            "stopped": stopped}


# ===================================================================== URL verdict
_LEAD = {"critical": "Likely phishing", "warning": "Suspicious", "info": "No obvious red flags", "ok": "Looks legitimate"}
_WRAP_SHORT = {"Microsoft Safe Links": "Safe Link", "Microsoft Safe Links (Teams)": "Teams Safe Link", "Proofpoint URL Defense v1": "Proofpoint link",
               "Proofpoint URL Defense v2": "Proofpoint link", "Proofpoint URL Defense v3": "Proofpoint link", "Barracuda Link Protection": "Barracuda link",
               "Google redirect": "Google redirect", "Google AMP link": "Google AMP link", "Outlook redirector": "Outlook redirect",
               "Trend Micro Time-of-Click": "Trend Micro link", "Cisco Secure Email link": "Cisco link", "Sophos Time-of-Click": "Sophos link"}


def _page_findings(fr: dict, landing: dict) -> list[dict]:
    F: list[dict] = []
    title = fr.get("title")
    brand = landing.get("brand")
    if fr.get("password_field") and not brand:
        F.append(_find("critical" if (landing.get("score", 0) >= 20 or title and _brand_hits(title)) else "warning",
                       f"The landing page asks for a password{f' (title: “{title}”)' if title else ''}",
                       f"A password box on {landing.get('domain')}, a site that isn't a known identity provider, is how credential phishing works. "
                       "If a user typed their password here, treat the account as compromised.", 45, "hosting a page with a password box"))
    if title and not brand:
        th = [h for h in _brand_hits(title) if h["how"] == "exact"]
        if th and re.search(r"sign.?in|log.?in|account|verify|password|secure|document|voicemail|invoice|shared", title, re.I):
            F.append(_find("critical", f"Page titled “{title}” on a non-{th[0]['brand']} domain",
                           f"The page presents itself as {th[0]['brand']} but is hosted on {landing.get('domain')}.", 60,
                           f"hosting a {th[0]['brand']} sign-in lookalike" if re.search(r"sign.?in|log.?in|password|account", title, re.I)
                           else f"hosting a {th[0]['brand']}-branded page"))
    if fr.get("uses_js_redirect"):
        F.append(_find("info", "The page contains a JavaScript redirect that wasn't run",
                       "Scripts are never executed here, so the real destination may be one step further. Phishing kits often redirect with script to dodge scanners.", 5))
    if fr.get("stopped") and "Refused" in fr["stopped"] and len(fr.get("hops") or []) > 1:
        F.append(_find("warning", "A redirect points at an internal or reserved address", fr["stopped"] + " Legitimate public links never do this.", 30))
    return F


def _verdict(item: dict) -> tuple[str, str]:
    F = item["findings"]
    score = sum(f.get("w", 0) for f in F)
    item["score"] = score
    if any(f["severity"] == "critical" for f in F) or score >= 70:
        sev = "critical"
    elif any(f["severity"] == "warning" for f in F) or score >= 30:
        sev = "warning"
    elif item.get("brand") and not (item.get("user_content") and item.get("user_content") != "SharePoint / OneDrive for Business"):
        sev = "ok"
    else:
        sev = "info"
    risky = sev in ("critical", "warning")
    land = item.get("landing") or {}
    tgt = land if land.get("domain") and land.get("domain") != item.get("domain") else item
    dom = tgt.get("domain") or "an unknown host"
    show = defang_domain(dom) if risky else dom
    en = tgt.get("enrichment") or {}
    age = ((en.get("rdap") or {}).get("age_days"))
    created = ((en.get("rdap") or {}).get("created") or "")[:4]

    if item.get("scheme") in ("javascript", "vbscript", "data"):
        return sev, f"{_LEAD[sev]}: this is a {item['scheme']}: link that carries its own code or page instead of pointing to a website."
    dfn = item.get("defensive")
    if dfn and sev == "warning" and tgt is item and not any(
            f["severity"] in ("critical", "warning") and "registered defensively" not in f["title"]
            and "doesn't exist in DNS" not in f["title"] for f in F):
        since = f" since {dfn['year']}" if dfn.get("year") else ""
        by = "a brand-protection registrar" if dfn["by_registrar"] else "a brand-protection company"
        dfn["verdict"] = True
        return sev, (f"Typo of {dfn['brand']}, but registered defensively by {by} ({dfn['company']}){since}; "
                     f"probably {dfn['brand']}'s own ({item.get('domain')}).")
    if (item.get("opaque") or item.get("shortener")) and not land and sev in ("info", "ok"):
        what = f"{item['opaque']['wrapper']} link" if item.get("opaque") else f"{item.get('host')} short link"
        return "info", f"Destination hidden: this is a {what}. Turn on Follow redirects to see where it really goes."
    if item["layers"]:
        names = list(dict.fromkeys(_WRAP_SHORT.get(lay["wrapper"], lay["wrapper"]) for lay in item["layers"] if lay.get("to")))
        lead_in = f"unwrapped {' inside '.join(reversed(names))} leads to " if names else "links to "
    elif item.get("opaque"):
        lead_in = f"{item['opaque']['wrapper']} link leads to "
    else:
        lead_in = "links to "
    if tgt is land and land:
        lead_in += f"{item.get('domain')}, which redirects to " if not item["layers"] else ""
    if tgt.get("ip"):
        dphrase = f"a bare IP address ({tgt['ip']})"
    elif tgt.get("brand") and not risky:
        svc = tgt.get("user_content")
        dphrase = f"{tgt.get('host') if svc else dom} ({svc or tgt['brand']})" if svc and svc != "SharePoint / OneDrive for Business" else f"{dom} ({tgt['brand']})"
    elif age is not None and age < 365:
        dphrase = f"a domain registered today ({show})" if age <= 0 else f"a {age}-day-old domain ({show})"
    elif tgt.get("user_content") and not risky:
        dphrase = f"{tgt.get('host')} ({tgt['user_content']}), where anyone can publish content"
    else:
        dphrase = show
    tags = []
    for f in sorted(F, key=lambda f: -f.get("w", 0)):
        if f.get("tag") and f["tag"] not in tags and f["severity"] in ("critical", "warning"):
            tags.append(f["tag"])
    reason = (" " + " and ".join(tags[:2])) if tags and risky else ""
    reason = reason.replace(" which displays", ", which displays")
    year = f", domain registered {created}" if created and (age is None or age >= 365) and not tgt.get("ip") else ""
    if sev == "info" and tgt.get("user_content"):
        return sev, f"Legitimate service, so check who published it: {lead_in}{dphrase}{year}."
    return sev, f"{_LEAD[sev]}: {lead_in}{dphrase}{reason}{year}."


def _block_entries(item: dict) -> list[str]:
    tgt = item.get("landing") if (item.get("landing") or {}).get("domain") and item["landing"]["domain"] != item.get("domain") else item
    if tgt.get("brand") or tgt.get("user_content") or tgt.get("shortener"):
        # Shared platform: block the exact URL, never the whole service.
        u = re.sub(r"^[a-z]+://", "", tgt.get("url") or item["final"], flags=re.I).split("#")[0]
        if len(u) > 250:
            u = u.split("?")[0][:250]
        return [u]
    d = tgt.get("domain")
    if not d:
        return []
    return [d, f"*.{d}"] if not tgt.get("ip") else [d]


def _url_steps(item: dict, sev: str) -> list[dict]:
    if (item.get("defensive") or {}).get("verdict"):
        dfn = item["defensive"]
        return [{"title": f"Confirm with a registration lookup that {item.get('domain')} is {dfn['brand']}'s",
                 "detail": f"The registrar and DNS point to {dfn['company']}'s brand-protection service. Defensive typo domains usually just park "
                           f"or redirect to the real {dfn['brand']} site. Turn on Follow redirects to confirm where it goes."},
                {"title": "Check the sender, not just the link",
                 "detail": "A typo domain in an email is still unusual. Run the headers through the Header Analyzer to see who really sent it."}]
    if sev not in ("critical", "warning"):
        steps = [{"title": "Still unsure? Turn on Follow redirects",
                  "detail": "That shows where the link really ends up and the page title, without running any of its code."}]
        if item.get("opaque") or item.get("shortener"):
            steps[0]["detail"] = "The destination is hidden behind a wrapper or shortener; following it is the only way to see it."
        steps.append({"title": "Check the sender, not just the link",
                      "detail": "A legitimate link can still arrive in a malicious email (e.g. a real SharePoint file shared from a compromised tenant). Run the headers through the Header Analyzer."})
        return steps
    entries = _block_entries(item)
    ent = ",".join(f'"{e}"' for e in entries)
    key = (entries[0] if entries else "link").split("/")[0]
    name = re.sub(r"[^A-Za-z0-9-]", "-", key)[:40]
    today = _now().strftime("%Y-%m-%d")
    steps = []
    if entries:
        shared = item.get("brand") or item.get("user_content") or item.get("shortener") or (item.get("landing") or {}).get("brand")
        steps.append({"title": "Block the link in the Tenant Allow/Block List",
                      "detail": ("This is a shared service, so block only this exact URL, not the whole domain. " if shared else
                                 "Blocks the domain and all its subdomains for every user (Defender for Office 365 and EOP). ") +
                                "Safe Links then refuses clicks on it, including in messages already delivered.",
                      "commands": ["Connect-ExchangeOnline",
                                   f'New-TenantAllowBlockListItems -ListType Url -Block -Entries {ent} -NoExpiration -Notes "Phishing triage {today}"']})
    steps.append({"title": "Find and remove every copy of the email",
                  "detail": "Defender portal → Email & collaboration → Explorer: filter by URL domain (or sender / subject), select all, Take action → Move to junk / Soft delete. "
                            "Without Explorer (Defender for Office 365 Plan 2), use a compliance search purge (removes up to 10 items per mailbox per run):",
                  "commands": ["Connect-IPPSSession",
                               f'New-ComplianceSearch -Name "Phish-{name}" -ExchangeLocation All -ContentMatchQuery \'"{key}"\'',
                               f'Start-ComplianceSearch -Identity "Phish-{name}"',
                               f'New-ComplianceSearchAction -SearchName "Phish-{name}" -Purge -PurgeType SoftDelete']})
    steps.append({"title": "If anyone clicked and entered their password, treat the account as compromised",
                  "detail": "Reset the password, revoke sessions (stolen session cookies survive a password reset otherwise), review MFA methods for anything new, "
                            "check inbox rules for forwarding/deletion rules, and review the sign-in logs for logins from unfamiliar places.",
                  "commands": ['Revoke-MgUserSignInSession -UserId "user@contoso.com"',
                               'Get-InboxRule -Mailbox "user@contoso.com" | Format-List Name,Enabled,From,SubjectContainsWords,ForwardTo,ForwardAsAttachmentTo,RedirectTo,MoveToFolder,DeleteMessage']})
    steps.append({"title": "Report it to Microsoft",
                  "detail": "Defender portal → Actions & submissions → Submissions (https://security.microsoft.com/reportsubmission) → Emails → Submit as phishing. "
                            "This improves filtering and records the incident."})
    return steps


def _analyze_static_item(original: str) -> dict:
    un = unwrap(original)
    final = un["final"]
    st = static_analysis(final)
    item = {"input": original, "input_defanged": defang(original), "final": final, "final_defanged": defang(final),
            "layers": un["layers"], "opaque": un["opaque"], **{k: st[k] for k in st if k not in ("url", "defanged")}}
    if un["opaque"]:
        item["findings"].insert(0, _find("info", f"{un['opaque']['wrapper']} link: destination hidden", un["opaque"]["note"], 15))
    for lay in un["layers"]:
        if lay.get("error"):
            item["findings"].append(_find("warning", f"{lay['wrapper']} link couldn't be decoded", lay["error"], 10))
    if len([x for x in un["layers"] if x.get("to")]) >= 2:
        item["findings"].append(_find("info", f"Wrapped {len(un['layers'])} times",
                                      "Normal when mail passes through two filters (e.g. Proofpoint then Safe Links). Each layer was decoded offline.", 0))
    return item


def analyze_urls(text: str, follow: bool = False) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("Paste a URL, or an email body / text that contains links.")
    urls = extract_urls(text)
    if not urls:
        raise ValueError("No URL found in the text. Paste a link starting with http(s):// or www., or a defanged one (hxxps://example[.]com).")
    truncated = len(urls) > MAX_URLS
    urls = urls[:MAX_URLS]
    items = [_analyze_static_item(u) for u in urls]

    # Enrichment: one per distinct host, at most 12.
    targets: dict[str, tuple] = {}
    for it in items:
        if it.get("host") and it["scheme"] in ("http", "https") and it["host"] not in targets and len(targets) < 12:
            targets[it["host"]] = (it["domain"], it["host"], it["scheme"], it["port"], it.get("ip"))
    enrichments: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {h: pool.submit(_ip_enrich, t[4]) if t[4] else pool.submit(enrich, t[0], t[1], t[2], t[3]) for h, t in targets.items()}
        fr_futs = {}
        if follow:
            order = sorted(range(len(items)), key=lambda i: -sum(f["w"] for f in items[i]["findings"]))
            for i in order[:5]:
                it = items[i]
                if it["scheme"] in ("http", "https"):
                    start = it["input"] if it.get("opaque") else it["final"]
                    fr_futs[i] = pool.submit(follow_redirects, start)
        for h, f in futs.items():
            try:
                enrichments[h] = f.result()
            except Exception as exc:  # noqa: BLE001
                enrichments[h] = {"error": str(exc)}
        for i, f in fr_futs.items():
            try:
                items[i]["redirects"] = f.result()
            except Exception as exc:  # noqa: BLE001
                items[i]["redirects"] = {"hops": [], "stopped": f"Failed: {exc}"}

    # Landing analysis for followed links that end somewhere else.
    landing_jobs = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        for i, it in enumerate(items):
            fr = it.get("redirects")
            if not fr or not fr.get("hops"):
                continue
            land_url = fr["final_url"]
            if not re.match(r"https?://", land_url, re.I):
                continue
            lst = static_analysis(land_url)
            if lst.get("host") and lst["host"] != it.get("host"):
                it["landing"] = {"url": land_url, "defanged": defang(land_url), **{k: lst[k] for k in lst if k not in ("url", "defanged")}}
                if lst["host"] in enrichments:
                    it["landing"]["enrichment"] = enrichments[lst["host"]]
                elif lst.get("ip"):
                    landing_jobs[i] = pool.submit(_ip_enrich, lst["ip"])
                else:
                    landing_jobs[i] = pool.submit(enrich, lst["domain"], lst["host"], lst["scheme"], lst["port"])
        for i, f in landing_jobs.items():
            try:
                items[i]["landing"]["enrichment"] = f.result()
            except Exception as exc:  # noqa: BLE001
                items[i]["landing"]["enrichment"] = {"error": str(exc)}

    for it in items:
        it["enrichment"] = enrichments.get(it.get("host"))
        it["findings"].extend(_enrichment_findings(it, it["enrichment"]))
        land = it.get("landing")
        if land:
            lf = land["findings"] + _enrichment_findings(land, land.get("enrichment"))
            land["score"] = sum(f["w"] for f in lf)
            for f in lf:
                it["findings"].append({**f, "title": f"After redirects: {f['title']}"})
            if land.get("domain") != it.get("domain"):
                it["findings"].append(_find("info", f"Redirects to a different site: {defang(land['url'])}",
                                            f"The link starts at {it.get('domain')} but lands on {land.get('domain')}. The verdict is based on where it lands.", 5))
        if it.get("redirects"):
            target = land or {"domain": it.get("domain"), "brand": it.get("brand"), "score": sum(f["w"] for f in it["findings"])}
            it["findings"].extend(_page_findings(it["redirects"], target))
        _apply_defensive(it)
        sev, title = _verdict(it)
        it["severity"], it["headline"] = sev, title
        it["steps"] = _url_steps(it, sev)
        for f in it["findings"]:
            f.pop("tag", None)
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    items.sort(key=lambda x: (order[x["severity"]], -x.get("score", 0)))
    counts = {s: sum(1 for x in items if x["severity"] == s) for s in order}
    worst = items[0]
    caveat = "A triage aid based on the link itself" + (" and its redirects" if follow else "") + ", not a guarantee: a clean result can't prove a link is safe."
    if len(items) > 1:
        sub = (f"{len(items)} links found{' (first ' + str(MAX_URLS) + ' analysed)' if truncated else ''}: "
               f"{counts['critical']} likely phishing, {counts['warning']} suspicious, {counts['info'] + counts['ok']} without red flags. " + caveat)
    else:
        sub = caveat
    return {"severity": worst["severity"], "headline": worst["headline"], "subline": sub, "count": len(items), "truncated": truncated,
            "counts": counts, "followed": follow, "items": items}


# ===================================================================== lookalikes
_KB_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
_KB_POS = {c: (r, i) for r, row in enumerate(_KB_ROWS) for i, c in enumerate(row)}


def _kb_neighbors(c: str) -> list[str]:
    if c not in _KB_POS:
        return []
    r, i = _KB_POS[c]
    cand = [(r, i - 1), (r, i + 1), (r - 1, i), (r - 1, i + 1), (r + 1, i - 1), (r + 1, i)]
    return [_KB_ROWS[rr][ii] for rr, ii in cand if 0 <= rr < 3 and 0 <= ii < len(_KB_ROWS[rr])]


_HOMOGLYPHS = [("o", "0"), ("0", "o"), ("l", "1"), ("1", "l"), ("i", "1"), ("i", "l"), ("l", "i"), ("m", "rn"), ("rn", "m"),
               ("w", "vv"), ("vv", "w"), ("d", "cl"), ("cl", "d"), ("m", "nn"), ("nn", "m"), ("e", "3"), ("a", "4"), ("s", "5"),
               ("g", "q"), ("q", "g"), ("u", "v"), ("v", "u")]
_CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}
ADDON_WORDS = ["support", "help", "helpdesk", "it", "login", "secure", "security", "verify", "account", "accounts", "invoice",
               "invoices", "billing", "payment", "payments", "pay", "mail", "email", "portal", "online", "hr", "payroll", "docs",
               "files", "share", "office", "sso", "auth", "admin", "service", "services", "team", "group", "inc", "llc", "corp",
               "us", "usa", "global"]
PREFIX_WORDS = ["my", "secure", "login", "mail", "portal", "support", "hr", "e"]
COMMON_TLDS = ["com", "net", "org", "co", "io", "us", "biz", "info", "cc", "me", "xyz", "online", "top", "app"]
KIND_LABEL = {
    "idn": "IDN homoglyph (foreign look-alike letters)", "homoglyph": "Look-alike characters", "addon": "Brand + extra word",
    "subdomain": "Domain + TLD (subdomain style)", "omission": "Missing letter", "transposition": "Swapped letters",
    "repetition": "Doubled letter", "hyphen": "Extra hyphen", "vowel": "Vowel swap", "tld": "Different TLD", "adjacent": "Neighbouring key",
}
_KIND_WEIGHT = {"idn": 20, "homoglyph": 20, "addon": 15, "subdomain": 12, "omission": 10, "transposition": 10, "repetition": 8,
                "hyphen": 8, "vowel": 6, "tld": 5, "adjacent": 5}
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def generate_lookalikes(domain: str, cap: int = 400) -> tuple[list[dict], int]:
    rd = registered_domain(domain)
    name, _, suffix = rd.partition(".")
    if not name or not suffix:
        raise ValueError("Enter a registered domain such as contoso.com.")
    gen: dict[str, dict] = {}
    order: list[str] = []

    def add(label: str, kind: str, tld: str | None = None, unicode_label: str | None = None):
        t = tld or suffix
        if not label or label == name and t == suffix:
            return
        if not label.startswith("xn--"):
            if not _LABEL_RE.match(label) or label[2:4] == "--":
                return
        d = f"{label}.{t}"
        if d == rd:
            return
        if d in gen:
            if kind not in gen[d]["kinds"]:
                gen[d]["kinds"].append(kind)
            return
        gen[d] = {"domain": d, "kinds": [kind], "unicode": f"{unicode_label}.{t}" if unicode_label else None}
        order.append(d)

    n = name
    # Highest-value kinds first so they survive the cap.
    for i in range(len(n)):
        for a, b in _HOMOGLYPHS:
            if n.startswith(a, i):
                add(n[:i] + b + n[i + len(a):], "homoglyph")
    for i, ch in enumerate(n):
        if ch in _CYR:
            u = n[:i] + _CYR[ch] + n[i + 1:]
            try:
                add(u.encode("idna").decode("ascii"), "idn", unicode_label=u)
            except UnicodeError:
                pass
    if all(ch in _CYR for ch in n):
        u = "".join(_CYR[ch] for ch in n)
        try:
            add(u.encode("idna").decode("ascii"), "idn", unicode_label=u)
        except UnicodeError:
            pass
    for w in ADDON_WORDS:
        add(f"{n}-{w}", "addon")
        add(f"{n}{w}", "addon")
    for w in PREFIX_WORDS:
        add(f"{w}-{n}", "addon")
        add(f"{w}{n}", "addon")
    flat = suffix.replace(".", "-")
    add(f"{n}-{flat}", "subdomain", "com")
    add(f"{n}{suffix.replace('.', '')}", "subdomain", "com")
    if suffix != "com":
        add(f"{n}-{flat}", "subdomain")
    for i in range(len(n)):
        add(n[:i] + n[i + 1:], "omission")
    for i in range(len(n) - 1):
        add(n[:i] + n[i + 1] + n[i] + n[i + 2:], "transposition")
    for i in range(len(n)):
        if n[i].isalnum():
            add(n[:i] + n[i] + n[i:], "repetition")
    for i in range(1, len(n)):
        add(n[:i] + "-" + n[i:], "hyphen")
    tlds = list(COMMON_TLDS)
    parts = suffix.split(".")
    if len(parts) == 2:  # co.uk -> uk, org.uk, ...
        tlds += [parts[1], f"org.{parts[1]}", f"net.{parts[1]}", f"com.{parts[1]}", f"co.{parts[1]}"]
    for t in dict.fromkeys(tlds):
        if t != suffix:
            add(n, "tld", t)
    vowels = "aeiou"
    for i, ch in enumerate(n):
        if ch in vowels:
            for v in vowels:
                if v != ch:
                    add(n[:i] + v + n[i + 1:], "vowel")
    for i, ch in enumerate(n):
        for k in _kb_neighbors(ch):
            add(n[:i] + k + n[i + 1:], "adjacent")
    total = len(order)
    return [gen[d] for d in order[:cap]], total


def _ns_set(res, d: str) -> tuple[bool | None, list[str], str]:
    rdata, meta = resolve(res, d, "NS")
    if rdata:
        return True, sorted(r.target.to_text(omit_final_dot=True).lower() for r in rdata), meta["status"]
    if meta["status"] == "nxdomain":
        return False, [], "nxdomain"
    a, m2 = resolve(res, d, "A")
    if a:
        return True, [], "ok"
    if m2["status"] == "nxdomain" or meta["status"] == "noanswer" and m2["status"] == "noanswer":
        return False, [], m2["status"]
    return None, [], meta["status"]


def _parallel(fn, items: list, workers: int, deadline: float) -> list:
    """Run fn over items; results aligned with items (None = timed out or failed)."""
    if not items:
        return []
    pool = ThreadPoolExecutor(max_workers=workers)
    futs = [pool.submit(fn, it) for it in items]
    wait(futs, timeout=max(0.1, deadline - time.monotonic()))
    out = []
    for f in futs:
        try:
            out.append(f.result() if f.done() else None)
        except Exception:  # noqa: BLE001
            out.append(None)
    pool.shutdown(wait=False, cancel_futures=True)
    return out


def _registrable_details(res, d: str) -> dict:
    mx, mmeta = resolve(res, d, "MX")
    mxs = sorted(((r.preference, r.exchange.to_text(omit_final_dot=True).lower()) for r in mx))
    a, _ = resolve(res, d, "A")
    valid = [h for _, h in mxs if "." in h.strip(".") and h != "localhost" and not h.startswith("localhost.")]
    return {"mx": valid, "null_mx": bool(mxs) and not valid, "a": [r.address for r in a][:4]}


def check_lookalikes(domain: str) -> dict:
    t0 = time.monotonic()
    deadline = t0 + 27.0
    d = normalize_domain(domain)
    rd = registered_domain(d)
    candidates, generated = generate_lookalikes(rd)
    res = make_resolver(timeout=2.0, lifetime=4.0)
    client_name = rd.split(".")[0]

    # Client baseline (for "this one is probably yours").
    pool0 = ThreadPoolExecutor(max_workers=3)
    f_cns = pool0.submit(_ns_set, res, rd)
    f_cdet = pool0.submit(_registrable_details, res, rd)
    f_crdap = pool0.submit(domain_rdap, rd)

    # Phase 1: which are registered (NS, then A).
    reg = _parallel(lambda c: _ns_set(res, c["domain"]), candidates, 64, t0 + 16.0)
    for c, r in zip(candidates, reg):
        if isinstance(r, tuple):
            c["registered"], c["ns"], c["dns_status"] = r
        else:
            c["registered"], c["ns"], c["dns_status"] = None, [], "timeout"
    _, client_ns, _ = f_cns.result()
    client = f_cdet.result()
    client_ns_set = set(client_ns)
    registered = [c for c in candidates if c["registered"]]

    # Phase 2: MX + A for registered ones, then ASN for distinct IPs.
    det = _parallel(lambda c: _registrable_details(res, c["domain"]), registered, 32, min(deadline - 8, time.monotonic() + 8))
    for c, r in zip(registered, det):
        c.update(r if isinstance(r, dict) else {"mx": [], "null_mx": False, "a": []})
    ips = list(dict.fromkeys(c["a"][0] for c in registered if c.get("a")))[:60]
    asn = dict(zip(ips, _parallel(lambda ip: asn_lookup(res, ip), ips, 32, min(deadline - 6, time.monotonic() + 5))))

    client_a = set(client.get("a") or [])
    try:
        early_rdap = f_crdap.result(timeout=max(0.1, min(4.0, deadline - time.monotonic())))
    except Exception:  # noqa: BLE001
        early_rdap = {}
    client_bp = any(b in (early_rdap.get("registrar") or "").lower() for b in BRAND_PROTECTION_REGISTRARS) or any(
        h.endswith(BRAND_PROTECTION_INFRA) for h in client_ns)
    client_mx = set(client.get("mx") or [])
    for c in registered:
        ip = c["a"][0] if c.get("a") else None
        a_info = asn.get(ip) if ip else None
        c["hosting"] = ({"ip": ip, "asn": a_info.get("asn"), "as_name": a_info.get("name")} if isinstance(a_info, dict)
                        else {"ip": ip} if ip else None)
        c["has_mx"] = bool(c.get("mx")) and not c.get("null_mx")
        c["parked"] = any(h.endswith(p) for h in c["ns"] + c.get("mx", []) for p in PARKING_NS)
        hints = []
        if any(h.endswith("." + rd) or client_name + "-" in h.split(".")[0] and h.endswith("mail.protection.outlook.com") and h.startswith(client_name)
               for h in c.get("mx", [])):
            hints.append(("probably", f"its mail servers point at {rd}'s own mail setup"))
        if any(ns.endswith("." + rd) for ns in c["ns"]):
            hints.append(("probably", f"its DNS is hosted on {rd}'s own name servers"))
        if c.get("mx") and set(c["mx"]) == client_mx and client_mx and not any(re.search(r"google|outlook\.com|mimecast|pphosted", m) for m in client_mx):
            hints.append(("possibly", f"same mail servers as {rd}"))
        if client_ns_set and set(c["ns"]) == client_ns_set and not any(re.search(r"domaincontrol|registrar-servers|azure-dns|cloudflare|wixdns|googledomains|name-services|awsdns", n) for n in client_ns_set):
            hints.append(("possibly", f"same name servers as {rd}"))
        bp = next((h for h in c.get("mx", []) + c["ns"] if h.endswith(BRAND_PROTECTION_INFRA)), None)
        if bp:
            if client_bp:
                hints.append(("probably", f"parked by the same brand-protection company {rd} uses ({bp})"))
            else:
                hints.append(("possibly", f"parked by a brand-protection company ({bp}); usually the brand owner's defensive registration"))
        if c.get("a") and client_a and set(c["a"]) & client_a:
            hints.append(("possibly", f"same web server IP as {rd}"))
        c["ownership_hints"] = hints
        c["ownership"] = "probably" if any(h[0] == "probably" for h in hints) else "possibly" if hints else None
        score = max(_KIND_WEIGHT[k] for k in c["kinds"])
        if c["has_mx"]:
            score += 50
        if c.get("a"):
            score += 10
        if c["parked"]:
            score -= 15
        if c["ownership"] == "probably":
            score -= 60
        elif c["ownership"] == "possibly":
            score -= 25
        c["score"] = score

    # Phase 3: RDAP for the riskiest ~15 (+ the client itself for registrar comparison).
    top = sorted(registered, key=lambda c: -c["score"])[:15]
    rd_res = _parallel(lambda c: domain_rdap(c["domain"], timeout=7.0), top, 15, min(deadline, time.monotonic() + 9))
    try:
        client_rdap = f_crdap.result(timeout=max(0.1, deadline - time.monotonic()))
    except Exception:  # noqa: BLE001
        client_rdap = {}
    pool0.shutdown(wait=False, cancel_futures=True)
    c_registrar = (client_rdap.get("registrar") or "").lower()
    c_registrant = (client_rdap.get("registrant") or "").lower()
    for c, r in zip(top, rd_res):
        if not isinstance(r, dict):
            continue
        c["rdap"] = {k: r.get(k) for k in ("created", "age_days", "registrar", "registrant", "abuse_emails", "status", "error")}
        age = r.get("age_days")
        if age is not None:
            c["score"] += 50 if age < 30 else 40 if age < 90 else 15 if age < 365 else 0
        reg_l = (r.get("registrar") or "").lower()
        if c_registrant and (r.get("registrant") or "").lower() == c_registrant:
            c["ownership_hints"].append(("probably", f"same registrant as {rd} ({client_rdap.get('registrant')})"))
        elif reg_l and reg_l == c_registrar and any(b in reg_l for b in BRAND_PROTECTION_REGISTRARS):
            c["ownership_hints"].append(("probably", f"registered through the same brand-protection registrar as {rd} ({r.get('registrar')})"))
        if any(h[0] == "probably" for h in c["ownership_hints"]) and c["ownership"] != "probably":
            c["score"] -= 60 if c["ownership"] is None else 35
            c["ownership"] = "probably"

    client_created = _parse_dt(client_rdap.get("created"))
    for c in registered:
        age = (c.get("rdap") or {}).get("age_days")
        created = _parse_dt((c.get("rdap") or {}).get("created"))
        mine = c["ownership"] == "probably"
        # Mail-capable lookalikes are a BEC risk when they're new; an MX on a decades-old domain is usually just another business.
        c["mx_context"] = None
        if c["has_mx"] and not mine:
            if age is not None and age < 365:
                c["mx_context"] = "recent"
            elif created and client_created and created < client_created:
                c["mx_context"] = "older_than_client"
            elif created:
                c["mx_context"] = "established"
            else:
                c["mx_context"] = "unknown_age"
        if mine:
            risk = "low"
        elif c["has_mx"]:
            risk = "high" if c["mx_context"] == "recent" else "medium"
        elif age is not None and age < 90:
            risk = "medium"
        elif c.get("a") and not c["parked"]:
            risk = "medium" if c["score"] >= 25 else "low"
        else:
            risk = "low"
        c["risk"] = risk
        reasons = []
        if age is not None:
            reasons.append(_registered_phrase(age, c["rdap"].get("created")))
        if c["has_mx"]:
            reasons.append("has mail servers (can send and receive email)")
        elif c.get("null_mx"):
            reasons.append("publishes 'no mail' (null MX)")
        if c["parked"]:
            reasons.append("parked / for sale")
        if c["ownership_hints"]:
            reasons.append(("probably yours: " if mine else "possibly yours: ") + c["ownership_hints"][0][1])
        c["reasons"] = reasons
        c["kind_labels"] = [KIND_LABEL[k] for k in c["kinds"]]

    rorder = {"high": 0, "medium": 1, "low": 2}
    registered.sort(key=lambda c: (rorder[c["risk"]], -c["score"]))
    theirs = [c for c in registered if c["ownership"] != "probably"]
    yours = [c for c in registered if c["ownership"] == "probably"]
    with_mx = [c for c in theirs if c["has_mx"]]
    young = [c for c in theirs if (c.get("rdap") or {}).get("age_days") is not None and c["rdap"]["age_days"] < 90]
    unknown = [c for c in candidates if c["registered"] is None]

    def ex(c):
        age = (c.get("rdap") or {}).get("age_days")
        s = c["domain"] + (f" ({c['unicode']})" if c.get("unicode") else "")
        if age is not None and age < 365:
            if age <= 0:
                s += " registered today"
            elif age < 60:
                s += f" registered {age} day{'s' if age != 1 else ''} ago"
            else:
                s += f" registered {age // 30} months ago"
        return s

    if not theirs:
        sev = "ok"
        headline = f"No registered lookalikes of {rd} found among {len(candidates)} likely variants."
        if yours:
            headline = f"No suspicious lookalikes of {rd}: the {len(yours)} registered one{'s' if len(yours) != 1 else ''} appear to be {rd}'s own."
    else:
        n = len(theirs)
        lead = f"{n} lookalike{'s' if n != 1 else ''} of {rd} {'are' if n != 1 else 'is'} registered"
        recent_mx = [c for c in with_mx if c["mx_context"] == "recent"]
        if recent_mx:
            exs = ", ".join(ex(c) for c in recent_mx[:2])
            headline = (f"{lead}; {len(recent_mx)} {'were' if len(recent_mx) != 1 else 'was'} registered in the last year and "
                        f"{'have' if len(recent_mx) != 1 else 'has'} mail servers ({exs}). Treat mail from {'these' if len(recent_mx) != 1 else 'it'} as impersonation.")
        elif with_mx:
            exs = "; ".join(f"{c['domain']} {_registered_phrase((c.get('rdap') or {}).get('age_days'), (c.get('rdap') or {}).get('created'))}"
                            if (c.get("rdap") or {}).get("created") else c["domain"] for c in with_mx[:2])
            dated = all(c["mx_context"] in ("older_than_client", "established") for c in with_mx)
            headline = (f"{lead}; {len(with_mx)} {'have' if len(with_mx) != 1 else 'has'} mail servers ({exs}) but "
                        + ("none is newly registered, so they're probably unrelated businesses. Watch for impersonation."
                           if dated else "none was registered in the last year as far as checked. Probably unrelated businesses; watch for impersonation."))
        else:
            headline = f"{lead}, none with mail servers ({', '.join(ex(c) for c in theirs[:2])}). Watch for them in links."
            sev = "warning" if young else "info"
    sub = (f"Checked {len(candidates)} variants{f' (of {generated} generated)' if generated > len(candidates) else ''}: "
           f"{len(registered)} registered, {len(yours)} look like {rd}'s own defensive registrations"
           f"{f', {len(unknown)} could not be checked' if unknown else ''}. "
           "Not exhaustive, and ownership is inferred from DNS/RDAP: confirm with the client before acting on 'probably yours'.")

    findings = []
    for c in theirs[:8]:
        sev_c = {"high": "critical", "medium": "warning", "low": "info"}[c["risk"]]
        if c["risk"] == "low" and not c["has_mx"]:
            continue
        ctx = c.get("mx_context")
        if ctx == "recent":
            why = "Newly registered with mail servers: it can send convincing invoice/payment-change emails (business email compromise) and receive replies."
        elif ctx == "older_than_client":
            why = f"Similar name, probably an unrelated business: it was registered before {rd} itself. Watch for impersonation."
        elif ctx == "established":
            why = ("Similar name, probably an unrelated business: it has been registered for over a year. Watch for impersonation "
                   "(an old domain can still be bought or compromised).")
        elif ctx == "unknown_age":
            why = ("Has mail servers, so it could send and receive email as a lookalike. Its registration date wasn't checked "
                   "(only the riskiest 15 are looked up): run Domain Registration on it to see if it's new.")
        else:
            why = "No mail servers, but it can host a fake sign-in or invoice page."
        findings.append({"severity": sev_c, "title": f"{c['domain']}{' (' + c['unicode'] + ')' if c.get('unicode') else ''}: "
                                                       f"{', '.join(c['reasons']) or 'registered'}",
                         "detail": f"{' / '.join(c['kind_labels'])}. {why}"})
    low_rest = [c for c in theirs if c["risk"] == "low"]
    if low_rest:
        findings.append({"severity": "info", "title": f"{len(low_rest)} more registered lookalike{'s' if len(low_rest) != 1 else ''} without mail servers",
                         "detail": "Lower risk: parked, for sale or just a web page. They can still turn hostile later, so recheck periodically."})
    if yours:
        findings.append({"severity": "ok", "title": f"{len(yours)} lookalike{'s' if len(yours) != 1 else ''} appear to belong to {rd}",
                         "detail": "Inferred from shared mail servers, name servers or registrant. Good practice (defensive registration), but confirm with the client."})
    if not client_ns and not client.get("a") and not client.get("mx"):
        findings.insert(0, {"severity": "warning", "title": f"{rd} itself doesn't resolve in DNS",
                            "detail": "Check the spelling. The lookalike check still ran, but ownership hints (shared mail/name servers) can't work without the real domain."})
    if unknown:
        findings.append({"severity": "info", "title": f"{len(unknown)} variant{'s' if len(unknown) != 1 else ''} couldn't be checked (DNS timeout)",
                         "detail": "Run the check again; they're listed at the bottom."})
    # The banner must never look calmer (or louder) than the findings under it.
    _rank = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    if findings:
        sev = min((f["severity"] for f in findings), key=lambda s: _rank[s])

    steps = []
    block = [c["domain"] for c in theirs if c["risk"] in ("high", "medium")][:50]
    if block:
        ent = ",".join(f'"{b}"' for b in block)
        steps.append({"title": "Block these domains as senders in the Tenant Allow/Block List",
                      "detail": "Blocks mail from these domains (and their subdomains) for everyone in the tenant. Confirm none is a real partner first.",
                      "commands": ["Connect-ExchangeOnline",
                                   f'New-TenantAllowBlockListItems -ListType Sender -Block -Entries {ent} -NoExpiration -Notes "Lookalikes of {rd}"']})
        steps.append({"title": "Block the same domains as URLs",
                      "detail": "Stops clicks on links to these sites in email and Teams (Safe Links).",
                      "commands": [f'New-TenantAllowBlockListItems -ListType Url -Block -Entries {",".join(chr(34) + b + chr(34) for b in block[:25])} -NoExpiration -Notes "Lookalikes of {rd}"']})
    steps.append({"title": f"Turn on domain impersonation protection for {rd}",
                  "detail": f"Defender for Office 365 anti-phishing (Plan 1 and up, included in Business Premium). If {rd} is an accepted domain in this tenant, "
                            "organisation-domain protection covers it automatically; if it's a partner's domain, add it as a targeted domain instead.",
                  "commands": [f'Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableOrganizationDomainsProtection $true',
                               f'Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableTargetedDomainsProtection $true -TargetedDomainsToProtect @{{Add="{rd}"}} -TargetedDomainProtectionAction Quarantine']})
    warn_list = [c["domain"] for c in theirs][:50]
    if warn_list:
        steps.append({"title": "Add a warning banner to anything that does get through",
                      "detail": "A transport rule that prepends a red caution to mail from the lookalikes (useful while a block is being reviewed).",
                      "commands": [f'New-TransportRule -Name "Lookalike warning: {rd}" -SenderDomainIs {",".join(chr(34) + w + chr(34) for w in warn_list)} '
                                   f'-ApplyHtmlDisclaimerLocation Prepend -ApplyHtmlDisclaimerFallbackAction Wrap '
                                   f'-ApplyHtmlDisclaimerText "<p style=\'color:#b00020;font-weight:bold\'>Caution: this sender\'s domain imitates {rd}. Do not pay, sign in or reply without verifying by phone.</p>"']})
    abuse = [(c["domain"], c["rdap"].get("registrar"), c["rdap"].get("abuse_emails")) for c in theirs if (c.get("rdap") or {}).get("abuse_emails") and c["risk"] in ("high", "medium")]
    if abuse:
        steps.append({"title": "Report active impersonation to the registrar",
                      "detail": "Send the registrar's abuse team the lookalike domain, the domain it imitates, and evidence (phishing email with full headers, screenshots). "
                                "Registrars act fastest on domains with live phishing or BEC activity. " +
                                "; ".join(f"{d}: {r or 'registrar'} <{', '.join(e)}>" for d, r, e in abuse[:6])})
    steps.append({"title": "Recheck regularly", "detail": "New lookalikes are registered all the time. Rerun this check monthly, or right after any BEC attempt."})

    return {"domain": rd, "severity": sev, "headline": headline, "subline": sub, "generated": generated, "checked": len(candidates),
            "registered_count": len(registered), "theirs_count": len(theirs), "mx_count": len(with_mx), "yours_count": len(yours),
            "client": {"ns": client_ns, "mx": client.get("mx"), "a": client.get("a"), "registrar": client_rdap.get("registrar"),
                       "created": client_rdap.get("created")},
            "registered": registered, "unknown": [c["domain"] for c in unknown],
            "not_registered_by_kind": {KIND_LABEL[k]: sum(1 for c in candidates if c["registered"] is False and c["kinds"][0] == k) for k in KIND_LABEL},
            "findings": findings, "steps": steps, "elapsed": round(time.monotonic() - t0, 1)}


# ===================================================================== routes
class SecUrlRequest(BaseModel):
    text: str = Field(..., max_length=500_000)
    follow: bool = False


@router.post("/api/sec/url")
def sec_url_post(body: SecUrlRequest):
    return run(analyze_urls, body.text, body.follow)


@router.get("/api/sec/url")
def sec_url_get(u: str = Query(..., max_length=8000), follow: bool = False):
    return run(analyze_urls, u, follow)


@router.get("/api/sec/lookalike/{domain:path}")
def sec_lookalike(domain: str):
    return run(check_lookalikes, domain)
