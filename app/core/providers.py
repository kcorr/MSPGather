"""Recognise well-known mail platforms from host names.

kind:
  mailbox   - hosts mailboxes (Microsoft 365, Google, ...)
  gateway   - filtering gateway that sits in front of a mailbox platform
  signature - signature / disclaimer service that mail is routed through and back
  sender    - bulk / transactional sending platform
"""
from __future__ import annotations

import re

from .dns_utils import is_ip, registered_domain

_PROVIDERS: list[tuple[str, str, str]] = [
    (r"(^|\.)mail\.protection\.outlook\.com$", "Microsoft 365", "mailbox"),
    (r"(^|\.)mx\.microsoft$", "Microsoft 365", "mailbox"),
    (r"(^|\.)(outlook\.com|office365\.com|exchangelabs\.com|microsoft\.com|onmicrosoft\.com)$", "Microsoft 365", "mailbox"),
    (r"(^|\.)(google\.com|googlemail\.com|gmail\.com)$", "Google", "mailbox"),
    (r"(^|\.)(mimecast\.com|mimecast-offshore\.com|mimecast\.co\.za)$", "Mimecast", "gateway"),
    (r"(^|\.)(pphosted\.com|ppe-hosted\.com|proofpoint\.com)$", "Proofpoint", "gateway"),
    (r"(^|\.)(barracudanetworks\.com|cudasvc\.com|barracuda\.com)$", "Barracuda", "gateway"),
    (r"(^|\.)messagelabs\.com$", "Broadcom/Symantec Email Security", "gateway"),
    (r"(^|\.)iphmx\.com$", "Cisco Secure Email", "gateway"),
    (r"(^|\.)sophos\.com$", "Sophos Email", "gateway"),
    (r"(^|\.)(trendmicro\.com|trendmicro\.eu)$", "Trend Micro Email Security", "gateway"),
    (r"(^|\.)(hornetsecurity\.com|antispameurope\.com)$", "Hornetsecurity", "gateway"),
    (r"(^|\.)(antispamcloud\.com|n-able\.com|spamexperts\.com)$", "N-able Mail Assure / SpamExperts", "gateway"),
    (r"(^|\.)inkyphishfence\.com$", "INKY", "gateway"),
    (r"(^|\.)mailprotector\.net$", "Mailprotector", "gateway"),
    (r"(^|\.)(arsmtp\.com|zixmail\.net|appriver\.com)$", "AppRiver / Zix (OpenText)", "gateway"),
    (r"(^|\.)mailcontrol\.com$", "Forcepoint Email Security", "gateway"),
    (r"(^|\.)fireeyecloud\.com$", "Trellix (FireEye) Email Security", "gateway"),
    (r"(^|\.)vadesecure\.com$", "Vade", "gateway"),
    (r"(^|\.)(mxrecord\.(io|mx)|cf-emailsecurity\.net)$", "Cloudflare Email Security (Area 1)", "gateway"),
    (r"(^|\.)securence\.com$", "Securence", "gateway"),
    (r"(^|\.)mx\.cloudflare\.net$", "Cloudflare Email Routing (forwarding)", "mailbox"),
    (r"(^|\.)privateemail\.com$", "Namecheap Private Email", "mailbox"),
    (r"(^|\.)(messagingengine\.com|fastmail\.com)$", "Fastmail", "mailbox"),
    (r"(^|\.)protonmail\.ch$", "Proton Mail", "mailbox"),
    (r"(^|\.)titan\.email$", "Titan Mail", "mailbox"),
    (r"(^|\.)(kundenserver\.de|ionos\.(com|de|co\.uk))$", "IONOS Mail", "mailbox"),
    (r"(^|\.)mail\.ovh\.net$", "OVH Mail", "mailbox"),
    (r"(^|\.)hostinger\.com$", "Hostinger Mail", "mailbox"),
    (r"(^|\.)hostedemail\.com$", "Tucows / OpenSRS Hosted Email", "mailbox"),
    # Appliances / self-hosted gateways usually live on the customer's own
    # domain, so match the host label instead (spamtitan2.contoso.com).
    (r"(^|[.-])spamtitan\d*([.-]|$)|(^|\.)spamtitan\.com$", "SpamTitan", "gateway"),
    (r"(^|[.-])fortimail\d*([.-]|$)", "FortiMail", "gateway"),
    (r"(^|[.-])barracuda\d*([.-]|$)", "Barracuda (appliance)", "gateway"),
    (r"(^|[.-])(pmg|proxmox-?mail)\d*([.-]|$)", "Proxmox Mail Gateway", "gateway"),
    (r"(^|[.-])(esva|mailscanner|mailgw|mail-gw|smtpgw|smtp-gw|mxgw|mx-gw|mailfilter|spamfilter)\d*([.-]|$)", "Mail gateway (on-premises)", "gateway"),
    (r"(^|\.)(exclaimer\.net|exclaimer\.cloud)$", "Exclaimer", "signature"),
    (r"(^|\.)(codetwo\.online|codetwo\.com)$", "CodeTwo", "signature"),
    (r"(^|\.)(amazonses\.com|amazonaws\.com)$", "Amazon SES / AWS", "sender"),
    (r"(^|\.)sendgrid\.net$", "SendGrid", "sender"),
    (r"(^|\.)(mailgun\.org|mailgun\.net)$", "Mailgun", "sender"),
    (r"(^|\.)(mcsv\.net|mandrillapp\.com|rsgsv\.net)$", "Mailchimp / Mandrill", "sender"),
    (r"(^|\.)(zoho\.com|zoho\.eu|zoho\.in|zohomail\.com)$", "Zoho Mail", "mailbox"),
    (r"(^|\.)secureserver\.net$", "GoDaddy", "mailbox"),
    (r"(^|\.)emailsrvr\.com$", "Rackspace", "mailbox"),
    (r"(^|\.)(yahoodns\.net|yahoo\.com)$", "Yahoo", "mailbox"),
    (r"(^|\.)(icloud\.com|apple\.com)$", "Apple iCloud", "mailbox"),
]
_COMPILED = [(re.compile(p, re.I), name, kind) for p, name, kind in _PROVIDERS]

# SPF include that a domain using this provider normally needs.
PROVIDER_SPF_INCLUDES = {
    "Microsoft 365": ["spf.protection.outlook.com"],
    "Google": ["_spf.google.com"],
}


def provider_for(host: str | None) -> dict | None:
    if not host or is_ip(host):
        return None
    h = host.lower().rstrip(".")
    for rx, name, kind in _COMPILED:
        if rx.search(h):
            return {"name": name, "kind": kind}
    return None


def zone_for(host: str | None) -> str | None:
    """Group a host into an 'organisation' for loop detection: a known provider
    name, otherwise the registered domain."""
    if not host:
        return None
    prov = provider_for(host)
    if prov:
        return prov["name"]
    if is_ip(host):
        return host.strip("[]")
    if "." not in host:
        return f"{host.lower()} (local)"
    return registered_domain(host)
