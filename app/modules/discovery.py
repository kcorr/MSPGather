"""Prospect discovery: everything useful an MSP can learn about an organisation
from its domain name, using public information only (DNS, the public website,
public registration data and Microsoft's public tenant discovery endpoints).

Nothing here scans or logs in to the prospect's systems: host names are only
resolved in DNS, and the website is fetched once like any visitor would."""
from __future__ import annotations

import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter

from ..core.dns_utils import is_private_ip, make_resolver, normalize_domain, registered_domain, resolve, txt
from ..core import workspace
from ..core.http import run
from ..core.providers import provider_for
from .domain import (check_autodiscover, check_bimi, check_dkim, check_dmarc, check_mta_sts, check_mx, check_ns,
                     check_tlsrpt)
from .identity import tenant_lookup
from .ipinfo import asn_lookup
from .netdiag import _NO_CLIENT_LOCK_TLDS, _detect_cdn, _safe_get, domain_registration, http_inspect
from .spf import analyze_spf

router = APIRouter()

# --------------------------------------------------------------------- catalogs
# Host names checked in DNS only (never connected to). (purpose, area)
SUBDOMAINS: dict[str, tuple[str, str]] = {
    "www": ("Website", "web"),
    "mail": ("Mail server / webmail", "mail"), "webmail": ("Webmail", "mail"), "owa": ("Outlook Web App (Exchange)", "mail"),
    "exchange": ("Exchange server", "mail"), "outlook": ("Outlook / webmail", "mail"), "smtp": ("Outbound mail relay", "mail"),
    "relay": ("Mail relay", "mail"), "imap": ("IMAP mail", "mail"), "pop": ("POP mail", "mail"),
    "autodiscover": ("Outlook Autodiscover", "m365"), "lyncdiscover": ("Skype for Business / Teams discovery", "m365"),
    "sip": ("Skype for Business / Teams SIP", "m365"), "meet": ("Online meetings", "m365"), "dialin": ("Dial-in conferencing", "m365"),
    "enterpriseregistration": ("Entra device registration", "m365"), "enterpriseenrollment": ("Intune / MDM enrollment", "m365"),
    "remote": ("Remote access (often RD Web / RD Gateway)", "remote"), "rdweb": ("Remote Desktop Web Access", "remote"),
    "rds": ("Remote Desktop Services", "remote"), "rdgateway": ("RD Gateway", "remote"), "rdg": ("RD Gateway", "remote"),
    "rdp": ("Remote Desktop", "remote"), "gateway": ("Remote access gateway", "remote"), "citrix": ("Citrix", "remote"),
    "storefront": ("Citrix StoreFront", "remote"), "workspace": ("Remote workspace (Citrix / VMware)", "remote"),
    "horizon": ("VMware Horizon", "remote"), "vdi": ("Virtual desktops", "remote"), "desktop": ("Virtual desktop", "remote"),
    "vpn": ("VPN", "vpn"), "sslvpn": ("SSL VPN", "vpn"), "ra": ("Remote access VPN", "vpn"), "anyconnect": ("Cisco AnyConnect VPN", "vpn"),
    "globalprotect": ("Palo Alto GlobalProtect VPN", "vpn"), "fortigate": ("FortiGate firewall", "vpn"), "firewall": ("Firewall", "vpn"),
    "fw": ("Firewall", "vpn"), "access": ("Remote access", "vpn"),
    "sts": ("AD FS (security token service)", "identity"), "adfs": ("AD FS", "identity"), "fs": ("AD FS federation service", "identity"),
    "sso": ("Single sign-on", "identity"), "login": ("Login portal", "identity"), "auth": ("Authentication", "identity"),
    "idp": ("Identity provider", "identity"), "okta": ("Okta", "identity"),
    "portal": ("Portal", "apps"), "intranet": ("Intranet", "apps"), "extranet": ("Extranet", "apps"), "sharepoint": ("SharePoint", "apps"),
    "crm": ("CRM", "apps"), "erp": ("ERP", "apps"), "helpdesk": ("Helpdesk", "apps"), "help": ("Help centre", "apps"),
    "support": ("Support portal", "apps"), "servicedesk": ("Service desk", "apps"), "kb": ("Knowledge base", "apps"),
    "status": ("Status page", "apps"), "shop": ("Online shop", "apps"), "store": ("Online store", "apps"), "jira": ("Jira", "apps"),
    "confluence": ("Confluence", "apps"), "wiki": ("Wiki", "apps"), "git": ("Git server", "apps"), "api": ("API", "apps"),
    "dev": ("Development environment", "apps"), "test": ("Test environment", "apps"), "staging": ("Staging environment", "apps"),
    "ftp": ("FTP file transfer", "files"), "sftp": ("SFTP file transfer", "files"), "files": ("File sharing", "files"),
    "share": ("File sharing", "files"), "cloud": ("Cloud files", "files"), "nas": ("NAS", "files"), "backup": ("Backup", "files"),
    "voip": ("VoIP phone system", "phones"), "pbx": ("Phone system (PBX)", "phones"), "phone": ("Phone system", "phones"),
    "3cx": ("3CX phone system", "phones"),
    "cpanel": ("cPanel hosting panel", "hosting"), "webdisk": ("cPanel Web Disk", "hosting"), "whm": ("WHM hosting panel", "hosting"),
    "plesk": ("Plesk hosting panel", "hosting"), "mdm": ("Device management", "m365"),
}

# CNAME targets → what the host really is. (regex, name, category)
CNAME_SERVICES: list[tuple[str, str, str]] = [
    (r"^autodiscover\.outlook\.com$", "Microsoft 365 Autodiscover", "Microsoft 365"),
    (r"^enterpriseregistration\.windows\.net$", "Entra device registration", "Microsoft 365"),
    (r"^enterpriseenrollment(-s)?\.manage\.microsoft\.com$", "Microsoft Intune enrollment", "Microsoft 365"),
    (r"(^|\.)(webdir|sipdir)\.online\.lync\.com$", "Skype for Business Online / Teams (legacy record)", "Microsoft 365"),
    (r"\.sharepoint\.com$", "SharePoint Online", "Microsoft 365"),
    (r"\.azurewebsites\.net$", "Azure App Service", "Cloud hosting"), (r"\.cloudapp\.(azure\.com|net)$", "Azure virtual machine", "Cloud hosting"),
    (r"\.trafficmanager\.net$", "Azure Traffic Manager", "Cloud hosting"), (r"\.azurefd\.net$|\.azureedge\.net$", "Azure Front Door / CDN", "Cloud hosting"),
    (r"\.blob\.core\.windows\.net$|\.web\.core\.windows\.net$", "Azure Storage static site", "Cloud hosting"),
    (r"\.cloudfront\.net$", "AWS CloudFront", "Cloud hosting"), (r"\.elb\.amazonaws\.com$", "AWS load balancer", "Cloud hosting"),
    (r"\.amazonaws\.com$", "Amazon Web Services", "Cloud hosting"), (r"\.herokuapp\.com$|\.herokudns\.com$", "Heroku", "Cloud hosting"),
    (r"\.github\.io$", "GitHub Pages", "Cloud hosting"), (r"\.netlify\.(app|com)$", "Netlify", "Cloud hosting"),
    (r"\.vercel-dns\.com$|\.vercel\.app$", "Vercel", "Cloud hosting"), (r"\.googlehosted\.com$|^ghs\.google\.com$", "Google Sites / App Engine", "Cloud hosting"),
    (r"\.wpengine\.com$|\.wpenginepowered\.com$", "WP Engine (WordPress hosting)", "Website"), (r"\.myshopify\.com$|^shops\.myshopify\.com$", "Shopify", "Website"),
    (r"\.squarespace\.com$", "Squarespace", "Website"), (r"\.wixdns\.net$", "Wix", "Website"), (r"\.webflow\.(io|com)$", "Webflow", "Website"),
    (r"\.hubspot\.(com|net)$|\.hs-sites\.com$|\.hubspotemail\.net$", "HubSpot", "Marketing / CRM"),
    (r"\.zendesk\.com$", "Zendesk", "Helpdesk"), (r"\.freshdesk\.com$|\.freshservice\.com$", "Freshworks", "Helpdesk"),
    (r"\.service-now\.com$", "ServiceNow", "Helpdesk"), (r"\.statuspage\.io$", "Atlassian Statuspage", "Collaboration"),
    (r"\.atlassian\.net$", "Atlassian (Jira / Confluence)", "Collaboration"),
    (r"\.okta(preview)?\.com$|\.okta-emea\.com$", "Okta", "Identity"), (r"\.onelogin\.com$", "OneLogin", "Identity"),
    (r"\.auth0\.com$", "Auth0", "Identity"), (r"\.duosecurity\.com$", "Duo", "Identity"),
    (r"\.force\.com$|\.salesforce\.com$|\.my\.site\.com$", "Salesforce", "Marketing / CRM"), (r"\.pardot\.com$", "Salesforce Pardot", "Marketing / CRM"),
    (r"\.mktoweb\.com$|\.mktossl\.com$", "Marketo", "Marketing / CRM"), (r"\.unbouncepages\.com$", "Unbounce", "Marketing / CRM"),
    (r"\.secureserver\.net$", "GoDaddy", "Website"), (r"\.citrixcloud\.net$|\.cloud\.com$", "Citrix Cloud", "Remote access"),
    (r"\.quickconnect\.to$|\.synology\.me$", "Synology NAS (QuickConnect)", "Files"), (r"\.3cx\.", "3CX phone system", "Phones"),
    (r"\.ringcentral\.com$", "RingCentral", "Phones"), (r"\.8x8\.com$", "8x8", "Phones"),
    (r"\.jamfcloud\.com$", "Jamf (Apple device management)", "Device management"),
    (r"\.screenconnect\.com$|\.connectwise\.(com|net)$|\.myconnectwise\.net$", "ConnectWise (ScreenConnect / PSA)", "Remote support / RMM"),
    (r"\.kaseya\.(com|net)$", "Kaseya", "Remote support / RMM"), (r"\.n-able\.com$|\.solarwindsmsp\.com$", "N-able", "Remote support / RMM"),
    (r"\.datto\.(com|net)$", "Datto", "Remote support / RMM"), (r"\.ninjarmm\.com$|\.ninjaone\.com$", "NinjaOne", "Remote support / RMM"),
    (r"\.splashtop\.com$", "Splashtop", "Remote support / RMM"), (r"\.beyondtrustcloud\.com$|\.bomgarcloud\.com$", "BeyondTrust remote support", "Remote support / RMM"),
    (r"\.mimecast\.com$", "Mimecast", "Email security"), (r"\.zscaler(two|three)?\.(net|com)$", "Zscaler", "Security"),
    (r"\.cloudflare(-dns)?\.(com|net)$|\.cdn\.cloudflare\.net$", "Cloudflare", "Cloud hosting"),
    (r"\.akamai(edge|technologies)?\.(net|com)$|\.edgekey\.net$|\.edgesuite\.net$", "Akamai", "Cloud hosting"),
    (r"\.fastly(lb)?\.net$", "Fastly", "Cloud hosting"),
]

# TXT verification tokens → service. Only formats we're confident about.
TXT_TOKENS: list[tuple[str, str, str]] = [
    (r"^MS=ms\d+", "Microsoft 365", "Microsoft 365"),
    (r"^google-site-verification=", "Google site verification (Search Console / Workspace)", "Google"),
    (r"^facebook-domain-verification=", "Meta Business (Facebook / Instagram)", "Marketing / CRM"),
    (r"^atlassian-domain-verification=", "Atlassian (Jira / Confluence)", "Collaboration"),
    (r"^docusign=", "DocuSign", "Business apps"),
    (r"^adobe-idp-site-verification=", "Adobe (Creative Cloud / Acrobat SSO)", "Business apps"),
    (r"^adobe-sign-verification=", "Adobe Acrobat Sign", "Business apps"),
    (r"^apple-domain-verification=", "Apple Business Manager", "Device management"),
    (r"^zoom_verify_", "Zoom", "Collaboration"),
    (r"^stripe-verification=", "Stripe", "Business apps"),
    (r"^dropbox-domain-verification=", "Dropbox", "Files"),
    (r"^citrix-verification-code=", "Citrix", "Remote access"),
    (r"^knowbe4-site-verification=", "KnowBe4 (security awareness training)", "Security"),
    (r"^onetrust-domain-verification=", "OneTrust (privacy / cookie consent)", "Security"),
    (r"^smartsheet-site-validation=", "Smartsheet", "Collaboration"),
    (r"^miro-verification=", "Miro", "Collaboration"),
    (r"^webexdomainverification", "Cisco Webex", "Collaboration"),
    (r"^cisco-ci-domain-verification=", "Cisco (Webex / Umbrella)", "Collaboration"),
    (r"^slack-domain-verification=", "Slack", "Collaboration"),
    (r"^teamviewer-sso-verification=", "TeamViewer", "Remote support / RMM"),
    (r"^zoho-verification=", "Zoho", "Business apps"),
    (r"^(sendinblue|brevo)-code:", "Brevo (Sendinblue)", "Marketing / CRM"),
    (r"^globalsign-domain-verification=", "GlobalSign (certificates)", "Security"),
    (r"^openai-domain-verification=", "OpenAI (ChatGPT Team / Enterprise)", "Business apps"),
    (r"^lastpass-verification-code=", "LastPass", "Security"),
    (r"^status-page-domain-verification=", "Atlassian Statuspage", "Collaboration"),
    (r"^have-i-been-pwned-verification=", "Have I Been Pwned (breach monitoring)", "Security"),
    (r"^canva-site-verification=", "Canva", "Business apps"),
    (r"^twilio-domain-verification=", "Twilio", "Business apps"),
    (r"^postman-domain-verification=", "Postman", "Collaboration"),
    (r"^mongodb-site-verification=", "MongoDB Atlas", "Cloud hosting"),
    (r"^jamf-site-verification=", "Jamf", "Device management"),
    (r"^amazonses:", "Amazon SES", "Email sending"),
    (r"^pardot", "Salesforce Pardot", "Marketing / CRM"),
]
_TOKEN_GENERIC = re.compile(r"^([a-z0-9][a-z0-9_.-]*?)[-_]?(site|domain)?[-_]?(verification|verify|validation)[-_a-z]*[=:]", re.I)

# SPF include → sending service.
SPF_SERVICES: list[tuple[str, str, str]] = [
    (r"(^|\.)spf\.protection\.outlook\.com$", "Microsoft 365", "Mail platform"),
    (r"(^|\.)_spf\.google\.com$|(^|\.)_netblocks\d?\.google\.com$", "Google Workspace", "Mail platform"),
    (r"mimecast\.com$", "Mimecast", "Email security"), (r"ess\.barracudanetworks\.com$", "Barracuda Email Protection", "Email security"),
    (r"pphosted\.com$|ppe-hosted\.com$", "Proofpoint", "Email security"), (r"messagelabs\.com$", "Broadcom / Symantec Email", "Email security"),
    (r"antispamcloud\.com$", "N-able Mail Assure / SpamExperts", "Email security"), (r"trendmicro\.", "Trend Micro Email Security", "Email security"),
    (r"(^|\.)zoho\.(com|eu|in)$", "Zoho Mail", "Mail platform"), (r"emailsrvr\.com$", "Rackspace Email", "Mail platform"),
    (r"secureserver\.net$", "GoDaddy email", "Mail platform"),
    (r"servers\.mcsv\.net$", "Mailchimp", "Marketing"), (r"mandrillapp\.com$", "Mandrill (Mailchimp)", "Transactional email"),
    (r"(^|\.)sendgrid\.net$", "SendGrid", "Transactional email"), (r"mailgun\.org$", "Mailgun", "Transactional email"),
    (r"amazonses\.com$", "Amazon SES", "Transactional email"), (r"mtasv\.net$", "Postmark", "Transactional email"),
    (r"sparkpostmail\.com$", "SparkPost", "Transactional email"), (r"(brevo|sendinblue)\.com$", "Brevo (Sendinblue)", "Marketing"),
    (r"mailjet\.com$", "Mailjet", "Marketing"), (r"constantcontact\.com$", "Constant Contact", "Marketing"),
    (r"createsend\.com$", "Campaign Monitor", "Marketing"), (r"mktomail\.com$", "Marketo", "Marketing"),
    (r"hubspotemail\.net$", "HubSpot", "Marketing"), (r"_spf\.salesforce\.com$", "Salesforce", "CRM"),
    (r"zendesk\.com$", "Zendesk", "Helpdesk"), (r"freshdesk\.com$|freshemail\.io$", "Freshdesk", "Helpdesk"),
    (r"helpscoutemail\.com$", "Help Scout", "Helpdesk"), (r"service-now\.com$", "ServiceNow", "Helpdesk"),
    (r"atlassian\.net$", "Atlassian", "Collaboration"), (r"netsuite\.com$", "Oracle NetSuite", "ERP / finance"),
    (r"qualtrics\.com$", "Qualtrics", "Business apps"), (r"exclaimer\.", "Exclaimer (signatures)", "Signatures"),
    (r"codetwo\.", "CodeTwo (signatures)", "Signatures"), (r"smtp2go\.com$", "SMTP2GO", "Transactional email"),
    (r"elasticemail\.com$", "Elastic Email", "Transactional email"), (r"docusign\.", "DocuSign", "Business apps"),
]

DKIM_SERVICES = {
    "selector1": "Microsoft 365", "selector2": "Microsoft 365", "google": "Google Workspace", "k1": "Mailchimp", "k2": "Mailchimp",
    "k3": "Mailchimp", "smtpapi": "SendGrid", "mandrill": "Mandrill",
    "zendesk1": "Zendesk", "zendesk2": "Zendesk", "hs1": "HubSpot", "hs2": "HubSpot", "cm": "Campaign Monitor", "pm": "Postmark",
    "everlytickey1": "Everlytic", "everlytickey2": "Everlytic", "protonmail": "Proton Mail", "protonmail2": "Proton Mail",
    "protonmail3": "Proton Mail", "fm1": "Fastmail", "fm2": "Fastmail", "fm3": "Fastmail", "mimecast20190104": "Mimecast",
    "mailjet": "Mailjet", "amazonses": "Amazon SES", "ses": "Amazon SES",
}

DMARC_VENDORS = [
    (r"agari\.com$", "Agari"), (r"dmarcian\.com$", "dmarcian"), (r"valimail\.com$", "Valimail"),
    (r"emaildefense\.proofpoint\.com$", "Proofpoint Email Fraud Defense"), (r"cloudflare\.net$", "Cloudflare DMARC Management"),
    (r"ondmarc\.com$|redsift\.cloud$", "Red Sift OnDMARC"), (r"easydmarc\.(us|com|eu)$", "EasyDMARC"), (r"uriports\.com$", "URIports"),
    (r"postmarkapp\.com$", "Postmark DMARC"), (r"mailhardener\.com$", "Mailhardener"), (r"dmarcanalyzer\.com$", "Mimecast DMARC Analyzer"),
    (r"powerdmarc\.com$", "PowerDMARC"), (r"fraudmarc\.com$", "Fraudmarc"), (r"sendmarc\.com$", "Sendmarc"), (r"dmarc\.report$|dmarcreport\.com$", "DMARC Report"),
]

WEBSITE_TECH: list[tuple[str, str, str]] = [  # (regex on HTML/headers, name, kind)
    (r"/wp-content/|/wp-includes/", "WordPress", "cms"), (r"static\.wixstatic\.com|wix-warmup-data", "Wix", "cms"),
    (r"static1\.squarespace\.com|squarespace-cdn", "Squarespace", "cms"), (r"cdn\.shopify\.com", "Shopify", "cms"),
    (r"data-wf-site|assets\.website-files\.com|webflow\.js", "Webflow", "cms"), (r"/sites/default/files/|Drupal\.settings", "Drupal", "cms"),
    (r"/media/jui/|Joomla!", "Joomla", "cms"), (r"img1\.wsimg\.com", "GoDaddy Website Builder", "cms"), (r"weebly\.com", "Weebly", "cms"),
    (r"irp\.cdn-website\.com|multiscreensite", "Duda", "cms"), (r"__NEXT_DATA__", "Next.js", "framework"),
    (r"js\.hs-scripts\.com|js\.hsforms\.net|hs-analytics", "HubSpot tracking / forms", "marketing"),
    (r"googletagmanager\.com|google-analytics\.com|gtag\(", "Google Analytics / Tag Manager", "analytics"),
    (r"pi\.pardot\.com|pardot\.com/pd\.js", "Salesforce Pardot", "marketing"), (r"munchkin\.marketo\.net", "Marketo", "marketing"),
    (r"connect\.facebook\.net", "Meta Pixel", "marketing"), (r"snap\.licdn\.com", "LinkedIn Insight", "marketing"),
    (r"static\.hotjar\.com", "Hotjar", "analytics"), (r"clarity\.ms", "Microsoft Clarity", "analytics"),
    (r"widget\.intercom\.io|js\.intercomcdn\.com", "Intercom chat", "chat"), (r"js\.driftt\.com", "Drift chat", "chat"),
    (r"static\.zdassets\.com", "Zendesk widget", "chat"), (r"embed\.tawk\.to", "tawk.to chat", "chat"),
    (r"cdn\.livechatinc\.com", "LiveChat", "chat"), (r"cdn\.cookielaw\.org|onetrust", "OneTrust cookie consent", "privacy"),
    (r"cookieyes\.com", "CookieYes consent", "privacy"), (r"www\.google\.com/recaptcha", "Google reCAPTCHA", "security"),
    (r"challenges\.cloudflare\.com/turnstile", "Cloudflare Turnstile", "security"),
]

ISP_HINTS = [
    "comcast", "charter", "spectrum", "at&t", "att-internet", "verizon", "cox ", "cox-", "centurylink", "lumen", "level 3", "level3",
    "frontier", "windstream", "altice", "optimum", "mediacom", "rcn", "astound", "wideopenwest", "consolidated", "tds telecom",
    "sparklight", "cable one", "cogent", "zayo", "brightspeed", "ziply", "british telecom", "bt-", "virgin media", "sky-",
    "vodafone", "deutsche telekom", "orange", "telus", "rogers", "bell canada", "shaw", "optus", "telstra", "tpg", "spark new zealand",
    "telefonica", "kpn", "proximus", "swisscom", "telia", "telenor", "eir", "liberty global", "ntt", "kddi", "softbank",
]
HOSTING_HINTS = [
    "amazon", "aws", "microsoft", "google", "cloudflare", "akamai", "fastly", "digitalocean", "linode", "ovh", "hetzner",
    "godaddy", "wpengine", "wp engine", "rackspace", "ionos", "1&1", "hostgator", "newfold", "unified layer", "bluehost",
    "siteground", "liquid web", "a2 hosting", "namecheap", "squarespace", "wix", "shopify", "automattic", "pantheon",
    "kinsta", "vultr", "oracle", "ibm", "salesforce", "hubspot", "netlify", "vercel", "github", "fly.io", "leaseweb", "dreamhost",
    "inmotion", "hostinger", "contabo", "scaleway", "hostpapa", "media temple", "endurance", "network solutions", "web.com",
]


DNS_HOSTS: list[tuple[str, str]] = [
    (r"cloudflare\.com$", "Cloudflare"), (r"azure-dns\.", "Azure DNS"), (r"awsdns", "AWS Route 53"),
    (r"domaincontrol\.com$", "GoDaddy"), (r"registrar-servers\.com$", "Namecheap"), (r"nsone\.net$", "NS1"),
    (r"ultradns\.", "UltraDNS"), (r"dnsmadeeasy\.com$", "DNS Made Easy"), (r"dynect\.net$", "Oracle Dyn"),
    (r"googledomains\.com$|ns-cloud-.*\.googledomains\.com$", "Google Cloud DNS / Squarespace Domains"),
    (r"worldnic\.com$", "Network Solutions"), (r"ui-dns\.|ionos\.", "IONOS"), (r"name-services\.com$", "Enom"),
    (r"hover\.com$", "Hover"), (r"dnsimple\.com$", "DNSimple"), (r"gandi\.net$", "Gandi"), (r"ovh\.net$", "OVH"),
    (r"hetzner\.", "Hetzner"), (r"digitalocean\.com$", "DigitalOcean"), (r"linode\.com$", "Linode"),
    (r"stabletransit\.com$|rackspace\.com$", "Rackspace"), (r"markmonitor\.com$", "MarkMonitor"), (r"cscdns\.net$", "CSC"),
    (r"akam\.net$|akamai", "Akamai"), (r"wixdns\.net$", "Wix"), (r"squarespacedns\.com$", "Squarespace"),
    (r"bluehost\.com$", "Bluehost"), (r"hostgator\.com$", "HostGator"), (r"siteground\.net$", "SiteGround"),
    (r"dreamhost\.com$", "DreamHost"), (r"websitewelcome\.com$", "HostGator / Newfold"), (r"porkbun\.com$", "Porkbun"),
    (r"name\.com$", "Name.com"), (r"he\.net$", "Hurricane Electric"), (r"zoneedit\.com$", "ZoneEdit"),
]


def _dns_host(ns_hosts: list[str], domain: str) -> str | None:
    if not ns_hosts:
        return None
    for h in ns_hosts:
        hit = _match(DNS_HOSTS, h)
        if hit:
            return hit[0]
    if all(registered_domain(h) == registered_domain(domain) for h in ns_hosts):
        return "Own name servers (self-hosted DNS)"
    return registered_domain(ns_hosts[0])


def _match(rx_list, value: str):
    for rx, *rest in rx_list:
        if re.search(rx, value, re.I):
            return rest
    return None


def _classify_network(asn: dict | None) -> tuple[str, str | None]:
    """(kind, owner): kind is 'hosting', 'office' (business/home ISP) or 'unknown'."""
    if not asn or not asn.get("name"):
        return "unknown", None
    name = asn["name"]
    org = re.sub(r",\s*[A-Z]{2}$", "", name.split(" - ", 1)[-1]).strip()
    low = name.lower()
    if any(h in low for h in HOSTING_HINTS):
        return "hosting", org
    if any(h in low for h in ISP_HINTS):
        return "office", org
    return "unknown", org


# ------------------------------------------------------------------ collectors
def _txt_records(res, domain: str) -> dict:
    recs, _ = txt(res, domain)
    services, other_tokens, rest = [], [], []
    for r in recs:
        s = r.strip()
        low = s.lower()
        if low.startswith("v=spf1"):
            continue
        hit = _match(TXT_TOKENS, s)
        if hit:
            label = re.split(r"[=:]", s, maxsplit=1)[0][:60]
            services.append({"name": hit[0], "category": hit[1], "evidence": f"DNS verification record ({label})"})
            continue
        m = _TOKEN_GENERIC.match(s)
        if m:
            other_tokens.append(s[:80])
        else:
            rest.append(s[:200])
    return {"all": recs, "services": services, "other_tokens": other_tokens, "other": rest}


def _probe_host(res, host: str) -> dict:
    cname, _ = resolve(res, host, "CNAME")
    a, _ = resolve(res, host, "A")
    aaaa, _ = resolve(res, host, "AAAA")
    return {"cname": cname[0].target.to_text(omit_final_dot=True).lower() if cname else None,
            "ips": [r.address for r in a] + [r.address for r in aaaa]}


def _infrastructure(res, domain: str) -> dict:
    # Wildcard DNS makes every name "exist"; detect it so we don't report noise.
    wild = _probe_host(res, f"mspg-{uuid.uuid4().hex[:10]}.{domain}")
    wild_ips, wild_cname = set(wild["ips"]), wild["cname"]
    with ThreadPoolExecutor(max_workers=32) as pool:
        probes = dict(zip(SUBDOMAINS, pool.map(lambda s: _probe_host(res, f"{s}.{domain}"), SUBDOMAINS)))
    found = []
    for label, p in probes.items():
        if not p["ips"] and not p["cname"]:
            continue
        if (wild_ips or wild_cname) and set(p["ips"]) == wild_ips and p["cname"] == wild_cname:
            continue
        purpose, area = SUBDOMAINS[label]
        found.append({"host": f"{label}.{domain}", "label": label, "purpose": purpose, "area": area,
                      "cname": p["cname"], "ips": p["ips"][:4]})
    # Who runs each one: a known SaaS from the CNAME, or the network that owns the IP.
    def classify(item):
        if item["cname"] and not item["ips"]:
            # Takeover risk only where someone else could claim the target (unknown names,
            # cloud apps, static hosting). Vendor-owned targets (e.g. Microsoft's retired
            # Skype for Business hosts) are just stale records.
            hit = _match(CNAME_SERVICES, item["cname"])
            if not hit or hit[1] in ("Cloud hosting", "Website"):
                item.update(kind="dangling", service=None, owner=f"{item['cname']} doesn't resolve")
                return item
            item.update(kind="saas", service=f"{hit[0]} (stale record: target no longer resolves)", service_category=hit[1])
            return item
        if item["label"] == "mail" and (item["cname"] or "").endswith("ghs.googlehosted.com"):
            item.update(kind="saas", service="Gmail custom web address (Google Workspace)", service_category="Mail platform")
            return item
        svc = _match(CNAME_SERVICES, item["cname"] or "")
        if svc:
            item.update(kind="saas", service=svc[0], service_category=svc[1])
            return item
        if item["cname"]:
            p = provider_for(item["cname"])
            if p:
                item.update(kind="saas", service=p["name"], service_category="Email" if p["kind"] in ("mailbox", "gateway") else "Other")
                return item
        ip = next((i for i in item["ips"] if ":" not in i), item["ips"][0] if item["ips"] else None)
        if ip and is_private_ip(ip):
            item.update(kind="private", service=None, owner="private address (internal DNS leaking)")
            return item
        asn = asn_lookup(res, ip) if ip else None
        kind, owner = _classify_network(asn)
        kind = {"hosting": "cloud", "office": "onprem", "unknown": "unknown"}[kind]
        # Larger organisations own their IP ranges (owner name contains their brand).
        brand = registered_domain(domain).split(".")[0]
        if owner and len(brand) >= 4 and brand in owner.lower().replace(" ", "").replace("-", ""):
            kind = "own"
        item.update(kind=kind, owner=owner, asn=(asn or {}).get("asn"), service=None)
        if item["cname"] and registered_domain(item["cname"]) == registered_domain(domain):
            item["cname_internal"] = True
        return item
    with ThreadPoolExecutor(max_workers=16) as pool:
        found = list(pool.map(classify, found))
    order = {"remote": 0, "vpn": 1, "identity": 2, "mail": 3, "m365": 4, "files": 5, "phones": 6, "apps": 7, "hosting": 8, "web": 9}
    found.sort(key=lambda x: (order.get(x["area"], 9), x["host"]))
    return {"wildcard": bool(wild_ips or wild_cname), "hosts": found, "checked": len(SUBDOMAINS)}


def _srv(res, domain: str) -> dict:
    out = {}
    for name in ("_sipfederationtls._tcp", "_sip._tls", "_autodiscover._tcp"):
        rd, _ = resolve(res, f"{name}.{domain}", "SRV")
        if rd:
            out[name] = [r.target.to_text(omit_final_dot=True).lower() for r in rd]
    return out


def _caa_soa(res, domain: str) -> dict:
    caa, _ = resolve(res, domain, "CAA")
    soa, _ = resolve(res, domain, "SOA")
    issuers = sorted({r.value.decode() if isinstance(r.value, bytes) else str(r.value) for r in caa if r.tag in (b"issue", b"issuewild", "issue", "issuewild")})
    s = soa[0] if soa else None
    # 'issue ";"' means no CA may issue at all: keep it rather than reporting "no CAA".
    return {"caa": sorted({(i.split(";")[0].strip() or "none (no CA may issue)") for i in issuers}),
            "soa": {"primary_ns": s.mname.to_text(omit_final_dot=True), "contact": s.rname.to_text(omit_final_dot=True).replace(".", "@", 1),
                    "serial": s.serial} if s else None}


def _website(domain: str) -> dict:
    out: dict = {"url": None, "error": None}
    insp = None
    for url in (f"https://{domain}", f"https://www.{domain}", f"http://{domain}"):
        try:
            insp = http_inspect(url)
            if insp.get("hops") and insp["hops"][-1].get("status"):
                break
        except ValueError as exc:
            out["error"] = str(exc)
            insp = None
    if not insp or not insp.get("hops"):
        return out
    final = insp["hops"][-1]
    headers = final.get("headers") or []
    out.update(url=insp.get("final_url") or final.get("url"), status=final.get("status"), server=final.get("server"),
               title=final.get("title"), ip=final.get("ip"), tls=final.get("tls"), redirects=len(insp["hops"]) - 1,
               https=str(insp.get("final_url") or final.get("url", "")).startswith("https://"),
               hsts=any(k.lower() == "strict-transport-security" for k, _ in headers),
               cdn=[c.get("name") for c in _detect_cdn(headers)], error=None, headline=insp.get("headline"), severity=insp.get("severity"))
    tech: list[dict] = []
    html = ""
    if out["url"] and (out.get("status") or 0) < 400:
        try:
            _, body, _ = _safe_get(out["url"], 400_000, 8)
            html = body.decode("utf-8", "replace")
        except ValueError:
            html = ""
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,80})', html, re.I)
    out["generator"] = gen.group(1) if gen else None
    blob = html + "\n" + "\n".join(f"{k}: {v}" for k, v in headers)
    for rx, name, kind in WEBSITE_TECH:
        if re.search(rx, blob, re.I) and not any(t["name"] == name for t in tech):
            tech.append({"name": name, "kind": kind})
    out["tech"] = tech
    if out.get("ip"):
        res = make_resolver()
        kind, owner = _classify_network(asn_lookup(res, out["ip"]))
        out["host_owner"], out["host_kind"] = owner, kind
    # security.txt is a small, public signal of security maturity.
    try:
        st, body, _ = _safe_get(f"https://{domain}/.well-known/security.txt", 32_000, 5)
        out["security_txt"] = st == 200 and b"contact:" in body.lower()
    except (ValueError, httpx.HTTPError):
        out["security_txt"] = False
    return out


# crt.sh asks for no more than 5 requests a minute per client; stay under it and fall back to CertSpotter.
CRTSH_PER_MINUTE = 4
_crtsh_calls: list[float] = []
_crtsh_lock = threading.Lock()
CERTSPOTTER_KEY = os.environ.get("CERTSPOTTER_API_KEY", "").strip()


def _crtsh_slot() -> bool:
    now = time.monotonic()
    with _crtsh_lock:
        _crtsh_calls[:] = [t for t in _crtsh_calls if now - t < 60]
        if len(_crtsh_calls) >= CRTSH_PER_MINUTE:
            return False
        _crtsh_calls.append(now)
        return True


def _capped_json(url: str, params: dict, timeout: float, cap: int = 20_000_000, headers: dict | None = None):
    """GET JSON from a fixed public API with a size and time cap (large domains return huge CT results)."""
    import json
    from ..core.outbound import read_capped
    hdrs = {"user-agent": "MSPGather (+https://github.com/kcorr/MSPGather)", **(headers or {})}
    with httpx.Client(timeout=timeout, trust_env=False, headers=hdrs) as c, c.stream("GET", url, params=params) as r:
        r.raise_for_status()
        body, truncated = read_capped(r, cap, time.monotonic() + timeout * 2)
    if truncated:
        raise ValueError("response too large")
    return json.loads(body)


def _ct_names(domain: str) -> dict:
    """Certificate transparency: every host name that ever got a public certificate.
    crt.sh first (most complete, often slow), CertSpotter as a fallback."""
    raw: list[str] = []
    source, errors = None, []
    if not _crtsh_slot():
        errors.append("crt.sh: skipped to respect its rate limit")
    else:
        try:
            for row in _capped_json("https://crt.sh/", {"q": f"%.{domain}", "output": "json"}, 20)[:5000]:
                raw.extend(str(row.get("name_value", "")).splitlines())
            source = "crt.sh"
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"crt.sh: {'rate limited' if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429 else type(exc).__name__}")
    if source is None:
        try:
            for row in _capped_json("https://api.certspotter.com/v1/issuances",
                                    {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}, 15,
                                    headers={"authorization": f"Bearer {CERTSPOTTER_KEY}"} if CERTSPOTTER_KEY else None):
                raw.extend(row.get("dns_names", []))
            source = "CertSpotter"
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"CertSpotter: {'rate limited (set CERTSPOTTER_API_KEY for more)' if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429 else type(exc).__name__}")
    if source is None:
        return {"error": "Certificate transparency sources didn't answer (" + ", ".join(errors) + "). They are often slow; try again later.", "names": []}
    names = set()
    for n in raw:
        n = n.strip().lower().lstrip("*.")
        if (n == domain or n.endswith("." + domain)) and " " not in n:
            names.add(n)
    interesting = re.compile(r"(^|[.-])(vpn|sslvpn|remote|rdweb|rdg|rds|gateway|citrix|owa|mail|exchange|adfs|sts|fs|sso|portal|ftp|sftp|test|dev|staging|backup|nas|admin|intranet|crm|erp)\d*([.-])")
    names_l = sorted(names)
    return {"error": None, "source": source, "names": names_l[:400], "total": len(names_l),
            "interesting": [n for n in names_l if interesting.search(n + ".")][:60]}


# --------------------------------------------------------------------- analysis
def _services(txtinfo, spf, dkim, infra, website, dmarc_vendor, mx_providers, gateways) -> list[dict]:
    found: dict[str, dict] = {}

    def add(name, category, evidence):
        e = found.setdefault(name, {"name": name, "category": category, "evidence": []})
        if evidence not in e["evidence"]:
            e["evidence"].append(evidence)

    for s in txtinfo["services"]:
        add(s["name"], s["category"], s["evidence"])
    for inc in spf.get("includes", []):
        hit = _match(SPF_SERVICES, inc)
        if hit:
            add(hit[0], hit[1], f"SPF include:{inc}")
    for k in dkim.get("found", []):
        if k.get("bits") and k["selector"] in DKIM_SERVICES:
            add(DKIM_SERVICES[k["selector"]], "Email sending", f"DKIM key at {k['selector']}._domainkey")
    for h in infra["hosts"]:
        # Microsoft 365 plumbing records (Autodiscover, Lync, enrollment) are shown under Identity, not as SaaS.
        if h.get("service") and h.get("service_category") != "Microsoft 365":
            add(h["service"], h.get("service_category") or "Other", f"{h['host']} → {h.get('cname')}")
    for t in (website or {}).get("tech", []):
        add(t["name"], {"cms": "Website", "framework": "Website", "marketing": "Marketing / CRM", "analytics": "Marketing / CRM",
                        "chat": "Website", "privacy": "Website", "security": "Website"}.get(t["kind"], "Website"), "Website code")
    for p in mx_providers:
        if p and p != "Unknown / self-hosted":
            add(p, "Email security" if p in gateways else "Mail platform", "MX record")
    if dmarc_vendor:
        add(dmarc_vendor, "Email security", "DMARC report address")
    # Merge duplicates that come from different evidence sources.
    for dup, keep in (("Microsoft 365 / Exchange Online", "Microsoft 365"), ("Google site verification (Search Console / Workspace)", "Google Workspace"),
                      ("Mandrill (Mailchimp)", "Mandrill")):
        if dup in found and keep in found:
            found[keep]["evidence"] += found.pop(dup)["evidence"]
    if "Microsoft 365" in found:
        found["Microsoft 365"]["category"] = "Mail platform"
    return sorted(found.values(), key=lambda s: (s["category"], s["name"]))


def _posture(spf, dmarc, dkim, mta_sts, tls_rpt, reg, website, mx, gateways, in_m365, infra) -> dict:
    items = []

    def item(label, pts, mx_pts, note, optional=False):
        items.append({"label": label, "points": pts, "max": mx_pts, "note": note,
                      "status": "ok" if pts == mx_pts else "info" if optional else "warning" if pts > 0 else "critical"})

    p = (dmarc.get("tags", {}).get("p") or "").lower()
    pct = dmarc.get("tags", {}).get("pct", "100")
    item("DMARC policy", {"reject": 25, "quarantine": 15, "none": 5}.get(p, 0) - (5 if p in ("reject", "quarantine") and pct != "100" else 0), 25,
         {"reject": "p=reject: spoofing blocked", "quarantine": "p=quarantine: spoofing goes to junk", "none": "p=none: monitoring only, spoofing delivered"}.get(p, "No DMARC record: anyone can spoof the domain"))
    spf_crit = any(f["severity"] == "critical" for f in spf.get("findings", []))
    all_t = next((t["raw"] for t in (spf.get("tree") or {}).get("terms", []) if t.get("mechanism") == "all"), "")
    if not spf.get("record"):
        item("SPF", 0, 15, "No SPF record")
    elif spf_crit:
        item("SPF", 3, 15, "SPF is broken (" + next(f["title"] for f in spf["findings"] if f["severity"] == "critical") + ")")
    else:
        item("SPF", 15 if all_t in ("-all", "~all") else 8, 15, f"Valid, {spf.get('lookup_count')}/10 lookups, ends {all_t or 'without all'}")
    keys = [k for k in dkim.get("found", []) if k.get("bits")]
    item("DKIM", 15 if keys else 0, 15, f"Keys on {', '.join(k['selector'] for k in keys[:4])}" if keys else "Not found on common selectors (a custom selector is possible)")
    filtered = bool(gateways) or in_m365 or any(e.get("provider") == "Google" for e in mx.get("records", []))
    item("Inbound filtering", 10 if filtered else 0, 10, ("Gateway: " + ", ".join(gateways)) if gateways else
         "Microsoft 365 / Google built-in filtering" if filtered else "No known filtering service in front of the mailbox")
    item("MTA-STS / TLS-RPT", (4 if mta_sts.get("policy") else 0) + (1 if tls_rpt.get("record") else 0), 5,
         "Enforced TLS for inbound mail" if mta_sts.get("policy") else "Not configured (optional hardening)", optional=True)
    dnssec_ok = bool(((reg or {}).get("dnssec") or {}).get("live", {}).get("validated"))
    item("DNSSEC", 5 if dnssec_ok else 0, 5, "Signed and validating" if dnssec_ok else "Not signed (optional hardening)", optional=True)
    # Only score registration when the TLD publishes it (.edu, .de etc. often don't).
    if reg and reg.get("registered") and reg.get("statuses"):
        locked = any(s.get("code") in ("clientTransferProhibited", "serverTransferProhibited") for s in reg.get("statuses", []))
        days = reg.get("days_left")
        item("Domain registration", (3 if locked else 0) + (2 if days is None or days > 60 else 0), 5,
             ("Transfer-locked" if locked else "No transfer lock") + (f", expires in {days} days" if days is not None else ""))
    https_ok = bool(website and website.get("https"))
    item("Website HTTPS", (3 if https_ok else 0) + (2 if website and website.get("hsts") else 0), 5,
         "HTTPS" + (" with HSTS" if website and website.get("hsts") else "") if https_ok else "Website not on HTTPS (or unreachable)")
    exposed = [h for h in infra["hosts"] if h["area"] in ("remote", "vpn") and h.get("kind") == "onprem"]
    item("Exposed remote access", 10 if not exposed else 4, 10,
         "No remote-access host names pointing at an office connection" if not exposed else f"{len(exposed)} remote-access host name(s) on their office connection: " + ", ".join(h["host"] for h in exposed[:4]))
    score = sum(i["points"] for i in items)
    total = sum(i["max"] for i in items)
    pct_score = round(100 * score / total)
    grade = "A" if pct_score >= 90 else "B" if pct_score >= 80 else "C" if pct_score >= 65 else "D" if pct_score >= 50 else "F"
    return {"score": pct_score, "grade": grade, "items": items}


def _talking_points(ctx: dict) -> list[dict]:
    """Risks to raise, opportunities to propose and questions to ask."""
    tp: list[dict] = []

    def add(kind, area, title, detail):
        tp.append({"kind": kind, "area": area, "title": title, "detail": detail})

    d = ctx["domain"]
    mail_host, gateways, in_m365, google = ctx["mail_host"], ctx["gateways"], ctx["in_m365"], ctx["google"]
    tenant, dmarc, spf, dkim = ctx["tenant"], ctx["dmarc"], ctx["spf"], ctx["dkim"]
    infra, website, reg, services = ctx["infra"], ctx["website"], ctx["reg"], ctx["services"]
    names = {s["name"] for s in services}

    receives_mail = not mail_host.startswith("none")
    m365_mail = mail_host == "Microsoft 365"
    # --- mail platform
    if not receives_mail:
        add("question", "Email", f"{d} doesn't receive email",
            "No MX (or a null MX). Is this a secondary or parked domain? Make sure it's locked down against spoofing: v=spf1 -all and DMARC p=reject.")
    if m365_mail and not gateways:
        add("question", "Email", "Which Microsoft 365 licences and Defender plan?",
            "Mail goes straight into Microsoft 365 with no third-party filter. Ask whether they have Business Premium / Defender for Office 365 (Safe Links, Safe Attachments), or only the built-in filtering.")
    if gateways:
        add("question", "Email", f"Who manages {', '.join(gateways)}, and when does it renew?",
            "A separate filtering gateway is a cost line and a renewal date, and often a consolidation opportunity.")
        if m365_mail:
            add("question", "Email", "Is Enhanced Filtering for Connectors turned on?",
                f"Mail reaches Microsoft 365 through {', '.join(gateways)}. Without Enhanced Filtering, Microsoft judges SPF/DMARC against the gateway's IP, which weakens spoof protection. Easy to check with a message header.")
    if mail_host.startswith("self-hosted"):
        add("opportunity", "Email", "Self-hosted email server",
            f"The MX points to a server on the domain itself ({mail_host}). Likely on-premises Exchange or another self-managed mail server: a migration to Microsoft 365 removes the server, its patching and its exposure.")
    elif mail_host.startswith("third-party"):
        add("question", "Email", f"Email is handled by {mail_host.split('(', 1)[-1].rstrip(')')}",
            "Not a platform MSPGather recognises. Ask what it is: a hosting provider's mailboxes, a filtering service, or something else?")
    if mail_host in ("GoDaddy", "Rackspace", "Zoho Mail", "Yahoo", "IONOS Mail", "OVH Mail", "Hostinger Mail", "Titan Mail",
                     "Namecheap Private Email", "Tucows / OpenSRS Hosted Email") or "GoDaddy email" in names or "Rackspace Email" in names:
        add("opportunity", "Email", f"Mail hosted with {mail_host}", "Small hosted mailboxes usually mean no Entra ID, no device management and weak admin controls: a Microsoft 365 move with security baseline is a strong proposal.")
    if in_m365 and google and receives_mail:
        add("question", "Email", "Both Microsoft 365 and Google Workspace handle mail for this domain",
            "Google appears in MX, SPF or DKIM alongside Microsoft 365. Are they mid-migration, running two platforms, or is one left over? Licences may be paid twice.")
    # --- authentication
    p = (dmarc.get("tags", {}).get("p") or "").lower()
    if not dmarc.get("record"):
        add("risk", "Email security", "No DMARC record: anyone can send email as @" + d,
            "Direct-domain spoofing (fake invoices, CEO fraud) lands in inboxes. Google, Yahoo and Microsoft also require DMARC for bulk senders.")
        add("opportunity", "Email security", "DMARC rollout project", "Monitor → quarantine → reject over 4–8 weeks, including finding every legitimate sender. Use the DMARC Builder.")
    elif p == "none":
        add("risk", "Email security", "DMARC is monitoring only (p=none)", "Spoofed mail is still delivered.")
        vendor = ctx["dmarc_vendor"]
        add("opportunity", "Email security", "Finish the DMARC rollout to p=reject",
            (f"Reports already go to {vendor}, so the data to move forward probably exists. " if vendor else "") + "Ask who reviews the reports and why it's stuck at none.")
    if ctx["dmarc_vendor"]:
        add("question", "Email security", f"DMARC reports go to {ctx['dmarc_vendor']}", "Who owns that subscription and reviews it? Is it part of a current provider's bundle?")
    if spf.get("record") and spf.get("lookup_count", 0) >= 9:
        add("risk", "Email security", f"SPF is at {spf['lookup_count']}/10 DNS lookups",
            "Adding one more sending service will break SPF for all mail. A cleanup / restructuring is needed before any new vendor is added.")
    if any(f["severity"] == "critical" for f in spf.get("findings", [])):
        add("risk", "Email security", "SPF record is broken", next(f["title"] for f in spf["findings"] if f["severity"] == "critical"))
    # Only claim DKIM is missing when nothing signs at all; gateways and vendors often use their own selectors.
    if m365_mail and not gateways and not any(k.get("bits") for k in dkim.get("found", [])):
        add("opportunity", "Email security", "No DKIM signing found",
            "No DKIM keys on Microsoft 365's selectors (or other common ones). Enabling Microsoft 365 DKIM is a quick win: two CNAMEs and a toggle. Without it, DMARC depends on SPF alone, which breaks on forwarding. (A custom selector is possible; check a sent message's DKIM-Signature.)")
    # --- identity
    fed = (tenant or {}).get("namespace_type")
    idp = (tenant or {}).get("idp")
    if fed == "Federated":
        if idp and "AD FS" in str(idp):
            add("opportunity", "Identity", "Still on AD FS federation",
                "AD FS servers need patching, certificates and high availability, and are a common attack target. Moving to cloud authentication (Password Hash Sync + Conditional Access) removes the servers. A classic project.")
            cert = (((tenant or {}).get("federation") or {}).get("metadata") or {}).get("signing") or []
            if cert:
                soonest = min((c.get("days_left") for c in cert if c.get("days_left") is not None), default=None)
                if soonest is not None and soonest < 60:
                    add("risk", "Identity", f"AD FS token-signing certificate expires in {soonest} days", "If it lapses, every Microsoft 365 sign-in fails.")
        else:
            add("question", "Identity", f"Sign-in is federated to {idp or 'a third-party identity provider'}",
                "Who manages the IdP and its licences? Are all Microsoft 365 Conditional Access controls effective with it?")
    if in_m365 and receives_mail and not any(h["label"] == "enterpriseenrollment" for h in infra["hosts"]):
        add("question", "Devices", "How are laptops and phones managed?",
            "There's no Intune enrollment record. Ask whether devices are Intune-managed, Entra-joined, or not managed at all: Intune / Autopilot is a common project.")
    elif any(h["label"] == "enterpriseenrollment" for h in infra["hosts"]):
        add("question", "Devices", "Intune enrollment is configured", "Ask how far the rollout got: compliance policies, Autopilot, app deployment?")
    # --- exposed infrastructure
    # onprem = business/home ISP (classic SMB office), own = organisation's own IP range,
    # unknown = network we can't classify.
    selfrun = ("onprem", "own", "unknown")
    where = lambda h: {"onprem": f"their office internet connection ({h.get('owner')})", "own": f"their own IP range ({h.get('owner')})"}.get(
        h.get("kind"), h.get("owner") or "an unrecognised network")
    for h in infra["hosts"]:
        if h["area"] == "remote" and h.get("kind") == "onprem":
            add("risk", "Remote access", f"{h['host']} points to {where(h)}",
                f"{h['purpose']}. Remote Desktop / RD Gateway exposed to the internet is a top ransomware entry point. Ask: is MFA enforced on it? Opportunity: Azure Virtual Desktop, Windows 365 or Entra Private Access / App Proxy.")
        elif h["area"] == "remote" and h.get("kind") in ("own", "unknown"):
            add("question", "Remote access", f"{h['host']} points to {where(h)}",
                f"Name suggests {h['purpose'].lower()}. Ask what it is and whether it's protected with MFA.")
        elif h["area"] == "vpn" and h.get("kind") in selfrun and not h.get("service"):
            add("question", "Remote access", f"{h['host']}: {h['purpose']}",
                "Which VPN appliance and firmware version? Is MFA on? VPN appliances are heavily targeted: a ZTNA (e.g. Entra Private Access) proposal fits here.")
        elif h["area"] == "identity" and h.get("kind") in selfrun and h["label"] in ("sts", "adfs", "fs"):
            add("question", "Identity", f"{h['host']} looks like an on-premises AD FS server", "Confirms on-prem identity infrastructure: ask about the AD FS / WAP servers and their patch level.")
        elif h["area"] == "mail" and h["label"] in ("owa", "exchange", "mail", "webmail") and h.get("kind") == "onprem":
            add("risk", "Email", f"{h['host']} points to {where(h)}", "Possibly on-premises Exchange / OWA on the internet. On-prem Exchange has had several critical internet-facing vulnerabilities; ask what's still running there.")
        elif h["area"] == "mail" and h["label"] in ("owa", "exchange") and h.get("kind") in ("own", "unknown"):
            add("question", "Email", f"{h['host']} points to {where(h)}", "Is on-premises Exchange / OWA still running? Ask what it's used for (hybrid management server, or live mailboxes).")
        elif h["label"] in ("ftp",) and h.get("kind") in selfrun:
            add("question", "Files", f"{h['host']}: FTP server", "What is it used for? FTP sends credentials in clear text; SharePoint/OneDrive external sharing or SFTP is the usual replacement.")
        elif h["area"] == "hosting":
            add("question", "Website", f"{h['host']}: shared hosting control panel", "The website is on a shared hosting plan. Who has the login, and who patches the site?")
    dangling = [h for h in infra["hosts"] if h.get("kind") == "dangling"]
    if dangling:
        add("risk", "DNS", f"{len(dangling)} dangling DNS record{'s' if len(dangling) > 1 else ''}: CNAME to a name that no longer exists",
            "; ".join(f"{h['host']} → {h['cname']}" for h in dangling) + ". If someone can register or claim that target (an old cloud app, storage account or SaaS tenant), "
            "they can serve content on your subdomain (subdomain takeover). Delete the records if the service is gone.")
    private = [h["host"] for h in infra["hosts"] if h.get("kind") == "private"]
    if private:
        add("risk", "DNS", f"{len(private)} public host name{'s' if len(private) > 1 else ''} resolve to private IPs",
            ", ".join(private) + ". Internal addresses are published in public DNS, which leaks the internal network layout. Usually split-brain DNS records copied to the public zone.")
    msp_tools = sorted({s["name"] for s in services if s["category"] == "Remote support / RMM"})
    if msp_tools:
        add("question", "Current provider", f"Remote support / RMM tools visible: {', '.join(msp_tools)}",
            "Found in DNS host names or verification records. Ask whether these are run by an IT provider or internal IT, who supports them today, and what's in that contract.")
    # --- SaaS / SSO
    sso_candidates = sorted(n for n in names if any(x in n for x in ("Atlassian", "Zoom", "Slack", "DocuSign", "Adobe", "Dropbox", "Smartsheet", "Miro", "Salesforce", "Zendesk", "HubSpot", "Webex", "Canva", "LastPass")))
    if sso_candidates and in_m365:
        add("opportunity", "Identity", f"{len(sso_candidates)} SaaS apps that could use Entra single sign-on",
            ", ".join(sso_candidates) + ". Connecting them to Entra ID means one login, MFA everywhere, and automatic off-boarding.")
    if "KnowBe4 (security awareness training)" in names:
        add("question", "Security", "They already use KnowBe4", "Security awareness training is in place: ask who runs the campaigns and the phish-prone percentage.")
    else:
        add("question", "Security", "Do staff get security awareness training?", "Ask whether they run phishing simulations and training (most tools leave no DNS trace). If not, it's an easy add-on.")
    # --- website / domain
    if website and website.get("url") and not website.get("https"):
        add("risk", "Website", "Website isn't served over HTTPS", "Browsers mark it 'Not secure'.")
    if website and any(t["name"] == "WordPress" for t in website.get("tech", [])):
        add("question", "Website", "Website runs WordPress", f"Who updates WordPress and its plugins?{' Generator tag: ' + website['generator'] + '.' if website.get('generator') else ''} Unpatched plugins are a common breach route.")
    days = (reg or {}).get("days_left")
    if days is not None and days < 60:
        add("risk", "Domain", f"Domain expires in {days} days", "If it lapses, email and the website stop. Confirm auto-renew and who owns the registrar account.")
    registrar = ((reg or {}).get("registrar") or {}).get("name")
    add("question", "Domain", f"Who owns the {registrar or 'registrar'} account for {d}?",
        "Domain and DNS accounts are often in an ex-employee's or old provider's name. Make sure the company owns them and they have MFA.")
    no_client_locks = d.rsplit(".", 1)[-1] in _NO_CLIENT_LOCK_TLDS
    if not no_client_locks and not any(s.get("code") in ("clientTransferProhibited", "serverTransferProhibited") for s in (reg or {}).get("statuses", []))             and (reg or {}).get("registered") and (reg or {}).get("statuses"):
        add("risk", "Domain", "No transfer lock on the domain", "Turn on the registrar's transfer lock to prevent hijacking.")
    order = {"risk": 0, "opportunity": 1, "question": 2}
    tp.sort(key=lambda x: order[x["kind"]])
    return tp


def discover(domain: str, ct: bool = False) -> dict:
    domain = normalize_domain(domain)
    if domain.startswith("www.") and domain.count(".") >= 2:
        domain = domain[4:]  # people paste the website address
    res = make_resolver()
    started = datetime.now(timezone.utc)
    _, soa_meta = resolve(res, domain, "SOA")
    if soa_meta["status"] == "nxdomain":
        raise ValueError(f"{domain} doesn't exist in DNS: it isn't registered, has expired, or is misspelled.")
    with ThreadPoolExecutor(max_workers=16) as pool:
        jobs = {
            "mx": pool.submit(check_mx, res, domain), "spf": pool.submit(analyze_spf, domain),
            "dmarc": pool.submit(check_dmarc, res, domain), "dkim": pool.submit(check_dkim, res, domain, []),
            "mta_sts": pool.submit(check_mta_sts, res, domain), "tls_rpt": pool.submit(check_tlsrpt, res, domain),
            "bimi": pool.submit(check_bimi, res, domain), "autodiscover": pool.submit(check_autodiscover, res, domain),
            "ns": pool.submit(check_ns, res, domain), "txt": pool.submit(_txt_records, res, domain),
            "infra": pool.submit(_infrastructure, res, domain), "srv": pool.submit(_srv, res, domain),
            "caa_soa": pool.submit(_caa_soa, res, domain), "website": pool.submit(_website, domain),
        }
        tenant_f = pool.submit(lambda: _safe(tenant_lookup, domain))
        reg_f = pool.submit(lambda: _safe(domain_registration, domain))
        ct_f = pool.submit(_ct_names, domain) if ct else None
        r = {k: v.result() for k, v in jobs.items()}
        tenant, reg = tenant_f.result(), reg_f.result()
        ct_data = ct_f.result() if ct_f else None

    mx = r["mx"]
    mx_providers = [e["provider"] or "Unknown / self-hosted" for e in mx.get("records", [])]
    gateways = sorted({e["provider"] for e in mx.get("records", []) if e.get("provider_kind") == "gateway"})
    in_m365 = bool((tenant or {}).get("tenant_id")) or r["autodiscover"].get("cname") == "autodiscover.outlook.com" \
        or "Microsoft 365" in mx_providers or any(s["name"] == "Microsoft 365" for s in r["txt"]["services"])
    # Google only counts when it handles mail (a Search Console token alone doesn't).
    google = "Google" in mx_providers or "_spf.google.com" in r["spf"].get("includes", []) or \
        any(k["selector"] == "google" and k.get("bits") for k in r["dkim"].get("found", []))
    mailbox = [p for p in mx_providers if p not in gateways]
    if mx.get("null_mx"):
        mail_host = "none (null MX)"
    elif not mx.get("records"):
        mail_host = "none"
    elif "Microsoft 365" in mailbox:
        mail_host = "Microsoft 365"
    elif "Google" in mailbox:
        mail_host = "Google Workspace"
    elif gateways and (in_m365 or google):
        # The gateway hides the mailbox platform: weigh the evidence for each.
        inc = r["spf"].get("includes", [])
        sel = {k["selector"] for k in r["dkim"].get("found", []) if k.get("bits")}
        ms = 2 * (r["autodiscover"].get("cname") == "autodiscover.outlook.com") + 2 * ("spf.protection.outlook.com" in inc) \
            + 2 * bool(sel & {"selector1", "selector2"}) + bool((tenant or {}).get("tenant_id"))
        gg = 2 * ("_spf.google.com" in inc) + 2 * ("google" in sel)
        mail_host = "Microsoft 365" if ms > gg else "Google Workspace" if gg > ms else "Microsoft 365 or Google Workspace (unclear)"
    elif mailbox and mailbox[0] != "Unknown / self-hosted":
        mail_host = mailbox[0]
    elif gateways:
        mail_host = "unknown (behind " + ", ".join(gateways) + ")"
    else:
        mail_host = _unknown_mail_host(res, domain, mx.get("records", []))

    dmarc = r["dmarc"]
    rua_domains = [u.strip()[7:].split("@")[-1].split("!")[0].lower() for u in dmarc.get("tags", {}).get("rua", "").split(",") if u.strip().lower().startswith("mailto:")]
    dmarc_vendor = next((v[0] for dom in rua_domains for v in [_match(DMARC_VENDORS, dom)] if v), None)

    services = _services(r["txt"], r["spf"], r["dkim"], r["infra"], r["website"], dmarc_vendor, mx_providers, gateways)
    posture = _posture(r["spf"], dmarc, r["dkim"], r["mta_sts"], r["tls_rpt"], reg, r["website"], mx, gateways, in_m365, r["infra"])
    ctx = {"domain": domain, "mail_host": mail_host, "gateways": gateways, "in_m365": in_m365, "google": google,
           "tenant": tenant, "dmarc": dmarc, "spf": r["spf"], "dkim": r["dkim"], "infra": r["infra"], "website": r["website"],
           "reg": reg, "services": services, "dmarc_vendor": dmarc_vendor}
    talking = _talking_points(ctx)

    # One-paragraph snapshot.
    parts = [f"Email: {mail_host}" + (f" behind {', '.join(gateways)}" if gateways and not mail_host.startswith("unknown") else "")]
    if tenant and tenant.get("tenant_id"):
        idp = tenant.get("idp")
        parts.append("Microsoft 365 tenant" + (f", federated to {idp}" if tenant.get("namespace_type") == "Federated" else ", cloud sign-in"))
    p = (dmarc.get("tags", {}).get("p") or "").lower()
    parts.append({"reject": "DMARC enforced (reject)", "quarantine": "DMARC quarantine", "none": "DMARC monitoring only"}.get(p, "no DMARC"))
    parts.append(f"{len(services)} services detected")
    onprem = [h for h in r["infra"]["hosts"] if h.get("kind") == "onprem"]
    if onprem:
        parts.append(f"{len(onprem)} host name(s) on their office internet connection")
    headline = f"{domain}: " + " · ".join(parts)

    spf = r["spf"]
    return {
        "domain": domain, "generated": started.isoformat(), "headline": headline,
        "facts": {
            "mail_host": mail_host, "gateways": gateways, "dns_host": _dns_host(r["ns"].get("hosts") or [], domain), "name_servers": r["ns"].get("hosts"),
            "registrar": ((reg or {}).get("registrar") or {}).get("name"), "registered": ((reg or {}).get("events") or {}).get("registered"),
            "expires": ((reg or {}).get("events") or {}).get("expires"), "days_left": (reg or {}).get("days_left"),
            "website_host": (r["website"] or {}).get("host_owner"),
            "cms": next((t["name"] for t in (r["website"] or {}).get("tech", []) if t["kind"] == "cms"), None),
        },
        "posture": posture, "talking_points": talking, "services": services,
        "email": {
            "mx": mx.get("records", []), "null_mx": mx.get("null_mx"), "gateways": gateways, "mail_host": mail_host,
            "spf": {"record": spf.get("record"), "lookups": spf.get("lookup_count"), "includes": spf.get("includes", []),
                    "issues": [f for f in spf.get("findings", []) if f["severity"] in ("critical", "warning")]},
            "dmarc": {"record": dmarc.get("record"), "policy": p or None, "inherited": dmarc.get("inherited"), "vendor": dmarc_vendor,
                      "rua_domains": rua_domains},
            "dkim": [{"selector": k["selector"], "bits": k.get("bits"), "service": DKIM_SERVICES.get(k["selector"]), "cname": k.get("cname")}
                     for k in r["dkim"].get("found", []) if k.get("bits")],
            "mta_sts": (r["mta_sts"].get("policy") or {}).get("mode"), "tls_rpt": bool(r["tls_rpt"].get("record")),
            "bimi": bool(r["bimi"].get("record")),
        },
        "identity": {
            "tenant_id": (tenant or {}).get("tenant_id"), "namespace": (tenant or {}).get("namespace_type"),
            "brand": (tenant or {}).get("federation_brand"), "cloud": (tenant or {}).get("cloud_label"),
            "region": (tenant or {}).get("region_label"), "idp": (tenant or {}).get("idp"), "idp_host": (tenant or {}).get("idp_host"),
            "headline": (tenant or {}).get("headline"), "severity": (tenant or {}).get("severity"),
            "autodiscover": r["autodiscover"].get("cname"), "srv": r["srv"],
            "intune": any(h["label"] == "enterpriseenrollment" for h in r["infra"]["hosts"]),
            "device_registration": any(h["label"] == "enterpriseregistration" for h in r["infra"]["hosts"]),
        },
        "infrastructure": r["infra"], "website": r["website"],
        "domain_info": {"registration": _reg_summary(reg), "caa": r["caa_soa"]["caa"], "soa": r["caa_soa"]["soa"],
                        "dns_host": _dns_host(r["ns"].get("hosts") or [], domain), "name_servers": r["ns"].get("hosts")},
        "txt": {"all": r["txt"]["all"], "other_tokens": r["txt"]["other_tokens"]},
        "ct": ct_data,
    }


def _unknown_mail_host(res, domain: str, records: list[dict]) -> str:
    """Describe an MX that isn't a recognised platform: a server on the domain
    itself (self-hosted) or some other company's service."""
    first = records[0]
    host = first["host"]
    if registered_domain(host) != registered_domain(domain):
        return f"third-party ({registered_domain(host)})"
    ip = next((i["ip"] for i in first.get("ips", []) if ":" not in i["ip"]), None)
    kind, owner = _classify_network(asn_lookup(res, ip)) if ip else ("unknown", None)
    if kind == "office":
        return f"self-hosted on-premises ({owner})"
    if kind == "hosting":
        return f"self-hosted server at {owner}"
    return f"self-hosted ({owner})" if owner else "self-hosted"


def _reg_summary(reg: dict | None) -> dict | None:
    if not reg:
        return None
    return {"registrar": (reg.get("registrar") or {}).get("name"), "events": reg.get("events"), "days_left": reg.get("days_left"),
            "statuses": [s.get("code") for s in reg.get("statuses", [])], "dnssec": bool(((reg.get("dnssec") or {}).get("live") or {}).get("validated")),
            "headline": reg.get("headline"), "severity": reg.get("severity"), "rdap_available": reg.get("rdap_available")}


def _safe(fn, *args):
    try:
        return fn(*args)
    except Exception:  # noqa: BLE001 - one source failing must not sink the whole report
        return None


@router.get("/api/discover/{domain:path}")
def discover_route(domain: str, ct: bool = False):
    result = run(discover, domain, ct)
    result["result_id"] = workspace.remember("discovery", result["domain"], result)
    return result
