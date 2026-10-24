"""Decode bounce messages (NDRs / DSNs): enhanced status codes, Exchange
component strings, DSN fields, and any original headers embedded in the NDR."""
from __future__ import annotations

import re

from .headers import analyze_headers

# Exact codes first, then ranges, then the generic class.x.x meaning.
CODES: dict[str, dict] = {
    "4.4.7": {"title": "Message expired in queue",
              "cause": "The sending server retried for its full retry window (often 24-48h) and couldn't deliver.",
              "fix": "Check the destination's MX resolves and port 25 is reachable (SMTP Test), connector smart hosts, and the receiving side's firewall. Often follows repeated 4xx deferrals."},
    "4.4.2": {"title": "Connection dropped", "cause": "The remote server closed the connection mid-session (network, TLS negotiation, or an overloaded server).",
              "fix": "Usually retried automatically. If it persists, test TLS with SMTP Test and check firewalls doing SMTP inspection (Cisco ASA 'ESMTP inspect' is a classic)."},
    "4.7.0": {"title": "Temporary policy / auth failure", "cause": "Greylisting, TLS required, temporary reputation block, or rate limiting.",
              "fix": "Wait for automatic retry. If it never succeeds, read the diagnostic text: it usually names the reason (TLS, rate limit, IP reputation)."},
    "4.7.26": {"title": "Unauthenticated sender (temporary)", "cause": "Gmail: the message isn't SPF or DKIM authenticated.",
               "fix": "Publish SPF and DKIM for the sending domain. Gmail now requires authentication for all senders."},
    "5.1.0": {"title": "Bad address", "cause": "Sender or recipient address is invalid or blocked.", "fix": "Check the address for typos; check the sender isn't restricted."},
    "5.1.1": {"title": "Recipient does not exist",
              "cause": "The recipient's mailbox doesn't exist at the destination. In Exchange this can also be a stale autocomplete (IMCEAEX…) entry after a migration.",
              "fix": "Confirm the address. For IMCEAEX… addresses: clear the user's autocomplete entry, or add the old legacyExchangeDN as an X500 proxy address on the recipient."},
    "5.1.8": {"title": "Sender blocked (outbound spam)",
              "cause": "Exchange Online restricted the sending account because it sent spam. Usually a compromised account.",
              "fix": "Treat as a compromise: reset the password, revoke sessions, check inbox rules and app consents, then release the user in Defender → Restricted entities."},
    "5.1.10": {"title": "Recipient not found by SMTP address lookup",
               "cause": "The destination (Exchange Online) has no recipient with that address.",
               "fix": "Check the address. If the recipient is yours: make sure the proxy address exists, and for hybrid make sure the object is synced. Directory-Based Edge Blocking rejects unknown recipients."},
    "5.2.2": {"title": "Mailbox full", "cause": "The recipient's mailbox is over quota.", "fix": "The recipient needs to clean up, enable archiving, or get more quota."},
    "5.2.3": {"title": "Message too large", "cause": "The message exceeds a size limit (sender, recipient, connector, or organisation).",
              "fix": "Check MaxSendSize/MaxReceiveSize on both mailboxes and limits on connectors and gateways. Base64 encoding adds about 33% to attachment size."},
    "5.3.190": {"title": "Journaling on-prem to Exchange Online not supported",
                "cause": "An on-premises journal rule targets a cloud mailbox.", "fix": "Journal to a third-party archive or on-prem mailbox instead."},
    "5.4.1": {"title": "Recipient address rejected: access denied (relay / DBEB)",
              "cause": "Exchange Online doesn't think the recipient exists, or the domain isn't an accepted domain in that tenant. Often: MX points to Exchange Online but the domain or recipient isn't set up there (e.g. after a migration).",
              "fix": "Check the domain is verified and accepted in the right tenant. For hybrid/shared domains set the accepted domain to Internal Relay, and make sure the recipient object exists."},
    "5.4.4": {"title": "Unable to route / host not found",
              "cause": "No route to the destination: the domain or MX doesn't exist, the MX points to a loopback/the sending server itself, or a connector smart host is wrong.",
              "fix": "Run Domain Health on the recipient domain. SMTPSEND.DNS.MxLoopback means the MX points back to the sender's own servers."},
    "5.4.6": {"title": "Routing loop detected",
              "cause": "Mail is going in circles: forwarding rules, mailbox forwarding, or mail users/contacts pointing back to your own domain, or a hybrid/connector loop.",
              "fix": "Paste the original headers into the Header Analyzer for the route. Check inbox rules, ForwardingSmtpAddress, accepted-domain types (Internal Relay on both sides) and outbound connectors."},
    "5.4.14": {"title": "Hop count exceeded (possible mail loop)",
               "cause": "The message passed through too many servers. Almost always a mail loop.",
               "fix": "Same as 5.4.6: run the original headers through the Header Analyzer to see which systems it bounces between."},
    "5.4.300": {"title": "Message expired", "cause": "Exchange Online couldn't deliver within the retry window.", "fix": "See 4.4.7. Check the destination is reachable and the outbound connectors."},
    "5.4.310": {"title": "DNS domain does not exist", "cause": "The recipient domain has no DNS (typo or expired domain).", "fix": "Check the domain spelling; run Domain Health."},
    "5.4.312": {"title": "Message expired: DNS query failed", "cause": "The recipient domain's DNS servers failed to answer.", "fix": "The recipient's DNS hosting is broken; tell them. Check with DNS Lookup → authoritative."},
    "5.4.316": {"title": "Message expired: connection refused", "cause": "The destination server refused connections on port 25.", "fix": "Check the destination's MX and firewall (SMTP Test)."},
    "5.5.0": {"title": "Generic SMTP protocol / mailbox error", "cause": "Read the diagnostic text; the receiving server explains the reason there.", "fix": ""},
    "5.6.11": {"title": "Bare line feeds (SMTPSEND.BareLinefeedsAreIllegal)",
               "cause": "The message has LF without CR. Exchange Online rejects this toward servers that don't support BDAT/CHUNKING.",
               "fix": "Fix the sending application, or the receiving server needs to support CHUNKING."},
    "5.7.1": {"title": "Delivery not authorised / relay denied",
              "cause": "Many reasons: the sender isn't allowed to send to a group (RESOLVER.RST.AuthRequired), relaying is denied, the IP is blocked, or a rule rejected it.",
              "fix": "Read the diagnostic text. For groups: check AcceptMessagesOnlyFrom and RequireSenderAuthenticationEnabled. For relay: the device/app must authenticate or use a connector."},
    "5.7.3": {"title": "Authentication unsuccessful", "cause": "Wrong credentials, or SMTP AUTH / basic auth is blocked (Security Defaults, Conditional Access, or SMTP AUTH disabled).",
              "fix": "For printers and apps: check Set-CASMailbox -SmtpClientAuthenticationDisabled, Security Defaults, or move to an SMTP relay connector / high-volume email."},
    "5.7.8": {"title": "Authentication credentials invalid", "cause": "Bad username/password for SMTP AUTH.", "fix": "Check credentials; MFA-enabled accounts can't use basic SMTP AUTH."},
    "5.7.12": {"title": "Sender not authenticated for this group/recipient",
               "cause": "The recipient (usually a group) only accepts mail from authenticated (internal) senders.",
               "fix": "Set-DistributionGroup <group> -RequireSenderAuthenticationEnabled $false if external senders are allowed."},
    "5.7.20": {"title": "No passing DKIM signature", "cause": "The receiver requires a valid DKIM signature.", "fix": "Enable DKIM signing for the sending domain."},
    "5.7.21": {"title": "No acceptable DKIM signature", "cause": "DKIM signature present but not acceptable (weak key, wrong domain).", "fix": "Sign with a 2048-bit key in the From domain."},
    "5.7.22": {"title": "No valid author-matched DKIM signature", "cause": "DKIM passed but not for the From domain.", "fix": "Sign with the From domain (aligned DKIM)."},
    "5.7.23": {"title": "SPF validation failed",
               "cause": "The sending IP isn't in the sender domain's SPF and the receiver rejects SPF fails (-all).",
               "fix": "Add the sending service to SPF (check the 10-lookup limit with the SPF Inspector). If the mail was forwarded, the forwarder should use SRS."},
    "5.7.24": {"title": "SPF validation error", "cause": "The SPF record is broken (PermError: too many lookups, syntax).", "fix": "Run the SPF Inspector on the sender domain."},
    "5.7.25": {"title": "Reverse DNS validation failed", "cause": "The sending IP has no PTR record or it doesn't match (Gmail requires PTR).",
               "fix": "Ask the ISP / hosting provider to set a PTR for the sending IP that resolves back to it."},
    "5.7.26": {"title": "Multiple authentication checks failed / unauthenticated",
               "cause": "Gmail: SPF and DKIM both failed, or DMARC failed. Microsoft: similar meaning.",
               "fix": "Make sure mail passes DMARC: aligned SPF or aligned DKIM for the From domain."},
    "5.7.27": {"title": "Sender address has null MX", "cause": "The sender's domain publishes a null MX (accepts no mail), so the receiver rejects it.", "fix": "Remove the null MX if the domain sends and receives mail."},
    "5.7.57": {"title": "Client not authenticated to send anonymous mail",
               "cause": "A device/app connected to smtp.office365.com:587 without authenticating.",
               "fix": "Configure SMTP AUTH credentials on the device, or use direct send / a relay connector on port 25 to the MX endpoint."},
    "5.7.60": {"title": "Client does not have permissions to send as this sender",
               "cause": "The authenticated account isn't allowed to Send As the From address.", "fix": "Grant Send As (Add-RecipientPermission) or change the From address."},
    "5.7.64": {"title": "TenantAttribution; relay access denied",
               "cause": "Exchange Online couldn't match the incoming connection to an inbound connector (IP or certificate mismatch).",
               "fix": "Check the inbound connector's sender IPs / TLS certificate name match the relaying server. Run: Get-InboundConnector | fl Name,SenderIPAddresses,TlsSenderCertificateName,RestrictDomainsToIPAddresses"},
    "5.7.133": {"title": "Sender not authenticated for group", "cause": "The group only accepts internal senders.", "fix": "Allow external senders on the group (RequireSenderAuthenticationEnabled $false)."},
    "5.7.134": {"title": "Sender not authenticated for mailbox", "cause": "The mailbox only accepts internal senders.", "fix": "Set-Mailbox -RequireSenderAuthenticationEnabled $false"},
    "5.7.135": {"title": "Sender not authenticated for public folder", "cause": "The public folder only accepts internal senders.", "fix": "Set-MailPublicFolder -RequireSenderAuthenticationEnabled $false"},
    "5.7.136": {"title": "Sender not authenticated for mail user", "cause": "The mail user only accepts internal senders.", "fix": "Set-MailUser -RequireSenderAuthenticationEnabled $false"},
    "5.7.139": {"title": "SMTP AUTH disabled for the tenant or mailbox",
                "cause": "SmtpClientAuthentication is disabled (tenant-wide or per mailbox), or Security Defaults block basic auth.",
                "fix": "Set-CASMailbox <mbx> -SmtpClientAuthenticationDisabled $false (only if SMTP AUTH is really needed), or move the device to a connector-based relay."},
    "5.7.520": {"title": "External forwarding blocked by policy",
                "cause": "Exchange Online's outbound spam policy blocks automatic forwarding to external addresses (the default). A mailbox forwarding setting, inbox rule or transport rule tried to forward mail outside the organisation.",
                "fix": "If the forward is legitimate, allow it for that mailbox with a custom outbound spam policy (Automatic forwarding rules: On) scoped to the user. If nobody set it up, treat it as a possible compromise and check the mailbox's inbox rules and forwarding."},
    "5.7.509": {"title": "DMARC reject", "cause": "The sending domain fails DMARC and has p=reject.", "fix": "The sender must fix SPF/DKIM alignment for their domain."},
    "5.7.511": {"title": "Banned sender", "cause": "Microsoft has banned the sending IP/domain.", "fix": "Request delisting through the Microsoft sender support form, quoting the full NDR."},
    "5.7.512": {"title": "Message must be RFC 5322 compliant", "cause": "The From header is missing or malformed.", "fix": "Fix the sending application so it sends a valid From: header."},
    "5.7.515": {"title": "Sender doesn't meet required authentication level",
                "cause": "Outlook.com/Hotmail high-volume sender rules: the domain needs SPF, DKIM and DMARC that pass.", "fix": "Publish and align SPF, DKIM and DMARC (p=none at minimum)."},
    "5.7.705": {"title": "Tenant exceeded threshold (outbound spam)", "cause": "Your tenant is blocked from sending because of bad outbound reputation.", "fix": "Find the compromised accounts/apps, then contact Microsoft support."},
    "5.7.708": {"title": "Traffic not accepted from this IP",
                "cause": "Usually a new tenant, or one sending from a low-reputation IP pool.", "fix": "Contact Microsoft support. Make sure all domains are verified and the tenant isn't a trial sending bulk mail."},
    "5.7.750": {"title": "Client blocked from sending from unregistered domains",
                "cause": "The tenant is sending as domains that aren't verified/accepted in the tenant.", "fix": "Add and verify the sending domain as an accepted domain, or stop sending as it."},
}

RANGES = [
    (("5.7", 606, 649), {"title": "Banned sending IP", "cause": "The sending IP is on Microsoft's block list.",
                         "fix": "Delist at the Microsoft delist portal (sender.office.com) and find out why the IP was sending spam."}),
    (("5.7", 700, 749), {"title": "Tenant has exceeded its sending threshold", "cause": "Microsoft blocked the tenant's outbound mail.",
                         "fix": "Look for compromised accounts or misbehaving apps, then contact Microsoft support."}),
]

CLASS = {"2": "Success", "4": "Temporary failure: the sending server will retry",
         "5": "Permanent failure: the message will not be retried"}
SUBJECT = {"0": "Other / undefined", "1": "Addressing", "2": "Mailbox", "3": "Mail system", "4": "Network / routing",
           "5": "Mail delivery protocol", "6": "Message content / media", "7": "Security / policy"}

COMPONENTS = {
    "RESOLVER.ADR.RecipNotFound": "Recipient not found in the directory.",
    "RESOLVER.ADR.RecipientNotFound": "Recipient not found by SMTP address lookup.",
    "RESOLVER.ADR.ExRecipNotFound": "Recipient not found by Exchange legacy encapsulated address (stale autocomplete / X500 needed).",
    "RESOLVER.RST.AuthRequired": "Recipient (often a group) requires authenticated senders.",
    "RESOLVER.RST.NotAuthorized": "The sender isn't allowed to send to this recipient (delivery restrictions).",
    "RESOLVER.RST.RecipSizeLimit": "Message exceeds the recipient's size limit.",
    "RESOLVER.RST.SendSizeLimit": "Message exceeds the sender's size limit.",
    "RESOLVER.FWD.Forwarded": "The recipient's forwarding caused the failure.",
    "SMTPSEND.DNS.NonExistentDomain": "The recipient domain doesn't exist in DNS.",
    "SMTPSEND.DNS.MxLoopback": "The recipient domain's MX points back to the sending organisation itself: a routing loop.",
    "SMTPSEND.BareLinefeedsAreIllegal": "Message contains bare LF characters.",
    "STOREDRV.Deliver.Exception:QuotaExceededException": "Recipient mailbox is full.",
    "STOREDRV.Submission.Exception:SubmissionQuotaExceededException": "Sender exceeded their sending limit (recipient rate limit or message rate).",
    "STOREDRV.Submission.Exception:SendAsDeniedException": "Sender has no Send As / Send on Behalf permission.",
    "ROUTING.NoConnectorForAddressType": "No connector can route this address type.",
    "Hop count exceeded": "Too many hops: a mail loop.",
    "Routing loop detected": "Exchange detected a routing loop.",
    "AS(201806281)": "Exchange Online Directory-Based Edge Blocking: the recipient doesn't exist in the tenant.",
}

DSN_FIELDS = ["Reporting-MTA", "Received-From-MTA", "Arrival-Date", "Final-Recipient", "Original-Recipient",
              "Action", "Status", "Remote-MTA", "Diagnostic-Code", "Last-Attempt-Date", "X-Display-Name"]


def lookup_code(code: str) -> dict:
    cls, subj, det = code.split(".")
    info = CODES.get(code)
    if not info:
        for (prefix, lo, hi), meta in RANGES:
            if code.startswith(prefix + ".") and lo <= int(det) <= hi:
                info = meta
                break
    generic = f"{CLASS.get(cls, '?')}; {SUBJECT.get(subj, 'Unknown subject')}"
    return {"code": code, "class": CLASS.get(cls), "category": SUBJECT.get(subj), "known": bool(info),
            "title": (info or {}).get("title", generic), "cause": (info or {}).get("cause", ""),
            "fix": (info or {}).get("fix", ""), "generic": generic}


# IMCEAEX ("Internet Mail Connector Encapsulated Address, EX type") is how Exchange
# writes a legacyExchangeDN as an SMTP address: '/' becomes '_' and other
# characters become +XX (hex). It shows up in NDRs when Outlook's autocomplete
# (or a cached entry) still points at a mailbox's old legacyExchangeDN.
IMCEAEX_RE = re.compile(r"IMCEAEX-([^\s@<>\"';,\[\]]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", re.I)


def decode_imceaex(encoded: str) -> str:
    """'_o=Org_ou=Exchange+20Administrative...' -> '/o=Org/ou=Exchange Administrative...'."""
    def sub(m: re.Match) -> str:
        return "/" if m.group(0) == "_" else chr(int(m.group(1), 16))
    return re.sub(r"_|\+([0-9A-Fa-f]{2})", sub, encoded)


def find_x500(text: str) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for m in IMCEAEX_RE.finditer(text or ""):
        dn = decode_imceaex(m.group(1))
        if not dn.lower().startswith("/o="):
            continue  # not a legacyExchangeDN; don't guess
        x500 = "X500:" + dn
        if x500.lower() in seen:
            continue
        seen.add(x500.lower())
        last_cn = re.findall(r"/cn=([^/]+)", dn, re.I)
        alias = re.sub(r"^[0-9a-f]{8,}-", "", last_cn[-1], flags=re.I) if last_cn else None
        out.append({"encoded": m.group(0), "domain": m.group(2).lower(), "legacy_dn": dn, "x500": x500,
                    "alias_hint": alias})
    return out


def analyze_ndr(raw: str) -> dict:
    text = (raw or "").replace("\r\n", "\n")
    if not text.strip():
        raise ValueError("Paste the bounce message (NDR) text.")

    found: list[dict] = []
    seen: set[str] = set()
    for m in re.finditer(r"(?<![\d.])([245])\.(\d{1,3})\.(\d{1,3})(?![\d.])", text):
        code = m.group(0)
        if code in seen:
            continue
        # Skip version-looking strings like 15.20.7000 (preceded by digits) handled by lookbehind.
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        context = text[line_start: line_end if line_end != -1 else len(text)].strip()
        seen.add(code)
        entry = lookup_code(code)
        entry["context"] = context[:400]
        smtp = re.search(r"\b([245]\d\d)[ -]" + re.escape(code), text)
        entry["smtp_code"] = smtp.group(1) if smtp else None
        found.append(entry)

    # Prefer specific codes over x.0.0 generic ones when ranking.
    found.sort(key=lambda e: (not e["known"], e["code"].endswith(".0.0")))

    components = [{"component": k, "meaning": v} for k, v in COMPONENTS.items() if k.lower() in text.lower()]

    dsn = {}
    for field in DSN_FIELDS:
        m = re.search(rf"^{re.escape(field)}:\s*(.+(?:\n[ \t].+)*)", text, re.M | re.I)
        if m:
            dsn[field] = re.sub(r"\s+", " ", m.group(1)).strip()

    exo = {}
    for label, rx in (("generating_server", r"Generating server:\s*(\S+)"),
                      ("remote_server", r"Remote server returned ['\"]?(.+?)['\"]?\s*$"),
                      ("receiving_server", r"Receiving server:\s*(\S+)"),
                      ("rejecting_server", r"(?:The following organization rejected your message|Rejecting server):\s*\[?(\S+?)\]?\.?\s*$")):
        m = re.search(rx, text, re.M | re.I)
        if m:
            exo[label] = m.group(1).strip()

    recipients = sorted(set(a.lower() for a in re.findall(r"(?:Final-Recipient:\s*rfc822;\s*|^\s*)([\w.+'-]+@[\w-]+(?:\.[\w-]+)+)", text, re.M | re.I)))[:20]

    original = None
    m = re.search(r"(?im)^(?:Original message headers:|-+ ?Original message headers ?-+|Content-Type: text/rfc822-headers.*)$", text)
    if m:
        chunk = text[m.end():]
        try:
            original = analyze_headers(chunk)
        except ValueError:
            original = None
    elif re.search(r"(?im)^Received:\s", text):
        try:
            original = analyze_headers(text[re.search(r"(?im)^Received:\s", text).start():])
        except ValueError:
            original = None

    x500 = find_x500(text)

    primary = found[0] if found else None
    if x500 and not found:
        summary = "The sender's Outlook used a stale cached address (legacyExchangeDN). Add the X500 proxy address below to the recipient."
    elif not found and not components:
        summary = "No SMTP enhanced status code found. Paste the full NDR, including the 'Diagnostic information for administrators' section."
    elif primary:
        summary = f"{primary['code']}: {primary['title']}"
        # A generic class code (x.0.0 / x.y.0) says little; a recognised Exchange component says what happened.
        if not primary["known"] and components:
            summary = f"{primary['code']}: {components[0]['meaning']}"
    else:
        summary = components[0]["meaning"]

    return {"summary": summary, "codes": found, "components": components, "dsn": dsn, "exchange": exo,
            "recipients": recipients, "original_headers": original, "x500": x500,
            "is_loop": any(c["code"] in ("5.4.6", "5.4.14") for c in found)
                       or any("loop" in c["component"].lower() or "Loopback" in c["component"] for c in components)}
