"""Hardening Plan: control logic on synthetic discovery results (no network).
Fictional data only: contoso.com, fabrikam.com and documentation IP ranges."""
import copy
import json
import re
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.modules import harden
from app.modules.harden import plan_from

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
D = "contoso.com"
WWW = {"host": "www.contoso.com", "label": "www", "purpose": "Website", "area": "web", "cname": None,
       "ips": ["203.0.113.10"], "kind": "cloud", "owner": "Example Hosting", "service": None}
BASE = {
    "domain": D,
    "email": {
        "mx": [{"preference": 0, "host": "contoso-com.mail.protection.outlook.com", "provider": "Microsoft 365",
                "provider_kind": "mailbox", "cname": None, "ips": []}],
        "null_mx": False, "gateways": [], "mail_host": "Microsoft 365",
        "spf": {"record": "v=spf1 include:spf.protection.outlook.com -all", "lookups": 2,
                "includes": ["spf.protection.outlook.com"], "issues": []},
        "dmarc": {"record": "v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com", "policy": "reject", "inherited": False,
                  "vendor": None, "rua_domains": ["contoso.com"]},
        "dkim": [{"selector": "selector1", "bits": 2048, "service": "Microsoft 365",
                  "cname": "selector1-contoso-com._domainkey.contoso.onmicrosoft.com"}],
        "mta_sts": "enforce", "tls_rpt": True, "bimi": False,
    },
    "identity": {"tenant_id": "00000000-0000-0000-0000-000000000001", "namespace": "Managed", "idp": None},
    "infrastructure": {"wildcard": False, "checked": 85, "hosts": [WWW]},
    "website": {"url": "https://www.contoso.com/", "status": 200, "https": True, "hsts": True, "security_txt": True,
                "cdn": [], "severity": "ok", "headline": "https://www.contoso.com/ loads fine.",
                "tls": {"cert": {"issuer": "CN=R11,O=Let's Encrypt,C=US", "days_left": 60, "hostname_match": True}}},
    "domain_info": {"registration": {"registrar": "Contoso Registrar Inc.", "events": {"expires": "2027-06-30"},
                                     "days_left": 240, "statuses": ["clientTransferProhibited"], "dnssec": True,
                                     "headline": "contoso.com is registered and healthy.", "severity": "ok",
                                     "rdap_available": True},
                    "caa": ["letsencrypt.org"], "soa": None, "dns_host": "Contoso DNS", "name_servers": []},
}
NO_DMARC = {"record": None, "policy": None, "inherited": False, "vendor": None, "rua_domains": []}
NO_SPF = {"record": None, "lookups": 0, "includes": [], "issues": [{"severity": "critical", "title": "No SPF record"}]}
PARKED = {"email.mx": [], "email.mail_host": "none", "email.spf": NO_SPF, "email.dmarc": NO_DMARC, "email.dkim": [],
          "email.mta_sts": None, "email.tls_rpt": False, "identity": {}}
M365_COMMANDS = [
    "Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled",
    "Get-HostedOutboundSpamFilterPolicy | Format-List Name,AutoForwardingMode",
    "Get-EOPProtectionPolicyRule | Format-List Name,State",
    "Get-ATPProtectionPolicyRule | Format-List Name,State",
    "Get-ExternalInOutlook",
    "Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled",
    "Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Format-List IsEnabled",
]
DKIM_GET = "Get-DkimSigningConfig -Identity contoso.com | Format-List Selector1CNAME,Selector2CNAME,Enabled"
DKIM_ENABLE = "Set-DkimSigningConfig -Identity contoso.com -Enabled $true"
DKIM_NEW = "New-DkimSigningConfig -DomainName contoso.com -Enabled $true"


def make(changes: dict | None = None, **kw) -> dict:
    """BASE with dotted-path overrides, e.g. make({"email.dmarc.record": "v=DMARC1; p=none"})."""
    d = copy.deepcopy(BASE)
    for path, value in {**(changes or {}), **kw}.items():
        *parents, last = path.split(".")
        cur = d
        for p in parents:
            cur = cur[p]
        cur[last] = copy.deepcopy(value)
    return d


def plan(disc: dict, extra: dict | None = None) -> dict:
    return plan_from(disc, extra or {}, now=NOW)


def ctl(p: dict, cid: str) -> dict:
    return next(c for c in p["controls"] if c["id"] == cid)


def ids(p: dict) -> set[str]:
    return {c["id"] for c in p["controls"]}


def host(name: str, area: str, kind: str, **kw) -> dict:
    return {"host": f"{name}.{D}", "label": name, "purpose": name, "area": area, "cname": None, "ips": [],
            "kind": kind, "owner": None, "service": None, **kw}


# ------------------------------------------------------------------ overall shape
def test_healthy_domain_passes_everything():
    p = plan(make())
    assert p["severity"] == "ok"
    assert p["headline"] == "contoso.com passes all 23 hardening checks."
    assert p["summary"] == {"pass": 23, "fail": 0, "warn": 0, "manual": 6, "unknown": 0, "na": 1, "total": 23, "score": 100}
    assert p["sends_mail"] and p["receives_mail"] and p["mail_platform"] == "Microsoft 365"
    assert p["subline"] == "Public DNS, registry and website data only. Tenant settings are listed as manual checks."
    assert all("fix" not in c for c in p["controls"] if c["status"] == "pass")


def test_contract_shape_and_severity_rules():
    p = plan(make({"email.dmarc.record": "v=DMARC1; p=none", "email.spf.lookups": 10}))
    assert set(p) == {"domain", "generated", "severity", "headline", "subline", "summary", "sends_mail", "receives_mail",
                      "mail_platform", "areas", "controls"}
    assert p["generated"] == "2026-10-26T12:00:00+00:00"
    assert [a["id"] for a in p["areas"]] == ["email-auth", "mail-transport", "domain", "dns-hygiene", "web", "exposure", "m365"]
    assert all(set(a) == {"id", "title", "desc"} for a in p["areas"])
    areas = {a["id"] for a in p["areas"]}
    for c in p["controls"]:
        assert set(c) - {"fix"} == {"id", "area", "title", "status", "severity", "priority", "found", "why", "optional"}
        assert c["area"] in areas and c["priority"] in (1, 2, 3) and c["found"] and c["why"]
        expected = {"pass": {"ok"}, "fail": {"critical", "warning"}, "warn": {"warning"}}.get(c["status"], {"info"})
        assert c["severity"] in expected, c
        if "fix" in c:
            assert set(c["fix"]) == {"summary", "tool", "params", "tool_label", "records", "commands", "steps"}
            assert all(set(r) == {"type", "name", "value"} for r in c["fix"]["records"])
    assert len({c["id"] for c in p["controls"]}) == len(p["controls"])
    json.dumps(p)


# ------------------------------------------------------------------ DMARC
def test_no_dmarc_is_critical_and_named_first():
    p = plan(make({"email.dmarc": NO_DMARC}))
    c = ctl(p, "dmarc-published")
    assert (c["status"], c["severity"], c["priority"]) == ("fail", "critical", 1)
    assert c["fix"]["tool"] == "dmarcbuild" and c["fix"]["params"] == {"d": D}
    assert c["fix"]["records"] == [{"type": "TXT", "name": "_dmarc.contoso.com", "value": "v=DMARC1; p=none"}]
    assert ctl(p, "dmarc-enforced")["status"] == "fail" and ctl(p, "dmarc-sp")["status"] == "na"
    assert p["severity"] == "critical"
    # Dependent controls (enforcement, reports) don't crowd the headline.
    assert p["headline"] == "contoso.com passes 19 of 22 hardening checks. Fix first: no DMARC record."


def test_dmarc_p_none_moves_to_quarantine_keeping_own_values():
    p = plan(make({"email.dmarc.record": "v=DMARC1; p=none; rua=mailto:dmarc@contoso.com; fo=1"}))
    c = ctl(p, "dmarc-enforced")
    assert (c["status"], c["severity"], c["priority"]) == ("fail", "warning", 1)
    assert "p=none" in c["found"]
    assert c["fix"]["records"] == [{"type": "TXT", "name": "_dmarc.contoso.com",
                                    "value": "v=DMARC1; p=quarantine; rua=mailto:dmarc@contoso.com; fo=1"}]
    assert "DMARC is monitoring only (p=none)" in p["headline"]


def test_dmarc_reject_and_quarantine_pass_partial_pct_warns():
    assert ctl(plan(make()), "dmarc-enforced")["status"] == "pass"
    q = ctl(plan(make({"email.dmarc.record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@contoso.com"})), "dmarc-enforced")
    assert q["status"] == "pass" and "end goal" in q["found"]
    c = ctl(plan(make({"email.dmarc.record": "v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@contoso.com"})), "dmarc-enforced")
    assert c["status"] == "warn" and "50%" in c["found"]
    assert c["fix"]["records"][0]["value"] == "v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com"


def test_dmarc_without_reports_never_invents_a_mailbox():
    c = ctl(plan(make({"email.dmarc.record": "v=DMARC1; p=reject"})), "dmarc-rua")
    assert (c["status"], c["severity"]) == ("fail", "warning")
    assert c["fix"]["records"] == [] and c["fix"]["tool"] == "dmarcbuild"


def test_dmarc_invalid_or_multiple_records_are_critical():
    bad = ctl(plan(make({"email.dmarc.record": "v=DMARC1; p=block"})), "dmarc-published")
    assert (bad["status"], bad["severity"]) == ("fail", "critical")
    extra = {"dmarc": {"record": "v=DMARC1; p=reject", "source": D, "inherited": False, "tags": {"v": "DMARC1", "p": "reject"},
                       "findings": [{"severity": "critical", "title": "Multiple DMARC records"}]}}
    multi = ctl(plan(make(), extra), "dmarc-published")
    assert multi["status"] == "fail" and "More than one" in multi["found"]


def test_dmarc_lookup_failure_is_unknown_not_missing():
    extra = {"dmarc": {"record": None, "source": None, "inherited": False, "tags": {},
                       "findings": [{"severity": "warning", "title": "DMARC lookup failed"}]}}
    p = plan(make({"email.dmarc": NO_DMARC}), extra)
    assert ctl(p, "dmarc-published")["status"] == "unknown"


def test_subdomain_policy_weaker_than_p_is_an_optional_warning():
    p = plan(make({"email.dmarc.record": "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@contoso.com"}))
    c = ctl(p, "dmarc-sp")
    assert (c["status"], c["optional"]) == ("warn", True)
    assert c["fix"]["records"][0]["value"] == "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@contoso.com"
    assert p["severity"] == "ok" and p["summary"]["score"] == 100
    assert p["headline"].endswith("including every required one. Optional next: sp=reject for subdomains.")


# ------------------------------------------------------------------ SPF
def test_spf_missing_is_critical_with_platform_record():
    p = plan(make({"email.spf": NO_SPF}))
    c = ctl(p, "spf-valid")
    assert (c["status"], c["severity"], c["priority"]) == ("fail", "critical", 1)
    assert c["fix"]["records"] == [{"type": "TXT", "name": D, "value": "v=spf1 include:spf.protection.outlook.com ~all"}]
    assert ctl(p, "spf-lookups")["status"] == "na"
    assert ctl(p, "spf-all")["status"] == "fail" and ctl(p, "spf-all")["priority"] == 2
    assert p["headline"].endswith("Fix first: no SPF record.")


def test_spf_over_ten_lookups_is_critical():
    issues = [{"severity": "critical", "title": "Too many DNS lookups: 12/10 (PermError)"}]
    p = plan(make({"email.spf.lookups": 12, "email.spf.issues": issues}))
    c = ctl(p, "spf-lookups")
    assert (c["status"], c["severity"], c["priority"]) == ("fail", "critical", 1)
    assert ctl(p, "spf-valid")["status"] == "pass"  # the lookup limit has its own control
    assert "SPF over the 10-lookup limit" in p["headline"]
    near = ctl(plan(make({"email.spf.lookups": 10})), "spf-lookups")
    assert (near["status"], near["severity"]) == ("warn", "warning")


@pytest.mark.parametrize("record, status, severity, fixed", [
    ("v=spf1 include:spf.protection.outlook.com +all", "fail", "critical", "v=spf1 include:spf.protection.outlook.com ~all"),
    ("v=spf1 include:spf.protection.outlook.com ?all", "fail", "warning", "v=spf1 include:spf.protection.outlook.com ~all"),
    ("v=spf1 include:spf.protection.outlook.com", "fail", "warning", "v=spf1 include:spf.protection.outlook.com ~all"),
    ("v=spf1 include:spf.protection.outlook.com ~all", "pass", "ok", None),
])
def test_spf_ending(record, status, severity, fixed):
    c = ctl(plan(make({"email.spf.record": record})), "spf-all")
    assert (c["status"], c["severity"]) == (status, severity)
    if fixed:
        assert c["fix"]["records"] == [{"type": "TXT", "name": D, "value": fixed}]


def test_spf_ending_followed_through_redirect():
    tree = {"domain": D, "record": "v=spf1 redirect=_spf.contoso.com", "terms": [
        {"raw": "redirect=_spf.contoso.com", "kind": "modifier", "name": "redirect", "value": "_spf.contoso.com"}],
        "redirect": {"domain": "_spf.contoso.com", "record": "v=spf1 include:spf.protection.outlook.com +all", "terms": [
            {"raw": "include:spf.protection.outlook.com", "kind": "mechanism", "mechanism": "include", "qualifier": "+"},
            {"raw": "+all", "kind": "mechanism", "mechanism": "all", "qualifier": "+"}]}}
    extra = {"spf": {"record": "v=spf1 redirect=_spf.contoso.com", "tree": tree, "lookup_count": 3,
                     "includes": ["_spf.contoso.com", "spf.protection.outlook.com"], "findings": []}}
    c = ctl(plan(make(), extra), "spf-all")
    assert (c["status"], c["severity"]) == ("fail", "critical")
    assert "redirect=_spf.contoso.com" in c["found"]
    assert c["fix"]["records"] == []  # rewriting the root record would disable the redirect


def test_multiple_spf_records_offer_the_merged_record():
    extra = {"spf": {"record": "v=spf1 include:spf.protection.outlook.com -all", "multiple": True,
                     "merged": {"record": "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all", "lookups": 4},
                     "tree": {"domain": D, "terms": [], "permerror": True}, "lookup_count": 4,
                     "includes": ["spf.protection.outlook.com", "_spf.google.com"],
                     "findings": [{"severity": "critical", "title": "2 SPF records published: SPF fails for every sender"}]}}
    c = ctl(plan(make(), extra), "spf-valid")
    assert (c["status"], c["severity"]) == ("fail", "critical")
    assert c["fix"]["records"][0]["value"] == "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all"


def test_spf_missing_platform_include_warns():
    p = plan(make({"email.spf.record": "v=spf1 ip4:198.51.100.7 -all", "email.spf.includes": []}))
    c = ctl(p, "spf-valid")
    assert c["status"] == "warn" and "spf.protection.outlook.com" in c["found"]
    assert c["fix"]["params"] == {"d": D, "add": "include:spf.protection.outlook.com"}


# ------------------------------------------------------------------ DKIM
def test_dkim_missing_on_microsoft_365_gives_the_dkim_commands():
    c = ctl(plan(make({"email.dkim": []})), "dkim")
    assert (c["status"], c["severity"], c["priority"]) == ("fail", "warning", 1)
    assert c["fix"]["commands"] == [DKIM_GET, DKIM_ENABLE, DKIM_NEW]
    assert c["fix"]["records"] == []  # the CNAME targets are tenant-specific


def test_dkim_cnames_published_but_signing_off():
    cname = {"cname": "selector1-contoso-com._domainkey.contoso.onmicrosoft.com", "bits": None, "revoked": False,
             "error": "CNAME exists but the target has no DKIM key"}
    extra = {"dkim": {"selector1": {"selector": "selector1", **cname}, "selector2": {"selector": "selector2", **cname}, "google": None}}
    c = ctl(plan(make({"email.dkim": []}), extra), "dkim")
    assert c["status"] == "fail" and "isn't turned on" in c["found"]
    assert c["fix"]["commands"] == [DKIM_GET, DKIM_ENABLE]


def test_dkim_1024_bit_key_warns():
    c = ctl(plan(make({"email.dkim": [{"selector": "selector1", "bits": 1024}]})), "dkim")
    assert (c["status"], c["severity"]) == ("warn", "warning")
    assert "Rotate-DkimSigningConfig -Identity contoso.com -KeySize 2048" in c["fix"]["commands"]


def test_dkim_behind_a_gateway_is_a_warning():
    c = ctl(plan(make({"email.dkim": [], "email.gateways": ["Mimecast"]})), "dkim")
    assert c["status"] == "warn" and "Mimecast" in c["found"]


def test_dkim_google_workspace_steps():
    p = plan(make({"email.mail_host": "Google Workspace", "email.dkim": [], "identity": {},
                   "email.mx": [{"host": "smtp.google.com", "provider": "Google", "provider_kind": "mailbox"}],
                   "email.spf.record": "v=spf1 include:_spf.google.com ~all", "email.spf.includes": ["_spf.google.com"]}))
    c = ctl(p, "dkim")
    assert c["status"] == "fail" and "google" in c["title"].lower()
    steps = " ".join(c["fix"]["steps"])
    for part in ("Authenticate email", "2048-bit", "google._domainkey.contoso.com", "Start authentication"):
        assert part in steps
    assert "m365" not in {a["id"] for a in p["areas"]}


# ------------------------------------------------------------------ parked / non-sending
def test_parked_domain_without_mx_needs_the_lockdown_records():
    p = plan(make(PARKED))
    assert (p["sends_mail"], p["receives_mail"], p["mail_platform"]) == (False, False, None)
    assert p["headline"].startswith("contoso.com is a parked domain and passes")
    spf = ctl(p, "spf-valid")
    assert (spf["status"], spf["severity"], spf["fix"]["tool"]) == ("fail", "critical", "parked")
    assert spf["fix"]["records"] == [{"type": "TXT", "name": D, "value": "v=spf1 -all"}]
    dmarc = ctl(p, "dmarc-published")
    assert dmarc["fix"]["records"] == [{"type": "TXT", "name": "_dmarc.contoso.com",
                                        "value": "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"}]
    assert dmarc["fix"]["tool"] == "parked"
    mx = ctl(p, "null-mx")
    assert mx["status"] == "fail" and mx["fix"]["records"] == [{"type": "MX", "name": D, "value": "0 ."}]
    for cid in ("dkim", "spf-lookups", "spf-all", "mta-sts", "tls-rpt", "inbound-filtering"):
        assert ctl(p, cid)["status"] == "na", cid


def test_parked_domain_locked_down_passes():
    p = plan(make(PARKED, **{"email.null_mx": True, "email.mail_host": "none (null MX)",
                            "email.spf": {"record": "v=spf1 -all", "lookups": 0, "includes": [], "issues": []},
                            "email.dmarc.record": "v=DMARC1; p=reject"}))
    for cid in ("spf-valid", "dmarc-published", "dmarc-enforced", "null-mx"):
        assert ctl(p, cid)["status"] == "pass", cid
    assert ctl(p, "dkim")["status"] == "na"
    assert "parked domain" in p["subline"]


def test_parked_domain_quarantine_is_not_enough():
    p = plan(make(PARKED, **{"email.null_mx": True, "email.spf": {"record": "v=spf1 -all", "lookups": 0, "includes": [], "issues": []},
                            "email.dmarc.record": "v=DMARC1; p=quarantine"}))
    c = ctl(p, "dmarc-enforced")
    assert c["status"] == "fail" and c["title"] == "DMARC policy is p=reject"
    assert c["fix"]["records"][0]["value"] == "v=DMARC1; p=reject"


def test_send_only_domain_is_not_parked():
    p = plan(make({"email.mx": [], "email.mail_host": "none", "email.mta_sts": None, "email.tls_rpt": False,
                   "email.spf": {"record": "v=spf1 include:sendgrid.net ~all", "lookups": 2, "includes": ["sendgrid.net"], "issues": []}}))
    assert p["sends_mail"] and not p["receives_mail"]
    assert "null-mx" not in ids(p) and ctl(p, "mta-sts")["status"] == "na"
    assert ctl(p, "dkim")["status"] in ("pass", "warn", "fail")


def test_receive_only_domain_with_spf_minus_all():
    p = plan(make({"email.spf.record": "v=spf1 -all", "email.dkim": []}))
    assert not p["sends_mail"] and p["receives_mail"]
    assert ctl(p, "spf-valid")["status"] == "pass" and "still receives mail" in ctl(p, "spf-valid")["found"]
    assert ctl(p, "dkim")["status"] == "na"


def test_mx_lookup_failure_never_classifies_as_parked():
    p = plan(make(PARKED), {"mx_status": "timeout"})
    assert p["sends_mail"] and "null-mx" not in ids(p)
    assert ctl(p, "mta-sts")["status"] == "unknown"


# ------------------------------------------------------------------ DNS hygiene and exposure
def test_dangling_cname_is_critical_and_commands_stay_safe():
    bad = host("shop", "apps", "dangling", cname='contoso-shop.azurewebsites.net"; Start-Process calc; "')
    p = plan(make({"infrastructure.hosts": [WWW, bad]}))
    c = ctl(p, "dangling-cname")
    assert (c["status"], c["severity"], c["priority"]) == ("fail", "critical", 1)
    assert "shop.contoso.com →" in c["found"]
    assert c["fix"]["commands"] == ["Resolve-DnsName -Name shop.contoso.com -Type CNAME -Server 1.1.1.1"]
    assert "a dangling CNAME (shop.contoso.com)" in p["headline"]


def test_private_ip_in_public_dns_is_critical():
    c = ctl(plan(make({"infrastructure.hosts": [host("intranet", "apps", "private", ips=["10.0.0.5"])]})), "private-ips")
    assert (c["status"], c["severity"]) == ("fail", "critical") and "10.0.0.5" in c["found"]


def test_legacy_skype_records_are_an_info_manual_check():
    sip = host("sip", "m365", "saas", cname="sipdir.online.lync.com", service="Skype for Business Online / Teams (legacy record)")
    c = ctl(plan(make({"infrastructure.hosts": [sip]})), "legacy-sfb")
    assert (c["status"], c["severity"], c["optional"]) == ("manual", "info", True)


def test_remote_desktop_on_an_office_connection_is_critical():
    rd = host("remote", "remote", "onprem", ips=["198.51.100.20"], owner="Example Cable Business")
    p = plan(make({"infrastructure.hosts": [rd]}))
    c = ctl(p, "remote-access")
    assert (c["status"], c["severity"], c["priority"]) == ("fail", "critical", 1)
    assert c["fix"]["tool"] == "ip" and c["fix"]["params"] == {"t": "198.51.100.20"}
    own = ctl(plan(make({"infrastructure.hosts": [host("rdg", "remote", "own", ips=["198.51.100.21"])]})), "remote-access")
    assert own["status"] == "manual"
    vendor = ctl(plan(make({"infrastructure.hosts": [host("citrix", "remote", "saas", service="Citrix Cloud")]})), "remote-access")
    assert vendor["status"] == "pass"


def test_vpn_and_owa_names():
    vpn = host("vpn", "vpn", "onprem", ips=["198.51.100.30"], purpose="VPN")
    owa = host("owa", "mail", "onprem", ips=["198.51.100.31"])
    p = plan(make({"infrastructure.hosts": [vpn, owa]}))
    assert ctl(p, "vpn")["status"] == "manual"
    assert ctl(p, "selfhosted-mail")["status"] == "fail" and ctl(p, "selfhosted-mail")["severity"] == "warning"
    assert ctl(plan(make()), "vpn")["status"] == "na"
    webmail = host("webmail", "mail", "unknown", ips=["198.51.100.32"])
    assert ctl(plan(make({"infrastructure.hosts": [webmail]})), "selfhosted-mail")["status"] == "pass"


# ------------------------------------------------------------------ website
def test_https_without_hsts():
    p = plan(make({"website.hsts": False}))
    assert ctl(p, "https")["status"] == "pass"
    c = ctl(p, "hsts")
    assert (c["status"], c["severity"]) == ("fail", "warning")
    assert c["fix"]["commands"] == ["curl.exe -sIL https://www.contoso.com/"]
    # A site that redirects to another domain: the command still names only the client's domain.
    other = ctl(plan(make({"website.hsts": False, "website.url": "https://www.fabrikam.com/"})), "hsts")
    assert other["fix"]["commands"] == ["curl.exe -sIL https://contoso.com/"]
    assert "no HSTS on the website" in p["headline"]


def test_plain_http_site_and_no_site():
    p = plan(make({"website.url": "http://contoso.com/", "website.https": False, "website.hsts": False}))
    assert ctl(p, "https")["status"] == "fail"
    assert ctl(p, "hsts")["status"] == "fail" and "no HSTS" not in p["headline"]  # follows from no HTTPS
    p = plan(make({"website": {"url": None, "error": None}}))
    assert {ctl(p, c)["status"] for c in ("https", "hsts", "security-txt")} == {"na"}


def test_security_txt_template_expires_within_a_year():
    c = ctl(plan(make({"website.security_txt": False})), "security-txt")
    assert (c["status"], c["optional"]) == ("fail", True)
    assert "Contact: mailto:security@contoso.com" in c["fix"]["commands"][0]
    assert "Expires: 2027-10-25T00:00:00Z" in c["fix"]["commands"][0]


# ------------------------------------------------------------------ domain & registrar
def test_transfer_lock():
    c = ctl(plan(make({"domain_info.registration.statuses": ["active"]})), "transfer-lock")
    assert (c["status"], c["severity"]) == ("fail", "warning")
    assert ctl(plan(make({"domain_info.registration.statuses": []})), "transfer-lock")["status"] == "unknown"
    uk = plan(make({"domain": "contoso.co.uk", "domain_info.registration.statuses": []}))
    assert ctl(uk, "transfer-lock")["status"] == "na"


@pytest.mark.parametrize("days, status, severity", [
    (-3, "fail", "critical"), (12, "fail", "critical"), (45, "warn", "warning"), (240, "pass", "ok"), (None, "unknown", "info"),
])
def test_expiry_thresholds(days, status, severity):
    p = plan(make({"domain_info.registration.days_left": days}))
    c = ctl(p, "expiry")
    assert (c["status"], c["severity"]) == (status, severity)
    if days == 12:
        assert p["headline"].endswith("Fix first: the domain expires in 12 days.")


def test_caa_fix_uses_the_certificate_issuer_or_a_template():
    c = ctl(plan(make({"domain_info.caa": []})), "caa")
    assert (c["status"], c["optional"]) == ("fail", True)
    assert c["fix"]["records"] == [{"type": "CAA", "name": D, "value": '0 issue "letsencrypt.org"'}]
    t = ctl(plan(make({"domain_info.caa": [], "website.tls.cert.issuer": "CN=Fabrikam Private CA"})), "caa")
    assert [r["value"] for r in t["fix"]["records"]] == ['0 issue "letsencrypt.org"', '0 issue "digicert.com"']
    assert any("Template" in s for s in t["fix"]["steps"])
    forbid = ctl(plan(make({"domain_info.caa": []}), {"caa": [{"flags": 0, "tag": "issue", "value": ";"}]}), "caa")
    assert forbid["status"] == "pass"
    parked = ctl(plan(make(PARKED, **{"domain_info.caa": [], "website": {"url": None}})), "caa")
    assert parked["fix"]["records"] == [{"type": "CAA", "name": D, "value": '0 issue ";"'}]


def test_broken_dnssec_is_a_required_fix():
    p = plan(make({"domain_info.registration.dnssec": False, "domain_info.registration.severity": "critical",
                   "domain_info.registration.headline": "DNSSEC is broken for contoso.com: the registry has a DS record but the zone isn't signed."}))
    c = ctl(p, "dnssec")
    assert c["status"] == "fail" and not c["optional"] and "broken DNSSEC" in p["headline"]
    assert ctl(plan(make({"domain_info.registration.dnssec": False})), "dnssec")["optional"] is True


# ------------------------------------------------------------------ mail transport
def test_mta_sts_states():
    p = plan(make({"email.mta_sts": None}))
    c = ctl(p, "mta-sts")
    assert (c["status"], c["optional"], c["fix"]["tool"]) == ("fail", True, "mtasts")
    assert c["fix"]["records"] == [{"type": "TXT", "name": "_mta-sts.contoso.com", "value": "v=STSv1; id=20261026120000"}]
    assert "mx: contoso-com.mail.protection.outlook.com" in " ".join(c["fix"]["steps"])
    assert ctl(plan(make({"email.mta_sts": "testing"})), "mta-sts")["status"] == "warn"
    broken = ctl(plan(make({"email.mta_sts": None}), {"mta_sts_txt": {"record": "v=STSv1; id=1"}}), "mta-sts")
    assert broken["status"] == "warn" and "couldn't be fetched" in broken["found"]
    assert ctl(plan(make({"email.tls_rpt": False})), "tls-rpt")["fix"]["tool"] == "mtasts"


def test_inbound_filtering():
    assert ctl(plan(make({"email.gateways": ["Mimecast"]})), "inbound-filtering")["found"].startswith("Filtered by Mimecast")
    selfhosted = make({"email.mail_host": "self-hosted on-premises (Example Cable Business)", "identity": {},
                       "email.mx": [{"host": "mail.contoso.com", "provider": None, "provider_kind": None}]})
    c = ctl(plan(selfhosted), "inbound-filtering")
    assert (c["status"], c["severity"]) == ("manual", "info")
    assert ctl(plan(selfhosted), "selfhosted-mail")["status"] == "fail"


# ------------------------------------------------------------------ Microsoft 365 manual checks
def test_m365_manual_checks_carry_the_exact_commands():
    p = plan(make())
    m365 = [c for c in p["controls"] if c["area"] == "m365"]
    assert m365 and all(c["status"] == "manual" and c["priority"] in (2, 3) and c["severity"] == "info" for c in m365)
    commands = [cmd for c in m365 for cmd in c["fix"]["commands"]]
    for cmd in M365_COMMANDS:
        assert cmd in commands
    gw = plan(make({"email.gateways": ["Mimecast"]}))
    assert "m365-gateway" in ids(gw) and "m365-gateway" not in ids(p)


def test_no_m365_area_without_a_real_tenant():
    google = {"email.mail_host": "Google Workspace", "email.mx": [{"host": "smtp.google.com", "provider": "Google", "provider_kind": "mailbox"}]}
    assert "m365" not in {a["id"] for a in plan(make(google, identity={}))["areas"]}
    internal = make(google, identity={"tenant_id": "00000000-0000-0000-0000-000000000002", "namespace": "Federated",
                                      "idp": "Microsoft (internal)"})
    assert not [c for c in plan(internal)["controls"] if c["area"] == "m365"]


# ------------------------------------------------------------------ scoring and headline
def test_score_counts_warn_as_half_and_ignores_optional():
    p = plan(make({"email.spf.lookups": 10, "email.mta_sts": None}))
    # 16 required controls evaluated: 15 pass + 1 warn -> (15 + 0.5) / 16 = 96.9; the optional MTA-STS fail doesn't count.
    assert p["summary"]["score"] == 97
    assert p["summary"]["total"] == p["summary"]["pass"] + p["summary"]["fail"] + p["summary"]["warn"]
    assert p["severity"] == "warning"


def test_headline_names_the_two_most_important_fixes():
    issues = [{"severity": "critical", "title": "Too many DNS lookups: 12/10 (PermError)"}]
    p = plan(make({"email.dmarc": NO_DMARC, "email.spf.lookups": 12, "email.spf.issues": issues, "website.hsts": False}))
    assert p["headline"].endswith("Fix first: no DMARC record, SPF over the 10-lookup limit.")


# ------------------------------------------------------------------ robustness and safety
def test_missing_sources_become_unknown_not_errors():
    p = plan_from({"domain": "Contoso.COM"}, {}, now=NOW)
    assert p["domain"] == D
    for cid in ("spf-valid", "dmarc-published", "dkim", "expiry", "dangling-cname", "https", "remote-access"):
        assert ctl(p, cid)["status"] == "unknown", cid
    assert p["summary"]["score"] is None and p["severity"] == "info"
    json.dumps(p)
    junk = {"domain": D, "email": "x", "identity": [], "website": 3, "domain_info": {"registration": "y"}, "infrastructure": None}
    json.dumps(plan_from(junk, {"spf": "z", "dmarc": [], "dkim": 1, "caa": "q"}, now=NOW))
    bad_url = plan(make({"website.url": "https://[malformed", "website.hsts": False}))
    assert ctl(bad_url, "hsts")["status"] == "fail" and ctl(bad_url, "hsts")["fix"]["commands"] == ["curl.exe -sIL https://contoso.com/"]
    with pytest.raises(ValueError):
        plan_from({"domain": "not a domain"}, {})


def test_commands_never_contain_untrusted_values():
    evil = "$(Start-Process calc)"
    hosts = [host("shop", "apps", "dangling", cname=f"x.example.net{evil}"), host("remote", "remote", "onprem", ips=["198.51.100.20"], owner=evil),
             host("intranet", "apps", "private", ips=["10.0.0.5"]), host("vpn", "vpn", "onprem", ips=["198.51.100.30"], owner=evil)]
    p = plan(make({"infrastructure.hosts": hosts, "email.dkim": [], "email.gateways": [f"Gateway{evil}"], "email.dmarc.record": "v=DMARC1; p=none",
                   "domain_info.registration.registrar": evil, "domain_info.registration.statuses": ["active"], "domain_info.caa": [],
                   "domain_info.dns_host": evil, "website.hsts": False, "website.security_txt": False, "email.mta_sts": None,
                   "website.url": f"https://www.contoso.com/{evil}", "email.mx": [{"host": f"mx.contoso.com{evil}", "provider": None}]}))
    commands = [cmd for c in p["controls"] for cmd in (c.get("fix") or {}).get("commands", [])]
    assert commands and not [cmd for cmd in commands if "calc" in cmd]
    # Every domain-like token in a command is the validated domain or one of its sub-names.
    for cmd in commands:
        for name in re.findall(r"[a-z0-9_.-]+\.(?:com|net)\b", cmd):
            assert name == D or name.endswith("." + D) or name.endswith("@" + D), (name, cmd)


def test_build_plan_is_fail_soft_and_strips_www(monkeypatch):
    seen = {}

    def fake_discover(domain, ct=False):
        seen["domain"], seen["ct"] = domain, ct
        return make()

    def boom(*a, **k):
        raise RuntimeError("source down")

    monkeypatch.setattr(harden, "discover", fake_discover)
    monkeypatch.setattr(harden, "make_resolver", lambda *a, **k: None)
    for name in ("analyze_spf", "check_dmarc", "_platform_dkim", "_caa", "_mx_status", "_mta_sts_txt"):
        monkeypatch.setattr(harden, name, boom)
    p = harden.build_plan("https://www.Contoso.com/contact")
    assert seen == {"domain": D, "ct": False}
    assert p["domain"] == D and ctl(p, "spf-valid")["status"] == "pass"


def test_route_returns_the_plan(monkeypatch):
    monkeypatch.setattr(harden, "discover", lambda domain, ct=False: make())
    for name in ("analyze_spf", "check_dmarc", "_platform_dkim", "_caa", "_mx_status", "_mta_sts_txt"):
        monkeypatch.setattr(harden, name, lambda *a, **k: None)
    p = harden.harden_route("contoso.com")
    assert p["domain"] == D and p["controls"]
    # Additive: an id the page can use to save the plan (only when result saving is available).
    assert set(p) - {"result_id"} == {"domain", "generated", "severity", "headline", "subline", "summary", "sends_mail",
                                      "receives_mail", "mail_platform", "areas", "controls"}
    assert isinstance(p.get("result_id", ""), str)


def test_route_turns_bad_input_into_400(monkeypatch):
    with pytest.raises(HTTPException) as exc:
        harden.harden_route("not a domain!")
    assert exc.value.status_code == 400

    def nxdomain(domain, ct=False):
        raise ValueError(f"{domain} doesn't exist in DNS")

    monkeypatch.setattr(harden, "discover", nxdomain)
    for name in ("analyze_spf", "check_dmarc", "_platform_dkim", "_caa", "_mx_status", "_mta_sts_txt"):
        monkeypatch.setattr(harden, name, lambda *a, **k: None)
    with pytest.raises(HTTPException) as exc:
        harden.harden_route("fabrikam.com")
    assert exc.value.status_code == 400 and "doesn't exist" in exc.value.detail


def test_route_is_mounted():
    from app import main
    assert "harden" not in main.MODULE_ERRORS
    assert main.app.url_path_for("harden_route", domain="contoso.com") == "/api/harden/contoso.com"
