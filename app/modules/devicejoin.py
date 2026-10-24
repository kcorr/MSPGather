"""Device Join Analyzer: reads `dsregcmd /status` output and explains the join
state (Entra joined, hybrid joined, pending, registered), the PRT / SSO state
and why a hybrid join is failing.

Only field meanings we are confident about are explained. Error codes are
looked up in the shared Windows knowledge base (wincodes.py); anything not
there is reported as "not in the knowledge base" and linked to the Error Code
Lookup tool by the frontend.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..core.http import run
from ..core import cmdsafe
from . import wincodes as kb

router = APIRouter()

MAX_INPUT = 200_000
PRT_STALE_HOURS = 4

# Known section titles -> internal id. Matching is by substring, lower case.
SECTIONS = [
    ("device state", "device_state"),
    ("device details", "device_details"),
    ("tenant details", "tenant_details"),
    ("user state", "user_state"),
    ("sso state", "sso_state"),
    ("diagnostic data", "diagnostic_data"),
    ("ie proxy", "ie_proxy"),
    ("winhttp", "winhttp_proxy"),
    ("ngc prerequisite", "ngc_prereq"),
    ("work account", "work_account"),
]
SECTION_TITLES = {
    "device_state": "Device State", "device_details": "Device Details", "tenant_details": "Tenant Details",
    "user_state": "User State", "sso_state": "SSO State", "diagnostic_data": "Diagnostic Data",
    "ie_proxy": "IE Proxy Config (current user)", "winhttp_proxy": "WinHTTP Default Proxy Config",
    "ngc_prereq": "Ngc Prerequisite Check (Windows Hello for Business)", "work_account": "Work Account",
    "other": "Other",
}

PRE_JOIN_TESTS = [
    ("adconnectivitytest", "AD Connectivity Test", "Can the device reach a domain controller?"),
    ("adconfigurationtest", "AD Configuration Test", "Was the service connection point (SCP) read from AD, with the Entra tenant details?"),
    ("drsdiscoverytest", "DRS Discovery Test", "Can the device discover the Entra device registration service (enterpriseregistration.windows.net)?"),
    ("drsconnectivitytest", "DRS Connectivity Test", "Can the device connect to the device registration service?"),
    ("tokenacquisitiontest", "Token Acquisition Test", "Can the device get an Entra ID token for the join (federated path)?"),
]

_TASK = 'Start-ScheduledTask -TaskPath "\\Microsoft\\Windows\\Workplace Join\\" -TaskName "Automatic-Device-Join"'
_AAD_LOG = ("Get-WinEvent -LogName 'Microsoft-Windows-AAD/Operational' -MaxEvents 50 |\n"
            "  Where-Object LevelDisplayName -in 'Error','Warning' | Format-List TimeCreated, Id, Message")
_DRS_TCP = "Test-NetConnection enterpriseregistration.windows.net -Port 443   # direct TCP only; does not use the proxy"
_SCP = ('Get-ADObject "CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,'
        '$((Get-ADRootDSE).configurationNamingContext)" -Properties keywords | Select-Object -ExpandProperty keywords')


def _f(sev: str, title: str, detail: str = "", codes: list | None = None) -> dict:
    d = {"severity": sev, "title": title, "detail": detail}
    if codes:
        d["codes"] = codes
    return d


def _norm(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


# --------------------------------------------------------------------- parsing
def parse_dsreg(raw: str) -> dict:
    """Loose parser: section headers ('| Device State |' or a bare known title)
    and 'Key : Value' lines. Returns {sections: {id: [(key, value)]}, order}."""
    sections: dict[str, list] = {}
    order: list[str] = []
    cur = "other"
    for line in raw.splitlines():
        s = line.strip().strip("﻿")
        if not s or re.fullmatch(r"[+\-=|\s]+", s):
            continue
        m = re.fullmatch(r"\|\s*(.+?)\s*\|", s)
        title = m.group(1) if m else (s if ":" not in s and len(s) < 60 else None)
        if title:
            tl = title.lower()
            sid = next((i for t, i in SECTIONS if t in tl), None)
            if sid:
                cur = sid
                if sid not in order:
                    order.append(sid)
                continue
            if m:  # unknown boxed header
                cur = "other"
                continue
        if " : " in s:
            k, v = s.split(" : ", 1)
        elif re.match(r"^[A-Za-z][A-Za-z0-9 \-]{1,40}\s*:(\s|$)", s):
            k, v = s.split(":", 1)
        else:
            continue
        k, v = k.strip(), v.strip()
        if not k or "/" in k:
            continue
        sections.setdefault(cur, []).append((k, v))
        if cur not in order:
            order.append(cur)
    return {"sections": sections, "order": order}


class _Doc:
    def __init__(self, parsed: dict):
        self.sections = parsed["sections"]
        self.order = parsed["order"]
        self.idx: dict[str, dict[str, str]] = {}
        for sid, rows in self.sections.items():
            d = self.idx.setdefault(sid, {})
            for k, v in rows:
                d.setdefault(_norm(k), v)

    def get(self, key: str, section: str | None = None) -> str | None:
        nk = _norm(key)
        if section:
            return self.idx.get(section, {}).get(nk)
        for sid in self.order:
            if nk in self.idx.get(sid, {}):
                return self.idx[sid][nk]
        return None

    def yes(self, key: str, section: str | None = None) -> bool | None:
        v = self.get(key, section)
        if v is None:
            return None
        return v.strip().upper().startswith("YES")

    def has(self, section: str) -> bool:
        return section in self.sections


def _parse_time(v: str | None) -> datetime | None:
    if not v:
        return None
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})", v)
    if not m:
        return None
    try:
        return datetime(*map(int, m.groups()), tzinfo=timezone.utc)
    except ValueError:
        return None


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _lc(s: str) -> str:
    """Lower-case the first letter for use mid-sentence, unless it starts an acronym (WinHTTP, PRT)."""
    return s if len(s) > 1 and s[1].isupper() else s[:1].lower() + s[1:]


def _human(seconds: float) -> str:
    s = int(abs(seconds))
    if s < 90:
        return f"{s} seconds"
    if s < 3600:
        m = round(s / 60)
        return f"{m} minute{'s' if m != 1 else ''}"
    if s < 86400:
        h, m = divmod(s // 60, 60)
        return f"{h} hour{'s' if h != 1 else ''}" + (f" {m} min" if m else "")
    d, h = divmod(s // 3600, 24)
    return f"{d} day{'s' if d != 1 else ''}" + (f" {h} h" if h else "")


# ------------------------------------------------------------------ error codes
_HEX_RE = re.compile(r"0x[0-9a-fA-F]{8}\b")


def code_info(hexcode: str) -> dict:
    """Look a code up in the shared knowledge base (read-only)."""
    v = int(hexcode, 16)
    disp = f"0x{v:08X}"
    e = kb.HRESULT.get(v)
    if e and e.get("meaning"):
        return {"code": disp, "known": True, "name": e.get("name"), "meaning": e["meaning"]}
    if (v >> 16) == 0x8007:
        w = kb.WIN32.get(v & 0xFFFF)
        if w:
            return {"code": disp, "known": True, "name": w.get("name"), "meaning": w["meaning"], "win32": v & 0xFFFF}
    nt = kb.NTSTATUS.get(v)
    if nt:
        return {"code": disp, "known": True, "name": nt.get("name"), "meaning": nt["meaning"]}
    return {"code": disp, "known": False, "name": None, "meaning": None}


def _codes_in(text: str | None) -> list[dict]:
    seen, out = set(), []
    for c in _HEX_RE.findall(text or ""):
        c2 = c.lower()
        if c2 not in seen and int(c, 16) != 0:
            seen.add(c2)
            out.append(code_info(c))
    return out


def _code_label(ci: dict) -> str:
    return f"{ci['code']}{' ' + ci['name'] if ci.get('name') else ''}"


# -------------------------------------------------------------------- analysis
def analyze(raw: str) -> dict:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Paste the output of dsregcmd /status.")
    if len(raw) > MAX_INPUT:
        raise ValueError("That's too long for dsregcmd /status output (limit 200 KB).")
    parsed = parse_dsreg(raw)
    doc = _Doc(parsed)
    if doc.get("AzureAdJoined") is None and doc.get("DomainJoined") is None and doc.get("WorkplaceJoined") is None:
        raise ValueError("This doesn't look like dsregcmd /status output: no AzureAdJoined, DomainJoined or WorkplaceJoined line was found. "
                         "Run 'dsregcmd /status' in a normal (non-elevated) command prompt as the affected user and paste everything.")

    F: list[dict] = []
    steps: list[dict] = []
    aadj = doc.yes("AzureAdJoined") or False
    dj = doc.yes("DomainJoined") or False
    ej = doc.yes("EnterpriseJoined") or False
    wpj = doc.yes("WorkplaceJoined") or False
    device = doc.get("Device Name") or None
    dev_ph = cmdsafe.host_label((device or "PC01").split(".")[0])
    tenant_name = doc.get("TenantName") or doc.get("WorkplaceTenantName")
    tenant_id = doc.get("TenantId") or doc.get("WorkplaceTenantId")
    device_id = doc.get("DeviceId") or doc.get("WorkplaceDeviceId")

    client_time = _parse_time(doc.get("Client Time", "diagnostic_data"))
    ref = client_time or datetime.now(timezone.utc)
    ref_label = "the Client Time in the output" if client_time else "now (the output has no Client Time, so if it was captured earlier, ages are overstated)"

    if aadj and dj:
        join, join_label = "hybrid", "Hybrid Entra joined"
    elif aadj:
        join, join_label = "entra", "Entra joined"
    elif dj:
        join, join_label = "domain", "Domain joined only (not hybrid joined)"
    elif wpj:
        join, join_label = "registered", "Entra registered (workplace joined)"
    elif ej:
        join, join_label = "enterprise", "Enterprise joined (on-premises DRS)"
    else:
        join, join_label = "none", "Not joined"

    # ---------------------------------------------------------------- device health
    auth = (doc.get("DeviceAuthStatus") or "").upper()
    auth_failed = auth.startswith("FAIL")
    if aadj:
        if auth_failed:
            F.append(_f("critical", "Entra ID doesn't accept this device: DeviceAuthStatus is FAILED (device disabled or deleted in Entra ID)",
                        "The device still thinks it is joined, but its object in Entra ID is disabled or was deleted. Users get no PRT, no SSO and fail "
                        "device-based Conditional Access. Check the device in Entra ID: enable it if disabled, or re-register it if it was deleted."))
        elif auth.startswith("SUCCESS"):
            F.append(_f("ok", "Device is present and enabled in Entra ID (DeviceAuthStatus SUCCESS)"))
        elif auth:
            F.append(_f("warning", f"DeviceAuthStatus is {doc.get('DeviceAuthStatus')}",
                        "The device health check against Entra ID couldn't complete (often no connectivity to Entra ID at the time). Re-run dsregcmd /status when online."))

    tpm = doc.yes("TpmProtected")
    if aadj and tpm is False:
        F.append(_f("info", "Device keys are not protected by the TPM (TpmProtected NO)",
                    "The device's private key is stored in software instead of a TPM (common on VMs without a virtual TPM). It works, but the keys and PRT are "
                    "less protected. Windows Hello for Business and some policies may require a TPM."))
    keysign = (doc.get("KeySignTest") or "").upper()
    if keysign.startswith("FAIL"):
        F.append(_f("critical", "KeySignTest FAILED: the device keys are not healthy",
                    "Windows couldn't sign with the device key (TPM cleared or reset, or key lost). The device usually has to be re-registered: "
                    "dsregcmd /leave, then join again.", _codes_in(doc.get("KeySignTest"))))
    elif keysign.startswith("PASS"):
        F.append(_f("ok", "KeySignTest passed: the device key can sign"))

    validity = doc.get("DeviceCertificateValidity")
    cert_to = None
    if validity:
        times = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", validity)
        if len(times) >= 2:
            cert_to = _parse_time(times[1])
            if cert_to and cert_to < ref:
                F.append(_f("critical", f"Device certificate expired on {cert_to:%Y-%m-%d}",
                            "The device certificate is how the device proves its identity to Entra ID. Re-register the device."))

    # ------------------------------------------------------------------ SSO / PRT
    prt = doc.yes("AzureAdPrt")
    prt_update = _parse_time(doc.get("AzureAdPrtUpdateTime") or doc.get("PrtUpdateTime"))
    prt_expiry = _parse_time(doc.get("AzureAdPrtExpiryTime") or doc.get("PrtExpiryTime"))
    prt_auth = doc.get("AzureAdPrtAuthority")
    prt_age = (ref - prt_update).total_seconds() if prt_update else None
    prt_state = None  # ok / stale / expired / missing
    prt_codes: list[dict] = []
    attempt = doc.get("Attempt Status", "diagnostic_data")
    srv_desc = doc.get("Server Error Description", "diagnostic_data")
    srv_code = doc.get("Server Error Code", "diagnostic_data")
    aadsts = sorted(set(re.findall(r"AADSTS(\d{4,7})", f"{srv_desc or ''} {srv_code or ''}")))
    if aadj or (prt is not None and join != "domain"):
        if prt is False:
            prt_state = "missing"
            prt_codes = _codes_in(attempt)
            extra = ""
            if aadsts:
                extra = f" The last PRT attempt failed with AADSTS{aadsts[0]}: decode it with the Sign-in Error Decoder."
            elif prt_codes:
                extra = f" The last PRT attempt status was {prt_codes[0]['code']}."
            F.append(_f("critical", "No Primary Refresh Token (AzureAdPrt NO): SSO to Microsoft 365 and device-based Conditional Access will fail for this user",
                        "The PRT is the token Windows uses for single sign-on to Entra ID apps. Without it users get extra prompts and 'device not compliant / not "
                        "registered' blocks. Make sure dsregcmd was run as the affected user, NOT elevated as another account (the PRT is per user)." + extra,
                        prt_codes))
        elif prt:
            if prt_expiry and prt_expiry < ref:
                prt_state = "expired"
                F.append(_f("critical", f"The PRT expired {_human((ref - prt_expiry).total_seconds())} ago ({prt_expiry:%Y-%m-%d %H:%M} UTC)",
                            "Windows hasn't been able to renew the PRT. SSO will fail until the user signs in again with working connectivity to Entra ID. "
                            f"Ages are relative to {ref_label}."))
            elif prt_age is not None and prt_age > PRT_STALE_HOURS * 3600:
                prt_state = "stale"
                F.append(_f("warning", f"PRT last renewed {_human(prt_age)} ago (Windows normally renews it about every {PRT_STALE_HOURS} hours while in use)",
                            "A PRT that isn't renewing suggests Windows can't reach Entra ID (proxy, firewall, TLS inspection) or the device/user can't authenticate. "
                            f"Lock and unlock, then check again. Ages are relative to {ref_label}."))
            else:
                prt_state = "ok"
                F.append(_f("ok", "User has a Primary Refresh Token (AzureAdPrt YES)" + (f", renewed {_human(prt_age)} ago" if prt_age is not None and prt_age >= 0 else "")))
        if prt_auth and tenant_id and tenant_id.lower() not in prt_auth.lower() and re.search(r"[0-9a-f]{8}-", prt_auth.lower()):
            F.append(_f("info", "The PRT authority is a different tenant from the one the device is joined to",
                        f"AzureAdPrtAuthority is {prt_auth} but TenantId is {tenant_id}. The signed-in user may be from another tenant."))

    eprt = doc.yes("EnterprisePrt")
    if eprt:
        F.append(_f("info", "User also has an Enterprise PRT (AD FS)",
                    f"Federated SSO through AD FS{(' at ' + doc.get('EnterprisePrtAuthority')) if doc.get('EnterprisePrtAuthority') else ''} is available."))

    # ----------------------------------------------------------------- user state
    ngc = doc.yes("NgcSet")
    if aadj and ngc is False:
        pre = doc.get("PreReqResult")
        F.append(_f("info", "Windows Hello for Business isn't set up for this user (NgcSet NO)",
                    f"Only an issue if WHfB is expected.{(' The NGC prerequisite check says: ' + pre + '.') if pre else ''}"))
    wam = doc.yes("WamDefaultSet")
    if aadj and wam is False:
        F.append(_f("info", "WamDefaultSet is NO",
                    "No default Web Account Manager account is set for this user. This is expected if dsregcmd was run from an elevated prompt; otherwise the user "
                    "may get extra sign-in prompts in Office and other WAM-based apps."))
    if aadj and wpj:
        F.append(_f("info", "Device is joined AND has a registered work account (WorkplaceJoined YES)",
                    "A 'dual state' device. If the registered account is in the same tenant, remove it from Settings → Accounts → Access work or school, because "
                    "it can confuse which device identity Conditional Access sees."))

    # ---------------------------------------------------------------------- MDM
    mdm = doc.get("MdmUrl") or doc.get("WorkplaceMdmUrl")
    if aadj or wpj:
        if mdm:
            intune = "manage.microsoft.com" in mdm.lower()
            F.append(_f("info", f"MDM enrollment URL is present{' (Microsoft Intune)' if intune else ''}",
                        "Entra ID gave the device an MDM enrollment endpoint, so automatic MDM enrollment is configured for this join. Check the device in "
                        "Intune to confirm it actually enrolled."))
        elif doc.has("tenant_details") and aadj:
            F.append(_f("info", "No MdmUrl in Tenant Details",
                        "Automatic MDM (e.g. Intune) enrollment wasn't offered for this device or user (MDM user scope in Entra ID → Mobility). "
                        "This doesn't prove the device isn't enrolled by another method."))

    # -------------------------------------------------------------------- proxy
    ie_rows = doc.idx.get("ie_proxy", {})
    wh_rows = doc.idx.get("winhttp_proxy", {})
    ie_server = ie_rows.get("proxyserverlist") or ""
    ie_pac = ie_rows.get("autoconfigurationurl") or ""
    wh_access = (wh_rows.get("accesstype") or "").upper()
    wh_proxy = any(v and k != "accesstype" and "proxy" in k for k, v in wh_rows.items()) or (wh_access and "DIRECT" not in wh_access)
    proxy_gap = bool((ie_server or ie_pac) and doc.has("winhttp_proxy") and not wh_proxy)
    if proxy_gap:
        what = f"proxy {ie_server}" if ie_server else f"PAC file {ie_pac}"
        quiet = aadj and prt_state == "ok"
        F.append(_f("info" if quiet else "warning", f"WinHTTP proxy is not set, but the user's IE/Windows proxy is ({what})",
                    "Device registration runs as SYSTEM and uses the WinHTTP proxy, not the user's proxy settings. If the network needs a proxy, "
                    "the device can't reach enterpriseregistration.windows.net or login.microsoftonline.com. Set the WinHTTP proxy (or publish WPAD), and "
                    "make sure the proxy doesn't require user authentication for those URLs."
                    + (" The PRT is renewing, so the device can currently reach Entra ID (perhaps via WPAD or direct access); this matters mainly for joining and re-registering." if quiet else "")))

    # ------------------------------------------------------------ diagnostics
    tests = []
    for nk, label, why in PRE_JOIN_TESTS:
        v = doc.get(nk, "diagnostic_data") or doc.get(nk)
        if v is None:
            continue
        st = "fail" if v.upper().startswith("FAIL") else "pass" if v.upper().startswith("PASS") else "skipped" if v.upper().startswith("SKIP") else "other"
        tests.append({"key": nk, "name": label, "value": v, "status": st, "why": why, "codes": _codes_in(v)})
    failed_tests = [t for t in tests if t["status"] == "fail"]
    phase = (doc.get("Error Phase") or "").strip().lower() or None
    client_err = doc.get("Client ErrorCode")
    server_err = doc.get("Server ErrorCode")
    server_msg = doc.get("Server Message")
    reg_type = doc.get("Registration Type")
    prev_reg = _parse_time(doc.get("Previous Registration"))
    client_codes = _codes_in(client_err)
    first_code = (client_codes[0] if client_codes else None) or next((c for t in failed_tests for c in t["codes"]), None)
    not_synced = bool(server_msg and re.search(r"not\s+found", server_msg, re.I)) or (first_code and first_code["code"] == "0x801C03F2")
    disc_fail = phase in ("discover", "discovery") or any(t["key"] == "drsdiscoverytest" for t in failed_tests) or \
        (first_code and first_code["code"] in ("0x801C001F", "0x801C0021"))
    scp_fail = any(t["key"] == "adconfigurationtest" for t in failed_tests) or (first_code and first_code["code"] == "0x801C001D")
    ad_fail = any(t["key"] == "adconnectivitytest" for t in failed_tests)
    token_fail = phase == "auth" or any(t["key"] == "tokenacquisitiontest" for t in failed_tests)
    join_fail = bool(client_codes or failed_tests or server_err)

    for t in failed_tests:
        codes = t["codes"]
        F.append(_f("critical", f"{t['name']} failed{(' (' + ', '.join(c['code'] for c in codes) + ')') if codes else ''}",
                    f"{t['why']} " + "; ".join(f"{_code_label(c)}: {c['meaning']}" if c["known"] else f"{c['code']} is not in the knowledge base" for c in codes),
                    codes))
    if client_codes and join != "hybrid":
        c = client_codes[0]
        F.append(_f("warning" if not_synced else "critical", f"Last join attempt failed{(' in the ' + phase + ' phase') if phase else ''} with {_code_label(c)}",
                    (c["meaning"] if c["known"] else "This code is not in the knowledge base; open it in the Error Code Lookup.")
                    + (f" Server said: {server_err}{(' - ' + server_msg) if server_msg else ''}." if server_err or server_msg else ""), client_codes))
    elif client_codes and join == "hybrid":
        F.append(_f("info", f"An earlier join attempt failed with {client_codes[0]['code']}, but the device is now joined",
                    "The Diagnostic Data block shows the last failed attempt. Since the device is hybrid joined, it later succeeded.", client_codes))
    if not_synced and join == "domain":
        F.append(_f("warning", "Entra ID has no device object for this computer yet (it hasn't synced): hybrid join is pending",
                    "For a managed (non-federated) domain, hybrid join only completes after Entra Connect syncs the computer object (with its userCertificate "
                    "attribute) to Entra ID. Check the computer's OU is in the sync scope and wait for/run a sync cycle. Shortly after a domain join this is expected; if it persists past a sync cycle, it's a sync-scope problem."))

    # ------------------------------------------------------------------- join state
    if join == "domain" and not join_fail:
        F.append(_f("warning", "Device is domain joined but NOT hybrid joined to Entra ID (pending)",
                    "Normal for a while after domain join or first sync: the join completes when the computer object has synced to Entra ID and the "
                    "Automatic-Device-Join task runs (at sign-in). If it stays like this, check the SCP (hybrid join configuration), the sync scope, and "
                    "the WinHTTP proxy."))
    if join == "registered":
        F.append(_f("info", "Entra registered only (personal / BYOD style)",
                    "A work account was added to this Windows device, but the device itself isn't joined. Device-based Conditional Access that requires "
                    "'hybrid joined' won't be satisfied; 'compliant' can be if it's enrolled in Intune."))

    # ------------------------------------------------------------------- verdict
    sev, title = _verdict(locals())
    sub_bits = [join_label, f"device {device}" if device else None, f"tenant {tenant_name}" if tenant_name else None,
                f"{('pre-join tests failed: ' + ', '.join(t['name'] for t in failed_tests)) if failed_tests else ''}" or None]
    sub = " · ".join(b for b in sub_bits if b)

    # ---------------------------------------------------------------- what to do
    _steps(locals(), steps)

    facts = [["Join type", join_label], ["Device", device], ["Tenant", tenant_name], ["Tenant ID", tenant_id], ["Device ID", device_id],
             ["PRT", ("YES" + (f", renewed {_human(prt_age)} ago" if prt_age is not None and prt_age >= 0 else "")) if prt else ("NO" if prt is False else None)],
             ["TPM", doc.get("TpmProtected")], ["Previous registration", f"{prev_reg:%Y-%m-%d %H:%M} UTC" if prev_reg else None]]

    sections = [{"id": sid, "title": SECTION_TITLES.get(sid, sid), "rows": [[k, v] for k, v in parsed["sections"][sid]]}
                for sid in parsed["order"] if parsed["sections"].get(sid)]
    bad = set()
    if auth_failed:
        bad.add("deviceauthstatus")
    if keysign.startswith("FAIL"):
        bad.add("keysigntest")
    if prt_state in ("missing", "expired", "stale"):
        bad.update({"azureadprt", "azureadprtupdatetime", "azureadprtexpirytime"})
    if proxy_gap:
        bad.update({"proxyserverlist", "autoconfigurationurl", "accesstype"})
    for t in failed_tests:
        bad.add(t["key"])
    if client_codes and join != "hybrid":
        bad.update({"clienterrorcode", "servererrorcode", "servermessage", "errorphase"})
    if prt is False:
        bad.update({"attemptstatus", "servererrorcode", "servererrordescription"})
    for s in sections:
        s["bad"] = [i for i, (k, _) in enumerate(s["rows"]) if _norm(k) in bad and not (s["id"] == "ie_proxy" and _norm(k) == "accesstype")]

    return {
        "severity": sev, "headline": title, "subline": sub, "join": join, "join_label": join_label,
        "facts": facts, "findings": F, "steps": steps, "tests": tests,
        "diag": {"phase": phase, "client_error": client_err, "server_error": server_err, "server_message": server_msg,
                 "registration_type": reg_type, "previous_registration": _iso(prev_reg), "codes": client_codes,
                 "prt_attempt_status": attempt, "prt_attempt_codes": prt_codes, "aadsts": [f"AADSTS{c}" for c in aadsts]},
        "prt": {"present": prt, "update": _iso(prt_update), "expiry": _iso(prt_expiry), "age_seconds": prt_age, "state": prt_state, "authority": prt_auth},
        "reference_time": _iso(ref), "reference_is_client_time": bool(client_time),
        "sections": sections,
    }


def _verdict(v: dict) -> tuple[str, str]:
    join, F = v["join"], v["F"]
    prt_state, prt_age = v["prt_state"], v["prt_age"]
    code = v["first_code"]
    code_txt = f" ({code['code'].lower()})" if code else ""
    phase = v["phase"]
    if v["aadj"] and v["auth_failed"]:
        return "critical", f"{'Hybrid' if join == 'hybrid' else 'Entra'} join is broken: Entra ID says this device is disabled or deleted (DeviceAuthStatus FAILED)"
    if join == "domain":
        if v["join_fail"]:
            ph = phase or ("discover" if v["disc_fail"] else "auth" if v["token_fail"] else None)
            where = f" at the {ph} phase" if ph else ""
            if v["ad_fail"]:
                why = "the device can't reach a domain controller"
            elif v["scp_fail"]:
                why = "the device couldn't read the hybrid join configuration (SCP) from Active Directory"
            elif v["disc_fail"] and v["proxy_gap"]:
                why = "the device can't reach enterpriseregistration.windows.net as SYSTEM, likely because the WinHTTP proxy isn't set"
            elif v["disc_fail"]:
                why = "the device can't reach the Entra device registration service (enterpriseregistration.windows.net) as SYSTEM: check the proxy, firewall and TLS inspection"
            elif v["not_synced"]:
                return "warning", f"Hybrid join is pending{where}{code_txt}: Entra ID has no device object for this computer yet, because the computer object hasn't synced through Entra Connect."
            elif v["token_fail"]:
                why = "the device couldn't get a token from Entra ID or AD FS for the join"
            elif code and code["known"]:
                why = code["meaning"].rstrip(".")
                why = _lc(why)
            else:
                why = "see the error code below"
            return "critical", f"Hybrid join is failing{where}{code_txt}: {why}."
        if v["proxy_gap"]:
            return "warning", "Domain joined but not hybrid joined yet (pending), and the WinHTTP proxy isn't set while the user's proxy is"
        return "warning", "Domain joined only: hybrid join is pending (the device isn't registered in Entra ID yet)"
    if join in ("hybrid", "entra"):
        name = "Hybrid joined" if join == "hybrid" else "Entra joined"
        crit = next((f for f in F if f["severity"] == "critical" and "earlier join attempt" not in f["title"]), None)
        if prt_state == "missing":
            return "critical", f"{name}, but the user has no Primary Refresh Token: SSO and device-based Conditional Access will fail"
        if prt_state == "expired":
            return "critical", f"{name}, but the PRT has expired: Windows can't renew it, so SSO will fail"
        if crit:
            return "critical", f"{name}, but {_lc(crit['title'])}"
        if prt_state == "stale":
            return "warning", f"{name}, but the PRT hasn't renewed in {_human(prt_age)}: Windows may not be reaching Entra ID"
        warn = next((f for f in F if f["severity"] == "warning"), None)
        if warn:
            return "warning", f"{name}, with a problem: {_lc(warn['title'])}"
        if prt_state == "ok":
            return "ok", f"{name} and healthy: PRT renewed {_human(prt_age)} ago." if prt_age is not None and prt_age >= 0 else f"{name} and healthy: the user has a PRT."
        return "ok", f"{name}. The SSO State section isn't in the paste, so the PRT wasn't checked."
    if join == "registered":
        return "info", "Entra registered only: a work account is added, but the device isn't Entra or hybrid joined"
    if join == "enterprise":
        return "info", "Enterprise joined to an on-premises device registration service (AD FS), not to Entra ID"
    return "info", "This device isn't joined to Entra ID or a domain, and has no registered work account"


def _steps(v: dict, steps: list) -> None:
    join, dev = v["join"], v["dev_ph"]
    dev_id = v["device_id"]
    graph = [f'Connect-MgGraph -Scopes "Device.Read.All"',
             f"Get-MgDevice -Filter \"displayName eq '{dev}'\" | Format-List DisplayName, Id, DeviceId, AccountEnabled, TrustType, ApproximateLastSignInDateTime"]
    if dev_id:
        graph.append(f"Get-MgDevice -Filter \"deviceId eq '{dev_id}'\" | Format-List DisplayName, Id, AccountEnabled, TrustType")
    leave_warn = ("WARNING: run elevated. On an Entra joined (cloud-only) device, /leave removes the join: Entra accounts can't sign in afterwards, "
                  "so confirm a local administrator account works first. On a hybrid device it re-joins automatically at the next sign-in once the "
                  "computer object is in sync.")
    if v["proxy_gap"] or (v["disc_fail"] and not v["scp_fail"] and not v["ad_fail"]):
        steps.append({"title": "Check the WinHTTP proxy (what SYSTEM uses) and set it if the network needs a proxy",
                      "detail": "Device registration runs as SYSTEM and ignores the user's proxy. Either publish WPAD, set the WinHTTP proxy by GPO/command, "
                                "or allow direct access to enterpriseregistration.windows.net, login.microsoftonline.com and device.login.microsoftonline.com. "
                                "'import proxy source=ie' copies a static proxy from the user running the command (not a PAC file).",
                      "commands": ["netsh winhttp show proxy",
                                   'netsh winhttp set proxy proxy-server="proxy.contoso.com:8080" bypass-list="<local>;*.contoso.com"   # replace with your proxy',
                                   "netsh winhttp import proxy source=ie", _DRS_TCP]})
    if v["scp_fail"]:
        steps.append({"title": "Check the hybrid join SCP (service connection point) in Active Directory",
                      "detail": "It should contain azureADId:<tenant ID> and azureADName:<verified domain>. Configure it in Entra Connect → Configure device options, "
                                "or via targeted registry settings.", "commands": [_SCP]})
    if v["ad_fail"]:
        steps.append({"title": "Fix domain controller connectivity", "commands": ["nltest /dsgetdc:contoso.com   # replace with your AD domain", "Test-ComputerSecureChannel -Verbose"]})
    if join == "domain" and not (v["disc_fail"] or v["scp_fail"] or v["ad_fail"]):
        steps.append({"title": "Make sure the computer object syncs to Entra ID",
                      "detail": "Managed domains: the computer must be in an OU that's in the Entra Connect sync scope and have a userCertificate value "
                                "(written by the device on its first join attempt). Then run a sync cycle on the Entra Connect server and check the device appears in Entra ID.",
                      "commands": [f"Get-ADComputer {dev} -Properties userCertificate, DistinguishedName | Select-Object Name, DistinguishedName, @{{n='userCertificates';e={{$_.userCertificate.Count}}}}",
                                   "Start-ADSyncSyncCycle -PolicyType Delta   # on the Entra Connect server"] + graph})
    if join == "domain":
        steps.append({"title": "Retry the join and re-check",
                      "detail": "The Automatic-Device-Join task runs at sign-in; trigger it (elevated) or sign out and back in, then re-run dsregcmd /status. "
                                "Read the User Device Registration log for the exact failure.",
                      "commands": [_TASK, "dsregcmd /join   # run elevated: schedules and runs the hybrid join task", "dsregcmd /status", kb._DSREG_LOG]})
    if join in ("hybrid", "entra") and v["auth_failed"]:
        steps.append({"title": "Check the device object in Entra ID", "detail": "If AccountEnabled is False, enable it (Update-MgDevice takes the object Id). If it's missing, it was deleted: re-register the device.",
                      "commands": graph + ["Connect-MgGraph -Scopes \"Directory.AccessAsUser.All\"   # delegated device updates need this, plus Cloud Device Administrator or higher",
                                           f"$dev = Get-MgDevice -Filter \"displayName eq '{dev}'\"; Update-MgDevice -DeviceId $dev.Id -AccountEnabled:$true"]})
        steps.append({"title": "Re-register the device if its Entra object was deleted", "detail": leave_warn,
                      "commands": ["dsregcmd /leave", _TASK + "   # hybrid: or sign out and in" if join == "hybrid" else "# Entra joined: re-join from Settings → Accounts → Access work or school"]})
    if v["keysign"].startswith("FAIL") or (v["cert_to"] and v["cert_to"] < v["ref"]):
        steps.append({"title": "Re-register the device (unhealthy device key or certificate)", "detail": leave_warn,
                      "commands": ["dsregcmd /leave", _TASK + "   # hybrid" if join == "hybrid" else "# Entra joined: re-join from Settings → Accounts → Access work or school", "dsregcmd /status"]})
    if v["prt_state"] in ("missing", "expired", "stale") and join in ("hybrid", "entra"):
        steps.append({"title": "Get the user a fresh PRT",
                      "detail": "Run dsregcmd /status as the affected user in a non-elevated prompt. Lock and unlock (or sign out and in) while connected to the "
                                "network, then check again. The AAD Operational log shows why the PRT request failed."
                                + (" The last attempt returned " + ", ".join(f"AADSTS{a}" for a in v["aadsts"]) + ": decode it in the Sign-in Error Decoder." if v["aadsts"] else ""),
                      "commands": ["dsregcmd /status", _AAD_LOG, "netsh winhttp show proxy"]})


# ---------------------------------------------------------------------- routes
class DsregIn(BaseModel):
    raw: str = Field(..., max_length=MAX_INPUT)


@router.post("/api/devicejoin/analyze")
def devicejoin_analyze(body: DsregIn):
    return run(analyze, body.raw)
