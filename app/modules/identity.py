"""Identity (Entra ID) tools: sign-in error decoder and tenant / federation check.

The token decoder runs entirely in the browser (static/tools/identity.js)."""
from __future__ import annotations

import base64
import time
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from ..core.dns_utils import addresses, is_ip, make_resolver, normalize_domain
from ..core import cmdsafe
from ..core.http import run
from .domain import check_m365_tenant
from .smtp_test import _cert_info

router = APIRouter()

HTTP_TIMEOUT = 6.0
FETCH_TIMEOUT = 8.0
MAX_BODY = 512 * 1024
MAX_REDIRECTS = 5


def _f(sev: str, title: str, detail: str = "") -> dict:
    return {"severity": sev, "title": title, "detail": detail}


# =====================================================================================
#                               AADSTS KNOWLEDGE BASE
# =====================================================================================
# Each entry: name (Microsoft's error name), short (headline phrase), meaning, causes,
# fix, sev (critical = user is blocked, warning = degraded, info = interrupt/benign),
# interrupt (normally followed by a successful sign-in), steps (optional next steps).
# Placeholders in commands: {upn}, {appid}, {tenant}, {sam}.
KB: dict[int, dict] = {
    16000: dict(name="SelectUserAccount / InteractionRequired", sev="info", interrupt=True,
                short="user has to pick an account (interrupt)",
                meaning="Entra ID found more than one signed-in account, or the app asked for silent sign-in (prompt=none) and interaction is needed. The user is shown an account picker.",
                causes=["Several accounts signed in to the same browser", "App tried a silent (prompt=none) sign-in"],
                fix="Usually harmless. If the user is stuck in a loop, sign out of all accounts in the browser (or use an InPrivate window) and sign in with the right one."),
    50011: dict(name="InvalidReplyTo", sev="critical", short="the app's reply (redirect) URL is not registered",
                meaning="The redirect URI the app sent does not exactly match any redirect URI on its app registration.",
                causes=["Redirect URI missing from the app registration", "http vs https, trailing slash, port or case differs", "App moved to a new URL"],
                fix="In Entra admin center → App registrations → the app → Authentication, add the exact redirect URI from the error message (it must match character for character).",
                steps=[{"title": "Add the exact redirect URI to the app registration", "detail": "Copy the reply URL from the error text. Entra admin center → App registrations → (app) → Authentication → Add URI. For a gallery/SAML app, check Enterprise applications → (app) → Single sign-on → Reply URL."}]),
    50020: dict(name="UserUnauthorized (user not in tenant)", sev="critical",
                short="the account is not a member or guest of the tenant it is signing in to",
                meaning="The user signed in with an account from another directory (or a personal Microsoft account) that does not exist in the resource tenant.",
                causes=["External user was never invited as a guest", "Guest invitation was deleted or not redeemed", "Single-tenant app used by a user from another tenant", "Personal Microsoft account used with an app that only accepts work/school accounts"],
                fix="Invite the user as a B2B guest in the resource tenant, or have them sign in with the right account. App developers: make the app multi-tenant or use the correct tenant endpoint.",
                steps=[{"title": "Invite the user as a guest (if they should have access)", "commands": ["Connect-MgGraph -Scopes User.Invite.All", "New-MgInvitation -InvitedUserEmailAddress {upn} -InviteRedirectUrl 'https://myapps.microsoft.com' -SendInvitationMessage:$true"]}]),
    50034: dict(name="UserAccountNotFound", sev="critical", short="the user account does not exist in this directory",
                meaning="Entra ID could not find an account with that sign-in name in the tenant.",
                causes=["Typo in the username", "User signs in with an email address that is not their UPN", "Account deleted or not yet synced from on-prem AD", "Signing in to the wrong tenant"],
                fix="Confirm the exact UPN. If the user is synced from AD, check Entra Connect sync. Restore the account from Deleted users if it was removed within 30 days.",
                steps=[{"title": "Look the account up by UPN and by email", "commands": ["Connect-MgGraph -Scopes User.Read.All", "Get-MgUser -Filter \"userPrincipalName eq '{upn}'\"", "Get-MgUser -Filter \"proxyAddresses/any(p:p eq 'smtp:{upn}')\" -ConsistencyLevel eventual -CountVariable c"]}]),
    50053: dict(name="IdsLocked (account locked / malicious IP)", sev="critical",
                short="the account is locked by Smart Lockout, or the sign-in came from a malicious IP",
                meaning="Too many failed sign-ins with a wrong password, so Entra Smart Lockout temporarily locked the account. The same code is also returned when the sign-in came from an IP address Microsoft has seen doing malicious activity.",
                causes=["Old password saved on a phone, mail client, mapped drive or service retrying", "Password spray or brute force from the internet", "User repeatedly typing the wrong password"],
                fix="Find and stop the source of the bad passwords (see the IP addresses in the sign-in logs). Smart Lockout releases the account automatically (60 seconds by default, longer on repeated lockouts). If the source IP is external and hits many accounts, treat it as an attack and block it.",
                steps=[{"title": "Find the source of the failed attempts", "detail": "Entra admin center → Sign-in logs → filter on the user and Status = Failure. Look at IP address, Client app and Application for the repeating failures (paste them here as JSON to group them)."},
                       {"title": "If the user is synced from AD, check on-prem lockout too", "commands": ["Get-ADUser {sam} -Properties LockedOut,BadLogonCount,LastBadPasswordAttempt,PasswordLastSet | Format-List Name,LockedOut,BadLogonCount,LastBadPasswordAttempt,PasswordLastSet"]}]),
    50055: dict(name="InvalidPasswordExpiredPassword", sev="critical", short="the user's password has expired",
                meaning="The cloud password has passed its expiry date, so the user must change it before signing in.",
                causes=["Password expiration policy on the domain", "Synced user with cloud password policy enforced"],
                fix="Have the user change their password (the sign-in page prompts for it), or reset it. Review the password expiration policy if this is unexpected.",
                steps=[{"title": "Check when the password was last set", "commands": ["Connect-MgGraph -Scopes User.Read.All", "Get-MgUser -UserId {upn} -Property LastPasswordChangeDateTime,PasswordPolicies | Format-List LastPasswordChangeDateTime,PasswordPolicies"]}]),
    50056: dict(name="InvalidOrNullPassword", sev="critical", short="no password exists in Entra ID for this user",
                meaning="The user has no password stored in the directory (or it is null), so password sign-in cannot work.",
                causes=["Synced user whose password hash has not synced (Password Hash Sync off or failing)", "Account created without a password"],
                fix="Check that Password Hash Sync is running in Entra Connect, or reset the user's password in the cloud."),
    50057: dict(name="UserDisabled", sev="critical", short="the user account is disabled",
                meaning="The account exists but sign-in is blocked (accountEnabled = false).",
                causes=["Account disabled by an admin or leaver process", "Account disabled in on-prem AD and synced"],
                fix="If the user should have access, enable the account. For synced users, enable it in on-prem AD and let it sync; the cloud setting will be overwritten otherwise.",
                steps=[{"title": "Check whether the account is cloud-only or synced", "commands": ["Connect-MgGraph -Scopes User.ReadWrite.All", "Get-MgUser -UserId {upn} -Property AccountEnabled,OnPremisesSyncEnabled | Format-List AccountEnabled,OnPremisesSyncEnabled"]},
                       {"title": "Enable it (cloud-only user)", "commands": ["Update-MgUser -UserId {upn} -AccountEnabled:$true"]},
                       {"title": "Enable it (synced user, on a DC)", "commands": ["Enable-ADAccount -Identity {sam}", "Start-ADSyncSyncCycle -PolicyType Delta"]}]),
    50058: dict(name="UserInformationNotProvided", sev="info", interrupt=True, short="no signed-in session was found for silent sign-in (interrupt)",
                meaning="The app tried to sign the user in silently, but there was no usable session (user not signed in, or the session cookie was not sent).",
                causes=["User not signed in yet", "Third-party cookies blocked in the browser", "Silent sign-in (prompt=none) from an iframe"],
                fix="Normally followed by an interactive sign-in. If it repeats, check the browser's cookie/tracking settings."),
    50072: dict(name="UserStrongAuthEnrollmentRequiredInterrupt", sev="info", interrupt=True, short="the user has to register for MFA (interrupt)",
                meaning="The user must register a second factor before continuing. The sign-in page asks them to set up MFA.",
                causes=["MFA required but the user has no methods registered"],
                fix="Have the user complete registration at https://aka.ms/mysecurityinfo. If registration is blocked, check the Conditional Access policy for 'Register security information'."),
    50074: dict(name="UserStrongAuthClientAuthNRequiredInterrupt", sev="info", interrupt=True, short="MFA was required and not yet completed (interrupt)",
                meaning="Strong authentication (MFA) is required. This entry is logged when the user is sent to the MFA prompt; it is normally followed by a successful sign-in.",
                causes=["MFA prompt shown to the user", "User closed the window before completing MFA"],
                fix="Harmless if a later sign-in with the same correlation ID succeeded. If not, the user did not complete MFA: check their registered methods."),
    50076: dict(name="UserStrongAuthClientAuthNRequired", sev="warning", interrupt=True, short="MFA is required for this sign-in",
                meaning="A Conditional Access policy, per-user MFA, or a new location requires MFA. Interactive clients prompt for it. Clients that cannot show an MFA prompt (legacy/basic auth, old scripts) fail here.",
                causes=["Conditional Access or per-user MFA requires MFA", "Legacy protocol (IMAP, POP, SMTP AUTH, old Office) that cannot do MFA", "Non-interactive token refresh after MFA policy changed"],
                fix="Use a modern-auth client that can prompt for MFA. If the failure is from a legacy protocol, move that client to modern auth; don't exclude it from MFA."),
    50079: dict(name="UserStrongAuthEnrollmentRequired", sev="warning", interrupt=True, short="the user must register for MFA",
                meaning="An admin setting (Conditional Access, Security Defaults, per-user MFA) requires MFA and the user has not registered any MFA method.",
                causes=["New user who has not set up MFA", "MFA methods were deleted (e.g. new phone)"],
                fix="Have the user register at https://aka.ms/mysecurityinfo. For a lost phone, an admin can require re-registration or issue a Temporary Access Pass.",
                steps=[{"title": "Check the user's registered methods", "commands": ["Connect-MgGraph -Scopes UserAuthenticationMethod.Read.All", "Get-MgUserAuthenticationMethod -UserId {upn}"]}]),
    50089: dict(name="Flow token expired", sev="warning", short="the sign-in took too long and its flow token expired",
                meaning="The user spent too long on the sign-in page (e.g. left it open), so the temporary sign-in state expired.",
                causes=["Sign-in page left open", "Very slow MFA response"],
                fix="Have the user start the sign-in again."),
    50097: dict(name="DeviceAuthenticationRequired", sev="info", interrupt=True, short="device authentication is required (interrupt)",
                meaning="A policy needs to know which device is signing in, so Entra ID asks the device to prove its identity (using its Primary Refresh Token or device certificate).",
                causes=["Device-based Conditional Access (compliant / hybrid joined device)"],
                fix="Usually followed by success. If not: on Windows use Edge signed in with the work account (or Chrome with the Microsoft SSO extension); run dsregcmd /status to confirm the device is joined and has a PRT.",
                steps=[{"title": "Check device registration on the PC", "commands": ["dsregcmd /status"]}]),
    50105: dict(name="EntitlementGrantsNotFound", sev="critical", short="the user is not assigned to this application",
                meaning="The enterprise application has 'Assignment required' turned on, and the user (or a group they are in) is not assigned to it.",
                causes=["User not added to the app's Users and groups", "User removed from the assigned group", "Nested groups (assignment does not follow nested membership)"],
                fix="Entra admin center → Enterprise applications → (app) → Users and groups → Add the user or a group they are a direct member of. Or turn off 'Assignment required' if everyone should have access.",
                steps=[{"title": "Confirm assignment is required on the app", "commands": ["Connect-MgGraph -Scopes Application.Read.All", "Get-MgServicePrincipal -Filter \"appId eq '{appid}'\" | Format-List DisplayName,AppId,AppRoleAssignmentRequired"]}]),
    50126: dict(name="InvalidUserNameOrPassword", sev="critical", short="wrong username or password",
                meaning="Entra ID (or the on-prem agent for pass-through authentication) rejected the password.",
                causes=["User typed the wrong password", "Old password saved in a phone, mail client or service", "Password spray / brute force", "Recent password change not yet synced (Password Hash Sync delay)"],
                fix="Confirm the user knows their current password; reset it if needed. Repeated failures from one IP are usually a device with a saved old password. Many accounts failing from one IP is a password spray.",
                steps=[{"title": "If the user is synced from AD, compare with on-prem", "commands": ["Get-ADUser {sam} -Properties PasswordLastSet,LastBadPasswordAttempt,BadLogonCount,LockedOut | Format-List Name,PasswordLastSet,LastBadPasswordAttempt,BadLogonCount,LockedOut"]}]),
    50132: dict(name="SsoArtifactInvalidOrExpired", sev="warning", short="the session is no longer valid (password expired or recently changed)",
                meaning="The existing single sign-on session can't be used because the password expired or was changed.",
                causes=["Password changed or reset", "Password expired"],
                fix="Have the user sign in again with their current password."),
    50133: dict(name="SsoArtifactRevoked", sev="warning", short="the session was revoked (password expired or recently changed)",
                meaning="The session token was invalidated, typically after a password change or expiry.",
                causes=["Password changed or reset", "Admin revoked sessions"],
                fix="Have the user sign in again with their current password."),
    50140: dict(name="KmsiInterrupt", sev="info", interrupt=True, short="'Stay signed in?' prompt (interrupt)",
                meaning="The user was shown the 'Stay signed in?' (Keep me signed in) prompt. This is not a failure.",
                causes=["Normal sign-in flow"], fix="Nothing to fix."),
    50144: dict(name="InvalidPasswordExpiredOnPremPassword", sev="critical", short="the user's on-premises AD password has expired",
                meaning="The user's Active Directory password has expired (pass-through authentication or federated sign-in checks on-prem).",
                causes=["AD password expiry policy"],
                fix="Have the user change their password (on a domain PC with Ctrl+Alt+Del, via SSPR with password writeback, or an admin reset).",
                steps=[{"title": "Check password expiry in AD", "commands": ["Get-ADUser {sam} -Properties PasswordLastSet,PasswordExpired,msDS-UserPasswordExpiryTimeComputed | Select-Object Name,PasswordLastSet,PasswordExpired,@{n='Expires';e={[datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')}}"]}]),
    50158: dict(name="ExternalSecurityChallenge", sev="warning", short="an external security challenge was not satisfied",
                meaning="An external check (a third-party MFA provider via Conditional Access custom controls or external authentication methods, or a federated IdP's MFA) was not completed.",
                causes=["User did not complete the third-party MFA (e.g. Duo)", "Third-party MFA provider misconfigured or unreachable"],
                fix="Check the external MFA provider's own logs for this user and time."),
    50173: dict(name="FreshTokenNeeded", sev="warning", short="tokens were revoked, so the user must sign in again",
                meaning="The refresh token was revoked (by an admin, by the user, or by a password change), so the app needs a fresh sign-in.",
                causes=["Admin ran 'Revoke sessions'", "Password changed or reset"],
                fix="Have the user sign out of the app and sign in again."),
    50199: dict(name="CmsiInterrupt", sev="info", interrupt=True, short="user confirmation prompt (interrupt)",
                meaning="For security, the user is asked to confirm the sign-in (for example 'Are you trying to sign in to …?' in device code or native app flows).",
                causes=["Normal security prompt"], fix="Nothing to fix if the user confirmed and the next sign-in succeeded."),
    51004: dict(name="UserAccountNotInDirectory", sev="critical", short="the user account does not exist in the directory",
                meaning="No account with that name exists in the tenant.",
                causes=["Typo in the sign-in name", "Account deleted or not synced", "Wrong tenant"],
                fix="Confirm the UPN and that the account exists (check Deleted users and Entra Connect sync)."),
    53000: dict(name="DeviceNotCompliant", sev="critical", short="the device is not compliant in Intune",
                meaning="A Conditional Access policy requires a device marked as compliant, and this device is not (or Entra ID could not identify the device).",
                causes=["Device not enrolled in Intune", "Device enrolled but failing a compliance policy (encryption, OS version, antivirus…)", "Browser not passing the device identity (Chrome without the SSO extension, InPrivate, non-Edge on macOS/iOS without Company Portal)"],
                fix="Check the device in Intune → Devices → (device) → Device compliance, fix the failing setting and sync. If the device IS compliant, the browser didn't send device identity: use Edge signed in with the work profile, or install the Microsoft SSO extension / Company Portal.",
                steps=[{"title": "Check the device's join state and PRT", "commands": ["dsregcmd /status"]},
                       {"title": "Check compliance in Intune", "detail": "Intune admin center → Devices → find the device → Device compliance. Fix the failing policy, then Sync from the device (Settings → Accounts → Access work or school → Info → Sync)."}]),
    53001: dict(name="DeviceNotDomainJoined", sev="critical", short="the device is not hybrid Entra joined",
                meaning="A Conditional Access policy requires a hybrid Microsoft Entra joined device, and this device is not (or its identity was not sent).",
                causes=["Device not domain joined or not yet registered in Entra ID", "Hybrid join pending (device not synced by Entra Connect)", "Browser not passing device identity"],
                fix="Run dsregcmd /status on the device: DomainJoined and AzureAdJoined must both be YES. Check the device appears in Entra ID as 'Microsoft Entra hybrid joined'.",
                steps=[{"title": "Check hybrid join on the device", "commands": ["dsregcmd /status"]}]),
    53002: dict(name="ApplicationUsedIsNotAnApprovedApp", sev="critical", short="the app used is not an approved client app",
                meaning="A Conditional Access policy requires an approved client app (or an app protection policy), and this app is not on the list.",
                causes=["Native mail app (iOS Mail, Gmail) instead of Outlook", "Third-party app not supporting Intune app protection"],
                fix="Use an approved Microsoft app (Outlook, Teams, Edge…) on the mobile device."),
    53003: dict(name="BlockedByConditionalAccess", sev="critical", short="access is blocked by a Conditional Access policy",
                meaning="A Conditional Access policy with a 'Block access' grant matched this sign-in.",
                causes=["Location, platform, client app, risk or app condition matched a block policy"],
                fix="Find the policy with result 'Failure' in the sign-in's Conditional Access tab and check which condition matched. Use the What If tool to test changes.",
                steps=[{"title": "Find the policy that blocked", "detail": "Sign-in logs → (sign-in) → Conditional Access tab → the policy with Result = Failure. Then Conditional Access → Policies → What If, with the same user, app, IP and platform."}]),
    53004: dict(name="ProofUpBlockedDueToRisk", sev="critical", short="MFA registration was blocked",
                meaning="The user must register for MFA but registration is blocked, typically by risk or by a Conditional Access policy on 'Register security information' (e.g. only from trusted locations).",
                causes=["User risk / sign-in risk detected during registration", "CA policy requires registering security info from a trusted location"],
                fix="Have the user register from a trusted location, or issue a Temporary Access Pass. Review the user's risk in Identity Protection."),
    530003: dict(name="Device must be managed", sev="critical", short="the device must be managed to access this resource",
                 meaning="A Conditional Access policy requires a managed device (compliant or hybrid joined) and this device isn't.",
                 causes=["Personal / unmanaged device", "Browser not passing device identity"],
                 fix="Enroll the device in Intune (or hybrid join it), or access from a managed device. Check the device state with dsregcmd /status.",
                 steps=[{"title": "Check the device's state", "commands": ["dsregcmd /status"]}]),
    500011: dict(name="InvalidResourceServicePrincipalNotFound", sev="critical", short="the resource app is not found in this tenant",
                 meaning="The app (resource) being accessed has no service principal in the tenant.",
                 causes=["Third-party app never consented/installed in the tenant", "Wrong tenant in the sign-in URL", "Typo in the resource URI / app ID"],
                 fix="Have an admin consent to the app (which creates its service principal), or check the tenant and resource identifier the app is using.",
                 steps=[{"title": "Check for the service principal", "commands": ["Connect-MgGraph -Scopes Application.Read.All", "Get-MgServicePrincipal -Filter \"appId eq '{appid}'\""]}]),
    500121: dict(name="Authentication failed during strong authentication request", sev="critical", short="the user did not complete MFA",
                 meaning="The MFA step failed: the user denied or didn't answer the prompt, entered a wrong code, the request timed out, or reported fraud.",
                 causes=["User ignored or denied the Authenticator prompt", "Wrong number entered (number matching)", "Unexpected prompt: someone else has the password (MFA fatigue attack)"],
                 fix="Ask the user whether they were signing in. If not, the password is compromised: reset it and revoke sessions. Otherwise check their registered methods.",
                 steps=[{"title": "Review the user's MFA methods", "commands": ["Connect-MgGraph -Scopes UserAuthenticationMethod.Read.All", "Get-MgUserAuthenticationMethod -UserId {upn}"]},
                        {"title": "If the user was NOT signing in: reset the password and revoke sessions", "commands": ["Connect-MgGraph -Scopes User.ReadWrite.All", "Revoke-MgUserSignInSession -UserId {upn}"]}]),
    65001: dict(name="DelegationDoesNotExist", sev="critical", short="nobody has consented to this app",
                meaning="The user or an admin has not consented to the permissions the app is asking for.",
                causes=["User consent disabled in the tenant", "App requests new permissions", "Admin consent never granted"],
                fix="An admin grants consent: Entra admin center → Enterprise applications → (app) → Permissions → Grant admin consent, or use the admin consent URL.",
                steps=[{"title": "Grant admin consent", "detail": "Open this URL as a Global/Cloud Application Administrator:", "commands": ["https://login.microsoftonline.com/{tenant}/adminconsent?client_id={appid}"]}]),
    65004: dict(name="UserDeclinedConsent", sev="warning", short="the user declined consent",
                meaning="The user was shown a consent prompt and chose Cancel/Decline.",
                causes=["User declined the permissions prompt"],
                fix="Have the user try again and accept, or have an admin grant consent for the whole tenant."),
    70000: dict(name="InvalidGrant", sev="warning", short="the grant (refresh token or code) is invalid",
                meaning="The authorization code or refresh token presented by the app was rejected.",
                causes=["Refresh token revoked or expired", "Auth code reused or expired", "Token issued to a different app"],
                fix="Have the user sign in again. App developers: request a new token interactively."),
    70008: dict(name="ExpiredOrRevokedGrant", sev="warning", short="the refresh token expired or was revoked",
                meaning="The refresh token or authorization code has expired (for example due to inactivity) or was revoked.",
                causes=["Token unused for a long time", "Sessions revoked by an admin", "Password change"],
                fix="Have the user sign in again."),
    70011: dict(name="InvalidScope", sev="critical", short="the app requested an invalid scope",
                meaning="The scope (permission) in the app's request is not valid.",
                causes=["Typo in the scope", "Mixing scopes for different resources in one request", "Using /.default incorrectly"],
                fix="App developer issue: fix the scope parameter in the app's request."),
    70043: dict(name="BadTokenDueToSignInFrequency", sev="warning", short="sign-in frequency policy requires a fresh sign-in",
                meaning="A Conditional Access sign-in frequency control made the refresh token expire, so the user must sign in again.",
                causes=["CA session control 'Sign-in frequency'"],
                fix="Expected behaviour; the user signs in again. If prompts are too frequent, review the sign-in frequency setting."),
    700016: dict(name="UnauthorizedClient_DoesNotMatchRequest", sev="critical", short="the application ID was not found in this tenant",
                 meaning="The client app ID in the request does not exist in the directory being signed in to.",
                 causes=["Wrong app (client) ID", "App registered in a different tenant (and not multi-tenant)", "App deleted"],
                 fix="Check the client ID and tenant the app uses. For a multi-tenant app from another publisher, an admin must consent to it in this tenant first.",
                 steps=[{"title": "Check whether the app exists here", "commands": ["Connect-MgGraph -Scopes Application.Read.All", "Get-MgServicePrincipal -Filter \"appId eq '{appid}'\""]}]),
    700082: dict(name="ExpiredOrRevokedGrantInactiveToken", sev="warning", short="the refresh token expired from inactivity",
                 meaning="The refresh token was not used for too long (90 days by default) and expired.",
                 causes=["App or script not used for a long time"],
                 fix="Have the user (or the app's service account) sign in again interactively."),
    7000215: dict(name="InvalidClientSecretProvided", sev="critical", short="the app's client secret is wrong",
                  meaning="The client secret the app presented does not match any secret on the app registration.",
                  causes=["Secret ID pasted instead of the secret Value", "Secret was regenerated and the app not updated", "Secret for a different app"],
                  fix="Create a new client secret on the app registration and copy its Value (shown only once) into the app's configuration.",
                  steps=[{"title": "List the app's secrets and their expiry", "commands": ["Connect-MgGraph -Scopes Application.Read.All", "(Get-MgApplication -Filter \"appId eq '{appid}'\").PasswordCredentials | Format-Table DisplayName,KeyId,EndDateTime"]}]),
    7000222: dict(name="InvalidClientSecretExpiredKeysProvided", sev="critical", short="the app's client secret has expired",
                  meaning="The client secret the app is using is past its expiry date.",
                  causes=["Secret reached its end date"],
                  fix="Create a new client secret on the app registration, update the app/integration with it, then delete the expired one.",
                  steps=[{"title": "List the app's secrets and their expiry", "commands": ["Connect-MgGraph -Scopes Application.Read.All", "(Get-MgApplication -Filter \"appId eq '{appid}'\").PasswordCredentials | Format-Table DisplayName,KeyId,EndDateTime"]}]),
    81010: dict(name="DesktopSsoAuthTokenInvalid", sev="warning", short="Seamless SSO failed: the Kerberos ticket is invalid or expired",
                meaning="Seamless single sign-on could not use the user's Kerberos ticket, so the user is asked for a password.",
                causes=["Kerberos ticket expired or stale", "AZUREADSSOACC computer account key out of date", "Device clock skew"],
                fix="Purge the Kerberos tickets on the PC and sign in again. If it affects everyone, roll over the Seamless SSO Kerberos decryption key (AZUREADSSOACC) with the AzureADSSO PowerShell module from Entra Connect.",
                steps=[{"title": "Clear Kerberos tickets on the affected PC", "commands": ["klist purge"]}]),
    81012: dict(name="DesktopSsoUserAccountMismatch", sev="info", short="Seamless SSO: the user signing in is not the user logged on to the PC",
                meaning="Not an error: the account entered differs from the Windows user, so Seamless SSO doesn't apply.",
                causes=["Shared PC or user signing in with a second account"], fix="Nothing to fix."),
    90072: dict(name="PassThroughUserMfaError", sev="critical", short="the external account can't satisfy MFA in this tenant",
                meaning="The user signed in with an external account that does not exist in this tenant, so it cannot do MFA here. It can also happen for synced users when the ImmutableID (sourceAnchor) in Entra ID does not match on-prem AD.",
                causes=["Guest not invited / signing in to the wrong tenant", "ImmutableID mismatch for a synced or federated user"],
                fix="Invite the user as a guest, or have them use the right account. For a synced user, compare the ImmutableID with on-prem AD.",
                steps=[{"title": "Check the user's ImmutableID", "commands": ["Connect-MgGraph -Scopes User.Read.All", "Get-MgUser -UserId {upn} -Property OnPremisesImmutableId,OnPremisesSyncEnabled | Format-List OnPremisesImmutableId,OnPremisesSyncEnabled"]}]),
    90094: dict(name="AdminConsentRequired", sev="critical", short="admin consent is required for this app",
                meaning="The app asks for permissions that only an administrator can grant, or user consent is turned off.",
                causes=["App requests admin-only permissions", "User consent disabled in the tenant"],
                fix="An admin reviews the app and grants consent (Enterprise applications → (app) → Permissions), or enable the admin consent workflow so users can request it.",
                steps=[{"title": "Grant admin consent", "commands": ["https://login.microsoftonline.com/{tenant}/adminconsent?client_id={appid}"]}]),
    90095: dict(name="AdminConsentRequiredRequestAccess", sev="info", interrupt=True, short="the user must request admin approval for this app",
                meaning="The admin consent workflow is enabled: the user is told to request approval from an admin.",
                causes=["App needs consent the user can't give"],
                fix="An admin reviews the request in Enterprise applications → Admin consent requests."),
    9002313: dict(name="InvalidRequest (malformed)", sev="critical", short="the sign-in request is malformed",
                  meaning="Entra ID couldn't parse the request (OAuth or SAML) the app sent.",
                  causes=["App sent bad or missing parameters", "SAML AuthnRequest malformed or wrongly encoded", "URL truncated or altered by a proxy"],
                  fix="App/SSO configuration issue. Capture the request (browser dev tools → Network) and check it; for SAML apps decode the AuthnRequest with the Token Decoder."),
    # ---- extra codes we are confident about
    50001: dict(name="InvalidResource", sev="critical", short="the resource is disabled or doesn't exist",
                meaning="The resource (API) the app requested a token for is disabled or does not exist in the tenant.",
                causes=["Wrong resource URI in the app", "Resource service principal disabled"],
                fix="Check the resource identifier the app uses and that the resource's enterprise app is enabled."),
    50005: dict(name="DevicePolicyError", sev="critical", short="the device platform is not supported by a Conditional Access policy",
                meaning="The user signed in from a device platform that a Conditional Access policy doesn't support.",
                causes=["Device platform condition in a CA policy"], fix="Review the CA policy's device platform conditions."),
    50078: dict(name="UserStrongAuthExpired", sev="warning", short="the MFA claim has expired; the user must do MFA again",
                meaning="The earlier MFA is too old for this request, so the user must complete MFA again.",
                causes=["Sign-in frequency / MFA freshness requirement"], fix="The user completes MFA again."),
    50125: dict(name="PasswordResetRegistrationRequiredInterrupt", sev="info", interrupt=True, short="password reset or registration interrupt",
                meaning="Sign-in was interrupted to make the user reset their password or register for self-service password reset.",
                causes=["SSPR registration required", "Forced password change"], fix="The user completes the prompt."),
    50127: dict(name="BrokerAppNotInstalled", sev="warning", short="a broker app must be installed",
                meaning="The user needs a broker app (Microsoft Authenticator or Company Portal) to access this content.",
                causes=["Device-based CA on mobile without the broker app"], fix="Install Microsoft Authenticator (iOS) or Company Portal (Android) and sign in again."),
    50129: dict(name="DeviceIsNotWorkplaceJoined", sev="critical", short="the device must be registered (workplace joined)",
                meaning="The device needs to be registered in Entra ID (workplace joined) to access this resource.",
                causes=["Device not registered"], fix="Register the device (Settings → Accounts → Access work or school → Connect, or Company Portal on mobile)."),
    50131: dict(name="ConditionalAccessFailed", sev="critical", short="a Conditional Access requirement failed",
                meaning="A Conditional Access check failed (for example Windows device state or a blocked request).",
                causes=["Device state or other CA requirement not met"], fix="Check the Conditional Access tab of the sign-in for the failed policy."),
    50135: dict(name="PasswordChangeCompromisedPassword", sev="warning", short="password change required because of account risk",
                meaning="Identity Protection detected risk on the account and requires a password change.",
                causes=["User risk policy (leaked credentials, risky behaviour)"],
                fix="The user changes their password (SSPR). Review the risk detections in Identity Protection."),
    50155: dict(name="DeviceAuthenticationFailed", sev="critical", short="device authentication failed",
                meaning="The device could not authenticate to Entra ID.",
                causes=["Device deleted or disabled in Entra ID", "Device certificate problem"],
                fix="Check the device object in Entra ID (enabled?), run dsregcmd /status on the device, and re-register it if needed.",
                steps=[{"title": "Check device registration", "commands": ["dsregcmd /status"]}]),
    50180: dict(name="WindowsIntegratedAuthMissing", sev="warning", short="Integrated Windows authentication is needed (Seamless SSO)",
                meaning="Integrated Windows authentication is required. The tenant needs Seamless SSO enabled, or the browser didn't send a Kerberos ticket.",
                causes=["Seamless SSO not enabled", "Intranet zone settings missing for https://autologon.microsoftazuread-sso.com"],
                fix="Check Seamless SSO is enabled in Entra Connect and that autologon.microsoftazuread-sso.com is in the browser's Intranet zone."),
    50196: dict(name="LoopDetected", sev="warning", short="a sign-in loop was detected",
                meaning="The app made the same sign-in request repeatedly in a short time, so Entra ID stopped it.",
                causes=["App bug or misconfiguration that re-requests tokens in a loop"],
                fix="App issue: check the app's sign-in configuration (often a reply URL / cookie problem)."),
    53011: dict(name="User blocked due to risk on home tenant", sev="critical", short="the user is blocked because of risk in their home tenant",
                meaning="The guest user's home tenant flagged them as risky, so access is blocked.",
                causes=["Identity Protection risk in the user's home organisation"], fix="The user's home tenant admin must remediate the risk."),
    530032: dict(name="BlockedByConditionalAccessOnSecurityPolicy", sev="critical", short="blocked by the tenant's security policy",
                 meaning="The tenant admin configured a security policy that blocks this request.",
                 causes=["Security policy / Conditional Access configuration"], fix="Review the tenant's security policies for this user and app."),
    700054: dict(name="Response_type 'id_token' not enabled", sev="critical", short="the app is not enabled for ID tokens (implicit flow)",
                 meaning="The app asked for an id_token but ID token issuance is not enabled on its app registration.",
                 causes=["Implicit grant setting off"], fix="App registration → Authentication → enable 'ID tokens', or change the app to the auth code flow."),
    7000218: dict(name="InvalidClient (no secret or assertion)", sev="critical", short="the app sent no client secret or certificate",
                  meaning="The request body must contain client_assertion or client_secret.",
                  causes=["Confidential app missing its credential", "Public client flows not enabled for a mobile/desktop app"],
                  fix="Configure the app's secret/certificate, or enable 'Allow public client flows' if it is a public client."),
    50194: dict(name="Application not configured as multi-tenant", sev="critical", short="the app is not multi-tenant, but was used with /common",
                meaning="The app isn't multi-tenant, so the /common endpoint can't be used. Use the tenant-specific endpoint or make the app multi-tenant.",
                causes=["Single-tenant app using /common or /organizations"], fix="Use https://login.microsoftonline.com/<tenant-id> or set the app to multi-tenant."),
    75011: dict(name="NoMatchedAuthnContextInOutputClaims", sev="critical", short="the authentication method doesn't match what the SAML app requested",
                meaning="The SAML app requested a specific authentication context (RequestedAuthnContext) that doesn't match how the user authenticated.",
                causes=["SAML app sends RequestedAuthnContext (e.g. PasswordProtectedTransport) while the user signed in with SSO/MFA"],
                fix="Remove RequestedAuthnContext from the app's SAML request, or set it to unspecified."),
    90002: dict(name="InvalidTenantName", sev="critical", short="the tenant was not found",
                meaning="The tenant name or ID in the request does not exist.",
                causes=["Typo in tenant name / domain", "Tenant deleted", "Wrong cloud (e.g. GCC High tenant on the commercial endpoint)"],
                fix="Check the tenant ID or domain in the sign-in URL. Use the Tenant & Federation tool to look it up."),
}

LEGACY_CLIENTS = {"exchange activesync", "imap4", "imap", "pop3", "pop", "authenticated smtp", "smtp", "mapi over http",
                  "offline address book", "other clients", "autodiscover", "exchange web services", "exchange online powershell",
                  "outlook anywhere (rpc over http)", "reporting web services", "universal outlook", "exchange activesync (supported)",
                  "exchange activesync (unsupported)"}
PASSWORD_CODES = {50126, 50053, 50056, 50034, 51004}
CA_CODES = {53000, 53001, 53002, 53003, 53004, 530003, 530032, 50005, 50131}
CA_REASON = {53000: "the device is not Intune-compliant", 53001: "the device is not hybrid Entra joined",
             53002: "the app is not an approved client app", 53003: "the policy blocks this access",
             53004: "MFA registration was blocked", 530003: "the device is not managed",
             50005: "the device platform is not supported", 50131: "a Conditional Access requirement was not met"}
CA_RESULT_LABEL = {"success": "Success", "failure": "Failure", "notapplied": "Not applied", "notenabled": "Not enabled",
                   "reportonlysuccess": "Report-only: success", "reportonlyfailure": "Report-only: failure",
                   "reportonlynotapplied": "Report-only: not applied", "reportonlyinterrupted": "Report-only: interrupted",
                   "unknownfuturevalue": "Unknown"}


def _err_url(code: int) -> str:
    return f"https://login.microsoftonline.com/error?code={code}"


def _code_info(code: int) -> dict:
    e = KB.get(code)
    if not e:
        return {"code": code, "aadsts": f"AADSTS{code}", "known": False, "url": _err_url(code),
                "short": "error not in the knowledge base", "sev": "warning", "interrupt": False}
    return {"code": code, "aadsts": f"AADSTS{code}", "known": True, "url": _err_url(code),
            "interrupt": bool(e.get("interrupt")), **{k: v for k, v in e.items() if k not in ("steps", "interrupt")}}


# -------------------------------------------------------------------- input parsing
def _lk(obj, *names):
    """Case-insensitive key lookup on a dict; returns first non-empty match."""
    if not isinstance(obj, dict):
        return None
    low = {str(k).lower(): v for k, v in obj.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, "", [], {}):
            if isinstance(v, str) and v[:1] in "{[":
                try:
                    return json.loads(v)
                except ValueError:
                    pass
            return v
    return None


def _to_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


GRANT_LABELS = {"mfa": "Require MFA", "block": "Block access", "requirecompliantdevice": "Require compliant device",
                "compliantdevice": "Require compliant device", "requiredomainjoineddevice": "Require hybrid Entra joined device",
                "domainjoineddevice": "Require hybrid Entra joined device", "requireapprovedapp": "Require approved client app",
                "approvedapplication": "Require approved client app", "requirecompliantapp": "Require app protection policy",
                "compliantapplication": "Require app protection policy", "passwordchange": "Require password change",
                "requirepasswordchange": "Require password change"}


def _grant_label(g) -> str:
    return GRANT_LABELS.get(str(g).replace(" ", "").lower(), str(g))


def _human_auth_req(v):
    return {"multifactorauthentication": "MFA required", "singlefactorauthentication": "Single-factor (password only)"}.get(
        str(v or "").replace("-", "").replace(" ", "").lower(), v)


def _norm_ca(p: dict) -> dict:
    res = str(_lk(p, "result") or "").replace(" ", "").replace("-", "").replace(":", "").lower()
    grants = _lk(p, "enforcedGrantControls") or []
    sess = _lk(p, "enforcedSessionControls") or []
    return {"name": _lk(p, "displayName", "DisplayName", "name") or "(unnamed policy)", "result": res or "unknown",
            "result_label": CA_RESULT_LABEL.get(res, res or "unknown"),
            "grant_controls": [_grant_label(g) for g in (grants if isinstance(grants, list) else [str(grants)])],
            "session_controls": sess if isinstance(sess, list) else [str(sess)]}


def _norm_event(o: dict) -> dict:
    status = _lk(o, "status") if isinstance(_lk(o, "status"), dict) else {}
    code = _to_int(_lk(status, "errorCode")) if status else None
    if code is None:
        code = _to_int(_lk(o, "errorCode", "ResultType", "resultType"))
    loc = _lk(o, "location", "LocationDetails") or {}
    loc_s = None
    if isinstance(loc, dict):
        loc_s = ", ".join(x for x in (_lk(loc, "city"), _lk(loc, "state"), _lk(loc, "countryOrRegion")) if x) or None
    elif isinstance(loc, str):
        loc_s = loc
    dev = _lk(o, "deviceDetail", "DeviceDetail") or {}
    if not isinstance(dev, dict):
        dev = {}
    mfa = _lk(o, "mfaDetail", "MfaDetail") or {}
    ca = _lk(o, "appliedConditionalAccessPolicies", "ConditionalAccessPolicies") or []
    auth_details = _lk(o, "authenticationDetails", "AuthenticationDetails") or []
    return {
        "time": _lk(o, "createdDateTime", "TimeGenerated", "CreatedDateTime"),
        "user": _lk(o, "userDisplayName", "UserDisplayName"),
        "upn": _lk(o, "userPrincipalName", "UserPrincipalName"),
        "user_type": _lk(o, "userType", "UserType"),
        "app": _lk(o, "appDisplayName", "AppDisplayName"),
        "app_id": _lk(o, "appId", "AppId"),
        "resource": _lk(o, "resourceDisplayName", "ResourceDisplayName"),
        "ip": _lk(o, "ipAddress", "IPAddress"),
        "location": loc_s,
        "client_app": _lk(o, "clientAppUsed", "ClientAppUsed"),
        "user_agent": _lk(o, "userAgent", "UserAgent"),
        "error_code": code,
        "failure_reason": (_lk(status, "failureReason") if status else None) or _lk(o, "ResultDescription", "failureReason"),
        "additional_details": (_lk(status, "additionalDetails") if status else None) or _lk(o, "additionalDetails"),
        "correlation_id": _lk(o, "correlationId", "CorrelationId"),
        "request_id": _lk(o, "id", "originalRequestId", "OriginalRequestId"),
        "auth_requirement": _lk(o, "authenticationRequirement", "AuthenticationRequirement"),
        "ca_status": _lk(o, "conditionalAccessStatus", "ConditionalAccessStatus"),
        "ca": [_norm_ca(p) for p in ca if isinstance(p, dict)] if isinstance(ca, list) else [],
        "mfa_method": _lk(mfa, "authMethod") if isinstance(mfa, dict) else None,
        "mfa_detail": _lk(mfa, "authDetail") if isinstance(mfa, dict) else None,
        "auth_steps": [{"method": _lk(a, "authenticationMethod"), "succeeded": _lk(a, "succeeded"),
                        "detail": _lk(a, "authenticationStepResultDetail")} for a in auth_details if isinstance(a, dict)][:10]
        if isinstance(auth_details, list) else [],
        "device": {"name": _lk(dev, "displayName"), "id": _lk(dev, "deviceId"), "os": _lk(dev, "operatingSystem"),
                   "browser": _lk(dev, "browser"), "compliant": _lk(dev, "isCompliant"), "managed": _lk(dev, "isManaged"),
                   "join_type": _lk(dev, "trustType")},
        "risk": _lk(o, "riskLevelDuringSignIn", "RiskLevelDuringSignIn"),
        "risk_state": _lk(o, "riskState", "RiskState"),
        "interactive": _lk(o, "isInteractive", "IsInteractive"),
        "home_tenant": _lk(o, "homeTenantId", "HomeTenantId"),
        "resource_tenant": _lk(o, "resourceTenantId", "ResourceTenantId"),
    }


def _looks_like_signin(o) -> bool:
    return isinstance(o, dict) and any(str(k).lower() in ("status", "errorcode", "resulttype", "appliedconditionalaccesspolicies",
                                                           "userprincipalname", "createddatetime", "conditionalaccesspolicies")
                                       for k in o)


def _parse_json(raw: str):
    s = raw.strip()
    data = None
    try:
        data = json.loads(s)
    except ValueError:
        # JSON lines
        items = []
        for line in s.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    items.append(json.loads(line))
                except ValueError:
                    return None
        data = items or None
    if data is None:
        return None
    if isinstance(data, dict):
        if isinstance(data.get("value"), list):
            data = data["value"]
        else:
            data = [data]
    if not isinstance(data, list):
        return None
    events = [_norm_event(o) for o in data if _looks_like_signin(o)]
    return events


TEXT_LABELS = {
    "date": "time", "request id": "request_id", "correlation id": "correlation_id",
    "authentication requirement": "auth_requirement", "status": "status", "sign-in error code": "error_code",
    "error code": "error_code", "failure reason": "failure_reason", "additional details": "additional_details",
    "user": "user", "username": "upn", "user principal name": "upn", "user type": "user_type", "application": "app",
    "application id": "app_id", "app id": "app_id", "resource": "resource", "client app": "client_app",
    "ip address": "ip", "location": "location", "device id": "device_id", "browser": "browser",
    "operating system": "os", "compliant": "compliant", "managed": "managed", "join type": "join_type",
    "user agent": "user_agent", "conditional access": "ca_status", "mfa result": "mfa_detail",
    "authentication method": "mfa_method",
}
_LABEL_RE = re.compile(r"^\s*(" + "|".join(sorted((re.escape(k) for k in TEXT_LABELS), key=len, reverse=True)) +
                       r")\s*(?::|\t|\s{2,})\s*(.+?)\s*$", re.I)
_CA_RESULT_RE = re.compile(r"^(report-only:\s*)?(success|failure|not applied|not enabled|interrupted)$", re.I)


def _parse_text(raw: str) -> dict | None:
    """Sign-in log details copied from the Entra portal (Basic info / Device info / Conditional Access tabs)."""
    lines = [l.rstrip() for l in raw.replace("\r", "").split("\n")]
    vals: dict = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _LABEL_RE.match(line)
        if m and TEXT_LABELS[m.group(1).lower()] not in vals:
            vals[TEXT_LABELS[m.group(1).lower()]] = m.group(2)
        elif line.strip().lower() in TEXT_LABELS and i + 1 < len(lines):
            nxt = lines[i + 1].strip()
            key = TEXT_LABELS[line.strip().lower()]
            if nxt and nxt.lower() not in TEXT_LABELS and key not in vals:
                vals[key] = nxt
                i += 1
        i += 1

    # Conditional Access tab: tab-separated rows, or one cell per line after a "Policy Name" header.
    ca: list[dict] = []
    in_ca = False
    buf: list[str] = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if re.match(r"(?i)^policy\s*name", s):
            in_ca = True
            buf = []
            continue
        cells = [c.strip() for c in line.split("\t") if c.strip()]
        if (len(cells) >= 3 or (in_ca and len(cells) == 2)) and _CA_RESULT_RE.match(cells[-1]) \
                and cells[0].lower() not in TEXT_LABELS:
            ca.append({"name": cells[0], "result_text": cells[-1], "grant_controls": cells[1:-1]})
            buf = []
            continue
        if in_ca:
            if _CA_RESULT_RE.match(s):
                if buf:
                    ca.append({"name": buf[0], "result_text": s, "grant_controls": buf[1:]})
                buf = []
            elif not re.match(r"(?i)^(grant controls|session controls|result)$", s):
                buf.append(s)
    for p in ca:
        res = p.pop("result_text").replace(" ", "").replace("-", "").replace(":", "").lower()
        p.update({"result": res, "result_label": CA_RESULT_LABEL.get(res, res), "session_controls": []})

    code = _to_int(vals.get("error_code"))
    if code is None and not ca and len(vals) < 2:
        return None
    if code is None and str(vals.get("status", "")).lower().startswith("success"):
        code = 0
    def yn(v):
        return None if v is None else str(v).strip().lower() in ("yes", "true")
    return {
        "time": vals.get("time"), "user": vals.get("user"), "upn": vals.get("upn"), "user_type": vals.get("user_type"),
        "app": vals.get("app"), "app_id": vals.get("app_id"), "resource": vals.get("resource"), "ip": vals.get("ip"),
        "location": vals.get("location"), "client_app": vals.get("client_app"), "user_agent": vals.get("user_agent"),
        "error_code": code, "failure_reason": vals.get("failure_reason"), "additional_details": vals.get("additional_details"),
        "correlation_id": vals.get("correlation_id"), "request_id": vals.get("request_id"),
        "auth_requirement": vals.get("auth_requirement"), "ca_status": vals.get("ca_status"), "ca": ca,
        "mfa_method": vals.get("mfa_method"), "mfa_detail": vals.get("mfa_detail"), "auth_steps": [],
        "device": {"name": None, "id": vals.get("device_id"), "os": vals.get("os"), "browser": vals.get("browser"),
                   "compliant": yn(vals.get("compliant")), "managed": yn(vals.get("managed")), "join_type": vals.get("join_type")},
        "risk": None, "risk_state": None, "interactive": None, "home_tenant": None, "resource_tenant": None,
    }


def _codes_in_text(raw: str) -> list[int]:
    s = raw.strip()
    if re.fullmatch(r"(?:AADSTS)?\d{4,7}(?:[\s,;]+(?:AADSTS)?\d{4,7})*[\s,;]*", s, re.I):
        return list(dict.fromkeys(int(x) for x in re.findall(r"\d{4,7}", s)))
    codes = [int(x) for x in re.findall(r"AADSTS(\d{4,7})", s, re.I)]
    codes += [int(x) for x in re.findall(r"(?i)(?:error\s*code|errorcode|resulttype)\W{0,6}(\d{5,7})\b", s)]
    return list(dict.fromkeys(codes))


# -------------------------------------------------------------------- analysis
def _fill(text: str, ev: dict | None) -> str:
    ev = ev or {}
    upn = ev.get("upn") or "user@contoso.com"
    sam = upn.split("@")[0] if "@" in upn else "username"
    return (text.replace("{upn}", upn).replace("{sam}", sam)
            .replace("{appid}", ev.get("app_id") or "<application-id>")
            .replace("{tenant}", ev.get("resource_tenant") or ev.get("home_tenant") or "<tenant-id>"))


def _steps_for(code: int, ev: dict | None) -> list[dict]:
    e = KB.get(code)
    if not e:
        return [{"title": f"Look up AADSTS{code} on Microsoft's error page", "detail": "This code isn't in MSPGather's knowledge base. Microsoft's lookup page explains it:",
                 "commands": [_err_url(code)]}]
    steps = []
    for s in e.get("steps", []):
        steps.append({"title": s["title"], "detail": _fill(s.get("detail", ""), ev) or None,
                      "commands": [_fill(c, ev) for c in s.get("commands", [])]})
    if not steps:
        steps.append({"title": e["fix"]})
    return steps


def _is_legacy(client_app: str | None) -> bool:
    return bool(client_app) and client_app.strip().lower() in LEGACY_CLIENTS


def _ca_blockers(ev: dict) -> list[dict]:
    return [p for p in ev.get("ca", []) if p["result"] == "failure"]


def _event_findings(ev: dict) -> list[dict]:
    F: list[dict] = []
    code = ev.get("error_code")
    blockers = _ca_blockers(ev)
    for p in blockers:
        grants = ", ".join(p["grant_controls"]) or "its grant controls"
        F.append(_f("critical", f"Conditional Access policy '{p['name']}' blocked this sign-in",
                    f"Result: Failure. The policy requires: {grants}. This is the policy to look at first."))
    for p in ev.get("ca", []):
        if p["result"] == "reportonlyfailure":
            F.append(_f("info", f"Report-only policy '{p['name']}' would block this sign-in once enabled",
                        "It's in report-only mode, so it did not block anything yet. Fix the cause before you switch it on."))
    if code not in (None, 0):
        info = _code_info(code)
        if info["known"]:
            sev = info["sev"]
            F.append(_f(sev, f"AADSTS{code}: {info['short']}",
                        f"{info['meaning']} Fix: {info['fix']}"))
        else:
            F.append(_f("warning", f"AADSTS{code} is not in the knowledge base",
                        f"Look it up on {_err_url(code)}. The failure reason Microsoft logged is shown below."))
    if _is_legacy(ev.get("client_app")):
        F.append(_f("warning", f"Legacy authentication: client app '{ev['client_app']}'",
                    "Legacy (basic auth) protocols can't do MFA and are the main target of password spray. "
                    "Move the client to modern authentication and block legacy auth with Conditional Access."))
    dev = ev.get("device") or {}
    if code in (53000, 530003) or any("compliant" in " ".join(p["grant_controls"]).lower() for p in blockers):
        if not dev.get("id"):
            F.append(_f("warning", "No device identity was sent with this sign-in",
                        "Entra ID could not tell which device this was, so it can't count as compliant or managed. Usually the browser: use Edge "
                        "signed in with the work profile, Chrome with the Microsoft Single Sign On extension, or Company Portal on macOS/iOS. "
                        "Device-based policies can never pass from an InPrivate/Incognito window."))
        elif dev.get("compliant") is False:
            F.append(_f("info", f"Entra ID identified the device ({dev.get('name') or dev['id']}) and it is marked not compliant",
                        "So the device identity reached Entra ID; the device itself is failing Intune compliance (or isn't enrolled)."))
    if code == 0 and str(ev.get("auth_requirement") or "").lower().startswith("single"):
        F.append(_f("info", "Signed in with a password only (single-factor)",
                    "No MFA was required for this sign-in. Check this is intended (trusted location, or a policy gap)."))
    if code == 0 and not ev.get("ca"):
        pass
    elif ev.get("ca") and all(p["result"] in ("notapplied", "notenabled", "reportonlynotapplied") for p in ev["ca"]):
        F.append(_f("info", "No Conditional Access policy applied to this sign-in",
                    "Every policy was 'Not applied' (its conditions didn't match). If you expected one to apply, check its users, apps and conditions."))
    risk = str(ev.get("risk") or "").lower()
    if risk in ("high", "medium"):
        F.append(_f("warning", f"Sign-in risk was {risk}", "Identity Protection flagged this sign-in. Check the risk detections for the user."))
    return F


def _event_headline(ev: dict) -> tuple[str, str]:
    code = ev.get("error_code")
    who = ev.get("upn") or ev.get("user") or "the user"
    app = ev.get("app") or "the app"
    if code == 0:
        if _is_legacy(ev.get("client_app")):
            return "warning", f"Sign-in succeeded for {who} to {app}, but over legacy authentication ({ev['client_app']})"
        return "ok", f"Sign-in succeeded for {who} to {app}"
    if code is None:
        return "info", f"Sign-in details for {who} (no error code found)"
    info = _code_info(code)
    blockers = _ca_blockers(ev)
    if blockers and (code in CA_CODES or not info["known"]):
        reason = CA_REASON.get(code, "its requirements were not met")
        return "critical", f"Blocked by Conditional Access policy '{blockers[0]['name']}': {reason} (AADSTS{code})"
    if code in CA_CODES:
        return "critical", f"Blocked by Conditional Access: {CA_REASON.get(code, info['short'])} (AADSTS{code})"
    if not info["known"]:
        return "warning", f"Sign-in failed with AADSTS{code}, which is not in the knowledge base"
    short = info["short"][0].upper() + info["short"][1:]
    if info["interrupt"]:
        return "info", f"{short} (AADSTS{code}). This is normally not a failure"
    return info["sev"], f"{short} (AADSTS{code})"


def _summarise_event(ev: dict) -> list[list]:
    dev = ev.get("device") or {}
    yn = lambda v: None if v is None else ("Yes" if v else "No")
    return [["When", ev.get("time")], ["User", " · ".join(x for x in (ev.get("user"), ev.get("upn")) if x) or None],
            ["User type", ev.get("user_type")], ["Application", ev.get("app")], ["Application ID", ev.get("app_id")],
            ["Resource", ev.get("resource")], ["Client app", ev.get("client_app")], ["IP address", ev.get("ip")],
            ["Location", ev.get("location")], ["Error code", None if ev.get("error_code") in (None,) else str(ev["error_code"])],
            ["Failure reason", ev.get("failure_reason")], ["Additional details", ev.get("additional_details")],
            ["Authentication requirement", ev.get("auth_requirement")],
            ["MFA", " · ".join(x for x in (ev.get("mfa_method"), ev.get("mfa_detail")) if x) or None],
            ["Conditional Access status", ev.get("ca_status")], ["Sign-in risk", ev.get("risk")],
            ["Device", " · ".join(x for x in (dev.get("name"), dev.get("os"), dev.get("browser")) if x) or None],
            ["Device ID", dev.get("id")], ["Device join type", dev.get("join_type")],
            ["Device compliant", yn(dev.get("compliant"))], ["Device managed", yn(dev.get("managed"))],
            ["Correlation ID", ev.get("correlation_id")], ["Request ID", ev.get("request_id")], ["User agent", ev.get("user_agent")]]


def _group_failures(events: list[dict]) -> tuple[list[dict], list[dict], tuple | None]:
    """Groups repeated failures by (code, IP). Returns (groups, findings, headline override)."""
    fails = [e for e in events if e.get("error_code") not in (None, 0)]
    groups: dict = defaultdict(lambda: {"count": 0, "users": set(), "apps": set(), "clients": set(), "times": []})
    for e in fails:
        g = groups[(e["error_code"], e.get("ip") or "?")]
        g["count"] += 1
        if e.get("upn"):
            g["users"].add(e["upn"].lower())
        if e.get("app"):
            g["apps"].add(e["app"])
        if e.get("client_app"):
            g["clients"].add(e["client_app"])
        if e.get("time"):
            g["times"].append(str(e["time"]))
    out = []
    for (code, ip), g in groups.items():
        t = sorted(g["times"])
        out.append({"code": code, "ip": ip, "count": g["count"], "users": sorted(g["users"]), "apps": sorted(g["apps"]),
                    "clients": sorted(g["clients"]), "first": t[0] if t else None, "last": t[-1] if t else None,
                    "short": _code_info(code)["short"]})
    out.sort(key=lambda g: -g["count"])
    F: list[dict] = []
    headline = None
    for g in out:
        if g["code"] not in PASSWORD_CODES or g["count"] < 5:
            continue
        nu = len(g["users"])
        clients = ", ".join(g["clients"]) or "unknown client"
        if nu >= 3:
            F.append(_f("critical", f"Password spray: {g['count']} failed sign-ins (AADSTS{g['code']}) against {nu} accounts from {g['ip']}",
                        f"One IP trying passwords against many accounts is an attack. Client app: {clients}. Block the IP (named location + CA block), "
                        "confirm MFA is enforced for everyone, block legacy authentication, and check whether any of these accounts had a successful sign-in from this IP."))
            headline = headline or ("critical", f"Password spray: {g['count']} failed sign-ins against {nu} accounts from {g['ip']} (AADSTS{g['code']})")
        else:
            who = g["users"][0] if g["users"] else "one account"
            F.append(_f("critical" if g["code"] == 50053 else "warning",
                        f"{g['count']} × AADSTS{g['code']} for {who} from {g['ip']}: likely a device or app with a saved old password",
                        f"Repeated failures from one IP for one user are almost always a phone, mail client, mapped drive or service still using an old password. Client app: {clients}; app: {', '.join(g['apps']) or 'unknown'}. "
                        "Find the device at that IP and update or remove the saved password."))
            headline = headline or ("critical" if g["code"] == 50053 else "warning",
                                    f"Stale credentials: {g['count']} × AADSTS{g['code']} ({g['short']}) for {who} from {g['ip']}")
    # Many IPs against one user.
    per_user: dict = defaultdict(set)
    for e in fails:
        if e["error_code"] in PASSWORD_CODES and e.get("upn") and e.get("ip"):
            per_user[e["upn"].lower()].add(e["ip"])
    for user, ips in per_user.items():
        if len(ips) >= 5:
            F.append(_f("critical", f"{user} failed password sign-ins from {len(ips)} different IPs",
                        "Distributed brute force against one account. Make sure MFA is enforced, reset the password if any attempt succeeded, and review the sign-ins."))
            headline = headline or ("critical", f"Brute force: failed password sign-ins for {user} from {len(ips)} different IP addresses")
    if any(e["error_code"] == 50053 for e in fails) and any(e["error_code"] == 50126 for e in fails):
        F.append(_f("info", "The lockouts (50053) follow wrong-password failures (50126)",
                    "Smart Lockout locked the account because of the 50126 failures. Fix the source of the wrong passwords and the lockouts stop."))
    return out, F, headline


def _spray_mode(events: list[dict], spray_groups: list[dict], findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Password spray: the victim-style advice for 50126/50053 ("does the user know their password?") is wrong here.
    Replace it with attacker-side guidance."""
    ips = list(dict.fromkeys(g["ip"] for g in spray_groups if g["ip"] and g["ip"] != "?"))
    targeted = sorted({u for g in spray_groups for u in g["users"]})
    victim_titles = tuple(f"AADSTS{c}:" for c in PASSWORD_CODES)
    out = [f for f in findings if not f["title"].startswith(victim_titles)
           and not f["title"].startswith("The lockouts (50053) follow wrong-password failures")]
    ips = [i for i in (cmdsafe.ip(x) for x in ips) if i]
    ip_txt = ", ".join(ips) or "the source IP"
    if any(e.get("error_code") == 50053 for e in events):
        locked = sorted({(e.get("upn") or "").lower() for e in events if e.get("error_code") == 50053 and e.get("upn")})
        out.append(_f("info", f"Smart Lockout is protecting these accounts ({len(locked) or 'some'} locked: AADSTS50053)",
                      "Entra Smart Lockout temporarily locks an account after repeated wrong passwords from unfamiliar locations, so the attacker "
                      "can't keep guessing. The real users can usually still sign in from their familiar locations. No password resets are "
                      "needed unless an attempt succeeded."))
    ok_from_ip = [e for e in events if e.get("error_code") == 0 and e.get("ip") in ips]
    ok_users = sorted({(e.get("upn") or "?").lower() for e in ok_from_ip})
    if ok_from_ip:
        out.append(_f("critical", f"Successful sign-in from the spraying IP: {', '.join(ok_users[:5])}",
                      "The attacker guessed a valid password. Treat the account as compromised: reset the password, revoke sessions, "
                      "check MFA methods and inbox rules, and review what it accessed."))
    else:
        out.append(_f("info", f"No successful sign-in from {ip_txt} in the pasted records",
                      "Good, but only these records were checked. Search the full sign-in log for that IP (command below)."))
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    out.sort(key=lambda f: order.get(f["severity"], 9))
    first_ip = ips[0] if ips else "203.0.113.10"
    ranges = ",".join(f'@{{"@odata.type"="#microsoft.graph.iPv{6 if ":" in ip else 4}CidrRange";cidrAddress="{ip}/{128 if ":" in ip else 32}"}}' for ip in (ips or [first_ip]))
    steps = [
        {"title": f"Block {ip_txt} with a Conditional Access named location",
         "detail": "Create an IP named location for the source, then a Conditional Access policy: All users (exclude break-glass accounts), "
                   "All resources, Network → Include that named location, Grant → Block access.",
         "commands": ["Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess",
                      'New-MgIdentityConditionalAccessNamedLocation -BodyParameter @{"@odata.type"="#microsoft.graph.ipNamedLocation";'
                      f'displayName="Blocked: password spray";isTrusted=$false;ipRanges=@({ranges})}}']},
        {"title": "Check for any successful sign-in from the source",
         "detail": f"A success from {ip_txt} means a guessed password: reset it and revoke that user's sessions.",
         "commands": ["Connect-MgGraph -Scopes AuditLog.Read.All"] +
                     [f"Get-MgAuditLogSignIn -Filter \"ipAddress eq '{ip}' and status/errorCode eq 0\" -All | "
                      "Format-Table CreatedDateTime,UserPrincipalName,AppDisplayName,ClientAppUsed" for ip in (ips or [first_ip])[:3]]},
        {"title": "Enforce MFA for every account and block legacy authentication",
         "detail": f"{len(targeted)} accounts were targeted. A Conditional Access policy requiring MFA for all users stops a guessed password "
                   "from being enough, and blocking legacy authentication (SMTP AUTH, IMAP, POP, ActiveSync basic auth) closes the protocols "
                   "sprays use because they can't do MFA."},
    ]
    return out, steps


def analyze_signin(raw: str) -> dict:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Paste an AADSTS code, an error message or sign-in log details.")
    events = None
    mode = "code"
    if raw[:1] in "{[":
        events = _parse_json(raw)
        if events is None:
            raise ValueError("This looks like JSON but couldn't be parsed. Paste the complete export (Graph signIns / Log Analytics SigninLogs).")
        if not events:
            raise ValueError("The JSON doesn't contain sign-in records (expected fields like status.errorCode, userPrincipalName, appliedConditionalAccessPolicies).")
        mode = "json"
    else:
        ev = _parse_text(raw)
        if ev:
            events = [ev]
            mode = "text"

    text_codes = _codes_in_text(raw)
    findings: list[dict] = []
    steps: list[dict] = []
    groups: list[dict] = []
    primary = None

    if events:
        fails = [e for e in events if e.get("error_code") not in (None, 0)]
        if mode == "text" and events[0].get("error_code") is None and text_codes:
            events[0]["error_code"] = text_codes[0]
            fails = events
        codes_count = Counter(e["error_code"] for e in fails)
        real_fails = [e for e in fails if not _code_info(e["error_code"]).get("interrupt")]
        pool = real_fails or fails or events
        top = Counter(e["error_code"] for e in pool).most_common(1)
        primary = next((e for e in reversed(pool) if not top or e.get("error_code") == top[0][0]), events[-1])
        sev, headline = _event_headline(primary)
        groups, gf, override = _group_failures(events)
        if override:
            sev, headline = override
        findings.extend(gf)
        findings.extend(_event_findings(primary))
        if override and any(f["severity"] == "critical" for f in findings):
            sev = "critical"
        # Interrupt followed by success within the same correlation ID.
        by_corr = defaultdict(list)
        for e in events:
            if e.get("correlation_id"):
                by_corr[e["correlation_id"]].append(e.get("error_code"))
        recovered = sum(1 for cs in by_corr.values() if 0 in cs and any(c not in (0, None) for c in cs))
        if recovered:
            findings.append(_f("info", f"{recovered} sign-in flow(s) failed first and then succeeded (same correlation ID)",
                               "Interrupts like 50074 / 50140 followed by success are normal steps in a sign-in, not failures."))
        if len(events) > 1:
            ok = sum(1 for e in events if e.get("error_code") == 0)
            findings.append(_f("info", f"{len(events)} sign-in records: {len(fails)} failed, {ok} succeeded",
                               "Error codes: " + ", ".join(f"{c} × {n}" for c, n in codes_count.most_common(8)) if codes_count else ""))
        if primary.get("error_code") not in (None, 0):
            # For multi-account patterns, don't fill one random victim into the commands.
            many_users = len({(e.get("upn") or "").lower() for e in fails}) > 1
            steps = _steps_for(primary["error_code"], None if many_users else primary)
        spray_groups = [g for g in groups if g["code"] in PASSWORD_CODES and g["count"] >= 5 and len(g["users"]) >= 3]
        if spray_groups:
            findings, steps = _spray_mode(events, spray_groups, findings)
        codes = [dict(_code_info(c), count=n) for c, n in codes_count.most_common()] or (
            [dict(_code_info(c), count=1) for c in text_codes])
        subline_bits = [primary.get("upn"), primary.get("app"), primary.get("ip"), primary.get("location"), primary.get("time")]
        subline = " · ".join(str(x) for x in subline_bits if x)
        if len(events) > 1:
            times = sorted(str(e["time"]) for e in events if e.get("time"))
            nu = len({(e.get('upn') or '').lower() for e in events if e.get('upn')})
            ni = len({e.get('ip') for e in events if e.get('ip')})
            subline = (f"{len(events)} sign-in records · {nu} account{'s' * (nu != 1)} · {ni} IP address{'es' * (ni != 1)}"
                       + (f" · {times[0]} → {times[-1]}" if times else ""))
        elif primary.get("failure_reason"):
            subline = (subline + " · " if subline else "") + f"Logged reason: {primary['failure_reason']}"
    else:
        if not text_codes:
            raise ValueError("No AADSTS error code found. Paste a code like AADSTS50126 or 50126, an error message, "
                             "or sign-in details copied from Entra admin center → Sign-in logs.")
        mode = "code"
        codes = [dict(_code_info(c), count=1) for c in text_codes]
        first = codes[0]
        if first["known"]:
            short = first["short"][0].upper() + first["short"][1:]
            sev = "info" if first["interrupt"] else first["sev"]
            headline = f"AADSTS{first['code']}: {short}" + (" (an interrupt, normally not a failure)" if first["interrupt"] and "interrupt" not in short else "")
            subline = first["meaning"]
        else:
            sev = "warning"
            headline = f"AADSTS{first['code']} is not in the knowledge base"
            subline = f"Microsoft's lookup page explains it: {first['url']}"
        for c in codes:
            if c["known"]:
                findings.append(_f("info" if c["interrupt"] else c["sev"], f"AADSTS{c['code']}: {c['short']}",
                                   f"Typical causes: {'; '.join(c['causes'])}. Fix: {c['fix']}"))
            else:
                findings.append(_f("warning", f"AADSTS{c['code']} is not in the knowledge base",
                                   f"Microsoft's own lookup: {c['url']}"))
        steps = _steps_for(codes[0]["code"], None)

    facts = []
    if primary:
        dev = primary.get("device") or {}
        n_accounts = len({(e.get("upn") or "").lower() for e in (events or []) if e.get("upn")})
        facts = [["Accounts", f"{n_accounts} accounts"] if n_accounts > 1 else ["User", primary.get("upn") or primary.get("user")],
                 ["App", primary.get("app")],
                 ["Client app", primary.get("client_app")], ["IP", primary.get("ip")],
                 ["Device", "compliant" if dev.get("compliant") else ("not compliant" if dev.get("compliant") is False else None)],
                 ["Auth", _human_auth_req(primary.get("auth_requirement"))]]
    rows = [{"time": e.get("time"), "upn": e.get("upn"), "app": e.get("app"), "ip": e.get("ip"), "location": e.get("location"),
             "client_app": e.get("client_app"), "code": e.get("error_code"),
             "short": None if e.get("error_code") in (None, 0) else _code_info(e["error_code"])["short"]}
            for e in (events or [])][:500]
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return {"mode": mode, "severity": sev, "headline": headline, "subline": subline, "facts": facts,
            "findings": findings, "steps": steps, "codes": codes, "primary": _summarise_event(primary) if primary else None,
            "ca": primary.get("ca", []) if primary else [], "auth_steps": primary.get("auth_steps", []) if primary else [],
            "groups": groups[:50] if len(events or []) > 1 else [], "events": rows, "event_count": len(events or [])}


def kb_list() -> dict:
    return {"codes": [{"code": c, "name": e["name"], "short": e["short"]} for c, e in sorted(KB.items())]}


# =====================================================================================
#                               TENANT & FEDERATION
# =====================================================================================
CLOUDS = {"microsoftonline.com": "Worldwide (commercial)", "microsoftonline.us": "US Government (GCC High / DoD)",
          "partner.microsoftonline.cn": "China (operated by 21Vianet)", "microsoftonline.de": "Germany (legacy, retired)"}
REGION_SCOPES = {"NA": "North America", "EU": "Europe", "AS": "Asia", "OC": "Oceania", "AF": "Africa", "SA": "South America",
                 "WW": "Worldwide", "USGov": "US Government", "USG": "US Government"}
SUB_SCOPES = {"GCC": "GCC (US Government Community Cloud, on the commercial cloud)", "DODCON": "GCC High", "DOD": "DoD"}


def _short_lived(cert: dict) -> bool:
    """Certificates valid for <= 100 days (Let's Encrypt and similar ACME issuers) are renewed automatically."""
    try:
        life = datetime.fromisoformat(cert["not_after"]) - datetime.fromisoformat(cert["not_before"])
    except (KeyError, ValueError):
        return False
    return life.days <= 100


def _lc(s: str) -> str:
    """Lower-case the first letter unless it starts an acronym (HTTPS, AD FS)."""
    return s if len(s) > 1 and s[1].isupper() else s[:1].lower() + s[1:]


def _idp_for(url: str) -> tuple[str, str | None]:
    """Guess the identity provider from the federation AuthURL. Returns (name, kind)."""
    p = urlparse(url or "")
    host, path = (p.hostname or "").lower(), (p.path or "").lower()
    if "/adfs/" in path:
        return "AD FS", "adfs"
    if host.endswith((".okta.com", ".oktapreview.com", ".okta-emea.com")) or ("/app/office365/" in path and "/sso/wsfed" in path):
        return "Okta", "okta"
    if host.endswith((".pingone.com", ".pingone.eu", ".pingidentity.com")) or path.startswith("/idp/prp.wsf") or "/idp/sso.saml2" in path:
        return "PingFederate / PingOne", "ping"
    if path.startswith("/idp/profile/saml2"):
        return "Shibboleth", "shibboleth"
    if host.endswith(".onelogin.com"):
        return "OneLogin", "onelogin"
    if host.endswith(".duosecurity.com"):
        return "Duo", "duo"
    if host.endswith(".jumpcloud.com"):
        return "JumpCloud", "jumpcloud"
    if host.endswith((".auth0.com",)):
        return "Auth0", "auth0"
    if host == "accounts.google.com":
        return "Google", "google"
    if "/saml/sps/" in path:
        return "IBM Security Verify Access", "ibm"
    if "/nidp/" in path:
        return "NetIQ Access Manager", "netiq"
    return "a third-party identity provider", None


def _microsoft_realm(host: str) -> str | None:
    """'consumer' for Microsoft personal-account sign-in hosts, 'internal' for other *.microsoftonline.com targets."""
    host = (host or "").lower().rstrip(".")
    if host in ("login.live.com", "login.microsoftonline.com"):
        return "consumer"
    if host == "microsoftonline.com" or host.endswith(".microsoftonline.com"):
        return "internal"
    return None


class OutboundRefused(Exception):
    pass


def _public_ips(host: str) -> list[str]:
    """Resolve and refuse anything that is not a globally routable unicast address."""
    ips = [host.strip("[]")] if is_ip(host) else addresses(make_resolver(), host)
    if not ips:
        raise OutboundRefused(f"{host} does not resolve")
    for ip in ips:
        a = ipaddress.ip_address(ip)
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
            a = a.ipv4_mapped
        if (not a.is_global or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
                or a.is_reserved or a.is_private or a in ipaddress.ip_network("100.64.0.0/10")):
            raise OutboundRefused(f"{host} resolves to {ip}, a private/internal address. MSPGather won't connect to it")
    return sorted(ips, key=lambda x: ":" in x)  # IPv4 first


def _connect_tls(host: str, ips: list[str], timeout: float):
    """Connect to the first reachable IP; verify TLS, falling back to unverified so we can still read the cert."""
    last: Exception | None = None
    for ip in ips[:4]:
        try:
            raw = socket.create_connection((ip, 443), timeout=timeout)
        except OSError as exc:
            last = exc
            continue
        try:
            ctx = ssl.create_default_context()
            return ctx.wrap_socket(raw, server_hostname=host), None, ip
        except ssl.SSLCertVerificationError as exc:
            raw.close()
            err = exc.verify_message or str(exc)
            raw = socket.create_connection((ip, 443), timeout=timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx.wrap_socket(raw, server_hostname=host), err, ip
        except (ssl.SSLError, OSError) as exc:
            raw.close()
            last = exc
    raise last or OSError("connection failed")


def _read_http(sock) -> tuple[int, dict, bytes, bool]:
    data = b""
    truncated = False
    deadline = time.monotonic() + 15
    while True:
        if time.monotonic() > deadline:
            truncated = True
            break
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_BODY + 16384:
            truncated = True
            break
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    status = int(m.group(1)) if m else 0
    headers = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        out, rest = b"", body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            try:
                size = int(size_line.split(b";")[0].strip() or b"0", 16)
            except ValueError:
                break
            if size == 0:
                break
            out += rest[:size]
            rest = rest[size + 2:]
        body = out
    return status, headers, body[:MAX_BODY], truncated


def _https_get(url: str, timeout: float = FETCH_TIMEOUT) -> dict:
    """GET over a socket pinned to the validated IP (no DNS rebinding), with TLS cert details."""
    result: dict = {"url": url, "status": None, "error": None, "tls_error": None, "cert": None, "body": b"", "ip": None,
                    "redirects": []}
    for _ in range(MAX_REDIRECTS + 1):
        p = urlparse(url)
        if p.scheme != "https" or not p.hostname:
            result["error"] = f"Refused to follow non-HTTPS URL {url}"
            return result
        host = p.hostname
        try:
            ips = _public_ips(host)
            sock, tls_err, ip = _connect_tls(host, ips, timeout)
        except OutboundRefused as exc:
            result["error"] = str(exc)
            return result
        except (OSError, ssl.SSLError) as exc:
            result["error"] = f"Could not connect to {host}:443 ({exc.__class__.__name__}: {exc})"
            return result
        with sock:
            sock.settimeout(timeout)
            if result["cert"] is None:
                der = sock.getpeercert(binary_form=True)
                if der:
                    result["cert"] = _cert_info(der, host)
                result["tls_error"] = tls_err
                result["tls_version"] = sock.version()
                result["ip"] = ip
            path = (p.path or "/") + (f"?{p.query}" if p.query else "")
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MSPGather/identity\r\n"
                   "Accept: application/xml, text/xml, */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
            try:
                sock.sendall(req.encode())
                status, headers, body, truncated = _read_http(sock)
            except (OSError, ssl.SSLError) as exc:
                result["error"] = f"Connection to {host} failed while reading ({exc})"
                return result
        result["status"] = status
        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            url = urljoin(url, headers["location"])
            result["redirects"].append(url)
            continue
        result["body"] = body
        result["truncated"] = truncated
        result["content_type"] = headers.get("content-type")
        return result
    result["error"] = "Too many redirects"
    return result


MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def _parse_metadata(body: bytes) -> dict:
    text = body.decode("utf-8-sig", "replace")
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise ValueError("metadata contains a DOCTYPE/ENTITY declaration; refusing to parse it")
    root = ET.fromstring(text)
    out: dict = {"entity_id": root.get("entityID"), "signing": [], "encryption": []}
    seen: set = set()
    for kd in root.iter(f"{{{MD_NS}}}KeyDescriptor"):
        use = (kd.get("use") or "signing").lower()
        for c in kd.iter(f"{{{DS_NS}}}X509Certificate"):
            b64 = re.sub(r"\s+", "", c.text or "")
            try:
                der = base64.b64decode(b64)
                cert = x509.load_der_x509_certificate(der)
            except (ValueError, TypeError):
                continue
            sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
            if (use, sha1) in seen:
                continue
            seen.add((use, sha1))
            info = _cert_info(der, "")
            info.pop("hostname_match", None)
            info["thumbprint_sha1"] = sha1
            info["thumbprint_sha256"] = hashlib.sha256(der).hexdigest().upper()
            (out["encryption"] if use == "encryption" else out["signing"]).append(info)
    for k in ("signing", "encryption"):
        out[k].sort(key=lambda c: c["not_after"])
    return out


def _tenant_extras(domain: str) -> dict:
    out: dict = {"realm": None, "v1": None, "realm_error": None}
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            with ThreadPoolExecutor(max_workers=2) as pool:
                fr = pool.submit(client.get, "https://login.microsoftonline.com/getuserrealm.srf",
                                 params={"login": f"mspgather-probe@{domain}", "json": "1"})
                fv = pool.submit(client.get, f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration")
                r, v = fr.result(), fv.result()
            if r.status_code == 200:
                out["realm"] = r.json()
            if v.status_code == 200:
                out["v1"] = v.json()
            elif v.status_code == 400:
                try:
                    out["v1_error"] = v.json().get("error_description", "").split("\r\n")[0]
                except ValueError:
                    pass
    except (httpx.HTTPError, ValueError) as exc:
        out["realm_error"] = str(exc)
    return out


def tenant_lookup(target: str) -> dict:
    raw = (target or "").strip()
    if not raw:
        raise ValueError("Enter a domain or email address.")
    domain = normalize_domain(raw)
    cloud_hint = None
    if domain.endswith((".b2clogin.com", ".ciamlogin.com")):
        cloud_hint = "Azure AD B2C" if domain.endswith(".b2clogin.com") else "Entra External ID (CIAM)"
        domain = domain.split(".")[0] + ".onmicrosoft.com"
    with ThreadPoolExecutor(max_workers=2) as pool:
        fm = pool.submit(check_m365_tenant, domain)
        fx = pool.submit(_tenant_extras, domain)
        m365, extra = fm.result(), fx.result()
    realm = extra.get("realm") or {}
    v1 = extra.get("v1") or {}
    ns = realm.get("NameSpaceType") or m365.get("namespace_type")
    tenant_id = m365.get("tenant_id")
    if not tenant_id and v1:
        mm = re.search(r"/([0-9a-f-]{36})/", v1.get("issuer", ""))
        tenant_id = mm.group(1) if mm else None
    cloud_name = realm.get("CloudInstanceName") or v1.get("cloud_instance_name") or m365.get("cloud_instance")
    region = v1.get("tenant_region_scope")
    sub = v1.get("tenant_region_sub_scope")
    cloud_label = cloud_hint or (SUB_SCOPES.get(sub) and f"{CLOUDS.get(cloud_name, cloud_name)} · {SUB_SCOPES[sub]}") or CLOUDS.get(cloud_name, cloud_name)
    auth_url = realm.get("AuthURL") or m365.get("auth_url")
    out: dict = {"domain": domain, "input": raw, "tenant_id": tenant_id, "namespace_type": ns,
                 "federation_brand": realm.get("FederationBrandName") or m365.get("federation_brand"),
                 "cloud_instance": cloud_name, "cloud_label": cloud_label, "region_scope": region,
                 "region_label": REGION_SCOPES.get(region, region), "region_sub_scope": sub,
                 "auth_url": auth_url, "idp": None, "idp_host": None, "federation": None,
                 "errors": [e for e in (m365.get("error"), extra.get("realm_error")) if e]}
    F: list[dict] = []
    steps: list[dict] = []
    if out["errors"] and not tenant_id and not ns:
        raise ValueError(f"Could not reach Microsoft's discovery endpoints: {out['errors'][0]}")

    if ns == "Unknown" and not tenant_id:
        out.update(severity="info", headline=f"{domain} is not in any Microsoft 365 / Entra ID tenant",
                   subline="Microsoft doesn't know this domain: it isn't verified in any tenant, so users can't sign in with it.")
        F.append(_f("info", "Domain not found in Entra ID",
                    "If it should be in Microsoft 365: add and verify the domain (Microsoft 365 admin center → Settings → Domains). "
                    "Mail to Exchange Online for this domain will be rejected until it is verified."))
        out.update(findings=F, steps=steps)
        return out

    if tenant_id:
        F.append(_f("ok", f"Domain is verified in tenant {tenant_id}"))
    if cloud_name and cloud_name != "microsoftonline.com":
        F.append(_f("info", f"Tenant is in the {CLOUDS.get(cloud_name, cloud_name)} cloud",
                    f"Sign-in and admin endpoints differ from commercial Microsoft 365 (login.{cloud_name}). Tools and scripts must use that cloud's endpoints."))
    if sub in SUB_SCOPES:
        F.append(_f("info", f"US Government tenant: {SUB_SCOPES[sub]}", "Some features and third-party apps are not available in government clouds."))
    if cloud_hint:
        F.append(_f("info", f"{cloud_hint} tenant", "This is a customer-identity tenant, not a workforce Microsoft 365 tenant."))

    if ns == "Managed":
        short_tid = (tenant_id[:4] + "…") if tenant_id else "?"
        out.update(severity="ok", headline=f"Managed domain in tenant {short_tid}, no federation",
                   subline="Users sign in directly with Entra ID (cloud passwords, Password Hash Sync or Pass-through Authentication). There is no AD FS or third-party IdP to check.")
        out.update(findings=F, steps=steps)
        return out

    if ns != "Federated":
        out.update(severity="info", headline=f"{domain}: namespace type '{ns or 'unknown'}' in tenant {tenant_id or '?'}",
                   subline="Microsoft returned an unusual answer for this domain.")
        out.update(findings=F, steps=steps)
        return out

    # ---------------- federated
    idp_name, kind = _idp_for(auth_url or "")
    host = (urlparse(auth_url or "").hostname or "").lower()
    out["idp"], out["idp_host"], out["idp_kind"] = idp_name, host, kind
    fed: dict = {"host": host, "https": None, "metadata_url": None, "metadata": None, "metadata_error": None}
    out["federation"] = fed
    if not host:
        out.update(severity="warning", headline=f"{domain} is federated, but Microsoft returned no sign-in URL",
                   subline="Can't check the identity provider without its URL.", findings=F, steps=steps)
        return out

    # Microsoft's own sign-in hosts are not a customer IdP: no AD FS to probe, no metadata to read.
    ms_kind = _microsoft_realm(host)
    if ms_kind:
        out["idp_kind"] = ms_kind
        if ms_kind == "consumer":
            out["idp"] = "Microsoft personal accounts"
            headline = f"{domain} uses Microsoft personal accounts (consumer domain, not a work tenant)"
            F.append(_f("info", f"Sign-in goes to Microsoft's consumer account service ({host})",
                        f"Addresses at {domain} are personal Microsoft accounts (Outlook.com / Live / Hotmail style), not work or school accounts. "
                        "Microsoft reports this as 'federated', but there is no customer identity provider, AD FS or token-signing certificate to check. "
                        "Such users can't be managed from a business tenant; invite them as guests if they need access."))
        else:
            out["idp"] = "Microsoft (internal)"
            headline = f"{domain}: unmanaged or Microsoft-internal test configuration, not real federation"
            F.append(_f("info", f"The federation target is a Microsoft host ({host})",
                        f"Microsoft reports {domain} as federated to its own {host} endpoint rather than to a customer identity provider. "
                        "That's an unmanaged or Microsoft-internal (test) configuration, not an AD FS farm, so there's nothing to troubleshoot on a customer IdP. "
                        "If a client really owns this domain, they need to add and verify it in their own tenant."))
        F.sort(key=lambda f: {"critical": 0, "warning": 1, "info": 2, "ok": 3}.get(f["severity"], 9))
        out.update(severity="info", headline=headline,
                   subline=f"Tenant {tenant_id or '?'} · {out['federation_brand'] or ''} · Microsoft sends users to {host} to sign in.".replace(" ·  ·", " ·"),
                   findings=F, steps=steps)
        return out

    jobs = {"https": f"https://{host}/"}
    if kind in ("adfs", None):
        fed["metadata_url"] = f"https://{host}/FederationMetadata/2007-06/FederationMetadata.xml"
        jobs = {"https": fed["metadata_url"]}
    r = _https_get(jobs["https"])
    fed["https"] = {k: r.get(k) for k in ("status", "error", "tls_error", "cert", "ip", "tls_version", "redirects")}
    if fed["metadata_url"] and not r.get("error"):
        if r.get("status") == 200 and r.get("body"):
            try:
                fed["metadata"] = _parse_metadata(r["body"])
            except (ET.ParseError, ValueError) as exc:
                fed["metadata_error"] = f"Federation metadata could not be parsed: {exc}"
        else:
            fed["metadata_error"] = f"Federation metadata returned HTTP {r.get('status')}"

    # HTTPS / reachability findings
    cert = r.get("cert")
    if r.get("error"):
        F.append(_f("warning" if "private" not in r["error"] else "info", f"{host} could not be reached from MSPGather",
                    f"{r['error']}. Federated sign-in needs this host reachable from the user's network. If it's down for everyone, "
                    "all federated sign-ins fail. Check the AD FS / Web Application Proxy servers and the firewall/load balancer."))
    else:
        if r.get("tls_error"):
            F.append(_f("critical", f"HTTPS certificate on {host} is not trusted: {r['tls_error']}",
                        "Browsers will show a certificate error on the sign-in page. Renew/replace the SSL (service communications) certificate, "
                        "including on every Web Application Proxy server."))
        if cert:
            if cert["expired"]:
                F.append(_f("critical", f"HTTPS certificate on {host} expired on {cert['not_after'][:10]}",
                            "Users get a certificate error at sign-in. Install a renewed certificate on AD FS and the Web Application Proxies."))
            elif _short_lived(cert) and cert["days_left"] <= 14:
                F.append(_f("critical" if cert["days_left"] <= 3 else "warning",
                            f"HTTPS certificate on {host} expires in {cert['days_left']} days",
                            f"It's a short-lived, automatically renewed certificate (issued by {cert['issuer']}), so a short remaining life can be normal, "
                            "but by now it would usually have been renewed. Check the renewal job and that the renewed certificate is bound on AD FS / every Web Application Proxy."))
            elif cert["days_left"] <= 14:
                F.append(_f("critical", f"HTTPS certificate on {host} expires in {cert['days_left']} days",
                            "Renew it now and install it on the AD FS servers and Web Application Proxies."))
            elif cert["days_left"] <= 30 and not _short_lived(cert):
                F.append(_f("warning", f"HTTPS certificate on {host} expires in {cert['days_left']} days",
                            "Plan the renewal: AD FS servers and every Web Application Proxy need the new certificate."))
            elif not r.get("tls_error"):
                F.append(_f("ok", f"HTTPS certificate on {host} is valid ({cert['days_left']} days left)"))

    headline = None
    sev = "info"
    md = fed.get("metadata")
    if kind == "adfs" or md:
        signing = (md or {}).get("signing", [])
        if md and signing:
            latest = max(signing, key=lambda c: c["not_after"])
            soonest = min(signing, key=lambda c: c["not_after"])
            dl = latest["days_left"]
            if latest["expired"]:
                sev = "critical"
                headline = f"Federated to {idp_name} ({host}): token-signing certificate EXPIRED on {latest['not_after'][:10]}"
                F.append(_f("critical", f"Token-signing certificate expired {abs(dl)} days ago",
                            "Every federated sign-in to Microsoft 365 fails, because Entra ID can't trust the tokens AD FS signs. Renew the token-signing "
                            "certificate on AD FS and update the federation settings in Entra ID."))
            elif dl <= 30:
                sev = "critical"
                headline = f"Federated to {idp_name} ({host}): token-signing certificate expires in {dl} days"
                F.append(_f("critical", f"Token-signing certificate expires in {dl} days ({latest['not_after'][:10]})",
                            "When it expires, ALL federated sign-ins to Microsoft 365 break. Renew it on AD FS now and make sure Entra ID has the new certificate."))
            elif dl <= 60:
                sev = "warning"
                headline = f"Federated to {idp_name} ({host}): token-signing certificate expires in {dl} days"
                F.append(_f("warning", f"Token-signing certificate expires in {dl} days ({latest['not_after'][:10]})",
                            "Plan the renewal. If AutoCertificateRollover is on, AD FS creates the new certificate 20 days before expiry, but Entra ID still needs to get it."))
            else:
                sev = "ok"
                headline = f"Federated to {idp_name} ({host}): token-signing certificate valid for {dl} days"
                F.append(_f("ok", f"Token-signing certificate valid until {latest['not_after'][:10]} ({dl} days)"))
            if len(signing) > 1 and soonest is not latest:
                sd = soonest["days_left"]
                soon = not soonest["expired"] and sd <= 30
                F.append(_f("warning" if soon else "info",
                            f"Token-signing certificate rollover in progress: the current certificate expires in {sd} days" if soon
                            else f"Metadata publishes {len(signing)} token-signing certificates (old and new, normal during rollover)",
                            f"The older one ({soonest['thumbprint_sha1'][:12]}…) {'expired' if soonest['expired'] else f'expires in {sd} days'}; the newer one is valid "
                            f"until {latest['not_after'][:10]}. Make sure Entra ID trusts the NEW certificate (Get-MgDomainFederationConfiguration shows "
                            "SigningCertificate / NextSigningCertificate); otherwise sign-ins break when AD FS switches over."))
            if any(c["self_signed"] for c in signing):
                F.append(_f("info", "Token-signing certificate is self-signed",
                            "Normal for AD FS (auto-generated certificates). Not a problem."))
        elif fed.get("metadata_error") or r.get("error"):
            sev = "warning"
            headline = f"Federated to {idp_name} ({host}): token-signing certificate could not be checked"
            unreadable = bool(fed.get("metadata_error") and "parsed" in fed["metadata_error"])
            F.append(_f("warning", "Federation metadata could not be read" if unreadable else "Federation metadata not available from the internet",
                        f"{fed.get('metadata_error') or r.get('error')}. " + ("" if unreadable else "Many organisations don't publish it externally. ") +
                        "Check the token-signing certificate on the AD FS server (Get-AdfsCertificate)."))
        if md and md.get("entity_id"):
            F.append(_f("info", f"Federation service identifier: {md['entity_id']}",
                        "This must match the IssuerUri configured for the domain in Entra ID."))
        steps = [
            {"title": "Check the token-signing certificates and auto-rollover on the AD FS server",
             "commands": ["Get-AdfsCertificate -CertificateType Token-Signing | Format-Table IsPrimary,Thumbprint,@{n='NotAfter';e={$_.Certificate.NotAfter}}",
                          "Get-AdfsProperties | Format-List AutoCertificateRollover,CertificateGenerationThreshold,CertificatePromotionThreshold"]},
            {"title": "Compare with what Entra ID trusts for the domain",
             "detail": "SigningCertificate (and NextSigningCertificate during rollover) must match the AD FS token-signing certificate.",
             "commands": ["Connect-MgGraph -Scopes Domain.Read.All",
                          f"Get-MgDomainFederationConfiguration -DomainId {domain} | Format-List IssuerUri,PassiveSignInUri,SigningCertificate,NextSigningCertificate"]},
        ]
        if sev in ("critical", "warning") and md:
            steps.insert(0, {"title": "Renew the token-signing certificate now (AD FS with auto-rollover on)",
                             "detail": "Then update Entra ID with the new certificate (Update-MgDomainFederationConfiguration, or Entra Connect → Manage federation).",
                             "commands": ["Update-AdfsCertificate -CertificateType Token-Signing -Urgent"]})
    else:
        sev = "info"
        headline = f"Federated to {idp_name} ({host}): sign-in for {domain} happens there, not in Entra ID"
        F.append(_f("info", f"Sign-in is handled by {idp_name}",
                    "Password, MFA and lockout problems for these users are on the IdP side: check its logs. "
                    "The token-signing certificate is managed in that IdP; make sure its expiry is tracked."))
        steps = [{"title": "Check the federation settings Entra ID holds for the domain",
                  "commands": ["Connect-MgGraph -Scopes Domain.Read.All",
                               f"Get-MgDomainFederationConfiguration -DomainId {domain} | Format-List IssuerUri,PassiveSignInUri,SigningCertificate,NextSigningCertificate"]}]
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    worst = min(F, key=lambda f: order.get(f["severity"], 9), default=None)
    if worst and worst["severity"] in ("critical", "warning") and order[worst["severity"]] < order.get(sev, 9):
        sev = worst["severity"]
        t = worst["title"]
        if t.startswith(host):
            t = "the sign-in host " + t
        headline = f"Federated to {idp_name} ({host}): {_lc(t)}"
    F.sort(key=lambda f: order.get(f["severity"], 9))
    out.update(severity=sev, headline=headline,
               subline=f"Tenant {tenant_id or '?'} · {out['federation_brand'] or ''} · Microsoft 365 sends users to {host} to sign in.".replace(" ·  ·", " ·"),
               findings=F, steps=steps)
    return out


# =====================================================================================
#                                     ROUTES
# =====================================================================================
class SigninText(BaseModel):
    raw: str = Field(..., max_length=5_000_000)


@router.post("/api/identity/aadsts")
def api_aadsts(body: SigninText):
    return run(analyze_signin, body.raw)


@router.get("/api/identity/aadsts")
def api_aadsts_get(code: str = Query(..., max_length=200)):
    return run(analyze_signin, code)


@router.get("/api/identity/aadsts-codes")
def api_aadsts_codes():
    return kb_list()


@router.get("/api/identity/tenant/{target:path}")
def api_tenant(target: str):
    return run(tenant_lookup, target)
