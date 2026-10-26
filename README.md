# MSPGather

A self-hosted toolkit for MSP engineers, organised the way you work:

- **Discover**: profile a prospect from public data before the first call. Their email platform and spam filter, Microsoft 365 tenant, security grade, SaaS stack and internet-facing systems, turned into talking points and a client-ready snapshot.
- **Harden**: turn findings into a prioritised fix list for a client's public-facing configuration, with the exact DNS records and commands, and prove the improvement on the next run.
- **Troubleshoot**: paste message headers, a bounce, a sign-in error or a log and get the cause and the fix.

Every result reads top-down: a **one-sentence verdict**, findings ordered by severity, **what to do** (with copy-paste records and PowerShell), then the raw details. Prospect work uses public information only, and active tests only run against systems you're authorized to test (see [Responsible use](#responsible-use)).

## Quick start

```bash
docker run -d --name mspgather -p 127.0.0.1:8080:8080 -v mspgather-data:/data --restart unless-stopped \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/kcorr/mspgather:latest
```

Or with compose:

```bash
curl -O https://raw.githubusercontent.com/kcorr/MSPGather/main/docker-compose.yml
docker compose up -d
```

### First sign-in

1. Get the one-time setup token from the logs: `docker logs mspgather`
2. Open <http://localhost:8080>, paste the token, and create the first administrator.
3. Scan the QR code with an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password…) and save the recovery codes.
4. Add your team under **Administration → Users**. Each person gets a temporary password and sets up their own MFA at first sign-in.

Prefer to skip the token? Set `MSPGATHER_ADMIN_USER` and `MSPGATHER_ADMIN_PASSWORD` on first start. That admin must change the password and enrol MFA at first sign-in.

Press **Ctrl+K** anywhere and type a tool name, a symptom ("lockout", "bounce") or paste a domain, IP, URL or error code (AADSTS50126, 0x80070005) to jump straight to the answer.

## Deploying for a team

The container serves plain HTTP on port 8080. To expose it beyond your machine:

- **Put HTTPS in front** (Caddy, Traefik, nginx, Cloudflare Tunnel). Cookies are marked `Secure` automatically when requests arrive over HTTPS.
- Set `FORWARDED_ALLOW_IPS` to your proxy's IP or subnet so the app sees real client IPs (rate limiting and the audit log depend on it).
- A VPN or identity-aware proxy in front is better still. Sign-in with mandatory MFA is the floor, not the ceiling.
- If it is reachable from the internet, set `MSPGATHER_ALLOW_PRIVATE_TARGETS=false` so the network tools can only reach public addresses, and `MSPGATHER_ALLOWED_HOSTS` to its public name.
- Back up the `mspgather-data` volume (users, MFA secrets, audit log, saved reports and branding).

Minimal Caddy example:

```
mspgather.example.com {
    reverse_proxy mspgather:8080
}
```

## Responsible use

MSPGather is built so the work you do on **prospects** stays on public information, and anything that **probes** a system needs an explicit, logged authorization confirmation. Every tool page shows what it touches:

| Label | What it means | Tools |
|---|---|---|
| Local analysis | Works on what you paste or type. Nothing is sent to the target. | Triage, decoders, analyzers, converters, calculators |
| Public lookups | Public information only: DNS, domain registries (RDAP), certificate transparency logs, Microsoft's public tenant discovery and an ordinary visit to the public website. Nothing is scanned. | Prospect Discovery, Hardening Plan, builders, Lookalike Domains, Bulk Domain Audit, DNS/IP/registration lookups, Blacklist Check |
| Contacts target | Ordinary client requests to the target, like a browser or Outlook would make. No probing. | HTTP Inspector, Autodiscover, certificate fetch, URL Analyzer (when following a link) |
| **Active test** | Probes the target: open ports, TLS protocol support, a live SMTP session. | SSL/TLS Checker, Port Check, SMTP Test |

- **Active tests require authorization.** They only run after the engineer ticks "I own, or am authorized to test, the systems I enter here". The server refuses active-test requests without that confirmation (HTTP 428), and each run is recorded in the audit log with it. Use them on your own and your clients' systems, never on prospects.
- **Links can't trigger lookups.** A tool opened from an external link shows its input and waits for the engineer to press Run.
- **Data sources have terms.** MSPGather stays within them by default, but some matter for commercial use:
  - **Spamhaus** public mirrors are free only for low-volume, non-commercial use and refuse public resolvers (Google, Cloudflare, Quad9). For client work, get a Data Query Service key and set `SPAMHAUS_DQS_KEY`.
  - **SURBL** requires a usage agreement for products and services built on its data; **URIBL** is for low-volume use; **Barracuda** asks you to register the DNS servers that query it. Blacklist Check asks every list about its own test entry first, so a list that refuses your resolver shows as "couldn't check", never as "clean".
  - **Registration data (RDAP)** is fetched straight from each registry through IANA's bootstrap, a few requests at a time, backing off when asked. Registry terms forbid high-volume automated querying, and ARIN's don't allow its IP data to be used for marketing: MSPGather uses it to describe infrastructure, and Prospect Discovery identifies network owners through Team Cymru's free IP-to-ASN service instead.
  - **crt.sh** is limited to 4 requests a minute from MSPGather (it asks for no more than 5); **CertSpotter** is used as a fallback and gives more with `CERTSPOTTER_API_KEY`.
- **Prospect data is business data.** Saved reports contain information from public sources about other organisations. Email addresses that look like a named person are replaced with "[name removed]" when a report is saved; reports are shared with your team, can be deleted at any time and expire after `MSPGATHER_ASSESSMENT_RETENTION_DAYS` (365 by default). Under GDPR and similar laws, handle them like any other prospect record (legitimate interest, limited retention, honour objections).

This is general information, not legal advice. Computer-misuse laws (for example the US Computer Fraud and Abuse Act, the UK Computer Misuse Act and EU member-state laws) and internet providers' acceptable-use policies differ; when in doubt, get written permission before running an active test.

## Workspaces and tools

### Discover
| Tool | Touches | What it answers |
|---|---|---|
| **Prospect Discovery** | Public lookups | Profile a prospect from their domain before the first call: where email is hosted and what filters it (Mimecast, Proofpoint, Barracuda…), the Microsoft 365 tenant and sign-in model (cloud, AD FS, Okta), an email & domain security grade, the SaaS stack and IT-provider signals (RMM tools), internet-facing host names (VPN, RD Gateway, OWA…) and the website's host and CMS. The report is a meeting briefing: **risks to raise, opportunities to propose, questions to ask, proposal starters**, a plain-text briefing for CRM notes and a one-page **client snapshot** to print or save as PDF. |
| **Saved Reports** | Local | Save a prospect briefing or hardening plan for the team, reopen it before the meeting, and see **what changed since the last save** (grade, resolved and new risks). |
| **Bulk Domain Audit** | Public lookups | Paste a client list (domains, emails or URLs from any CSV export) and get one row per domain: mail host, filter, SPF/DMARC/DKIM state and grade, sortable, with CSV export. Good for quarterly reviews and acquisitions. |
| **Lookalike Domains** | Public lookups | Registered typosquats of a client's domain, prioritising ones with **mail servers** (BEC risk) and recent registration; recognises the client's own defensive registrations. |
| **Tenant & Federation** | Public lookups | Tenant ID, cloud, managed vs federated, which IdP; for AD FS: **token-signing certificate expiry** and HTTPS health. |

### Harden
| Tool | Touches | What it answers |
|---|---|---|
| **Hardening Plan** | Public lookups | A prioritised checklist of a client's public-facing controls (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC, CAA, registrar lock and expiry, HTTPS/HSTS, security.txt, dangling and stale DNS records, exposed remote access), each with the exact record or command to fix it, plus read-only PowerShell checks for Microsoft 365 tenant settings. Re-run it after the changes and compare with the saved plan. |
| **SPF Builder** | Public lookups | Load the published SPF, add/remove senders from a catalog of common services (or any include/IP), and get a corrected record **validated against live DNS before publishing**: lookup count, per-sender lookup cost, broken includes, weakening `-all`, what changed, exact DNS instructions (incl. BIND split format). IP Lookup links here with the missing include pre-added. |
| **DMARC Builder** | Public lookups | One-click rollout stages (monitor → quarantine 25% → 100% → reject), SPF/DKIM readiness check, external report-address authorisation check, downgrade warnings, and the exact `_dmarc` record to publish. |
| **MTA-STS & TLS-RPT Builder** | Public lookups | Generates the MTA-STS policy file, the `_mta-sts` and `_smtp._tls` records and hosting instructions from the domain's real MX hosts, checks an existing policy covers every MX, and walks the testing → enforce rollout. |
| **Parked Domain Lockdown** | Public lookups | For domains that send and receive no mail: checks and generates null MX, `v=spf1 -all`, DMARC `p=reject` and a DKIM revocation record, for one domain or a list of up to 20. |
| **DMARC Report Analyzer** | Public lookups | Drop in aggregate (RUA) reports (XML, .gz or .zip) or TLS-RPT JSON: who sends as the domain, which senders fail SPF/DKIM alignment and why, and whether it is safe to move to quarantine or reject. Parsed in memory, never stored. |
| **SSL/TLS Checker** | **Active test** | HTTPS, STARTTLS (SMTP/IMAP/POP3), LDAPS, **RDP**: chain, **missing intermediate**, expiry, name, trust, TLS 1.0–1.3 support. |
| **Port Check** | **Active test** | Open/closed/filtered from the MSPGather server's network; exposed RDP/SMB/WinRM flagged critical. |

### Troubleshoot
| Tool | Touches | What it answers |
|---|---|---|
| **Triage** | Local | Paste anything (headers, a bounce, an AADSTS error, `dsregcmd /status`, an event log, a certificate, a token, a link) and it opens the right tool with it, or start from a symptom. |
| **Header Analyzer** | Public lookups | Where did this message go and what went wrong? Hop-by-hop route with delays and TLS, SPF/DKIM/DMARC/compauth/ARC, Microsoft 365 spam stamps, identity alignment. **Mail loop diagnosis** (repeated hand-offs, inbox-rule loops, auto-reply wars) and **SPF judged against a gateway instead of the real sender** (missing Enhanced Filtering), with a live SPF re-check of the true origin IP. |
| **NDR Decoder** | Public lookups | Why did it bounce? Enhanced status codes and Exchange component strings → cause and fix; analyzes original headers embedded in the bounce. |
| **Domain Health** | Public lookups | MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, Autodiscover, Entra tenant, and cross-checks between them. Recognises correctly parked domains. |
| **SPF Inspector** | Public lookups | Full include tree, 10-lookup / void-lookup limits, and "does this IP pass?" with the matching term. |
| **Blacklist Check** | Public lookups | 18 DNS blocklists; policy listings and resolver refusals shown separately from real listings. |
| **SMTP Test** | **Active test** | Banner, EHLO, STARTTLS, certificate, firewall SMTP-inspection detection, optional RCPT probe (never sends a message). |
| **Sign-in Error Decoder** | Local | Paste an AADSTS code, error text, portal text or sign-in JSON: which Conditional Access policy blocked it, password spray / stale-credential detection, legacy auth, and the fix (68-code knowledge base). |
| **Token Decoder** | Local | JWT and SAML decoded **in the browser** (nothing sent to the server): who, which app, audience, scopes/roles, expiry, group overage, SAML status/audience/signing cert. |
| **Device Join Analyzer** | Local | Paste `dsregcmd /status` output: Entra joined / hybrid / registered state, PRT status, and the failing step (discovery, SCP, DRS, TPM) with the fix. |
| **Identity Converters** | Local | ObjectGUID ⇄ ImmutableID (sourceAnchor), SID formats, and IMCEAEX bounce addresses back to the X500 address to add as a proxy. Runs in the browser. |
| **Autodiscover Walkthrough** | Contacts target | Every step Outlook tries, in order, and which one causes certificate prompts or slow profile setup, with the registry fix. |
| **Endpoint Connectivity** | Local | A read-only PowerShell collector run on the affected PC; paste the output back to detect **TLS inspection** (names the firewall product), blocked endpoints, proxy mismatches and DNS overrides. |
| **DNS Lookup** | Public lookups | One record across system/public/DoH resolvers and every authoritative server: propagation and stale caches. |
| **IP Lookup** | Public lookups | Who owns an IP (RDAP, ASN, abuse contact, PTR); recognises email services and suggests the SPF include. |
| **HTTP Inspector** | Contacts target | Redirect chain hop by hop, status, timing, CDN/WAF, security headers. |
| **Domain Registration** | Public lookups | Expiry, registrar, dangerous EPP statuses (hold, redemption), name server drift, **broken DNSSEC**. |
| **Certificate & CSR Decoder** | Contacts target | Paste a PEM/DER certificate, chain or CSR (or fetch one from a host): subject, SANs, key, chain order, expiry, and whether a CSR matches the certificate issued for it. |
| **Subnet Calculator** | Local | Ranges, masks, Azure usable counts, and **VPN / VNet overlap detection**. Runs in the browser. |
| **Error Code Lookup** | Local | HRESULT / Win32 / NTSTATUS / Windows Update / Intune & Autopilot / Entra join / Kerberos / bug checks, in any input form, with structural decoding for unknown codes. |
| **Event Log Analyzer** | Local | Paste events (text, Format-List, JSON, CSV, XML): **account lockout source**, password spray, crash and bug check correlation with WHEA hardware errors, suspicious service installs, log clearing. Copy-paste collectors included. |
| **URL Analyzer** | Contacts target | Unwraps Safe Links / Proofpoint / Barracuda / Google links, flags phishing traits (homoglyphs, brand impersonation, new domains, encoded recipient addresses), optional safe redirect following, and Tenant Allow/Block List commands. |

### Administration
| Tool | Touches | What it answers |
|---|---|---|
| **My Account** | Local | Change password, set up or reset MFA, new recovery codes, see and sign out other sessions. |
| **Users** | Local | *(admins)* Add engineers (with a one-time temporary password), set roles, reset MFA, disable accounts. |
| **Audit Log** | Local | *(admins)* Sign-ins, failures, lockouts, account changes, and which tool was run against which target. |
| **Report Branding** | Local | *(admins)* Your organisation's name, website and contact, shown on client snapshots. |
| **About & Responsible Use** | Local | What each tool touches, the public sources MSPGather uses, what it stores, and how active tests are kept to authorized targets. |


## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MSPGATHER_AUTH` | `on` | Set `off` only for a single-user instance bound to localhost. |
| `MSPGATHER_REQUIRE_MFA` | `true` | Everyone must enrol TOTP MFA. |
| `MSPGATHER_ADMIN_USER` / `MSPGATHER_ADMIN_PASSWORD` | unset | Create the first admin at startup instead of using the setup token. Ignored once any user exists. |
| `MSPGATHER_SESSION_IDLE_MINUTES` | `240` | Sign out after this much inactivity. |
| `MSPGATHER_SESSION_MAX_HOURS` | `12` | Sign out after this long regardless. |
| `MSPGATHER_COOKIE_SECURE` | `auto` | `auto` (Secure over HTTPS), `true`, or `false`. |
| `MSPGATHER_AUDIT_TOOL_USAGE` | `true` | Log which tool was run against which target (never pasted content). |
| `MSPGATHER_AUDIT_RETENTION_DAYS` | `90` | Audit log retention. |
| `MSPGATHER_IP_MAX_FAILS` | `20` | Failed sign-in attempts (password or MFA) allowed per client network per 15 minutes. Raise it if a large office shares one public IP. |
| `MSPGATHER_ALLOW_PRIVATE_TARGETS` | `true` | `false` refuses RFC 1918 / CGNAT targets in every network tool. Loopback, link-local and cloud metadata are always refused. |
| `MSPGATHER_DENY_NETS` | unset | Extra CIDRs the network tools must never reach (e.g. `10.0.0.0/24,192.168.1.0/24`). The container host gateway is always refused. |
| `MSPGATHER_ALLOWED_HOSTS` | unset | Comma-separated host names the app answers to (rejects other `Host` headers; guards against DNS rebinding). |
| `MSPGATHER_ASSESSMENT_RETENTION_DAYS` | `365` | How long saved prospect briefings and hardening plans are kept. |
| `MSPGATHER_ORG_NAME` / `MSPGATHER_ORG_WEBSITE` / `MSPGATHER_ORG_CONTACT` | unset | Defaults for report branding on client snapshots (admins can change them under Report Branding). |
| `MSPGATHER_MAX_CONCURRENT_SCANS` | `6` | Concurrent heavy scans (discovery, port scans, bulk audits). |
| `MSPGATHER_API_DOCS` | `false` | Serve OpenAPI docs at `/api/docs` (signed-in users only). |
| `MSPGATHER_TOTP_ISSUER` | `MSPGather` | Name shown in authenticator apps. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies trusted for `X-Forwarded-For` / `X-Forwarded-Proto`. |
| `SPAMHAUS_DQS_KEY` | unset | Spamhaus Data Query Service key. Blacklist Check then queries ZEN and DBL through DQS, which works through any resolver and is the licensed route for commercial use. The key is never shown in results. |
| `CERTSPOTTER_API_KEY` | unset | SSLMate CertSpotter key for the optional certificate-log search in Prospect Discovery (more queries than anonymous use). |
| `DEFAULT_RESOLVER` | `system` | `system`, `cloudflare`, `google`, `quad9`, `doh-cloudflare`, `doh-google` |
| `DOH_FALLBACK` | `true` | Retry over DNS-over-HTTPS when classic DNS fails or drops large answers (common behind Docker Desktop and some firewalls). DNSBL checks never fall back. |
| `SMTP_HELO` | `mspgather.diagnostics.local` | HELO name for SMTP tests. |
| `LOG_LEVEL` | `INFO` | Python log level. |

## Privacy: what leaves the server

MSPGather has no telemetry and needs no external accounts. Pasted content (headers, NDRs, event logs, reports, tokens) is analysed in memory and never stored or logged. It stores only user accounts and sessions, the audit log, saved reports (when someone presses Save) and report branding, all in the `/data` volume. Some tools look things up on the internet by design:

| Data | Sent to | Used by |
|---|---|---|
| Domain and host names | Your DNS resolver; Cloudflare DNS-over-HTTPS when classic DNS fails | Most tools |
| Domain names | Public RDAP registries | Domain Registration, Prospect Discovery, Hardening Plan, Lookalike Domains, Bulk Domain Audit |
| IP addresses | RDAP registries (ARIN, RIPE…), Team Cymru DNS (ASN) | IP Lookup, Header Analyzer |
| Domain names | Microsoft's public tenant discovery endpoints | Tenant & Federation, Domain Health, Prospect Discovery, Hardening Plan |
| Domain names (optional) | crt.sh / CertSpotter certificate transparency search | Prospect Discovery, when ticked |
| Hosts and URLs you enter | The host itself (TCP, TLS, SMTP, HTTP) | SMTP Test, SSL/TLS Checker, Port Check (active, authorized only), HTTP Inspector, URL Analyzer, certificate fetch, Prospect Discovery (an ordinary website visit) |
| IPs and domains | DNS blocklist operators | Blacklist Check |

Token Decoder, Subnet Calculator and Identity Converters run entirely in the browser.

### Things to know
- Network tests run **from the MSPGather server**. Many ISPs and clouds block outbound port 25.
- Spamhaus, URIBL and SURBL refuse queries from public resolvers. Blacklist Check detects this with each list's test entry and reports those lists as "couldn't check"; run MSPGather with its own recursive resolver (or set `SPAMHAUS_DQS_KEY`) for complete results.
- Knowledge bases (AADSTS, error codes, event IDs, NDR codes) only include entries believed accurate; unknown codes say so instead of guessing.

## Development

```bash
git clone https://github.com/kcorr/MSPGather.git
cd MSPGather
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the readability contract, file layout and testing. New tools are picked up automatically. Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Microsoft 365, Entra, Exchange, Mimecast, Proofpoint and other product names are trademarks of their owners. MSPGather is not affiliated with or endorsed by any of them.
