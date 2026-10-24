# MSPGather

A self-hosted troubleshooting and discovery toolkit for **level 3 / escalation engineers** at MSPs. 30 tools across discovery, email, identity, Microsoft 365, DNS & network, Windows and security. None of them need access to a client tenant.

Every result reads top-down: a **one-sentence verdict** naming the problem, then findings ordered by severity, then **what to do** (with copy-paste PowerShell), then the raw details.

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

Use the home page search ("lockout", "AADSTS50126", "certificate", "0x80070005", a domain or an IP) to jump to the right tool.

## Deploying for a team

The container serves plain HTTP on port 8080. To expose it beyond your machine:

- **Put HTTPS in front** (Caddy, Traefik, nginx, Cloudflare Tunnel). Cookies are marked `Secure` automatically when requests arrive over HTTPS.
- Set `FORWARDED_ALLOW_IPS` to your proxy's IP or subnet so the app sees real client IPs (rate limiting and the audit log depend on it).
- A VPN or identity-aware proxy in front is better still. Sign-in with mandatory MFA is the floor, not the ceiling.
- If it is reachable from the internet, set `MSPGATHER_ALLOW_PRIVATE_TARGETS=false` so the network tools can only reach public addresses, and `MSPGATHER_ALLOWED_HOSTS` to its public name.
- Back up the `mspgather-data` volume (users, MFA secrets, audit log).

Minimal Caddy example:

```
mspgather.example.com {
    reverse_proxy mspgather:8080
}
```

## Tools

### Discovery
| Tool | What it answers |
|---|---|
| **Domain Discovery** | Profile a prospect or new client from their domain name before the first call. Shows where email is hosted and what filters it (Mimecast, Proofpoint, Barracuda, Mailprotector…), the Microsoft 365 tenant and sign-in model (cloud, AD FS, Okta), DMARC/SPF/DKIM and who manages DMARC reports, an email security grade, the SaaS stack (from DNS verification records, SPF, DKIM, CNAMEs and the website), public host names (VPN, RD Gateway, OWA, AD FS…) classified as SaaS / cloud / office connection, the website's host and CMS, and registrar/DNS host/expiry. Finishes with **talking points**: risks to raise, opportunities to propose and questions to ask, plus a one-click plain-text briefing for CRM notes. Public information only: DNS, one normal website visit, public registration data, Microsoft's public tenant lookup, and optionally certificate transparency logs. |
| **Bulk Domain Audit** | Paste a client list (domains, emails or URLs from any CSV export) and get one row per domain: mail host, filter, SPF/DMARC/DKIM state and grade, sortable, with CSV export. Good for quarterly reviews and acquisitions. |

### Email
| Tool | What it answers |
|---|---|
| **Header Analyzer** | Where did this message go and what went wrong? Hop-by-hop route with delays and TLS, SPF/DKIM/DMARC/compauth/ARC, Microsoft 365 spam stamps, identity alignment. **Mail loop diagnosis** (repeated hand-offs, inbox-rule loops, auto-reply wars) and **SPF judged against a gateway instead of the real sender** (missing Enhanced Filtering), with a live SPF re-check of the true origin IP. |
| **NDR Decoder** | Why did it bounce? Enhanced status codes and Exchange component strings → cause and fix; analyzes original headers embedded in the bounce. |
| **Domain Health** | MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, Autodiscover, Entra tenant, and cross-checks between them. Recognises correctly parked domains. |
| **SPF Inspector** | Full include tree, 10-lookup / void-lookup limits, and "does this IP pass?" with the matching term. |
| **SMTP Test** | Banner, EHLO, STARTTLS, certificate, firewall SMTP-inspection detection, optional RCPT probe (never sends a message). |
| **Blacklist Check** | 18 DNS blocklists; policy listings and resolver refusals shown separately from real listings. |
| **SPF Builder** *(fix-it)* | Load the published SPF, add/remove senders from a catalog of common services (or any include/IP), and get a corrected record **validated against live DNS before publishing**: lookup count, per-sender lookup cost, broken includes, weakening `-all`, what changed, exact DNS instructions (incl. BIND split format). IP Lookup links here with the missing include pre-added. |
| **DMARC Builder** *(fix-it)* | One-click rollout stages (monitor → quarantine 25% → 100% → reject), SPF/DKIM readiness check, external report-address authorisation check, downgrade warnings, and the exact `_dmarc` record to publish. |
| **DMARC Report Analyzer** | Drop in aggregate (RUA) reports (XML, .gz or .zip) or TLS-RPT JSON: who sends as the domain, which senders fail SPF/DKIM alignment and why, and whether it is safe to move to quarantine or reject. Parsed in memory, never stored. |

### Identity
| Tool | What it answers |
|---|---|
| **Sign-in Error Decoder** | Paste an AADSTS code, error text, portal text or sign-in JSON: which Conditional Access policy blocked it, password spray / stale-credential detection, legacy auth, and the fix (68-code knowledge base). |
| **Token Decoder** | JWT and SAML decoded **in the browser** (nothing sent to the server): who, which app, audience, scopes/roles, expiry, group overage, SAML status/audience/signing cert. |
| **Tenant & Federation** | Tenant ID, cloud, managed vs federated, which IdP; for AD FS: **token-signing certificate expiry** and HTTPS health. |
| **Device Join Analyzer** | Paste `dsregcmd /status` output: Entra joined / hybrid / registered state, PRT status, and the failing step (discovery, SCP, DRS, TPM) with the fix. |
| **Identity Converters** | ObjectGUID ⇄ ImmutableID (sourceAnchor), SID formats, and IMCEAEX bounce addresses back to the X500 address to add as a proxy. Runs in the browser. |

### Microsoft 365
| Tool | What it answers |
|---|---|
| **Autodiscover Walkthrough** | Every step Outlook tries, in order, and which one causes certificate prompts or slow profile setup, with the registry fix. |
| **Endpoint Connectivity** | A read-only PowerShell collector run on the affected PC; paste the output back to detect **TLS inspection** (names the firewall product), blocked endpoints, proxy mismatches and DNS overrides. |

### DNS & Network
| Tool | What it answers |
|---|---|
| **DNS Lookup** | One record across system/public/DoH resolvers and every authoritative server: propagation and stale caches. |
| **IP Lookup** | Who owns an IP (RDAP, ASN, abuse contact, PTR); recognises email services and suggests the SPF include. |
| **SSL/TLS Checker** | HTTPS, STARTTLS (SMTP/IMAP/POP3), LDAPS, **RDP**: chain, **missing intermediate**, expiry, name, trust, TLS 1.0–1.3 support. |
| **Certificate & CSR Decoder** | Paste a PEM/DER certificate, chain or CSR (or fetch one from a host): subject, SANs, key, chain order, expiry, and whether a CSR matches the certificate issued for it. |
| **Port Check** | Open/closed/filtered from the MSPGather server's network; exposed RDP/SMB/WinRM flagged critical. |
| **HTTP Inspector** | Redirect chain hop by hop, status, timing, CDN/WAF, security headers. |
| **Domain Registration** | Expiry, registrar, dangerous EPP statuses (hold, redemption), name server drift, **broken DNSSEC**. |
| **Subnet Calculator** | Ranges, masks, Azure usable counts, and **VPN / VNet overlap detection**. Runs in the browser. |

### Windows
| Tool | What it answers |
|---|---|
| **Error Code Lookup** | HRESULT / Win32 / NTSTATUS / Windows Update / Intune & Autopilot / Entra join / Kerberos / bug checks, in any input form, with structural decoding for unknown codes. |
| **Event Log Analyzer** | Paste events (text, Format-List, JSON, CSV, XML): **account lockout source**, password spray, crash and bug check correlation with WHEA hardware errors, suspicious service installs, log clearing. Copy-paste collectors included. |

### Security
| Tool | What it answers |
|---|---|
| **URL Analyzer** | Unwraps Safe Links / Proofpoint / Barracuda / Google links, flags phishing traits (homoglyphs, brand impersonation, new domains, encoded recipient addresses), optional safe redirect following, and Tenant Allow/Block List commands. |
| **Lookalike Domains** | Registered typosquats of a client's domain, prioritising ones with **mail servers** (BEC risk) and recent registration; recognises the client's own defensive registrations. |

### Administration
| Tool | What it answers |
|---|---|
| **My Account** | Change password, set up or reset MFA, new recovery codes, see and sign out other sessions. |
| **Users** *(admins)* | Add engineers (with a one-time temporary password), set roles, reset MFA, disable accounts. |
| **Audit Log** *(admins)* | Sign-ins, failures, lockouts, account changes, and which tool was run against which target. |

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
| `MSPGATHER_MAX_CONCURRENT_SCANS` | `6` | Concurrent heavy scans (discovery, port scans, bulk audits). |
| `MSPGATHER_API_DOCS` | `false` | Serve OpenAPI docs at `/api/docs` (signed-in users only). |
| `MSPGATHER_TOTP_ISSUER` | `MSPGather` | Name shown in authenticator apps. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies trusted for `X-Forwarded-For` / `X-Forwarded-Proto`. |
| `DEFAULT_RESOLVER` | `system` | `system`, `cloudflare`, `google`, `quad9`, `doh-cloudflare`, `doh-google` |
| `DOH_FALLBACK` | `true` | Retry over DNS-over-HTTPS when classic DNS fails or drops large answers (common behind Docker Desktop and some firewalls). DNSBL checks never fall back. |
| `SMTP_HELO` | `mspgather.diagnostics.local` | HELO name for SMTP tests. |
| `LOG_LEVEL` | `INFO` | Python log level. |

## Privacy: what leaves the server

MSPGather has no telemetry and needs no external accounts. Pasted content (headers, NDRs, event logs, reports, tokens) is analysed in memory and never stored or logged. Some tools look things up on the internet by design:

| Data | Sent to | Used by |
|---|---|---|
| Domain and host names | Your DNS resolver; Cloudflare DNS-over-HTTPS when classic DNS fails | Most tools |
| Domain names | Public RDAP registries | Domain Registration, Discovery, Lookalike Domains |
| IP addresses | RDAP registries (ARIN, RIPE…), Team Cymru DNS (ASN) | IP Lookup, Header Analyzer |
| Domain names | Microsoft's public tenant discovery endpoints | Tenant & Federation, Domain Health, Discovery |
| Domain names (optional) | crt.sh certificate transparency search | Discovery, when ticked |
| Hosts and URLs you enter | The host itself (TCP, TLS, SMTP, HTTP) | SMTP Test, SSL/TLS, Port Check, HTTP Inspector, URL Analyzer, Discovery (one website visit) |
| IPs and domains | DNS blocklist operators | Blacklist Check |

Token Decoder, Subnet Calculator and Identity Converters run entirely in the browser.

### Things to know
- Network tests run **from the MSPGather server**. Many ISPs and clouds block outbound port 25.
- Spamhaus / URIBL / SURBL refuse queries from public resolvers; run on a network with its own recursive resolver for complete blocklist results.
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
