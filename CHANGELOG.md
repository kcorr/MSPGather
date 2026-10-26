# Changelog

## 1.1.0 (2026-10-26)

MSPGather is now organised around how it's used: **Discover** a prospect, **Harden** a client, **Troubleshoot** an issue.

- New app shell: workspace tabs, a contextual sidebar, a command palette (Ctrl+K) that understands domains, IPs, URLs and error codes, light and dark themes, and a mobile layout.
- Prospect Discovery report rebuilt as a meeting briefing: grade, stack at a glance, talking points, proposal starters, scorecard and evidence, with a one-page **client snapshot** to print or save as PDF.
- **Saved reports**: save a prospect briefing or hardening plan for the team, reopen it later, and see what changed since the last save.
- **Hardening Plan**: a prioritised checklist of a client's public-facing controls with the exact record or command for each fix, plus read-only Microsoft 365 checks.
- New builders: **MTA-STS & TLS-RPT** and **Parked Domain Lockdown**.
- **Triage**: paste headers, a bounce, an error, a log, a certificate or a token and MSPGather opens the right tool with it.
- **Responsible use**: every tool shows what it touches (local analysis, public lookups, contacts target, active test). Active tests (SSL/TLS Checker, Port Check, SMTP Test) only run after the engineer confirms they're authorized to test the target; the server enforces this and records it in the audit log. New About & Responsible Use page and report branding settings.

## 1.0.0 (2026-10-24)

First public release.

- 30 troubleshooting tools across Discovery, Email, Identity, Microsoft 365, DNS & Network, Windows and Security.
- Fix-it builders for SPF (with multiple-record merge) and DMARC (staged rollout).
- Domain Discovery for prospects, plus Bulk Domain Audit.
- DMARC aggregate / TLS-RPT report analyzer, certificate and CSR decoder, device join (dsregcmd) analyzer, identity converters.
- Built-in authentication: scrypt passwords, TOTP MFA with recovery codes, admin and user roles, session management, lockout and rate limiting, audit log.
- Hardened container: non-root, read-only root filesystem support, multi-arch images on GHCR.
