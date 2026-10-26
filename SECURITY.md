# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
(Security tab → "Report a vulnerability") on this repository. Include steps to
reproduce and the version (`/api/health` shows it). You should get a reply within a week.

## Supported versions

Only the latest release receives fixes.

## Security model

MSPGather is designed to be safe to expose to a team network, and survivable on the internet behind HTTPS:

- **Sign-in required** for every page and API call (except `/api/health` and the login page).
  Passwords are hashed with scrypt; TOTP MFA is required by default, with single-use recovery codes.
- **Sessions** are random tokens stored only as hashes, in an `HttpOnly`, `SameSite=Strict` cookie
  (`Secure` over HTTPS), with idle and absolute timeouts. Signing out or changing a password revokes them.
- **Brute force**: failures are throttled per account and network, per network, and per account overall (password and MFA codes alike); one pending sign-in per account; lockouts don't reveal whether a username exists.
- **CSRF**: every state-changing request needs a per-session token and a same-origin `Origin`.
- **Headers**: strict Content-Security-Policy (no inline script), `frame-ancestors 'none'`, `nosniff`,
  `no-referrer`, HSTS over HTTPS, `no-store` on API responses.
- **Outbound safety**: network tools refuse loopback, link-local, cloud-metadata (169.254.169.254),
  multicast, reserved and container-host-gateway targets, and connect to the IP that was checked (no DNS rebinding).
  URL fetchers also refuse private addresses on every redirect hop. Set
  `MSPGATHER_ALLOW_PRIVATE_TARGETS=false` to refuse RFC 1918 targets everywhere.
- **Links can't trigger scans**: a tool opened from an external link shows its input and waits for the engineer to press Run.
- **Active tests need authorization**: SSL/TLS Checker, Port Check and SMTP Test are refused by the server (HTTP 428) unless the request carries the confirmation the engineer gives on the tool page; each run is recorded in the audit log with it. The confirmation is a custom header, so a cross-site page or link can't supply it.
- **Saved reports**: only server-generated results can be saved (by a short-lived result id), they're shared with signed-in users, deletable by their author or an admin, and expire after `MSPGATHER_ASSESSMENT_RETENTION_DAYS`.
- **Copy-paste commands** only include values that pass strict validation (emails, host names, IPs, URLs), single-quoted for PowerShell.
- **Audit log** of sign-ins, account changes and tool usage (targets only, never pasted content).
- **Container**: non-root user, read-only application code, data only in `/data`; the provided
  compose file runs with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Deployment advice

- Put it behind HTTPS (Caddy, Traefik, nginx, Cloudflare Tunnel). Set `FORWARDED_ALLOW_IPS` to your
  proxy's address so sign-in rate limits see real client IPs.
- Prefer a VPN or an identity-aware proxy over a bare internet exposure.
- Back up the `/data` volume; it holds user accounts and the audit log.
