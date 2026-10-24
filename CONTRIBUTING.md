# Contributing to MSPGather

Thanks for helping. MSPGather is for engineers working escalated issues, so every tool has one job: make the problem obvious at a glance.

## Development setup

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

This mounts `./app` into the container with auto-reload. For local development without sign-in, set `MSPGATHER_AUTH=false` in a compose override (never on an exposed instance).

Run the tests:

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

## The readability contract

Every result renders top-down in this order:

1. **Verdict banner**: `verdict(sev, title, sub)`. The title is one plain-language sentence that answers the question the engineer came with.
   - Good: "Account is locked out by a stale password on SERVER01 (event 4740)", "Certificate is missing an intermediate. Android and Java clients will fail."
   - Bad: "Analysis complete", "3 findings".
   - Severity: `critical` = broken or will break, `warning` = risky or degraded, `info` = notable, `ok` = healthy.
2. **Key facts** (optional): `facts([[label, value], ...])`, 3 to 6 chips.
3. **Findings**: `card("Findings", findingsList(findings), {flush: true})`. Each finding is `{severity, title, detail}`: the title says what is wrong, the detail says why it matters and how to fix it.
4. **What to do**: `nextSteps([{title, detail, commands: [...]}])` when there is a fix. Commands must be real and copy-pasteable.
5. **Details**: tables and raw data last.

Rules:
- Lead with the answer, not the data.
- Plain English. Expand jargon the first time it appears.
- Never invent facts. Knowledge bases (error codes, event IDs) only contain entries known to be correct; unknown input gets an honest "not in the knowledge base" plus whatever can be decoded structurally.
- Highlight problem rows in tables with the row class `hl`.

## Where things live

| What | Where |
|---|---|
| Backend logic and routes | `app/modules/<name>.py`. Define `router = APIRouter()`; it is mounted automatically. Routes start with `/api/<tool-id>`. |
| Frontend | `app/static/tools/<section>.js`. Loaded automatically, in alphabetical order. |
| Samples (optional) | `app/static/samples/<tool-id>-*.txt`. **Fictional data only** (contoso.com, fabrikam.com, 192.0.2.x, 198.51.100.x, 203.0.113.x). Never real people, companies or client data. |
| Shared plumbing | `app/main.py` (access gate, security headers), `app/core/` (auth, DNS, outbound safety), `app/static/core.js` (UI helpers, router, menu). |


## Backend conventions

```python
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from ..core.http import run          # ValueError -> HTTP 400 with the message

router = APIRouter()

@router.get("/api/mytool/{target}")
def mytool(target: str):
    return run(analyze, target)       # analyze() returns a plain dict
```

- Available packages: standard library, fastapi, pydantic, httpx, dnspython, cryptography. Please discuss new dependencies in an issue first.
- Reusable helpers (import, don't copy):
  - `app/core/dns_utils.py`: `make_resolver(name)`, `resolve(res, name, rtype)`, `txt()`, `addresses()`, `ptr()`, `fcrdns()`, `normalize_domain()`, `is_ip()`, `is_private_ip()`, `registered_domain()`. `resolve()` never raises; it returns `(rdata_list, meta)` with `meta["status"]` in ok/nxdomain/noanswer/servfail/timeout/error and falls back to DNS-over-HTTPS automatically.
  - `app/core/providers.py`: `provider_for(host)` recognises Microsoft 365, Google, gateways, etc.
  - `app/modules/ipinfo.py`: `rdap_lookup(ip)`, `asn_lookup(res, ip)`, `ip_lookup(target, domain)`.
  - `app/modules/domain.py`: `check_m365_tenant(domain)` returns tenant ID, namespace type, federation.
  - `app/modules/spf.py`: `analyze_spf(domain, resolver_name, ip)`.
  - `app/modules/smtp_test.py`: `_cert_info(der_bytes, host)` parses an X.509 cert.
- Network calls: always set timeouts (≤ 10s per call) and run independent lookups in a `ThreadPoolExecutor`. Whole requests should finish in < 20s.
- **Outbound safety** (use `app/core/outbound.py` `resolve_safe()`) for anything that connects to a user-supplied host or URL: resolve it first and refuse loopback, link-local (incl. 169.254.169.254 cloud metadata), multicast, unspecified and reserved addresses. URL fetchers must also refuse RFC 1918/CGNAT (private) targets. Cap response bodies (≤ 512 KB), cap redirects (≤ 10), send no cookies or credentials, never execute content.
- Input validation: raise `ValueError("human readable message")` for bad input.
- Return JSON-serialisable dicts (convert datetimes to ISO strings).

## Frontend conventions

```js
"use strict";
function renderMyTool(main, params) {
  const out = el("div");
  main.append(card(null, hashForm("mytool", [
    { name: "t", label: "Host", placeholder: "contoso.com", grow: true, required: true },
  ], params, "Check")), out);
  if (params.get("t")) runInto(out, "Checking…", () => api(`/api/mytool/${encodeURIComponent(params.get("t"))}`), renderMyResult);
}
function renderMyResult(d) {
  const frag = el("div");
  frag.append(verdict(d.severity, d.headline, d.subline));
  frag.append(card("Findings", findingsList(d.findings), { flush: true }));
  // nextSteps(...), details...
  return frag;
}
registerTool({ category: "network", group: "Certificates", id: "mytool", title: "My Tool", render: renderMyTool,
  icon: "M4 4h16v16H4z" /* 24x24 SVG path, stroke style */, keywords: "search words people would type",
  desc: "One sentence: what you give it and what it tells you." });
```

- Build all DOM with `el(tag, attrs, ...children)`. **Never use `innerHTML`** (inputs are untrusted).
- Prefix any function or `const` you define at top level with your tool id (e.g. `tlsRenderChain`), because all tool files share one global scope. `render<ToolId>Tool` / `render<ToolId>Result` are fine.
- Core helpers: `el, card, kv, table(cols, rows, rowClassFn), code(text), badge(sev, text), findingsList, verdict, facts, nextSteps, stat, link(toolId, params, text), api(path, {body}), runInto(target, label, fn, renderFn), hashForm, pasteBox({placeholder, onRun, sample}), worstSeverity, fmtDuration, fmtTime, addStyles(css), resultSev`.
- Existing CSS classes: `card, stats/stat, kv, table.t (+ tr.hl), badge sev-*, verdict, notice, hint, sub, mono, code, grid-2, tree, transcript, btn, btn secondary, tool-form, field, check`. For anything else, `addStyles()` with selectors prefixed by your tool id.
- Pasted-text tools: use `pasteBox()` and run the analysis client-side or via POST.
- Link to other tools where it helps (e.g. an IP → `link("ip", {t: ip}, ip)`, a domain → `link("domain", {d})`).

Existing tool ids (for links): `discover, bulkaudit` (Discovery), `headers, ndr, domain, spf, smtp, blacklist, spfbuild, dmarcbuild, dmarcreport` (Email), `aadsts, token, tenant, dsreg, idconvert` (Identity), `autodiscover, m365net` (Microsoft 365), `dns, ip, tls, certdecode, ports, http, whois, subnet` (DNS & Network), `errcode, eventlog` (Windows), `url, lookalike` (Security).

## Before opening a pull request

- `pytest` passes and `node --check app/static/tools/<file>.js` is clean.
- `/api/health` shows no `module_errors`.
- You tested real-world input, edge cases (empty, garbage, unreachable host, IPv6), and that the verdict reads correctly for both healthy and broken cases.
- No real client data in code, samples, tests or screenshots.

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
