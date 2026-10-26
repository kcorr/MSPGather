"""MSPGather: discovery, hardening and troubleshooting toolkit for MSP engineers."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import importlib
import logging
import os
import pkgutil
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import __version__, modules
from .auth_api import client_ip
from .auth_api import router as auth_router
from .core import auth, workspace
from .core.dns_utils import resolver_names
from .core.http import run as _run
from .modules.blacklist import check_target
from .modules.dnslookup import RECORD_TYPES, lookup
from .modules.domain import check_domain
from .modules.headers import analyze_headers
from .modules.ipinfo import ip_lookup
from .modules.ndr import analyze_ndr
from .modules.smtp_test import smtp_test
from .modules.spf import analyze_spf

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
STATIC = Path(__file__).parent / "static"
log = logging.getLogger("mspgather")
API_DOCS = os.environ.get("MSPGATHER_API_DOCS", "false").strip().lower() in ("1", "true", "yes", "on")
MAX_HEAVY = max(1, int(os.environ.get("MSPGATHER_MAX_CONCURRENT_SCANS", "6")))

auth.init()
workspace.init()
app = FastAPI(title="MSPGather", version=__version__, openapi_url="/api/openapi.json",
              docs_url="/api/docs" if API_DOCS else None, redoc_url=None)
app.include_router(auth_router)
# Optional Host allow-list (defends against DNS rebinding, mainly relevant with auth off).
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("MSPGATHER_ALLOWED_HOSTS", "").split(",") if h.strip()]
if ALLOWED_HOSTS:
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[*ALLOWED_HOSTS, "localhost", "127.0.0.1"])


@app.exception_handler(auth.AuthError)
async def _auth_error(_request: Request, exc: auth.AuthError):
    return JSONResponse({"detail": str(exc)}, status_code=exc.status)


# Any module in app/modules that defines `router = APIRouter()` is mounted
# automatically. A module that fails to import is logged and skipped, so one
# broken tool can't take the whole app down.
MODULE_ERRORS: dict[str, str] = {}
for info in pkgutil.iter_modules(modules.__path__):
    try:
        mod = importlib.import_module(f"{modules.__name__}.{info.name}")
    except Exception as exc:  # noqa: BLE001 - report and continue
        MODULE_ERRORS[info.name] = f"{type(exc).__name__}: {exc}"
        log.exception("Failed to load module %s", info.name)
        continue
    router = getattr(mod, "router", None)
    if router is not None:
        app.include_router(router)

log.info("MSPGather %s starting: auth=%s, require_mfa=%s, allow_private_targets=%s, max_concurrent_scans=%s",
         __version__, "on" if auth.AUTH_ENABLED else "OFF", auth.REQUIRE_MFA,
         os.environ.get("MSPGATHER_ALLOW_PRIVATE_TARGETS", "true"), MAX_HEAVY)


def _version(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def _page(name: str) -> HTMLResponse:
    """Serve an HTML page with every asset URL carrying a content hash, so a
    browser never mixes a new page with an old cached file."""
    tool_files = sorted((STATIC / "tools").glob("*.js"))
    scripts = "\n".join(f'  <script src="tools/{p.name}?v={_version(p)}"></script>' for p in tool_files)
    html = ((STATIC / name).read_text(encoding="utf-8")
            .replace('href="styles.css"', f'href="styles.css?v={_version(STATIC / "styles.css")}"')
            .replace('src="core.js"', f'src="core.js?v={_version(STATIC / "core.js")}"')
            .replace('src="login.js"', f'src="login.js?v={_version(STATIC / "login.js")}"')
            .replace("  <!--TOOL_SCRIPTS-->", scripts))
    return HTMLResponse(html, headers={"Cache-Control": "no-cache"})


@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
def index():
    return _page("index.html")


@app.get("/login", include_in_schema=False)
def login_page():
    if not auth.AUTH_ENABLED:
        return RedirectResponse("/", status_code=303)
    return _page("login.html")


# --------------------------------------------------------------- access gate
# Reachable without a full session. /api/auth/* handlers enforce their own stage.
PUBLIC_PATHS = {"/login", "/login.js", "/styles.css", "/logo.svg", "/api/health", "/favicon.ico"}
# Requests that fan out to many DNS/HTTP/TCP lookups share a concurrency cap.
HEAVY_PREFIXES = ("/api/discover", "/api/harden", "/api/builder/", "/api/sec/lookalike", "/api/bulk", "/api/net/ports", "/api/blacklist", "/api/domain/",
                  "/api/smtp", "/api/dmarcreport", "/api/net/tls", "/api/m365/autodiscover", "/api/sec/url",
                  "/api/net/http", "/api/cert/fetch", "/api/identity/tenant")
_heavy = asyncio.Semaphore(MAX_HEAVY)
# Active tests (port scan, TLS protocol probing, live SMTP session) only run after the engineer
# confirms they're authorized to test the target. The browser sends this header once the box is
# ticked; a custom header also can't be forged by a cross-site link or form.
ACTIVE_PREFIXES = ("/api/net/ports", "/api/net/tls", "/api/smtp/")
_uploads = asyncio.Semaphore(2)  # report uploads decompress up to 60 MB each: keep memory bounded

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


def _secure_headers(resp: Response, request: Request) -> Response:
    h = resp.headers
    if not (API_DOCS and request.url.path == "/api/docs"):  # Swagger UI loads from a CDN
        h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.url.scheme == "https":
        h["Strict-Transport-Security"] = "max-age=31536000"
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    elif "Cache-Control" not in h:
        h["Cache-Control"] = "no-cache"  # revalidate UI files (ETag) so updates show up
    return resp


def _deny(request: Request, status: int, detail: str) -> Response:
    return _secure_headers(JSONResponse({"detail": detail}, status_code=status), request)


def _same_origin(request: Request) -> bool:
    """Browsers send Origin on cross-site POSTs; reject anything not from this host."""
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return origin is None
    return urlsplit(origin).netloc.lower() == request.headers.get("host", "").lower()


@app.middleware("http")
async def gate(request: Request, call_next):
    path = request.url.path
    # Encoded dot-segments (/api/auth/..%2f..%2fcore.js) would pass a prefix check and reach StaticFiles.
    segs = path.split("/")
    if ".." in segs or "." in segs or "\\" in path or "\x00" in path:
        return _deny(request, 404, "Not Found")
    unsafe = request.method in ("POST", "PUT", "PATCH", "DELETE")
    sess = None
    if auth.AUTH_ENABLED:
        token = request.cookies.get(auth.COOKIE_NAME)
        sess = await run_in_threadpool(auth.load_session, token) if token else None
    request.state.session = sess

    if unsafe and not _same_origin(request):
        return _deny(request, 403, "Cross-origin request refused.")
    if unsafe:
        # Cap request bodies before anything reads them (report uploads are base64, so allow more there).
        limit = 40_000_000 if path.startswith("/api/dmarcreport") else 5_000_000
        length = request.headers.get("content-length")
        if length is None and request.headers.get("transfer-encoding"):
            return _deny(request, 411, "Send a Content-Length header.")
        if length and (not length.isdigit() or int(length) > limit):
            return _deny(request, 413, f"Request too large (limit {limit // 1_000_000} MB).")
    if auth.AUTH_ENABLED:
        is_auth_api = path.startswith("/api/auth/")
        if not (path in PUBLIC_PATHS or is_auth_api):
            if not sess or sess["stage"] != "full":
                if path in ("/", "/index.html"):
                    return _secure_headers(RedirectResponse("/login", status_code=303), request)
                return _deny(request, 401, "Sign in required.")
            if path.startswith("/api/admin/") and sess["role"] != "admin":
                return _deny(request, 403, "Administrators only.")
        if unsafe:
            if path in ("/api/auth/login", "/api/auth/setup"):
                # JSON-only forces a CORS preflight for any cross-site attempt (login CSRF).
                if not request.headers.get("content-type", "").lower().startswith("application/json"):
                    return _deny(request, 415, "Send JSON.")
            elif sess and not hmac.compare_digest(request.headers.get("x-csrf-token", "").encode("latin-1", "replace"), sess["csrf"].encode()):
                return _deny(request, 403, "Missing or invalid CSRF token. Reload the page.")
            elif not sess and not is_auth_api:
                return _deny(request, 401, "Sign in required.")

    authorized = request.headers.get("x-mspg-authorized") == "1"
    if path.startswith(ACTIVE_PREFIXES) and not authorized:
        return _deny(request, 428, "This is an active test: it probes the target system. Confirm you own it or are authorized to test it "
                                   "(tick the authorization box on the tool page), then run it again.")

    heavy = path.startswith(HEAVY_PREFIXES)
    sem = _uploads if path.startswith("/api/dmarcreport") else _heavy
    if heavy:
        try:
            await asyncio.wait_for(sem.acquire(), timeout=30)
        except asyncio.TimeoutError:
            return _deny(request, 503, "The server is busy with other scans. Try again in a moment.")
    try:
        response = await call_next(request)
    finally:
        if heavy:
            sem.release()

    # Who ran which tool (target in the URL; pasted bodies are never logged).
    if (auth.AUTH_ENABLED and auth.AUDIT_TOOL_USAGE and sess and sess["stage"] == "full" and path.startswith("/api/")
            and not path.startswith(("/api/auth/", "/api/admin/", "/api/health", "/api/meta"))
            and not (path.startswith("/api/assessments") and request.method == "GET")):  # viewing saved reports isn't tool use
        detail = f"{request.method} {path}" + (f"?{request.url.query}" if request.url.query and request.method == "GET" else "")
        if path.startswith(ACTIVE_PREFIXES):
            detail += " [active test, authorization confirmed]"
        await run_in_threadpool(auth.audit, "tool", sess["username"], client_ip(request), detail[:400])
    return _secure_headers(response, request)


class RawText(BaseModel):
    raw: str = Field(..., max_length=2_000_000)


class SmtpRequest(BaseModel):
    target: str = Field(..., max_length=255)
    port: int = 25
    tls_mode: str = "starttls"
    helo: str | None = Field(None, max_length=255)
    mail_from: str | None = Field(None, max_length=320)
    rcpt_to: str | None = Field(None, max_length=320)
    resolve_mx: bool = True


@app.get("/api/health")
def health(request: Request):
    body = {"status": "ok" if not MODULE_ERRORS else "degraded", "version": __version__}
    sess = getattr(request.state, "session", None)
    if not auth.AUTH_ENABLED or (sess and sess["stage"] == "full"):
        body["module_errors"] = MODULE_ERRORS  # internal detail: signed-in users only
    return body


@app.get("/api/meta")
def meta():
    org = workspace.get_settings()
    return {"version": __version__, "resolvers": resolver_names(), "record_types": RECORD_TYPES, "saving": workspace.AVAILABLE,
            "org": {"name": org["org_name"], "website": org["org_website"], "contact": org["org_contact"]}}


@app.post("/api/headers/analyze")
def headers_analyze(body: RawText):
    return _run(analyze_headers, body.raw)


@app.post("/api/ndr/analyze")
def ndr_analyze(body: RawText):
    return _run(analyze_ndr, body.raw)


@app.get("/api/domain/{domain:path}")
def domain_check(domain: str, resolver: str | None = None, selectors: str = ""):
    return _run(check_domain, domain, resolver, [s for s in selectors.split(",") if s.strip()])


@app.get("/api/spf/{domain:path}")
def spf_check(domain: str, ip: str | None = None, resolver: str | None = None):
    return _run(analyze_spf, domain, resolver, ip or None)


@app.post("/api/smtp/test")
def smtp_check(body: SmtpRequest):
    mail_from = body.mail_from.strip() if body.mail_from is not None else None
    return _run(smtp_test, body.target, body.port, body.tls_mode, body.helo, mail_from,
                (body.rcpt_to or "").strip() or None, body.resolve_mx)


@app.get("/api/blacklist/{target:path}")
def blacklist_check(target: str, resolver: str | None = None):
    return _run(check_target, target, resolver)


@app.get("/api/ip/{target:path}")
def ip_info(target: str, domain: str | None = None):
    return _run(ip_lookup, target, domain)


@app.get("/api/dns")
def dns_lookup(name: str = Query(..., max_length=255), type: str = "A"):
    return _run(lookup, name, type)


app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
