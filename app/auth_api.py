"""HTTP routes for sign-in, account self-service and user administration.
The access gate itself (who may reach what) is the middleware in main.py."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .core import auth

router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)


class SetupBody(BaseModel):
    token: str = Field(..., max_length=100)
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)


class CodeBody(BaseModel):
    code: str = Field(..., max_length=32)


class PasswordBody(BaseModel):
    current: str | None = Field(None, max_length=256)
    new: str = Field(..., max_length=256)


class EnrollBody(BaseModel):
    password: str | None = Field(None, max_length=256)


class ConfirmBody(BaseModel):
    password: str = Field(..., max_length=256)


class NewUserBody(BaseModel):
    username: str = Field(..., max_length=64)
    role: str = Field("user", max_length=10)


class UpdateUserBody(BaseModel):
    role: str | None = Field(None, max_length=10)
    disabled: bool | None = None
    unlock: bool = False
    reset_password: bool = False
    reset_mfa: bool = False
    sign_out: bool = False


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _err(exc: auth.AuthError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=exc.status)


def _set_cookie(resp: JSONResponse, request: Request, token: str) -> None:
    resp.set_cookie(auth.COOKIE_NAME, token, httponly=True, samesite="strict", path="/",
                    secure=auth.cookie_secure(request.url.scheme), max_age=auth.SESSION_MAX_HOURS * 3600)


def _session(request: Request) -> dict | None:
    return getattr(request.state, "session", None)


def _require(request: Request, *stages: str) -> dict:
    sess = _session(request)
    if not sess or (stages and sess["stage"] not in stages):
        raise auth.AuthError("Not signed in.", 401)
    return sess


# ------------------------------------------------------------------ sign-in
@router.get("/api/auth/status")
def status(request: Request):
    sess = _session(request)
    return {"auth_enabled": auth.AUTH_ENABLED, "setup_required": auth.setup_required(),
            "stage": sess["stage"] if sess else None, "require_mfa": auth.REQUIRE_MFA}


@router.post("/api/auth/setup")
def setup(body: SetupBody, request: Request):
    try:
        auth.setup_admin(body.token, body.username, body.password, client_ip(request))
    except auth.AuthError as exc:
        return _err(exc)
    return {"ok": True}


@router.post("/api/auth/login")
def login(body: LoginBody, request: Request):
    try:
        token, stage = auth.login(body.username, body.password, client_ip(request), request.headers.get("user-agent"))
    except auth.AuthError as exc:
        return _err(exc)
    resp = JSONResponse({"stage": stage})
    _set_cookie(resp, request, token)
    return resp


@router.post("/api/auth/mfa")
def mfa(body: CodeBody, request: Request):
    try:
        stage, token = auth.complete_mfa(_require(request, "mfa"), body.code, client_ip(request))
    except auth.AuthError as exc:
        return _err(exc)
    resp = JSONResponse({"stage": stage})
    _set_cookie(resp, request, token)
    return resp


@router.post("/api/auth/password")
def password(body: PasswordBody, request: Request):
    try:
        stage, token = auth.change_password(_require(request, "full", "password_change"), body.current, body.new, client_ip(request))
    except auth.AuthError as exc:
        return _err(exc)
    resp = JSONResponse({"stage": stage})
    if token:
        _set_cookie(resp, request, token)
    return resp


@router.post("/api/auth/mfa/enroll/start")
def enroll_start(request: Request, body: EnrollBody | None = None):
    try:
        return auth.mfa_enroll_start(_require(request, "mfa_enroll", "full"), body.password if body else None)
    except auth.AuthError as exc:
        return _err(exc)


@router.post("/api/auth/mfa/enroll/finish")
def enroll_finish(body: CodeBody, request: Request):
    try:
        result = auth.mfa_enroll_finish(_require(request, "mfa_enroll", "full"), body.code, client_ip(request))
    except auth.AuthError as exc:
        return _err(exc)
    token = result.pop("_token", None)
    resp = JSONResponse(result)
    if token:
        _set_cookie(resp, request, token)
    return resp


@router.post("/api/auth/logout")
def logout(request: Request):
    sess = _session(request)
    auth.logout(request.cookies.get(auth.COOKIE_NAME))
    if sess:
        auth.audit("logout", sess["username"], client_ip(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME, path="/")
    return resp


# --------------------------------------------------------------- self-service
@router.get("/api/auth/me")
def me(request: Request):
    if not auth.AUTH_ENABLED:
        return {"auth_enabled": False, "username": None, "role": "admin", "csrf": None}
    try:
        sess = _require(request)
    except auth.AuthError as exc:
        return _err(exc)
    info = auth.account_info(sess) if sess["stage"] == "full" else {"username": sess["username"], "role": sess["role"]}
    return {"auth_enabled": True, "stage": sess["stage"], "csrf": sess["csrf"], **info}


@router.get("/api/auth/sessions")
def sessions(request: Request):
    return {"sessions": auth.my_sessions(_require(request, "full"))}


@router.post("/api/auth/sessions/revoke-others")
def revoke_others(request: Request):
    return {"signed_out": auth.sign_out_others(_require(request, "full"), client_ip(request))}


@router.post("/api/auth/mfa/disable")
def mfa_disable(body: ConfirmBody, request: Request):
    try:
        auth.mfa_disable(_require(request, "full"), body.password, client_ip(request))
    except auth.AuthError as exc:
        return _err(exc)
    return {"ok": True}


@router.post("/api/auth/recovery-codes")
def recovery_codes(body: ConfirmBody, request: Request):
    try:
        return {"recovery_codes": auth.new_recovery_codes(_require(request, "full"), body.password, client_ip(request))}
    except auth.AuthError as exc:
        return _err(exc)


# ------------------------------------------------------------------- admin
# The middleware already restricts /api/admin/* to signed-in admins.
@router.get("/api/admin/users")
def users():
    return {"users": auth.list_users()}


@router.post("/api/admin/users")
def add_user(body: NewUserBody, request: Request):
    try:
        return auth.create_user(body.username, None, body.role, must_change=True, actor=_session(request)["username"], ip=client_ip(request))
    except auth.AuthError as exc:
        return _err(exc)


@router.patch("/api/admin/users/{user_id}")
def edit_user(user_id: int, body: UpdateUserBody, request: Request):
    changes = {k: v for k, v in body.model_dump().items() if v not in (None, False)}
    if body.disabled is False:
        changes["disabled"] = False
    try:
        return auth.update_user(user_id, changes, _session(request), client_ip(request))
    except auth.AuthError as exc:
        return _err(exc)


@router.delete("/api/admin/users/{user_id}")
def remove_user(user_id: int, request: Request):
    try:
        auth.delete_user(user_id, _session(request), client_ip(request))
    except auth.AuthError as exc:
        return _err(exc)
    return {"ok": True}


@router.get("/api/admin/audit")
def audit_log(limit: int = 200, offset: int = 0, q: str = ""):
    return {"events": auth.audit_list(limit, offset, q[:100])}
