"""Saved assessments (prospect reports and hardening plans) and report branding."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..core import auth, workspace
from ..core.dns_utils import normalize_domain

router = APIRouter()
_ID = re.compile(r"[0-9a-f]{16}")


class SaveBody(BaseModel):
    result_id: str = Field(..., max_length=64)


class BrandingBody(BaseModel):
    org_name: str | None = Field(None, max_length=120)
    org_website: str | None = Field(None, max_length=200)
    org_contact: str | None = Field(None, max_length=200)


def _who(request: Request) -> tuple[str | None, bool]:
    """(username, is_admin). With sign-in turned off there is one implicit admin."""
    sess = getattr(request.state, "session", None) or {}
    return sess.get("username"), (not auth.AUTH_ENABLED) or sess.get("role") == "admin"


@router.get("/api/assessments")
def list_assessments(kind: str | None = Query(None, max_length=20), domain: str | None = Query(None, max_length=255), limit: int = Query(50, ge=1, le=500)):
    if kind and kind not in workspace.KINDS:
        raise HTTPException(400, "Unknown assessment kind.")
    d = None
    if domain:
        try:
            d = normalize_domain(domain)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    return {"available": workspace.AVAILABLE, "items": workspace.list_saved(kind, d, limit)}


@router.get("/api/assessments/{aid}")
def get_assessment(aid: str):
    if not _ID.fullmatch(aid):
        raise HTTPException(404, "That saved assessment doesn't exist.")
    try:
        return workspace.get(aid)
    except LookupError as exc:
        raise HTTPException(404, "That saved assessment doesn't exist (it may have been deleted or expired).") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/assessments")
def save_assessment(body: SaveBody, request: Request):
    user, _ = _who(request)
    try:
        return workspace.save(body.result_id, user)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.delete("/api/assessments/{aid}")
def delete_assessment(aid: str, request: Request):
    if not _ID.fullmatch(aid):
        raise HTTPException(404, "That saved assessment doesn't exist.")
    user, admin = _who(request)
    try:
        workspace.delete(aid, user, admin)
    except LookupError as exc:
        raise HTTPException(404, "That saved assessment doesn't exist.") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


# The access gate restricts /api/admin/* to administrators.
@router.get("/api/admin/settings")
def get_branding():
    return {"available": workspace.AVAILABLE, **workspace.get_settings()}


@router.put("/api/admin/settings")
def put_branding(body: BrandingBody):
    try:
        return {"available": workspace.AVAILABLE, **workspace.put_settings(body.model_dump())}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
