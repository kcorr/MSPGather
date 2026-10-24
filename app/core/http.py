"""Helpers for API route handlers."""
from __future__ import annotations

from fastapi import HTTPException


def run(fn, *args, **kwargs):
    """Call a tool function; a ValueError becomes a 400 with its message."""
    try:
        return fn(*args, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
