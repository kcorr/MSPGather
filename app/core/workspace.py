"""Team workspace storage: saved assessments and report branding.

A prospect report or hardening plan is only stored when an engineer presses Save:
the server keeps each fresh result in memory for an hour under a random id, and
saving copies that server-generated result into SQLite (so a client can't store
arbitrary data). Saved assessments are shared with the whole team, kept for
MSPGATHER_ASSESSMENT_RETENTION_DAYS (default 365) and can be deleted at any time.
Pasted content (headers, logs, tokens) is never stored."""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import zlib
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger("mspgather.workspace")

DATA_DIR = Path(os.environ.get("MSPGATHER_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "workspace.db"
RETENTION_DAYS = max(1, int(os.environ.get("MSPGATHER_ASSESSMENT_RETENTION_DAYS", "365")))
MAX_SAVED = 5000
CACHE_TTL = 3600
CACHE_MAX = 64
KINDS = ("discovery", "hardening")
SETTING_KEYS = {"org_name": 120, "org_website": 200, "org_contact": 200}

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  domain TEXT NOT NULL,
  created REAL NOT NULL,
  created_by TEXT,
  grade TEXT,
  score INTEGER,
  org TEXT,
  headline TEXT,
  counts TEXT,
  data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS assessments_domain ON assessments(domain, created);
CREATE INDEX IF NOT EXISTS assessments_created ON assessments(created);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

AVAILABLE = False
_cache: dict[str, tuple[float, str, str, dict]] = {}
_lock = threading.Lock()


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def init() -> None:
    """Create the database. Without a writable data directory the feature stays off."""
    global AVAILABLE
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with _conn() as c:
            c.execute("PRAGMA journal_mode = WAL")
            c.executescript(SCHEMA)
        AVAILABLE = True
        _prune()
    except (OSError, sqlite3.Error) as exc:
        AVAILABLE = False
        log.warning("Saved assessments are disabled: %s is not writable (%s)", DATA_DIR, exc)


def _require() -> None:
    if not AVAILABLE:
        raise ValueError("Saving is unavailable: the server has no writable data directory (mount a volume at /data).")


# ------------------------------------------------------------------ result cache
def remember(kind: str, domain: str, data: dict) -> str:
    """Keep a fresh, server-generated result for an hour so it can be saved without re-running."""
    rid = secrets.token_urlsafe(12)
    now = time.time()
    with _lock:
        for k in [k for k, v in _cache.items() if now - v[0] > CACHE_TTL]:
            _cache.pop(k, None)
        while len(_cache) >= CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[rid] = (now, kind, domain, data)
    return rid


# Saved reports keep business information, not people: an address that looks like a named
# person (jsmith@, john.smith@) becomes "[name removed]@domain"; role and machine addresses
# (hostmaster@, dmarc-reports@, vendor report tokens) are kept.
_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
_ROLE_WORDS = re.compile(r"dmarc|postmaster|hostmaster|webmaster|abuse|noreply|no-reply|donotreply|helpdesk|servicedesk|support|security|"
                         r"admin|billing|privacy|compliance|registrar|sysadmin|devops|reports?|tlsrpt|bounces?|enquir|inquir|feedback", re.I)
_ROLE_TOKENS = {"it", "hr", "ops", "dns", "info", "mail", "email", "team", "tech", "sales", "office", "hello", "contact", "help", "root",
                "noc", "soa", "mta", "rua", "ruf", "zone", "cert", "certs", "tls", "spam", "inbox", "press", "media", "jobs", "careers",
                "accounts", "finance", "marketing", "reception", "partners", "service", "services", "domains", "domain", "legal"}


def _person_like(local: str) -> bool:
    if _ROLE_WORDS.search(local):
        return False
    tokens = [t for t in re.split(r"[._+%-]", local.lower()) if t]
    if any(t in _ROLE_TOKENS or re.fullmatch(r"[0-9a-f]{8,}|\w*\d{3,}\w*", t) for t in tokens):
        return False
    return True


def _redact(obj):
    if isinstance(obj, str):
        return _EMAIL.sub(lambda m: f"[name removed]@{m.group(2)}" if _person_like(m.group(1)) else m.group(0), obj)
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _redact(v) for k, v in obj.items()}
    return obj


def _org(data: dict) -> str | None:
    title = ((data.get("website") or {}).get("title") or "").strip()
    brand = re.split(r"\s[|·–—-]\s|\s[|·]\s?|:\s", title)[0].strip() if title else ""
    if brand and len(brand) <= 60 and not re.match(r"(home|welcome|index|untitled|40\d|just a moment)", brand, re.I):
        return brand
    return ((data.get("identity") or {}).get("brand") or None)


def _summarize(kind: str, data: dict) -> dict:
    if kind == "discovery":
        tp = data.get("talking_points") or []
        posture = data.get("posture") or {}
        return {"grade": posture.get("grade"), "score": posture.get("score"), "org": _org(data), "headline": data.get("headline"),
                "counts": {k: sum(1 for t in tp if t.get("kind") == k) for k in ("risk", "opportunity", "question")}}
    summary = data.get("summary") or {}
    score = summary.get("score")
    grade = None if score is None else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    return {"grade": grade, "score": score, "org": None, "headline": data.get("headline"),
            "counts": {k: summary.get(k, 0) for k in ("pass", "fail", "warn", "manual")}}


def save(result_id: str, user: str | None) -> dict:
    _require()
    with _lock:
        item = _cache.get(result_id or "")
    if not item or time.time() - item[0] > CACHE_TTL:
        raise ValueError("That result is no longer available to save (results are kept for an hour). Run it again, then save.")
    _, kind, domain, data = item
    data = _redact(data)
    s = _summarize(kind, data)
    aid = secrets.token_hex(8)
    blob = zlib.compress(json.dumps(data, separators=(",", ":"), default=str).encode("utf-8"), 6)
    with _conn() as c:
        c.execute("INSERT INTO assessments (id, kind, domain, created, created_by, grade, score, org, headline, counts, data) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                  (aid, kind, domain, time.time(), user, s["grade"], s["score"], s["org"], s["headline"], json.dumps(s["counts"]), blob))
    _prune()
    return {"id": aid, "kind": kind, "domain": domain}


def _row(r: sqlite3.Row, with_data: bool = False) -> dict:
    out = {k: r[k] for k in ("id", "kind", "domain", "created_by", "grade", "score", "org", "headline")}
    out["created"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["created"]))
    out["counts"] = json.loads(r["counts"] or "{}")
    if with_data:
        out["data"] = json.loads(zlib.decompress(r["data"]).decode("utf-8"))
    return out


def list_saved(kind: str | None = None, domain: str | None = None, limit: int = 50) -> list[dict]:
    if not AVAILABLE:
        return []
    limit = max(1, min(int(limit), 500))
    q, args = "SELECT id, kind, domain, created, created_by, grade, score, org, headline, counts FROM assessments WHERE 1=1", []
    if kind:
        q += " AND kind = ?"; args.append(kind)
    if domain:
        q += " AND domain = ?"; args.append(domain.lower())
    q += " ORDER BY created DESC LIMIT ?"; args.append(limit)
    with _conn() as c:
        return [_row(r) for r in c.execute(q, args).fetchall()]


def get(aid: str) -> dict:
    _require()
    with _conn() as c:
        r = c.execute("SELECT * FROM assessments WHERE id = ?", (aid,)).fetchone()
    if not r:
        raise LookupError("not found")
    return _row(r, with_data=True)


def delete(aid: str, user: str | None, is_admin: bool) -> None:
    _require()
    with _conn() as c:
        r = c.execute("SELECT created_by FROM assessments WHERE id = ?", (aid,)).fetchone()
        if not r:
            raise LookupError("not found")
        if not is_admin and r["created_by"] and r["created_by"] != user:
            raise PermissionError("Only the engineer who saved it, or an administrator, can delete it.")
        c.execute("DELETE FROM assessments WHERE id = ?", (aid,))


def _prune() -> None:
    with _conn() as c:
        c.execute("DELETE FROM assessments WHERE created < ?", (time.time() - RETENTION_DAYS * 86400,))
        c.execute("DELETE FROM assessments WHERE id NOT IN (SELECT id FROM assessments ORDER BY created DESC LIMIT ?)", (MAX_SAVED,))


# ------------------------------------------------------------------ branding
def get_settings() -> dict:
    """Report branding (org name/website/contact). Environment variables are the defaults."""
    out = {"org_name": os.environ.get("MSPGATHER_ORG_NAME", ""), "org_website": os.environ.get("MSPGATHER_ORG_WEBSITE", ""),
           "org_contact": os.environ.get("MSPGATHER_ORG_CONTACT", "")}
    if AVAILABLE:
        with _conn() as c:
            for r in c.execute("SELECT key, value FROM settings").fetchall():
                if r["key"] in SETTING_KEYS:
                    out[r["key"]] = r["value"]
    return out


def put_settings(changes: dict) -> dict:
    _require()
    with _conn() as c:
        for key, limit in SETTING_KEYS.items():
            if key in changes and changes[key] is not None:
                value = re.sub(r"[\x00-\x1f\x7f]", "", str(changes[key])).strip()[:limit]
                c.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    return get_settings()
