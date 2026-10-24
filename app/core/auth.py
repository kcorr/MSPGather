"""Authentication: local accounts, TOTP MFA, sessions, CSRF, lockout, audit log.

Design notes
- Passwords: scrypt (N=2^15, r=8, p=1) with a per-user random salt.
- Sessions: 256-bit random token in an HttpOnly, SameSite=Strict cookie; only
  its SHA-256 is stored, so a stolen database can't be replayed as sessions.
- Sign-in is staged: password → (forced password change) → MFA / MFA enrolment
  → full session. Partial sessions can only reach /api/auth/*.
- CSRF: every state-changing request from a signed-in browser must send the
  session's CSRF token in X-CSRF-Token (checked in main.py middleware).
- First run: no default credentials. If no users exist, a one-time setup token
  is printed to the logs; only that token can create the first admin.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import struct
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

log = logging.getLogger("mspgather.auth")


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


AUTH_ENABLED = os.environ.get("MSPGATHER_AUTH", "on").strip().lower() not in ("off", "false", "0", "no")
REQUIRE_MFA = _env_bool("MSPGATHER_REQUIRE_MFA", True)
SESSION_IDLE_MIN = int(os.environ.get("MSPGATHER_SESSION_IDLE_MINUTES", "240"))
SESSION_MAX_HOURS = int(os.environ.get("MSPGATHER_SESSION_MAX_HOURS", "12"))
COOKIE_SECURE = os.environ.get("MSPGATHER_COOKIE_SECURE", "auto").strip().lower()  # auto | true | false
AUDIT_TOOL_USAGE = _env_bool("MSPGATHER_AUDIT_TOOL_USAGE", True)
AUDIT_RETENTION_DAYS = int(os.environ.get("MSPGATHER_AUDIT_RETENTION_DAYS", "90"))
DATA_DIR = Path(os.environ.get("MSPGATHER_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "mspgather.db"
COOKIE_NAME = "mspg_session"
PENDING_MINUTES = 10
MAX_FAILS_PER_USER = 5      # per (username, client network) in the window
USER_MAX_FAILS = 50         # per account from anywhere: then the account locks
MAX_MFA_FAILS = 10          # wrong MFA codes per account before it locks
LOCK_MINUTES = 15
IP_WINDOW_SEC = 15 * 60
IP_MAX_FAILS = max(5, int(os.environ.get("MSPGATHER_IP_MAX_FAILS", "20")))  # per client network per 15 min (password + MFA)
MIN_PASSWORD_LEN = 12
ISSUER = os.environ.get("MSPGATHER_TOTP_ISSUER", "MSPGather")

_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "dklen": 64, "maxmem": 64 * 1024 * 1024}
_DUMMY_HASH: str | None = None
_SETUP_TOKEN: str | None = None
_ip_fails: dict[str, list[float]] = {}
_ip_lock = threading.Lock()
_setup_lock = threading.Lock()
_last_cleanup = 0.0


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  must_change_password INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  recovery_codes TEXT NOT NULL DEFAULT '[]',
  disabled INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  mfa_failed INTEGER NOT NULL DEFAULT 0,
  locked_until REAL NOT NULL DEFAULT 0,
  created REAL NOT NULL,
  last_login REAL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage TEXT NOT NULL,
  csrf TEXT NOT NULL,
  created REAL NOT NULL,
  last_seen REAL NOT NULL,
  expires REAL NOT NULL,
  mfa_attempts INTEGER NOT NULL DEFAULT 0,
  pending_totp TEXT,
  ip TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  username TEXT,
  event TEXT NOT NULL,
  ip TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
"""


_local = threading.local()


@contextmanager
def db():
    """One connection per unit of work. Nested use on the same thread (e.g. an
    audit write inside a sign-in transaction) reuses the open connection instead
    of deadlocking on SQLite's write lock. An AuthError still commits: failed
    attempts, lockouts and their audit entries are intended state changes."""
    outer = getattr(_local, "conn", None)
    if outer is not None:
        yield outer
        return
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _local.conn = conn
    try:
        yield conn
        conn.commit()
    except AuthError:
        conn.commit()
        raise
    except BaseException:
        conn.rollback()
        raise
    finally:
        _local.conn = None
        conn.close()


def init() -> None:
    """Create the database and, on first run, a setup token."""
    global _DUMMY_HASH, _SETUP_TOKEN
    if not AUTH_ENABLED:
        log.warning("AUTHENTICATION IS DISABLED (MSPGATHER_AUTH=off). Never expose this instance to a network you don't trust.")
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.execute("PRAGMA journal_mode = WAL")
        c.executescript(SCHEMA)
        cols = {r[1] for r in c.execute("PRAGMA table_info(users)")}
        if "mfa_failed" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN mfa_failed INTEGER NOT NULL DEFAULT 0")
    _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    _bootstrap_from_env()
    if user_count() == 0:
        _SETUP_TOKEN = secrets.token_urlsafe(24)
        banner = "=" * 72
        log.warning("\n%s\n MSPGather first-run setup\n Open the web UI and enter this one-time setup token to create the admin account:\n\n   %s\n\n The token changes every time the container restarts until setup is done.\n%s",
                    banner, _SETUP_TOKEN, banner)
        print(f"\n{banner}\n MSPGather first-run setup token: {_SETUP_TOKEN}\n{banner}\n", flush=True)


def _bootstrap_from_env() -> None:
    """Optional unattended setup: MSPGATHER_ADMIN_USER + MSPGATHER_ADMIN_PASSWORD
    create the first admin only if no users exist (must change password at first sign-in)."""
    user, pw = os.environ.get("MSPGATHER_ADMIN_USER"), os.environ.get("MSPGATHER_ADMIN_PASSWORD")
    if user and pw and user_count() == 0:
        create_user(user, pw, "admin", must_change=True, actor="bootstrap", ip=None)
        log.warning("Created admin account '%s' from environment variables. Remove MSPGATHER_ADMIN_PASSWORD from the environment now.", user)


def user_count() -> int:
    with db() as c:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def setup_required() -> bool:
    return AUTH_ENABLED and user_count() == 0


# ------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return "scrypt${n}${r}${p}${s}${h}".format(n=_SCRYPT["n"], r=_SCRYPT["r"], p=_SCRYPT["p"],
                                                 s=base64.b64encode(salt).decode(), h=base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, s, h = stored.split("$")
        dk = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(s), n=int(n), r=int(r), p=int(p),
                            dklen=len(base64.b64decode(h)), maxmem=_SCRYPT["maxmem"])
        return hmac.compare_digest(dk, base64.b64decode(h))
    except (ValueError, TypeError):
        return False


_COMMON = {"password", "password123", "passw0rd", "123456789012", "qwertyuiop", "letmein", "welcome", "changeme", "administrator",
           "mspgather", "admin123", "p@ssw0rd", "iloveyou", "trustno1", "summer2026", "winter2026", "spring2026", "autumn2026"}


def check_password_policy(password: str, username: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LEN} characters. A passphrase of a few random words works well.")
    if len(password) > 256:
        raise AuthError("Password is too long (max 256 characters).")
    low = password.lower()
    if username and username.lower() in low:
        raise AuthError("Password must not contain the username.")
    if low in _COMMON or len(set(password)) < 5:
        raise AuthError("That password is too common or too simple.")


USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{3,64}$")


def _check_username(username: str) -> str:
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise AuthError("Username must be 3–64 characters: letters, numbers, . _ @ -")
    return username


# ----------------------------------------------------------------------- TOTP
def _totp_at(secret_b32: str, step: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_verify(secret_b32: str, code: str, last_step: int) -> int | None:
    """Return the matched time step (to block replay), or None. ±1 step of clock drift."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    now = int(time.time() // 30)
    for step in (now - 1, now, now + 1):
        if step > last_step and hmac.compare_digest(_totp_at(secret_b32, step), code):
            return step
    return None


def _qr_svg(data: str) -> str | None:
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").lower().encode()).hexdigest()


def _new_recovery_codes() -> tuple[list[str], list[str]]:
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(8)]
    return codes, [_hash_code(c) for c in codes]


# -------------------------------------------------------------------- audit
def audit(event: str, username: str | None = None, ip: str | None = None, detail: str | dict | None = None) -> None:
    if not AUTH_ENABLED:
        return
    if isinstance(detail, dict):
        detail = json.dumps(detail, separators=(",", ":"))
    with db() as c:
        c.execute("INSERT INTO audit (ts, username, event, ip, detail) VALUES (?,?,?,?,?)",
                  (time.time(), username, event, ip, (detail or "")[:500]))


def audit_list(limit: int = 200, offset: int = 0, q: str = "") -> list[dict]:
    limit = max(1, min(int(limit), 1000))
    with db() as c:
        if q:
            like = f"%{q}%"
            rows = c.execute("SELECT * FROM audit WHERE username LIKE ? OR event LIKE ? OR detail LIKE ? OR ip LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                             (like, like, like, like, limit, offset)).fetchall()
        else:
            rows = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------- lockout
def _ip_key(ip: str) -> str:
    """IPv6 clients are throttled per /64 so rotating addresses inside one allocation doesn't help."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6 and not addr.ipv4_mapped:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(getattr(addr, "ipv4_mapped", None) or addr)


def _throttle(key: str, limit: int) -> bool:
    """Atomically check a sliding-window counter and reserve one attempt.
    Returns False (and reserves nothing) when the key is at its limit.
    Call _release(key) when the attempt turns out to be a success."""
    now = time.time()
    with _ip_lock:
        fails = [t for t in _ip_fails.get(key, []) if now - t < IP_WINDOW_SEC]
        if len(fails) >= limit:
            _ip_fails[key] = fails
            return False
        fails.append(now)
        _ip_fails[key] = fails
        if len(_ip_fails) > 20_000:  # bound memory: drop the oldest-touched keys
            for k in sorted(_ip_fails, key=lambda k: _ip_fails[k][-1] if _ip_fails[k] else 0)[:10_000]:
                _ip_fails.pop(k, None)
        return True


def _release(key: str) -> None:
    with _ip_lock:
        if _ip_fails.get(key):
            _ip_fails[key].pop()


# ------------------------------------------------------------------ sessions
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _new_session(c, user_id: int, stage: str, ip: str | None, ua: str | None) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    expires = now + (PENDING_MINUTES * 60 if stage != "full" else SESSION_MAX_HOURS * 3600)
    c.execute("INSERT INTO sessions (token_hash, user_id, stage, csrf, created, last_seen, expires, ip, user_agent) VALUES (?,?,?,?,?,?,?,?,?)",
              (_token_hash(token), user_id, stage, secrets.token_urlsafe(24), now, now, expires, ip, (ua or "")[:200]))
    return token


def _cleanup() -> None:
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < 300:
        return
    _last_cleanup = now
    with db() as c:
        c.execute("DELETE FROM sessions WHERE expires < ? OR (stage = 'full' AND last_seen < ?)", (now, now - SESSION_IDLE_MIN * 60))
        c.execute("DELETE FROM audit WHERE ts < ?", (now - AUDIT_RETENTION_DAYS * 86400,))


def load_session(token: str | None) -> dict | None:
    """Session + user for a cookie token, enforcing expiry and idle timeout."""
    if not token or len(token) > 100:
        return None
    _cleanup()
    now = time.time()
    with db() as c:
        row = c.execute("""SELECT s.*, u.username, u.role, u.disabled, u.totp_enabled, u.must_change_password
                           FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?""", (_token_hash(token),)).fetchone()
        if not row:
            return None
        if row["expires"] < now or row["disabled"] or (row["stage"] == "full" and now - row["last_seen"] > SESSION_IDLE_MIN * 60):
            c.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
            return None
        if now - row["last_seen"] > 60:
            c.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, row["token_hash"]))
        return dict(row)


def _set_stage(c, token_hash: str, stage: str, prev_stage: str | None = None) -> str | None:
    """Move a session to its next stage. Reaching 'full' from a pending stage issues a
    new token and CSRF value (returned), so a pending-stage token never becomes a full one."""
    now = time.time()
    expires = now + (SESSION_MAX_HOURS * 3600 if stage == "full" else PENDING_MINUTES * 60)
    new_token = secrets.token_urlsafe(32) if stage == "full" and prev_stage != "full" else None
    c.execute("UPDATE sessions SET token_hash = ?, csrf = CASE WHEN ? THEN ? ELSE csrf END, stage = ?, expires = ?, last_seen = ?, "
              "mfa_attempts = 0, pending_totp = NULL WHERE token_hash = ?",
              (_token_hash(new_token) if new_token else token_hash, 1 if new_token else 0, secrets.token_urlsafe(24),
               stage, expires, now, token_hash))
    return new_token


def _next_stage(user: sqlite3.Row | dict) -> str:
    if user["must_change_password"]:
        return "password_change"
    if user["totp_enabled"]:
        return "mfa"
    if REQUIRE_MFA:
        return "mfa_enroll"
    return "full"


def logout(token: str | None) -> None:
    if token:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


# ------------------------------------------------------------------ sign-in
def login(username: str, password: str, ip: str, ua: str | None) -> tuple[str, str]:
    """Returns (session token, next stage). Raises AuthError with a generic message:
    unknown, wrong-password and locked accounts look the same unless the password is right."""
    generic = AuthError("Incorrect username or password.", 401)
    username = (username or "").strip()[:64]
    ipk = _ip_key(ip)
    if not _throttle(f"ip:{ipk}", IP_MAX_FAILS):
        audit("login_blocked_ip", username or None, ip, "too many failures from this network")
        raise AuthError("Too many failed sign-ins from your network. Try again in 15 minutes.", 429)
    # Throttle per (username, network): an attacker elsewhere can't lock the real user out.
    ukey = f"user:{username.lower()}|{ipk}"
    if not _throttle(ukey, MAX_FAILS_PER_USER):
        _release(f"ip:{ipk}")
        audit("login_blocked", username or None, ip, "too many failures for this account from this network")
        raise AuthError("Too many failed sign-ins. Try again in 15 minutes.", 429)
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            verify_password(password or "", _DUMMY_HASH or "")  # same time cost as a real check
            audit("login_failed", username, ip, "unknown user")
            raise generic
        now = time.time()
        ok = verify_password(password or "", user["pw_hash"])
        if user["locked_until"] > now:
            audit("login_locked", username, ip, "correct password" if ok else "wrong password")
            if ok:  # only someone who knows the password learns the account is locked
                raise AuthError(f"This account is locked after too many failed attempts. Try again in {int((user['locked_until'] - now) // 60) + 1} minutes, or ask an admin.", 423)
            raise generic
        if not ok:
            fails = user["failed_count"] + 1
            locked = now + LOCK_MINUTES * 60 if fails >= USER_MAX_FAILS else 0
            c.execute("UPDATE users SET failed_count = ?, locked_until = ? WHERE id = ?", (0 if locked else fails, locked, user["id"]))
            audit("login_failed", username, ip, "wrong password" + (", account locked" if locked else ""))
            raise generic
        if user["disabled"]:
            audit("login_failed", username, ip, "account disabled")
            raise generic
        _release(ukey)
        _release(f"ip:{ipk}")
        c.execute("UPDATE users SET failed_count = 0 WHERE id = ?", (user["id"],))
        # One pending sign-in per account: opening many MFA-stage sessions must not multiply guesses.
        c.execute("DELETE FROM sessions WHERE user_id = ? AND stage != 'full'", (user["id"],))
        stage = _next_stage(user)
        token = _new_session(c, user["id"], stage, ip, ua)
        if stage == "full":
            c.execute("UPDATE users SET last_login = ?, mfa_failed = 0 WHERE id = ?", (now, user["id"]))
    audit("login_success" if stage == "full" else "login_password_ok", user["username"], ip, None if stage == "full" else f"next: {stage}")
    return token, stage


def complete_mfa(sess: dict, code: str, ip: str) -> tuple[str, str]:
    """Returns (stage, new session token)."""
    if sess["stage"] != "mfa":
        raise AuthError("No MFA step is pending.", 409)
    ipk = f"ip:{_ip_key(ip)}"
    if not _throttle(ipk, IP_MAX_FAILS):
        raise AuthError("Too many failed attempts from your network. Try again in 15 minutes.", 429)
    with db() as c:
        # Count the attempt atomically before checking it, so parallel guesses can't share one slot.
        row = c.execute("UPDATE sessions SET mfa_attempts = mfa_attempts + 1 WHERE token_hash = ? AND stage = 'mfa' AND mfa_attempts < 5 "
                        "RETURNING mfa_attempts", (sess["token_hash"],)).fetchone()
        user = c.execute("SELECT * FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
        if not row or user["locked_until"] > time.time():
            c.execute("DELETE FROM sessions WHERE token_hash = ?", (sess["token_hash"],))
            audit("mfa_failed", user["username"], ip, "too many attempts, sign-in cancelled")
            raise AuthError("Too many wrong codes. Sign in again.", 401)
        used_recovery = False
        step = totp_verify(user["totp_secret"], code, user["totp_last_step"])
        if step is not None:
            # Conditional update: of two parallel requests with the same code, only one wins.
            if c.execute("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
                         (step, user["id"], step)).rowcount != 1:
                step = None
        else:
            hashes = json.loads(user["recovery_codes"] or "[]")
            h = _hash_code(code or "")
            if code and h in hashes:
                remaining = [x for x in hashes if x != h]
                used_recovery = c.execute("UPDATE users SET recovery_codes = ? WHERE id = ? AND recovery_codes = ?",
                                          (json.dumps(remaining), user["id"], user["recovery_codes"])).rowcount == 1
        if step is None and not used_recovery:
            fails = user["mfa_failed"] + 1
            locked = time.time() + LOCK_MINUTES * 60 if fails >= MAX_MFA_FAILS else 0
            c.execute("UPDATE users SET mfa_failed = ?, locked_until = CASE WHEN ? > 0 THEN ? ELSE locked_until END WHERE id = ?",
                      (0 if locked else fails, locked, locked, user["id"]))
            if locked:
                c.execute("DELETE FROM sessions WHERE user_id = ? AND stage != 'full'", (user["id"],))
            audit("mfa_failed", user["username"], ip, "account locked" if locked else None)
            raise AuthError("That code isn't valid. Check the time on your phone and try the newest code.", 401)
        _release(ipk)
        token = _set_stage(c, sess["token_hash"], "full", sess["stage"])
        c.execute("UPDATE users SET last_login = ?, mfa_failed = 0, failed_count = 0 WHERE id = ?", (time.time(), user["id"]))
    audit("login_success", user["username"], ip, "recovery code used" if used_recovery else "mfa")
    return "full", token


def change_password(sess: dict, current: str | None, new: str, ip: str) -> tuple[str, str | None]:
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
        if sess["stage"] == "full" and not verify_password(current or "", user["pw_hash"]):
            audit("password_change_failed", user["username"], ip, "wrong current password")
            raise AuthError("Current password is incorrect.", 401)
        if sess["stage"] not in ("full", "password_change"):
            raise AuthError("Finish signing in first.", 409)
        check_password_policy(new, user["username"])
        if verify_password(new, user["pw_hash"]):
            raise AuthError("The new password must be different from the current one.")
        c.execute("UPDATE users SET pw_hash = ?, must_change_password = 0 WHERE id = ?", (hash_password(new), user["id"]))
        # Sign out every other session for this user.
        c.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user["id"], sess["token_hash"]))
        stage = "full" if sess["stage"] == "full" else _next_stage({**dict(user), "must_change_password": 0})
        token = _set_stage(c, sess["token_hash"], stage, sess["stage"])
        if stage == "full":
            c.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user["id"]))
    audit("password_changed", user["username"], ip)
    return stage, token


def mfa_enroll_start(sess: dict, password: str | None = None) -> dict:
    if sess["stage"] not in ("mfa_enroll", "full"):
        raise AuthError("Finish signing in first.", 409)
    if sess["stage"] == "full" and sess.get("totp_enabled"):
        with db() as c:
            user = c.execute("SELECT pw_hash FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
        if not verify_password(password or "", user["pw_hash"]):
            raise AuthError("Enter your current password to replace your authenticator.", 401)
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    uri = f"otpauth://totp/{quote(ISSUER)}:{quote(sess['username'])}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits=6&period=30"
    with db() as c:
        c.execute("UPDATE sessions SET pending_totp = ? WHERE token_hash = ?", (secret, sess["token_hash"]))
    return {"secret": secret, "uri": uri, "qr_svg": _qr_svg(uri)}


def mfa_enroll_finish(sess: dict, code: str, ip: str) -> dict:
    with db() as c:
        row = c.execute("SELECT pending_totp FROM sessions WHERE token_hash = ?", (sess["token_hash"],)).fetchone()
        secret = row["pending_totp"] if row else None
        if not secret:
            raise AuthError("Start MFA setup first.", 409)
        step = totp_verify(secret, code, 0)
        if step is None:
            raise AuthError("That code doesn't match. Make sure you scanned the newest QR code and your phone's clock is correct.")
        codes, hashes = _new_recovery_codes()
        c.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_step = ?, recovery_codes = ? WHERE id = ?",
                  (secret, step, json.dumps(hashes), sess["user_id"]))
        stage = "full"
        token = _set_stage(c, sess["token_hash"], stage, sess["stage"])
        # A new authenticator signs out every other session for this account.
        c.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                  (sess["user_id"], _token_hash(token) if token else sess["token_hash"]))
        c.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), sess["user_id"]))
    audit("mfa_enrolled", sess["username"], ip)
    return {"stage": stage, "recovery_codes": codes, "_token": token}


def mfa_disable(sess: dict, password: str, ip: str) -> None:
    if REQUIRE_MFA:
        raise AuthError("MFA is required on this server and can't be turned off.", 403)
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
        if not verify_password(password or "", user["pw_hash"]):
            raise AuthError("Password is incorrect.", 401)
        c.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL, recovery_codes = '[]' WHERE id = ?", (user["id"],))
    audit("mfa_disabled", sess["username"], ip)


def setup_admin(token: str, username: str, password: str, ip: str) -> None:
    with _setup_lock:
        if not setup_required():
            raise AuthError("Setup is already complete.", 409)
        ipk = f"ip:{_ip_key(ip)}"
        if not _throttle(ipk, IP_MAX_FAILS):
            raise AuthError("Too many failed attempts from your network. Try again in 15 minutes.", 429)
        if not _SETUP_TOKEN or not hmac.compare_digest((token or "").strip().encode(), _SETUP_TOKEN.encode()):
            audit("setup_failed", None, ip, "wrong setup token")
            raise AuthError("Setup token is incorrect. Copy it from the container logs: docker logs mspgather", 401)
        _release(ipk)
        create_user(username, password, "admin", must_change=False, actor="setup", ip=ip)


# ---------------------------------------------------------------- user admin
def create_user(username: str, password: str | None, role: str, must_change: bool, actor: str, ip: str | None) -> dict:
    username = _check_username(username)
    if role not in ("admin", "user"):
        raise AuthError("Role must be admin or user.")
    temp = None
    if password is None:
        temp = _temp_password()
        password = temp
    else:
        check_password_policy(password, username)
    with db() as c:
        try:
            c.execute("INSERT INTO users (username, pw_hash, role, must_change_password, created) VALUES (?,?,?,?,?)",
                      (username, hash_password(password), role, 1 if must_change else 0, time.time()))
        except sqlite3.IntegrityError as exc:
            raise AuthError(f"User '{username}' already exists.", 409) from exc
    audit("user_created", actor, ip, f"{username} ({role})")
    return {"username": username, "temporary_password": temp}


def _temp_password() -> str:
    words = secrets.token_urlsafe(18)
    return f"{words[:6]}-{words[6:12]}-{words[12:18]}"


def list_users() -> list[dict]:
    now = time.time()
    with db() as c:
        rows = c.execute("""SELECT u.id, u.username, u.role, u.disabled, u.totp_enabled, u.must_change_password, u.created, u.last_login,
                                   u.locked_until, (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.stage = 'full') AS sessions
                            FROM users u ORDER BY u.username""").fetchall()
    return [{**dict(r), "locked": r["locked_until"] > now} for r in rows]


def update_user(user_id: int, changes: dict, actor_sess: dict, ip: str) -> dict:
    result: dict = {}
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            raise AuthError("User not found.", 404)
        self_edit = user["id"] == actor_sess["user_id"]
        admins = c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0").fetchone()[0]
        last_admin = user["role"] == "admin" and not user["disabled"] and admins <= 1
        if "role" in changes:
            if changes["role"] not in ("admin", "user"):
                raise AuthError("Role must be admin or user.")
            if last_admin and changes["role"] != "admin":
                raise AuthError("Can't demote the last admin.")
            c.execute("UPDATE users SET role = ? WHERE id = ?", (changes["role"], user_id))
        if "disabled" in changes:
            if changes["disabled"] and (self_edit or last_admin):
                raise AuthError("You can't disable yourself or the last admin.")
            c.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if changes["disabled"] else 0, user_id))
            if changes["disabled"]:
                c.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        if changes.get("unlock"):
            c.execute("UPDATE users SET failed_count = 0, locked_until = 0 WHERE id = ?", (user_id,))
        if changes.get("reset_password"):
            temp = _temp_password()
            c.execute("UPDATE users SET pw_hash = ?, must_change_password = 1, failed_count = 0, locked_until = 0 WHERE id = ?",
                      (hash_password(temp), user_id))
            c.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            result["temporary_password"] = temp
        if changes.get("reset_mfa"):
            c.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL, recovery_codes = '[]', totp_last_step = 0 WHERE id = ?", (user_id,))
            c.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        if changes.get("sign_out"):
            c.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    safe = {k: v for k, v in changes.items() if k in ("role", "disabled", "unlock", "reset_password", "reset_mfa", "sign_out")}
    audit("user_updated", actor_sess["username"], ip, f"{user['username']}: {json.dumps(safe)}")
    return result


def delete_user(user_id: int, actor_sess: dict, ip: str) -> None:
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            raise AuthError("User not found.", 404)
        if user["id"] == actor_sess["user_id"]:
            raise AuthError("You can't delete your own account.")
        admins = c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0").fetchone()[0]
        if user["role"] == "admin" and admins <= 1:
            raise AuthError("Can't delete the last admin.")
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    audit("user_deleted", actor_sess["username"], ip, user["username"])


def my_sessions(sess: dict) -> list[dict]:
    with db() as c:
        rows = c.execute("SELECT token_hash, created, last_seen, ip, user_agent FROM sessions WHERE user_id = ? AND stage = 'full' ORDER BY last_seen DESC",
                         (sess["user_id"],)).fetchall()
    return [{"id": r["token_hash"][:16], "current": r["token_hash"] == sess["token_hash"], "created": r["created"],
             "last_seen": r["last_seen"], "ip": r["ip"], "user_agent": r["user_agent"]} for r in rows]


def sign_out_others(sess: dict, ip: str) -> int:
    with db() as c:
        n = c.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (sess["user_id"], sess["token_hash"])).rowcount
    audit("signed_out_other_sessions", sess["username"], ip, f"{n} sessions")
    return n


def account_info(sess: dict) -> dict:
    with db() as c:
        u = c.execute("SELECT username, role, totp_enabled, recovery_codes, last_login, created FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
    return {"username": u["username"], "role": u["role"], "mfa_enabled": bool(u["totp_enabled"]),
            "recovery_codes_left": len(json.loads(u["recovery_codes"] or "[]")), "require_mfa": REQUIRE_MFA,
            "last_login": u["last_login"], "created": u["created"]}


def new_recovery_codes(sess: dict, password: str, ip: str) -> list[str]:
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
        if not verify_password(password or "", user["pw_hash"]):
            raise AuthError("Password is incorrect.", 401)
        if not user["totp_enabled"]:
            raise AuthError("Turn on MFA first.", 409)
        codes, hashes = _new_recovery_codes()
        c.execute("UPDATE users SET recovery_codes = ? WHERE id = ?", (json.dumps(hashes), user["id"]))
    audit("recovery_codes_regenerated", sess["username"], ip)
    return codes


def cookie_secure(request_scheme: str) -> bool:
    if COOKIE_SECURE == "true":
        return True
    if COOKIE_SECURE == "false":
        return False
    return request_scheme == "https"
