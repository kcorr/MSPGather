"""Offline tests for the hardening builders (MTA-STS & TLS-RPT Builder, Parked Domain
Lockdown). Pure functions only: no DNS or HTTP. Fictional domains (contoso, fabrikam)."""
from datetime import datetime, timezone

import pytest

from app.modules import hardbuild as hb

NOW = datetime(2026, 10, 26, 9, 30, 15, tzinfo=timezone.utc)
M365_MX = (("contoso-com.mail.protection.outlook.com", "Microsoft 365"),)


def _current(hosts=M365_MX, null_mx=False, mx_status="ok", sts_txt=(), policy=None, policy_findings=(), tlsrpt=(), resolves=False):
    """A hand-made input for mtasts_plan(), shaped like _sts_current() output."""
    return {
        "mx": {"status": mx_status, "null_mx": null_mx, "providers": [], "findings": [],
               "hosts": [{"host": h, "preference": 10, "provider": p, "cname": None, "resolves": True, "ip_literal": hb.is_ip(h)} for h, p in hosts]},
        "sts_txt": {"status": "ok" if sts_txt else "nxdomain", "records": list(sts_txt),
                    "sts": [r for r in sts_txt if r.replace(" ", "").lower().startswith("v=stsv1")]},
        "policy": {"url": "https://mta-sts.contoso.com/.well-known/mta-sts.txt", "fetched": policy is not None, "policy": policy,
                   "raw": None, "findings": list(policy_findings)},
        "tlsrpt": {"status": "ok" if tlsrpt else "nxdomain", "records": list(tlsrpt),
                   "rpt": [r for r in tlsrpt if r.replace(" ", "").lower().startswith("v=tlsrptv1")]},
        "policy_host": {"name": "mta-sts.contoso.com", "cname": None, "addresses": [], "resolves": resolves},
    }


def _records(plan):
    return {r["id"]: r for r in plan["generated"]["records"]}


# ------------------------------------------------------------------ MTA-STS inputs
def test_sts_inputs_validate_and_normalise():
    assert hb.sts_inputs(None, None, None) == (None, None, None)
    assert hb.sts_inputs(" Enforce ", "604800", "  ") == ("enforce", 604800, None)
    _, age, rua = hb.sts_inputs("testing", 0, "tls@contoso.com, MAILTO:ops@Contoso.COM https://reports.example.net/tlsrpt")
    assert age == 0
    assert rua == ["mailto:tls@contoso.com", "mailto:ops@contoso.com", "https://reports.example.net/tlsrpt"]


@pytest.mark.parametrize("mode,age,rua,message", [
    ("bogus", None, None, "Mode must be"),
    (None, "abc", None, "whole number"),
    (None, "-5", None, "whole number"),
    (None, "31557601", None, "at most 31557600"),
    (None, None, "http://reports.example.net/x", "must use https"),
    (None, None, "ftp://reports.example.net", "isn't a report destination"),
    (None, None, "not-an-address", "isn't a report destination"),
    (None, None, "mailto:bad@", "not a valid report email"),
    (None, None, "https://user:pw@reports.example.net/x", "user name or password"),
    (None, None, "https://192.0.2.10/report", "valid host name"),
    (None, None, "a@contoso.com b@contoso.com c@contoso.com d@contoso.com e@contoso.com f@contoso.com", "at most 5"),
])
def test_sts_inputs_reject_bad_input(mode, age, rua, message):
    with pytest.raises(ValueError, match=message):
        hb.sts_inputs(mode, age, rua)


def test_rua_can_never_break_the_txt_record():
    # A string is split on , ; and spaces; a list is taken as-is, so each item is checked whole.
    for bad in ("https://reports.example.net/a;b", 'mailto:"a"@contoso.com', "https://reports.example.net/a b"):
        with pytest.raises(ValueError):
            hb.sts_rua([bad])


# ------------------------------------------------------------- MTA-STS parsing
def test_parse_sts_record():
    assert hb.parse_sts_record("v=STSv1; id=20190225000000Z;")["id"] == "20190225000000Z"
    assert hb.parse_sts_record("v=STSv1;id=20210803T010101")["valid"]
    assert "letters and digits" in hb.parse_sts_record("v=STSv1; id=2024-01-01")["errors"][0]
    assert "case-sensitive" in hb.parse_sts_record("v=stsv1; id=1")["errors"][0]
    assert "missing" in hb.parse_sts_record("v=STSv1;")["errors"][0]
    assert "lowercase" in hb.parse_sts_record("v=STSv1; ID=123")["errors"][0]
    assert not hb.parse_sts_record("v=STSv1; id=" + "a" * 33)["valid"]
    assert not hb.parse_sts_record("v=STSv1; id = 123")["valid"]


def test_parse_tlsrpt_record():
    ok = hb.parse_tlsrpt_record("v=TLSRPTv1;rua=mailto:sts-reports@contoso.com,https://reports.example.net/tls")
    assert ok["valid"] and ok["rua"] == ["mailto:sts-reports@contoso.com", "https://reports.example.net/tls"]
    assert "missing" in hb.parse_tlsrpt_record("v=TLSRPTv1;")["errors"][0]
    assert "mailto: or https:" in hb.parse_tlsrpt_record("v=TLSRPTv1; rua=ftp://x.example.net")["errors"][0]
    assert not hb.parse_tlsrpt_record("v=tlsrptv1; rua=mailto:a@contoso.com")["valid"]


def test_mx_patterns_use_a_documented_wildcard_only_when_every_host_matches():
    m365 = hb.sts_mx_patterns(["contoso-com.mail.protection.outlook.com"])
    assert m365["patterns"] == ["*.mail.protection.outlook.com"] and m365["wildcard"]["provider"] == "Microsoft 365"
    mixed = hb.sts_mx_patterns(["contoso-com.mail.protection.outlook.com", "backup.contoso.com"])
    assert mixed["patterns"] == ["contoso-com.mail.protection.outlook.com", "backup.contoso.com"] and mixed["wildcard"] is None
    assert hb.sts_mx_patterns(["smtp.google.com"])["patterns"] == ["smtp.google.com"]
    # "*." matches exactly one label (RFC 8461 section 4.1).
    assert hb.sts_mx_patterns(["a.b.mail.protection.outlook.com"])["wildcard"] is None


def test_policy_text_id_and_age():
    assert hb.build_sts_policy("testing", 86400, ["*.mail.protection.outlook.com"]) == \
        "version: STSv1\r\nmode: testing\r\nmx: *.mail.protection.outlook.com\r\nmax_age: 86400\r\n"
    assert hb.sts_id(NOW) == "20261026093015"
    assert [hb._age_text(s) for s in (604800, 86400, 31557600, 3600, 0)] == ["7 days", "1 day", "about 1 year", "1 hour", "0 seconds"]


def test_policy_review_coverage_and_max_age():
    hosts = ["contoso-com.mail.protection.outlook.com", "mx2.contoso.com"]
    r = hb.sts_policy_review({"version": "STSv1", "mode": "enforce", "mx": ["*.mail.protection.outlook.com", "mail.fabrikam.com"],
                              "max_age": "3600"}, hosts)
    assert r["uncovered"] == ["mx2.contoso.com"] and r["stale"] == ["mail.fabrikam.com"] and r["max_age"] == 3600
    found = [(f["severity"], f["title"]) for f in r["findings"]]
    assert any(s == "critical" and "doesn't cover MX host mx2.contoso.com" in t for s, t in found)
    assert any(s == "warning" and "too short for enforce" in t for s, t in found)
    assert any(s == "info" and "mail.fabrikam.com" in t for s, t in found)
    testing = hb.sts_policy_review({"version": "STSv1", "mode": "testing", "mx": ["*.mail.protection.outlook.com"], "max_age": "86400"}, hosts)
    assert [f["severity"] for f in testing["findings"]] == ["warning"]
    too_long = hb.sts_policy_review({"version": "STSv1", "mode": "enforce", "mx": ["mx2.contoso.com"], "max_age": "99999999"}, ["mx2.contoso.com"])
    assert too_long["findings"][0]["severity"] == "warning" and "maximum" in too_long["findings"][0]["title"]
    no_age = hb.sts_policy_review({"version": "STSv1", "mode": "testing", "mx": ["mx2.contoso.com"]}, ["mx2.contoso.com"])
    assert no_age["findings"][0]["severity"] == "critical"


# ---------------------------------------------------------------- MTA-STS plans
def test_plan_new_m365_domain_starts_in_testing():
    p = hb.mtasts_plan("contoso.com", _current(), now=NOW)
    assert p["stage"] == "off" and p["severity"] == "info" and "doesn't use MTA-STS yet" in p["headline"]
    assert p["inputs"]["mode"] == "testing" and p["inputs"]["max_age"] == 86400 and p["inputs"]["rua_placeholder"]
    g = p["generated"]
    assert g["policy"]["text"] == "version: STSv1\r\nmode: testing\r\nmx: *.mail.protection.outlook.com\r\nmax_age: 86400\r\n"
    rec = _records(p)
    assert rec["sts"]["value"] == "v=STSv1; id=20261026093015" and rec["sts"]["status"] == "missing"
    assert rec["sts"]["bind"] == '_mta-sts.contoso.com. 3600 IN TXT "v=STSv1; id=20261026093015"'
    assert rec["tlsrpt"]["value"] == "v=TLSRPTv1; rua=mailto:tls-reports@contoso.com" and rec["tlsrpt"]["fqdn"] == "_smtp._tls.contoso.com"
    assert g["hosting"]["url"] == "https://mta-sts.contoso.com/.well-known/mta-sts.txt"
    assert [s["id"] for s in p["rollout"] if s["current"]] == ["tlsrpt"]


def test_plan_unchanged_policy_keeps_the_id():
    cur = _current(sts_txt=["v=STSv1; id=20190225000000Z;"], tlsrpt=["v=TLSRPTv1;rua=mailto:tls@contoso.com"], resolves=True,
                   policy={"version": "STSv1", "mode": "enforce", "mx": ["*.mail.protection.outlook.com"], "max_age": "604800"})
    p = hb.mtasts_plan("contoso.com", cur, now=NOW)
    assert p["severity"] == "ok" and p["headline"].startswith("No changes needed")
    rec = _records(p)
    assert rec["sts"]["status"] == "correct" and rec["sts"]["value"] == "v=STSv1; id=20190225000000Z;"
    assert rec["tlsrpt"]["status"] == "correct" and p["generated"]["policy"]["status"] == "correct"


def test_plan_enforce_policy_missing_an_mx_host_is_critical():
    cur = _current(hosts=[("mx1.contoso.com", None), ("mx2.contoso.com", None)], sts_txt=["v=STSv1; id=1"],
                   tlsrpt=["v=TLSRPTv1; rua=mailto:tls@contoso.com"],
                   policy={"version": "STSv1", "mode": "enforce", "mx": ["mx1.contoso.com"], "max_age": "604800"})
    p = hb.mtasts_plan("contoso.com", cur, now=NOW)
    assert p["severity"] == "critical" and "mx2.contoso.com" in p["headline"]
    g = p["generated"]
    assert g["policy"]["mx"] == ["mx1.contoso.com", "mx2.contoso.com"] and g["policy"]["added"] == ["mx2.contoso.com"]
    assert _records(p)["sts"]["status"] == "update" and _records(p)["sts"]["value"] == "v=STSv1; id=20261026093015"


def test_plan_switch_testing_to_enforce():
    cur = _current(sts_txt=["v=STSv1; id=20260101000000"], tlsrpt=["v=TLSRPTv1; rua=mailto:tls@contoso.com"],
                   policy={"version": "STSv1", "mode": "testing", "mx": ["*.mail.protection.outlook.com"], "max_age": "86400"})
    p = hb.mtasts_plan("contoso.com", cur, mode="enforce", now=NOW)
    assert p["inputs"]["max_age"] == 604800 and p["severity"] == "ok"
    assert "mode: enforce\r\n" in p["generated"]["policy"]["text"] and "max_age: 604800\r\n" in p["generated"]["policy"]["text"]
    assert p["headline"].startswith("Ready to publish: switch from testing to enforce")
    assert _records(p)["tlsrpt"]["status"] == "correct"


def test_plan_straight_to_enforce_with_short_max_age_warns():
    p = hb.mtasts_plan("contoso.com", _current(), mode="enforce", max_age=3600, rua=["mailto:tls@contoso.com"], now=NOW)
    warnings = [f["title"] for f in p["generated"]["findings"] if f["severity"] == "warning"]
    assert any("short for enforce" in t for t in warnings) and any("straight to enforce" in t for t in warnings)
    assert p["severity"] == "warning" and not p["inputs"]["rua_placeholder"]


def test_plan_weakening_enforce_to_testing_warns():
    cur = _current(sts_txt=["v=STSv1; id=1"], tlsrpt=["v=TLSRPTv1; rua=mailto:tls@contoso.com"],
                   policy={"version": "STSv1", "mode": "enforce", "mx": ["*.mail.protection.outlook.com"], "max_age": "604800"})
    p = hb.mtasts_plan("contoso.com", cur, mode="testing", now=NOW)
    assert p["severity"] == "warning" and "weakens protection" in p["headline"]


def test_plan_flags_the_mx_problems_mta_sts_cares_about():
    cur = _current(hosts=[("mail.contoso.com", None), ("192.0.2.25", None)])
    cur["mx"]["hosts"][0]["cname"] = "contoso.mail.example.net"
    p = hb.mtasts_plan("contoso.com", cur, mode="enforce", now=NOW)
    found = {f["title"]: f["severity"] for f in p["generated"]["findings"]}
    assert found["MX record points to an IP address: 192.0.2.25"] == "critical"
    assert found["MX host mail.contoso.com is an alias (CNAME) for contoso.mail.example.net"] == "warning"
    assert p["generated"]["policy"]["mx"] == ["mail.contoso.com"] and p["severity"] == "critical"
    assert p["headline"].startswith("Don't publish yet")


def test_plan_reuses_the_published_tlsrpt_address():
    p = hb.mtasts_plan("contoso.com", _current(tlsrpt=["v=TLSRPTv1; rua=mailto:tls@contoso.com"]), now=NOW)
    assert p["inputs"]["rua"] == ["mailto:tls@contoso.com"] and not p["inputs"]["rua_placeholder"]
    assert _records(p)["tlsrpt"]["status"] == "correct" and [s["id"] for s in p["rollout"] if s["current"]] == ["testing"]


def test_plan_without_mx_hosts_is_not_buildable():
    null = hb.mtasts_plan("contoso.net", _current(hosts=[], null_mx=True))
    assert not null["generated"]["buildable"] and "null MX" in null["headline"] and null["severity"] == "info"
    none = hb.mtasts_plan("contoso.net", _current(hosts=[]))
    assert not none["generated"]["buildable"] and none["severity"] == "warning"
    failed = hb.mtasts_plan("contoso.net", _current(hosts=[], mx_status="timeout"))
    assert failed["severity"] == "critical"


def test_plan_invalid_or_duplicate_txt_is_critical():
    bad = hb.mtasts_plan("contoso.com", _current(sts_txt=["v=STSv1; id=2024-01-01"]), now=NOW)
    assert bad["severity"] == "critical" and bad["stage"] == "broken" and _records(bad)["sts"]["status"] == "conflicting"
    dup = hb.mtasts_plan("contoso.com", _current(sts_txt=["v=STSv1; id=1", "v=STSv1; id=2"]), now=NOW)
    assert dup["severity"] == "critical" and "2 _mta-sts TXT records" in dup["headline"]


def test_plan_unfetchable_policy_mentions_the_missing_host():
    fetch_failed = {"severity": "critical", "area": "MTA-STS", "title": "MTA-STS policy cannot be fetched",
                    "detail": "https://mta-sts.contoso.com/.well-known/mta-sts.txt: connection or TLS failure."}
    p = hb.mtasts_plan("contoso.com", _current(sts_txt=["v=STSv1; id=1"], policy_findings=[fetch_failed]), now=NOW)
    assert p["stage"] == "broken" and p["severity"] == "critical" and "doesn't resolve in DNS" in p["subline"]
    assert p["generated"]["policy"]["status"] == "missing"


def test_plan_mode_none_gives_the_removal_steps():
    cur = _current(sts_txt=["v=STSv1; id=1"], tlsrpt=["v=TLSRPTv1; rua=mailto:tls@contoso.com"],
                   policy={"version": "STSv1", "mode": "enforce", "mx": ["*.mail.protection.outlook.com"], "max_age": "604800"})
    p = hb.mtasts_plan("contoso.com", cur, mode="none", now=NOW)
    assert "mode: none\r\n" in p["generated"]["policy"]["text"] and p["inputs"]["max_age"] == 86400
    assert [s["id"] for s in p["rollout"]] == ["none", "wait", "remove"] and "604800 seconds" in p["rollout"][1]["detail"]


def test_sts_current_shapes_the_lookups():
    mx = {"status": "ok", "null_mx": False, "providers": ["Microsoft 365"], "findings": [{"severity": "ok", "area": "MX", "title": "fine", "detail": ""}],
          "records": [{"host": "contoso-com.mail.protection.outlook.com", "preference": 0, "provider": "Microsoft 365", "provider_kind": "mailbox",
                       "cname": None, "ips": [{"ip": "192.0.2.1"}]}]}
    sts = {"record": None, "policy": None, "policy_raw": None, "findings": [{"severity": "info", "area": "MTA-STS", "title": "MTA-STS not configured", "detail": ""}]}
    cur = hb._sts_current("contoso.com", mx, sts, (["v=spf1 -all"], {"status": "ok"}), ([], {"status": "nxdomain"}),
                          {"name": "mta-sts.contoso.com", "resolves": False})
    assert cur["mx"]["hosts"][0]["resolves"] and cur["mx"]["findings"] == [] and cur["sts_txt"]["sts"] == []
    assert not cur["policy"]["fetched"] and cur["policy"]["findings"] == []


# ------------------------------------------------------------------- Lockdown
LOCKED = dict(mx=hb.lock_assess_mx("ok", [(0, ".")]), spf=hb.lock_assess_spf("ok", ["v=spf1 -all"]),
              dmarc=hb.lock_assess_dmarc("ok", ["v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"]), dkim=hb.lock_assess_dkim("ok", ["v=DKIM1; p="]))


def test_lock_records_and_zone_lines():
    rec = {r["id"]: r for r in hb.lock_records("contoso.net", ["mailto:dmarc@contoso.com"])}
    assert rec["mx"]["bind"] == "contoso.net. 3600 IN MX 0 ." and (rec["mx"]["priority"], rec["mx"]["value"]) == (0, ".")
    assert rec["spf"]["bind"] == 'contoso.net. 3600 IN TXT "v=spf1 -all"'
    assert rec["dmarc"]["fqdn"] == "_dmarc.contoso.net"
    assert rec["dmarc"]["value"] == "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@contoso.com"
    assert rec["dkim"]["fqdn"] == "*._domainkey.contoso.net" and rec["dkim"]["value"] == "v=DKIM1; p=" and rec["dkim"]["optional"]
    assert hb.lock_dmarc_value() == "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"
    assert hb._bind_txt("_dmarc.contoso.net", "x" * 300) == '_dmarc.contoso.net. 3600 IN TXT "' + "x" * 255 + '" "' + "x" * 45 + '"'


def test_lock_assess_mx():
    assert hb.lock_assess_mx("ok", [(0, ".")])["status"] == "correct"
    missing = hb.lock_assess_mx("noanswer", [], ["192.0.2.10"])
    assert missing["status"] == "missing" and "192.0.2.10" in missing["note"] and not missing["receives"]
    real = hb.lock_assess_mx("ok", [(10, "contoso-net.mail.protection.outlook.com")])
    assert real["status"] == "conflicting" and real["receives"] and "Microsoft 365" in real["note"]
    assert hb.lock_assess_mx("timeout", [])["status"] == "unknown"


@pytest.mark.parametrize("records,status,sends", [
    (["v=spf1 -all"], "correct", False),
    (["v=spf1  -ALL"], "correct", False),
    (["v=spf1 ~all"], "conflicting", False),
    (["v=spf1 include:spf.protection.outlook.com -all"], "conflicting", True),
    (["v=spf1 ip4:192.0.2.0/24 -all"], "conflicting", True),
    (["v=spf1 redirect=_spf.contoso.com"], "conflicting", True),
    (["v=spf1 -all", "v=spf1 ~all"], "conflicting", False),
    ([], "missing", False),
])
def test_lock_assess_spf(records, status, sends):
    r = hb.lock_assess_spf("ok", records)
    assert (r["status"], r["sends"]) == (status, sends)


def test_lock_assess_dmarc():
    assert hb.lock_assess_dmarc("ok", ["v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"]) == {"status": "correct", "current": ["v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"],
                                                                                         "problems": [], "note": None}
    relaxed = hb.lock_assess_dmarc("ok", ["v=DMARC1; p=reject"], rua=["mailto:dmarc@contoso.com"])
    assert relaxed["status"] == "correct" and "optional" in relaxed["note"]
    for rec in ("v=DMARC1; p=none; rua=mailto:d@contoso.com", "v=DMARC1; p=reject; sp=none", "v=DMARC1; p=reject; pct=50", "v=DMARC1; p=reject; t=y"):
        assert hb.lock_assess_dmarc("ok", [rec])["status"] == "conflicting", rec
    assert hb.lock_assess_dmarc("ok", ["v=DMARC1; p=reject", "v=DMARC1; p=none"])["problems"] == ["multiple records"]
    inherited = hb.lock_assess_dmarc("nxdomain", [], ("contoso.com", ["v=DMARC1; p=none; sp=reject"]))
    assert inherited["status"] == "correct" and "contoso.com" in inherited["note"]
    assert hb.lock_assess_dmarc("nxdomain", [], ("contoso.com", ["v=DMARC1; p=none"]))["status"] == "missing"
    assert hb.lock_assess_dmarc("timeout", [])["status"] == "unknown"


def test_lock_assess_dkim():
    assert hb.lock_assess_dkim("ok", ["v=DKIM1; p="])["status"] == "correct"
    assert hb.lock_assess_dkim("nxdomain", [])["status"] == "missing"
    assert hb.lock_assess_dkim("ok", ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"])["status"] == "conflicting"
    assert hb.lock_assess_dkim("ok", ["v=spf1 -all"])["status"] == "conflicting"


def test_lock_plan_statuses_and_actions():
    locked = hb.lock_plan("contoso.net", **LOCKED)
    assert (locked["status"], locked["severity"], locked["todo"]) == ("locked", "ok", [])
    partial = hb.lock_plan("contoso.net", **{**LOCKED, "spf": hb.lock_assess_spf("noanswer", []), "dkim": hb.lock_assess_dkim("nxdomain", [])})
    assert partial["status"] == "partial" and partial["todo"] == ["spf"] and "1 more record (SPF)" in partial["headline"]
    assert {r["id"]: r["action"] for r in partial["records"]} == {"mx": "none", "spf": "add", "dmarc": "none", "dkim": "add"}
    nothing = hb.lock_plan("contoso.net", hb.lock_assess_mx("noanswer", []), hb.lock_assess_spf("noanswer", []),
                           hb.lock_assess_dmarc("nxdomain", []), hb.lock_assess_dkim("nxdomain", []))
    assert nothing["status"] == "open" and nothing["todo"] == ["mx", "spf", "dmarc"]
    receives = hb.lock_plan("contoso.net", **{**LOCKED, "mx": hb.lock_assess_mx("ok", [(10, "mail.contoso.net")])})
    assert receives["status"] == "receives_mail" and receives["severity"] == "critical" and not receives["safe"]
    assert {r["action"] for r in receives["records"]} <= {"none", "hold"}
    sends = hb.lock_plan("contoso.net", **{**LOCKED, "mx": hb.lock_assess_mx("noanswer", []),
                                          "spf": hb.lock_assess_spf("ok", ["v=spf1 include:sendgrid.net -all"])})
    assert sends["status"] == "sends_mail" and "include:sendgrid.net" in sends["headline"]
    # The advice must not tell the engineer to publish a null MX on a domain that still sends.
    assert not any("MX 0 ." in f["detail"] for f in sends["findings"])
    assert any("MX 0 ." in f["detail"] for f in nothing["findings"])
    unknown = hb.lock_plan("contoso.net", **{**LOCKED, "spf": hb.lock_assess_spf("timeout", [])})
    assert unknown["status"] == "unknown" and not unknown["safe"]


def test_lock_bulk_summary():
    rows = [hb._lock_row(hb.lock_plan(d, **LOCKED)) for d in ("contoso.net", "contoso.org")]
    rows.append(hb._lock_row(hb.lock_plan("fabrikam.net", **{**LOCKED, "mx": hb.lock_assess_mx("ok", [(10, "mail.fabrikam.net")])})))
    rows.append(hb._lock_row({"domain": "bad name", "status": "invalid", "error": "not a domain"}))
    s = hb.lock_bulk_summary(rows)
    assert s["severity"] == "critical" and s["counts"] == {"locked": 2, "receives_mail": 1, "invalid": 1}
    assert s["headline"] == "1 receives mail and 2 are already locked down"
    all_locked = hb.lock_bulk_summary(rows[:2])
    assert (all_locked["severity"], all_locked["headline"]) == ("ok", "All 2 domains are locked down")


def test_lock_bulk_rejects_bad_input_before_any_lookup():
    with pytest.raises(ValueError, match="at least one domain"):
        hb.lock_bulk([" , "])
    with pytest.raises(ValueError, match="Up to 20 domains"):
        hb.lock_bulk([f"d{i}.contoso.net" for i in range(21)])
    with pytest.raises(ValueError, match="not a valid report email"):
        hb.lock_bulk(["contoso.net"], "not-an-address")
    with pytest.raises(ValueError, match="at most 5"):
        hb.lock_rua(",".join(f"d{i}@contoso.com" for i in range(6)))
    only_invalid = hb.lock_bulk(["not_a_domain!"])  # nothing valid, so nothing is looked up
    assert [r["status"] for r in only_invalid["rows"]] == ["invalid"]


def test_routes_are_registered():
    routes = {(r.path, tuple(sorted(r.methods))) for r in hb.router.routes}
    assert {("/api/builder/mtasts/{domain:path}", ("GET",)), ("/api/builder/parked/{domain:path}", ("GET",)),
            ("/api/builder/parked", ("POST",))} <= routes
