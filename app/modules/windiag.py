"""Windows diagnostics: error code lookup and event log analysis.

Routes:
  GET  /api/win/code?q=...      decode / look up an error code (or search by name/keyword)
  POST /api/win/events {raw}    parse pasted events (text, Format-List, JSON, CSV, XML) and analyze them
"""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from ..core.http import run
from . import wincodes as kb

router = APIRouter()


class RawText(BaseModel):
    raw: str = Field(..., max_length=8_000_000)


@router.get("/api/win/code")
def win_code(q: str = Query(..., max_length=4000)):
    return run(lookup_code, q)


@router.post("/api/win/events")
def win_events(body: RawText):
    return run(analyze_events, body.raw)


# =============================================================== CODE LOOKUP
KIND_LABEL = {"win32": "Win32 error", "hresult": "HRESULT", "ntstatus": "NTSTATUS", "kerberos": "Kerberos error", "bugcheck": "Bug check"}


def _hex(v: int, width: int = 8) -> str:
    return f"0x{v:0{width}X}"


def _signed(v: int) -> int:
    return v - 0x100000000 if v & 0x80000000 else v


def _first_sentence(text: str) -> str:
    m = re.match(r"(.+?[.!?])(\s|$)", text or "")
    return m.group(1) if m else (text or "")


def _build_name_index() -> dict[str, tuple[str, int]]:
    idx: dict[str, tuple[str, int]] = {}
    for kind, table in (("win32", kb.WIN32), ("hresult", kb.HRESULT), ("ntstatus", kb.NTSTATUS), ("kerberos", kb.KERBEROS), ("bugcheck", kb.BUGCHECK)):
        for code, e in table.items():
            name = e.get("name") or ""
            for part in re.split(r"\s*/\s*", name):
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*_[A-Za-z0-9_]+|[A-Z][A-Za-z]+_[A-Za-z]+", part):
                    key = part.upper()
                    # Win32-mapped HRESULT context entries share the Win32 name; keep the Win32 one.
                    if key in idx and kind == "hresult" and (code >> 16) == 0x8007:
                        continue
                    idx.setdefault(key, (kind, code))
    for alias, v in kb.HRESULT_ALIASES.items():
        idx[alias] = ("hresult", v)
    return idx


NAME_INDEX = _build_name_index()

_TOKEN_RE = re.compile(r"(?<![\w$])(0x[0-9a-fA-F]{1,16}|-\d{1,10}|[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+|[0-9a-fA-F]{8}|\d{1,10})(?![\w])")
_CTX_KERB = re.compile(r"kerberos|\bkdc\b|\bkrb|4771|4768|4769|failure code|result code|pre-?auth", re.I)
_CTX_BUG = re.compile(r"bug ?check|bsod|blue ?screen|\bstop\b|crash|minidump|memory\.dmp|1001", re.I)


def _parse_token(tok: str):
    """Return (value, form) for a numeric token, ('name', KEY) for a known name, or None."""
    t = tok.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{1,16}", t, re.I):
        digits = t[2:]
        v = int(digits, 16)
        if len(digits) > 8:
            if v >> 32 in (0, 0xFFFFFFFF):
                v &= 0xFFFFFFFF  # sign-extended 64-bit form
            else:
                return None
        return v, "hex"
    if re.fullmatch(r"-\d{1,10}", t):
        v = int(t)
        if v < -0x80000000:
            return None
        return v & 0xFFFFFFFF, "negative"
    if re.fullmatch(r"[0-9a-fA-F]{8}", t) and not re.fullmatch(r"\d{8}", t) or re.fullmatch(r"(8|C|c)\d{7}", t):
        return int(t, 16), "barehex"
    if re.fullmatch(r"\d{1,10}", t):
        v = int(t)
        if v > 0xFFFFFFFF:
            return None
        return v, "decimal"
    key = t.upper()
    if key in NAME_INDEX:
        return ("name", key)
    return None


def _extract(q: str):
    """Find the codes in a query. Returns a list of (raw_token, parsed)."""
    whole = _parse_token(q.strip().strip("\"'`.,;:()[]"))
    if whole:
        return [(q.strip().strip("\"'`.,;:()[]"), whole)]
    strong, weak = [], []
    for m in _TOKEN_RE.finditer(q):
        tok = m.group(1)
        p = _parse_token(tok)
        if not p:
            continue
        if p[0] == "name" or p[1] in ("hex", "negative"):
            strong.append((tok, p))
        elif p[1] == "barehex" and tok[0] in "8Cc":
            strong.append((tok, p))
        elif p[1] == "decimal":
            # Plain numbers in prose are only codes when introduced as such.
            before = q[max(0, m.start() - 24):m.start()].lower()
            if re.search(r"(error|code|status|err|result|exit)\s*(code)?\s*[:=#]?\s*$", before):
                weak.append((tok, p))
    seen, out = set(), []
    for tok, p in strong + weak:
        if p in seen:
            continue
        seen.add(p)
        out.append((tok, p))
    return out


def _entry_out(kind: str, code: int, e: dict, extra_title: str | None = None) -> dict:
    if kind == "win32":
        disp = f"{code} (0x{code:X})"
        forms = {"hresult": _hex(0x80070000 | code) if 0 < code <= 0xFFFF else None}
    elif kind in ("kerberos", "bugcheck") and code <= 0xFFFF:
        disp = f"0x{code:X}" if kind == "kerberos" else _hex(code)
        forms = {}
    else:
        disp = _hex(code)
        forms = {}
    sev = e.get("severity") or ("critical" if kind == "bugcheck" else "warning")
    nm = e.get("name") or ""
    if not extra_title:
        if kind == "ntstatus" and "exception" in nm:
            extra_title = "Exception code"
        elif nm.startswith("Windows Setup"):
            extra_title, nm = "Windows Setup code", None
        elif nm.startswith("Activation"):
            extra_title, nm = "Activation (Software Licensing) code", None
        elif nm.startswith("ERROR_ADAL"):
            extra_title = "Entra auth library code"
        elif kind == "hresult" and (code >> 16) == 0x8018:
            extra_title = "MDM enrollment code"
        elif kind == "hresult" and (code >> 16) == 0x801C:
            extra_title = "Device registration code"
        elif kind == "hresult" and (code >> 16) == 0x8024:
            extra_title = "Windows Update code"
    if nm is None:
        e = dict(e, name=None)
    return {"kind": kind, "kind_label": extra_title or KIND_LABEL[kind], "code": code, "display": disp, "name": e.get("name"),
            "meaning": e.get("meaning") or "", "causes": e.get("causes", []), "fixes": e.get("fixes", []), "commands": e.get("commands", []),
            "related": e.get("related", []), "notes": e.get("notes", []), "severity": sev, "forms": forms}


def _merge(base: dict, ctx: dict) -> dict:
    """Merge an HRESULT context entry into a Win32 entry for 0x8007xxxx values."""
    out = dict(base)
    for k in ("causes", "fixes", "commands", "notes", "related"):
        out[k] = list(dict.fromkeys(list(base.get(k, [])) + list(ctx.get(k, []))))
    if ctx.get("meaning"):
        out["meaning"] = ctx["meaning"]
    return out


def _interpretations(v: int, form: str, q: str) -> list[dict]:
    res: list[dict] = []
    kerb_ctx, bug_ctx = bool(_CTX_KERB.search(q)), bool(_CTX_BUG.search(q))

    if v <= 0xFFFF:
        cand = []
        if v in kb.WIN32:
            cand.append(("win32", _entry_out("win32", v, kb.WIN32[v])))
        if v in kb.KERBEROS:
            cand.append(("kerberos", _entry_out("kerberos", v, kb.KERBEROS[v])))
        if v in kb.BUGCHECK:
            cand.append(("bugcheck", _entry_out("bugcheck", v, kb.BUGCHECK[v])))
        if form in ("hex", "barehex"):
            order = ["bugcheck", "kerberos", "win32"]
        else:
            order = ["win32", "kerberos", "bugcheck"]
        if v == 0:
            order = ["win32", "kerberos", "bugcheck"]
        elif kerb_ctx:
            order = ["kerberos"] + [o for o in order if o != "kerberos"]
        if bug_ctx and v:
            order = ["bugcheck"] + [o for o in order if o != "bugcheck"]
        cand.sort(key=lambda c: order.index(c[0]))
        res = [c[1] for c in cand]
        if v == 0 and not res:
            res.append(_entry_out("hresult", 0, kb.HRESULT[0]))
        return res

    # 32-bit values
    if (v >> 16) == 0x8007:
        w = v & 0xFFFF
        if w in kb.WIN32:
            base = _entry_out("win32", w, kb.WIN32[w], "HRESULT_FROM_WIN32")
            base["display"] = _hex(v)
            base["win32"] = w
            if v in kb.HRESULT:
                base = _merge(base, kb.HRESULT[v])
                if kb.HRESULT[v].get("name") and kb.HRESULT[v]["name"].startswith("E_"):
                    base["alias"] = kb.HRESULT[v]["name"]
            res.append(base)
        elif v in kb.HRESULT:
            res.append(_entry_out("hresult", v, kb.HRESULT[v]))
    elif v in kb.HRESULT:
        res.append(_entry_out("hresult", v, kb.HRESULT[v]))
    if (v >> 16) == 0xC007 and (v & 0xFFFF) in kb.WIN32:
        w = v & 0xFFFF
        e = _entry_out("win32", w, kb.WIN32[w], "NTSTATUS wrapping a Win32 error")
        e["display"], e["win32"] = _hex(v), w
        res.append(e)
    if v in kb.NTSTATUS:
        res.append(_entry_out("ntstatus", v, kb.NTSTATUS[v]))
    if (v & 0xF0000000) == 0x90000000 or (v & 0xF0000000) == 0xD0000000:
        nt = v & ~0x10000000
        if nt in kb.NTSTATUS:
            e = _entry_out("ntstatus", nt, kb.NTSTATUS[nt], "HRESULT_FROM_NT (NTSTATUS wrapped as HRESULT)")
            e["display"] = _hex(v)
            res.append(e)
    if v in kb.BUGCHECK:
        res.append(_entry_out("bugcheck", v, kb.BUGCHECK[v]))
    if (v & 0xF0000000) == 0x10000000 and (v & 0x0FFFFFFF) in kb.BUGCHECK:
        e = _entry_out("bugcheck", v & 0x0FFFFFFF, kb.BUGCHECK[v & 0x0FFFFFFF], "Bug check (_M variant)")
        e["display"] = _hex(v)
        e["notes"] = ["The 0x10000000 bit marks the '_M' variant of the same bug check; the meaning is identical."] + e["notes"]
        res.append(e)
    if bug_ctx:
        res.sort(key=lambda r: r["kind"] != "bugcheck")
    return res


_NT_PREFIX_USAGE = {0xC190: "used by Windows Setup (upgrades)", 0xC004: "used by Software Licensing (activation)",
                    0xCAA8: "used by the Entra authentication library", 0xCAA2: "used by the Entra authentication library", 0xCAA9: "used by the Entra authentication library"}


def _structure(v: int, form: str) -> dict:
    forms = [["Hex", _hex(v)], ["Unsigned decimal", str(v)]]
    if v & 0x80000000:
        forms.append(["Signed decimal", str(_signed(v))])
    fields: list[list[str]] = []
    notes: list[str] = []
    layout = None
    if v <= 0xFFFF:
        layout = "Small value"
        notes.append(f"A value this small is usually a Win32 error code (decimal {v}). As an HRESULT it would appear as {_hex(0x80070000 | v)}." if v else
                     "Zero means success in every scheme (ERROR_SUCCESS / S_OK / STATUS_SUCCESS).")
        if form in ("hex", "barehex"):
            notes.append("Written in hex it may also be a bug check code (from a blue screen) or a Kerberos failure code (from events 4768/4769/4771).")
        return {"forms": forms, "layout": layout, "fields": fields, "notes": notes}

    top = v >> 28
    sev_bit = (v >> 31) & 1
    cust = (v >> 29) & 1
    nbit = (v >> 28) & 1
    fac = (v >> 16) & 0x7FF
    low = v & 0xFFFF
    # Bit 30 set (top nibble 4-7 or C-F) is NTSTATUS-style severity; HRESULTs never use it
    # except via HRESULT_FROM_NT (bit 28 set on top of an NTSTATUS).
    if top in (0x4, 0x6, 0x7, 0xC, 0xE, 0xF):
        # NTSTATUS layout
        layout = "NTSTATUS-style"
        sev = (v >> 30) & 3
        ntfac = (v >> 16) & 0xFFF
        sev_name = ["Success", "Informational", "Warning", "Error"][sev]
        fields = [["Severity (bits 30-31)", f"{sev} = {sev_name}", ""],
                  ["Customer bit (29)", str(cust), "1 = defined by a vendor/application, not by Microsoft" if cust else "0 = Microsoft-defined"],
                  ["Facility (bits 16-27)", f"0x{ntfac:X} ({ntfac})", _NT_PREFIX_USAGE.get(v >> 16) or (kb.NT_FACILITIES.get(ntfac, "not a facility we can name") if not cust else "vendor-defined")],
                  ["Code (bits 0-15)", f"0x{low:X} ({low})", ""]]
        if cust and sev == 3:
            notes.append("Severity 'Error' with the customer bit set: this is an application-defined code (for example an exception code such as 0xE0434352 for .NET).")
        if ntfac == 7 and not cust:
            notes.append(f"Facility NTWIN32: the low 16 bits are Win32 error {low}.")
        if top == 0xC and (v >> 16) not in (0xC190, 0xC004, 0xCAA8, 0xCAA2, 0xCAA9):
            notes.append("Codes starting with 0xC are typically NTSTATUS errors from the kernel, drivers or LSA (logon), e.g. the Status / Sub Status in event 4625.")
        if (v >> 16) == 0xC190:
            notes.append("0xC19xxxxx codes come from Windows Setup (feature updates / upgrades).")
        if (v >> 16) == 0xC004:
            notes.append("0xC004xxxx codes come from the Software Licensing (activation) service.")
        if (v >> 16) == 0xCAA8 or (v >> 16) == 0xCAA2 or (v >> 16) == 0xCAA9:
            notes.append("0xCAAxxxxx codes come from the Entra (ADAL/token broker) authentication library used by device registration and SSO.")
        return {"forms": forms, "layout": layout, "fields": fields, "notes": notes}

    layout = "HRESULT"
    if nbit and top in (0x5, 0x9, 0xD):
        nt = v & ~0x10000000
        notes.append(f"The NT bit is set: this is HRESULT_FROM_NT, an NTSTATUS ({_hex(nt)}) carried as an HRESULT.")
    if top in (0x1, 0x3) and (v & 0x0FFFFFFF) <= 0xFFFF:
        notes.append(f"If this came from a blue screen, 0x1xxxxxxx is the '_M' variant of bug check {_hex(v & 0x0FFFFFFF)} (same meaning).")
    fname = kb.FACILITIES.get(fac) if not cust else None
    usage = kb.FACILITY_USAGE.get(fac)
    fields = [["Severity (bit 31)", f"{sev_bit} = {'Failure' if sev_bit else 'Success'}", ""],
              ["Customer bit (29)", str(cust), "1 = vendor-defined" if cust else "0 = Microsoft-defined"],
              ["NT bit (28)", str(nbit), "1 = an NTSTATUS mapped into an HRESULT (HRESULT_FROM_NT)" if nbit and sev_bit else ""],
              ["Facility (bits 16-26)", f"{fac} (0x{fac:X})", fname or usage or "not a facility we can name"],
              ["Code (bits 0-15)", f"{low} (0x{low:X})", ""]]
    if fac == 7 and not cust:
        notes.append(f"HRESULT_FROM_WIN32: the low 16 bits are Win32 error {low}." + ("" if low in kb.WIN32 else " That Win32 error isn't in the knowledge base."))
    if fac == 25 and not cust:
        notes.append(f"Facility HTTP: the low 16 bits are the HTTP status code {low}.")
    if fac == 36 and not cust:
        sub = (v >> 12) & 0xF
        rng = kb.WU_RANGES.get(sub)
        notes.append(f"Windows Update agent error (0x8024xxxx)" + (f", in the {rng} range (0x8024{sub:X}xxx)." if rng else "."))
        notes.append("Run Get-WindowsUpdateLog and search WindowsUpdate.log for the code to see which step failed.")
    if fac == 15 and (low >> 8) == 0x08 or (fac == 15 and (low >> 8) == 0x09):
        notes.append("0x800F08xx / 0x800F09xx codes come from component-based servicing (CBS/DISM). Details are in C:\\Windows\\Logs\\CBS\\CBS.log and C:\\Windows\\Logs\\DISM\\dism.log.")
    if fac == 0x18:
        notes.append("Collect MDM diagnostics (mdmdiagnosticstool.exe) and read the DeviceManagement-Enterprise-Diagnostics-Provider/Admin log for the matching event.")
    if fac == 0x1C:
        notes.append("Run dsregcmd /status and read the 'User Device Registration/Admin' event log for details.")
    return {"forms": forms, "layout": layout, "fields": fields, "notes": notes}


def _search(words: list[str], limit: int = 40) -> list[dict]:
    out = []
    for kind, table in (("win32", kb.WIN32), ("hresult", kb.HRESULT), ("ntstatus", kb.NTSTATUS), ("kerberos", kb.KERBEROS), ("bugcheck", kb.BUGCHECK)):
        for code, e in table.items():
            if kind == "hresult" and (code >> 16) == 0x8007 and not e.get("meaning"):
                continue  # context-only entries; the Win32 entry covers them
            name = (e.get("name") or "").lower()
            hay = f"{name} {name.replace('_', ' ')} {e.get('meaning', '')} {' '.join(e.get('causes', []))} {' '.join(e.get('notes', []))}".lower()
            if all(w in hay for w in words):
                score = sum(3 if w in name.replace("_", " ") or w in name else 1 for w in words) + (2 if all(w in e.get("meaning", "").lower() for w in words) else 0)
                o = _entry_out(kind, code, e)
                out.append({"score": score, "kind": kind, "kind_label": KIND_LABEL[kind], "display": o["display"], "name": o["name"],
                            "meaning": _first_sentence(o["meaning"]), "query": _hex(code) if kind not in ("win32",) else str(code)})
    out.sort(key=lambda x: -x["score"])
    for o in out:
        if o["kind"] == "kerberos":
            o["query"] = f"kerberos {o['display']}"
        elif o["kind"] == "bugcheck":
            o["query"] = f"bugcheck {o['display']}"
    return out[:limit]


def lookup_code(q: str) -> dict:
    q = (q or "").strip()
    if not q:
        raise ValueError("Enter an error code, a name like ERROR_ACCESS_DENIED, or a few words like 'access denied'.")
    found = _extract(q)
    if not found:
        words = [w for w in re.findall(r"[a-z0-9]+", q.lower()) if len(w) > 1 and w not in {"the", "error", "code", "is", "of", "an", "and", "or", "a", "to", "in"}]
        cands = _search(words) if words else []
        if not cands:
            return {"query": q, "severity": "info", "headline": f"No error code found in “{q[:80]}”",
                    "subline": "Paste a code like 0x80070005, -2147024891, 5, 0xC000006A, 0x7E, KDC_ERR_PREAUTH_FAILED, or a name like ERROR_ACCESS_DENIED.",
                    "primary": None, "alternatives": [], "structure": None, "candidates": [], "others": []}
        return {"query": q, "severity": "info", "headline": f"{len(cands)} knowledge base entr{'y matches' if len(cands) == 1 else 'ies match'} “{q[:60]}”",
                "subline": "No code in the search, so this is a keyword match on names and meanings. Pick the one that fits.",
                "primary": None, "alternatives": [], "structure": None, "candidates": cands, "others": []}

    raw_tok, parsed = found[0]
    others = [t for t, _ in found[1:6]]
    if parsed[0] == "name":
        kind, code = NAME_INDEX[parsed[1]]
        v, form = code, ("hex" if kind in ("bugcheck", "kerberos") else "decimal" if kind == "win32" else "hex")
        q_ctx = q + (" kerberos" if kind == "kerberos" else " bugcheck" if kind == "bugcheck" else "")
        interps = _interpretations(v, form, q_ctx)
        interps.sort(key=lambda r: r["kind"] != kind)
        if kind == "hresult" and (v >> 16) == 0x8007:
            pass
    else:
        v, form = parsed
        interps = _interpretations(v, form, q)
    structure = _structure(v, form)
    bc_params = None
    m = re.search(r"(0x[0-9a-fA-F]{1,16})\s*\(\s*(0x[0-9a-fA-F]+(?:\s*,\s*0x[0-9a-fA-F]+){1,4})\s*\)", q)
    if m and any(i["kind"] == "bugcheck" for i in interps):
        bc_params = [p.strip() for p in m.group(2).split(",")]
        interps.sort(key=lambda r: r["kind"] != "bugcheck")
        others = []

    shown = (interps[0]["display"] if interps else raw_tok) if parsed[0] == "name" else (_hex(v) if form in ("negative", "barehex") or (form == "hex" and v > 0xFFFF) else raw_tok)
    if not interps:
        layout = structure["layout"]
        what = {"HRESULT": "an HRESULT", "NTSTATUS-style": "an NTSTATUS-style code", "Small value": "a small value (likely a Win32 error)"}.get(layout, "a code")
        fac_note = ""
        for f in structure["fields"]:
            if f[0].startswith("Facility"):
                fac_note = f" from facility {f[1]}" + (f" ({f[2]})" if f[2] and "can name" not in f[2] else "")
        return {"query": q, "value": v, "severity": "info", "headline": f"{shown} is not in the knowledge base",
                "subline": f"Structurally it is {what}{fac_note}. Its specific meaning isn't known here; search the code together with the product that logged it.",
                "primary": None, "alternatives": [], "structure": structure, "candidates": [], "others": others}

    p = interps[0]
    meaning = p["meaning"]
    kind_bits = p["kind_label"]
    if p.get("win32") is not None:
        kind_bits = f"Win32 error {p['win32']}"
    elif p["kind"] == "win32":
        kind_bits = f"Win32 error {p['code']}"
    name = p.get("name")
    if p.get("alias") and p["alias"] != name:
        name = f"{name} / {p['alias']}" if name else p["alias"]
    label = f"{kind_bits}, {name}" if name else kind_bits
    head, _, rest = meaning.partition(": ")
    if rest and len(head) <= 70 and (len(head.split()) <= 2 or "(" in head or "/" in head):
        # "Context: what it means" style, e.g. "MDM enrollment: this device isn't allowed to enroll."
        r1 = _first_sentence(rest)
        headline = f"{shown} = {head}: {r1.rstrip('.')} ({label})"
        sub = rest[len(r1):].strip() or None
    elif rest and len(head) <= 70:
        headline = f"{shown} = {head.rstrip('.')} ({label})"
        sub = rest[0].upper() + rest[1:]
    elif len(meaning) <= 90:
        headline = f"{shown} = {meaning.rstrip('.')} ({label})"
        sub = None
    else:
        first = _first_sentence(meaning)
        if name and len(first) <= 160:
            headline = f"{shown} {name} ({kind_bits}): {first[0].lower() + first[1:]}"
            sub = meaning[len(first):].strip() or None
        elif not name:
            headline = f"{shown} = {first.rstrip('.')} ({kind_bits})"
            sub = meaning[len(first):].strip() or None
        else:
            headline = f"{shown} = {name} ({kind_bits})"
            sub = meaning
    if len(interps) > 1:
        alts = ", ".join(f"{a['kind_label']} {a.get('name') or a['display']}" for a in interps[1:3])
        sub = (sub + " " if sub else "") + f"The same number is also {alts}; see below."
    return {"query": q, "value": v, "severity": p["severity"], "headline": headline, "subline": sub, "primary": p,
            "alternatives": interps[1:], "structure": structure, "candidates": [], "others": others, "bugcheck_params": bc_params}


# ============================================================ EVENT PARSING
LEVELS = {"0": "Information", "1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}
_DOTNET_DATE = re.compile(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/")


def _norm_provider(p: str | None) -> str:
    if not p:
        return ""
    toks = [t for t in re.split(r"[-\s._]+", p.lower()) if t and t not in ("microsoft", "windows")]
    return "".join(re.sub(r"[^a-z0-9]", "", t) for t in toks)


def _parse_time(s) -> datetime | None:
    if s is None:
        return None
    if isinstance(s, dict):
        s = s.get("DateTime") or s.get("value") or s.get("Value")
        if s is None:
            return None
    s = str(s).strip()
    if not s:
        return None
    m = _DOTNET_DATE.search(s)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc).replace(tzinfo=None)
    iso = re.sub(r"(\.\d{6})\d+", r"\1", s).replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(iso)
        if d.tzinfo:
            d = d.astimezone(timezone.utc).replace(tzinfo=None)
        return d
    except ValueError:
        pass
    s2 = re.sub(r"\s+", " ", s.replace("\u200e", "").replace("\u200f", ""))
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M %p", "%d/%m/%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%A, %B %d, %Y %I:%M:%S %p", "%A, %d %B %Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(s2, fmt)
        except ValueError:
            continue
    return None


def _ev(id_, time=None, provider=None, log=None, computer=None, level=None, task=None, message="", data=None) -> dict | None:
    try:
        eid = int(str(id_).strip())
    except (TypeError, ValueError):
        return None
    if eid < 0 or eid > 0xFFFFFFFF:
        return None
    if eid > 0xFFFF:
        eid &= 0xFFFF  # Get-EventLog InstanceId carries qualifier bits
    lvl = str(level).strip() if level is not None else ""
    lvl = LEVELS.get(lvl, lvl)
    return {"id": eid, "time_dt": _parse_time(time), "time_raw": str(time) if time is not None else "", "provider": (provider or "").strip(),
            "log": (log or "").strip(), "computer": (computer or "").strip(), "level": lvl, "task": (task or "").strip(),
            "message": (message or "").replace("\r\n", "\n").replace("\r", "\n").strip(), "data": data or {}}


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml_event(xml: str) -> dict | None:
    if re.search(r"<!DOCTYPE|<!ENTITY", xml, re.I):
        raise ValueError("XML with DOCTYPE/ENTITY declarations is not accepted.")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    sys_ = next((c for c in root if _strip_ns(c.tag) == "System"), None)
    if sys_ is None:
        return None
    vals: dict = {}
    for c in sys_:
        t = _strip_ns(c.tag)
        if t == "Provider":
            vals["provider"] = c.get("Name") or c.get("EventSourceName")
        elif t == "EventID":
            vals["id"] = (c.text or "").strip()
        elif t == "TimeCreated":
            vals["time"] = c.get("SystemTime")
        elif t == "Computer":
            vals["computer"] = c.text
        elif t == "Channel":
            vals["log"] = c.text
        elif t == "Level":
            vals["level"] = (c.text or "").strip()
        elif t == "Task":
            vals["task"] = c.text
    data: dict = {}
    msg = ""
    for c in root:
        t = _strip_ns(c.tag)
        if t == "EventData":
            n = 0
            for d in c:
                if _strip_ns(d.tag) != "Data":
                    continue
                n += 1
                data[d.get("Name") or f"param{n}"] = (d.text or "").strip()
        elif t == "UserData":
            for top in c:
                for d in top.iter():
                    if d is top:
                        continue
                    if len(d) == 0:
                        data[_strip_ns(d.tag)] = (d.text or "").strip()
        elif t == "RenderingInfo":
            for r in c:
                if _strip_ns(r.tag) == "Message":
                    msg = r.text or ""
                elif _strip_ns(r.tag) == "Level" and r.text:
                    vals["level"] = r.text
                elif _strip_ns(r.tag) == "Task" and r.text:
                    vals["task"] = r.text
    if vals.get("level") in ("0", "4"):
        vals["level"] = "Information"
    return _ev(vals.get("id"), vals.get("time"), vals.get("provider"), vals.get("log"), vals.get("computer"), vals.get("level"), vals.get("task"), msg, data)


_XML_EVENT_RE = re.compile(r"<Event[\s>].*?</Event>", re.S)


def _parse_xml(raw: str) -> list[dict]:
    if re.search(r"<!DOCTYPE|<!ENTITY", raw, re.I):
        raise ValueError("XML with DOCTYPE/ENTITY declarations is not accepted.")
    out = []
    for m in _XML_EVENT_RE.finditer(raw):
        ev = _parse_xml_event(m.group(0))
        if ev:
            out.append(ev)
    return out


_EV_TEXT_KEYS = {"log name": "log", "source": "provider", "date": "time", "event id": "id", "task category": "task", "task": "task", "level": "level",
                 "computer": "computer", "keywords": None, "user": None, "opcode": None}


def _parse_ev_text(raw: str) -> list[dict]:
    """Event Viewer 'Copy details as text' (blocks starting with 'Log Name:') and wevtutil /f:text ('Event[n]:')."""
    if re.search(r"^\s*Event\[\d+\]:", raw, re.M):
        blocks = re.split(r"^\s*Event\[\d+\]:\s*$", raw, flags=re.M)
    else:
        blocks = re.split(r"(?=^\s*Log Name:)", raw, flags=re.M)
    out = []
    for b in blocks:
        if not re.search(r"Event ID:", b):
            continue
        vals: dict = {}
        msg_lines: list[str] = []
        xml_part = ""
        lines = b.split("\n")
        i = 0
        in_desc = False
        while i < len(lines):
            line = lines[i].rstrip("\r")
            if in_desc:
                if re.match(r"^\s*Event Xml:\s*$", line):
                    xml_part = "\n".join(lines[i + 1:])
                    break
                msg_lines.append(line)
            else:
                m = re.match(r"^\s*([A-Za-z ]+?):\s*(.*)$", line)
                if m:
                    k = m.group(1).strip().lower()
                    if k == "description":
                        in_desc = True
                        if m.group(2).strip():
                            msg_lines.append(m.group(2))
                    elif k in _EV_TEXT_KEYS and _EV_TEXT_KEYS[k]:
                        vals.setdefault(_EV_TEXT_KEYS[k], m.group(2).strip())
            i += 1
        data = {}
        if xml_part:
            x = _parse_xml(xml_part)
            if x:
                data = x[0]["data"]
                if not vals.get("time") and x[0]["time_dt"]:
                    vals["time"] = x[0]["time_dt"].isoformat()
        ev = _ev(vals.get("id"), vals.get("time"), vals.get("provider"), vals.get("log"), vals.get("computer"), vals.get("level"), vals.get("task"),
                 "\n".join(msg_lines), data)
        if ev:
            out.append(ev)
    return out


_FL_KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*)\s*:\s?(.*)$")
_FL_MAP = {"id": "id", "eventid": "id", "instanceid": "instanceid", "timecreated": "time", "timegenerated": "time", "providername": "provider",
           "source": "provider", "logname": "log", "machinename": "computer", "message": "message", "leveldisplayname": "level", "entrytype": "level",
           "taskdisplayname": "task", "level": "levelnum"}


def _parse_format_list(raw: str) -> list[dict]:
    records: list[dict] = []
    cur: dict = {}
    key = None
    indent = None

    def flush():
        if cur:
            records.append(dict(cur))

    for line in raw.split("\n"):
        line = line.rstrip("\r")
        m = _FL_KEY_RE.match(line)
        if m and not line[:1].isspace():
            k = m.group(1)
            if k in cur:
                flush()
                cur.clear()
            cur[k] = m.group(2)
            key = k
            indent = len(line) - len(m.group(2)) if m.group(2) else None
            continue
        if key is None:
            continue
        if indent is None:
            indent = len(line) - len(line.lstrip(" "))
        cont = line[indent:] if line[:indent].strip() == "" else line.strip()
        cur[key] = cur[key] + "\n" + cont
    flush()
    out = []
    for r in records:
        vals = {}
        for k, v in r.items():
            mk = _FL_MAP.get(k.lower())
            if mk and mk not in vals:
                vals[mk] = v.strip() if mk != "message" else v
        eid = vals.get("id") or vals.get("instanceid")
        level = vals.get("level") or vals.get("levelnum")
        ev = _ev(eid, vals.get("time"), vals.get("provider"), vals.get("log"), vals.get("computer"), level, vals.get("task"), vals.get("message", ""))
        if ev:
            out.append(ev)
    return out


_JSON_MAP = {"id": "id", "eventid": "id", "instanceid": "instanceid", "event id": "id", "timecreated": "time", "timegenerated": "time", "date": "time",
             "date and time": "time", "time": "time", "providername": "provider", "source": "provider", "provider": "provider", "logname": "log",
             "log name": "log", "machinename": "computer", "computer": "computer", "message": "message", "description": "message",
             "leveldisplayname": "level", "entrytype": "level", "level": "levelnum", "taskdisplayname": "task", "task category": "task"}


def _from_mapping(obj: dict) -> dict | None:
    vals: dict = {}
    for k, v in obj.items():
        mk = _JSON_MAP.get(str(k).strip().lower())
        if mk and mk not in vals and v not in (None, ""):
            vals[mk] = v
    if isinstance(vals.get("levelnum"), dict):
        vals["levelnum"] = None
    data = {}
    props = obj.get("Properties") or obj.get("properties")
    eid = vals.get("id", vals.get("instanceid"))
    for dk in ("BugcheckCode", "PowerButtonTimestamp"):
        if obj.get(dk) not in (None, ""):
            data[dk] = str(obj[dk])
    if isinstance(props, list) and str(eid) == "41" and props and isinstance(props[0], dict) and "Value" in props[0]:
        data["BugcheckCode"] = str(props[0]["Value"])
    lvl = vals.get("level") or vals.get("levelnum")
    if isinstance(lvl, dict):
        lvl = lvl.get("value")
    return _ev(eid, vals.get("time"), vals.get("provider"), vals.get("log"), vals.get("computer"), lvl, vals.get("task"),
               str(vals.get("message") or ""), data)


def _parse_json(raw: str) -> list[dict]:
    s = raw.strip().lstrip("\ufeff")
    try:
        obj = json.loads(s)
        items = obj if isinstance(obj, list) else [obj]
    except json.JSONDecodeError:
        items = []
        for line in s.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if not items:
            raise ValueError("This looks like JSON but couldn't be parsed. Paste the complete ConvertTo-Json output, including the opening [ and closing ].")
    out = []
    for it in items:
        if isinstance(it, dict):
            ev = _from_mapping(it)
            if ev:
                out.append(ev)
    return out


def _parse_csv(raw: str, delimiter: str = ",") -> list[dict]:
    lines = [l for l in raw.lstrip("\ufeff").split("\n") if not l.startswith("#TYPE")]
    text = "\n".join(lines)
    rdr = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows = list(rdr)
    if not rows:
        return []
    header = [h.strip() for h in rows[0]]
    out = []
    for r in rows[1:]:
        if not any(c.strip() for c in r):
            continue
        obj = {header[i] if i < len(header) and header[i] else "Description": c for i, c in enumerate(r)}
        if len(r) > len(header):
            obj["Description"] = ",".join(r[len(header):]) if len(r) - len(header) > 1 else r[len(header)]
        ev = _from_mapping(obj)
        if ev:
            out.append(ev)
    return out


def parse_events(raw: str) -> tuple[list[dict], str]:
    s = raw.strip().lstrip("\ufeff")
    if not s:
        raise ValueError("Paste some events first.")
    s = s.replace("\x00", "")
    if s[:1] in "[{":
        return _parse_json(s), "JSON (ConvertTo-Json)"
    if re.search(r"^\s*Event\[\d+\]:", s, re.M):
        return _parse_ev_text(s), "wevtutil text"
    if re.search(r"^\s*Log Name:", s, re.M) and re.search(r"^\s*Event ID:", s, re.M):
        return _parse_ev_text(s), "Event Viewer text (Copy details as text)"
    if re.search(r"<Event[\s>]", s):
        return _parse_xml(s), "XML"
    first = next((l for l in s.split("\n") if l.strip() and not l.startswith("#TYPE")), "")
    if "\t" in first and re.search(r"event id|\bid\b|eventid|instanceid", first, re.I):
        return _parse_csv(s, "\t"), "Tab-delimited text (Event Viewer export)"
    if "," in first and re.search(r"event id|\bid\b|eventid|instanceid", first, re.I):
        return _parse_csv(s), "CSV"
    if re.search(r"^(Id|EventID|InstanceId)\s*:", s, re.M):
        return _parse_format_list(s), "PowerShell Format-List"
    raise ValueError("Couldn't recognise the format. Paste Event Viewer 'Copy details as text', Get-WinEvent | Format-List *, ConvertTo-Json output, a CSV export, or event XML.")


# ======================================================== MESSAGE FIELDS
def _msg_fields(msg: str) -> list[tuple[str, str, str]]:
    """(section, key, value) triples from a Security-style rendered message."""
    out = []
    section = ""
    for line in msg.split("\n"):
        st = line.strip()
        if not st:
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9 \-/()'\.]{0,60}?):\s*(.*)$", st)
        if m:
            k, v = m.group(1).strip(), m.group(2).strip()
            if v == "" and not line.startswith(("\t", " ")) or v == "" and k.endswith(("Account", "Information", "Logon", "Subject", "Member", "Group", "Process", "Details", "Failed")):
                section = k
                continue
            out.append((section, k, v))
    return out


def _f(ev: dict, data_keys=(), msg_keys=()) -> str:
    for k in data_keys:
        v = ev["data"].get(k)
        if v not in (None, "", "-"):
            return str(v).strip()
    if "_fields" not in ev:
        ev["_fields"] = _msg_fields(ev["message"])
    for spec in msg_keys:
        sec, key = spec if isinstance(spec, tuple) else (None, spec)
        for s, k, v in ev["_fields"]:
            if k.lower() == key.lower() and (sec is None or sec.lower() in s.lower()) and v not in ("", "-"):
                return v
    return ""


def _clean_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if ip.lower().startswith("::ffff:"):
        ip = ip[7:]
    return "" if ip in ("-", "::1", "127.0.0.1") else ip


def _clean_host(h: str) -> str:
    h = (h or "").strip().lstrip("\\").strip()
    return "" if h in ("-", "") else h.upper()


def _code_int(s: str) -> int | None:
    s = (s or "").strip()
    m = re.match(r"^(0x[0-9a-fA-F]+|\d+)", s)
    if not m:
        return None
    t = m.group(1)
    return int(t, 16) if t.lower().startswith("0x") else int(t)


def _nt_name(code: int | None) -> str:
    if code is None:
        return ""
    e = kb.NTSTATUS.get(code)
    return e["name"] if e else ""


def _kerb_name(code: int | None) -> str:
    if code is None:
        return ""
    e = kb.KERBEROS.get(code)
    return e["name"] if e else ""


def _short_nt(code: int | None) -> str:
    e = kb.NTSTATUS.get(code) if code is not None else None
    return _first_sentence(e["meaning"]).split(":")[0] if e else ""


LOGON_TYPES = {
    2: "Interactive (at the console)", 3: "Network (file share, IIS, most remote access)", 4: "Batch (scheduled task)", 5: "Service (service start-up)",
    7: "Unlock (workstation unlock)", 8: "NetworkCleartext (password sent in clear, e.g. IIS basic auth)", 9: "NewCredentials (runas /netonly)",
    10: "RemoteInteractive (Remote Desktop)", 11: "CachedInteractive (cached domain credentials, no DC contact)",
    12: "CachedRemoteInteractive (RDP with cached credentials)", 13: "CachedUnlock",
}
PRIV_GROUPS = {"domain admins", "enterprise admins", "schema admins", "administrators", "account operators", "backup operators", "server operators",
               "print operators", "dnsadmins", "group policy creator owners", "enterprise key admins", "key admins"}

# ========================================================= EVENT KNOWLEDGE
SEC = ["securityauditing"]


def K(ids, title, sev, meaning, prov=None, msg=None, default=False, cat="other", noise=False):
    return {"ids": ids if isinstance(ids, (list, tuple)) else [ids], "title": title, "sev": sev, "meaning": meaning, "prov": prov,
            "msg": re.compile(msg, re.I) if msg else None, "default": default, "cat": cat, "noise": noise}


EVENT_KB = [
    K(4624, "Successful logon", "info", "An account logged on successfully. The Logon Type says how (3 = network, 10 = Remote Desktop, 2 = console, 5 = service, 4 = scheduled task).", SEC, default=True, cat="auth"),
    K(4625, "Failed logon", "warning", "An account failed to log on. Status / Sub Status say why (e.g. 0xC000006A = wrong password, 0xC0000064 = no such user). Source Network Address / Workstation Name say where it came from.", SEC, default=True, cat="auth"),
    K(4634, "Logoff", "info", "A logon session ended.", SEC, default=True, cat="auth", noise=True),
    K(4647, "User-initiated logoff", "info", "The user logged off.", SEC, default=True, cat="auth", noise=True),
    K(4648, "Logon with explicit credentials", "info", "A process logged on using explicitly supplied credentials (runas, mapped drive with other credentials, scheduled task).", SEC, default=True, cat="auth"),
    K(4672, "Special privileges assigned to new logon", "info", "An admin-equivalent logon occurred. Normal for administrators and service accounts; mostly noise.", SEC, default=True, cat="auth", noise=True),
    K(4740, "Account locked out", "critical", "A user account was locked out. Logged on domain controllers (always on the PDC emulator). 'Caller Computer Name' is the machine the bad passwords came from.", SEC, default=True, cat="auth"),
    K(4767, "Account unlocked", "info", "A user account was unlocked.", SEC, default=True, cat="account"),
    K(4768, "Kerberos TGT requested", "info", "A Kerberos ticket-granting ticket (initial logon) was requested. Result Code 0x0 = success; anything else is a failure.", SEC, default=True, cat="auth"),
    K(4769, "Kerberos service ticket requested", "info", "A Kerberos service ticket was requested. Failure codes here often point at SPN or encryption type problems.", SEC, default=True, cat="auth"),
    K(4771, "Kerberos pre-authentication failed", "warning", "Kerberos pre-authentication failed on the DC. Failure Code 0x18 = wrong password; Client Address is where it came from.", SEC, default=True, cat="auth"),
    K(4776, "NTLM credential validation", "info", "The DC validated NTLM credentials. Error Code 0x0 = success; 0xC000006A = wrong password. Source Workstation is the client name the request claims.", SEC, default=True, cat="auth"),
    K(4720, "User account created", "info", "A user account was created.", SEC, default=True, cat="account"),
    K(4722, "User account enabled", "info", "A user account was enabled.", SEC, default=True, cat="account"),
    K(4723, "Password change attempt", "info", "A user attempted to change their own password.", SEC, default=True, cat="account"),
    K(4724, "Password reset attempt", "info", "An administrator attempted to reset an account's password.", SEC, default=True, cat="account"),
    K(4725, "User account disabled", "info", "A user account was disabled.", SEC, default=True, cat="account"),
    K(4726, "User account deleted", "warning", "A user account was deleted.", SEC, default=True, cat="account"),
    K(4738, "User account changed", "info", "A user account's attributes were changed.", SEC, default=True, cat="account"),
    K(4741, "Computer account created", "info", "A computer account was created.", SEC, default=True, cat="account"),
    K(4742, "Computer account changed", "info", "A computer account was changed.", SEC, default=True, cat="account", noise=True),
    K(4743, "Computer account deleted", "info", "A computer account was deleted.", SEC, default=True, cat="account"),
    K([4728, 4732, 4756], "Member added to security group", "info", "A member was added to a security-enabled group (4728 global, 4732 local/domain local, 4756 universal).", SEC, default=True, cat="account"),
    K([4729, 4733, 4757], "Member removed from security group", "info", "A member was removed from a security-enabled group.", SEC, default=True, cat="account"),
    K(1102, "Security audit log cleared", "critical", "The Security log was cleared. Unless an admin did this on purpose, treat it as an attacker covering tracks.", ["eventlog"], default=True, cat="security"),
    K(104, "Event log cleared", "warning", "An event log (System or another log) was cleared.", ["eventlog"], msg=r"log file was cleared", cat="security"),
    K(4719, "Audit policy changed", "warning", "The system audit policy was changed. Unexpected changes can be an attacker disabling auditing.", SEC, default=True, cat="security"),
    K(4697, "Service installed (Security log)", "warning", "A service was installed on the system. Check the service file name is expected.", SEC, default=True, cat="security"),
    K(7045, "Service installed", "info", "A new service was installed. Check the Service File Name: services running from Temp/AppData or launching encoded PowerShell are a classic attacker technique.", ["servicecontrolmanager"], msg=r"service was installed", cat="security"),
    K(41, "Unexpected reboot (Kernel-Power)", "critical", "The system rebooted without cleanly shutting down first: it crashed, hung, or lost power. BugcheckCode 0 = no blue screen was recorded (power loss, forced power-off or hard hang).", ["kernelpower"], msg=r"rebooted without cleanly shutting down", cat="crash"),
    K(6008, "Previous shutdown was unexpected", "critical", "Logged at boot when the previous shutdown wasn't clean (crash, power loss, hard reset).", ["eventlog"], msg=r"previous system shutdown.*unexpected", cat="crash"),
    K(1001, "Bug check (blue screen)", "critical", "The computer rebooted from a bug check (blue screen). The bug check code and parameters are in the message; a dump file was written.", ["bugcheck", "wersystemerrorreporting"], msg=r"rebooted from a bugcheck", cat="crash"),
    K(1074, "Planned restart/shutdown", "info", "A process or user initiated a restart or shutdown (the message says who, which process, and why).", ["user32"], msg=r"has initiated the (restart|shutdown|power off)", cat="power"),
    K(6005, "Event Log service started (boot)", "info", "The Event Log service started, which marks a system boot.", ["eventlog"], msg=r"event log service was started", cat="power"),
    K(6006, "Event Log service stopped (clean shutdown)", "info", "The Event Log service stopped, which marks a clean shutdown.", ["eventlog"], msg=r"event log service was stopped", cat="power"),
    K(6009, "OS version at boot", "info", "Logged at every boot with the OS version.", ["eventlog"], msg=r"Microsoft \(R\) Windows", cat="power", noise=True),
    K(6013, "System uptime", "info", "Daily uptime report.", ["eventlog"], msg=r"system uptime", cat="power", noise=True),
    K(12, "Operating system started", "info", "The kernel started (boot).", ["kernelgeneral"], msg=r"operating system started", cat="power"),
    K(13, "Operating system shutting down", "info", "The kernel is shutting down cleanly.", ["kernelgeneral"], msg=r"operating system is shutting down", cat="power"),
    K(109, "Kernel power manager initiated shutdown", "info", "The kernel power manager has initiated a shutdown transition.", ["kernelpower"], msg=r"initiated a shutdown transition", cat="power"),
    K(42, "Entering sleep", "info", "The system is entering sleep.", ["kernelpower"], msg=r"entering sleep", cat="power", noise=True),
    K(107, "Resumed from sleep", "info", "The system has resumed from sleep.", ["kernelpower"], msg=r"resumed from sleep", cat="power", noise=True),
    K(7031, "Service crashed (recovery action taken)", "warning", "A service terminated unexpectedly; Windows ran its recovery action (usually a restart).", ["servicecontrolmanager"], msg=r"terminated unexpectedly", cat="service"),
    K(7034, "Service crashed", "warning", "A service terminated unexpectedly (no recovery action, or recovery attempts exhausted).", ["servicecontrolmanager"], msg=r"terminated unexpectedly", cat="service"),
    K(7000, "Service failed to start", "warning", "A service failed to start; the error is in the message.", ["servicecontrolmanager"], msg=r"failed to start", cat="service"),
    K(7009, "Service start timed out", "warning", "A timeout was reached waiting for a service to connect (start).", ["servicecontrolmanager"], msg=r"timeout was reached", cat="service"),
    K(7011, "Service response timed out", "warning", "A timeout was reached waiting for a transaction response from a service (the service hung).", ["servicecontrolmanager"], msg=r"timeout .* transaction response", cat="service"),
    K(7023, "Service terminated with error", "warning", "A service stopped with an error.", ["servicecontrolmanager"], msg=r"terminated with the following error", cat="service"),
    K(7024, "Service terminated with service-specific error", "warning", "A service stopped with a service-specific error code.", ["servicecontrolmanager"], msg=r"service-specific error", cat="service"),
    K(7038, "Service logon failed (password)", "critical", "A service could not log on with its configured account and password. Stale service passwords are a common cause of account lockouts.", ["servicecontrolmanager"], msg=r"unable to log on", cat="service"),
    K(7041, "Service logon failed (logon right)", "critical", "A service could not log on because the account lacks the 'Log on as a service' right.", ["servicecontrolmanager"], msg=r"logon type|log on as a service", cat="service"),
    K(7036, "Service state change", "info", "A service entered the running/stopped state. Noise for troubleshooting.", ["servicecontrolmanager"], msg=r"entered the .* state", cat="service", noise=True),
    K(7040, "Service start type changed", "info", "A service's start type was changed.", ["servicecontrolmanager"], msg=r"start type", cat="service"),
    K(17, "Corrected hardware error (WHEA)", "warning", "A corrected hardware error occurred (often PCI Express AER corrected errors). Corrected means no data loss, but frequent ones point at a failing or badly seated device, a firmware/ASPM issue, or the slot.", ["whealogger"], msg=r"corrected hardware error", cat="hardware"),
    K(18, "Fatal hardware error (WHEA)", "critical", "A fatal hardware error occurred (machine check). This usually caused a 0x124 bug check. The message names the component (processor core, cache, memory, bus).", ["whealogger"], msg=r"fatal hardware error", cat="hardware"),
    K(19, "Corrected hardware error (WHEA)", "warning", "A corrected hardware error occurred, reported by the CPU's machine check architecture (processor core, cache or bus). Frequent ones predict a fatal error: check BIOS/microcode, overclocking and cooling.", ["whealogger"], msg=r"corrected hardware error", cat="hardware"),
    K(47, "Corrected memory error (WHEA)", "warning", "A corrected hardware error occurred in memory (ECC corrected it). Repeated errors on the same module mean the DIMM should be replaced.", ["whealogger"], msg=r"corrected hardware error", cat="hardware"),
    K(7, "Bad block on disk", "critical", "The disk reported a bad block. The disk is failing or the data on it is damaged: back up and plan replacement.", ["disk"], msg=r"has a bad block", cat="storage"),
    K(11, "Disk controller error", "critical", "The driver detected a controller error on a disk: cable, controller, backplane, or failing disk.", ["disk"], msg=r"controller error", cat="storage"),
    K(51, "Paging error on disk", "warning", "An error was detected on a disk during a paging operation (storage path problem or failing disk).", ["disk"], msg=r"during a paging operation", cat="storage"),
    K(153, "Disk I/O retried", "warning", "An I/O operation to the disk was retried. Occasional retries are tolerable; many indicate a struggling disk, path, or SAN.", ["disk"], msg=r"was retried", cat="storage"),
    K(157, "Disk surprise removed", "critical", "A disk was surprise removed (disappeared without warning): failing disk, cable, controller, or a storage path/SAN drop.", ["disk"], msg=r"surprise removed", cat="storage"),
    K(129, "Storage reset (timeout)", "warning", "The storage driver reset the device because I/O timed out (Reset to device ... was issued). Points at a slow/failing disk, controller firmware, or SAN/virtual storage latency.", None, msg=r"reset to device", cat="storage"),
    K(55, "NTFS corruption", "critical", "NTFS found corruption in the file system structure on a volume. Run chkdsk; check the disk for hardware errors.", ["ntfs"], msg=r"corrupt", cat="storage"),
    K(98, "NTFS volume health", "warning", "NTFS reported the volume's health. If it says the volume needs a full chkdsk, schedule one; if it says healthy, it's informational.", ["ntfs"], msg=r"volume", cat="storage"),
    K(10016, "DCOM permission (usually noise)", "info", "DCOM application-specific permission settings don't grant Local Activation. Microsoft documents these as expected and safe to ignore; they almost never explain a problem.", ["distributedcom", "dcom"], msg=r"application-specific permission", cat="noise", noise=True),
    K(1129, "Group Policy: no DC connectivity", "warning", "Group Policy processing failed because of lack of network connectivity to a domain controller (common at boot on Wi-Fi/VPN; persistent = network/DNS problem).", ["grouppolicy"], msg=r"lack of network connectivity", cat="gp"),
    K(1053, "Group Policy: couldn't resolve user/computer", "warning", "Group Policy processing failed: Windows could not resolve the user or computer name (DNS, DC reachability, or secure channel).", ["grouppolicy"], msg=r"could not resolve the (user|computer) name", cat="gp"),
    K(1058, "Group Policy: couldn't read gpt.ini from SYSVOL", "warning", "Group Policy processing failed: Windows couldn't read gpt.ini from SYSVOL on a DC (SYSVOL/DFS-R replication, DFS client, permissions, or network/SMB problems).", ["grouppolicy"], msg=r"gpt\.ini", cat="gp"),
    K(1085, "Group Policy: extension failed", "warning", "A Group Policy client-side extension failed to apply its settings (the message names which one).", ["grouppolicy"], msg=r"failed to apply", cat="gp"),
    K(5719, "Netlogon: no secure session with a DC", "warning", "This computer could not set up a secure session with a domain controller. A single one at boot (network not ready yet) is common; repeated ones mean DC connectivity, DNS or secure-channel trouble.", ["netlogon"], msg=r"not able to set up a secure session", cat="netlogon"),
    K(5722, "Netlogon: computer failed to authenticate", "warning", "Logged on a DC: a computer's session setup failed to authenticate, usually because its machine account password doesn't match AD (restored snapshot, duplicate name). Reset the computer's secure channel.", ["netlogon"], msg=r"failed to authenticate", cat="netlogon"),
    K(5723, "Netlogon: no computer account", "warning", "Logged on a DC: a computer tried to set up a session but AD has no matching computer account (deleted or never created). Rejoin the computer.", ["netlogon"], msg=r"does not contain a trust account", cat="netlogon"),
    K(5805, "Netlogon: session setup failed to authenticate", "warning", "Logged on a DC: a computer's session setup failed to authenticate (machine account password mismatch).", ["netlogon"], msg=r"failed to authenticate", cat="netlogon"),
    K(5807, "Netlogon: clients outside AD sites", "info", "Clients connected whose IP subnets don't map to any AD site. Add the missing subnets in AD Sites and Services so clients find the nearest DC.", ["netlogon"], msg=r"don't map to any of the existing sites|do not map to any of the existing sites", cat="netlogon"),
    K(3210, "Netlogon: couldn't authenticate with a DC", "warning", "This computer could not authenticate with a domain controller (secure channel problem); logons may be denied. Test and repair the secure channel.", ["netlogon"], msg=r"could not authenticate with", cat="netlogon"),
    K([5827, 5828], "Netlogon: vulnerable connection denied", "warning", "The Netlogon service denied a vulnerable Netlogon secure channel connection (CVE-2020-1472 enforcement). The account named needs a supported client or an explicit allow-list entry.", ["netlogon"], msg=r"vulnerable", cat="netlogon"),
    K(5829, "Netlogon: vulnerable connection allowed", "warning", "The Netlogon service allowed a vulnerable Netlogon secure channel connection (CVE-2020-1472). Update or replace the device named.", ["netlogon"], msg=r"vulnerable", cat="netlogon"),
    K(3, "Kerberos error received", "warning", "A Kerberos error message was received. The Error Code says what failed (e.g. 0x25 KRB_AP_ERR_SKEW = clock skew, 0x7 = unknown SPN).", ["kerberos"], msg=r"kerberos error message was received", cat="kerberos"),
    K(4, "Kerberos KRB_AP_ERR_MODIFIED", "warning", "The target server couldn't decrypt the client's Kerberos ticket: the server's SPN is registered on a different account than the one the service runs as (duplicate/misplaced SPN, DNS alias, or computer account password mismatch).", ["kerberos"], msg=r"KRB_AP_ERR_MODIFIED", cat="kerberos"),
    K(36, "Time not synchronised", "warning", "The time service has not synchronized the system time for a long period. Kerberos breaks once the clock drifts more than 5 minutes.", ["timeservice", "w32time"], msg=r"has not synchronized", cat="time"),
    K(20, "Windows Update install failed", "warning", "Windows Update failed to install an update; the error code is in the message.", ["windowsupdateclient"], msg=r"installation failure", cat="update"),
    K(19, "Windows Update installed an update", "info", "Windows Update installed an update successfully.", ["windowsupdateclient"], msg=r"installation successful", cat="update"),
    K(43, "Windows Update install started", "info", "Windows Update started installing an update.", ["windowsupdateclient"], msg=r"installation started", cat="update", noise=True),
    K(44, "Windows Update download started", "info", "Windows Update started downloading an update.", ["windowsupdateclient"], msg=r"started downloading", cat="update", noise=True),
    K(1000, "Application crash", "warning", "An application crashed. The message names the faulting application, faulting module and exception code.", ["applicationerror"], msg=r"faulting application", cat="app"),
    K(1002, "Application hang", "warning", "An application stopped responding and was closed.", ["applicationhang"], msg=r"stopped interacting", cat="app"),
    K(1026, ".NET Runtime unhandled exception", "warning", "A .NET application terminated due to an unhandled exception; the message has the exception type and stack.", ["netruntime"], msg=r"unhandled exception", cat="app"),
]
_EKB_BY_ID: dict[int, list[dict]] = defaultdict(list)
for _k in EVENT_KB:
    for _i in _k["ids"]:
        _EKB_BY_ID[_i].append(_k)


def _match_kb(ev: dict) -> dict | None:
    cands = _EKB_BY_ID.get(ev["id"], [])
    if not cands:
        return None
    pn = _norm_provider(ev["provider"])
    if pn:
        for k in cands:
            if k["prov"] is None:
                # e.g. storage resets come from the miniport driver; exclude known other providers
                if "time" not in pn and (not k["msg"] or k["msg"].search(ev["message"]) or not ev["message"]):
                    return k
            elif any(p in pn for p in k["prov"]):
                if len([c for c in cands if c["prov"] and any(p in pn for p in c["prov"])]) > 1 and k["msg"] and ev["message"] and not k["msg"].search(ev["message"]):
                    continue
                return k
        return None
    for k in cands:
        if k["msg"] and ev["message"] and k["msg"].search(ev["message"]):
            return k
    for k in cands:
        if k["default"]:
            return k
    return None


# ============================================================== EXTRACTORS
def _enrich(ev: dict) -> None:
    """Pull out the fields the analysis needs into ev['x']."""
    i = ev["id"]
    x: dict = {}
    k = ev.get("kb")
    cat = k["cat"] if k else None
    if cat == "auth" or i in (4740,):
        if i == 4740:
            x["user"] = _f(ev, ["TargetUserName"], [("Locked Out", "Account Name")])
            x["caller"] = _clean_host(_f(ev, ["TargetDomainName"], ["Caller Computer Name"]))
        elif i == 4625:
            x["user"] = _f(ev, ["TargetUserName"], [("Failed", "Account Name")])
            x["domain"] = _f(ev, ["TargetDomainName"], [("Failed", "Account Domain")])
            x["status"] = _code_int(_f(ev, ["Status"], ["Status"]))
            x["substatus"] = _code_int(_f(ev, ["SubStatus"], ["Sub Status"]))
            x["logon_type"] = _code_int(_f(ev, ["LogonType"], ["Logon Type"]))
            x["workstation"] = _clean_host(_f(ev, ["WorkstationName"], [("Network", "Workstation Name"), "Workstation Name"]))
            x["ip"] = _clean_ip(_f(ev, ["IpAddress"], ["Source Network Address"]))
            x["process"] = _f(ev, ["ProcessName"], ["Caller Process Name"])
            x["auth"] = _f(ev, ["AuthenticationPackageName"], ["Authentication Package"])
            code = x["substatus"] if x["substatus"] not in (None, 0) else x["status"]
            x["code"], x["code_name"], x["code_text"] = code, _nt_name(code), _short_nt(code)
        elif i == 4624:
            x["user"] = _f(ev, ["TargetUserName"], [("New Logon", "Account Name")])
            x["domain"] = _f(ev, ["TargetDomainName"], [("New Logon", "Account Domain")])
            x["logon_type"] = _code_int(_f(ev, ["LogonType"], ["Logon Type"]))
            x["workstation"] = _clean_host(_f(ev, ["WorkstationName"], [("Network", "Workstation Name"), "Workstation Name"]))
            x["ip"] = _clean_ip(_f(ev, ["IpAddress"], ["Source Network Address"]))
            x["auth"] = _f(ev, ["AuthenticationPackageName"], ["Authentication Package"])
        elif i in (4771, 4768, 4769):
            x["user"] = _f(ev, ["TargetUserName"], [("Account Information", "Account Name"), "Account Name"])
            x["ip"] = _clean_ip(_f(ev, ["IpAddress"], ["Client Address"]))
            x["service"] = _f(ev, ["ServiceName"], ["Service Name"])
            c = _code_int(_f(ev, ["Status"], ["Failure Code", "Result Code"]))
            x["code"], x["code_name"] = c, _kerb_name(c)
            e = kb.KERBEROS.get(c) if c is not None else None
            x["code_text"] = _first_sentence(e["meaning"]).split(":")[0] if e else ""
            if "@" in x["user"]:
                x["user"] = x["user"].split("@")[0]
        elif i == 4776:
            x["user"] = _f(ev, ["TargetUserName"], ["Logon Account"])
            x["workstation"] = _clean_host(_f(ev, ["Workstation"], ["Source Workstation"]))
            c = _code_int(_f(ev, ["Status"], ["Error Code"]))
            x["code"], x["code_name"], x["code_text"] = c, _nt_name(c), _short_nt(c)
        elif i == 4648:
            x["user"] = _f(ev, ["TargetUserName"], [("Credentials Were Used", "Account Name")])
            x["target"] = _f(ev, ["TargetServerName"], ["Target Server Name"])
    elif cat == "account":
        x["subject"] = _f(ev, ["SubjectUserName"], [("Subject", "Account Name")])
        if i in (4728, 4732, 4756, 4729, 4733, 4757):
            member = _f(ev, ["MemberName"], [("Member", "Account Name")])
            m = re.match(r"CN=([^,]+)", member or "")
            x["member"] = m.group(1) if m else member or _f(ev, ["MemberSid"], [("Member", "Security ID")])
            x["group"] = _f(ev, ["TargetUserName"], [("Group", "Group Name"), ("Group", "Account Name")])
        else:
            x["target"] = _f(ev, ["TargetUserName"], [("New Account", "Account Name"), ("Target Account", "Account Name"), ("Computer Account That Was Changed", "Account Name"),
                                                      ("New Computer Account", "Account Name"), "Account Name"])
    elif i in (7045, 4697):
        x["service"] = _f(ev, ["ServiceName"], ["Service Name"])
        x["path"] = _f(ev, ["ImagePath", "ServiceFileName"], ["Service File Name"])
        x["account"] = _f(ev, ["AccountName", "ServiceAccount"], ["Service Account"])
        x["start"] = _f(ev, ["StartType", "ServiceStartType"], ["Service Start Type"])
    elif i == 1102:
        x["subject"] = _f(ev, ["SubjectUserName"], [("Subject", "Account Name"), "Account Name"])
    elif i == 41 and cat == "crash":
        bc = ev["data"].get("BugcheckCode")
        try:
            x["bugcheck"] = int(str(bc), 0) if bc not in (None, "") else None
        except ValueError:
            x["bugcheck"] = None
        pb = ev["data"].get("PowerButtonTimestamp")
        x["power_button"] = bool(pb and str(pb).strip() not in ("0", ""))
    elif i == 1001 and cat == "crash":
        txt = ev["data"].get("param1") or ev["message"]
        m = re.search(r"(0x[0-9a-fA-F]{1,16})\s*\(([^)]*)\)", txt or "")
        if m:
            code = int(m.group(1), 16) & 0xFFFFFFFF
            x["bugcheck"] = code
            x["params"] = [p.strip() for p in m.group(2).split(",")]
        dm = re.search(r"dump was saved in:\s*(\S+)", ev["message"], re.I)
        x["dump"] = dm.group(1).rstrip(".") if dm else ev["data"].get("param2", "")
    elif i == 1074 and cat == "power":
        m = re.search(r"The process (.+?) \((.*?)\) has initiated the (\w+(?: \w+)?) of computer (\S+) on behalf of user (.+?) for the following reason: ([^\n]+)", ev["message"])
        if m:
            x.update(process=m.group(1), kind=m.group(3), user=m.group(5), reason=m.group(6).strip())
        else:
            d = ev["data"]
            x.update(process=d.get("param1", ""), kind=d.get("param5", ""), user=d.get("param7", ""), reason=d.get("param3", ""))
        cm = re.search(r"Comment:\s*(.*)", ev["message"])
        x["comment"] = (cm.group(1).strip() if cm else ev["data"].get("param6", "")) or ""
    elif cat == "service":
        m = re.search(r"^The (.+?) service ", ev["message"]) or re.search(r"waiting for the (.+?) service", ev["message"])
        x["service"] = m.group(1) if m else ev["data"].get("param1", "")
        if i in (7038,):
            am = re.search(r"log on as (\S+)", ev["message"])
            x["account"] = am.group(1) if am else ev["data"].get("param2", "")
        em = re.search(r"following error:\s*\n?\s*(.+)", ev["message"])
        x["error"] = em.group(1).strip() if em else ""
    elif cat == "hardware":
        cm = re.search(r"component:\s*(.+)", ev["message"], re.I)
        sm = re.search(r"Error Source:\s*(.+)", ev["message"])
        x["component"] = cm.group(1).strip() if cm else ""
        x["source"] = sm.group(1).strip() if sm else ""
    elif cat == "kerberos" and i == 3:
        cm = re.search(r"Error Code:\s*(0x[0-9a-fA-F]+)", ev["message"])
        x["code"] = int(cm.group(1), 16) if cm else None
        x["code_name"] = _kerb_name(x["code"])
        sm = re.search(r"Server Name:\s*(\S+)", ev["message"])
        x["server"] = sm.group(1) if sm else ""
    elif cat == "kerberos" and i == 4:
        sm = re.search(r"from the server (\S+)", ev["message"])
        x["server"] = sm.group(1).rstrip(".") if sm else ""
    elif cat == "update" and i == 20:
        m = re.search(r"error (0x[0-9a-fA-F]+):\s*(.+)", ev["message"])
        if m:
            x["code"] = int(m.group(1), 16)
            x["update"] = m.group(2).strip()
    elif cat == "app" and i == 1000:
        for key, pat in (("app", r"Faulting application name:\s*([^,\n]+)"), ("module", r"Faulting module name:\s*([^,\n]+)"), ("exc", r"Exception code:\s*(0x[0-9a-fA-F]+)")):
            m = re.search(pat, ev["message"])
            x[key] = m.group(1).strip() if m else ev["data"].get({"app": "AppName", "module": "ModuleName", "exc": "ExceptionCode"}[key], "")
    elif cat == "storage" and i == 98:
        x["healthy"] = bool(re.search(r"is healthy", ev["message"], re.I))
    ev["x"] = x


# ================================================================ ANALYSIS
def _fmt_t(d: datetime | None) -> str | None:
    return d.strftime("%Y-%m-%d %H:%M:%S") if d else None


def _span(times: list[datetime]) -> str:
    times = [t for t in times if t]
    if len(times) < 2:
        return ""
    s = (max(times) - min(times)).total_seconds()
    if s < 60:
        return f"{int(s)}s"
    if s < 3600:
        return f"{int(s // 60)} min"
    if s < 86400 * 2:
        h = s / 3600
        return f"{h:.0f}h" if h >= 10 else f"{h:.1f}h".replace(".0h", "h")
    return f"{s / 86400:.0f} days"


def _summary(ev: dict) -> str:
    x, i = ev.get("x", {}), ev["id"]
    if i == 4740:
        return f"{x.get('user') or '?'} locked out; caller computer {x.get('caller') or '(blank)'}"
    if i == 4625:
        lt = x.get("logon_type")
        src = " / ".join(filter(None, [x.get("workstation"), x.get("ip")])) or "unknown source"
        code = f"{_hex(x['code'])} {x.get('code_name') or ''}".strip() if x.get("code") is not None else ""
        return f"{x.get('user') or '?'} from {src}" + (f", logon type {lt}" if lt is not None else "") + (f", {code}" if code else "")
    if i in (4771, 4768, 4769):
        code = f"0x{x['code']:X} {x.get('code_name') or ''}".strip() if x.get("code") is not None else ""
        return f"{x.get('user') or '?'} from {x.get('ip') or 'unknown IP'}" + (f", {code}" if code else "") + (f", service {x['service']}" if i == 4769 and x.get("service") else "")
    if i == 4776:
        code = f"{_hex(x['code'])} {x.get('code_name') or ''}".strip() if x.get("code") is not None else ""
        return f"{x.get('user') or '?'} from workstation {x.get('workstation') or '?'}" + (f", {code}" if code else "")
    if i == 4624:
        lt = x.get("logon_type")
        return f"{x.get('user') or '?'} logon type {lt} ({LOGON_TYPES.get(lt, '?')})" + (f" from {x.get('ip') or x.get('workstation')}" if x.get("ip") or x.get("workstation") else "")
    if i in (4728, 4732, 4756, 4729, 4733, 4757):
        verb = "added to" if i in (4728, 4732, 4756) else "removed from"
        return f"{x.get('member') or '?'} {verb} {x.get('group') or '?'} by {x.get('subject') or '?'}"
    if i in (4720, 4722, 4725, 4726, 4738, 4767, 4723, 4724, 4741, 4742, 4743):
        return f"{x.get('target') or '?'} by {x.get('subject') or '?'}"
    if i in (7045, 4697):
        return f"{x.get('service') or '?'}: {x.get('path') or '?'}" + (f" (as {x['account']})" if x.get("account") else "")
    if i == 1102:
        return f"cleared by {x.get('subject') or '?'}"
    if i == 41 and "bugcheck" in x:
        bc = x.get("bugcheck")
        if bc:
            n = kb.BUGCHECK.get(bc, {}).get("name")
            return f"bug check {_hex(bc)}" + (f" {n}" if n else "")
        return "no bug check recorded" + (" (power button held)" if x.get("power_button") else "")
    if i == 1001 and x.get("bugcheck") is not None:
        n = kb.BUGCHECK.get(x["bugcheck"], {}).get("name")
        return f"bug check {_hex(x['bugcheck'])}" + (f" {n}" if n else "")
    if i == 1074 and x.get("process"):
        return f"{x.get('kind', 'restart')} by {x.get('user') or '?'} via {x.get('process')}: {x.get('reason', '')}" + (f" ({x['comment']})" if x.get("comment") else "")
    if ev.get("kb") and ev["kb"]["cat"] == "service" and x.get("service"):
        return x["service"] + (f": {x['error']}" if x.get("error") else "")
    if ev.get("kb") and ev["kb"]["cat"] == "hardware" and (x.get("component") or x.get("source")):
        return " / ".join(filter(None, [x.get("component"), x.get("source")]))
    if i == 3 and x.get("code") is not None:
        return f"error 0x{x['code']:X} {x.get('code_name') or ''}" + (f" for {x['server']}" if x.get("server") else "")
    if i == 20 and x.get("code") is not None:
        n = (kb.HRESULT.get(x["code"]) or {}).get("name") or ""
        return f"{_hex(x['code'])} {n}: {x.get('update', '')}".strip()
    if i == 1000 and x.get("app"):
        return f"{x['app']} crashed in {x.get('module') or '?'} ({x.get('exc') or '?'})"
    first = next((l.strip() for l in ev["message"].split("\n") if l.strip()), "")
    return first[:200]


_SUSPICIOUS_SVC = [
    (re.compile(r"\\(windows\\)?temp\\|%temp%|\\appdata\\|\\users\\public\\|\\perflogs\\|\\programdata\\[^\\]+\.exe", re.I), "runs from a user-writable or temporary folder"),
    (re.compile(r"powershell.*(-e(nc|ncodedcommand)?\s|-w(indowstyle)?\s+hidden|-nop|iex|downloadstring|frombase64string)", re.I), "launches PowerShell with encoded/hidden/download options"),
    (re.compile(r"(cmd(\.exe)?\s*/c|%comspec%)", re.I), "runs a command line through cmd.exe"),
    (re.compile(r"\b(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript)(\.exe)?\b", re.I), "uses a living-off-the-land binary (mshta, rundll32, regsvr32, certutil, ...)"),
    (re.compile(r"\\\\[^\\]+\\(admin|c)\$", re.I), "runs from an admin share on another machine"),
]


def analyze_events(raw: str) -> dict:
    events, fmt = parse_events(raw)
    if not events:
        raise ValueError(f"Recognised the format as {fmt}, but found no events with an Event ID in it.")
    truncated = len(events) > 20000
    events = events[:20000]
    for ev in events:
        ev["kb"] = _match_kb(ev)
        _enrich(ev)
    events.sort(key=lambda e: (e["time_dt"] is None, e["time_dt"] or datetime.min))

    findings: list[dict] = []
    steps: list[dict] = []
    headline_candidates: list[tuple[int, str, str, str]] = []  # (priority, sev, title, sub)

    def add(sev, title, detail, prio=50, headline=None, sub=None):
        findings.append({"severity": sev, "title": title, "detail": detail})
        headline_candidates.append((prio, sev, headline or title, sub or detail))

    computers = Counter(e["computer"] for e in events if e["computer"])
    # Machines that logged DC-only events (lockouts, Kerberos, NTLM validation) are domain controllers.
    dc_names = {e["computer"].split(".")[0].upper() for e in events if e["computer"] and e["id"] in (4740, 4771, 4768, 4769, 4776)}

    # ------------------------------------------------------------- lockouts
    users: dict[str, dict] = {}

    def U(name):
        key = (name or "").strip().lower()
        if not key or key in ("-", "anonymous logon"):
            return None
        if key not in users:
            users[key] = {"user": name.strip(), "lockouts": [], "fails": [], "callers": Counter(), "sources": Counter(), "codes": Counter(), "src_ip": {}, "ltypes": Counter(), "procs": Counter()}
        return users[key]

    fails_by_source: dict[str, dict] = defaultdict(lambda: {"users": Counter(), "times": [], "codes": Counter(), "nouser": 0})
    succ_by_ip: dict[str, set] = defaultdict(set)
    for ev in events:
        x, i = ev["x"], ev["id"]
        k = ev.get("kb")
        if not k or k["cat"] != "auth":
            continue
        if i == 4740:
            u = U(x.get("user"))
            if u:
                u["lockouts"].append(ev)
                u["callers"][x.get("caller") or "(blank)"] += 1
            continue
        if i == 4624 and x.get("ip"):
            succ_by_ip[x["ip"]].add((x.get("user") or "").lower())
            continue
        failed = (i == 4625) or (i in (4771, 4768, 4769) and x.get("code") not in (None, 0)) or (i == 4776 and x.get("code") not in (None, 0))
        if not failed:
            continue
        if i in (4768, 4769) and x.get("code") in (0x19,):
            continue
        u = U(x.get("user"))
        if not u:
            continue
        src_name, src_ip = x.get("workstation") or "", x.get("ip") or ""
        src = src_name or src_ip or "(unknown)"
        if src_name and src_ip:
            u["src_ip"].setdefault(src_name, src_ip)
        u["fails"].append(ev)
        u["sources"][src] += 1
        if i == 4625 and x.get("logon_type") is not None:
            u["ltypes"][(ev["computer"].split(".")[0].upper() or src, x["logon_type"])] += 1
            if x.get("process") and x["process"] != "-":
                u["procs"][x["process"]] += 1
        cn = x.get("code_name") or (_hex(x["code"]) if x.get("code") is not None else "")
        if cn:
            u["codes"][cn] += 1
        skey = src_ip or src_name
        if skey:
            fs = fails_by_source[skey]
            fs["users"][u["user"].lower()] += 1
            fs["times"].append(ev["time_dt"])
            if x.get("code") == 0xC0000064 or x.get("code") == 0x6:
                fs["nouser"] += 1
            if cn:
                fs["codes"][cn] += 1
            if src_name and src_ip:
                fs["name"] = src_name

    lockout_rows = []
    for key, u in users.items():
        if not u["lockouts"] and len(u["fails"]) < 3:
            continue
        times = [e["time_dt"] for e in u["lockouts"] + u["fails"]]
        caller = None
        if u["callers"]:
            caller, _ = u["callers"].most_common(1)[0]
        top_src = u["sources"].most_common(1)[0][0] if u["sources"] else None
        likely = caller if caller and caller != "(blank)" else top_src
        likely_ip = u["src_ip"].get(likely or "", "") if likely else ""
        ip_sources = [[s_, n] for s_, n in u["sources"].most_common() if re.fullmatch(r"[0-9a-fA-F:.]+", s_) and ("." in s_ or ":" in s_)]
        lockout_rows.append({"user": u["user"], "lockouts": len(u["lockouts"]), "failures": len(u["fails"]),
                             "callers": [[c, n] for c, n in u["callers"].most_common(8)], "sources": [[s, n, u["src_ip"].get(s, "")] for s, n in u["sources"].most_common(8)],
                             "codes": [[c, n] for c, n in u["codes"].most_common(5)], "likely_source": likely, "likely_ip": likely_ip,
                             "first": _fmt_t(min([t for t in times if t], default=None)), "last": _fmt_t(max([t for t in times if t], default=None)),
                             "span": _span(times), "dcs": sorted({e["computer"] for e in u["lockouts"] if e["computer"]}),
                             "ip_sources": ip_sources[:5], "logon_types": [[c, t, LOGON_TYPES.get(t, "?"), n] for (c, t), n in u["ltypes"].most_common(5)],
                             "processes": [[p, n] for p, n in u["procs"].most_common(3)]})
    lockout_rows.sort(key=lambda r: (-r["lockouts"], -r["failures"]))
    spray_sources = {k_ for k_, fs_ in fails_by_source.items() if len(fs_["users"]) >= 5}
    # Users whose only failures come from a spray source are covered by the spray finding.
    lockout_rows = [r for r in lockout_rows if r["lockouts"] or not all(s_ in spray_sources for s_, _, _ in r["sources"])]

    for idx, r in enumerate(lockout_rows[:10]):
        src = r["likely_source"] or "an unknown source"
        src_full = f"{src} ({r['likely_ip']})" if r["likely_ip"] and r["likely_ip"] != src else src
        n_fail = r["failures"]
        span = f" in {r['span']}" if r["span"] else ""
        codes = ", ".join(f"{c} ×{n}" for c, n in r["codes"][:3])
        src_short = (src or "").split(".")[0].upper()
        via_dc = src_short in dc_names and src_short != ""
        if r["lockouts"]:
            title = f"{r['user']} is being locked out by {src_full}"
            stats = f"{r['lockouts']} lockout{'s' if r['lockouts'] != 1 else ''}" + (f", {n_fail} failed-logon events" if n_fail else "") + span
            if r["callers"] and r["callers"][0][0] == "(blank)":
                detail = (f"{stats}. Event 4740 has a blank Caller Computer Name, which happens when the failing logon came through a service that doesn't pass the client name "
                          f"(Exchange/OWA/ActiveSync, ADFS, IIS, RD Gateway, VPN/NPS). The bad-password source by IP is {src_full}.")
            else:
                detail = (f"{stats}. Event 4740's Caller Computer Name is {src}: the bad passwords come from that machine. Typically a stale password in a service, scheduled task, "
                          "mapped drive, saved credential (Credential Manager), RDP session left logged in, or a phone/mail client.")
            if via_dc:
                detail += f" {src} is one of the machines that logged these events (likely a DC or server receiving the logons): the real client is connecting to it; look at the 4771/4776 Client Address / Source Workstation."
            hint = _ltype_hint(r, src_short)
            if hint:
                detail += " " + hint
            elif r["ip_sources"] and not r["likely_ip"]:
                detail += " Kerberos failures came from " + ", ".join(f"{ip} ×{n}" for ip, n in r["ip_sources"][:3]) + f" (check which machine that is: Resolve-DnsName {r['ip_sources'][0][0]})."
            if len(r["callers"]) > 1:
                detail += " Other callers: " + ", ".join(f"{c} ×{n}" for c, n in r["callers"][1:4]) + "."
            if codes:
                detail += f" Failure codes: {codes}."
            add("critical", title, detail, prio=10 + idx, headline=f"{title}: {r['lockouts']} lockout{'s' if r['lockouts'] != 1 else ''}" + (f" and {n_fail} failed-logon events" if n_fail else "") + span,
                sub=hint or "Typically a stale password in a service, scheduled task, mapped drive, saved credential or phone. Check that machine first.")
        else:
            title = f"{r['user']}: {n_fail} failed logons from {src_full}"
            add("warning", title, f"No lockout event in the data{span}. Failure codes: {codes or 'n/a'}. If these are bad passwords, the source machine has a stale or wrong credential (or someone is guessing).",
                prio=30 + idx)

    if lockout_rows and (lockout_rows[0]["lockouts"] or lockout_rows[0]["failures"] >= 5):
        r = lockout_rows[0]
        src = r["likely_source"] or "SOURCE-PC"
        u = r["user"]
        steps.append({"title": f"On {src}, find what is using {u}'s old password",
                      "detail": "Run these on the source machine. Services and scheduled tasks running as the user are the most common cause; then saved credentials and mapped drives (run cmdkey/net use as the user). "
                                "If the source is a mail, ADFS, RD Gateway or VPN server, search its logs (IIS, ADFS, NPS) for the user instead to find the real client IP.",
                      "commands": [f"Get-CimInstance Win32_Service | Where-Object StartName -like '*{u}*' | Select-Object Name, StartName, State",
                                   f"Get-ScheduledTask | Where-Object {{ $_.Principal.UserId -like '*{u}*' }} | Select-Object TaskPath, TaskName, State",
                                   "cmdkey /list", "net use",
                                   f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents 200 | Where-Object {{ $_.Message -match '{u}' }} | Select-Object -First 5 TimeCreated, Message | Format-List   # shows the Caller Process Name"]})
        steps.append({"title": f"Check and unlock {u} once the source is fixed",
                      "detail": "Unlocking before removing the stale credential just gets the account locked again.",
                      "commands": [_adu(u), f"Unlock-ADAccount -Identity {u}"]})

    # ------------------------------------------------------- password spray
    spray_rows = []
    for skey, fs in fails_by_source.items():
        nu = len(fs["users"])
        if nu >= 5:
            total = sum(fs["users"].values())
            spray_rows.append({"source": skey, "name": fs.get("name", ""), "users": nu, "attempts": total, "nonexistent": fs["nouser"], "span": _span(fs["times"]),
                               "codes": [[c, n] for c, n in fs["codes"].most_common(4)], "top_users": [u for u, _ in fs["users"].most_common(10)],
                               "succeeded": sorted(set(fs["users"]) & succ_by_ip.get(skey, set()))})
    spray_rows.sort(key=lambda r: -r["users"])
    for r in spray_rows[:5]:
        label = r["source"] + (f" ({r['name']})" if r["name"] and r["name"] != r["source"] else "")
        span = f" in {r['span']}" if r["span"] else ""
        detail = (f"{r['attempts']} failed attempts against {r['users']} different accounts{span}"
                  + (f", {r['nonexistent']} for usernames that don't exist" if r["nonexistent"] else "")
                  + ". Many accounts failing from one source is the signature of password spraying (or a misconfigured app/server using many accounts). Block or investigate the source.")
        if r["succeeded"]:
            detail += f" Successful logons (4624) from the same source for: {', '.join(r['succeeded'][:5])}. Treat those accounts as possibly compromised."
        hl = f"Password spray suspected: {label} failed logons for {r['users']} different accounts{span}"
        if r["succeeded"]:
            hl += f", then logged on successfully as {', '.join(r['succeeded'][:3])}"
        add("critical", f"Password spray suspected from {label}: {r['users']} accounts" + (f" (then a successful logon as {', '.join(r['succeeded'][:3])})" if r["succeeded"] else ""),
            detail, prio=5, headline=hl, sub=detail)
    if spray_rows:
        r = spray_rows[0]
        steps.insert(0, {"title": f"Contain the spray source {r['source']}",
                         "detail": "Identify the device (DHCP/firewall logs), block it at the firewall if it isn't a known server, and check whether any of the targeted accounts logged on successfully afterwards. Reset passwords for any that did.",
                         "commands": [f"Resolve-DnsName {r['source']} -ErrorAction SilentlyContinue", f"Test-NetConnection {r['source']}"]})
        if r["succeeded"]:
            u0 = r["succeeded"][0]
            steps.insert(1, {"title": f"Treat {', '.join(r['succeeded'][:3])} as compromised",
                             "detail": "A logon succeeded from the spraying source. Reset the password, disable the account if it isn't needed, and review what it accessed after the logon (4624 Logon ID, file/RDP activity).",
                             "commands": [f"Set-ADAccountPassword -Identity {u0} -Reset -NewPassword (Read-Host -AsSecureString 'New password')",
                                          f"Disable-ADAccount -Identity {u0}   # if the account isn't needed", _adu(u0)]})

    # ---------------------------------------------- security-relevant changes
    for ev in events:
        x, i = ev["x"], ev["id"]
        k = ev.get("kb")
        if not k:
            continue
        if i == 1102 and k["cat"] == "security":
            add("critical", f"Security log cleared on {ev['computer'] or 'this computer'} by {x.get('subject') or 'unknown'} at {_fmt_t(ev['time_dt']) or '?'}",
                "Clearing the Security log destroys audit evidence. Unless this was a planned admin action, treat it as a possible intrusion: check who the account is, what it did before, and preserve other logs.", prio=3)
        elif i == 104 and k["cat"] == "security":
            add("warning", f"Event log cleared on {ev['computer'] or 'this computer'} at {_fmt_t(ev['time_dt']) or '?'}", _first_sentence(ev["message"]) + " Confirm it was intentional.", prio=40)
        elif i == 4719:
            add("warning", f"Audit policy changed on {ev['computer'] or 'this computer'} by {_f(ev, ['SubjectUserName'], [('Subject', 'Account Name')]) or 'unknown'}",
                "Check the change was intended; attackers disable auditing to hide activity.", prio=35)
        elif i in (7045, 4697):
            path = x.get("path") or ""
            reasons = [why for rx, why in _SUSPICIOUS_SVC if rx.search(path)]
            if reasons:
                add("critical", f"Suspicious service installed: {x.get('service') or '?'} on {ev['computer'] or '?'}",
                    f"Service file: {path}. It {'; it '.join(reasons)}. Attackers (and tools like PsExec/Cobalt Strike) install services this way to run code as SYSTEM. Verify who installed it and what the file is.", prio=4)
            elif re.search(r"psexesvc", path + (x.get("service") or ""), re.I):
                add("info", f"PsExec service installed on {ev['computer'] or '?'}", "PSEXESVC means someone ran PsExec against this machine. Fine if it was an admin; otherwise investigate.", prio=60)
        elif i in (4728, 4732, 4756) and (x.get("group") or "").lower() in PRIV_GROUPS:
            add("warning", f"{x.get('member') or '?'} added to privileged group {x.get('group')} by {x.get('subject') or '?'}",
                f"At {_fmt_t(ev['time_dt']) or '?'} on {ev['computer'] or '?'}. Confirm this change was approved; adding accounts to admin groups is a common persistence step.", prio=20)
        elif i == 4726:
            pass

    # ----------------------------------------------------------- crashes
    by_comp: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        k = ev.get("kb")
        if k and k["cat"] in ("crash", "hardware", "storage", "power"):
            by_comp[ev["computer"] or "(this computer)"].append(ev)
    crash_rows = []
    for comp, evs in by_comp.items():
        evs.sort(key=lambda e: e["time_dt"] or datetime.min)
        incidents: list[dict] = []
        for ev in evs:
            if ev["kb"]["cat"] != "crash":
                continue
            t = ev["time_dt"]
            inc = None
            for cand in incidents:
                if t and cand["t"] and abs((t - cand["t"]).total_seconds()) <= 900:
                    inc = cand
                    break
            if inc is None:
                inc = {"t": t, "events": [], "bugcheck": None, "params": None, "power_button": False}
                incidents.append(inc)
            inc["events"].append(ev)
            bc = ev["x"].get("bugcheck")
            if bc:
                inc["bugcheck"] = bc
                if ev["x"].get("params"):
                    inc["params"] = ev["x"]["params"]
            if ev["x"].get("power_button"):
                inc["power_button"] = True
            if t and inc["t"] and t < inc["t"]:
                inc["t"] = t
        hw = [e for e in evs if e["kb"]["cat"] == "hardware"]
        st = [e for e in evs if e["kb"]["cat"] == "storage" and not (e["id"] == 98 and e["x"].get("healthy"))]
        for inc in incidents:
            t = inc["t"]
            inc["hw_before"] = [e for e in hw if t and e["time_dt"] and timedelta(0) <= t - e["time_dt"] <= timedelta(hours=24)] if t else []
            inc["st_before"] = [e for e in st if t and e["time_dt"] and timedelta(0) <= t - e["time_dt"] <= timedelta(hours=24)] if t else []
        if not incidents and not hw and not st:
            continue
        codes = Counter(inc["bugcheck"] for inc in incidents if inc["bugcheck"])
        no_bc = [inc for inc in incidents if not inc["bugcheck"]]
        crash_rows.append({"computer": comp, "incidents": [{"time": _fmt_t(inc["t"]), "bugcheck": _hex(inc["bugcheck"]) if inc["bugcheck"] else None,
                                                            "bugcheck_name": kb.BUGCHECK.get(inc["bugcheck"] or -1, {}).get("name"),
                                                            "params": inc["params"], "power_button": inc["power_button"],
                                                            "events": sorted({e["id"] for e in inc["events"]}), "hw_before": len(inc["hw_before"]), "storage_before": len(inc["st_before"])}
                                                           for inc in incidents],
                           "bugchecks": [[_hex(c), kb.BUGCHECK.get(c, {}).get("name"), n] for c, n in codes.most_common()], "hardware": len(hw), "storage": len(st)})
        comp_label = comp if comp != "(this computer)" else "This computer"
        comp_step = comp if comp != "(this computer)" else "this computer"
        if codes:
            top, n_top = codes.most_common(1)[0]
            e = kb.BUGCHECK.get(top)
            nm = e["name"] if e else "a bug check not in the knowledge base"
            total = sum(codes.values())
            if len(codes) == 1:
                head = f"{comp_label} crashed {total} time{'s' if total != 1 else ''} with bug check {_hex(top)} {nm if e else ''}".rstrip()
            else:
                head = f"{comp_label} crashed {total} times: " + ", ".join(f"{_hex(c)}{' ' + kb.BUGCHECK[c]['name'] if c in kb.BUGCHECK else ''} ×{n}" for c, n in codes.most_common(3))
            hw_inc = sum(1 for inc in incidents if inc["bugcheck"] and inc["hw_before"])
            detail = (_first_sentence(e["meaning"]) if e else f"Bug check {_hex(top)} isn't in the knowledge base; the dump analysis (!analyze -v) will name it and the likely driver.") + (
                f" WHEA hardware errors were logged in the 24h before {hw_inc} of these crashes, which points at hardware." if hw_inc else "")
            if len(codes) > 2:
                detail += " Several different bug check codes on one machine usually means hardware (RAM/CPU/PSU) or a driver corrupting memory, rather than one specific bug."
            add("critical", head, detail, prio=15, headline=head, sub=detail)
            steps.append({"title": f"Analyze the crash dump on {comp_step}",
                          "detail": "Copy the newest dump (C:\\Windows\\Minidump\\*.dmp or MEMORY.DMP) to an admin workstation, open it in WinDbg and run !analyze -v. "
                                    + (" ".join(e.get("fixes", [])[:1]) if e else ""),
                          "commands": [kb._DUMPS, "!analyze -v   # in WinDbg"] + [c for c in (e.get("commands", []) if e else []) if c not in (kb._WINDBG, kb._DUMPS)][:3]})
        if no_bc:
            pb = sum(1 for inc in no_bc if inc["power_button"])
            hw_inc = sum(1 for inc in no_bc if inc["hw_before"])
            head = f"{comp_label} shut down unexpectedly {len(no_bc)} time{'s' if len(no_bc) != 1 else ''} with no bug check recorded"
            detail = ("No blue screen was recorded for " + ("it" if len(no_bc) == 1 else "them") + " (no BugCheck 1001 event and no bug check code in event 41), so the machine most likely lost power, was forced off, or hung so hard it couldn't write a dump."
                      + (f" The power button was held during {pb} of them." if pb else "")
                      + (f" WHEA hardware errors preceded {hw_inc} of them." if hw_inc else "")
                      + " Check the power supply/UPS and PDU logs, the hypervisor/host logs for VMs, BIOS/BMC (iLO/iDRAC) event logs, and whether a dump is configured.")
            add("critical" if len(no_bc) > 1 or hw_inc else "warning", head, detail, prio=18)
            steps.append({"title": f"Find out why {comp_step} lost power or hung",
                          "detail": "Check the hardware management log (iLO/iDRAC/BMC) and UPS for power events; for VMs check the host. Make sure a dump is configured so the next crash leaves evidence.",
                          "commands": ["Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl | Select-Object CrashDumpEnabled, DumpFile, AutoReboot",
                                       "Get-CimInstance Win32_PageFileUsage | Select-Object Name, AllocatedBaseSize"]})
        if hw:
            fatal = [e for e in hw if e["id"] == 18]
            comps = Counter((e["x"].get("component") or "unknown component") for e in hw)
            head = f"{comp_label}: {len(hw)} WHEA hardware error{'s' if len(hw) != 1 else ''}" + (f" ({len(fatal)} fatal)" if fatal else "")
            detail = "Components: " + ", ".join(f"{c} ×{n}" for c, n in comps.most_common(4)) + ". " + (
                "Fatal hardware errors crash the machine (bug check 0x124). Update BIOS/firmware, remove overclocking, and run the vendor's hardware diagnostics." if fatal else
                "Corrected errors didn't crash anything yet, but a steady stream on the same component predicts a failure. Update firmware and check that component.")
            add("critical" if fatal else "warning", head, detail, prio=16 if fatal else 25)
            steps.append({"title": f"Investigate the hardware errors on {comp_step}", "detail": "Read the full WHEA events (component, bus/device, error type) and compare with the vendor's diagnostics.",
                          "commands": [kb._WHEA]})
        if st:
            ids = Counter(e["id"] for e in st)
            names = {7: "bad block", 11: "controller error", 51: "paging error", 153: "I/O retried", 157: "disk surprise removed", 129: "storage reset/timeout", 55: "NTFS corruption", 98: "NTFS needs chkdsk"}
            head = f"{comp_label}: storage errors (" + ", ".join(f"{names.get(i, i)} ×{n}" for i, n in ids.most_common(4)) + ")"
            sev = "critical" if any(i in ids for i in (7, 11, 55, 157)) else "warning"
            add(sev, head, "Disk, controller or storage-path problems. These also cause hangs, 0x7A/0xF4/0x154 bug checks and file corruption. Check disk health, firmware and (for VMs/SAN) storage latency.",
                prio=17 if sev == "critical" else 26)
            steps.append({"title": f"Check the disks on {comp_step}", "detail": "Look at the reliability counters and SMART status, then run an online chkdsk scan.",
                          "commands": [kb._DISK_HEALTH, "Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, FirmwareVersion", "chkdsk C: /scan"]})

    planned = [e for e in events if e["id"] == 1074 and e.get("kb") and e["kb"]["cat"] == "power"]
    if planned:
        who = Counter(f"{e['x'].get('user') or '?'} via {(e['x'].get('process') or '?').split(chr(92))[-1]}" for e in planned)
        add("info", f"{len(planned)} planned restart{'s' if len(planned) != 1 else ''}/shutdown{'s' if len(planned) != 1 else ''} (event 1074)",
            "Initiated by: " + ", ".join(f"{w} ×{n}" for w, n in who.most_common(4)) + ". These were clean, intended restarts (e.g. Windows Update via TrustedInstaller/MoUsoCoreWorker, or an admin).", prio=80)

    # ---------------------------------------------------------- services
    svc = Counter()
    svc_comp: dict[str, set] = defaultdict(set)
    svc_logon = []
    for ev in events:
        k = ev.get("kb")
        if k and k["cat"] == "service" and ev["id"] in (7031, 7034, 7023, 7024, 7000, 7009, 7011):
            name = ev["x"].get("service") or "?"
            svc[(name, "crash" if ev["id"] in (7031, 7034) else "fail")] += 1
            svc_comp[name].add(ev["computer"])
        if k and ev["id"] in (7038, 7041):
            svc_logon.append(ev)
    for (name, kind), n in svc.most_common(6):
        if kind == "crash":
            add("warning" if n < 5 else "critical", f"Service '{name}' crashed {n} time{'s' if n != 1 else ''}",
                "Check the Application log for an Application Error (1000) or .NET Runtime (1026) event from the service's process at the same time; update or repair the product.", prio=40)
        else:
            add("warning", f"Service '{name}' failed to start or stopped with an error ({n}×)", "The error text is in the event message; look it up in the Error Code Lookup if it has a code.", prio=45)
    for ev in svc_logon[:5]:
        x = ev["x"]
        add("critical", f"Service '{x.get('service') or '?'}' can't log on as {x.get('account') or 'its account'}",
            "The service has a wrong/expired password or lacks the 'Log on as a service' right. A stale service password also locks the account out repeatedly. Update the password on the service or move to a gMSA.", prio=12)

    # ---------------------------------------------------------- apps
    apps = Counter()
    for ev in events:
        if ev["id"] == 1000 and ev.get("kb") and ev["kb"]["cat"] == "app" and ev["x"].get("app"):
            apps[(ev["x"]["app"], ev["x"].get("module") or "?", ev["x"].get("exc") or "?")] += 1
    for (app, mod, exc), n in apps.most_common(3):
        exc_i = _code_int(exc)
        en = kb.NTSTATUS.get(exc_i) if exc_i is not None else None
        add("warning", f"{app} crashed {n} time{'s' if n != 1 else ''} in {mod} ({exc}{' ' + en['name'] if en else ''})",
            (_first_sentence(en["meaning"]) + " " if en else "") + f"The faulting module {mod} is where it broke: update/repair that application or the third-party DLL.", prio=50)

    # ------------------------------------------------- GP / netlogon / time / kerberos
    misc = Counter()
    misc_sample: dict[int, dict] = {}
    for ev in events:
        k = ev.get("kb")
        if k and k["cat"] in ("gp", "netlogon", "kerberos", "time", "update") and k["sev"] != "info":
            misc[ev["id"]] += 1
            misc_sample.setdefault(ev["id"], ev)
    for i, n in misc.most_common():
        ev = misc_sample[i]
        k = ev["kb"]
        extra = ""
        if i == 3 and ev["x"].get("code") is not None:
            ke = kb.KERBEROS.get(ev["x"]["code"])
            extra = f" Error 0x{ev['x']['code']:X} {ke['name'] + ': ' + _first_sentence(ke['meaning']) if ke else ''}"
        if i == 20 and ev["x"].get("code") is not None:
            extra = f" Error {_hex(ev['x']['code'])}: see the Error Code Lookup for the fix."
        if i == 5719 and n == 1:
            sev = "info"
        else:
            sev = k["sev"]
        add(sev, f"{k['title']} (event {i}{', ' + str(n) + '×' if n > 1 else ''})", k["meaning"] + extra, prio=55)
        if i in (5719, 3210, 5722, 5805, 1129, 1053):
            if not any(s["title"].startswith("Check domain connectivity") for s in steps):
                steps.append({"title": "Check domain connectivity and the secure channel", "detail": "Run these on the affected member computer.",
                              "commands": [kb._DSGETDC, kb._SECURE_CHANNEL, "Test-ComputerSecureChannel -Repair -Credential (Get-Credential)", "gpupdate /force"]})
        if i in (3, 36) and not any(s["title"].startswith("Fix time") for s in steps):
            steps.append({"title": "Fix time synchronisation", "detail": "Members sync from DCs; the PDC emulator should sync from a reliable external source.",
                          "commands": ["w32tm /query /status", "w32tm /query /source", "w32tm /resync /force"]})

    if any(e["id"] == 10016 for e in events):
        n = sum(1 for e in events if e["id"] == 10016)
        add("info", f"DCOM 10016 warnings ({n}×) are noise", "Microsoft documents DistributedCOM 10016 events as expected and safe to ignore. Don't spend time on them.", prio=95)

    # ---------------------------------------------------------- groups
    groups: dict[tuple, dict] = {}
    for ev in events:
        k = ev.get("kb")
        key = (ev["id"], _norm_provider(ev["provider"]) or (k["title"] if k else ""))
        g = groups.get(key)
        if not g:
            g = groups[key] = {"id": ev["id"], "provider": ev["provider"], "title": k["title"] if k else None, "severity": k["sev"] if k else "info",
                               "meaning": k["meaning"] if k else None, "known": bool(k), "noise": bool(k and k["noise"]), "count": 0, "first": None, "last": None,
                               "sample": _summary(ev), "computers": set()}
        g["count"] += 1
        t = ev["time_dt"]
        if t:
            g["first"] = min(filter(None, [g["first"], t])) if g["first"] else t
            g["last"] = max(filter(None, [g["last"], t])) if g["last"] else t
        if ev["computer"]:
            g["computers"].add(ev["computer"])
        if k and k["sev"] == "info" and ev["id"] == 4625:
            pass
    sev_rank = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    group_list = sorted(groups.values(), key=lambda g: (g["noise"], sev_rank.get(g["severity"], 9), -g["count"]))
    for g in group_list:
        g["first"], g["last"] = _fmt_t(g["first"]), _fmt_t(g["last"])
        g["computers"] = sorted(g["computers"])[:5]

    # ---------------------------------------------------------- timeline
    notable = []
    for ev in events:
        k = ev.get("kb")
        if not k or k["noise"]:
            continue
        if k["cat"] == "auth" and ev["id"] not in (4740,):
            continue
        if k["sev"] == "info" and k["cat"] not in ("power", "crash", "security", "account"):
            continue
        sev = k["sev"]
        if ev["id"] == 98 and ev["x"].get("healthy"):
            sev = "info"
        notable.append({"time": _fmt_t(ev["time_dt"]) or ev["time_raw"], "computer": ev["computer"], "id": ev["id"], "provider": ev["provider"], "severity": sev,
                        "title": k["title"], "summary": _summary(ev)})
    timeline_truncated = len(notable) > 400
    notable = notable[-400:]

    # ---------------------------------------------------------- verdict
    counts = Counter(e["id"] for e in events)
    known = sum(1 for e in events if e.get("kb"))
    times = [e["time_dt"] for e in events if e["time_dt"]]
    if headline_candidates:
        order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
        best = sorted(headline_candidates, key=lambda h: (order[h[1]], h[0]))[0]
        sev, headline, sub = best[1], best[2], best[3]
        if sev == "info":
            sev = "ok" if not any(f["severity"] in ("critical", "warning") for f in findings) else sev
            headline = f"No problems found in {len(events)} events" if sev == "ok" else headline
            sub = "Nothing critical: " + "; ".join(f["title"] for f in findings[:3]) if sev == "ok" else sub
    else:
        sev, headline = "ok", f"No problems found in {len(events)} events"
        sub = "None of the events matched a known problem pattern. Unknown event IDs are listed below with their messages."
    n_crit = sum(1 for f in findings if f["severity"] == "critical")
    n_warn = sum(1 for f in findings if f["severity"] == "warning")

    facts = [["Events", str(len(events))], ["Format", fmt], ["Time range", f"{_fmt_t(min(times))} → {_fmt_t(max(times))}" if times else None],
             ["Computers", ", ".join(c for c, _ in computers.most_common(3)) + (f" +{len(computers) - 3}" if len(computers) > 3 else "") if computers else None],
             ["Known event types", f"{known}/{len(events)} events"],
             ["Times shown in", "UTC" if fmt.startswith(("JSON", "XML")) else "the exporting machine's local time"]]

    ev_out = []
    for ev in events[-3000:]:
        k = ev.get("kb")
        ev_out.append({"time": _fmt_t(ev["time_dt"]) or ev["time_raw"], "id": ev["id"], "provider": ev["provider"], "log": ev["log"], "computer": ev["computer"],
                       "level": ev["level"], "title": k["title"] if k else None, "severity": (k["sev"] if k else "info"), "summary": _summary(ev),
                       "message": ev["message"][:4000]})

    return {"severity": sev, "headline": headline, "subline": sub, "counts": {"critical": n_crit, "warning": n_warn}, "facts": facts,
            "findings": findings, "steps": steps[:6], "lockouts": lockout_rows[:50], "spray": spray_rows[:20], "crashes": crash_rows,
            "timeline": notable, "timeline_truncated": timeline_truncated, "groups": group_list, "events": ev_out,
            "parse": {"format": fmt, "count": len(events), "truncated": truncated, "events_shown": len(ev_out), "ids": dict(counts.most_common(30))}}


_LTYPE_HINT = {
    4: "a scheduled task is running as {u} with an old password",
    5: "a service is configured to run as {u} with an old password",
    3: "something is connecting over the network with {u}'s old password (mapped drive, app, script or file share access)",
    2: "someone is typing the wrong password at the console",
    7: "a session left open from before the password change is being unlocked with the old password",
    8: "an application is sending {u}'s old password in clear text (e.g. IIS basic authentication)",
    10: "a Remote Desktop connection is using an old saved password",
    11: "cached credentials are being used with an old password",
}


def _ltype_hint(r: dict, src_short: str) -> str:
    """Turn the 4625 logon types seen on the source machine into a plain-language cause."""
    lts = [lt for lt in r.get("logon_types", []) if not src_short or lt[0] == src_short] or r.get("logon_types", [])
    if not lts:
        return ""
    comp, t, desc, n = lts[0]
    tmpl = _LTYPE_HINT.get(t)
    if not tmpl:
        return ""
    proc = f" (caller process {r['processes'][0][0]})" if r.get("processes") else ""
    return f"{comp} logs failed logon type {t} ({desc.split(' (')[0]}){proc}: {tmpl.format(u=r['user'])}."


def _adu(u: str) -> str:
    return kb._ADUSER.replace("jsmith", u)
