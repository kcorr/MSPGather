"""Values from pasted logs, headers, certificates and DNS end up in copy-paste
PowerShell/openssl commands. Only well-formed values may be interpolated; anything
else is replaced by a placeholder so a crafted input can't smuggle in a command."""
from __future__ import annotations

import ipaddress
import re

_EMAIL = re.compile(r"[A-Za-z0-9._+'-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+")
_DNS = re.compile(r"(?:\*\.)?[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)*")
_HOST_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
_URL = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~%/+\-=&?]*)?")


def ps_quote(value: str) -> str:
    """PowerShell single-quoted literal: no variable or subexpression expansion."""
    return "'" + str(value).replace("'", "''") + "'"


def email(value: str, placeholder: str = "user@contoso.com") -> str:
    return value if value and _EMAIL.fullmatch(value) else placeholder


def dns_name(value: str, placeholder: str = "www.contoso.com") -> str:
    return value if value and len(value) <= 253 and _DNS.fullmatch(value) else placeholder


def host_label(value: str, placeholder: str = "PC01") -> str:
    return value if value and _HOST_LABEL.fullmatch(value) else placeholder


def url(value: str) -> str | None:
    return value if value and len(value) <= 2000 and _URL.fullmatch(value) else None


def ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None
