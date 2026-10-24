"""Outbound-connection safety policy, shared by every tool that connects to a
user-supplied host.

Always refused: loopback, link-local (incl. 169.254.169.254 and other cloud
metadata addresses), multicast, unspecified and reserved addresses.
Private (RFC 1918 / CGNAT / ULA) targets are refused when the caller asks for
public-only, or everywhere when MSPGATHER_ALLOW_PRIVATE_TARGETS=false.

Callers must connect to the returned IP (not re-resolve the name) so a second
DNS answer can't redirect the connection somewhere internal.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import time
import zlib
from functools import lru_cache

ALLOW_PRIVATE_TARGETS = os.environ.get("MSPGATHER_ALLOW_PRIVATE_TARGETS", "true").strip().lower() not in ("0", "false", "no", "off")


@lru_cache(maxsize=1)
def denied_networks() -> tuple:
    """Always-refused networks besides the built-in classes: inside a container, the
    Docker/Podman host gateway (reaching it = reaching services bound to the host's
    loopback), plus anything listed in MSPGATHER_DENY_NETS (comma-separated CIDRs)."""
    nets = []
    for item in os.environ.get("MSPGATHER_DENY_NETS", "").split(","):
        if item.strip():
            try:
                nets.append(ipaddress.ip_network(item.strip(), strict=False))
            except ValueError:
                pass
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        for name in ("host.docker.internal", "gateway.docker.internal", "host.containers.internal"):
            try:
                for info in socket.getaddrinfo(name, None):
                    nets.append(ipaddress.ip_network(info[4][0].split("%")[0]))
            except (OSError, ValueError):
                pass
        try:  # default gateway from the kernel routing table
            with open("/proc/net/route") as fh:
                for line in fh.readlines()[1:]:
                    f = line.split()
                    if len(f) > 2 and f[1] == "00000000":
                        nets.append(ipaddress.ip_network(socket.inet_ntoa(bytes.fromhex(f[2])[::-1])))
        except (OSError, ValueError):
            pass
    return tuple(dict.fromkeys(nets))


def read_capped(resp, max_bytes: int, deadline: float) -> tuple[bytes, bool]:
    """Read an httpx streaming response body with hard limits on decoded size and
    wall-clock time. Decompresses at most one gzip/deflate layer ourselves, with a
    bounded output per chunk (httpx's own decoders expand a whole chunk at once and
    stack 'gzip, gzip'). Returns (body, truncated)."""
    enc = [e.strip().lower() for e in resp.headers.get("content-encoding", "").split(",") if e.strip() and e.strip().lower() != "identity"]
    if len(enc) > 1 or (enc and enc[0] not in ("gzip", "x-gzip", "deflate")):
        return b"", True  # unsupported or stacked encodings: don't decode
    d = zlib.decompressobj(16 + zlib.MAX_WBITS if enc and enc[0] != "deflate" else zlib.MAX_WBITS) if enc else None
    body = bytearray()
    try:
        for raw in resp.iter_raw():
            if d is None:
                body += raw
            else:
                body += d.decompress(raw, max_bytes - len(body) + 1)
                while d.unconsumed_tail and len(body) <= max_bytes:
                    body += d.decompress(d.unconsumed_tail, max_bytes - len(body) + 1)
            if len(body) > max_bytes or time.monotonic() > deadline:
                return bytes(body[:max_bytes]), True
    except zlib.error:
        return bytes(body[:max_bytes]), True
    return bytes(body), False


def resolve_safe(host: str, allow_private: bool = True) -> list[str]:
    """Resolve host and return its IPs (IPv4 first), or raise ValueError with a
    human-readable refusal."""
    from ..modules.netdiag import _resolve_safe  # single implementation lives with the network tools
    return _resolve_safe(host, allow_private)


def refusal(ip: str, allow_private: bool = True) -> str | None:
    """Why this IP must not be connected to, or None."""
    from ..modules.netdiag import _refusal
    return _refusal(ip, allow_private)
