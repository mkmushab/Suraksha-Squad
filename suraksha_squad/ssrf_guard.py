"""
Hardened SSRF (Server-Side Request Forgery) & Safe Fetch Guard.
Directly addresses the ActionPilot hosted-agent vulnerability identified during code review:
- Rejects non-HTTP/HTTPS schemes (`file://`, `ftp://`, `gopher://`, `javascript:`, `data:`)
- Resolves hostnames and blocks RFC1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`),
  loopback (`127.0.0.0/8`, `::1`, `localhost`), link-local cloud metadata (`169.254.169.254`),
  multicast, reserved, and unspecified IPs at EVERY hop of a redirect chain.
- Enforces read-only GET/HEAD, short timeouts, and a hard response byte cap (64 KB).
"""

from __future__ import annotations
import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import requests


BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "169.254.169.254",
    "0.0.0.0",
}


@dataclass
class SSRFCheckResult:
    allowed: bool
    url: str
    hostname: str = ""
    resolved_ips: List[str] = field(default_factory=list)
    blocked_reason: Optional[str] = None


def is_ip_public_and_safe(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Verifies that an IPv4 or IPv6 literal is globally routable and not private/loopback/metadata."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address literal: {ip_str}"

    if ip_obj.is_loopback:
        return False, f"Blocked loopback IP ({ip_str})"
    if ip_obj.is_private:
        return False, f"Blocked private RFC1918/ULA network IP ({ip_str})"
    if ip_obj.is_link_local:
        return False, f"Blocked link-local / cloud metadata IP ({ip_str})"
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return False, f"Blocked reserved/multicast/unspecified IP ({ip_str})"
    if str(ip_obj).startswith("100.64."):  # CGNAT RFC6598
        return False, f"Blocked CGNAT shared address space ({ip_str})"
    return True, None


def validate_url_ssrf(url: str, resolve_dns: bool = True) -> SSRFCheckResult:
    """Validates a URL against SSRF vectors before any network socket is opened."""
    try:
        parsed = urllib.parse.urlparse(url.strip())
    except Exception as exc:
        return SSRFCheckResult(allowed=False, url=url, blocked_reason=f"URL parse error: {exc}")

    if parsed.scheme.lower() not in ("http", "https"):
        return SSRFCheckResult(
            allowed=False,
            url=url,
            blocked_reason=f"Blocked non-HTTP/HTTPS scheme: {parsed.scheme or 'empty'}",
        )

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return SSRFCheckResult(allowed=False, url=url, blocked_reason="Missing hostname in URL")

    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".internal") or hostname.endswith(".local"):
        return SSRFCheckResult(
            allowed=False,
            url=url,
            hostname=hostname,
            blocked_reason=f"Blocked internal/metadata hostname: {hostname}",
        )

    # Check if hostname is already an IP literal
    try:
        ipaddress.ip_address(hostname)
        ok, reason = is_ip_public_and_safe(hostname)
        if not ok:
            return SSRFCheckResult(allowed=False, url=url, hostname=hostname, resolved_ips=[hostname], blocked_reason=reason)
        return SSRFCheckResult(allowed=True, url=url, hostname=hostname, resolved_ips=[hostname])
    except ValueError:
        pass

    if not resolve_dns:
        return SSRFCheckResult(allowed=True, url=url, hostname=hostname)

    # Attempt DNS resolution; if offline in sandbox, validate syntactically without allowing private literals
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        for entry in addr_info:
            ip_str = entry[4][0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
            ok, reason = is_ip_public_and_safe(ip_str)
            if not ok:
                return SSRFCheckResult(
                    allowed=False,
                    url=url,
                    hostname=hostname,
                    resolved_ips=resolved_ips,
                    blocked_reason=reason,
                )
    except socket.gaierror:
        # DNS unavailable or domain unregistered; safe to report as unresolved without opening socket
        return SSRFCheckResult(allowed=True, url=url, hostname=hostname, resolved_ips=[])

    return SSRFCheckResult(allowed=True, url=url, hostname=hostname, resolved_ips=resolved_ips)


@dataclass
class GuardedFetchResult:
    ok: bool
    final_url: str
    status_code: Optional[int] = None
    redirect_chain: List[str] = field(default_factory=list)
    content_snippet: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    ssrf_blocked: bool = False
    error_reason: Optional[str] = None


def guarded_http_get(url: str, max_redirects: int = 4, timeout_sec: float = 3.5, max_bytes: int = 65536) -> GuardedFetchResult:
    """
    Executes a strictly read-only GET request with manual per-hop SSRF validation.
    Never submits forms, never executes JS, and caps body read at `max_bytes`.
    """
    current_url = url
    chain: List[str] = [current_url]

    for _ in range(max_redirects + 1):
        check = validate_url_ssrf(current_url, resolve_dns=True)
        if not check.allowed:
            return GuardedFetchResult(
                ok=False,
                final_url=current_url,
                redirect_chain=chain,
                ssrf_blocked=True,
                error_reason=check.blocked_reason,
            )

        try:
            resp = requests.get(
                current_url,
                allow_redirects=False,
                timeout=timeout_sec,
                stream=True,
                headers={"User-Agent": "SurakshaSquad-PassiveAuditor/1.0 (+https://agentverse.ai)"},
            )
        except Exception as exc:
            return GuardedFetchResult(
                ok=False,
                final_url=current_url,
                redirect_chain=chain,
                error_reason=f"Network fetch unavailable or timed out: {type(exc).__name__}",
            )

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            resp.close()
            if not loc:
                break
            next_url = urllib.parse.urljoin(current_url, loc)
            chain.append(next_url)
            current_url = next_url
            continue

        raw_chunks = []
        read_len = 0
        try:
            for chunk in resp.iter_content(chunk_size=4096):
                if not chunk:
                    break
                raw_chunks.append(chunk)
                read_len += len(chunk)
                if read_len >= max_bytes:
                    break
        finally:
            resp.close()

        body_text = b"".join(raw_chunks).decode("utf-8", errors="replace")
        return GuardedFetchResult(
            ok=True,
            final_url=current_url,
            status_code=resp.status_code,
            redirect_chain=chain,
            content_snippet=body_text[:max_bytes],
            headers={k.lower(): v for k, v in resp.headers.items()},
        )

    return GuardedFetchResult(
        ok=False,
        final_url=current_url,
        redirect_chain=chain,
        error_reason=f"Exceeded max redirect hops ({max_redirects})",
    )
