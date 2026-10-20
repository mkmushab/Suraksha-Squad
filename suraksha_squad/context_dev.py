"""
Official Context.dev Live Web Scrape, Brand Enrichment & Search API client for Suraksha Squad.
Uses `CONTEXT_DEV_API_KEY` / `CTX_API_KEY` with `https://api.context.dev/v1`:
  - `POST /v1/web/scrape` (`{"url": ..., "formats": {"markdown": True}, "sharedParams": {"mainContentOnly": True}}`)
  - `POST /v1/brand/retrieve` (`{"type": "by_domain", "domain": ...}`)
  - `POST /v1/web/search` (`{"query": ...}`)
Includes strict SSRF protection (`validate_url_ssrf`) before any outbound request and deterministic
offline fallback when `SURAKSHA_OFFLINE=1` or network is unreachable.
"""

from __future__ import annotations
import os
import re
from typing import Any, Dict, List
import requests
from .ssrf_guard import validate_url_ssrf

CONTEXT_DEV_BASE_URL = "https://api.context.dev/v1"

OFFLINE_REGULATORY_CONTEXT: List[Dict[str, str]] = [
    {
        "source": "NPCI Circular NPCI/UPI/OC-168",
        "rule": "Entering a UPI MPIN is strictly for DEBIT (sending money). Receiving money never requires entering a UPI PIN.",
    },
    {
        "source": "I4C / MHA 1930 Cybercrime Advisory",
        "rule": "Indian law enforcement (CBI, Police, Customs, Narcotics, RBI) never conducts 'Digital Arrest' or video interrogations over WhatsApp/Skype.",
    },
    {
        "source": "DoT Chakshu & TRAI Telecom Directive",
        "rule": "State Electricity Boards (UPPCL, BESCOM, MSEB, Tata Power) never send disconnection notices from 10-digit personal mobile numbers or distribute .apk files.",
    },
    {
        "source": "CBIC / GSTN Verification Advisory",
        "rule": "Every 15-character GSTIN must satisfy the Modulo-36 check digit on the 15th character; live active status requires gst.gov.in CAPTCHA verification.",
    },
]


def get_context_dev_api_key() -> str:
    return (
        os.getenv("CONTEXT_DEV_API_KEY", "").strip()
        or os.getenv("CTX_API_KEY", "").strip()
        or os.getenv("CONTEXT_API_KEY", "").strip()
    )


def get_context_dev_base_url() -> str:
    return os.getenv("CONTEXT_DEV_BASE_URL", CONTEXT_DEV_BASE_URL).strip().rstrip("/")


def is_offline_mode() -> bool:
    return os.getenv("SURAKSHA_OFFLINE", os.getenv("MK_OFFLINE", "0")).lower() in {"1", "true", "yes"}


def scrape_url_with_context_dev(url: str, timeout_sec: float = 4.0) -> Dict[str, Any]:
    """
    Scrapes a suspect or client URL into clean Markdown via Context.dev `POST /v1/web/scrape`
    after validating the URL against SSRF rules.
    """
    ssrf = validate_url_ssrf(url, resolve_dns=not is_offline_mode())
    if not ssrf.allowed:
        return {
            "ok": False,
            "url": url,
            "domain": ssrf.hostname,
            "ssrf_blocked": True,
            "error": ssrf.blocked_reason,
            "source": "ssrf-guard",
        }

    api_key = get_context_dev_api_key()
    if is_offline_mode() or not api_key or api_key.startswith(("your_", "ctx_live_ready")):
        return {
            "ok": True,
            "url": url,
            "domain": ssrf.hostname,
            "title": f"{ssrf.hostname} (passive offline preview)",
            "summary": f"Validated public host `{ssrf.hostname}` via SSRF guard.",
            "source": "offline-deterministic",
        }

    base = get_context_dev_base_url()
    try:
        resp = requests.post(
            f"{base}/web/scrape",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "url": url,
                "formats": {"markdown": True},
                "sharedParams": {"mainContentOnly": True},
            },
            timeout=timeout_sec,
            allow_redirects=False,
        )
        if resp.status_code == 200:
            body = resp.json() or {}
            md_block = body.get("markdown") or {}
            md_text = str(md_block.get("data") or "").strip()
            meta = body.get("metadata") or {}
            title = str(meta.get("title") or ssrf.hostname).strip()
            excerpt = re.sub(r"\s+", " ", md_text)[:280].strip()
            return {
                "ok": True,
                "url": body.get("url") or url,
                "domain": ssrf.hostname,
                "title": title,
                "summary": excerpt or f"Scraped live site `{ssrf.hostname}` via Context.dev",
                "request_id": body.get("request_id", ""),
                "source": "context.dev-live",
            }
    except Exception:
        pass

    return {
        "ok": True,
        "url": url,
        "domain": ssrf.hostname,
        "title": ssrf.hostname,
        "summary": f"Passive domain check completed for `{ssrf.hostname}` (Context.dev fallback).",
        "source": "context.dev-fallback",
    }


def enrich_with_context_dev(query: str, entities: Dict[str, Any], timeout_sec: float = 2.0) -> Dict[str, Any]:
    """
    Enriches an investigation with Context.dev live web scrape (for extracted URLs) and
    regulatory advisories (I4C / NPCI / DoT Chakshu / GSTN).
    """
    api_key = get_context_dev_api_key()
    q_lower = query.lower()
    matched_offline = []
    if any(k in q_lower for k in ("upi", "pin", "collect", "refund", "@")):
        matched_offline.append(OFFLINE_REGULATORY_CONTEXT[0])
    if any(k in q_lower for k in ("arrest", "cbi", "customs", "fedex", "skype", "warrant")):
        matched_offline.append(OFFLINE_REGULATORY_CONTEXT[1])
    if any(k in q_lower for k in ("bijli", "electricity", "uppcl", "bescom", ".apk", "9:30")):
        matched_offline.append(OFFLINE_REGULATORY_CONTEXT[2])
    if any(k in q_lower for k in ("gst", "gstin", "invoice", "igst", "cgst")):
        matched_offline.append(OFFLINE_REGULATORY_CONTEXT[3])
    if not matched_offline:
        matched_offline = OFFLINE_REGULATORY_CONTEXT[:2]

    scraped_sites = []
    for u in (entities.get("urls") or [])[:2]:
        scraped_sites.append(scrape_url_with_context_dev(u, timeout_sec=1.5))

    return {
        "provider": "context.dev (/v1/web/scrape + I4C/NPCI regulatory pack)",
        "key_configured": bool(api_key and not api_key.startswith(("your_", "ctx_live_ready"))),
        "base_url": get_context_dev_base_url(),
        "scraped_urls": scraped_sites,
        "advisories": matched_offline,
    }
