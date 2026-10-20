"""
Deterministic entity extraction from Hindi / Hinglish / English user messages:
Extracts URLs, UPI IDs (VPAs), IFSC codes, 15-char GSTINs, Indian phone numbers, and email headers.
"""

from __future__ import annotations
import re
from typing import List, Optional
from .models import InvestigationRequest


URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\]\)]+|(?:[a-zA-Z0-9-]+\.)+(?:in|com|org|net|gov\.in|co\.in|sbi|xyz|top|click|buzz|loan|work|apk|ngrok-free\.app|trycloudflare\.com|bit\.ly|tinyurl\.com)(?:/[^\s<>\"'\]\)]*)?",
    re.IGNORECASE,
)

UPI_REGEX = re.compile(r"\b([a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64})\b")
IFSC_REGEX = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
GSTIN_REGEX = re.compile(r"\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9][A-Z0-9][A-Z0-9])\b")
PHONE_REGEX = re.compile(r"(?:\+?91[\-\s]?|0)?([6-9]\d{9})\b|\b(1800[\-\s]?\d{3}[\-\s]?\d{3,4})\b|\b(\+?(?:92|855|234)\d{8,11})\b")

COMMON_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "rediffmail.com", "proton.me", "protonmail.com", "sbi.co.in", "npci.org.in",
    "hdfcbank.com", "icicibank.com",
}


def build_investigation_request(
    raw_text: str,
    request_id: str = "req_001",
    channel_hint: Optional[str] = None,
    raw_email_headers: Optional[str] = None,
) -> InvestigationRequest:
    text = raw_text.strip()

    # Extract URLs
    urls: List[str] = []
    for match in URL_REGEX.finditer(text):
        candidate = match.group(0).rstrip(".,;:!?)")
        if "@" in candidate and not candidate.lower().startswith(("http://", "https://")):
            continue
        if not candidate.lower().startswith(("http://", "https://", "ftp://", "file://", "gopher://")):
            candidate = "https://" + candidate
        if candidate not in urls:
            urls.append(candidate)

    # Also detect explicit non-http schemes like file:// or gopher:// for SSRF testing
    for scheme_match in re.finditer(r"\b(?:file|gopher|ftp)://[^\s<>\"']+", text, re.IGNORECASE):
        sc_url = scheme_match.group(0).rstrip(".,;:!?)")
        if sc_url not in urls:
            urls.insert(0, sc_url)

    # Extract UPI VPAs (excluding standard email addresses with dots in handle like @gmail.com)
    upis: List[str] = []
    for match in UPI_REGEX.finditer(text):
        vpa = match.group(1)
        handle = vpa.split("@", 1)[1].lower()
        # Look ahead in text to see if @handle is followed by .com/.in (email)
        end_pos = match.end(1)
        trailing = text[end_pos:end_pos + 10].lower()
        if trailing.startswith((".com", ".in", ".org", ".net", ".co.in", ".gov.in")):
            continue
        if handle not in COMMON_EMAIL_DOMAINS and vpa.lower() not in [u.lower() for u in upis]:
            upis.append(vpa)

    # Extract IFSC codes
    ifscs: List[str] = []
    for match in IFSC_REGEX.finditer(text.upper()):
        code = match.group(1)
        if code not in ifscs:
            ifscs.append(code)

    # Extract GSTIN candidates (including near-miss 15-char uppercase tokens preceded by GST/GSTIN)
    gstins: List[str] = []
    for match in GSTIN_REGEX.finditer(text.upper()):
        g = match.group(1)
        if g not in gstins:
            gstins.append(g)
    for explicit_gst in re.finditer(r"(?:GSTIN|GST\s*(?:No|Number|ID)?)[\s:\-#]*([0-9A-Z]{15})\b", text.upper()):
        g = explicit_gst.group(1)
        if g not in gstins:
            gstins.append(g)

    # Extract Phone numbers
    phones: List[str] = []
    for match in PHONE_REGEX.finditer(text):
        num = next((g for g in match.groups() if g), "")
        cleaned = re.sub(r"[\s\-]", "", num)
        if cleaned and cleaned not in phones:
            phones.append(cleaned)

    # Auto-detect email headers if pasted directly in raw_text
    if not raw_email_headers and any(
        hdr in text for hdr in ("Authentication-Results:", "Received-SPF:", "Return-Path:", "Reply-To:")
    ):
        raw_email_headers = text

    return InvestigationRequest(
        request_id=request_id,
        raw_text=text,
        extracted_urls=urls,
        extracted_upis=upis,
        extracted_ifsccodes=ifscs,
        extracted_gstins=gstins,
        extracted_phones=phones,
        raw_email_headers=raw_email_headers,
        channel_hint=channel_hint or "auto",
    )
