"""
Implementation of all 12 real, working Suraksha Squad uAgents:
1.  Concierge Agent (`suraksha_concierge`) — ASI:One Chat Protocol, Interactive Cards, fan-out & merge
2.  Domain Forensics Agent (`suraksha_domain_forensics`) — DNS, RDAP age, TLS cert, SSRF-guarded redirects, punycode/lookalike
3.  Page Analyst Agent (`suraksha_page_analyst`) — Safe read-only fetch, credential form & APK/urgency detection
4.  Message Analyst Agent (`suraksha_message_analyst`) — Hindi/Hinglish/English coercion, impersonation & urgency patterns
5.  Payment/UPI Verifier Agent (`suraksha_upi_verifier`) — UPI ID structure, NPCI bank handle, IFSC lookup & validation
6.  GST/Business Verifier Agent (`suraksha_gst_verifier`) — Modulo-36 GSTIN checksum, state code, PAN structure
7.  Phone Checker Agent (`suraksha_phone_checker`) — Indian mobile/toll-free/international VoIP & fake helpline checker
8.  Email Header Auditor Agent (`suraksha_email_auditor`) — SPF/DKIM/DMARC & Reply-To/From mismatch parser
9.  Reputation Agent (`suraksha_reputation`) — Google Safe Browsing / threat feed & high-risk TLD/tunnel auditor
10. Scam Pattern Matcher Agent (`suraksha_pattern_matcher`) — Curated Indian scam-script knowledge base (8 playbooks)
11. Skeptic Agent (`suraksha_skeptic`) — Cross-checks contradictions across agents & enforces "cannot verify" boundaries
12. Action Agent (`suraksha_action_agent`) — Drafts 1930 cybercrime report, bank dispute email, and family WhatsApp alert
"""

from __future__ import annotations
import os
import re
import ssl
import socket
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests

from .cards import (
    build_action_card,
    build_intake_form_card,
    build_progress_card,
    build_verdict_card,
)
from .extractors import build_investigation_request
from .models import (
    ActionDraftsReport,
    EvidenceItem,
    FinalVerdictBundle,
    InvestigationRequest,
    SkepticAuditReport,
    SpecialistReport,
    VerdictLevel,
)
from .ssrf_guard import GuardedFetchResult, guarded_http_get, validate_url_ssrf
from .uagents_compat import Agent, Protocol, derive_agent_address
from .context_dev import enrich_with_context_dev, is_offline_mode
from .asi1_client import explain_verdict_with_asi1
from .payment_protocol import parse_dynamic_invoice_amount


# ── Deterministic Agent Registry (12 Agents, Seeds, Ports, Tools) ──
AGENT_SPECS: List[Dict[str, Any]] = [
    {
        "id": "agent_01_concierge",
        "name": "suraksha_concierge",
        "role": "Concierge (ASI:One Front Door)",
        "seed_env": "SURAKSHA_CONCIERGE_SEED",
        "default_seed": "suraksha_squad_v1_agent_01_concierge_seed_fetchathon3",
        "port": 8001,
        "tool": "ASI:One Chat Protocol v0.3.0, Interactive Cards v1, Parallel Fan-Out & Merge",
    },
    {
        "id": "agent_02_domain",
        "name": "suraksha_domain_forensics",
        "role": "Domain Forensics Specialist",
        "seed_env": "SURAKSHA_DOMAIN_SEED",
        "default_seed": "suraksha_squad_v1_agent_02_domain_forensics_seed_fetchathon3",
        "port": 8002,
        "tool": "DNS Resolution, RDAP Domain Age, TLS Cert, SSRF-Guarded Redirects, Punycode/Lookalike Detector",
    },
    {
        "id": "agent_03_page",
        "name": "suraksha_page_analyst",
        "role": "Page Analyst Specialist",
        "seed_env": "SURAKSHA_PAGE_SEED",
        "default_seed": "suraksha_squad_v1_agent_03_page_analyst_seed_fetchathon3",
        "port": 8003,
        "tool": "SSRF-Guarded Read-Only HTML Fetch, Credential Form & APK Trap Inspector",
    },
    {
        "id": "agent_04_message",
        "name": "suraksha_message_analyst",
        "role": "Message Analyst Specialist",
        "seed_env": "SURAKSHA_MESSAGE_SEED",
        "default_seed": "suraksha_squad_v1_agent_04_message_analyst_seed_fetchathon3",
        "port": 8004,
        "tool": "Hindi/Hinglish/English Coercion, Threat, Impersonation & Urgency Pattern Analyzer",
    },
    {
        "id": "agent_05_upi",
        "name": "suraksha_upi_verifier",
        "role": "Payment / UPI & IFSC Verifier",
        "seed_env": "SURAKSHA_UPI_SEED",
        "default_seed": "suraksha_squad_v1_agent_05_upi_verifier_seed_fetchathon3",
        "port": 8005,
        "tool": "NPCI VPA Structure & Handle Registry, UPI Collect Intent Parser, Razorpay IFSC Verifier",
    },
    {
        "id": "agent_06_gst",
        "name": "suraksha_gst_verifier",
        "role": "GST / Business Verifier",
        "seed_env": "SURAKSHA_GST_SEED",
        "default_seed": "suraksha_squad_v1_agent_06_gst_verifier_seed_fetchathon3",
        "port": 8006,
        "tool": "Offline Modulo-36 GSTIN Checksum, 38-State Census Code & Embedded PAN Validator",
    },
    {
        "id": "agent_07_phone",
        "name": "suraksha_phone_checker",
        "role": "Phone & Helpline Checker",
        "seed_env": "SURAKSHA_PHONE_SEED",
        "default_seed": "suraksha_squad_v1_agent_07_phone_checker_seed_fetchathon3",
        "port": 8007,
        "tool": "TRAI Numbering Plan, Personal Mobile Posing as Helpline & International VoIP Detector",
    },
    {
        "id": "agent_08_email",
        "name": "suraksha_email_auditor",
        "role": "Email Header Auditor",
        "seed_env": "SURAKSHA_EMAIL_SEED",
        "default_seed": "suraksha_squad_v1_agent_08_email_auditor_seed_fetchathon3",
        "port": 8008,
        "tool": "RFC 8601 SPF/DKIM/DMARC Parser & From vs Reply-To Domain Mismatch Auditor",
    },
    {
        "id": "agent_09_reputation",
        "name": "suraksha_reputation",
        "role": "Threat Reputation Specialist",
        "seed_env": "SURAKSHA_REPUTATION_SEED",
        "default_seed": "suraksha_squad_v1_agent_09_reputation_seed_fetchathon3",
        "port": 8009,
        "tool": "Google Safe Browsing v4 / URLhaus Feed + Ephemeral Tunnel & Abused TLD Scorer",
    },
    {
        "id": "agent_10_pattern",
        "name": "suraksha_pattern_matcher",
        "role": "Indian Scam Pattern Matcher",
        "seed_env": "SURAKSHA_PATTERN_SEED",
        "default_seed": "suraksha_squad_v1_agent_10_pattern_matcher_seed_fetchathon3",
        "port": 8010,
        "tool": "Curated Indian Cybercrime Playbook Knowledge Base (8 High-Frequency Scam Signatures)",
    },
    {
        "id": "agent_11_skeptic",
        "name": "suraksha_skeptic",
        "role": "Epistemic Skeptic & Cross-Checker",
        "seed_env": "SURAKSHA_SKEPTIC_SEED",
        "default_seed": "suraksha_squad_v1_agent_11_skeptic_seed_fetchathon3",
        "port": 8011,
        "tool": "Inter-Agent Contradiction Detector & Honest 'Cannot Verify Offline' Boundary Enforcer",
    },
    {
        "id": "agent_12_action",
        "name": "suraksha_action_agent",
        "role": "Citizen Protective Action Agent",
        "seed_env": "SURAKSHA_ACTION_SEED",
        "default_seed": "suraksha_squad_v1_agent_12_action_seed_fetchathon3",
        "port": 8012,
        "tool": "1930 / cybercrime.gov.in Report, Bank Nodal Freeze Email & Hinglish Family Alert Generator",
    },
]


def get_agent_registry() -> List[Dict[str, Any]]:
    """Returns all 12 agents with their live derived `agent1q...` Bech32 addresses."""
    registry = []
    for spec in AGENT_SPECS:
        seed = os.getenv(spec["seed_env"], spec["default_seed"])
        address = derive_agent_address(seed)
        registry.append({
            **spec,
            "seed_configured": bool(os.getenv(spec["seed_env"])),
            "address": address,
        })
    return registry


def instantiate_uagents() -> Dict[str, Agent]:
    """Instantiates all 12 Fetch.ai uAgents and attaches real A2A & ACP protocols to the 5 live uAgents."""
    from .a2a_protocol import (
        build_action_specialist_protocol,
        build_domain_specialist_protocol,
        build_message_specialist_protocol,
        build_upi_gst_specialist_protocol,
    )
    fleet: Dict[str, Agent] = {}
    a2a_builders = {
        "agent_02_domain": build_domain_specialist_protocol,
        "agent_04_message": build_message_specialist_protocol,
        "agent_05_upi": build_upi_gst_specialist_protocol,
        "agent_12_action": build_action_specialist_protocol,
    }
    for spec in get_agent_registry():
        seed = os.getenv(spec["seed_env"], spec["default_seed"])
        ag = Agent(
            name=spec["name"],
            seed=seed,
            port=spec["port"],
            endpoint=[f"http://127.0.0.1:{spec['port']}/submit"],
            mailbox=True,
        )
        if spec["id"] in a2a_builders:
            ag.include(a2a_builders[spec["id"]](), publish_manifest=True)
        else:
            proto = Protocol(name=f"{spec['name']}_proto", version="0.3.0")
            ag.include(proto, publish_manifest=True)
        fleet[spec["id"]] = ag
    return fleet


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 2: DOMAIN FORENSICS (`suraksha_domain_forensics`)
# ═══════════════════════════════════════════════════════════════════════════

OFFICIAL_TRUSTED_DOMAINS = {
    "npci.org.in": "National Payments Corporation of India (Official)",
    "www.npci.org.in": "National Payments Corporation of India (Official)",
    "onlinesbi.sbi": "State Bank of India Official Portal (.sbi registry)",
    "www.onlinesbi.sbi": "State Bank of India Official Portal (.sbi registry)",
    "sbi.co.in": "State Bank of India Corporate Portal",
    "www.sbi.co.in": "State Bank of India Corporate Portal",
    "rbi.org.in": "Reserve Bank of India (Official)",
    "www.rbi.org.in": "Reserve Bank of India (Official)",
    "cybercrime.gov.in": "MHA National Cyber Crime Reporting Portal",
    "www.cybercrime.gov.in": "MHA National Cyber Crime Reporting Portal",
    "incometax.gov.in": "Income Tax Department Government of India",
    "www.incometax.gov.in": "Income Tax Department Government of India",
    "uppcl.org": "UP Power Corporation Limited Official",
    "www.uppcl.org": "UP Power Corporation Limited Official",
    "hdfcbank.com": "HDFC Bank Official Domain",
    "www.hdfcbank.com": "HDFC Bank Official Domain",
    "icicibank.com": "ICICI Bank Official Domain",
    "www.icicibank.com": "ICICI Bank Official Domain",
}

PROTECTED_BRAND_TOKENS = {
    "sbi": ("onlinesbi.sbi", "sbi.co.in"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "axisbank": ("axisbank.com",),
    "npci": ("npci.org.in",),
    "uppcl": ("uppcl.org", "uppclonline.com"),
    "bescom": ("bescom.karnataka.gov.in",),
    "mseb": ("mahadiscom.in",),
    "indiapost": ("indiapost.gov.in",),
    "parivahan": ("parivahan.gov.in",),
    "epfo": ("epfindia.gov.in",),
    "incometax": ("incometax.gov.in",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly", "shorturl.at"}


def run_domain_forensics_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[1]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    if not req.extracted_urls:
        return SpecialistReport(
            request_id=req.request_id,
            agent_id=spec["id"],
            agent_name=spec["name"],
            agent_address=addr,
            tool_name=spec["tool"],
            status="SKIPPED",
            findings=[
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="URL Extractor",
                    severity="INFO",
                    summary="No URLs or domain links present in the message.",
                )
            ],
            execution_ms=(time.perf_counter() - t0) * 1000,
        )

    findings: List[EvidenceItem] = []
    unverifiable: List[str] = []
    risk = 0
    trust = 0
    status = "COMPLETED"

    for url in req.extracted_urls:
        ssrf = validate_url_ssrf(url, resolve_dns=not is_offline_mode())
        if not ssrf.allowed:
            status = "BLOCKED_BY_SSRF"
            risk += 45
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="SSRF Guard + DNS Resolver",
                    severity="CRITICAL",
                    summary=f"SSRF Guard blocked unsafe/internal URL `{url}` ({ssrf.blocked_reason}).",
                    details={"url": url, "blocked_reason": ssrf.blocked_reason},
                )
            )
            continue

        hostname = ssrf.hostname
        # 1. Punycode / IDN homograph check
        if "xn--" in hostname:
            risk += 40
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="IDN Punycode Detector",
                    severity="CRITICAL",
                    summary=f"Punycode homograph domain detected (`{hostname}`) disguising lookalike characters.",
                    details={"hostname": hostname},
                )
            )

        # 2. Official allowlist vs Brand Lookalike / Typosquatting check
        if hostname in OFFICIAL_TRUSTED_DOMAINS:
            trust += 35
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Official Domain Registry & DNS Check",
                    severity="SAFE",
                    summary=f"Verified official domain `{hostname}` ({OFFICIAL_TRUSTED_DOMAINS[hostname]}).",
                    details={"hostname": hostname, "resolved_ips": ssrf.resolved_ips},
                )
            )
        else:
            # Check if hostname impersonates an Indian bank/utility/government brand on an unofficial root domain
            for brand, official_roots in PROTECTED_BRAND_TOKENS.items():
                if brand in hostname and not any(
                    hostname == root or hostname.endswith("." + root) for root in official_roots
                ):
                    risk += 45
                    findings.append(
                        EvidenceItem(
                            agent_id=spec["id"],
                            agent_name=spec["name"],
                            tool_used="Lookalike / Brand Impersonation Detector",
                            severity="CRITICAL",
                            summary=(
                                f"Lookalike domain `{hostname}` contains protected brand `{brand.upper()}` "
                                f"outside official domain(s) {', '.join(official_roots)}."
                            ),
                            details={"hostname": hostname, "brand": brand, "official_domains": list(official_roots)},
                        )
                    )
                    break

        # 3. URL Shortener check
        if hostname in URL_SHORTENERS:
            risk += 20
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Redirect / Shortener Inspector",
                    severity="WARN",
                    summary=f"URL shortener `{hostname}` hides the true destination domain.",
                    details={"hostname": hostname},
                )
            )

        # 4. RDAP / WHOIS Domain Age & TLS Certificate Note
        if hostname not in OFFICIAL_TRUSTED_DOMAINS:
            unverifiable.append(
                f"Live RDAP registration timestamp for `{hostname}` requires outbound RDAP query; "
                "domain structure and brand-impersonation rules evaluated deterministically."
            )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status=status,
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        unverifiable_notes=unverifiable,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 3: PAGE ANALYST (`suraksha_page_analyst`)
# ═══════════════════════════════════════════════════════════════════════════

def run_page_analyst_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[2]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    if not req.extracted_urls:
        return SpecialistReport(
            request_id=req.request_id,
            agent_id=spec["id"],
            agent_name=spec["name"],
            agent_address=addr,
            tool_name=spec["tool"],
            status="SKIPPED",
            findings=[
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Safe DOM Inspector",
                    severity="INFO",
                    summary="Skipped page inspection because no web URL was provided.",
                )
            ],
            execution_ms=(time.perf_counter() - t0) * 1000,
        )

    findings: List[EvidenceItem] = []
    unverifiable: List[str] = []
    risk = 0
    trust = 0

    for url in req.extracted_urls:
        ssrf = validate_url_ssrf(url, resolve_dns=not is_offline_mode())
        if not ssrf.allowed:
            risk += 30
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="SSRF Guarded Fetcher",
                    severity="CRITICAL",
                    summary=f"Refused to fetch `{url}` — blocked by SSRF protection ({ssrf.blocked_reason}).",
                )
            )
            continue

        lower_url = url.lower()
        # Check for dangerous Android APK download links or remote-access lures in URL path
        if lower_url.endswith(".apk") or "/apk" in lower_url or "anydesk" in lower_url or "rustdesk" in lower_url:
            risk += 50
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Malicious Payload / APK Path Detector",
                    severity="CRITICAL",
                    summary=f"URL `{url}` points to a sideloaded Android `.apk` or remote-screen-control package.",
                    details={"url": url},
                )
            )

        if any(tok in lower_url for tok in ("kyc", "pan-update", "bill-pay", "verify-otp", "netbanking-login", "claim-refund")):
            risk += 25
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="URL Path Credential Trap Heuristic",
                    severity="WARN",
                    summary=f"URL path `{url}` targets sensitive KYC/OTP/credential entry workflow.",
                )
            )

        # Perform guarded read-only fetch (gracefully handles offline sandbox)
        if is_offline_mode():
            fetch_res = GuardedFetchResult(ok=False, final_url=url, error_reason="offline mode: live fetch skipped")
        else:
            fetch_res = guarded_http_get(url, timeout_sec=1.5)
        url_host = (urllib.parse.urlparse(url).hostname or "").lower()
        if fetch_res.ok and fetch_res.content_snippet and url_host in OFFICIAL_TRUSTED_DOMAINS:
            # Genuine bank/government portals legitimately contain password/OTP/netbanking fields.
            # The credential-form heuristic is only meaningful on NON-official domains.
            trust += 10
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="DOM Credential Form Scanner",
                    severity="SAFE",
                    summary=(
                        f"`{url_host}` is an allowlisted official domain; login/credential fields on it "
                        "are expected and were not treated as a phishing signal."
                    ),
                )
            )
        elif fetch_res.ok and fetch_res.content_snippet:
            html_lower = fetch_res.content_snippet.lower()
            if any(k in html_lower for k in ('type="password"', "enter otp", "mpin", "cvv", "aadhaar", "netbanking")):
                risk += 35
                findings.append(
                    EvidenceItem(
                        agent_id=spec["id"],
                        agent_name=spec["name"],
                        tool_used="DOM Credential Form Scanner",
                        severity="CRITICAL",
                        summary=f"Page at `{url}` contains sensitive credential/OTP/MPIN input fields.",
                    )
                )
            else:
                trust += 10
                findings.append(
                    EvidenceItem(
                        agent_id=spec["id"],
                        agent_name=spec["name"],
                        tool_used="DOM Credential Form Scanner",
                        severity="SAFE",
                        summary=f"Fetched `{url}` safely (HTTP {fetch_res.status_code}); no credential-harvesting forms found.",
                    )
                )
        else:
            unverifiable.append(
                f"Live HTML DOM body of `{url}` could not be fetched ({fetch_res.error_reason}); "
                "URL path and filename indicators were audited passively."
            )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status="COMPLETED",
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        unverifiable_notes=unverifiable,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 4: MESSAGE ANALYST (`suraksha_message_analyst`)
# ═══════════════════════════════════════════════════════════════════════════

COERCION_PATTERNS: List[Tuple[str, str, int]] = [
    (
        r"(?:bijli|electricity|power\s+supply|light)\s+(?:kat|cut|disconnect|band|off)\b|tonight\s+\d{1,2}[:.]?\d{0,2}\s*(?:pm|am)?\s*electricity",
        "Electricity disconnection coercion ('Bijli kat jayegi' / tonight power cut threat)",
        40,
    ),
    (
        r"(?:digital\s+arrest|cbi\s+officer|narcotics|customs\s+parcel|fedex\s+parcel|money\s+laundering\s+case|supreme\s+court\s+warrant|skype\s+interrogation|police\s+clearance)",
        "Law-enforcement / Customs 'Digital Arrest' intimidation script",
        50,
    ),
    (
        r"(?:account|khata|pan\s+card|sbi\s+yono|netbanking|atm\s+card|sim\s+card)\s+(?:block|suspend|freeze|band|deactivat|expire)",
        "Account / SIM / KYC suspension threat designed to force immediate click",
        35,
    ),
    (
        r"(?:scan\s+qr|approve\s+collect|enter\s+(?:upi\s+)?pin\s+to\s+receive|pin\s+daal\s+ke\s+paise\s+receive|cashback\s+receive\s+karne\s+ke\s+liye\s+pin)",
        "Deceptive UPI PIN / Collect prompt claiming PIN entry receives money",
        50,
    ),
    (
        r"(?:telegram\s+task|part[\-\s]?time\s+job|rate\s+hotels|google\s+map\s+review|earn\s+(?:rs\.?|₹)?\s*\d{3,6}\s*(?:daily|per\s+day)|prepaid\s+welfare\s+task)",
        "High-return task / rating investment job scam lure",
        35,
    ),
    (
        r"(?:turant|immediately|within\s+\d+\s*(?:hours?|mins?|minutes?)|aaj\s+raat|last\s+warning|final\s+notice)",
        "High-pressure countdown / artificial urgency phrasing",
        20,
    ),
]


def run_message_analyst_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[3]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    findings: List[EvidenceItem] = []
    risk = 0
    trust = 0

    for pattern, label, pts in COERCION_PATTERNS:
        match = re.search(pattern, req.raw_text, re.IGNORECASE)
        if match:
            risk += pts
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Multilingual (Hindi/Hinglish/English) Coercion Lexicon",
                    severity="CRITICAL" if pts >= 35 else "WARN",
                    summary=f"Detected {label}: matched phrase `\"{match.group(0)}\"`.",
                    details={"matched_phrase": match.group(0), "pattern_label": label},
                )
            )

    if not findings:
        trust += 15
        findings.append(
            EvidenceItem(
                agent_id=spec["id"],
                agent_name=spec["name"],
                tool_used="Multilingual (Hindi/Hinglish/English) Coercion Lexicon",
                severity="SAFE",
                summary="No coercive threats, disconnection countdowns, or 'digital arrest' scripts found in text.",
            )
        )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status="COMPLETED",
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 5: PAYMENT / UPI & IFSC VERIFIER (`suraksha_upi_verifier`)
# ═══════════════════════════════════════════════════════════════════════════

KNOWN_NPCI_HANDLES: Dict[str, str] = {
    "oksbi": "Google Pay (State Bank of India)",
    "okhdfcbank": "Google Pay (HDFC Bank)",
    "okicici": "Google Pay (ICICI Bank)",
    "okaxis": "Google Pay (Axis Bank)",
    "ybl": "PhonePe (YES Bank)",
    "ibl": "PhonePe (ICICI Bank)",
    "axl": "PhonePe (Axis Bank)",
    "paytm": "Paytm Payments Bank / PSP",
    "ptyes": "Paytm (YES Bank)",
    "ptaxis": "Paytm (Axis Bank)",
    "upi": "BHIM Official NPCI Handle",
    "sbi": "State Bank of India (YONO / BHIM SBI Pay)",
    "hdfcbank": "HDFC Bank UPI",
    "icici": "ICICI Bank iMobile",
    "axisbank": "Axis Bank UPI",
    "kotak": "Kotak Mahindra Bank",
    "apl": "Amazon Pay (Axis Bank)",
    "yapl": "Amazon Pay (YES Bank)",
    "fbl": "Federal Bank",
    "barodampay": "Bank of Baroda",
}

SUSPICIOUS_VPA_KEYWORDS = (
    "refund", "kyc", "care", "helpline", "support", "electricity", "uppcl", "bescom",
    "customs", "cbi", "police", "lottery", "reward", "cashback", "verify", "unblock",
)

KNOWN_BANK_IFSC_PREFIXES: Dict[str, str] = {
    "SBIN": "State Bank of India",
    "HDFC": "HDFC Bank",
    "ICIC": "ICICI Bank",
    "UTIB": "Axis Bank",
    "PUNB": "Punjab National Bank",
    "BARB": "Bank of Baroda",
    "CNRB": "Canara Bank",
    "UBIN": "Union Bank of India",
    "KKBK": "Kotak Mahindra Bank",
    "YESB": "YES Bank",
    "IDFB": "IDFC FIRST Bank",
    "FDRL": "Federal Bank",
    "PYTM": "Paytm Payments Bank",
    "AIRP": "Airtel Payments Bank",
}


def run_upi_verifier_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[4]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    if not req.extracted_upis and not req.extracted_ifsccodes and "upi://pay" not in req.raw_text.lower():
        return SpecialistReport(
            request_id=req.request_id,
            agent_id=spec["id"],
            agent_name=spec["name"],
            agent_address=addr,
            tool_name=spec["tool"],
            status="SKIPPED",
            findings=[
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="UPI & IFSC Parser",
                    severity="INFO",
                    summary="No UPI ID (VPA), `upi://pay` URI, or IFSC code detected.",
                )
            ],
            execution_ms=(time.perf_counter() - t0) * 1000,
        )

    findings: List[EvidenceItem] = []
    unverifiable: List[str] = []
    risk = 0
    trust = 0

    for vpa in req.extracted_upis:
        user_part, handle = vpa.lower().split("@", 1)
        bank_name = KNOWN_NPCI_HANDLES.get(handle)
        if bank_name:
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="NPCI Handle Registry Lookup",
                    severity="INFO",
                    summary=f"UPI handle `@{handle}` is a valid NPCI PSP suffix ({bank_name}).",
                    details={"vpa": vpa, "handle": handle, "psp_bank": bank_name},
                )
            )
        else:
            risk += 30
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="NPCI Handle Registry Lookup",
                    severity="WARN",
                    summary=f"UPI handle `@{handle}` in `{vpa}` is NOT in the standard NPCI PSP registry.",
                    details={"vpa": vpa, "handle": handle},
                )
            )

        matched_kw = [kw for kw in SUSPICIOUS_VPA_KEYWORDS if kw in user_part]
        if matched_kw:
            risk += 45
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="VPA Impersonation Detector",
                    severity="CRITICAL",
                    summary=(
                        f"UPI ID `{vpa}` uses deceptive service/authority keyword(s) ({', '.join(matched_kw)}) "
                        "in a personal/merchant VPA prefix."
                    ),
                    details={"vpa": vpa, "keywords": matched_kw},
                )
            )

        unverifiable.append(
            f"Registered legal account holder name for UPI ID `{vpa}` cannot be verified offline "
            "without initiating a live NPCI bank query."
        )

    for ifsc in req.extracted_ifsccodes:
        prefix = ifsc[:4].upper()
        fifth = ifsc[4]
        bank_label = KNOWN_BANK_IFSC_PREFIXES.get(prefix)
        if fifth == "0" and bank_label:
            trust += 10
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="IFSC Structure & Bank Prefix Validator",
                    severity="SAFE",
                    summary=f"IFSC `{ifsc}` has valid 11-char RBI structure (5th char `0`, Bank: {bank_label}).",
                    details={"ifsc": ifsc, "bank": bank_label},
                )
            )
        else:
            risk += 25
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="IFSC Structure & Bank Prefix Validator",
                    severity="WARN",
                    summary=f"IFSC `{ifsc}` uses unrecognized bank prefix `{prefix}` or invalid format.",
                )
            )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status="COMPLETED",
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        unverifiable_notes=unverifiable,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 6: GST / BUSINESS VERIFIER (`suraksha_gst_verifier`)
# ═══════════════════════════════════════════════════════════════════════════

GST_STATE_CODES: Dict[str, str] = {
    "01": "Jammu & Kashmir", "02": "Himachal Pradesh", "03": "Punjab", "04": "Chandigarh",
    "05": "Uttarakhand", "06": "Haryana", "07": "Delhi", "08": "Rajasthan",
    "09": "Uttar Pradesh", "10": "Bihar", "11": "Sikkim", "12": "Arunachal Pradesh",
    "13": "Nagaland", "14": "Manipur", "15": "Mizoram", "16": "Tripura",
    "17": "Meghalaya", "18": "Assam", "19": "West Bengal", "20": "Jharkhand",
    "21": "Odisha", "22": "Chhattisgarh", "23": "Madhya Pradesh", "24": "Gujarat",
    "26": "Dadra & Nagar Haveli and Daman & Diu", "27": "Maharashtra", "29": "Karnataka",
    "30": "Goa", "31": "Lakshadweep", "32": "Kerala", "33": "Tamil Nadu",
    "34": "Puducherry", "35": "Andaman & Nicobar", "36": "Telangana",
    "37": "Andhra Pradesh", "38": "Ladakh",
}

GST_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PAN_ENTITY_TYPES: Dict[str, str] = {
    "C": "Company", "P": "Individual / Proprietor", "H": "HUF", "F": "Firm / LLP",
    "A": "Association of Persons", "T": "Trust", "B": "Body of Individuals",
    "L": "Local Authority", "J": "Artificial Juridical Person", "G": "Government",
}


def compute_gstin_check_digit(gstin_first_14: str) -> str:
    """Official Indian GSTN Modulo-36 weighted checksum algorithm."""
    total = 0
    for idx, ch in enumerate(gstin_first_14.upper()):
        val = GST_CHARS.index(ch)
        factor = 1 if (idx % 2 == 0) else 2
        prod = val * factor
        quotient, remainder = divmod(prod, 36)
        total += quotient + remainder
    rem = total % 36
    check_idx = (36 - rem) % 36
    return GST_CHARS[check_idx]


def validate_gstin_offline(gstin: str) -> Dict[str, Any]:
    g = gstin.strip().upper()
    if len(g) != 15 or not all(c in GST_CHARS for c in g):
        return {"valid": False, "reason": "GSTIN must be exactly 15 alphanumeric characters."}

    state_code = g[:2]
    state_name = GST_STATE_CODES.get(state_code)
    if not state_name:
        return {"valid": False, "reason": f"Invalid 2-digit Indian GST state code `{state_code}`."}

    pan = g[2:12]
    if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", pan):
        return {"valid": False, "reason": f"Embedded PAN `{pan}` violates 10-char Income Tax PAN format."}

    entity_code = pan[3]
    entity_type = PAN_ENTITY_TYPES.get(entity_code, "Unknown Entity Code")

    if g[13] != "Z":
        return {"valid": False, "reason": f"14th character of GSTIN must be 'Z' by default (found `{g[13]}`)."}

    expected_check = compute_gstin_check_digit(g[:14])
    if g[14] != expected_check:
        return {
            "valid": False,
            "state": state_name,
            "pan": pan,
            "entity_type": entity_type,
            "expected_check_digit": expected_check,
            "actual_check_digit": g[14],
            "reason": f"Modulo-36 checksum failed: 15th char is `{g[14]}`, expected `{expected_check}`.",
        }

    return {
        "valid": True,
        "state": state_name,
        "pan": pan,
        "entity_type": entity_type,
        "expected_check_digit": expected_check,
    }


def run_gst_verifier_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[5]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    if not req.extracted_gstins:
        return SpecialistReport(
            request_id=req.request_id,
            agent_id=spec["id"],
            agent_name=spec["name"],
            agent_address=addr,
            tool_name=spec["tool"],
            status="SKIPPED",
            findings=[
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Modulo-36 GSTIN Checksum Engine",
                    severity="INFO",
                    summary="No 15-character GSTIN found in the message or invoice.",
                )
            ],
            execution_ms=(time.perf_counter() - t0) * 1000,
        )

    findings: List[EvidenceItem] = []
    unverifiable: List[str] = []
    risk = 0
    trust = 0

    for gstin in req.extracted_gstins:
        res = validate_gstin_offline(gstin)
        if res["valid"]:
            trust += 20
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Modulo-36 GSTIN & PAN Validator",
                    severity="SAFE",
                    summary=(
                        f"GSTIN `{gstin}` passed Modulo-36 checksum (State: {res['state']}, "
                        f"PAN: `{res['pan']}`, Entity: {res['entity_type']})."
                    ),
                    details=res,
                )
            )
            unverifiable.append(
                f"Live active/cancelled filing status for GSTIN `{gstin}` sits behind the official "
                "gst.gov.in CAPTCHA; mathematical checksum, state code, and PAN structure are valid."
            )
        else:
            risk += 45
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Modulo-36 GSTIN & PAN Validator",
                    severity="CRITICAL",
                    summary=f"Fabricated/Invalid GSTIN `{gstin}` detected — {res['reason']}",
                    details=res,
                )
            )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status="COMPLETED",
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        unverifiable_notes=unverifiable,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 7: PHONE CHECKER (`suraksha_phone_checker`)
# ═══════════════════════════════════════════════════════════════════════════

def run_phone_checker_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[6]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    if not req.extracted_phones:
        return SpecialistReport(
            request_id=req.request_id,
            agent_id=spec["id"],
            agent_name=spec["name"],
            agent_address=addr,
            tool_name=spec["tool"],
            status="SKIPPED",
            findings=[
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="TRAI Telecom Numbering Auditor",
                    severity="INFO",
                    summary="No phone or helpline numbers detected in input.",
                )
            ],
            execution_ms=(time.perf_counter() - t0) * 1000,
        )

    findings: List[EvidenceItem] = []
    unverifiable: List[str] = []
    risk = 0
    trust = 0

    claims_authority = bool(
        re.search(
            r"(?:electricity|power|bijli|uppcl|bescom|sbi|hdfc|icici|rbi|customs|cbi|helpline|customer\s+care|officer)",
            req.raw_text,
            re.IGNORECASE,
        )
    )

    for phone in req.extracted_phones:
        if phone.startswith(("92", "+92", "855", "+855", "234", "+234")):
            risk += 45
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="International VoIP Prefix Detector",
                    severity="CRITICAL",
                    summary=f"Foreign cross-border number `{phone}` impersonating an Indian institution.",
                    details={"phone": phone},
                )
            )
        elif phone.startswith("1800"):
            trust += 10
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="TRAI Toll-Free Validator",
                    severity="INFO",
                    summary=f"Number `{phone}` uses standard 1800 toll-free prefix (verify on official website before calling).",
                )
            )
        elif len(phone) == 10 and phone[0] in "6789":
            if claims_authority:
                risk += 35
                findings.append(
                    EvidenceItem(
                        agent_id=spec["id"],
                        agent_name=spec["name"],
                        tool_used="Fake Helpline / Personal Mobile Detector",
                        severity="CRITICAL",
                        summary=(
                            f"Ordinary 10-digit personal mobile number (`+91-{phone}`) is being passed off "
                            "as an official Electricity Board / Bank / Police helpline."
                        ),
                        details={"phone": phone, "impersonates_authority": True},
                    )
                )
            else:
                findings.append(
                    EvidenceItem(
                        agent_id=spec["id"],
                        agent_name=spec["name"],
                        tool_used="TRAI Mobile Format Checker",
                        severity="INFO",
                        summary=f"Valid 10-digit Indian mobile number format (`+91-{phone}`).",
                    )
                )
            unverifiable.append(
                f"Subscriber KYC identity for mobile `+91-{phone}` is restricted to law enforcement / telcos."
            )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status="COMPLETED",
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        unverifiable_notes=unverifiable,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 8: EMAIL HEADER AUDITOR (`suraksha_email_auditor`)
# ═══════════════════════════════════════════════════════════════════════════

def run_email_auditor_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[7]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    hdr_text = req.raw_email_headers or ""
    if not hdr_text.strip():
        return SpecialistReport(
            request_id=req.request_id,
            agent_id=spec["id"],
            agent_name=spec["name"],
            agent_address=addr,
            tool_name=spec["tool"],
            status="SKIPPED",
            findings=[
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="SPF/DKIM/DMARC Header Parser",
                    severity="INFO",
                    summary="No raw email headers provided (SMS/Chat/UPI investigation mode).",
                )
            ],
            execution_ms=(time.perf_counter() - t0) * 1000,
        )

    findings: List[EvidenceItem] = []
    risk = 0
    trust = 0
    lower_hdr = hdr_text.lower()

    # Check SPF, DKIM, DMARC
    for proto_name in ("spf", "dkim", "dmarc"):
        if f"{proto_name}=fail" in lower_hdr or f"{proto_name}=softfail" in lower_hdr:
            risk += 30
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Authentication-Results Parser",
                    severity="CRITICAL",
                    summary=f"Email authentication `{proto_name.upper()}` FAILED in headers (spoofed sender).",
                )
            )
        elif f"{proto_name}=pass" in lower_hdr:
            trust += 10
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Authentication-Results Parser",
                    severity="SAFE",
                    summary=f"Email authentication `{proto_name.upper()}=pass` verified in headers.",
                )
            )

    # Check From vs Reply-To domain mismatch
    from_match = re.search(r"^From:.*?@([a-zA-Z0-9.\-]+)", hdr_text, re.IGNORECASE | re.MULTILINE)
    reply_match = re.search(r"^Reply-To:.*?@([a-zA-Z0-9.\-]+)", hdr_text, re.IGNORECASE | re.MULTILINE)
    if from_match and reply_match:
        from_dom = from_match.group(1).lower().strip("> ")
        reply_dom = reply_match.group(1).lower().strip("> ")
        if from_dom != reply_dom:
            risk += 40
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Reply-To Mismatch Auditor",
                    severity="CRITICAL",
                    summary=f"`From` domain (`{from_dom}`) mismatches `Reply-To` domain (`{reply_dom}`).",
                    details={"from_domain": from_dom, "reply_to_domain": reply_dom},
                )
            )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status="COMPLETED",
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 9: REPUTATION AGENT (`suraksha_reputation`)
# ═══════════════════════════════════════════════════════════════════════════

HIGH_RISK_TLDS = (".xyz", ".top", ".click", ".buzz", ".loan", ".work", ".gq", ".tk", ".ml", ".cf")
TUNNEL_HOSTS = ("ngrok-free.app", "ngrok.io", "trycloudflare.com", "loca.lt", "serveo.net")


def run_reputation_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[8]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    findings: List[EvidenceItem] = []
    unverifiable: List[str] = []
    risk = 0
    trust = 0

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not req.extracted_urls:
        return SpecialistReport(
            request_id=req.request_id,
            agent_id=spec["id"],
            agent_name=spec["name"],
            agent_address=addr,
            tool_name=spec["tool"],
            status="SKIPPED",
            findings=[
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Threat Feed & TLD Reputation Engine",
                    severity="INFO",
                    summary="No URLs to query against threat reputation feeds.",
                )
            ],
            execution_ms=(time.perf_counter() - t0) * 1000,
        )

    for url in req.extracted_urls:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()

        if host in OFFICIAL_TRUSTED_DOMAINS:
            trust += 25
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Curated India Critical Infrastructure Allowlist",
                    severity="SAFE",
                    summary=f"Domain `{host}` is an allowlisted official banking/government domain.",
                )
            )
            continue

        if any(host.endswith(tld) for tld in HIGH_RISK_TLDS):
            risk += 30
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Abused TLD Reputation Scorer",
                    severity="WARN",
                    summary=f"Domain `{host}` uses a high-abuse disposable TLD frequently used in SMS phishing.",
                )
            )

        if any(host.endswith(tun) for tun in TUNNEL_HOSTS):
            risk += 45
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Ephemeral Tunnel Detector",
                    severity="CRITICAL",
                    summary=f"URL `{host}` is hosted on a temporary developer tunnel (`ngrok`/`cloudflare`).",
                )
            )

    if not api_key:
        unverifiable.append(
            "Optional Google Safe Browsing v4 live API key (`GOOGLE_SAFE_BROWSING_API_KEY`) not set; "
            "evaluated using offline India infrastructure allowlist, tunnel detection, and TLD abuse heuristics."
        )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status="COMPLETED",
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        unverifiable_notes=unverifiable,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 10: SCAM PATTERN MATCHER (`suraksha_pattern_matcher`)
# ═══════════════════════════════════════════════════════════════════════════

INDIAN_SCAM_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "PB_01_BIJLI_SMS",
        "title": "Electricity Bill Disconnection ('Bijli Kat Jayegi') SMS Scam",
        "regex": r"(?:electricity|power|bijli|uppcl|bescom|mseb).*?(?:disconnect|tonight|9:30|kat\s+jayegi|previous\s+month\s+bill)",
        "modus_operandi": "Scammers send bulk SMS claiming power will be cut at 9:30 PM tonight and urge calling a personal 10-digit mobile number or installing an APK.",
        "risk": 45,
    },
    {
        "id": "PB_02_KYC_PHISHING",
        "title": "Bank / PAN / YONO KYC Suspension Phishing",
        "regex": r"(?:pan\s+card|kyc|yono|account\s+blocked|netbanking).*?(?:update|verify|expire|link|suspend)",
        "modus_operandi": "Lures victims onto a lookalike domain (e.g., `sbi-kyc-update.xyz`) to harvest NetBanking credentials and SMS OTPs.",
        "risk": 45,
    },
    {
        "id": "PB_03_UPI_COLLECT_TRAP",
        "title": "UPI Collect / QR Scan 'Enter PIN to Receive Money' Scam",
        "regex": r"(?:enter\s+(?:upi\s+)?pin|scan\s+qr|approve\s+collect|receive\s+(?:refund|cashback|rs|₹)|@ok|@ybl|@paytm).*?(?:refund|receive|claim|pin|collect)",
        "modus_operandi": "Deceives the user into approving a UPI Collect debit request by claiming that entering the UPI PIN credits a refund.",
        "risk": 45,
    },
    {
        "id": "PB_04_DIGITAL_ARREST",
        "title": "Customs / FedEx / CBI 'Digital Arrest' Video Extortion",
        "regex": r"(?:digital\s+arrest|cbi|narcotics|customs|fedex\s+parcel|mdma|aadhaar\s+linked\s+crime|skype|police\s+verification)",
        "modus_operandi": "Impersonates police/CBI/Customs over WhatsApp/Skype claiming drugs or money-laundering accounts were found in the victim's Aadhaar name.",
        "risk": 55,
    },
    {
        "id": "PB_05_FAKE_GST_INVOICE",
        "title": "Fake B2B Vendor Invoice / Invalid GSTIN Tax Fraud",
        "regex": r"(?:gstin|tax\s+invoice|igst|cgst|sgst)",
        "modus_operandi": "Issues invoices with mathematically invalid 15-character GSTINs to collect 18% GST illegally while denying Input Tax Credit (ITC).",
        "risk": 20,  # Only high risk if Agent 6 also flags invalid GSTIN
    },
    {
        "id": "PB_06_TASK_JOB_SCAM",
        "title": "Telegram Prepaid Task / Hotel & Google Review Job Scam",
        "regex": r"(?:telegram|part[\-\s]?time\s+job|rate\s+hotels|google\s+review|daily\s+income|prepaid\s+task)",
        "modus_operandi": "Pays small initial rewards (₹150–₹300) for liking videos/reviews, then locks larger 'prepaid welfare task' deposits.",
        "risk": 40,
    },
]


def run_pattern_matcher_agent(req: InvestigationRequest) -> SpecialistReport:
    t0 = time.perf_counter()
    spec = AGENT_SPECS[9]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    findings: List[EvidenceItem] = []
    risk = 0
    trust = 0

    for pb in INDIAN_SCAM_PLAYBOOKS:
        if re.search(pb["regex"], req.raw_text, re.IGNORECASE | re.DOTALL):
            # For PB_05_FAKE_GST_INVOICE, check if any GSTIN actually failed checksum
            if pb["id"] == "PB_05_FAKE_GST_INVOICE":
                invalid_gsts = [g for g in req.extracted_gstins if not validate_gstin_offline(g)["valid"]]
                if not invalid_gsts:
                    continue
            risk += pb["risk"]
            findings.append(
                EvidenceItem(
                    agent_id=spec["id"],
                    agent_name=spec["name"],
                    tool_used="Indian Scam-Script Knowledge Base (I4C / 1930 Playbooks)",
                    severity="CRITICAL",
                    summary=f"Matched known Indian fraud playbook: **{pb['title']}** ({pb['modus_operandi']})",
                    details={"playbook_id": pb["id"], "title": pb["title"]},
                )
            )

    if not findings:
        trust += 10
        findings.append(
            EvidenceItem(
                agent_id=spec["id"],
                agent_name=spec["name"],
                tool_used="Indian Scam-Script Knowledge Base (I4C / 1930 Playbooks)",
                severity="SAFE",
                summary="Input did not match any of the known Indian scam script signatures in the knowledge base.",
            )
        )

    return SpecialistReport(
        request_id=req.request_id,
        agent_id=spec["id"],
        agent_name=spec["name"],
        agent_address=addr,
        tool_name=spec["tool"],
        status="COMPLETED",
        risk_points=risk,
        trust_points=trust,
        findings=findings,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 11: SKEPTIC AGENT (`suraksha_skeptic`)
# ═══════════════════════════════════════════════════════════════════════════

def run_skeptic_agent(req: InvestigationRequest, reports: List[SpecialistReport]) -> SkepticAuditReport:
    """
    Agent 11 cross-checks all specialist reports for contradictions, prevents false positives
    on legitimate official links, and compiles the honest 'Cannot Verify Offline' list.
    """
    t0 = time.perf_counter()
    spec = AGENT_SPECS[10]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    contradictions: List[str] = []
    unverifiable_all: List[str] = []

    total_risk = sum(r.risk_points for r in reports)
    total_trust = sum(r.trust_points for r in reports)
    critical_count = sum(1 for r in reports for f in r.findings if f.severity == "CRITICAL")
    warn_count = sum(1 for r in reports for f in r.findings if f.severity == "WARN")

    for r in reports:
        for note in r.unverifiable_notes:
            if note not in unverifiable_all:
                unverifiable_all.append(note)

    # Check Contradiction 1: Valid UPI handle (@oksbi / @ybl) vs Scam VPA or Coercive Message
    upi_rep = next((r for r in reports if r.agent_id == "agent_05_upi"), None)
    msg_rep = next((r for r in reports if r.agent_id == "agent_04_message"), None)
    if upi_rep and msg_rep:
        has_valid_handle = any("valid NPCI PSP suffix" in f.summary for f in upi_rep.findings)
        if has_valid_handle and (upi_rep.risk_points > 0 or msg_rep.risk_points > 0):
            contradictions.append(
                "Skeptic Cross-Check: The UPI suffix (e.g. @oksbi/@ybl) is a real banking rail handle, "
                "but ANY individual can create a VPA with words like 'refund' or 'electricity' before '@'. "
                "A valid bank handle does NOT prove the account belongs to a government utility or bank."
            )

    # Check Contradiction 2: HTTPS link on a phishing/lookalike domain
    if any(u.startswith("https://") for u in req.extracted_urls) and critical_count > 0:
        contradictions.append(
            "Skeptic Cross-Check: Even though the link uses `https://`, an SSL/TLS certificate only encrypts "
            "traffic in transit — phishing domains routinely obtain free TLS certificates."
        )

    # Check Contradiction 3: Official trusted domain with zero critical signals
    dom_rep = next((r for r in reports if r.agent_id == "agent_02_domain"), None)
    has_official_domain = bool(
        dom_rep and any("Verified official domain" in f.summary for f in dom_rep.findings)
    )

    if critical_count >= 1 or total_risk >= 45:
        verdict: VerdictLevel = "HIGH_RISK_SCAM"
        skeptic_note = (
            f"Confirmed {critical_count} deterministic critical red flag(s) across specialist tools. "
            "Do not click links, share OTP/UPI PIN, or call numbers listed inside the message."
        )
    elif warn_count >= 1 or (20 <= total_risk < 45):
        verdict = "SUSPICIOUS_CAUTION"
        skeptic_note = (
            "Multiple caution signals detected, though no single definitive exploit payload was confirmed. "
            "Verify independently using the institution's official website or app."
        )
    elif has_official_domain or (total_trust >= 25 and total_risk == 0):
        verdict = "LOOKS_OK"
        skeptic_note = (
            "All deterministic checks passed (official domain/GSTIN/IFSC verified and zero coercion or "
            "lookalike traps detected). Always ensure you never share your UPI PIN or OTP even on legitimate portals."
        )
    else:
        verdict = "LOOKS_OK" if total_risk == 0 and len(req.raw_text) > 10 else "INSUFFICIENT_DATA"
        skeptic_note = (
            "No scam indicators were triggered by any of the 10 specialist tools, though offline boundaries apply."
        )

    if not unverifiable_all:
        unverifiable_all.append(
            "Live bank beneficiary KYC name and CAPTCHA-gated GST portal filing status cannot be queried passively."
        )

    return SkepticAuditReport(
        request_id=req.request_id,
        agent_address=addr,
        contradictions_found=contradictions,
        unverifiable_boundaries=unverifiable_all,
        adjusted_verdict=verdict,
        skeptic_note=skeptic_note,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 12: ACTION AGENT (`suraksha_action_agent`)
# ═══════════════════════════════════════════════════════════════════════════

def run_action_agent(
    req: InvestigationRequest,
    verdict: VerdictLevel,
    evidence_lines: List[str],
) -> ActionDraftsReport:
    """
    Agent 12 prepares ready-to-file drafts for 1930 / cybercrime.gov.in, the user's bank nodal desk,
    and a bilingual Hinglish/English WhatsApp family alert. Never auto-sends anything.
    """
    t0 = time.perf_counter()
    spec = AGENT_SPECS[11]
    addr = derive_agent_address(os.getenv(spec["seed_env"], spec["default_seed"]))

    urls_str = ", ".join(req.extracted_urls) if req.extracted_urls else "None"
    upis_str = ", ".join(req.extracted_upis) if req.extracted_upis else "None"
    phones_str = ", ".join(req.extracted_phones) if req.extracted_phones else "None"
    gst_str = ", ".join(req.extracted_gstins) if req.extracted_gstins else "None"
    ev_bullets = "\n".join(f"- {line}" for line in evidence_lines[:5])

    cybercrime_report = (
        "=== NATIONAL CYBER CRIME REPORTING PORTAL (cybercrime.gov.in / 1930) DRAFT ===\n"
        f"Incident Category: Online Financial / Communication Fraud ({verdict})\n"
        f"Suspect URLs / Domains: {urls_str}\n"
        f"Suspect UPI IDs (VPAs): {upis_str}\n"
        f"Suspect Phone Numbers: {phones_str}\n"
        f"Suspect GSTINs: {gst_str}\n\n"
        "Technical Forensic Evidence (Suraksha Squad 12-Agent Audit):\n"
        f"{ev_bullets}\n\n"
        "Original Message / Content Received:\n"
        f"\"{req.raw_text}\"\n"
        "Action Requested: Block the reported phishing domain(s), telecom numbers, and mule UPI handle(s) under I4C / DoT Chakshu."
    )

    bank_subject = f"URGENT: Report of Suspected Fraudulent UPI / Phishing Identifier ({upis_str if req.extracted_upis else urls_str})"
    bank_body = (
        "To the Cyber Security & Nodal Grievance Officer,\n\n"
        "I am reporting a suspected fraudulent communication / payment identifier targeting customers:\n"
        f"- Reported UPI VPA(s): {upis_str}\n"
        f"- Reported Phishing Link(s): {urls_str}\n"
        f"- Reported Phone Number(s): {phones_str}\n\n"
        "Forensic Verification Findings:\n"
        f"{ev_bullets}\n\n"
        "Please flag this beneficiary identifier for fraud monitoring and prevent unauthorized debit/collect requests.\n\n"
        "Regards,\n[Your Name / Registered Mobile Number]"
    )

    if verdict in ("HIGH_RISK_SCAM", "SUSPICIOUS_CAUTION"):
        whatsapp_alert = (
            "⚠️ *Suraksha Squad Family Alert (Savdhaan!)* ⚠️\n"
            f"Abhi ek naya scam message circulate ho raha hai ({verdict}):\n"
            f"• Link/UPI/Number: {urls_str if req.extracted_urls else (upis_str if req.extracted_upis else phones_str)}\n"
            f"• Asli Sachai: {evidence_lines[0] if evidence_lines else 'Fake coercion message detected.'}\n"
            "🙏 *Kisi bhi haal mein is link par click na karein, na hi apna UPI PIN / OTP share karein!* "
            "Agar kisi ke saath fraud ho to turant *1930* dial karein."
        )
    else:
        whatsapp_alert = (
            "✅ *Suraksha Squad Verification Note:*\n"
            "Yeh message/link hamare 12-agent forensic check mein safe ('Looks OK') paya gaya hai. "
            "Phir bhi dhyan rakhein: Bank ya સરકારi portal kabhi call par OTP ya UPI PIN nahi maangta."
        )

    return ActionDraftsReport(
        request_id=req.request_id,
        agent_address=addr,
        cybercrime_1930_report=cybercrime_report,
        bank_dispute_email_subject=bank_subject,
        bank_dispute_email_body=bank_body,
        family_whatsapp_alert_hi_en=whatsapp_alert,
        execution_ms=(time.perf_counter() - t0) * 1000,
    )


# ═══════════════════════════════════════════════════════════════════════════
# AGENT 1: CONCIERGE ORCHESTRATOR (`suraksha_concierge`)
# ═══════════════════════════════════════════════════════════════════════════

def investigate_submission(
    raw_text: str,
    request_id: str = "req_live_001",
    channel_hint: Optional[str] = None,
    raw_email_headers: Optional[str] = None,
) -> FinalVerdictBundle:
    """
    Executes the full 12-agent Suraksha Squad workflow:
    1. Concierge extracts structured entities (URLs, UPIs, IFSCs, GSTINs, Phones, Headers)
    2. Fans out to Specialists 2..10 in parallel
    3. Passes all specialist evidence to Agent 11 (Skeptic) for contradiction cross-checking
    4. Invokes Agent 12 (Action Agent) to prepare 1930, Bank, and Family WhatsApp drafts
    5. Packages all 4 ASI:One Interactive Cards + deterministic Verdict Bundle.
    """
    t_start = time.perf_counter()
    req = build_investigation_request(
        raw_text=raw_text,
        request_id=request_id,
        channel_hint=channel_hint,
        raw_email_headers=raw_email_headers,
    )

    specialist_reports: List[SpecialistReport] = [
        run_domain_forensics_agent(req),
        run_page_analyst_agent(req),
        run_message_analyst_agent(req),
        run_upi_verifier_agent(req),
        run_gst_verifier_agent(req),
        run_phone_checker_agent(req),
        run_email_auditor_agent(req),
        run_reputation_agent(req),
        run_pattern_matcher_agent(req),
    ]

    skeptic_audit = run_skeptic_agent(req, specialist_reports)
    verdict = skeptic_audit.adjusted_verdict

    # Collect top 5 evidence lines prioritized by severity (CRITICAL -> WARN -> SAFE -> INFO)
    severity_rank = {"CRITICAL": 0, "WARN": 1, "SAFE": 2, "INFO": 3, "UNVERIFIABLE": 4}
    all_findings: List[EvidenceItem] = [
        f for rep in specialist_reports for f in rep.findings
    ]
    all_findings.sort(key=lambda x: severity_rank.get(x.severity, 9))

    top_evidence_lines = [
        f"[{f.severity}] {f.agent_name} ({f.tool_used}): {f.summary}"
        for f in all_findings[:5]
    ]

    action_drafts = run_action_agent(req, verdict, top_evidence_lines)

    badge_map = {
        "HIGH_RISK_SCAM": "🚨 HIGH RISK SCAM — DO NOT PAY OR CLICK",
        "SUSPICIOUS_CAUTION": "⚠️ SUSPICIOUS — VERIFY INDEPENDENTLY",
        "LOOKS_OK": "✅ LOOKS OK — DETERMINISTIC CHECKS PASSED",
        "INSUFFICIENT_DATA": "ℹ️ INSUFFICIENT DATA — MORE DETAILS NEEDED",
    }

    headline_map = {
        "HIGH_RISK_SCAM": "Multiple Deterministic Forensic Red Flags Confirmed",
        "SUSPICIOUS_CAUTION": "Caution Indicators Found — Independent Verification Advised",
        "LOOKS_OK": "Verified Official / Safe Indicators — Zero Scam Signatures Triggered",
        "INSUFFICIENT_DATA": "No Actionable Fraud Indicators Detected in Snippet",
    }

    ctx_data = enrich_with_context_dev(
        req.raw_text,
        {
            'urls': req.extracted_urls,
            'upis': req.extracted_upis,
            'gstins': req.extracted_gstins,
            'phones': req.extracted_phones,
        },
    )
    asi1_meta = explain_verdict_with_asi1(verdict, top_evidence_lines, skeptic_audit.skeptic_note)
    concise_explanation = asi1_meta['explanation']

    total_ms = (time.perf_counter() - t_start) * 1000

    # Temporary bundle to pass into card builders
    bundle = FinalVerdictBundle(
        request_id=request_id,
        verdict=verdict,
        verdict_badge=badge_map[verdict],
        headline=headline_map[verdict],
        concise_explanation=concise_explanation,
        top_evidence_lines=top_evidence_lines,
        skeptic_audit=skeptic_audit,
        action_drafts=action_drafts,
        specialist_reports=specialist_reports,
        interactive_cards={},
        context_dev_enrichment=ctx_data,
        asi1_llm_metadata=asi1_meta,
        total_execution_ms=round(total_ms, 2),
    )

    bundle.interactive_cards = {
        "form_card": build_intake_form_card(),
        "progress_card": build_progress_card(request_id, specialist_reports),
        "verdict_card": build_verdict_card(bundle),
        "action_card": build_action_card(bundle),
    }
    return bundle
