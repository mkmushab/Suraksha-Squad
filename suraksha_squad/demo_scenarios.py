"""
6 Realistic Indian Demo Scenarios for the 3-Minute Fetch-A-Thon 3.0 Judge Walkthrough:
Includes 5 high-impact scam vectors AND 1 verified legitimate sample ("Looks OK") to prove
Suraksha Squad does not blindly flag every link as a scam.
"""

from __future__ import annotations
from typing import Any, Dict, List

DEMO_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "bijli_sms_scam",
        "title": "1. 'Bijli Kat Jayegi' Electricity Disconnection SMS + APK Trap",
        "channel": "sms",
        "expected_verdict": "HIGH_RISK_SCAM",
        "raw_text": (
            "Dear consumer your Electricity power will be disconnected tonight 9:30 PM from UPPCL office "
            "because your previous month bijli bill was not updated. Immediately call electricity officer "
            "9876543210 or download bill update app https://uppcl-bill-update.xyz/QuickSupport.apk"
        ),
        "raw_email_headers": None,
    },
    {
        "id": "sbi_kyc_phishing",
        "title": "2. Fake SBI YONO PAN/KYC Expiry Link + Spoofed Email Headers",
        "channel": "email",
        "expected_verdict": "HIGH_RISK_SCAM",
        "raw_text": (
            "URGENT NOTICE: Dear Customer, your SBI YONO account and ATM card will be blocked within 2 hours "
            "due to incomplete PAN KYC. Click https://sbi-kyc-pan-verify.top/netbanking-login immediately to verify OTP."
        ),
        "raw_email_headers": (
            "Authentication-Results: mx.google.com; spf=fail (google.com: domain of alert@sbi.co.in does not designate 185.220.101.4 as permitted sender); dkim=fail; dmarc=fail\n"
            "From: SBI KYC Alert <alert@sbi.co.in>\n"
            "Reply-To: supportdesk@sbi-kyc-pan-verify.top"
        ),
    },
    {
        "id": "upi_collect_refund_trap",
        "title": "3. UPI Collect Request 'Enter PIN to Receive Refund' Scam",
        "channel": "upi",
        "expected_verdict": "HIGH_RISK_SCAM",
        "raw_text": (
            "Congratulations! Your electricity subsidy cashback of Rs 4,850 is approved. "
            "Approve UPI collect request from uppcl.refund.helpdesk@oksbi and enter UPI PIN to receive money "
            "into your bank account (IFSC: SBIN0001234) within 15 minutes."
        ),
        "raw_email_headers": None,
    },
    {
        "id": "fake_gst_vendor_invoice",
        "title": "4. B2B Fake GST Invoice with Forged Checksum & SSRF Webhook Trap",
        "channel": "invoice",
        "expected_verdict": "HIGH_RISK_SCAM",
        "raw_text": (
            "TAX INVOICE #INV-2026-991 | Vendor: Apex Infra Supplies | GSTIN: 07AABCU9603R1Z9 | "
            "Taxable Value: Rs 1,20,000 + 18% IGST = Rs 1,41,600. Pay immediately to avoid penalty. "
            "Verify invoice portal at http://169.254.169.254/latest/meta-data/ or https://gst-verify-portal.click/invoice"
        ),
        "raw_email_headers": None,
    },
    {
        "id": "digital_arrest_customs",
        "title": "5. FedEx / Customs / CBI 'Digital Arrest' Video Call Extortion",
        "channel": "whatsapp",
        "expected_verdict": "HIGH_RISK_SCAM",
        "raw_text": (
            "FINAL WARNING from Mumbai Customs & CBI Officer: A FedEx parcel linked to your Aadhaar card "
            "containing illegal passports and MDMA was seized. Supreme Court warrant issued for Digital Arrest. "
            "Stay on Skype video interrogation and transfer security deposit to cbi.clearance.verify@ybl or call +923001234567."
        ),
        "raw_email_headers": None,
    },
    {
        "id": "legitimate_official_safe",
        "title": "6. Legitimate Official NPCI & Valid GST Invoice ('Looks OK' Control)",
        "channel": "web",
        "expected_verdict": "LOOKS_OK",
        "raw_text": (
            "Official reference: Review UPI safety guidelines on https://www.npci.org.in and State Bank portal "
            "https://onlinesbi.sbi. Vendor GSTIN 07AABCU9603R1ZP and IFSC SBIN0000691 verified for standard billing."
        ),
        "raw_email_headers": (
            "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
            "From: NPCI Advisory <no-reply@npci.org.in>\n"
            "Reply-To: no-reply@npci.org.in"
        ),
    },
]
