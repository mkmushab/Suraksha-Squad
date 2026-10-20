# suraksha_upi_verifier

![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

NPCI UPI VPA, IFSC, and Modulo-36 GSTIN verification specialist uAgent used by **`suraksha_concierge`**.

- Checks UPI VPA handles (`@oksbi`, `@ybl`, `@okicici`, etc.), impersonation prefixes, and deceptive UPI Collect debit traps.
- Validates 11-character IFSC codes (`0` in 5th character) and 15-character GSTIN Modulo-36 check digits & state codes.

**Inter-agent protocol `suraksha-upi-gst-a2a` 1.0.0:** `ForensicSpecialistRequest` → `ForensicSpecialistResponse`.
