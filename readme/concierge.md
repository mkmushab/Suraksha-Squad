# suraksha_concierge — Suraksha Squad (ASI:One Front Door Orchestrator)

![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

**Multi-agent Indian scam, phishing, UPI Collect, GSTIN & 'Digital Arrest' investigator.** Paste any suspicious SMS, WhatsApp forward, URL, UPI ID, phone number, email header, or GST invoice inside this chat. I orchestrate live specialist uAgents over `ctx.send_and_receive` and return an evidence-backed verdict plus ready-to-file **1930 / `cybercrime.gov.in`**, **Bank Nodal Officer**, and **Hinglish Family WhatsApp Alert** drafts.

## Live Multi-Agent Architecture (`ctx.send_and_receive`)
1. **`suraksha_concierge` (`:8001`)** — ASI:One front door (`AgentChatProtocol v0.3.0`, Interactive Cards `form`/`review`, `AgentPaymentProtocol v0.1.0`).
2. **`suraksha_domain_forensics` (`:8002`)** — DNS, TLS, SSRF-guarded redirects, punycode/lookalike, `.apk` sideload trap & threat reputation.
3. **`suraksha_message_analyst` (`:8004`)** — Hindi/Hinglish/English coercion lexicon, TRAI phone checker, RFC 8601 SPF/DKIM/DMARC & I4C scam playbooks.
4. **`suraksha_upi_verifier` (`:8005`)** — NPCI UPI VPA handle registry, UPI Collect debit trap, 11-char IFSC & Modulo-36 GSTIN checksum.
5. **`suraksha_action_agent` (`:8012`)** — Epistemic Skeptic contradiction cross-checker & 1930 / Bank / Family WhatsApp draft generator.

## Try It in ASI:One Chat
- `hi`
- `Dear consumer your electricity power will be disconnected tonight 9:30 PM. Update KYC at http://uppcl-kyc-update.xyz/bill.apk or pay Rs 10 to electricity.refund@oksbi`
- `Verify official link https://onlinesbi.sbi and GSTIN 07AABCU9603R1ZP`
- `pay via Fetch.ai`
