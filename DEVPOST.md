# Devpost / Unstop Submission Kit — Suraksha Squad (Team MAA)

## 1. Brief Description (Copy-Paste for Devpost / Unstop)
* **Problem Solved:** Millions of Indian citizens and small businesses are targeted daily by high-urgency digital scams — fake *"Bijli kat jayegi tonight at 9:30 PM"* SMS messages, lookalike SBI/PAN KYC links, deceptive UPI Collect requests (*"Enter UPI PIN to receive money"*), forged GST invoices, and fake CBI/Customs *"Digital Arrest"* video extortion. Victims panic because they cannot quickly verify links, UPI handles, IFSC codes, or GSTINs inside a single chat.
* **Target Users:** Everyday Indian UPI/WhatsApp users, senior citizens & families, and small merchants/freelancers verifying unknown invoices or payment links.
* **Executable Outcome Produced by the Agent:** Inside a single **ASI:One conversation** (using **Agent Chat Protocol v0.3.0** and **ASI:One Interactive Cards**), the user pastes any suspicious message, URL, UPI ID, phone number, email header, or GST bill. **`suraksha_concierge`** fans out via real **`await ctx.send_and_receive(...)`** messages to specialist `uAgents` (`suraksha_domain_forensics`, `suraksha_message_analyst`, `suraksha_upi_verifier`, and `suraksha_action_agent`), cross-checks contradictions via an **Epistemic Skeptic**, and returns:
  1. An Interactive **Review Card** (`HIGH_RISK_SCAM`, `SUSPICIOUS_CAUTION`, or `LOOKS_OK`) with top deterministic evidence lines and explicit *"Cannot Verify Passively"* boundaries.
  2. A ready-to-file **1930 / `cybercrime.gov.in` Incident Report** pre-filled with extracted URLs, UPI VPAs, phone numbers, and forensic findings.
  3. A **Bank Nodal Officer Fraud Freeze Email** draft and a **Hinglish Family WhatsApp Alert**.
  4. Support for the **Fetch.ai Agent Payment Protocol (`v0.1.0`)** (`RequestPayment` in `USDC` / `FET`) for B2B merchants subscribing to the bulk API fraud shield.

## 2. Demo Prompts for ASI:One Chat (Shared Chat URL)
Run `python run_all.py`, connect the Mailboxes on Agentverse, open [ASI:One](https://asi1.ai/), and run these 4 turns before clicking **Share Chat**:
1. `hi`
   *(Triggers the ASI:One Interactive Form Card `card_kind: "form"`)*
2. `Dear consumer your electricity power will be disconnected tonight 9:30 PM. Update KYC immediately at http://uppcl-kyc-update.xyz/bill.apk or pay Rs 10 to electricity.refund@oksbi`
   *(Triggers real `ctx.send_and_receive` fan-out across `suraksha_domain_forensics`, `suraksha_message_analyst`, `suraksha_upi_verifier`, and `suraksha_action_agent` → returns `HIGH_RISK_SCAM` Review Card, catches the `@oksbi` handle contradiction via the Skeptic module inside `suraksha_action_agent`, and generates the 1930 complaint + Hinglish family alert)*
3. `Please verify official link https://onlinesbi.sbi and GSTIN 07AABCU9603R1ZP`
   *(Proves the legitimate control benchmark → returns `LOOKS_OK` after verifying the `.sbi` domain and Modulo-36 GSTIN checksum)*
4. `pay via Fetch.ai`
   *(Emits a native `AgentPaymentProtocol v0.1.0` `RequestPayment` in `USDC` and `FET` to the concierge agent's derived `fetch1...` wallet)*

## 3. Judge Q&A Cheat-Sheet
* **Q: Do your agents actually talk to each other over uAgents, or is it just one function call?**
  * **A:** Both are honestly separated and documented! Our 5 core agents (`suraksha_concierge` `:8001`, `suraksha_domain_forensics` `:8002`, `suraksha_message_analyst` `:8004`, `suraksha_upi_verifier` `:8005`, and `suraksha_action_agent` `:8012`) run as separate processes (`python run_all.py`) and exchange typed `ForensicSpecialistRequest/Response` and `SkepticActionRequest/Response` messages via **`await ctx.send_and_receive(...)`** (`suraksha_squad/a2a_protocol.py`). If a specialist process is stopped, `suraksha_concierge` degrades gracefully to local execution and explicitly flags it on the Review Card (`python scripts/local_demo.py --degraded`).
* **Q: How do you avoid LLM hallucinations on scam verdicts?**
  * **A:** Every verdict (`HIGH_RISK_SCAM`, `SUSPICIOUS_CAUTION`, `LOOKS_OK`) is computed 100% deterministically from passive tool checks (Modulo-36 GSTIN math, NPCI UPI VPA registry, SSRF-guarded domain/punycode/`.apk` inspection, SPF/DKIM/DMARC parsing). ASI:One (`asi1-mini`) is used strictly to summarize those deterministic findings in natural English/Hinglish.
