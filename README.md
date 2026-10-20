# 🛡️ Suraksha Squad — Multi-Agent Indian Scam & Invoice Investigator

![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

**Team MAA** — Mohd Mushab Khan (Team Leader) · Abiha · Abhilasha Singh  
**Challenge:** Fetch-A-Thon 3.0 (GCET Edition) · **ASI:One Agent Challenge — From Intent to Action**  
**Protocols:** Fetch.ai `uAgents` · `Agent Chat Protocol v0.3.0` (`uagents_core.contrib.protocols.chat`) · `ASI:One Interactive Cards v1` · `Agent Payment Protocol v0.1.0` (`uagents_core.contrib.protocols.payment`)

## 🎯 The Real-World Problem
Every day, Indian citizens and small businesses face high-pressure digital scams: **"Bijli kat jayegi tonight at 9:30 PM"** SMS messages, **SBI/PAN KYC phishing links**, **deceptive UPI Collect debit requests** (*"Enter UPI PIN to receive refund"*), **forged B2B GST invoices**, and **CBI/Customs 'Digital Arrest' video extortion**.

**Suraksha Squad** lets any user paste a suspicious SMS, WhatsApp forward, URL, UPI ID, phone number, email header, or GST invoice directly inside an **ASI:One conversation** (or our live web simulator). **`suraksha_concierge`** orchestrates specialist `uAgents` via **real `await ctx.send_and_receive(...)` protocol messages**, runs deterministic passive forensic tools, cross-checks contradictions through an **Epistemic Skeptic**, and returns an evidence-backed verdict plus ready-to-file **1930 / `cybercrime.gov.in`**, **Bank Nodal Officer**, and **Hinglish Family WhatsApp Alert** drafts.

```
 ASI:One User ──ACP v0.3.0 + Cards + Payment v0.1.0──▶ suraksha_concierge (:8001)
                                                               │
            ┌──────────────────────────────────────────────────┼──────────────────────────────────────────────────┐
            │ ctx.send_and_receive                             │ ctx.send_and_receive                             │ ctx.send_and_receive
            ▼                                                  ▼                                                  ▼
 suraksha_domain_forensics (:8002)                  suraksha_message_analyst (:8004)                   suraksha_upi_verifier (:8005)
 (Domain · Page APK · SSRF · Context.dev)           (Coercion · Phone · SPF/DKIM · Playbooks)          (NPCI UPI VPA · IFSC · Modulo-36 GSTIN)
            │                                                  │                                                  │
            └──────────────────────────────────────────────────┼──────────────────────────────────────────────────┘
                                                               │ ctx.send_and_receive (SkepticActionRequest)
                                                               ▼
                                                    suraksha_action_agent (:8012)
                                          (Epistemic Skeptic Cross-Check + 1930 / Bank / WhatsApp Drafts)
```

## 🤖 Multi-Agent Architecture: 5 Live A2A `uAgents` hosting 12 agent identities / forensic modules
All 12 specialist identities derive cryptographic Bech32 `agent1q...` addresses from their seeds via `uagents_core.identity.Identity.from_seed(seed, 0)`.

### A. 5 Live Multi-Process `uAgents` (Started by `python run_all.py`, Communicating via `await ctx.send_and_receive(...)`)
| Port | Agent Name | Inter-Agent Protocol | Live Responsibility |
|---|---|---|---|
| `:8001` | `suraksha_concierge` | `AgentChatProtocol v0.3.0` + `AgentPaymentProtocol v0.1.0` | ASI:One front door, Interactive Cards (`form`, `review`), parallel `ctx.send_and_receive` fan-out & graceful fallback |
| `:8002` | `suraksha_domain_forensics` | `suraksha-domain-a2a v1.0.0` | Executes Domain Forensics (`agent_02`), Page APK/Credential Analyst (`agent_03`), Reputation (`agent_09`) & Context.dev scrape |
| `:8004` | `suraksha_message_analyst` | `suraksha-message-a2a v1.0.0` | Executes Hindi/Hinglish Coercion Lexicon (`agent_04`), TRAI Phone Checker (`agent_07`), Email SPF/DKIM/DMARC (`agent_08`) & I4C Playbooks (`agent_10`) |
| `:8005` | `suraksha_upi_verifier` | `suraksha-upi-gst-a2a v1.0.0` | Executes NPCI UPI VPA & Collect Verifier (`agent_05`) + Offline Modulo-36 GSTIN & India Post PIN Verifier (`agent_06`) |
| `:8012` | `suraksha_action_agent` | `suraksha-action-a2a v1.0.0` | Executes Epistemic Skeptic Contradiction Cross-Checker (`agent_11`) + 1930 / Bank Nodal / Family Alert Draft Generator (`agent_12`) |

### B. Honest Epistemics & Security Guardrails
1. **Verdict from Tool Evidence, Never LLM Guessing:** Verdicts (`HIGH_RISK_SCAM`, `SUSPICIOUS_CAUTION`, `LOOKS_OK`) come strictly from deterministic tool checks. ASI:One (`asi1-mini`) is used only to explain the deterministic findings in clear English/Hinglish.
2. **Epistemic Skeptic (a module hosted inside `suraksha_action_agent`) & Honest Boundaries:** Explains why a valid `@oksbi` handle or `https://` TLS certificate does not prove legitimacy, and explicitly states what cannot be verified passively offline (such as live bank account holder KYC names or CAPTCHA-gated GST portal filings).
3. **Legitimate Control Benchmark (`LOOKS_OK`):** Official portals (`https://onlinesbi.sbi`, `https://www.npci.org.in`) and valid Modulo-36 GSTINs (`07AABCU9603R1ZP`) return `LOOKS_OK`.
4. **Graceful Degradation:** If any specialist `uAgent` process is offline, `suraksha_concierge` catches the timeout, computes the forensic step locally, and explicitly notes the fallback on the Review Card.

## 🚀 Quick Start (Windows PowerShell & Linux/macOS)

### 1. Create Virtual Environment & Install Dependencies
**Windows PowerShell:**
```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
**Linux / macOS:**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the 90 Automated Unit Tests & Pre-Flight Check
```powershell
python -m unittest discover -s tests -v
python scripts/check_setup.py
python run_demo.py
```

### 3. Rehearse the 5-Agent `ctx.send_and_receive` Flow Offline (No Internet Needed)
```powershell
$env:SURAKSHA_OFFLINE="1"
python scripts/local_demo.py
python scripts/local_demo.py --degraded
```

### 4. Start All 5 Live `uAgents` for Agentverse Mailbox & ASI:One Discovery
```powershell
python run_all.py
```
Each agent prints an **Agent Inspector** link on startup → open it in your browser → click **Connect → Mailbox → Finish**. Once connected, open [ASI:One](https://asi1.ai/) and chat directly with **`suraksha_concierge`**!

### 5. Launch the Optional Web Simulator & Dashboard (`http://localhost:8000`)
```powershell
python app.py
```
The web simulator runs the forensic tools **in-process** (the dashboard says so). The real agent-to-agent path is the
ASI:One / Agentverse chat path from step 4.

Full Agentverse + ASI:One walkthrough: [`docs/AGENTVERSE_SETUP.md`](docs/AGENTVERSE_SETUP.md).

## 🔐 Environment Variables (`.env`)
Never commit `.env` (`.gitignore`, `.dockerignore` and CI all block it). Run `python scripts/init_env.py` to create one with
fresh random seeds, then add your keys:
- `ASI1_API_KEY` (`asi1-mini`): natural-language explanation of the deterministic findings.
- `CTX_API_KEY`: live SSRF-guarded domain scraping via Context.dev (offline fallback if unset).
- `SURAKSHA_*_SEED`: seeds that derive each `agent1q...` address and the seller `fetch1...` wallet. **Use your own**: the
  defaults in the code are public. See [`SECURITY.md`](SECURITY.md).

## ⚠️ Known limits (so nobody is surprised)
- 5 processes are real uAgents talking over `ctx.send_and_receive`; they host 12 identities/modules (e.g. the Skeptic runs
  inside `suraksha_action_agent`, not as its own process).
- Payment Protocol: the demo emits `RequestPayment` and validates fields/hash format; it does not verify settlement on-chain.
- Cannot be verified passively: bank beneficiary KYC name, CAPTCHA-gated GST filing status. The Skeptic says so.
- Tests (90) run offline. Live Agentverse / ASI:One behaviour must be checked on your account.

MIT licensed, see [`LICENSE`](LICENSE).
