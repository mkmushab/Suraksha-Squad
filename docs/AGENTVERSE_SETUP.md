# Agentverse + ASI:One setup (step by step)

This is the exact flow to get `suraksha_concierge` answering inside ASI:One / Agentverse chat.
Everything here uses the standard uAgents mailbox flow. Nothing in this repo calls an undocumented Agentverse API.

## 0. Prerequisites
- Python 3.10+ and `pip install -r requirements.txt`
- A free account on https://agentverse.ai
- Optional keys (the app works offline without them): `ASI1_API_KEY` (https://asi1.ai) and `CTX_API_KEY` (Context.dev)

## 1. Generate your own seeds (do this before anything else)
```bash
python scripts/init_env.py      # creates .env with fresh random seeds, never overwrites an existing .env
```
The default seeds in the code are public (they are in GitHub), so anyone can derive those agents' private keys.
Your own seeds make your agent addresses yours. Changing seeds changes every `agent1q...` address, so do it once,
before you connect mailboxes. Then add your optional API keys to `.env`.

## 2. Check everything locally (no internet needed)
```bash
python -m unittest discover -s tests -v
SURAKSHA_OFFLINE=1 python scripts/local_demo.py            # full agent-to-agent flow
SURAKSHA_OFFLINE=1 python scripts/local_demo.py --degraded # specialists down -> honest fallback
```
Expected: `ALL STEPS PASSED`.

## 3. Start the 5 live agents
```bash
python run_all.py
```
This starts 5 separate processes: concierge (:8001), domain (:8002), message (:8004), upi (:8005), action (:8012).
Each prints an **Agent Inspector** link like `https://agentverse.ai/inspect/?uri=http%3A//127.0.0.1%3A8001&address=agent1q...`.

## 4. Connect each agent's mailbox (once per agent)
For every agent, in this order: concierge first, then the four specialists.
1. Open its Inspector link in your browser (logged in to Agentverse).
2. Click **Connect**, choose **Mailbox**, then **Finish**.
3. The terminal shows that the mailbox access token was acquired.

The specialists need the mailbox only if they run on a different machine from the concierge. On one laptop they reach
each other directly. The concierge needs it so ASI:One can reach you.

## 5. Make the concierge discoverable
In Agentverse open **Agents -> suraksha_concierge**:
1. Check that the README shows (it is loaded from `readme/concierge.md`; keep the two badge tags `innovationlab` and `hackathon`).
2. Check that the protocols list includes the Chat protocol.
3. Optional: set a handle / avatar.

## 6. Chat with it
Open https://asi1.ai (or the agent's **Chat with Agent** button in Agentverse) and try, in this order:
1. `hi`
2. `Dear consumer your electricity power will be disconnected tonight 9:30 PM. Update KYC at http://uppcl-kyc-update.xyz/bill.apk or pay Rs 10 to electricity.refund@oksbi` -> `HIGH_RISK_SCAM`
3. `Please verify official link https://onlinesbi.sbi and GSTIN 07AABCU9603R1ZP` -> `LOOKS_OK`
4. `pay via Fetch.ai` -> payment request message

In the terminal you will see each specialist log `A2A request ... from agent1q...`: those are real messages between agents.

## 7. Prove the agents really talk to each other (for judges)
- Stop one specialist (Ctrl+C in its terminal) and ask again. The reply says which agent was offline and that the
  concierge ran that step locally (`degraded`). This honesty is deliberate.
- Show the 5 terminals side by side while you send step 2.

## 8. Deploy the web simulator (optional, separate from the agents)
- Render: New -> Blueprint -> pick this repo (`render.yaml`). Add `ASI1_API_KEY` / `CTX_API_KEY` in the Environment tab.
- The web simulator runs the forensic tools in-process and says so on screen. The agent-to-agent path is the
  ASI:One chat path from step 6, which needs your agents running (laptop on, or a VM running `python run_all.py`).

## Troubleshooting
| Symptom | Fix |
|---|---|
| `Ledger unavailable` warnings | Harmless, no wallet funds needed for the mailbox flow |
| Agent not found in ASI:One | Mailbox not connected, or concierge process stopped. Re-open the Inspector link |
| Addresses changed after editing `.env` | Seeds changed. Reconnect mailboxes |
| Specialists show `local fallback` | Specialist process not running, or the 15 s timeout (`A2A_TIMEOUT`) was hit |
| Windows PowerShell activation blocked | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |

I have not been able to test the live Agentverse / ASI:One steps from the build environment, so run step 6 once yourself
before the demo and keep a screen recording as a backup.
