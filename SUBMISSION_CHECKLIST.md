# Submission Checklist (Fetch-A-Thon 3.0) — Team MAA

## Before anything else (SECURITY)
- [ ] `.env` is NOT in this zip on purpose. Create it: `cp .env.example .env` (or `python scripts/init_env.py`) and fill your keys.
- [ ] Old ASI:One + Context.dev keys and old agent seeds were exposed in an earlier zip: ROTATE them, use NEW seeds.
- [ ] Never upload `.env` to GitHub / Devpost / Unstop / Drive.

## Setup
- [ ] `python -m venv .venv` and activate, then `pip install -r requirements-dev.txt`
- [ ] `python -m unittest discover -s tests` -> must say `OK` (93 tests)
- [ ] `python scripts/check_setup.py`
- [ ] Offline rehearsal: `SURAKSHA_OFFLINE=1 python scripts/local_demo.py` (Windows: `$env:SURAKSHA_OFFLINE="1"`)

## Go live
- [ ] Put your `AGENTVERSE_API_KEY` in `.env`
- [ ] `python run_all.py` -> open each Agent Inspector link -> Connect -> Mailbox -> Finish (all 5 agents)
- [ ] Open https://asi1.ai, chat with `suraksha_concierge`, run the 4 prompts from DEVPOST.md
- [ ] Click Share Chat and copy the URL into the submission
- [ ] Keep `run_all.py` running during judging

## Submission form
- [ ] Public GitHub repo (without .env), README with innovationlab + hackathon badges (already present)
- [ ] Agent addresses (`agent1q...`) of the 5 live agents
- [ ] Shared ASI:One chat URL
- [ ] Demo video (if the portal asks): check the exact rules on the portal
