# Security notes

- **Never commit `.env`.** `.gitignore`, `.dockerignore` and the CI job all block it. If a `.env` ever left your machine
  (zip, chat, a public repo), rotate every key in it: ASI:One, Context.dev, Agentverse, Safe Browsing.
- **Use your own agent seeds.** The defaults in `suraksha_squad/agents.py` are public. Run `python scripts/init_env.py`.
- The web app never accepts or writes secrets. (An earlier `/api/config/env` endpoint was removed because on a public
  deployment anyone could overwrite server keys.)
- All outbound fetches go through the SSRF guard (`suraksha_squad/ssrf_guard.py`) at every redirect hop.
- Suraksha Squad only drafts complaints and messages. It never files, sends, calls or pays anything by itself.
- The Payment Protocol demo validates message fields and tx-hash format, but does not verify settlement on-chain.
  Do not treat it as a real payment verifier.
