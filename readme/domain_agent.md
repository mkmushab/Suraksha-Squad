# suraksha_domain_forensics

![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

Domain forensics, page analyst, and threat reputation specialist uAgent used by **`suraksha_concierge`**.

- SSRF-guarded domain, punycode (`xn--`), lookalike brand, and ephemeral tunnel (`ngrok`/`trycloudflare`) detector.
- Inspects suspect URLs for credential harvesting forms and `.apk` sideload malware traps.
- Enriches public domains via Context.dev (`/v1/web/scrape`).

**Inter-agent protocol `suraksha-domain-a2a` 1.0.0:** `ForensicSpecialistRequest` → `ForensicSpecialistResponse`.
