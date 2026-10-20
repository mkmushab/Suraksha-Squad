# suraksha_message_analyst

![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

Multilingual coercion lexicon, TRAI phone checker, RFC 8601 email header auditor, and I4C pattern matcher uAgent used by **`suraksha_concierge`**.

- Detects Hindi/Hinglish/English urgency, electricity disconnection ('tonight 9:30 PM'), and 'Digital Arrest' scripts.
- Validates Indian mobile vs official toll-free numbers and foreign VoIP prefixes (`+92`).
- Audits `Authentication-Results` (`SPF`/`DKIM`/`DMARC`) and `From` vs `Reply-To` mismatches.

**Inter-agent protocol `suraksha-message-a2a` 1.0.0:** `ForensicSpecialistRequest` → `ForensicSpecialistResponse`.
