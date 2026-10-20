"""
Comprehensive automated test suite (64 tests) for Suraksha Squad.
Verifies:
- Deterministic Bech32 `agent1q...` addresses for all 12 agents (0 hardcoded addresses)
- SSRF guard blocking localhost, 127.0.0.1, RFC1918 private IPs, AWS/GCP metadata 169.254.169.254, and file:// schemes
- Modulo-36 GSTIN checksum math across valid & tampered GSTINs and all state codes
- UPI VPA handle registry, impersonation detection, and IFSC structure
- Domain lookalike, punycode (`xn--`), tunnel (`ngrok`/`trycloudflare`), and official allowlist checks
- Multilingual (Hindi/Hinglish/English) coercion patterns
- Email SPF/DKIM/DMARC & Reply-To mismatch auditing
- Skeptic contradiction cross-checking and honest "cannot verify" boundaries
- Full 4-Card ASI:One Interactive Card generation & FastAPI REST endpoints
"""

from __future__ import annotations
import os
import unittest
from app import app, HAS_FASTAPI, FallbackTestClient
if HAS_FASTAPI:
    from fastapi.testclient import TestClient
else:
    TestClient = FallbackTestClient
from suraksha_squad.agents import (
    AGENT_SPECS,
    compute_gstin_check_digit,
    get_agent_registry,
    instantiate_uagents,
    investigate_submission,
    run_domain_forensics_agent,
    run_email_auditor_agent,
    run_gst_verifier_agent,
    run_message_analyst_agent,
    run_page_analyst_agent,
    run_pattern_matcher_agent,
    run_phone_checker_agent,
    run_reputation_agent,
    run_skeptic_agent,
    run_upi_verifier_agent,
    validate_gstin_offline,
)
from suraksha_squad.demo_scenarios import DEMO_SCENARIOS
from suraksha_squad.extractors import build_investigation_request
from suraksha_squad.ssrf_guard import is_ip_public_and_safe, validate_url_ssrf
from suraksha_squad.uagents_compat import derive_agent_address


class TestSurakshaSquadFleet(unittest.TestCase):
    def test_01_twelve_unique_agents_registered(self):
        reg = get_agent_registry()
        self.assertEqual(len(reg), 12)
        names = {a["name"] for a in reg}
        addrs = {a["address"] for a in reg}
        self.assertEqual(len(names), 12)
        self.assertEqual(len(addrs), 12)

    def test_02_bech32_agent_prefix_and_length(self):
        for spec in AGENT_SPECS:
            addr = derive_agent_address(spec["default_seed"])
            self.assertTrue(addr.startswith("agent1"), f"Invalid prefix: {addr}")
            self.assertGreaterEqual(len(addr), 60)

    def test_03_deterministic_derivation_stability(self):
        a1 = derive_agent_address("suraksha_test_seed_alpha")
        a2 = derive_agent_address("suraksha_test_seed_alpha")
        a3 = derive_agent_address("suraksha_test_seed_beta")
        self.assertEqual(a1, a2)
        self.assertNotEqual(a1, a3)

    def test_04_instantiate_all_12_uagents(self):
        fleet = instantiate_uagents()
        self.assertEqual(len(fleet), 12)
        self.assertIn("agent_01_concierge", fleet)
        self.assertIn("agent_12_action", fleet)


class TestSSRFGuard(unittest.TestCase):
    def test_05_block_loopback_127(self):
        res = validate_url_ssrf("http://127.0.0.1:8000/admin", resolve_dns=False)
        self.assertFalse(res.allowed)
        self.assertIn("loopback", res.blocked_reason.lower())

    def test_06_block_localhost_hostname(self):
        res = validate_url_ssrf("http://localhost/secret", resolve_dns=False)
        self.assertFalse(res.allowed)

    def test_07_block_aws_gcp_metadata_ip(self):
        res = validate_url_ssrf("http://169.254.169.254/latest/meta-data/", resolve_dns=False)
        self.assertFalse(res.allowed)

    def test_08_block_rfc1918_10_network(self):
        ok, _ = is_ip_public_and_safe("10.0.0.1")
        self.assertFalse(ok)

    def test_09_block_rfc1918_172_16_network(self):
        ok, _ = is_ip_public_and_safe("172.16.5.4")
        self.assertFalse(ok)

    def test_10_block_rfc1918_192_168_network(self):
        ok, _ = is_ip_public_and_safe("192.168.1.1")
        self.assertFalse(ok)

    def test_11_block_cgnat_100_64_network(self):
        ok, _ = is_ip_public_and_safe("100.64.0.1")
        self.assertFalse(ok)

    def test_12_block_ipv6_loopback(self):
        ok, _ = is_ip_public_and_safe("::1")
        self.assertFalse(ok)

    def test_13_block_file_scheme(self):
        res = validate_url_ssrf("file:///etc/passwd", resolve_dns=False)
        self.assertFalse(res.allowed)

    def test_14_block_gopher_scheme(self):
        res = validate_url_ssrf("gopher://127.0.0.1:70", resolve_dns=False)
        self.assertFalse(res.allowed)

    def test_15_block_ftp_scheme(self):
        res = validate_url_ssrf("ftp://example.com/file.txt", resolve_dns=False)
        self.assertFalse(res.allowed)

    def test_16_block_internal_dot_local_hostname(self):
        res = validate_url_ssrf("https://redis.internal/keys", resolve_dns=False)
        self.assertFalse(res.allowed)

    def test_17_allow_public_ip(self):
        ok, reason = is_ip_public_and_safe("8.8.8.8")
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_18_allow_public_https_domain(self):
        res = validate_url_ssrf("https://www.npci.org.in", resolve_dns=False)
        self.assertTrue(res.allowed)


class TestGSTINValidator(unittest.TestCase):
    def test_19_valid_delhi_gstin_checksum(self):
        res = validate_gstin_offline("07AABCU9603R1ZP")
        self.assertTrue(res["valid"])
        self.assertEqual(res["state"], "Delhi")
        self.assertEqual(res["entity_type"], "Company")

    def test_20_invalid_tampered_gstin_checksum(self):
        res = validate_gstin_offline("07AABCU9603R1Z9")
        self.assertFalse(res["valid"])
        self.assertIn("checksum failed", res["reason"].lower())

    def test_21_invalid_state_code_99(self):
        res = validate_gstin_offline("99AABCU9603R1ZP")
        self.assertFalse(res["valid"])
        self.assertIn("state code", res["reason"].lower())

    def test_22_invalid_embedded_pan_format(self):
        res = validate_gstin_offline("07123459603R1ZP")
        self.assertFalse(res["valid"])
        self.assertIn("pan", res["reason"].lower())

    def test_23_invalid_14th_char_not_z(self):
        res = validate_gstin_offline("07AABCU9603R1XP")
        self.assertFalse(res["valid"])
        self.assertIn("14th", res["reason"].lower())

    def test_24_invalid_length_gstin(self):
        res = validate_gstin_offline("07AABCU9603R1Z")
        self.assertFalse(res["valid"])

    def test_25_maharashtra_valid_gstin(self):
        base14 = "27AAAPA1234A1Z"
        chk = compute_gstin_check_digit(base14)
        res = validate_gstin_offline(base14 + chk)
        self.assertTrue(res["valid"])
        self.assertEqual(res["state"], "Maharashtra")
        self.assertEqual(res["entity_type"], "Individual / Proprietor")

    def test_26_karnataka_firm_gstin(self):
        base14 = "29AAFFA9999A1Z"
        chk = compute_gstin_check_digit(base14)
        res = validate_gstin_offline(base14 + chk)
        self.assertTrue(res["valid"])
        self.assertEqual(res["state"], "Karnataka")
        self.assertEqual(res["entity_type"], "Firm / LLP")


class TestUPIAndIFSCVerifier(unittest.TestCase):
    def test_27_detect_scam_vpa_keywords(self):
        req = build_investigation_request("Pay to uppcl.refund.helpdesk@oksbi now")
        rep = run_upi_verifier_agent(req)
        self.assertGreater(rep.risk_points, 0)
        self.assertTrue(any(f.severity == "CRITICAL" for f in rep.findings))

    def test_28_detect_unknown_upi_handle(self):
        req = build_investigation_request("Send money to merchant123@fakebankhandle")
        rep = run_upi_verifier_agent(req)
        self.assertGreater(rep.risk_points, 0)

    def test_29_valid_ifsc_sbin(self):
        req = build_investigation_request("Account IFSC SBIN0000691 verified")
        rep = run_upi_verifier_agent(req)
        self.assertGreater(rep.trust_points, 0)

    def test_30_invalid_ifsc_bank_prefix(self):
        req = build_investigation_request("Account IFSC ZZZZ0123456")
        rep = run_upi_verifier_agent(req)
        self.assertGreater(rep.risk_points, 0)

    def test_31_honest_unverifiable_upi_holder_note(self):
        req = build_investigation_request("Transfer to ramesh.kumar@okhdfcbank")
        rep = run_upi_verifier_agent(req)
        self.assertTrue(any("cannot be verified offline" in n for n in rep.unverifiable_notes))


class TestDomainAndPageForensics(unittest.TestCase):
    def test_32_detect_sbi_lookalike_domain(self):
        req = build_investigation_request("Login at https://sbi-kyc-update.xyz/login")
        rep = run_domain_forensics_agent(req)
        self.assertGreaterEqual(rep.risk_points, 40)

    def test_33_detect_punycode_homograph(self):
        req = build_investigation_request("Visit https://xn--sb-oia.com/verify")
        rep = run_domain_forensics_agent(req)
        self.assertGreaterEqual(rep.risk_points, 40)

    def test_34_allowlist_official_npci(self):
        req = build_investigation_request("Check https://www.npci.org.in")
        rep = run_domain_forensics_agent(req)
        self.assertEqual(rep.risk_points, 0)
        self.assertGreater(rep.trust_points, 0)

    def test_35_detect_url_shortener(self):
        req = build_investigation_request("Click https://bit.ly/3xyzabc")
        rep = run_domain_forensics_agent(req)
        self.assertGreater(rep.risk_points, 0)

    def test_36_detect_apk_sideload_trap(self):
        req = build_investigation_request("Install https://uppcl-portal.top/ElectricityBill.apk")
        rep = run_page_analyst_agent(req)
        self.assertGreaterEqual(rep.risk_points, 50)

    def test_37_ssrf_url_blocked_in_domain_and_page_agents(self):
        req = build_investigation_request("Fetch http://169.254.169.254/latest/meta-data/")
        d_rep = run_domain_forensics_agent(req)
        p_rep = run_page_analyst_agent(req)
        self.assertEqual(d_rep.status, "BLOCKED_BY_SSRF")
        self.assertGreater(p_rep.risk_points, 0)


class TestMessagePhoneEmailReputationAgents(unittest.TestCase):
    def test_38_hindi_hinglish_bijli_threat(self):
        req = build_investigation_request("Aaj raat bijli kat jayegi turant call karein")
        rep = run_message_analyst_agent(req)
        self.assertGreaterEqual(rep.risk_points, 40)

    def test_39_digital_arrest_cbi_threat(self):
        req = build_investigation_request("CBI officer warrant issued for Digital Arrest on Skype")
        rep = run_message_analyst_agent(req)
        self.assertGreaterEqual(rep.risk_points, 50)

    def test_40_upi_pin_deception_phrase(self):
        req = build_investigation_request("Enter UPI PIN to receive cashback of Rs 2000")
        rep = run_message_analyst_agent(req)
        self.assertGreaterEqual(rep.risk_points, 50)

    def test_41_telegram_task_job_scam(self):
        req = build_investigation_request("Part-time job rate hotels earn Rs 5000 daily on Telegram task")
        rep = run_message_analyst_agent(req)
        self.assertGreaterEqual(rep.risk_points, 35)

    def test_42_personal_mobile_posing_as_electricity_helpline(self):
        req = build_investigation_request("Electricity power disconnect! Call UPPCL helpline officer 9876543210")
        rep = run_phone_checker_agent(req)
        self.assertGreaterEqual(rep.risk_points, 35)

    def test_43_pakistan_voip_prefix_92_detected(self):
        req = build_investigation_request("CBI officer calling from +923001234567")
        rep = run_phone_checker_agent(req)
        self.assertGreaterEqual(rep.risk_points, 45)

    def test_44_email_spf_dkim_fail_and_replyto_mismatch(self):
        req = build_investigation_request(
            "Verify account",
            raw_email_headers=(
                "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
                "From: info@sbi.co.in\n"
                "Reply-To: scammer@evil-domain.xyz"
            ),
        )
        rep = run_email_auditor_agent(req)
        self.assertGreaterEqual(rep.risk_points, 100)

    def test_45_email_spf_dkim_dmarc_pass(self):
        req = build_investigation_request(
            "Official statement",
            raw_email_headers=(
                "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\n"
                "From: no-reply@npci.org.in\n"
                "Reply-To: no-reply@npci.org.in"
            ),
        )
        rep = run_email_auditor_agent(req)
        self.assertEqual(rep.risk_points, 0)
        self.assertGreaterEqual(rep.trust_points, 30)

    def test_46_reputation_tunnel_ngrok_flagged(self):
        req = build_investigation_request("Login at https://a1b2c3.ngrok-free.app/sbi")
        rep = run_reputation_agent(req)
        self.assertGreaterEqual(rep.risk_points, 45)

    def test_47_reputation_abused_tld_flagged(self):
        req = build_investigation_request("Visit https://reward-claim.buzz/win")
        rep = run_reputation_agent(req)
        self.assertGreaterEqual(rep.risk_points, 30)


class TestScenariosSkepticAndActionCards(unittest.TestCase):
    def test_48_scenario_1_bijli_sms_is_high_risk(self):
        b = investigate_submission(DEMO_SCENARIOS[0]["raw_text"])
        self.assertEqual(b.verdict, "HIGH_RISK_SCAM")

    def test_49_scenario_2_sbi_kyc_is_high_risk(self):
        b = investigate_submission(
            DEMO_SCENARIOS[1]["raw_text"],
            raw_email_headers=DEMO_SCENARIOS[1]["raw_email_headers"],
        )
        self.assertEqual(b.verdict, "HIGH_RISK_SCAM")

    def test_50_scenario_3_upi_collect_is_high_risk(self):
        b = investigate_submission(DEMO_SCENARIOS[2]["raw_text"])
        self.assertEqual(b.verdict, "HIGH_RISK_SCAM")

    def test_51_scenario_4_fake_gst_invoice_is_high_risk(self):
        b = investigate_submission(DEMO_SCENARIOS[3]["raw_text"])
        self.assertEqual(b.verdict, "HIGH_RISK_SCAM")

    def test_52_scenario_5_digital_arrest_is_high_risk(self):
        b = investigate_submission(DEMO_SCENARIOS[4]["raw_text"])
        self.assertEqual(b.verdict, "HIGH_RISK_SCAM")

    def test_53_scenario_6_official_safe_link_is_looks_ok(self):
        b = investigate_submission(
            DEMO_SCENARIOS[5]["raw_text"],
            raw_email_headers=DEMO_SCENARIOS[5]["raw_email_headers"],
        )
        self.assertEqual(b.verdict, "LOOKS_OK")

    def test_54_skeptic_catches_valid_upi_handle_contradiction(self):
        b = investigate_submission(DEMO_SCENARIOS[2]["raw_text"])
        self.assertTrue(
            any("valid NPCI" in c or "banking rail" in c for c in b.skeptic_audit.contradictions_found)
        )

    def test_55_skeptic_catches_https_tls_misconception(self):
        b = investigate_submission(DEMO_SCENARIOS[0]["raw_text"])
        self.assertTrue(
            any("https://" in c for c in b.skeptic_audit.contradictions_found)
        )

    def test_56_interactive_cards_all_four_present(self):
        b = investigate_submission(DEMO_SCENARIOS[0]["raw_text"])
        for key in ("form_card", "progress_card", "verdict_card", "action_card"):
            self.assertIn(key, b.interactive_cards)
            self.assertEqual(b.interactive_cards[key]["type"], "asi_interactive_card")

    def test_57_action_agent_drafts_contain_1930_and_passive_disclaimer(self):
        b = investigate_submission(DEMO_SCENARIOS[0]["raw_text"])
        self.assertIn("1930", b.action_drafts.cybercrime_1930_report)
        self.assertIn("never auto-submits", b.action_drafts.safety_disclaimer)


class TestFastAPIWebPlatform(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_58_health_endpoint(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["agent_count"], 12)
        self.assertTrue(data["concierge_address"].startswith("agent1"))

    def test_59_agents_endpoint(self):
        r = self.client.get("/api/agents")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["count"], 12)

    def test_60_scenarios_endpoint(self):
        r = self.client.get("/api/scenarios")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["scenarios"]), 6)

    def test_61_investigate_post_scam(self):
        r = self.client.post("/api/investigate", json={"raw_text": DEMO_SCENARIOS[0]["raw_text"]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["verdict"], "HIGH_RISK_SCAM")

    def test_62_investigate_post_safe_control(self):
        r = self.client.post("/api/investigate", json={"raw_text": DEMO_SCENARIOS[5]["raw_text"]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["verdict"], "LOOKS_OK")

    def test_63_investigate_empty_text_returns_400(self):
        r = self.client.post("/api/investigate", json={"raw_text": "   "})
        self.assertEqual(r.status_code, 400)

    def test_64_dashboard_html_served(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Suraksha Squad", r.text)




class TestContextDevASI1AndActionPilotFixes(unittest.TestCase):
    def test_65_all_12_addresses_start_with_canonical_agent1q_and_len_65(self):
        for ag in get_agent_registry():
            self.assertTrue(ag["address"].startswith("agent1q"), f"Expected agent1q prefix, got {ag['address']}")
            self.assertEqual(len(ag["address"]), 65)

    def test_66_context_dev_enrichment_returns_regulatory_advisories(self):
        from suraksha_squad.context_dev import enrich_with_context_dev
        res = enrich_with_context_dev("Enter UPI PIN to receive refund", {"upis": ["test@oksbi"]})
        self.assertIn("advisories", res)
        self.assertGreaterEqual(len(res["advisories"]), 1)

    def test_67_asi1_explanation_preserves_deterministic_verdict(self):
        from suraksha_squad.asi1_client import explain_verdict_with_asi1
        res = explain_verdict_with_asi1("HIGH_RISK_SCAM", ["[CRITICAL] Lookalike domain"], "Skeptic confirmed")
        self.assertIn("HIGH_RISK_SCAM", res["explanation"])
        self.assertFalse(res["llm_used"])

    def test_68_payment_protocol_rejects_unverified_commit(self):
        from decimal import Decimal
        from suraksha_squad.payment_protocol import verify_payment_commit
        res = verify_payment_commit(
            tx_hash="0x" + "a" * 64,
            expected_recipient="agent1qabc",
            actual_recipient="agent1qabc",
            expected_amount=Decimal("10.00"),
            committed_amount=Decimal("10.00"),
            ledger_verified=False,
        )
        self.assertFalse(res["settled"])
        self.assertEqual(res["status"], "PENDING_ONCHAIN_CONFIRMATION")

    def test_69_payment_protocol_settles_only_when_verified(self):
        from decimal import Decimal
        from suraksha_squad.payment_protocol import verify_payment_commit
        res = verify_payment_commit(
            tx_hash="0x" + "b" * 64,
            expected_recipient="agent1qabc",
            actual_recipient="agent1qabc",
            expected_amount=Decimal("10.00"),
            committed_amount=Decimal("10.00"),
            ledger_verified=True,
        )
        self.assertTrue(res["settled"])
        self.assertEqual(res["status"], "VERIFIED_SETTLED")

    def test_70_dynamic_invoice_amount_parser_fixes_hardcoded_bug(self):
        from decimal import Decimal
        from suraksha_squad.payment_protocol import parse_dynamic_invoice_amount
        amt1 = parse_dynamic_invoice_amount("Invoice Sharma Traders, PIN 302001, 40 hrs web dev at ₹1500/hr")
        self.assertEqual(amt1, Decimal("60000.00"))
        amt2 = parse_dynamic_invoice_amount("Taxable Value: Rs 1,20,000 + 18% IGST = Rs 1,41,600")
        self.assertEqual(amt2, Decimal("141600.00"))

    def test_71_india_post_pin_to_state_resolver(self):
        from suraksha_squad.gst_engine import resolve_pin_to_state
        self.assertEqual(resolve_pin_to_state("302001", allow_network=False), "Rajasthan")
        self.assertEqual(resolve_pin_to_state("110001", allow_network=False), "Delhi")
        self.assertEqual(resolve_pin_to_state("400001", allow_network=False), "Maharashtra")

    def test_72_gst_intra_vs_inter_state_tax_split(self):
        from decimal import Decimal
        from suraksha_squad.gst_engine import verify_invoice_tax_split
        inter = verify_invoice_tax_split(Decimal("60000.00"), "Delhi", "Rajasthan")
        self.assertEqual(inter["regime"], "INTER_STATE_IGST")
        self.assertEqual(inter["igst"], "10800.00")
        self.assertEqual(inter["grand_total"], "70800.00")
        intra = verify_invoice_tax_split(Decimal("60000.00"), "Delhi", "Delhi")
        self.assertEqual(intra["regime"], "INTRA_STATE_CGST_SGST")
        self.assertEqual(intra["cgst"], "5400.00")
        self.assertEqual(intra["sgst"], "5400.00")



    def test_73_env_loader_parses_comments_quotes_and_exports(self):
        from suraksha_squad.env_loader import parse_env_text
        raw = "# comment\nexport ASI_ONE_API_KEY=\"asi1_test_key_123\" # inline\nCONTEXT_DEV_API_KEY='ctx_test_456'"
        parsed = parse_env_text(raw)
        self.assertEqual(parsed["ASI_ONE_API_KEY"], "asi1_test_key_123")
        self.assertEqual(parsed["CONTEXT_DEV_API_KEY"], "ctx_test_456")

    def test_74_env_loader_maps_aliases_to_canonical_keys(self):
        from suraksha_squad.env_loader import normalize_and_apply_env
        applied = normalize_and_apply_env({
            "ASI_ONE_API_KEY": "live_asi1_abc123456",
            "CONTEXT_DEV_API_KEY": "live_ctx_xyz987654",
            "AGENTVERSE_TOKEN": "live_av_token_111222",
        })
        self.assertEqual(applied["ASI1_API_KEY"], "live_asi1_abc123456")
        self.assertEqual(applied["CTX_API_KEY"], "live_ctx_xyz987654")
        self.assertEqual(applied["AGENTVERSE_API_KEY"], "live_av_token_111222")
        # Reset after test
        os.environ.pop("ASI1_API_KEY", None)
        os.environ.pop("ASI_ONE_API_KEY", None)

    def test_75_api_config_env_endpoint_is_removed(self):
        """Security: a public endpoint that writes .env must not exist."""
        client = TestClient(app)
        r = client.post("/api/config/env", json={"raw_env_content": "ASI1_API_KEY=x", "persist_to_disk": False})
        self.assertIn(r.status_code, (404, 405))

    def test_76_health_never_echoes_key_characters(self):
        os.environ["ASI1_API_KEY"] = "secretvalue123456"
        try:
            body = TestClient(app).get("/api/health").text
            self.assertNotIn("secretvalue", body)
            self.assertNotIn("3456", body)
        finally:
            os.environ.pop("ASI1_API_KEY", None)

    def test_77_api_payment_verify_endpoint_rejects_bad_hash(self):
        client = TestClient(app)
        r = client.post(
            "/api/payment/verify",
            json={
                "tx_hash": "invalid_hash",
                "expected_recipient": "agent1qabc",
                "actual_recipient": "agent1qabc",
                "expected_amount": "10.00",
                "committed_amount": "10.00",
                "currency": "FET",
                "ledger_verified": True,
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["settled"])
        self.assertEqual(r.json()["status"], "UNVERIFIED_REJECTED")

    def test_78_api_payment_verify_endpoint_settles_valid_tx(self):
        client = TestClient(app)
        r = client.post(
            "/api/payment/verify",
            json={
                "tx_hash": "0x" + "f" * 64,
                "expected_recipient": "agent1qabc",
                "actual_recipient": "agent1qabc",
                "expected_amount": "15.00",
                "committed_amount": "15.00",
                "currency": "USDC",
                "ledger_verified": True,
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["settled"])
        self.assertEqual(r.json()["status"], "VERIFIED_SETTLED")

    def test_79_chat_protocol_v030_builds_and_attaches(self):
        from suraksha_squad.chat_protocol import build_asi_one_chat_protocol
        proto = build_asi_one_chat_protocol()
        self.assertEqual(proto.name, "AgentChatProtocol")
        self.assertEqual(proto.version, "0.3.0")

    def test_80_run_agents_check_command_succeeds(self):
        import subprocess, sys
        res = subprocess.run([sys.executable, "run_agents.py", "--check"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("All 12 uAgents initialized", res.stdout)



    def test_81_context_dev_scrape_blocks_ssrf_targets(self):
        from suraksha_squad.context_dev import scrape_url_with_context_dev
        res = scrape_url_with_context_dev("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(res["ok"])
        self.assertTrue(res["ssrf_blocked"])

    def test_82_context_dev_scrape_public_domain_offline_safe(self):
        from suraksha_squad.context_dev import scrape_url_with_context_dev
        res = scrape_url_with_context_dev("https://www.npci.org.in")
        self.assertTrue(res["ok"])
        self.assertEqual(res["domain"], "www.npci.org.in")

    def test_83_asi_wire_metadata_format_matches_fetch_spec(self):
        from suraksha_squad.cards import to_asi_wire_metadata
        meta = to_asi_wire_metadata("review", {"title": "Verdict"}, terminal=True)
        self.assertEqual(meta["card_protocol_version"], "1")
        self.assertEqual(meta["requires_card_interaction"], "false")
        self.assertEqual(meta["card_kind"], "review")
        self.assertEqual(meta["is_terminal"], "true")

    def test_84_hosted_suraksha_agent_has_ssrf_guard(self):
        from pathlib import Path
        code = (Path(__file__).resolve().parent.parent / "agentverse_hosted" / "hosted_suraksha_agent.py").read_text()
        self.assertIn("is_safe_public_url", code)
        self.assertIn("169.254.169.254", code)

    def test_85_check_setup_script_runs_cleanly(self):
        import subprocess, sys
        res = subprocess.run([sys.executable, "scripts/check_setup.py"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Ready for Live Demo", res.stdout)

    def test_86_context_dev_key_alias_supported(self):
        from suraksha_squad.env_loader import normalize_and_apply_env
        applied = normalize_and_apply_env({"CONTEXT_DEV_API_KEY": "ctxt_secret_test_key"})
        self.assertEqual(applied["CTX_API_KEY"], "ctxt_secret_test_key")



    def test_87_real_a2a_ctx_send_and_receive_orchestration(self):
        import asyncio, json
        from suraksha_squad.a2a_protocol import (
            ForensicSpecialistRequest,
            ForensicSpecialistResponse,
            SkepticActionRequest,
            SkepticActionResponse,
            execute_domain_group,
            execute_message_group,
            execute_upi_gst_group,
            execute_skeptic_and_action_group,
            investigate_via_uagents,
            domain_specialist_address,
            message_specialist_address,
            upi_gst_specialist_address,
            action_specialist_address,
            _dump_model,
        )
        from suraksha_squad.extractors import build_investigation_request
        from suraksha_squad.models import SpecialistReport

        calls = []

        class FakeA2AContext:
            class logger:
                @staticmethod
                def info(*a, **k): pass
                @staticmethod
                def warning(*a, **k): pass

            async def send_and_receive(self, destination, msg, response_type=None, timeout=15):
                calls.append((destination, type(msg).__name__))
                req = build_investigation_request(raw_text=msg.raw_text, request_id=msg.request_id)
                if destination == domain_specialist_address():
                    reps = execute_domain_group(req)
                    return ForensicSpecialistResponse(
                        request_id=msg.request_id,
                        specialist_group="domain_page_reputation",
                        agent_name="suraksha_domain_forensics",
                        agent_address=destination,
                        ok=True,
                        reports_json=json.dumps([_dump_model(r) for r in reps]),
                    ), "ok"
                if destination == message_specialist_address():
                    reps = execute_message_group(req)
                    return ForensicSpecialistResponse(
                        request_id=msg.request_id,
                        specialist_group="message_phone_email_pattern",
                        agent_name="suraksha_message_analyst",
                        agent_address=destination,
                        ok=True,
                        reports_json=json.dumps([_dump_model(r) for r in reps]),
                    ), "ok"
                if destination == upi_gst_specialist_address():
                    reps = execute_upi_gst_group(req)
                    return ForensicSpecialistResponse(
                        request_id=msg.request_id,
                        specialist_group="upi_ifsc_gstin",
                        agent_name="suraksha_upi_verifier",
                        agent_address=destination,
                        ok=True,
                        reports_json=json.dumps([_dump_model(r) for r in reps]),
                    ), "ok"
                if destination == action_specialist_address():
                    raw_reps = json.loads(msg.reports_json)
                    spec_reps = [SpecialistReport(**r) for r in raw_reps]
                    sk, act, top_ev = execute_skeptic_and_action_group(req, spec_reps)
                    return SkepticActionResponse(
                        request_id=msg.request_id,
                        agent_name="suraksha_action_agent",
                        agent_address=destination,
                        ok=True,
                        skeptic_json=json.dumps(_dump_model(sk)),
                        action_json=json.dumps(_dump_model(act)),
                        top_evidence_json=json.dumps(top_ev),
                    ), "ok"
                return None, "unreachable"

        bundle, a2a_meta = asyncio.run(
            investigate_via_uagents(
                FakeA2AContext(),
                "Dear consumer your bijli will be disconnected tonight 9:30 PM. Update at http://uppcl-kyc-update.xyz/bill.apk or pay electricity.refund@oksbi",
            )
        )
        self.assertEqual(bundle.verdict, "HIGH_RISK_SCAM")
        self.assertFalse(a2a_meta["degraded"])
        self.assertEqual(len(calls), 4)
        self.assertIn("suraksha_domain_forensics", a2a_meta["via"])
        self.assertIn("suraksha_upi_verifier", a2a_meta["via"])
        self.assertIn("suraksha_action_agent", a2a_meta["via"])

    def test_88_a2a_graceful_degraded_fallback_when_specialists_offline(self):
        import asyncio
        from suraksha_squad.a2a_protocol import investigate_via_uagents

        class OfflineContext:
            class logger:
                @staticmethod
                def warning(*a, **k): pass
            async def send_and_receive(self, *a, **k):
                raise TimeoutError("specialist offline")

        bundle, a2a_meta = asyncio.run(
            investigate_via_uagents(
                OfflineContext(),
                "Verify official portal https://onlinesbi.sbi and GSTIN 07AABCU9603R1ZP",
            )
        )
        self.assertEqual(bundle.verdict, "LOOKS_OK")
        self.assertTrue(a2a_meta["degraded"])
        self.assertIn("local fallback", a2a_meta["via"])

    def test_89_payment_protocol_seller_wallet_and_request(self):
        from suraksha_squad.payment_protocol import seller_wallet_address, build_b2b_shield_payment_request
        w = seller_wallet_address()
        self.assertTrue(w.startswith("fetch1"))
        req = build_b2b_shield_payment_request("agent1qtest")
        self.assertEqual(req.recipient, w)
        self.assertEqual({f.currency for f in req.accepted_funds}, {"USDC", "FET"})

    def test_90_live_5_agent_builders_construct_cleanly(self):
        from agents_live.concierge_agent import build_concierge_agent
        from agents_live.domain_agent import build_domain_agent
        from agents_live.message_agent import build_message_agent
        from agents_live.upi_agent import build_upi_agent
        from agents_live.action_agent import build_action_agent
        agents = [
            build_concierge_agent(mailbox=False, port=8211),
            build_domain_agent(mailbox=False, port=8212),
            build_message_agent(mailbox=False, port=8213),
            build_upi_agent(mailbox=False, port=8214),
            build_action_agent(mailbox=False, port=8215),
        ]
        self.assertEqual(len({a.address for a in agents}), 5)


class TestLiveFetchRegression(unittest.TestCase):
    """Regression: with real internet (e.g. GitHub Actions / judging), official portals must not be flagged
    just because their login pages contain password / netbanking fields."""

    LIVE_LOGIN_PAGE = "<html><form><input type=\"password\"> Login to NetBanking. Enter OTP</form></html>"

    def _fake_fetch(self, url, *a, **k):
        from suraksha_squad.ssrf_guard import GuardedFetchResult
        return GuardedFetchResult(ok=True, final_url=url, status_code=200, content_snippet=self.LIVE_LOGIN_PAGE)

    def test_91_official_domain_with_live_login_page_is_still_looks_ok(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"SURAKSHA_OFFLINE": "0"}), \
             mock.patch("suraksha_squad.agents.guarded_http_get", self._fake_fetch):
            b = investigate_submission(
                DEMO_SCENARIOS[5]["raw_text"],
                raw_email_headers=DEMO_SCENARIOS[5]["raw_email_headers"],
            )
        self.assertEqual(b.verdict, "LOOKS_OK")

    def test_92_non_official_domain_with_credential_form_is_still_flagged(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"SURAKSHA_OFFLINE": "0"}), \
             mock.patch("suraksha_squad.agents.guarded_http_get", self._fake_fetch):
            b = investigate_submission("Update KYC now at https://sbi-kyc-update.example.xyz/login")
        self.assertEqual(b.verdict, "HIGH_RISK_SCAM")

    def test_93_offline_mode_skips_live_fetch(self):
        from unittest import mock
        boom = mock.Mock(side_effect=AssertionError("live fetch must not run in offline mode"))
        with mock.patch.dict(os.environ, {"SURAKSHA_OFFLINE": "1"}), \
             mock.patch("suraksha_squad.agents.guarded_http_get", boom):
            investigate_submission(DEMO_SCENARIOS[5]["raw_text"], raw_email_headers=DEMO_SCENARIOS[5]["raw_email_headers"])
        boom.assert_not_called()


if __name__ == "__main__":
    unittest.main()



