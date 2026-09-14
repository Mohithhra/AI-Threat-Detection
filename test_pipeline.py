import os
import sys
import unittest

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, init_db
from app.modules.cyber_leader import parse_email_headers, extract_links_and_domains
from app.modules.cyber_2 import ThreatIntelClient
from app.modules.aids_member import evaluate_email_risk
from app.modules.cse3 import get_ip_geolocation, generate_pdf_report
from app.modules.ai_nlp import classify_email_intent, scan_body_for_qr_codes
from app.modules.cyber_crime.ncrp_portal import generate_ncrp_complaint_payload
from app.main import run_analysis_pipeline

class TestEmailThreatAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.samples_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
        
        with open(os.path.join(cls.samples_dir, "phishing_ceo_fraud.eml"), "r", encoding="utf-8") as f:
            cls.phish_eml = f.read()

        with open(os.path.join(cls.samples_dir, "malware_invoice.eml"), "r", encoding="utf-8") as f:
            cls.malware_eml = f.read()

        with open(os.path.join(cls.samples_dir, "clean_security_alert.eml"), "r", encoding="utf-8") as f:
            cls.clean_eml = f.read()

        with open(os.path.join(cls.samples_dir, "quishing_phishing.eml"), "r", encoding="utf-8") as f:
            cls.quishing_eml = f.read()

    def test_cyber_leader_header_parser(self):
        result = parse_email_headers(self.phish_eml)
        self.assertIn("headers", result)
        self.assertIn("authentication", result)
        self.assertIn("routing", result)
        self.assertEqual(result["authentication"]["spf_status"], "softfail")
        self.assertEqual(result["authentication"]["dkim_status"], "fail")
        self.assertEqual(result["authentication"]["dmarc_status"], "fail")
        self.assertEqual(result["routing"]["originating_ip"], "185.220.101.5")

    def test_cyber_leader_link_extractor(self):
        parsed = parse_email_headers(self.phish_eml)
        links = extract_links_and_domains(parsed["body"]["html"], parsed["body"]["text"])
        self.assertGreaterEqual(links["total_urls_found"], 1)
        self.assertTrue(any("Raw IP address" in flag or "Mismatched anchor" in flag for u in links["urls"] for flag in u["flags"]))

    def test_cyber_2_threat_intel(self):
        client = ThreatIntelClient()
        intel = client.run_full_threat_intel(
            sender_ip="185.220.101.5",
            sender_domain="apple-executive-support.xyz",
            extracted_urls=[{"url": "http://185.220.101.5/apple-verify/login.php"}]
        )
        self.assertIn("ip_intelligence", intel)
        self.assertIn("domain_intelligence", intel)
        self.assertGreater(intel["ip_intelligence"]["abuse_confidence_score"], 0)

    def test_ai_quishing_and_intent_classifier(self):
        parsed = parse_email_headers(self.quishing_eml)
        ai_intent = classify_email_intent(parsed["headers"]["subject"], parsed["body"]["text"], parsed["body"]["html"])
        quish = scan_body_for_qr_codes(parsed["body"]["html"], [])

        self.assertTrue(quish["has_quishing_threat"])
        self.assertGreater(quish["qr_count"], 0)
        self.assertIn("detected_qr_codes", quish)
        self.assertGreater(ai_intent["ai_risk_score"], 30)

    def test_ncrp_portal_complaint_generation(self):
        db = SessionLocal()
        try:
            scan_res = run_analysis_pipeline(self.phish_eml, "phishing_ceo_fraud.eml", db)
            ncrp = generate_ncrp_complaint_payload(
                scan_data=scan_res,
                victim_name="Rajesh Kumar",
                victim_email="rajesh@company.com",
                victim_phone="+91 9876543210",
                incident_type="Phishing & Brand Impersonation",
                financial_loss=50000.0,
                narrative="Received spoofed CEO email requesting wire transfer."
            )
            self.assertTrue(ncrp["ncrp_acknowledgment_no"].startswith("NCRP-"))
            self.assertGreater(len(ncrp["statutory_law_citations"]), 2)
            self.assertIn("Information Technology Act, 2000", ncrp["statutory_law_citations"][0]["act"])
        finally:
            db.close()

    def test_end_to_end_orchestrator_pipeline(self):
        db = SessionLocal()
        try:
            scan_res = run_analysis_pipeline(self.phish_eml, "phishing_ceo_fraud.eml", db)
            self.assertIn("scan_id", scan_res)
            self.assertIn("pdf_local_path", scan_res)
            self.assertTrue(os.path.exists(scan_res["pdf_local_path"]))
            self.assertEqual(scan_res["risk_assessment"]["threat_level"], "MALICIOUS")
            self.assertIn("quishing_analysis", scan_res)
            self.assertIn("ai_intent_analysis", scan_res)

            # Test clean email
            clean_res = run_analysis_pipeline(self.clean_eml, "clean_security_alert.eml", db)
            self.assertEqual(clean_res["risk_assessment"]["threat_level"], "CLEAN")
            self.assertLess(clean_res["risk_assessment"]["score"], 30)
        finally:
            db.close()

if __name__ == "__main__":
    unittest.main()
