import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, init_db
from app.modules.cyber_crime import generate_complaint_record, generate_cyber_crime_pdf, generate_abuse_takedown_notice
from app.modules.cyber_leader import scan_email_attachments, parse_email_headers, extract_links_and_domains
from app.modules.threat_export import generate_stix_bundle, generate_csv_iocs, generate_yara_snort_rules
from app.main import run_analysis_pipeline, raise_cyber_crime_complaint, RaiseComplaintRequest

class TestCyberCrimeAndAdvancedFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        samples_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
        with open(os.path.join(samples_dir, "phishing_ceo_fraud.eml"), "r", encoding="utf-8") as f:
            cls.phish_eml = f.read()

    def test_complaint_record_and_pdf_generation(self):
        db = SessionLocal()
        try:
            scan_res = run_analysis_pipeline(self.phish_eml, "phishing_ceo_fraud.eml", db)
            
            # File complaint
            complaint = generate_complaint_record(
                scan_data=scan_res,
                victim_name="John Doe",
                victim_email="victim@company.com",
                victim_phone="+1-555-0199",
                incident_type="CEO Fraud & Wire Extortion",
                financial_loss=45000.0,
                narrative="Received spoofed email claiming to be CEO requesting $45,000 escrow wire transfer.",
                raw_eml=self.phish_eml
            )
            
            self.assertTrue(complaint["case_id"].startswith("CYBER-"))
            self.assertIn("sha256_hash", complaint["evidence_integrity"])
            self.assertEqual(complaint["incident_details"]["financial_loss_amount"], 45000.0)

            # Generate PDF
            pdf_path = generate_cyber_crime_pdf(complaint, output_dir="reports")
            self.assertTrue(os.path.exists(pdf_path))
            self.assertTrue(pdf_path.endswith(".pdf"))
        finally:
            db.close()

    def test_abuse_takedown_notice_generator(self):
        db = SessionLocal()
        try:
            scan_res = run_analysis_pipeline(self.phish_eml, "phishing_ceo_fraud.eml", db)
            takedown = generate_abuse_takedown_notice(scan_res)
            self.assertIn("subject", takedown)
            self.assertIn("email_body", takedown)
            self.assertIn("185.220.101.5", takedown["email_body"])
            self.assertIn("apple-executive-support.xyz", takedown["email_body"])
        finally:
            db.close()

    def test_ioc_export_stix_and_csv(self):
        db = SessionLocal()
        try:
            scan_res = run_analysis_pipeline(self.phish_eml, "phishing_ceo_fraud.eml", db)
            
            # STIX 2.1
            stix = generate_stix_bundle(scan_res)
            self.assertEqual(stix["type"], "bundle")
            self.assertEqual(stix["spec_version"], "2.1")
            self.assertGreater(len(stix["objects"]), 1)

            # CSV
            csv_content = generate_csv_iocs(scan_res)
            self.assertIn("IOC_Type,Indicator_Value", csv_content)
            self.assertIn("185.220.101.5", csv_content)

            # Rules
            rules = generate_yara_snort_rules(scan_res)
            self.assertIn("snort_rule", rules)
            self.assertIn("yara_rule", rules)
            self.assertIn("alert tcp", rules["snort_rule"])
        finally:
            db.close()

    def test_attachment_scanner(self):
        # Scan sample without attachment
        att = scan_email_attachments(self.phish_eml)
        self.assertIn("total_attachments", att)
        self.assertEqual(att["total_attachments"], 0)

if __name__ == "__main__":
    unittest.main()
