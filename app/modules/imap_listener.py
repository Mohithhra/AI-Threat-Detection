import imaplib
import email
import time
import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from ..database import SessionLocal
from ..main import run_analysis_pipeline

logger = logging.getLogger("IMAPListener")

class RealtimeIMAPMonitor:
    def __init__(self, imap_server: str = "imap.gmail.com", port: int = 993):
        self.imap_server = imap_server
        self.port = port
        self.is_connected = False
        self.monitored_inbox = "INBOX"

    def connect(self, username: str, password: str) -> bool:
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_server, self.port)
            self.mail.login(username, password)
            self.is_connected = True
            logger.info(f"Successfully connected to IMAP server {self.imap_server} for {username}")
            return True
        except Exception as e:
            logger.error(f"IMAP connection failed: {str(e)}")
            self.is_connected = False
            return False

    def fetch_unread_emails(self, db: Session) -> List[Dict[str, Any]]:
        if not self.is_connected:
            return []

        results = []
        try:
            self.mail.select(self.monitored_inbox)
            status, response = self.mail.search(None, 'UNSEEN')
            if status != 'OK':
                return []

            email_ids = response[0].split()
            for eid in email_ids[:10]: # Process up to 10 unread
                status, data = self.mail.fetch(eid, '(RFC822)')
                if status == 'OK':
                    raw_eml = data[0][1].decode('utf-8', errors='replace')
                    filename = f"live_inbox_{eid.decode()}.eml"
                    
                    scan_res = run_analysis_pipeline(raw_eml, filename, db)
                    results.append(scan_res)
                    logger.info(f"Live inbox email {eid} processed: Threat Level={scan_res.get('risk_assessment', {}).get('threat_level')}")

        except Exception as e:
            logger.error(f"Error fetching live inbox emails: {str(e)}")

        return results

    def disconnect(self):
        if self.is_connected:
            try:
                self.mail.logout()
            except Exception:
                pass
            self.is_connected = False
