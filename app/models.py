from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class SubmittedEmail(Base):
    """Primary record for an analyzed email submission."""
    __tablename__ = "submitted_emails"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), unique=True, index=True)
    filename = Column(String(255), default="email.eml")
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Quick metadata
    subject = Column(String(512), default="")
    sender = Column(String(255), default="")
    recipient = Column(String(255), default="")
    sender_domain = Column(String(255), default="")
    sender_ip = Column(String(64), default="")
    
    # Risk assessment
    risk_score = Column(Integer, default=0)
    threat_level = Column(String(32), default="CLEAN") # CLEAN, SUSPICIOUS, MALICIOUS
    summary = Column(Text, default="")
    
    # Generated Report
    pdf_report_path = Column(String(512), default="")

    # Relationships
    header_analysis = relationship("ParsedHeaderRecord", back_populates="email", uselist=False, cascade="all, delete-orphan")
    threat_intel = relationship("ThreatIntelRecord", back_populates="email", uselist=False, cascade="all, delete-orphan")
    risk_signals = relationship("RiskSignalRecord", back_populates="email", cascade="all, delete-orphan")
    geolocation = relationship("GeolocationRecord", back_populates="email", uselist=False, cascade="all, delete-orphan")
    attachments = relationship("EmailAttachmentRecord", back_populates="email", cascade="all, delete-orphan")
    complaints = relationship("CyberCrimeComplaintRecord", back_populates="email", cascade="all, delete-orphan")

class ParsedHeaderRecord(Base):
    """Detailed parsed email authentication and routing data."""
    __tablename__ = "parsed_headers"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("submitted_emails.id"), nullable=False)
    
    spf_status = Column(String(32), default="none")
    dkim_status = Column(String(32), default="none")
    dmarc_status = Column(String(32), default="none")
    has_dkim_signature = Column(Boolean, default=False)
    domain_mismatch = Column(Boolean, default=False)
    
    originating_ip = Column(String(64), default="")
    total_hops = Column(Integer, default=0)
    
    raw_headers_json = Column(Text, default="{}")

    email = relationship("SubmittedEmail", back_populates="header_analysis")

class ThreatIntelRecord(Base):
    """Aggregated VirusTotal and AbuseIPDB results."""
    __tablename__ = "threat_intel_records"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("submitted_emails.id"), nullable=False)
    
    abuse_confidence_score = Column(Integer, default=0)
    abuse_total_reports = Column(Integer, default=0)
    vt_domain_malicious = Column(Integer, default=0)
    total_malicious_urls = Column(Integer, default=0)
    
    intel_json = Column(Text, default="{}")

    email = relationship("SubmittedEmail", back_populates="threat_intel")

class RiskSignalRecord(Base):
    """Individual triggered risk signals for explainability."""
    __tablename__ = "risk_signals"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("submitted_emails.id"), nullable=False)
    
    signal_id = Column(String(64))
    category = Column(String(64))
    name = Column(String(255))
    weight = Column(Integer, default=0)
    severity = Column(String(32), default="LOW")
    description = Column(Text, default="")

    email = relationship("SubmittedEmail", back_populates="risk_signals")

class GeolocationRecord(Base):
    """Origin IP geolocation details."""
    __tablename__ = "geolocation_records"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("submitted_emails.id"), nullable=False)
    
    ip = Column(String(64), default="")
    country = Column(String(128), default="")
    country_code = Column(String(16), default="")
    city = Column(String(128), default="")
    region = Column(String(128), default="")
    isp = Column(String(255), default="")
    asn = Column(String(64), default="")
    lat = Column(Float, default=0.0)
    lon = Column(Float, default=0.0)

    email = relationship("SubmittedEmail", back_populates="geolocation")

class EmailAttachmentRecord(Base):
    """Extracted file attachments and cryptographic hashes."""
    __tablename__ = "email_attachments"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("submitted_emails.id"), nullable=False)

    filename = Column(String(255), default="")
    file_size = Column(Integer, default=0)
    content_type = Column(String(128), default="")
    sha256 = Column(String(64), index=True)
    md5 = Column(String(32))
    sha1 = Column(String(40))
    is_dangerous = Column(Boolean, default=False)
    threat_flag = Column(String(255), default="")

    email = relationship("SubmittedEmail", back_populates="attachments")

class CyberCrimeComplaintRecord(Base):
    """Official filed Cyber Crime complaints and law enforcement case files."""
    __tablename__ = "cyber_crime_complaints"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(64), unique=True, index=True)
    email_id = Column(Integer, ForeignKey("submitted_emails.id"), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(32), default="FILED")

    victim_name = Column(String(255), default="")
    victim_email = Column(String(255), default="")
    victim_phone = Column(String(64), default="")

    incident_type = Column(String(128), default="")
    financial_loss = Column(Float, default=0.0)
    narrative = Column(Text, default="")

    suspect_email = Column(String(255), default="")
    suspect_ip = Column(String(64), default="")
    suspect_location = Column(String(255), default="")
    evidence_sha256 = Column(String(64), default="")

    complaint_pdf_path = Column(String(512), default="")
    complaint_json = Column(Text, default="{}")

    email = relationship("SubmittedEmail", back_populates="complaints")
