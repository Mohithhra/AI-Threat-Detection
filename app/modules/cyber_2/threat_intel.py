import os
import base64
import requests
from typing import Dict, Any, List, Optional

class ThreatIntelClient:
    """
    Threat Intelligence client integrating VirusTotal (v3) and AbuseIPDB (v2).
    Includes intelligent fallback/mock heuristics when keys are absent or rate-limited.
    """
    def __init__(self, vt_api_key: Optional[str] = None, abuse_api_key: Optional[str] = None):
        self.vt_api_key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.abuse_api_key = abuse_api_key or os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.timeout = 5.0

    def check_ip_abuseipdb(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation on AbuseIPDB v2 API.
        """
        # Exclude private/loopback
        if not ip_address or ip_address.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3")):
            return {
                "ip": ip_address,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "is_whitelisted": True,
                "country_code": "LOCAL",
                "usage_type": "Private Network",
                "is_mock": False,
                "status": "clean"
            }

        # If real API key is provided
        if self.abuse_api_key:
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Key": self.abuse_api_key,
                    "Accept": "application/json"
                }
                params = {
                    "ipAddress": ip_address,
                    "maxAgeInDays": "90",
                    "verbose": ""
                }
                response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    return {
                        "ip": ip_address,
                        "abuse_confidence_score": score,
                        "total_reports": data.get("totalReports", 0),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "country_code": data.get("countryCode", "UNKNOWN"),
                        "usage_type": data.get("usageType", "Data Center/Web Hosting/Transit"),
                        "domain": data.get("domain", ""),
                        "last_reported_at": data.get("lastReportedAt"),
                        "is_mock": False,
                        "status": "malicious" if score >= 50 else ("suspicious" if score >= 20 else "clean")
                    }
            except Exception:
                pass

        # Intelligent Fallback Heuristic
        return self._mock_abuseipdb(ip_address)

    def check_url_virustotal(self, target_url: str) -> Dict[str, Any]:
        """
        Check URL reputation on VirusTotal v3 API.
        """
        if self.vt_api_key:
            try:
                # VirusTotal requires base64 url without padding
                url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
                api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                headers = {"x-apikey": self.vt_api_key}
                
                response = requests.get(api_url, headers=headers, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    status = "clean"
                    if malicious > 0:
                        status = "malicious"
                    elif suspicious > 0:
                        status = "suspicious"

                    return {
                        "target": target_url,
                        "type": "url",
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "harmless_count": harmless,
                        "total_engines": total,
                        "reputation": data.get("reputation", 0),
                        "is_mock": False,
                        "status": status
                    }
            except Exception:
                pass

        return self._mock_virustotal_url(target_url)

    def check_domain_virustotal(self, domain: str) -> Dict[str, Any]:
        """
        Check Domain reputation on VirusTotal v3 API.
        """
        if self.vt_api_key:
            try:
                api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {"x-apikey": self.vt_api_key}
                response = requests.get(api_url, headers=headers, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    status = "clean"
                    if malicious > 0:
                        status = "malicious"
                    elif suspicious > 0:
                        status = "suspicious"

                    return {
                        "target": domain,
                        "type": "domain",
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "harmless_count": harmless,
                        "total_engines": total,
                        "reputation": data.get("reputation", 0),
                        "is_mock": False,
                        "status": status
                    }
            except Exception:
                pass

        return self._mock_virustotal_domain(domain)

    def run_full_threat_intel(self, sender_ip: str, sender_domain: str, extracted_urls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Orchestrate threat intelligence queries for IP, sender domain, and all extracted links.
        """
        # 1. IP Reputation (AbuseIPDB)
        ip_result = self.check_ip_abuseipdb(sender_ip)

        # 2. Sender Domain Reputation (VirusTotal)
        domain_result = self.check_domain_virustotal(sender_domain)

        # 3. URL Reputations (VirusTotal)
        url_results = []
        for url_item in extracted_urls[:8]: # Cap at top 8 to prevent rate limiting
            res = self.check_url_virustotal(url_item["url"])
            url_results.append(res)

        # Compute summary counts
        total_malicious_urls = sum(1 for u in url_results if u.get("status") == "malicious")
        total_suspicious_urls = sum(1 for u in url_results if u.get("status") == "suspicious")

        return {
            "ip_intelligence": ip_result,
            "domain_intelligence": domain_result,
            "url_intelligence": url_results,
            "summary": {
                "ip_flagged": ip_result.get("abuse_confidence_score", 0) >= 20,
                "domain_flagged": domain_result.get("malicious_count", 0) > 0,
                "total_malicious_urls": total_malicious_urls,
                "total_suspicious_urls": total_suspicious_urls,
                "using_live_keys": bool(self.vt_api_key or self.abuse_api_key)
            }
        }

    # --- Heuristic Fallback Simulators for Demos & Testing ---

    def _mock_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Deterministic mock for AbuseIPDB based on known suspicious test ranges/IPs."""
        # Check if IP has typical malicious test characteristics
        high_risk_prefixes = ("185.220.", "45.154.", "194.26.", "193.106.", "103.208.", "91.240.")
        
        if any(ip.startswith(prefix) for prefix in high_risk_prefixes) or "evil" in ip:
            score = 88
            reports = 142
            status = "malicious"
            country = "RU"
        elif ip.startswith("198.51.100.") or ip.startswith("203.0.113."): # RFC 5737 doc IPs
            score = 35
            reports = 8
            status = "suspicious"
            country = "NL"
        elif ip in ("127.0.0.1", "0.0.0.0", "localhost"):
            score = 0
            reports = 0
            status = "clean"
            country = "LOCAL"
        else:
            # Default benign score
            score = 0
            reports = 0
            status = "clean"
            country = "US"

        return {
            "ip": ip,
            "abuse_confidence_score": score,
            "total_reports": reports,
            "is_whitelisted": score == 0,
            "country_code": country,
            "usage_type": "Data Center / Hosting Provider",
            "is_mock": True,
            "status": status
        }

    def _mock_virustotal_url(self, target_url: str) -> Dict[str, Any]:
        """Deterministic mock for VirusTotal URL scan based on content heuristics."""
        lower_url = target_url.lower()
        malicious = 0
        suspicious = 0
        
        phish_keywords = ["paypal-security", "login-verify", "bank-update", "wallet-connect", "account-alert", "billing-update", "free-gift", "invoice-download", "malicious"]
        
        if any(kw in lower_url for kw in phish_keywords) or ".xyz/" in lower_url or ".top/" in lower_url or ".buzz/" in lower_url:
            malicious = 14
            suspicious = 5
        elif "bit.ly" in lower_url or "tinyurl.com" in lower_url:
            suspicious = 2
        
        total = 92
        harmless = total - malicious - suspicious
        status = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean")

        return {
            "target": target_url,
            "type": "url",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "total_engines": total,
            "reputation": -50 if malicious > 0 else 0,
            "is_mock": True,
            "status": status
        }

    def _mock_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Deterministic mock for VirusTotal Domain scan."""
        lower_domain = domain.lower()
        malicious = 0
        suspicious = 0

        if any(bad in lower_domain for bad in ["phish", "malware", "secure-update", "bank-login", "stealer", "evil"]) or lower_domain.endswith((".xyz", ".top", ".buzz", ".tk", ".ga")):
            malicious = 9
            suspicious = 3
        
        total = 90
        harmless = total - malicious - suspicious
        status = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean")

        return {
            "target": domain,
            "type": "domain",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "total_engines": total,
            "reputation": -30 if malicious > 0 else 10,
            "is_mock": True,
            "status": status
        }
