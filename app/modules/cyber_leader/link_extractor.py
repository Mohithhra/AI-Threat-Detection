import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Set

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.buzz', '.club', '.tk', '.work', '.click', '.fit', 
    '.live', '.cam', '.cfd', '.sbs', '.rest', '.monster', '.gq', '.ml', '.ga'
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly', 'cutt.ly', 't.co',
    'goo.gl', 'rebrand.ly', 'tiny.cc', 'bl.ink', 'shorturl.at'
}

def defang_url(url: str) -> str:
    """Defangs a URL for safe visual rendering (e.g. hxxps[://]domain[.]com)."""
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace("://", "[://]")
    defanged = defanged.replace(".", "[.]")
    return defanged

def is_ip_host(hostname: str) -> bool:
    """Check if the hostname is a raw IPv4 address."""
    if not hostname:
        return False
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, hostname))

def analyze_url(url: str, anchor_text: str = "") -> Dict[str, Any]:
    """Inspect a single URL for phishing and malicious heuristics."""
    clean_url = url.strip()
    flags = []
    
    # Ensure scheme for urlparse
    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        parsed = urlparse("http://" + clean_url)
    else:
        parsed = urlparse(clean_url)
        
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path
    
    # Heuristic 1: Raw IP used as host
    if is_ip_host(hostname):
        flags.append("Raw IP address used as URL host (High Risk)")
        
    # Heuristic 2: URL Shortener
    if hostname in URL_SHORTENERS:
        flags.append("URL shortener used to conceal real destination")
        
    # Heuristic 3: Suspicious high-abuse TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append(f"Suspicious high-risk TLD ({tld})")
            break
            
    # Heuristic 4: Punycode / IDN Homograph attack
    if "xn--" in hostname:
        flags.append("Punycode (IDN homograph attack) detected")
        
    # Heuristic 5: Non-standard web port
    if port and port not in (80, 443, 8080):
        flags.append(f"Non-standard web port (:{port})")
        
    # Heuristic 6: Mismatched Anchor Text (Phishing indicator)
    # E.g. Text looks like "https://chase.com" or "paypal.com" but href is "badsite.com"
    if anchor_text:
        anchor_clean = anchor_text.strip().lower()
        if ("http://" in anchor_clean or "https://" in anchor_clean or ".com" in anchor_clean or ".org" in anchor_clean):
            # Anchor claims to be a domain/URL
            if hostname and hostname not in anchor_clean:
                flags.append(f"Mismatched anchor text: Visual '{anchor_text}' differs from actual destination '{hostname}'")

    # Extract base domain
    domain_parts = hostname.split('.')
    if len(domain_parts) >= 2:
        base_domain = ".".join(domain_parts[-2:])
    else:
        base_domain = hostname
        
    return {
        "url": clean_url,
        "defanged_url": defang_url(clean_url),
        "hostname": hostname,
        "base_domain": base_domain,
        "anchor_text": anchor_text,
        "is_suspicious": len(flags) > 0,
        "flags": flags
    }

def extract_links_and_domains(html_content: str, text_content: str) -> Dict[str, Any]:
    """
    Extract all URLs from HTML and plain text bodies, deduplicate them,
    and run security heuristic inspections.
    """
    raw_urls_with_anchors: List[Dict[str, str]] = []
    seen_urls: Set[str] = set()

    # 1. Extract from HTML
    if html_content:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.startswith(("http://", "https://", "www.")):
                    anchor = a_tag.get_text(strip=True)
                    if href not in seen_urls:
                        seen_urls.add(href)
                        raw_urls_with_anchors.append({"url": href, "anchor": anchor})
        except Exception:
            pass

    # 2. Extract from Plain Text using regex
    url_regex = r'(https?://[^\s<>"\')]+|www\.[^\s<>"\')]+)'
    for match in re.finditer(url_regex, text_content or ""):
        found_url = match.group(0).rstrip('.,;:!?')
        if found_url not in seen_urls:
            seen_urls.add(found_url)
            raw_urls_with_anchors.append({"url": found_url, "anchor": ""})

    analyzed_links = []
    unique_domains = set()
    total_suspicious_links = 0

    for item in raw_urls_with_anchors:
        analysis = analyze_url(item["url"], item["anchor"])
        analyzed_links.append(analysis)
        if analysis["base_domain"]:
            unique_domains.add(analysis["base_domain"])
        if analysis["is_suspicious"]:
            total_suspicious_links += 1

    return {
        "total_urls_found": len(analyzed_links),
        "total_suspicious_urls": total_suspicious_links,
        "extracted_domains": list(unique_domains),
        "urls": analyzed_links
    }
