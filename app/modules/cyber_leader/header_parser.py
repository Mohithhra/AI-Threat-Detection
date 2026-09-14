import re
import email
from email import policy
from email.header import decode_header
import ipaddress
from typing import Dict, Any, List, Optional
import dns.resolver

def _decode_str(header_value: Optional[str]) -> str:
    """Safely decode RFC 2047 encoded email header strings."""
    if not header_value:
        return ""
    decoded_fragments = []
    try:
        fragments = decode_header(header_value)
        for fragment, encoding in fragments:
            if isinstance(fragment, bytes):
                decoded_fragments.append(fragment.decode(encoding or 'utf-8', errors='replace'))
            else:
                decoded_fragments.append(str(fragment))
        return "".join(decoded_fragments)
    except Exception:
        return str(header_value)

def _extract_email_address(full_header: str) -> Dict[str, str]:
    """Extract display name and pure email address from a header like 'John Doe <john@example.com>'."""
    if not full_header:
        return {"name": "", "address": "", "domain": ""}
    
    match = re.search(r'(.*?)(?:<([^>]+)>)?$', full_header.strip())
    if match:
        name = match.group(1).strip().strip('"\'')
        address = match.group(2).strip() if match.group(2) else name
        # If no brackets were used, address is the whole thing if it looks like an email
        if '@' in address:
            domain = address.split('@')[-1].lower()
            return {"name": name if name != address else "", "address": address, "domain": domain}
        elif '@' in name:
            domain = name.split('@')[-1].lower()
            return {"name": "", "address": name, "domain": domain}
            
    return {"name": full_header, "address": full_header, "domain": ""}

def _extract_ip_from_text(text: str) -> List[str]:
    """Extract all valid IPv4 addresses from a string."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    candidates = re.findall(ip_pattern, text)
    valid_ips = []
    for candidate in candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)
            # Filter out invalid or loopback unless private is needed
            valid_ips.append(candidate)
        except ValueError:
            continue
    return valid_ips

def parse_received_headers(received_headers: List[str]) -> Dict[str, Any]:
    """
    Parse email 'Received' headers to trace email routing hops and find the originating IP.
    Received headers are chronologically read bottom-to-top (bottom = first/originating hop).
    """
    hops = []
    originating_ip = None
    all_ips = []
    
    # Process from bottom (earliest) to top (latest)
    for idx, header_val in enumerate(reversed(received_headers)):
        clean_val = " ".join(header_val.split())
        ips = _extract_ip_from_text(clean_val)
        
        # Determine public IPs in this hop
        public_ips = []
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                all_ips.append(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
                    public_ips.append(ip)
            except ValueError:
                pass
        
        hop_info = {
            "hop_number": idx + 1,
            "raw": clean_val,
            "ips_found": ips,
            "public_ips": public_ips
        }
        hops.append(hop_info)
        
        if not originating_ip and public_ips:
            originating_ip = public_ips[0]

    # Fallback to any IP if no public IP was found in bottom hops
    if not originating_ip and all_ips:
        originating_ip = all_ips[0]
        
    return {
        "total_hops": len(received_headers),
        "originating_ip": originating_ip or "127.0.0.1",
        "hops": hops,
        "all_extracted_ips": list(set(all_ips))
    }

def parse_auth_results(auth_headers: List[str]) -> Dict[str, str]:
    """Parse Authentication-Results header for existing SPF, DKIM, and DMARC stamps."""
    combined = " ".join(auth_headers).lower()
    
    results = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "details": combined
    }
    
    # SPF extraction
    if "spf=pass" in combined:
        results["spf"] = "pass"
    elif "spf=fail" in combined or "spf=softfail" in combined:
        results["spf"] = "softfail" if "spf=softfail" in combined else "fail"
    elif "spf=neutral" in combined:
        results["spf"] = "neutral"
        
    # DKIM extraction
    if "dkim=pass" in combined:
        results["dkim"] = "pass"
    elif "dkim=fail" in combined:
        results["dkim"] = "fail"
        
    # DMARC extraction
    if "dmarc=pass" in combined:
        results["dmarc"] = "pass"
    elif "dmarc=fail" in combined:
        results["dmarc"] = "fail"
        
    return results

def verify_dns_auth(domain: str) -> Dict[str, Any]:
    """
    Perform live DNS queries to check for SPF and DMARC records for the sender domain.
    """
    if not domain or "." not in domain:
        return {
            "spf_record": None,
            "dmarc_record": None,
            "has_spf": False,
            "has_dmarc": False,
            "dmarc_policy": "none",
            "mx_records": []
        }
        
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    spf_record = None
    dmarc_record = None
    dmarc_policy = "none"
    mx_records = []
    
    # 1. Query SPF (TXT records on domain)
    try:
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_str = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if txt_str.startswith("v=spf1"):
                spf_record = txt_str
                break
    except Exception:
        spf_record = None
        
    # 2. Query DMARC (TXT record on _dmarc.domain)
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_str = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if "v=DMARC1" in txt_str or "v=dmarc1" in txt_str:
                dmarc_record = txt_str
                # extract policy (p=reject / p=quarantine / p=none)
                policy_match = re.search(r'p=(none|quarantine|reject)', txt_str, re.IGNORECASE)
                if policy_match:
                    dmarc_policy = policy_match.group(1).lower()
                break
    except Exception:
        dmarc_record = None

    # 3. Query MX records
    try:
        mx_answers = resolver.resolve(domain, 'MX')
        for rdata in mx_answers:
            mx_records.append(str(rdata.exchange).rstrip('.'))
    except Exception:
        mx_records = []

    return {
        "domain": domain,
        "spf_record": spf_record,
        "dmarc_record": dmarc_record,
        "has_spf": spf_record is not None,
        "has_dmarc": dmarc_record is not None,
        "dmarc_policy": dmarc_policy,
        "mx_records": mx_records
    }

def parse_email_headers(raw_eml_content: str) -> Dict[str, Any]:
    """
    Main header parser function. Takes raw EML string content and returns parsed headers,
    sender information, routing hops, originating IP, and email authentication results.
    """
    if isinstance(raw_eml_content, bytes):
        msg = email.message_from_bytes(raw_eml_content, policy=policy.default)
    else:
        msg = email.message_from_string(raw_eml_content, policy=policy.default)
        
    # Extract standard fields
    from_raw = _decode_str(msg.get("From", ""))
    to_raw = _decode_str(msg.get("To", ""))
    cc_raw = _decode_str(msg.get("Cc", ""))
    subject = _decode_str(msg.get("Subject", "(No Subject)"))
    date = _decode_str(msg.get("Date", ""))
    message_id = _decode_str(msg.get("Message-ID", ""))
    return_path_raw = _decode_str(msg.get("Return-Path", ""))
    reply_to_raw = _decode_str(msg.get("Reply-To", ""))
    
    sender_info = _extract_email_address(from_raw)
    recipient_info = _extract_email_address(to_raw)
    return_path_info = _extract_email_address(return_path_raw)
    reply_to_info = _extract_email_address(reply_to_raw)
    
    # Process Received headers
    received_headers = msg.get_all("Received", [])
    routing_data = parse_received_headers(received_headers)
    
    # Process Authentication-Results / DKIM headers
    auth_headers = msg.get_all("Authentication-Results", [])
    has_dkim_sig = msg.get("DKIM-Signature") is not None
    
    auth_results = parse_auth_results(auth_headers)
    if has_dkim_sig and auth_results["dkim"] == "none":
        auth_results["dkim"] = "present" # Signature is attached
        
    # Perform DNS verification for sender domain
    dns_auth = verify_dns_auth(sender_info["domain"])
    
    # Check for Domain Mismatch (From vs Return-Path or Reply-To)
    domain_mismatch = False
    mismatch_details = []
    if return_path_info["domain"] and sender_info["domain"]:
        if return_path_info["domain"] != sender_info["domain"]:
            domain_mismatch = True
            mismatch_details.append(f"From domain ({sender_info['domain']}) != Return-Path domain ({return_path_info['domain']})")
            
    if reply_to_info["domain"] and sender_info["domain"]:
        if reply_to_info["domain"] != sender_info["domain"]:
            domain_mismatch = True
            mismatch_details.append(f"From domain ({sender_info['domain']}) != Reply-To domain ({reply_to_info['domain']})")

    # Extract raw body text and HTML
    body_text = ""
    body_html = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                continue
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    decoded_text = payload.decode(charset, errors='replace')
                    if content_type == "text/plain":
                        body_text += decoded_text + "\n"
                    elif content_type == "text/html":
                        body_html += decoded_text + "\n"
            except Exception:
                pass
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            decoded_text = payload.decode(charset, errors='replace')
            if msg.get_content_type() == "text/html":
                body_html = decoded_text
            else:
                body_text = decoded_text
                
    return {
        "headers": {
            "from_raw": from_raw,
            "from_name": sender_info["name"],
            "from_address": sender_info["address"],
            "from_domain": sender_info["domain"],
            "to_raw": to_raw,
            "to_address": recipient_info["address"],
            "cc_raw": cc_raw,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "return_path": return_path_info["address"],
            "reply_to": reply_to_info["address"],
        },
        "routing": routing_data,
        "authentication": {
            "spf_status": auth_results["spf"],
            "dkim_status": auth_results["dkim"],
            "dmarc_status": auth_results["dmarc"],
            "has_dkim_signature": has_dkim_sig,
            "dns_verification": dns_auth,
            "domain_mismatch": domain_mismatch,
            "mismatch_details": mismatch_details
        },
        "body": {
            "text": body_text,
            "html": body_html
        }
    }
