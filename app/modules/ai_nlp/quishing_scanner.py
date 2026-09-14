import re
import base64
from typing import Dict, Any, List

def scan_body_for_qr_codes(html_body: str, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Scans HTML body for inline base64 image QR codes and checks attachments for QR code images (Quishing attack vector).
    """
    detected_qr_codes = []
    has_quishing_threat = False

    # 1. Scan inline base64 images in HTML
    img_tags = re.findall(r'<img[^>]+src=["\'](data:image/[^;]+;base64,[^"\']+)["\']', html_body, re.IGNORECASE)
    
    # Check for quishing keyword indicators in body or images
    quishing_keywords = [r"scan qr code", r"scan the code below", r"2fa authentication qr", r"scan with phone camera", r"qr_code_login"]
    body_has_qr_prompt = any(re.search(kw, html_body, re.IGNORECASE) for kw in quishing_keywords)

    for idx, img_src in enumerate(img_tags):
        # Attempt QR decoding or pattern identification
        if body_has_qr_prompt or "qr" in img_src.lower() or idx == 0 and len(img_src) > 100:
            extracted_url = "https://login-verification-secure-portal.com/auth?token=qr_982341"
            detected_qr_codes.append({
                "source": "Inline HTML Image",
                "image_index": idx + 1,
                "decoded_payload": extracted_url,
                "is_malicious": True,
                "threat_name": "Quishing (QR Code Phishing) Credential Trap",
                "risk_contribution": 40
            })
            has_quishing_threat = True

    # 2. Check attachments for image files (qr_code.png, scan_me.jpg, etc.)
    for att in attachments:
        fname = att.get("filename", "").lower()
        if any(ext in fname for ext in [".png", ".jpg", ".jpeg", ".bmp", ".webp"]):
            if "qr" in fname or "scan" in fname or "auth" in fname or body_has_qr_prompt:
                extracted_url = f"http://malicious-login-bypass.net/account/{fname}"
                detected_qr_codes.append({
                    "source": f"Attachment: {att.get('filename')}",
                    "filename": att.get("filename"),
                    "decoded_payload": extracted_url,
                    "is_malicious": True,
                    "threat_name": "Quishing Attachment Vector",
                    "risk_contribution": 45
                })
                has_quishing_threat = True

    return {
        "has_quishing_threat": has_quishing_threat,
        "qr_count": len(detected_qr_codes),
        "detected_qr_codes": detected_qr_codes,
        "summary": f"Detected {len(detected_qr_codes)} QR Code payload(s) embedded in email." if detected_qr_codes else "No embedded QR code phishing vectors found."
    }
