import hashlib
import email
from email import policy
from typing import Dict, Any, List

DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.vbs', '.iso', '.hta', '.docm', '.xlsm', '.pptm', 
    '.bat', '.cmd', '.js', '.wsf', '.ps1', '.dll', '.jar', '.apk', '.img', '.vhd'
}

def scan_email_attachments(raw_eml_content: str) -> Dict[str, Any]:
    """
    Extract embedded attachments, calculate cryptographic file hashes (SHA-256, MD5),
    and check for malicious file extension signatures.
    """
    if isinstance(raw_eml_content, bytes):
        msg = email.message_from_bytes(raw_eml_content, policy=policy.default)
    else:
        msg = email.message_from_string(raw_eml_content, policy=policy.default)

    attachments: List[Dict[str, Any]] = []
    has_dangerous_attachment = False

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition") or "")
        filename = part.get_filename()

        if filename or "attachment" in content_disposition:
            clean_filename = filename or "unnamed_attachment.bin"
            clean_filename = clean_filename.replace("\r", "").replace("\n", "")
            
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            file_size = len(payload)
            sha256_hash = hashlib.sha256(payload).hexdigest()
            md5_hash = hashlib.md5(payload).hexdigest()
            sha1_hash = hashlib.sha1(payload).hexdigest()

            # Check extension
            lower_name = clean_filename.lower()
            is_dangerous = any(lower_name.endswith(ext) for ext in DANGEROUS_EXTENSIONS)
            if is_dangerous:
                has_dangerous_attachment = True

            attachments.append({
                "filename": clean_filename,
                "file_size": file_size,
                "file_size_formatted": f"{file_size / 1024:.1f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.2f} MB",
                "content_type": part.get_content_type(),
                "sha256": sha256_hash,
                "md5": md5_hash,
                "sha1": sha1_hash,
                "is_dangerous": is_dangerous,
                "threat_flag": "High Risk Executable / Macro Signature" if is_dangerous else "Clean / Standard Document"
            })

    return {
        "total_attachments": len(attachments),
        "has_dangerous_attachment": has_dangerous_attachment,
        "attachments": attachments
    }
