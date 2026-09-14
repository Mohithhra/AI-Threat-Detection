import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

# In-memory store for demo active honeypots & hit logs
CANARY_TOKENS: Dict[str, Dict[str, Any]] = {}
CANARY_LOGS: List[Dict[str, Any]] = []

def generate_canary_token(scan_id: str, suspect_email: str, base_url: str = "http://localhost:8000") -> Dict[str, Any]:
    """
    Generates a dark tracer honeypot tracking pixel & canary URL token for counter-intelligence.
    """
    token_id = "canary_" + uuid.uuid4().hex[:10]
    created_at = datetime.now(timezone.utc).isoformat()

    pixel_url = f"{base_url}/api/tracer/pixel/{token_id}.png"
    tracking_link = f"{base_url}/api/tracer/click/{token_id}"

    record = {
        "token_id": token_id,
        "scan_id": scan_id,
        "suspect_email": suspect_email,
        "created_at": created_at,
        "pixel_url": pixel_url,
        "tracking_link": tracking_link,
        "html_embed": f'<img src="{pixel_url}" width="1" height="1" style="display:none;" alt="" />',
        "hits_count": 0,
        "hits": []
    }

    CANARY_TOKENS[token_id] = record
    return record

def log_canary_hit(token_id: str, ip: str, user_agent: str, hit_type: str = "PIXEL_OPEN") -> Dict[str, Any]:
    """
    Logs when an attacker opens the honeypot pixel or clicks the canary link.
    """
    token_data = CANARY_TOKENS.get(token_id)
    hit_entry = {
        "hit_id": "hit_" + uuid.uuid4().hex[:8],
        "token_id": token_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hit_type": hit_type,
        "attacker_ip": ip,
        "user_agent": user_agent,
        "suspect_email": token_data.get("suspect_email", "Unknown") if token_data else "Unknown"
    }

    if token_data:
        token_data["hits_count"] += 1
        token_data["hits"].append(hit_entry)

    CANARY_LOGS.insert(0, hit_entry)
    return hit_entry

def get_active_canaries() -> List[Dict[str, Any]]:
    return list(CANARY_TOKENS.values())

def get_canary_logs() -> List[Dict[str, Any]]:
    return CANARY_LOGS
