import requests
import ipaddress
from typing import Dict, Any

def get_ip_geolocation(ip_address: str) -> Dict[str, Any]:
    """
    Query ip-api.com for IP geolocation, ISP, and ASN information.
    Includes fallback for private/loopback and offline environments.
    """
    if not ip_address:
        ip_address = "127.0.0.1"
        
    # Check if private/loopback
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return {
                "status": "success",
                "ip": ip_address,
                "country": "Local / Internal Network",
                "country_code": "LOC",
                "region": "Intranet",
                "city": "Private Subnet",
                "zip": "N/A",
                "lat": 37.7749,
                "lon": -122.4194,
                "timezone": "UTC",
                "isp": "Local Area Network",
                "org": "Private / RFC1918",
                "asn": "AS0000",
                "is_private": True
            }
    except ValueError:
        pass

    # Query public ip-api.com endpoint
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    try:
        response = requests.get(url, timeout=4.0)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "status": "success",
                    "ip": data.get("query", ip_address),
                    "country": data.get("country", "Unknown Country"),
                    "country_code": data.get("countryCode", "UN"),
                    "region": data.get("regionName", "Unknown Region"),
                    "city": data.get("city", "Unknown City"),
                    "zip": data.get("zip", ""),
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "timezone": data.get("timezone", "UTC"),
                    "isp": data.get("isp", "Unknown ISP"),
                    "org": data.get("org", "Unknown Org"),
                    "asn": data.get("as", "Unknown ASN"),
                    "is_private": False
                }
    except Exception:
        pass

    # Fallback default location if network fails
    return {
        "status": "fallback",
        "ip": ip_address,
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "zip": "94105",
        "lat": 37.7749,
        "lon": -122.4194,
        "timezone": "America/Los_Angeles",
        "isp": "Cloud Hosting Service",
        "org": "Autonomous System",
        "asn": "AS15169",
        "is_private": False
    }
