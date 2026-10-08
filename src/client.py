"""Async threat intelligence clients for AbuseIPDB and VirusTotal."""

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional
import httpx


@dataclass
class TriageReport:
    indicator: str
    indicator_type: str
    virustotal: Optional[Dict[str, Any]] = None
    abuseipdb: Optional[Dict[str, Any]] = None
    errors: Optional[list[str]] = None


class ThreatIntelClient:
    def __init__(self) -> None:
        self.vt_key = os.getenv("VT_API_KEY", "").strip()
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.timeout = httpx.Timeout(10.0, connect=5.0)

    async def query_abuseipdb(self, client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
        """Queries AbuseIPDB v2 check endpoint."""
        if not self.abuse_key:
            return {"error": "AbuseIPDB API key not set"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuse_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        response = await client.get(url, headers=headers, params=params, timeout=self.timeout)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "usage_type": data.get("usageType", "N/A"),
            }
        return {"error": f"HTTP {response.status_code}: {response.text}"}

    async def query_virustotal_ip(self, client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
        """Queries VirusTotal v3 IP address endpoint."""
        if not self.vt_key:
            return {"error": "VirusTotal API key not set"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_key}

        response = await client.get(url, headers=headers, timeout=self.timeout)
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "as_owner": attrs.get("as_owner", "N/A"),
                "reputation": attrs.get("reputation", 0),
            }
        return {"error": f"HTTP {response.status_code}: {response.text}"}

    async def query_virustotal_hash(self, client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
        """Queries VirusTotal v3 files endpoint."""
        if not self.vt_key:
            return {"error": "VirusTotal API key not set"}

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_key}

        response = await client.get(url, headers=headers, timeout=self.timeout)
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "type_description": attrs.get("type_description", "Unknown"),
                "meaningful_name": attrs.get("meaningful_name", "N/A"),
                "reputation": attrs.get("reputation", 0),
            }
        return {"error": f"HTTP {response.status_code}: {response.text}"}
