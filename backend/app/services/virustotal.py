"""
VirusTotal API integration.
Free tier: 4 requests/minute, 500/day.
We use it as one signal layer, not the sole source of truth.
"""
import httpx
import base64
from typing import Optional, Dict, Any
from app.core.config import settings


VT_BASE = "https://www.virustotal.com/api/v3"


async def scan_url_virustotal(url: str) -> Optional[Dict[str, Any]]:
    """
    Submit URL to VirusTotal and return analysis summary.
    Returns None if API key not configured or request fails.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return None

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # VirusTotal URL ID = base64url(url) without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            resp = await client.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=headers,
            )

            if resp.status_code == 404:
                # URL not in VT cache — submit it
                submit = await client.post(
                    f"{VT_BASE}/urls",
                    headers=headers,
                    data={"url": url},
                )
                if submit.status_code != 200:
                    return None
                # For MVP we don't wait for analysis — return None and rely on heuristics
                return None

            if resp.status_code != 200:
                return None

            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1

            return {
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
                "detection_rate": round((malicious + suspicious) / total * 100, 1),
            }

    except Exception:
        # Never let VT failure break the scan — it's one signal layer
        return None


def virustotal_to_signal(vt_result: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Convert VT result to a ThreatSignal-compatible dict."""
    if not vt_result:
        return None

    malicious = vt_result["malicious_engines"]
    total = vt_result["total_engines"]

    if malicious == 0:
        return None  # Clean — no signal needed

    weight = min(int(malicious / total * 100), 60)  # cap at 60

    return {
        "name": "virustotal_detection",
        "value": f"{malicious}/{total} engines",
        "weight": weight,
        "description": f"VirusTotal: {malicious} out of {total} security tools flagged this URL as dangerous.",
    }
