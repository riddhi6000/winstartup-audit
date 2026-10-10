import os
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
MIN_SECONDS_BETWEEN_CALLS = 16  # free tier: 4 requests/minute -> 1 every 15s, +1s margin

_last_call_time = 0.0


def _respect_rate_limit():
    """Blocks just long enough to stay under VirusTotal's free-tier rate
    limit, if we've called recently. Only matters for actual API calls --
    cache hits never reach this function at all."""
    global _last_call_time
    elapsed = time.monotonic() - _last_call_time
    if elapsed < MIN_SECONDS_BETWEEN_CALLS:
        time.sleep(MIN_SECONDS_BETWEEN_CALLS - elapsed)
    _last_call_time = time.monotonic()


def check_hash(file_hash: str) -> dict:
    """Looks up a file's hash on VirusTotal. Returns:
    - {"found": True, "malicious_count": int, "total_engines": int, "checked_at": iso-string}
      if VirusTotal has seen this exact file before.
    - {"found": False, ...} if this exact file has never been submitted to
      VirusTotal -- NOT the same as "confirmed safe", just "unknown".
    - {"error": "..."} if the API key is missing or the request failed.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    _respect_rate_limit()

    try:
        response = requests.get(
            API_URL.format(hash=file_hash),
            headers={"x-apikey": api_key},
            timeout=15,
        )
    except requests.RequestException as e:
        return {"error": f"Request failed: {e}"}

    if response.status_code == 404:
        return {
            "found": False,
            "malicious_count": 0,
            "total_engines": 0,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    if response.status_code != 200:
        return {"error": f"VirusTotal returned status {response.status_code}"}

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    return {
        "found": True,
        "malicious_count": malicious + suspicious,
        "total_engines": total,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }