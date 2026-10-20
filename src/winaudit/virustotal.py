import os
import time
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

from . import hash_cache

load_dotenv()

API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
MIN_SECONDS_BETWEEN_CALLS = 16  # free tier: 4 requests/minute -> 1 every 15s, +1s margin

# A scan makes at most this many real VirusTotal requests (about 16 seconds
# each). Files that do not fit are marked "deferred" and picked up by a
# later scan, so the cache fills in gradually instead of one scan taking
# half an hour and spending the day's quota.
MAX_API_LOOKUPS_PER_SCAN = 8

# How long a stored verdict is trusted. Detections change as engines update,
# and a file VirusTotal had never seen can be submitted later, so "not
# found" expires much sooner than a verdict that has real detection data.
FOUND_MAX_AGE = timedelta(days=7)
NOT_FOUND_MAX_AGE = timedelta(days=1)

MISSING_KEY_ERROR = "VIRUSTOTAL_API_KEY not set in .env"

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
        return {"error": MISSING_KEY_ERROR}

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

    if response.status_code == 429:
        # Per-minute or daily quota used up: further requests will fail too.
        return {"error": "VirusTotal rate limit or daily quota reached", "rate_limited": True}

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

def _parse_time(value) -> datetime | None:
    """Reads a stored timestamp. Timestamps without a time zone are taken
    to be UTC; anything unreadable counts as "unknown age"."""
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_fresh(cached: dict, now: datetime | None = None) -> bool:
    checked_at = _parse_time(cached.get("checked_at"))
    if checked_at is None:
        return False

    now = now or datetime.now(timezone.utc)
    max_age = FOUND_MAX_AGE if cached["total_engines"] > 0 else NOT_FOUND_MAX_AGE
    return now - checked_at <= max_age


def _from_cache(file_hash: str, cached: dict, stale: bool, **extra) -> dict:
    return {
        "sha256": file_hash,
        "malicious_count": cached["malicious_count"],
        "total_engines": cached["total_engines"],
        "found": cached["total_engines"] > 0,
        "checked_at": cached["checked_at"],
        "from_cache": True,
        "stale": stale,
        "network_call": False,
        **extra,
    }


def check_file(file_path: str, allow_network: bool = True) -> dict:
    """The main entry point for checking a file against VirusTotal.

    A stored verdict that is still fresh is returned without any request.
    Otherwise, if `allow_network` is true, VirusTotal is asked and the
    answer stored. If it is not allowed (the scan's request budget is
    spent), an older stored verdict is returned marked "stale", or the
    file is marked "deferred" when nothing is stored at all.
    `network_call` says whether a real request was attempted, which is
    what the scan's budget counts.
    """
    file_hash = hash_cache.compute_sha256(file_path)
    cached = hash_cache.get_cached_result(file_hash)

    if cached is not None and is_fresh(cached):
        return _from_cache(file_hash, cached, stale=False)

    if not allow_network:
        if cached is not None:
            return _from_cache(file_hash, cached, stale=True)
        return {"sha256": file_hash, "deferred": True, "from_cache": False, "network_call": False}

    result = check_hash(file_hash)
    network_call = result.get("error") != MISSING_KEY_ERROR

    if "error" in result:
        if cached is not None:
            # Better an old verdict, labelled as such, than none at all.
            return _from_cache(
                file_hash, cached, stale=True,
                refresh_error=result["error"],
                rate_limited=result.get("rate_limited", False),
                network_call=network_call,
            )
        return {
            "sha256": file_hash,
            "error": result["error"],
            "rate_limited": result.get("rate_limited", False),
            "from_cache": False,
            "network_call": network_call,
        }

    hash_cache.store_result(
        file_hash,
        malicious_count=result["malicious_count"],
        total_engines=result["total_engines"],
        checked_at=result["checked_at"],
    )

    return {
        "sha256": file_hash,
        "malicious_count": result["malicious_count"],
        "total_engines": result["total_engines"],
        "found": result["found"],
        "checked_at": result["checked_at"],
        "from_cache": False,
        "stale": False,
        "network_call": True,
    }
