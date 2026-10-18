import logging
import os
import secrets
import threading
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from .scanners import registry_run, startup_folder, scheduled_tasks, services, winlogon
from . import risk, signature, virustotal
from .baseline import save_baseline, load_baseline, diff as diff_entries
from datetime import datetime, timedelta

logger = logging.getLogger("winaudit")

# The dashboard is served from this same server, so no CORS is configured:
# browsers will therefore refuse to let other sites read API responses.
# The interactive docs are disabled to keep the surface minimal.
app = FastAPI(
    title="Windows Startup Audit",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

ALLOWED_HOSTS = ("127.0.0.1", "localhost")

# Random per server start. It is injected into the dashboard page and must
# accompany every API call; a page on another origin cannot read it.
API_TOKEN = secrets.token_urlsafe(32)

_scan_lock = threading.Lock()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# Added after the middleware above so it runs first: requests whose Host
# header is not localhost are rejected before anything else happens
# (protects against DNS rebinding).
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ALLOWED_HOSTS))

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
STATIC_DIR = PROJECT_ROOT / "static"
BASELINE_PATH = PROJECT_ROOT / "baseline.json"
SCANNERS = [registry_run, startup_folder, scheduled_tasks, services, winlogon]


# Dual-use utilities that can be abused to execute code or scripts.
# Their presence alone is NOT suspicious; command arguments matter.
SUSPICIOUS_LOLBIN_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "installutil.exe",
}

SUSPICIOUS_COMMAND_MARKERS = (
    "-encodedcommand",
    " -enc ",
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "invoke-webrequest",
    "frombase64string",
    "javascript:",
    "vbscript:",
    "scrobj.dll",
    " -windowstyle hidden",
    " -w hidden",
    " -executionpolicy bypass",
    " -ep bypass",
)


def has_suspicious_lolbin_command(command: str) -> bool:
    """Flag known dual-use utilities only when arguments are suspicious."""
    if not isinstance(command, str) or not command.strip():
        return False

    exe_path = risk.extract_exe_path(command)
    if not exe_path:
        return False

    executable_name = os.path.basename(exe_path).lower()
    if executable_name not in SUSPICIOUS_LOLBIN_NAMES:
        return False

    command_lower = command.lower()
    return any(marker in command_lower for marker in SUSPICIOUS_COMMAND_MARKERS)


def require_local_client(request: Request) -> None:
    """Rejects browser requests from other origins, and any request that
    does not carry this server run's token."""
    origin = request.headers.get("origin")
    if origin is not None and urlparse(origin).hostname not in ALLOWED_HOSTS:
        raise HTTPException(
            status_code=403, detail="Cross-origin requests are not allowed."
        )

    supplied = request.headers.get("x-winaudit-token", "")
    if not secrets.compare_digest(
        supplied.encode("utf-8"), API_TOKEN.encode("utf-8")
    ):
        raise HTTPException(status_code=403, detail="Missing or invalid API token.")


@contextmanager
def _exclusive_scan():
    """Allows one scan at a time. A second request fails immediately with
    409 rather than queueing, because a scan can take minutes."""
    if not _scan_lock.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail="A scan is already running. Wait for it to finish.",
        )
    try:
        yield
    finally:
        _scan_lock.release()


def _perform_scan_exclusively() -> list[dict]:
    with _exclusive_scan():
        try:
            return perform_scan()
        except Exception:
            logger.exception("Scan failed")
            raise HTTPException(
                status_code=500,
                detail="Scan failed. Check the server console for details.",
            ) from None


@app.get("/", include_in_schema=False)
def serve_dashboard():
    nonce = secrets.token_urlsafe(16)
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    html = html.replace("__CSP_NONCE__", nonce).replace("__WINAUDIT_TOKEN__", API_TOKEN)

    csp = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        "style-src 'unsafe-inline'; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    )
    return HTMLResponse(
        html,
        headers={"Content-Security-Policy": csp, "Cache-Control": "no-store"},
    )

def add_reason(result: dict, points: int, reason: str) -> None:
    """Adds a score-raising reason after assess() has already run.
    Strips the 'no red flags' placeholder first if present -- that
    placeholder is only valid while nothing else has been found, and
    everything calling this function is, by definition, something else."""
    if result["reasons"] == [risk.NO_FLAGS_REASON]:
        result["reasons"] = []
    result["score"] += points
    result["reasons"].append(reason)

def perform_scan() -> list[dict]:
    """Runs all five scanners and risk-assesses every entry. This is the
    one shared implementation behind both /api/scan and
    /api/baseline/save, so there's exactly one place that defines 'what a
    scan actually is' -- the two endpoints just do different things with
    the same result."""
    all_entries = []
    for scanner in SCANNERS:
        all_entries.extend(scanner.scan())

    exe_paths = set()
    for entry in all_entries:
        path = risk.extract_exe_path(entry.command)
        if path and os.path.exists(path):
            exe_paths.add(path)

    signature_results = signature.batch_check(list(exe_paths))

    def sig_checker(path: str) -> dict:
        return signature_results.get(
            path,
            {
                "signed": False,
                "publisher": None,
                "checked": False,
                "status": "UnknownError",
            },
        )

    results = []
    for entry in all_entries:
        assessment = risk.assess(entry, signature_checker=sig_checker)
        exe_path = risk.extract_exe_path(entry.command)
        publisher = signature_results.get(exe_path, {}).get("publisher") if exe_path else None

        results.append({
            "source": entry.source,
            "name": entry.name,
            "command": entry.command,
            "location": entry.location,
            "scope": entry.scope,
            "created": entry.created.isoformat() if entry.created else None,
            "score": assessment.score,
            "reasons": assessment.reasons,
            "publisher": publisher,
            "signature_status": (
                signature_results.get(exe_path, {}).get("status")
                if exe_path
                else None
            ),
            "signature_status_message": (
                    signature_results.get(exe_path, {}).get("status_message")
                    if exe_path
                    else None
            ),
            "virustotal": None,
        })

    # Only ever check VirusTotal for entries our own risk scoring already
    # flagged -- this respects the free-tier rate limit (checking all 286+
    # entries every scan would be both wasteful and far too slow) and
    # focuses VirusTotal's slower, more authoritative answer on exactly
    # the handful of things actually worth it.
    for result in results:
        if result["score"] == 0:
            continue
        exe_path = risk.extract_exe_path(result["command"])
        if not exe_path or not os.path.exists(exe_path):
            continue
        vt_result = virustotal.check_file(exe_path)
        result["virustotal"] = vt_result

        if "error" not in vt_result and vt_result.get("found"):
            malicious = vt_result["malicious_count"]
            total = vt_result["total_engines"]
            ratio = malicious / total if total else 0

            # Below 10%: a single stray engine out of dozens is common
            # noise, not a meaningful signal -- ignore it entirely rather
            # than let it dilute genuinely important flags with clutter.

            if ratio >= 0.6:
                add_reason(
                    result,
                    15,
                    f"VirusTotal: {malicious}/{total} security vendors flag "
                    "this file as malicious — strong consensus",
                )
            elif ratio >= 0.3:
                add_reason(
                    result,
                    10,
                    f"VirusTotal: {malicious}/{total} security vendors flag "
                    "this file as malicious",
                )
            elif ratio >= 0.1:
                add_reason(
                    result,
                    5,
                    f"VirusTotal: {malicious}/{total} security vendors flag "
                    "this file as suspicious",
                )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


@app.get("/api/scan", dependencies=[Depends(require_local_client)])
def run_scan():
    results = _perform_scan_exclusively()

    baseline_error = None
    try:
        baseline_data = load_baseline(BASELINE_PATH)
    except ValueError as exc:
        logger.warning("Baseline could not be loaded: %s", exc)
        baseline_data = None
        baseline_error = str(exc)

    diff_result = None
    if baseline_data is not None:
        try:
            diff_result = diff_entries(results, baseline_data["entries"])
        except ValueError as exc:
            logger.warning("Baseline comparison failed: %s", exc)
            baseline_data = None
            baseline_error = f"Baseline comparison failed: {exc}"

    if diff_result is not None:
        # A modified entry is exactly the general case of what we built
        # dedicated Winlogon detection for -- something trusted silently
        # changed. Score it accordingly, consistent with that reasoning,
        # rather than only surfacing the change visually.
        modified_lookup = {
            (m["entry"]["source"], m["entry"]["name"], m["entry"]["location"]): m["previous_command"]
            for m in diff_result["modified"]
        }
        for result in results:
            key = (result["source"], result["name"], result["location"])
            if key in modified_lookup:
                add_reason(result, 3, f"Changed since last baseline (was: {modified_lookup[key]})")
        results.sort(key=lambda r: r["score"], reverse=True)

        # Only add the living-off-the-land penalty when a new
        # registration uses a known dual-use utility with suspicious
        # command arguments. A new entry pointing to an old executable
        # is not enough on its own.
        for entry_dict in diff_result["new"]:
            if not has_suspicious_lolbin_command(entry_dict["command"]):
                continue

            key = (
                entry_dict["source"],
                entry_dict["name"],
                entry_dict["location"],
            )

            for result in results:
                result_key = (
                    result["source"],
                    result["name"],
                    result["location"],
                )

                if result_key == key:
                    add_reason(
                        result,
                        4,
                        "New autostart entry uses a dual-use utility "
                        "with suspicious command arguments",
                    )
                    break

        results.sort(key=lambda r: r["score"], reverse=True)

    return {
        "total_entries": len(results),
        "flagged_count": sum(1 for r in results if r["score"] > 0),
        "entries": results,
        "baseline_saved_at": baseline_data["saved_at"] if baseline_data else None,
        "baseline_error": baseline_error,
        "diff": diff_result,
    }


@app.post("/api/baseline/save", dependencies=[Depends(require_local_client)])
def save_current_as_baseline():
    results = _perform_scan_exclusively()
    try:
        save_baseline(results, BASELINE_PATH)
    except (ValueError, OSError):
        logger.exception("Baseline save failed")
        raise HTTPException(
            status_code=500,
            detail="Baseline could not be saved. Check the server console for details.",
        ) from None
    return {"saved": True, "entry_count": len(results)}