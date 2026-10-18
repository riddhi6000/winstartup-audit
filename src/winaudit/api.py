import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from .scanners import registry_run, startup_folder, scheduled_tasks, services, winlogon
from . import risk, signature, virustotal
from .baseline import save_baseline, load_baseline, diff as diff_entries
from datetime import datetime, timedelta

app = FastAPI(title="Windows Startup Audit")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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



@app.get("/")
def serve_dashboard():
    return FileResponse(STATIC_DIR / "index.html")

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


@app.get("/api/scan")
def run_scan():
    results = perform_scan()
    baseline_data = load_baseline(BASELINE_PATH)

    diff_result = None
    if baseline_data is not None:
        diff_result = diff_entries(results, baseline_data["entries"])

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
        "diff": diff_result,
    }


@app.post("/api/baseline/save")
def save_current_as_baseline():
    results = perform_scan()
    save_baseline(results, BASELINE_PATH)
    return {"saved": True, "entry_count": len(results)}