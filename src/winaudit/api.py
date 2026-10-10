import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from .scanners import registry_run, startup_folder, scheduled_tasks, services, winlogon
from . import risk, signature
from .baseline import save_baseline, load_baseline, diff as diff_entries

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


@app.get("/")
def serve_dashboard():
    return FileResponse(STATIC_DIR / "index.html")


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

    def sig_checker(path: str) -> bool:
        result = signature_results.get(path, {})
        if not result.get("checked", True):
            return True
        return result.get("signed", False)

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
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


@app.get("/api/scan")
def run_scan():
    results = perform_scan()
    baseline_data = load_baseline(BASELINE_PATH)

    diff_result = None
    if baseline_data is not None:
        diff_result = diff_entries(results, baseline_data["entries"])

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