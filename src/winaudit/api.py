import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from .scanners import registry_run, startup_folder, scheduled_tasks, services
from . import risk, signature

app = FastAPI(title="Windows Startup Audit")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "static"
SCANNERS = [registry_run, startup_folder, scheduled_tasks, services]


@app.get("/")
def serve_dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/scan")
def run_scan():
    all_entries = []
    for scanner in SCANNERS:
        all_entries.extend(scanner.scan())

    # Only worth signature-checking paths that actually exist on disk --
    # many commands (shell one-liners, unexpanded %env% paths) aren't real
    # files, and checking them would just waste a PowerShell call each.
    exe_paths = set()
    for entry in all_entries:
        path = risk.extract_exe_path(entry.command)
        if path and os.path.exists(path):
            exe_paths.add(path)

    signature_results = signature.batch_check(list(exe_paths))

    def sig_checker(path: str) -> bool:
        result = signature_results.get(path, {})
        if not result.get("checked", True):
            # Still inconclusive even after retry -- don't penalize the
            # score for something we genuinely couldn't verify.
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

    return {
        "total_entries": len(results),
        "flagged_count": sum(1 for r in results if r["score"] > 0),
        "entries": results,
    }