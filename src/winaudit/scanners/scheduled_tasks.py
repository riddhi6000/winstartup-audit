import csv
import io
import subprocess
from . import AutostartEntry, ScanReport

SOURCE = "Scheduled Task"
SCHTASKS_TIMEOUT_SECONDS = 120

# Column names schtasks prints on an English-language Windows. On a
# localized Windows they are translated, so a missing column is reported
# instead of silently producing zero entries.
REQUIRED_COLUMNS = ("TaskName", "Task To Run")


def scan() -> ScanReport:
    report = ScanReport(scanner=SOURCE, locations_total=1)

    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, check=True,
            timeout=SCHTASKS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return _failed(report, f"schtasks did not finish within {SCHTASKS_TIMEOUT_SECONDS} seconds")
    except subprocess.CalledProcessError as exc:
        return _failed(report, f"schtasks exited with code {exc.returncode}")
    except OSError as exc:
        return _failed(report, f"schtasks could not be started ({exc.strerror or exc})")

    reader = csv.DictReader(io.StringIO(result.stdout))
    columns = reader.fieldnames or []
    if any(column not in columns for column in REQUIRED_COLUMNS):
        return _failed(
            report,
            "schtasks output did not have the expected column names "
            "(a non-English Windows language can cause this)",
        )

    seen_task_names = set()
    for row in reader:
        task_name = row.get("TaskName", "")
        if not task_name or task_name == "TaskName":
            continue
        command = row.get("Task To Run", "")
        if not command or command == "N/A":
            continue  # disabled or no-op tasks aren't worth flagging
        if task_name in seen_task_names:
            continue  # schtasks /v repeats a row per trigger for multi-trigger tasks
        seen_task_names.add(task_name)
        report.entries.append(AutostartEntry(
            source=SOURCE,
            name=task_name,
            command=command,
            location=row.get("Author", "unknown author"),
            scope="all users" if row.get("Run As User", "").lower() == "system" else "current user",
            extra={
                "status": row.get("Status", ""),
                "run_as": row.get("Run As User", ""),
            },
        ))

    report.locations_checked = 1
    return report


def _failed(report: ScanReport, message: str) -> ScanReport:
    report.failed = True
    report.errors.append(message)
    return report
