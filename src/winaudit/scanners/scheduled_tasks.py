import csv
import io
import subprocess
from . import AutostartEntry


def scan() -> list[AutostartEntry]:
    result = subprocess.run(
        ["schtasks", "/query", "/fo", "CSV", "/v"],
        capture_output=True, text=True, check=True,
    )
    reader = csv.DictReader(io.StringIO(result.stdout))
    entries = []
    for row in reader:
        task_name = row.get("TaskName", "")
        if not task_name or task_name == "TaskName":
            continue
        command = row.get("Task To Run", "")
        if not command or command == "N/A":
            continue  # disabled or no-op tasks aren't worth flagging
        entries.append(AutostartEntry(
            source="Scheduled Task",
            name=task_name,
            command=command,
            location=row.get("Author", "unknown author"),
            scope="all users" if row.get("Run As User", "").lower() == "system" else "current user",
            extra={
                "status": row.get("Status", ""),
                "run_as": row.get("Run As User", ""),
            },
        ))
    return entries