import csv
import io
import subprocess
from . import AutostartEntry

PS_COMMAND = (
    "Get-CimInstance -ClassName Win32_Service -Filter \"StartMode='Auto'\" | "
    "Select-Object Name, PathName, StartName | "
    "ConvertTo-Csv -NoTypeInformation"
)


def scan() -> list[AutostartEntry]:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", PS_COMMAND],
        capture_output=True, text=True, check=True,
    )
    reader = csv.DictReader(io.StringIO(result.stdout))
    entries = []
    for row in reader:
        name = (row.get("Name") or "").strip()
        path = (row.get("PathName") or "").strip()
        if not name or not path:
            continue
        entries.append(AutostartEntry(
            source="Windows Service",
            name=name,
            command=path,
            location="Service Control Manager",
            scope="all users",
            extra={"run_as": (row.get("StartName") or "").strip()},
        ))
    return entries