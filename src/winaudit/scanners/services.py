import csv
import io
import subprocess
from . import AutostartEntry, ScanReport

SOURCE = "Windows Service"
POWERSHELL_TIMEOUT_SECONDS = 120
REQUIRED_COLUMNS = ("Name", "PathName")

PS_COMMAND = (
    "Get-CimInstance -ClassName Win32_Service -Filter \"StartMode='Auto'\" | "
    "Select-Object Name, PathName, StartName | "
    "ConvertTo-Csv -NoTypeInformation"
)


def scan() -> ScanReport:
    report = ScanReport(scanner=SOURCE, locations_total=1)

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", PS_COMMAND],
            capture_output=True, text=True, check=True,
            timeout=POWERSHELL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return _failed(report, f"PowerShell did not finish within {POWERSHELL_TIMEOUT_SECONDS} seconds")
    except subprocess.CalledProcessError as exc:
        return _failed(report, f"PowerShell exited with code {exc.returncode}")
    except OSError as exc:
        return _failed(report, f"PowerShell could not be started ({exc.strerror or exc})")

    reader = csv.DictReader(io.StringIO(result.stdout))
    columns = reader.fieldnames or []
    if any(column not in columns for column in REQUIRED_COLUMNS):
        return _failed(report, "PowerShell returned no service list in the expected format")

    for row in reader:
        name = (row.get("Name") or "").strip()
        path = (row.get("PathName") or "").strip()
        if not name or not path:
            continue
        report.entries.append(AutostartEntry(
            source=SOURCE,
            name=name,
            command=path,
            location="Service Control Manager",
            scope="all users",
            extra={"run_as": (row.get("StartName") or "").strip()},
        ))

    report.locations_checked = 1
    return report


def _failed(report: ScanReport, message: str) -> ScanReport:
    report.failed = True
    report.errors.append(message)
    return report
