import csv
import io
import subprocess
from . import AutostartEntry, ScanReport
from .. import winenv

SOURCE = "Windows Service"
POWERSHELL_TIMEOUT_SECONDS = 120
REQUIRED_COLUMNS = ("Name", "PathName")

# Every service is listed, whatever its start type. A service set to
# Manual or Disabled is not part of the boot sequence, but it is still code
# installed on the machine that anything with administrator rights can
# switch back on -- and a service that vanished from the list only because
# it was disabled would otherwise look "removed" while its file is still there.
PS_COMMAND = (
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
    "Get-CimInstance -ClassName Win32_Service | "
    "Select-Object Name, PathName, StartName, StartMode, State | "
    "ConvertTo-Csv -NoTypeInformation"
)


def scan() -> ScanReport:
    report = ScanReport(scanner=SOURCE, locations_total=1)

    powershell = winenv.powershell_path()
    if powershell is None:
        return _failed(report, "The Windows folder could not be located (SystemRoot is not set)")

    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", PS_COMMAND],
            capture_output=True, text=True,
            encoding="utf-8-sig",  # services with non-English names or paths must not turn into garbage
            check=True, timeout=POWERSHELL_TIMEOUT_SECONDS,
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
            extra={
                "run_as": (row.get("StartName") or "").strip(),
                "start_mode": (row.get("StartMode") or "").strip(),
                "state": (row.get("State") or "").strip(),
            },
        ))

    report.locations_checked = 1
    return report


def _failed(report: ScanReport, message: str) -> ScanReport:
    report.failed = True
    report.errors.append(message)
    return report
