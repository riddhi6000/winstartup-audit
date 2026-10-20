import json
import re
import subprocess
import winreg
from . import AutostartEntry, ScanReport
from .. import winenv

SOURCE = "Scheduled Task"
LOCATION = "Task Scheduler"
POWERSHELL_TIMEOUT_SECONDS = 180

# Get-ScheduledTask returns every action as structured data, which is what
# lets this scanner see COM-handler actions and tasks with several actions
# (the older "schtasks /query /v" text output shows neither).
PS_COMMAND = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$tasks = foreach ($task in (Get-ScheduledTask)) {
    [pscustomobject]@{
        Path     = $task.TaskPath
        Name     = $task.TaskName
        State    = [string]$task.State
        Author   = $task.Author
        RunAs    = $task.Principal.UserId
        Group    = $task.Principal.GroupId
        Triggers = @($task.Triggers | ForEach-Object { $_.CimClass.CimClassName })
        Actions  = @($task.Actions | ForEach-Object {
            [pscustomobject]@{
                Type             = $_.CimClass.CimClassName
                Execute          = $_.Execute
                Arguments        = $_.Arguments
                WorkingDirectory = $_.WorkingDirectory
                ClassId          = $_.ClassId
                Data             = $_.Data
            }
        })
    }
}
ConvertTo-Json -InputObject @($tasks) -Depth 4 -Compress
"""

COM_HANDLER_ACTION = "MSFT_TaskComHandlerAction"

TRIGGER_NAMES = {
    "MSFT_TaskBootTrigger": "boot",
    "MSFT_TaskLogonTrigger": "logon",
    "MSFT_TaskTimeTrigger": "time",
    "MSFT_TaskDailyTrigger": "daily",
    "MSFT_TaskWeeklyTrigger": "weekly",
    "MSFT_TaskMonthlyTrigger": "monthly",
    "MSFT_TaskIdleTrigger": "idle",
    "MSFT_TaskEventTrigger": "event",
    "MSFT_TaskRegistrationTrigger": "registration",
    "MSFT_TaskSessionStateChangeTrigger": "session change",
}

SYSTEM_ACCOUNTS = {
    "system", "local service", "network service",
    "nt authority\\system", "nt authority\\local service", "nt authority\\network service",
}

# A COM class ID: {8-4-4-4-12 hexadecimal digits}. It comes from the task
# definition, so it is checked before being used to build a registry path.
CLASS_ID_PATTERN = re.compile(
    r"^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$"
)

# Where a COM class registers the file that implements it. 64-bit
# registrations come first; 32-bit ones live under WOW6432Node.
COM_SERVER_KEYS = [
    rf"CLSID\{{id}}\{kind}"
    for kind in ("InprocServer32", "LocalServer32")
] + [
    rf"WOW6432Node\CLSID\{{id}}\{kind}"
    for kind in ("InprocServer32", "LocalServer32")
]


def scan() -> ScanReport:
    report = ScanReport(scanner=SOURCE, locations_total=1)

    powershell = winenv.powershell_path()
    if powershell is None:
        return _failed(report, "The Windows folder could not be located (SystemRoot is not set)")

    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", PS_COMMAND],
            capture_output=True, text=True,
            encoding="utf-8-sig",  # tolerates a byte-order mark if PowerShell writes one
            check=True, timeout=POWERSHELL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return _failed(report, f"PowerShell did not finish within {POWERSHELL_TIMEOUT_SECONDS} seconds")
    except subprocess.CalledProcessError as exc:
        return _failed(report, f"PowerShell exited with code {exc.returncode} while listing tasks")
    except OSError as exc:
        return _failed(report, f"PowerShell could not be started ({exc.strerror or exc})")

    try:
        tasks = json.loads(result.stdout)
    except json.JSONDecodeError:
        return _failed(report, "PowerShell did not return a readable task list")
    if not isinstance(tasks, list):
        return _failed(report, "PowerShell returned the task list in an unexpected shape")

    com_lookup_errors = set()
    for task in tasks:
        if not isinstance(task, dict):
            continue  # an empty task list is serialised as [null]
        report.entries.extend(_entries_for_task(task, com_lookup_errors))

    report.errors.extend(sorted(com_lookup_errors))
    report.locations_checked = 1
    return report


def _entries_for_task(task: dict, com_lookup_errors: set) -> list[AutostartEntry]:
    full_name = f"{task.get('Path') or ''}{task.get('Name') or ''}"
    actions = _as_list(task.get("Actions"))
    run_as = (task.get("Group") or task.get("RunAs") or "").strip()
    triggers = [
        TRIGGER_NAMES.get(trigger, "other")
        for trigger in _as_list(task.get("Triggers"))
    ]
    runs_for_everyone = bool(task.get("Group")) or run_as.lower() in SYSTEM_ACCOUNTS

    entries = []
    for number, action in enumerate(actions, start=1):
        if not isinstance(action, dict):
            continue

        # Each action is its own entry, so every program a task can start is
        # examined. A task with one action keeps its plain name.
        name = full_name if len(actions) == 1 else f"{full_name} (action {number} of {len(actions)})"

        extra = {
            "state": task.get("State") or "",
            "run_as": run_as,
            "author": task.get("Author") or "",
            "triggers": triggers,
        }

        if action.get("Type") == COM_HANDLER_ACTION:
            class_id = (action.get("ClassId") or "").strip()
            command = _com_handler_command(class_id, com_lookup_errors)
            extra.update({
                "action_type": "com_handler",
                "com_class_id": class_id,
                "com_data": action.get("Data") or "",
            })
        else:
            command = _exec_command(action)
            extra["action_type"] = "exec"
            if action.get("WorkingDirectory"):
                extra["working_directory"] = action["WorkingDirectory"]

        entries.append(AutostartEntry(
            source=SOURCE,
            name=name,
            command=command,
            location=LOCATION,
            scope="all users" if runs_for_everyone else "current user",
            extra=extra,
        ))

    return entries


def _exec_command(action: dict) -> str:
    execute = (action.get("Execute") or "").strip()
    if not execute:
        return ""

    # Quote a program path that contains spaces so that it can be told
    # apart from its arguments.
    if " " in execute and not execute.startswith('"'):
        execute = f'"{execute}"'

    arguments = (action.get("Arguments") or "").strip()
    return f"{execute} {arguments}".strip()


def _com_handler_command(class_id: str, com_lookup_errors: set) -> str:
    """The file that implements the COM class, or "COM handler {id}" when it
    cannot be found. A COM-handler task runs that file, but the task itself
    only names the class."""
    server = _find_com_server(class_id, com_lookup_errors) if CLASS_ID_PATTERN.match(class_id) else None
    return server or f"COM handler {class_id}".strip()


def _find_com_server(class_id: str, com_lookup_errors: set) -> str | None:
    for template in COM_SERVER_KEYS:
        subkey = template.format(id=class_id)
        try:
            # HKEY_CLASSES_ROOT is Windows' merged view of the per-user and
            # machine-wide class registrations, so a per-user override is
            # seen the same way COM itself would see it.
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, subkey) as key:
                value, _ = winreg.QueryValueEx(key, "")
        except FileNotFoundError:
            continue
        except OSError as exc:
            com_lookup_errors.add(f"COM class registrations could not be read ({exc.strerror or exc})")
            continue

        if isinstance(value, str) and value.strip():
            return value.strip()

    return None


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _failed(report: ScanReport, message: str) -> ScanReport:
    report.failed = True
    report.errors.append(message)
    return report
