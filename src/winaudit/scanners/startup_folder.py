import json
import os
import subprocess
from pathlib import Path
from datetime import datetime
from . import AutostartEntry, ScanReport
from .. import startup_approved, winenv

SOURCE = "Startup Folder"
STARTUP_SUBPATH = r"Microsoft\Windows\Start Menu\Programs\Startup"
SHORTCUT_TIMEOUT_SECONDS = 60

# (environment variable holding the root folder, scope)
FOLDER_ROOTS = [
    ("APPDATA", "current user"),
    ("PROGRAMDATA", "all users"),
]

# Reads where each shortcut points. The shortcut paths are passed in an
# environment variable rather than written into this script, so a file name
# can never be interpreted as PowerShell code.
SHORTCUT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$paths = $env:WINAUDIT_SHORTCUTS | ConvertFrom-Json
$shell = New-Object -ComObject WScript.Shell
$items = foreach ($path in $paths) {
    $shortcut = $shell.CreateShortcut($path)
    [pscustomobject]@{
        Path      = $path
        Target    = $shortcut.TargetPath
        Arguments = $shortcut.Arguments
    }
}
ConvertTo-Json -InputObject @($items) -Compress
"""


def _folders() -> list[tuple[str, Path | None, str]]:
    """(variable name, folder, scope). The folder is None when the variable
    is unset -- Path("") would silently point at the current directory."""
    folders = []
    for variable, scope in FOLDER_ROOTS:
        root = os.environ.get(variable, "")
        folders.append((variable, Path(root) / STARTUP_SUBPATH if root else None, scope))
    return folders


def scan() -> ScanReport:
    report = ScanReport(scanner=SOURCE)
    found = []  # (item, stat, resolved path, scope, folder)

    for variable, folder, scope in _folders():
        report.locations_total += 1

        if folder is None:
            report.errors.append(
                f"{scope} Startup folder not checked: %{variable}% is not set"
            )
            continue

        try:
            if not folder.exists():
                report.locations_checked += 1  # nothing configured there
                continue
            items = list(folder.iterdir())
        except OSError as exc:
            report.errors.append(f"{folder}: could not be read ({exc.strerror or exc})")
            continue

        folder_complete = True
        for item in items:
            if item.name.lower() == "desktop.ini":
                continue

            try:
                stat = item.stat()
                resolved = str(item.resolve())
            except OSError as exc:
                report.errors.append(f"{item}: could not be read ({exc.strerror or exc})")
                folder_complete = False
                continue

            found.append((item, stat, resolved, scope, folder))

        if folder_complete:
            report.locations_checked += 1

    targets = _read_shortcut_targets(
        [resolved for item, _, resolved, _, _ in found if item.suffix.lower() == ".lnk"],
        report,
    )

    for item, stat, resolved, scope, folder in found:
        command = resolved
        extra = {}

        if item.suffix.lower() == ".lnk":
            target, arguments = targets.get(resolved, ("", ""))
            if target:
                # The entry is judged on what the shortcut starts, not on the
                # shortcut file itself.
                command = _join(target, arguments)
                extra["shortcut"] = resolved
            else:
                extra["shortcut_unresolved"] = True

        state = startup_approved.approval_state("StartupFolder", item.name)
        if state:
            extra["start_mode"] = state  # "Disabled" when switched off in Task Manager

        created = getattr(stat, "st_birthtime", None)
        if created is None:
            created = stat.st_ctime

        report.entries.append(AutostartEntry(
            source=SOURCE,
            name=item.name,
            command=command,
            location=str(folder),
            scope=scope,
            created=datetime.fromtimestamp(created),
            extra=extra,
        ))

    return report


def _join(target: str, arguments: str) -> str:
    if " " in target and not target.startswith('"'):
        target = f'"{target}"'
    return f"{target} {arguments}".strip()


def _read_shortcut_targets(paths: list[str], report: ScanReport) -> dict[str, tuple[str, str]]:
    """{shortcut path: (target, arguments)}. Empty when there is nothing to
    read or it could not be read; a failure is reported, not hidden."""
    if not paths:
        return {}

    powershell = winenv.powershell_path()
    if powershell is None:
        report.errors.append("Shortcut targets not read: the Windows folder could not be located")
        return {}

    env = os.environ.copy()
    env["WINAUDIT_SHORTCUTS"] = json.dumps(paths)

    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", SHORTCUT_SCRIPT],
            capture_output=True, text=True, encoding="utf-8-sig",
            check=True, timeout=SHORTCUT_TIMEOUT_SECONDS, env=env,
        )
        items = json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        report.errors.append("Shortcut targets not read: PowerShell timed out")
        return {}
    except subprocess.CalledProcessError as exc:
        report.errors.append(f"Shortcut targets not read: PowerShell exited with code {exc.returncode}")
        return {}
    except (OSError, json.JSONDecodeError):
        report.errors.append("Shortcut targets not read: PowerShell did not give a usable answer")
        return {}

    if not isinstance(items, list):
        report.errors.append("Shortcut targets not read: PowerShell did not give a usable answer")
        return {}

    return {
        item["Path"]: ((item.get("Target") or "").strip(), (item.get("Arguments") or "").strip())
        for item in items
        if isinstance(item, dict) and isinstance(item.get("Path"), str)
    }
