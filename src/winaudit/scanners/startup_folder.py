import os
from pathlib import Path
from datetime import datetime
from . import AutostartEntry, ScanReport

SOURCE = "Startup Folder"
STARTUP_SUBPATH = r"Microsoft\Windows\Start Menu\Programs\Startup"

# (environment variable holding the root folder, scope)
FOLDER_ROOTS = [
    ("APPDATA", "current user"),
    ("PROGRAMDATA", "all users"),
]


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

            created = getattr(stat, "st_birthtime", None)
            if created is None:
                created = stat.st_ctime

            report.entries.append(AutostartEntry(
                source=SOURCE,
                name=item.name,
                command=resolved,
                location=str(folder),
                scope=scope,
                created=datetime.fromtimestamp(created),
            ))

        if folder_complete:
            report.locations_checked += 1

    return report
