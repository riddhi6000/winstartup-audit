import os
from pathlib import Path
from datetime import datetime
from . import AutostartEntry


def _folders() -> list[tuple[Path, str]]:
    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("PROGRAMDATA", "")
    return [
        (Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup", "current user"),
        (Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\Startup", "all users"),
    ]


def scan() -> list[AutostartEntry]:
    entries = []
    for folder, scope in _folders():
        if not folder.exists():
            continue
        for item in folder.iterdir():
            if item.name.lower() == "desktop.ini":
                continue
            stat = item.stat()
            entries.append(AutostartEntry(
                source="Startup Folder",
                name=item.name,
                command=str(item.resolve()),
                location=str(folder),
                scope=scope,
                created=datetime.fromtimestamp(stat.st_ctime),
            ))
    return entries