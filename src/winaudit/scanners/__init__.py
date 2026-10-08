from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AutostartEntry:
    source: str              # "Registry Run Key", "Scheduled Task", etc.
    name: str                # the value name / task name / service name
    command: str             # the actual command or executable path that runs
    location: str            # e.g. the registry key path, or task folder
    scope: str                # "current user" or "all users / system"
    created: Optional[datetime] = None   # when discoverable
    extra: dict = field(default_factory=dict)  # scanner-specific details