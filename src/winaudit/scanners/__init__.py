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


@dataclass
class ScanReport:
    """What one scanner produced, including what it could NOT read.

    An empty `entries` list on its own is ambiguous: it can mean "nothing is
    configured here" or "the scanner was unable to look". `errors` and
    `failed` remove that ambiguity, so a gap in coverage can never be
    mistaken for a clean result.
    """
    scanner: str                                  # same text as entry.source
    entries: list[AutostartEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    failed: bool = False                          # True: the scanner could not run at all
    locations_total: int = 0                      # keys / folders / queries it set out to read
    locations_checked: int = 0                    # how many of those it read completely

    @property
    def status(self) -> str:
        if self.failed:
            return "failed"
        if self.errors:
            return "partial"
        return "complete"
