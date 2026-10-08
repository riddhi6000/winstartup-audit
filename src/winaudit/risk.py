import os
from datetime import datetime, timedelta
from dataclasses import dataclass
from .scanners import AutostartEntry

SUSPICIOUS_PATH_FRAGMENTS = ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
RECENT_DAYS_THRESHOLD = 30


@dataclass
class RiskAssessment:
    entry: AutostartEntry
    score: int                # 0 = looks fine, higher = more worth reviewing
    reasons: list[str]


def assess(entry: AutostartEntry, signature_checker=None) -> RiskAssessment:
    score = 0
    reasons = []

    command_lower = entry.command.lower()

    if any(frag in command_lower for frag in SUSPICIOUS_PATH_FRAGMENTS):
        score += 2
        reasons.append("Runs from a Temp/Downloads-style folder, not a standard install location")

    if entry.created and entry.created > datetime.now() - timedelta(days=RECENT_DAYS_THRESHOLD):
        score += 1
        reasons.append(f"Created recently ({entry.created.date()})")

    if signature_checker is not None:
        exe_path = _extract_exe_path(entry.command)
        if exe_path and os.path.exists(exe_path):
            if not signature_checker(exe_path):
                score += 2
                reasons.append("Executable is not digitally signed")

    if not reasons:
        reasons.append("No red flags — looks like a normal autostart entry")

    return RiskAssessment(entry=entry, score=score, reasons=reasons)


def _extract_exe_path(command: str) -> str | None:
    """Commands often come with quoted paths + arguments, e.g.
    '"C:\\Program Files\\App\\app.exe" --silent' — pull out just the exe path."""
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else None
    return command.split(" ")[0]