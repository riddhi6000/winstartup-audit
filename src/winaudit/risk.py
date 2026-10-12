import os
from datetime import datetime, timedelta
from dataclasses import dataclass
from .scanners import AutostartEntry

SUSPICIOUS_PATH_FRAGMENTS = ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
RECENT_DAYS_THRESHOLD = 30
NO_FLAGS_REASON = "No red flags — looks like a normal autostart entry"

@dataclass
class RiskAssessment:
    entry: AutostartEntry
    score: int                # 0 = looks fine, higher = more worth reviewing
    reasons: list[str]


def assess(entry: AutostartEntry, signature_checker=None) -> RiskAssessment:
    score = 0
    reasons = []

    # Winlogon values control programs launched during sign-in.
    # A deviation from the expected default deserves explicit review.
    # Only act when the scanner has explicitly identified a mismatch.
    if entry.source == "Winlogon Helper Key":
        if entry.extra.get("missing_value") is True:
            score += 4
            reasons.append(
                f"Winlogon value '{entry.name}' is missing"
            )
        elif entry.extra.get("matches_default") is False:
            score += 4
            reasons.append(
                f"Winlogon value '{entry.name}' differs from its expected default"
            )

    command_lower = entry.command.lower()

    exe_path = extract_exe_path(entry.command)
    exe_exists = bool(exe_path and os.path.exists(exe_path))

    if any(frag in command_lower for frag in SUSPICIOUS_PATH_FRAGMENTS):
        score += 2
        reasons.append("Runs from a Temp/Downloads-style folder, not a standard install location")

    # Prefer whatever the scanner already told us (e.g. Startup Folder
    # items carry their own creation time); otherwise fall back to the
    # actual executable's file creation date, so this check works for
    # EVERY scanner, not just the one that happens to populate `created`
    # directly. Deliberately NOT "when did this registry/service entry
    # appear" -- that's volatile for things like per-user services, which
    # get recreated with a new random name constantly. A file's own
    # creation date on disk is far more stable and meaningful.
    created = entry.created
    if created is None and exe_exists:
        try:
            created = datetime.fromtimestamp(os.path.getctime(exe_path))
        except OSError:
            created = None

    if created and created > datetime.now() - timedelta(days=RECENT_DAYS_THRESHOLD):
        score += 1
        reasons.append(f"Executable created recently ({created.date()})")

    is_store_app = "\\windowsapps\\" in command_lower


    if is_store_app:
        reasons.append(
            "Installed via Microsoft Store (WindowsApps) — "
            "signature not independently checked"
        )
    elif signature_checker is not None and exe_exists:
        signature_result = signature_checker(exe_path)

        # Support both the richer result dictionary and the old Boolean
        # interface, so existing callers do not break unexpectedly.
        if isinstance(signature_result, dict):
            status = signature_result.get("status", "UnknownError")
            checked = signature_result.get("checked", False)
            signed = signature_result.get("signed", False)
            status_message = signature_result.get("status_message", "")

            if status == "Valid" and checked and signed:
                pass  # Signature is valid; no signature-related penalty.

            elif status == "NotSigned" and checked:
                score += 2
                reasons.append("Executable is not digitally signed")

            elif status in ("HashMismatch", "NotTrusted"):
                score += 4
                reasons.append(
                    f"Executable signature has a trust concern ({status})"
                )

            elif (
                status == "UnknownError"
                and "root certificate" in status_message.lower()
                and "not trusted" in status_message.lower()
            ):
                score += 4
                reasons.append(
                    "Signature certificate chain terminates at an untrusted root certificate"
                )

            else:
                # A failed or inconclusive check is not proof of malware,
                # but it also must not be silently treated as trusted.
                score += 1
                reasons.append(
                    f"Executable signature could not be verified conclusively "
                    f"({status})"
                )

        elif not signature_result:
            # Backward compatibility for callers returning a Boolean.
            score += 2
            reasons.append("Executable is not digitally signed")


    if not reasons:
        reasons.append(NO_FLAGS_REASON)

    return RiskAssessment(entry=entry, score=score, reasons=reasons)

def extract_exe_path(command: str) -> str | None:
    """Commands often come with quoted paths + arguments, e.g.
    '"C:\\Program Files\\App\\app.exe" --silent' -- pull out just the exe path.
    For unquoted commands, naive space-splitting breaks on paths that
    themselves contain spaces (e.g. "...\\Windows Defender\\...\\MpCmdRun.exe
    -Arg"), so we instead find where a known executable extension ends and
    cut there."""
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else None

    lower = command.lower()
    for ext in (".exe", ".dll", ".com"):
        idx = lower.find(ext)
        if idx != -1:
            return command[:idx + len(ext)]
    return command.split(" ")[0]