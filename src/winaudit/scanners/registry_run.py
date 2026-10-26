import winreg
from . import AutostartEntry, ScanReport
from .. import startup_approved

SOURCE = "Registry Run Key"

# EnumValue reports "no more values" by raising OSError with this Windows
# error code (ERROR_NO_MORE_ITEMS). Any OTHER OSError is a genuine failure.
ERROR_NO_MORE_ITEMS = 259

# (hive, subkey, human-readable scope)
RUN_KEY_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "current user"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "current user"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "all users"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "all users"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "all users (32-bit)"),
    # Added after the original five (their positions are relied on elsewhere).
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "all users (32-bit)"),
    # Group Policy can set programs to run at sign-in; software can also
    # write here directly.
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "current user (policy)"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "all users (policy)"),
]

# Which StartupApproved record Task Manager keeps for each key, if any.
_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUN32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
APPROVAL_KIND = {
    (winreg.HKEY_CURRENT_USER, _RUN): "Run",
    (winreg.HKEY_LOCAL_MACHINE, _RUN): "Run",
    (winreg.HKEY_LOCAL_MACHINE, _RUN32): "Run32",
}


def scan() -> ScanReport:
    report = ScanReport(scanner=SOURCE, locations_total=len(RUN_KEY_LOCATIONS))

    for hive, subkey, scope in RUN_KEY_LOCATIONS:
        location = f"{_hive_name(hive)}\\{subkey}"

        try:
            key = winreg.OpenKey(hive, subkey)
        except FileNotFoundError:
            # An absent key just means nothing is configured there.
            report.locations_checked += 1
            continue
        except OSError as exc:
            # Access denied and similar: we could not look, which is NOT
            # the same as "nothing there", so it is reported.
            report.errors.append(f"{location}: could not be opened ({_describe(exc)})")
            continue

        with key:
            location_complete = True
            index = 0

            # Registry values can only be read one index at a time; the end
            # of the list is signalled by an exception, so the loop runs
            # until that specific exception arrives.
            while True:
                try:
                    name, command, _ = winreg.EnumValue(key, index)
                except OSError as exc:
                    if getattr(exc, "winerror", None) != ERROR_NO_MORE_ITEMS:
                        report.errors.append(
                            f"{location}: reading stopped early ({_describe(exc)})"
                        )
                        location_complete = False
                    break

                index += 1

                if not isinstance(command, str):
                    report.errors.append(
                        f"{location}: value '{name}' is not text "
                        f"(type {type(command).__name__}) and was skipped"
                    )
                    location_complete = False
                    continue

                extra = {}
                approval_kind = APPROVAL_KIND.get((hive, subkey))
                if approval_kind:
                    state = startup_approved.approval_state(approval_kind, name)
                    if state:
                        extra["start_mode"] = state  # "Disabled" when switched off in Task Manager

                report.entries.append(AutostartEntry(
                    source=SOURCE,
                    name=name,
                    command=command,
                    location=location,
                    scope=scope,
                    extra=extra,
                ))

            if location_complete:
                report.locations_checked += 1

    return report


def _describe(exc: OSError) -> str:
    return exc.strerror or str(exc)


def _hive_name(hive) -> str:
    return {
        winreg.HKEY_CURRENT_USER: "HKCU",
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
    }.get(hive, str(hive))
