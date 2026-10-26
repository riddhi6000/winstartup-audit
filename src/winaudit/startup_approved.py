"""Whether Windows has been told to skip an entry at sign-in.

Task Manager's Startup tab does not delete an entry when it is switched off;
it writes a record under StartupApproved and leaves the entry itself where
it is. Without reading those records, a disabled entry looks just like an
active one.
"""
import winreg

BASE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"


def approval_state(kind: str, name: str) -> str | None:
    """"Disabled", "Enabled", or None when there is no record for the entry.

    `kind` is the StartupApproved sub-key: "Run" (Run keys), "Run32" (the
    32-bit Run key) or "StartupFolder" (shortcuts in a Startup folder).

    The record is binary; by observed convention, an odd first byte means
    disabled (03) and an even one enabled (02, 06). Microsoft does not
    document the format, which is why a missing or unreadable record counts
    as "no record" rather than as an answer.
    """
    states = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, f"{BASE_KEY}\\{kind}") as key:
                data, _ = winreg.QueryValueEx(key, name)
        except OSError:
            continue

        if isinstance(data, (bytes, bytearray)) and data:
            states.append("Disabled" if data[0] & 1 else "Enabled")

    if "Disabled" in states:
        return "Disabled"
    if "Enabled" in states:
        return "Enabled"
    return None
