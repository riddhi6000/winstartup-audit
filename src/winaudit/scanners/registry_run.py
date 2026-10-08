import winreg
from . import AutostartEntry

# (hive, subkey, human-readable scope)
RUN_KEY_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "current user"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "current user"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "all users"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "all users"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "all users (32-bit)"),
]


def scan() -> list[AutostartEntry]:
    entries = []
    for hive, subkey, scope in RUN_KEY_LOCATIONS:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, command, _ = winreg.EnumValue(key, i)
                        entries.append(AutostartEntry(
                            source="Registry Run Key",
                            name=name,
                            command=command,
                            location=f"{_hive_name(hive)}\\{subkey}",
                            scope=scope,
                        ))
                        i += 1
                    except OSError:
                        break  # no more values in this key
        except FileNotFoundError:
            continue  # this key doesn't exist on this machine — fine
    return entries


def _hive_name(hive) -> str:
    return {
        winreg.HKEY_CURRENT_USER: "HKCU",
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
    }.get(hive, str(hive))