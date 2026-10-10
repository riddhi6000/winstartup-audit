import winreg
from . import AutostartEntry

WINLOGON_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Winlogon doesn't support enumerating arbitrary entries the way Run keys
# do -- it's a small, fixed set of named values controlling what launches
# as part of the login process itself. So instead of listing "everything
# present," we check each by name against what's normal on a clean system.
EXPECTED_DEFAULTS = {
    "Shell": "explorer.exe",
    "Userinit": r"C:\Windows\system32\userinit.exe,",
}


def scan() -> list[AutostartEntry]:
    entries = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY) as key:
            for value_name, expected in EXPECTED_DEFAULTS.items():
                try:
                    data, _ = winreg.QueryValueEx(key, value_name)
                except FileNotFoundError:
                    continue  # value isn't set -- nothing to report

                entries.append(AutostartEntry(
                    source="Winlogon Helper Key",
                    name=value_name,
                    command=data,
                    location=f"HKLM\\{WINLOGON_KEY}",
                    scope="all users",
                    extra={"matches_default": data.strip().lower() == expected.strip().lower()},
                ))
    except FileNotFoundError:
        pass  # Winlogon key itself missing -- shouldn't happen on real Windows, but don't crash over it

    return entries