import winreg
from . import AutostartEntry, ScanReport

SOURCE = "Winlogon Helper Key"
WINLOGON_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
LOCATION = f"HKLM\\{WINLOGON_KEY}"

# Winlogon doesn't support enumerating arbitrary entries the way Run keys
# do -- it's a small, fixed set of named values controlling what launches
# as part of the login process itself. So instead of listing "everything
# present," we check each by name against what's normal on a clean system.
EXPECTED_DEFAULTS = {
    "Shell": "explorer.exe",
    "Userinit": r"C:\Windows\system32\userinit.exe,",
}


def scan() -> ScanReport:
    report = ScanReport(scanner=SOURCE, locations_total=len(EXPECTED_DEFAULTS))

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY)
    except FileNotFoundError:
        # Every Windows installation has this key, so its absence is
        # unexpected and must not read as "nothing to report".
        report.failed = True
        report.errors.append("Winlogon registry key not found (expected on every Windows installation)")
        return report
    except OSError as exc:
        report.failed = True
        report.errors.append(f"Winlogon registry key could not be opened ({exc.strerror or exc})")
        return report

    with key:
        for value_name, expected in EXPECTED_DEFAULTS.items():
            try:
                data, _ = winreg.QueryValueEx(key, value_name)
            except FileNotFoundError:
                report.entries.append(AutostartEntry(
                    source=SOURCE,
                    name=value_name,
                    command="",
                    location=LOCATION,
                    scope="all users",
                    extra={
                        "matches_default": False,
                        "missing_value": True,
                    },
                ))
                report.locations_checked += 1
                continue
            except OSError as exc:
                report.errors.append(
                    f"Winlogon value '{value_name}' could not be read ({exc.strerror or exc})"
                )
                continue

            is_text = isinstance(data, str)
            extra = {
                "matches_default": (
                    is_text and data.strip().lower() == expected.strip().lower()
                )
            }
            if not is_text:
                extra["unexpected_type"] = type(data).__name__

            report.entries.append(AutostartEntry(
                source=SOURCE,
                name=value_name,
                command=data if is_text else "",
                location=LOCATION,
                scope="all users",
                extra=extra,
            ))
            report.locations_checked += 1

    return report
