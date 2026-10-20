"""Locations of Windows' own helper programs.

Helpers are launched by absolute path under the Windows folder. A bare name
like "powershell" lets Windows pick the first match from a list of
directories that can include the current one, which is not something a
security tool should leave to chance.
"""
import os


def system_root() -> str | None:
    return os.environ.get("SystemRoot") or os.environ.get("windir") or None


def powershell_path() -> str | None:
    root = system_root()
    if not root:
        return None
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
