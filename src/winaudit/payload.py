"""Finds the code that an entry really runs when the program it names is
only a host for something else.

`rundll32.exe X.dll,Entry` and `svchost.exe -k group` are signed by
Microsoft whatever they load, so the signature of the host proves nothing
about the DLL. This module works out which file the host will load, so that
file can be examined too.
"""
import ntpath
import os
import re
import winreg
from dataclasses import dataclass

from . import risk

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
SCRIPT_EXTENSIONS = (".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta")
SCRIPT_HOSTS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
})
PER_USER_SERVICE_SUFFIX = re.compile(r"_[0-9A-Fa-f]{4,8}$")
URL_SCHEME = re.compile(r"^[a-z]{2,}:")  # javascript:, http: ... but not a drive letter such as C:


@dataclass(frozen=True)
class Payload:
    kind: str          # "DLL", "service DLL" or "script"
    path: str | None   # expanded path; an existing file only when state is "found"
    state: str         # "found", "missing", "unexpanded" or "unresolved"


def find_payload(name: str, source: str, command: str, exists=None) -> Payload | None:
    """The file the entry's host program will load or run, or None when the
    program is not a host (or the command names nothing to load)."""
    exe_path = risk.extract_exe_path(command) if isinstance(command, str) else None
    if not exe_path:
        return None

    program = ntpath.basename(exe_path).lower()
    arguments = risk.command_arguments(command)

    if program == "rundll32.exe":
        return _resolve("DLL", _rundll32_target(arguments), exists)
    if program == "regsvr32.exe":
        return _resolve("DLL", _first_plain_token(arguments), exists)
    if program == "svchost.exe" and source == "Windows Service":
        return _service_dll_payload(name, exists)
    if program in SCRIPT_HOSTS:
        return _resolve("script", _script_target(arguments), exists, search_system_folders=False)
    return None


def _rundll32_target(arguments: str) -> str | None:
    """`rundll32.exe [/switches] dllname,EntryPoint args` -- the DLL is the
    text before the first comma (or the first word, if there is no comma)."""
    text = arguments.strip()
    while text.startswith("/"):
        parts = text.split(None, 1)
        text = parts[1] if len(parts) > 1 else ""
    if not text:
        return None

    if text.startswith('"'):
        end = text.find('"', 1)
        target = text[1:end] if end > 0 else ""
    elif "," in text:
        target = text.split(",", 1)[0]
    else:
        target = text.split(None, 1)[0]

    target = target.strip()
    if not target or URL_SCHEME.match(target.lower()):
        return None  # javascript: and similar are caught by the command rules instead
    return target


def _tokens(arguments: str) -> list[str]:
    return [token.strip('"') for token in re.findall(r'"[^"]*"|\S+', arguments)]


def _first_plain_token(arguments: str) -> str | None:
    for token in _tokens(arguments):
        if token and token[0] not in "/-":
            return token
    return None


def _script_target(arguments: str) -> str | None:
    for token in _tokens(arguments):
        if token and token[0] not in "/-" and token.lower().endswith(SCRIPT_EXTENSIONS):
            return token
    return None


def _resolve(kind: str, target: str | None, exists=None, search_system_folders: bool = True) -> Payload | None:
    if not target:
        return None

    exists = exists or os.path.exists
    path = risk.expand_variables(target)
    if "%" in path:
        return Payload(kind, path, "unexpanded")

    if "\\" not in path and "/" not in path:
        # A bare file name. Windows would look in its system folders (and
        # nowhere we can rely on), so only those are tried.
        if search_system_folders and ntpath.splitext(path)[1]:
            for directory in risk.system_directories():
                candidate = os.path.join(directory, path)
                if exists(candidate):
                    return Payload(kind, candidate, "found")
            return Payload(kind, path, "missing")
        return Payload(kind, path, "unresolved")

    return Payload(kind, path, "found" if exists(path) else "missing")


def _service_dll_payload(service_name: str, exists=None) -> Payload | None:
    """A service hosted by svchost keeps the DLL that implements it in the
    registry (ServiceDll), not in its command line."""
    value, unreadable = _read_service_dll(service_name)
    if unreadable:
        return Payload("service DLL", None, "unresolved")
    return _resolve("service DLL", value, exists)


def _read_service_dll(service_name: str) -> tuple[str | None, bool]:
    # Per-user services are registered under their base name; the random
    # suffix is only added to the running instance.
    candidates = [service_name]
    base_name = PER_USER_SERVICE_SUFFIX.sub("", service_name)
    if base_name != service_name:
        candidates.append(base_name)

    for candidate in candidates:
        if not candidate or "\\" in candidate or "/" in candidate:
            continue
        for subkey in (f"{SERVICES_KEY}\\{candidate}\\Parameters", f"{SERVICES_KEY}\\{candidate}"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                    value, _ = winreg.QueryValueEx(key, "ServiceDll")
            except FileNotFoundError:
                continue
            except OSError:
                return None, True
            if isinstance(value, str) and value.strip():
                return value.strip(), False

    return None, False
