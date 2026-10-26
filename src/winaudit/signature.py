import concurrent.futures
import json
import os
import subprocess

from . import winenv


# This script is constant. The file path is passed through the environment,
# rather than interpolated into PowerShell source code.
_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

try {
    $target = $env:WINAUDIT_AUTHENTICODE_TARGET

    if ([string]::IsNullOrWhiteSpace($target)) {
        throw 'No target path was supplied.'
    }

    $sig = Get-AuthenticodeSignature -LiteralPath $target

    $subject = ''
    if ($null -ne $sig.SignerCertificate) {
        $subject = $sig.SignerCertificate.Subject
    }

    [PSCustomObject]@{
        status         = [string]$sig.Status
        status_message = [string]$sig.StatusMessage
        subject        = $subject
    } | ConvertTo-Json -Compress
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
"""


def _inconclusive(status: str | None = None) -> dict:
    """Return a result when signature verification could not conclude."""
    return {
        "signed": False,
        "publisher": None,
        "checked": False,
        "status": status or "CheckFailed",
    }


def check_signature(exe_path: str, timeout: int = 15) -> dict:
    """Check a file's Authenticode signature without interpolating its path.

    Returns:
        signed: True only when Windows reports a valid signature.
        publisher: Certificate subject, when available.
        checked: Whether a conclusive signature status was obtained.
        status: The actual Authenticode status or a failure status.

    An invalid signature is distinct from an unsigned file. A failed or
    inconclusive check must not be interpreted as proof that a file is
    unsigned.
    """
    if not isinstance(exe_path, str) or not exe_path.strip():
        return _inconclusive("InvalidPath")

    if timeout <= 0:
        return _inconclusive("InvalidTimeout")

    powershell = winenv.powershell_path()
    if powershell is None:
        return _inconclusive("PowerShellNotFound")

    env = os.environ.copy()
    env["WINAUDIT_AUTHENTICODE_TARGET"] = exe_path

    try:
        result = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _POWERSHELL_SCRIPT,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return _inconclusive("Timeout")
    except OSError:
        # Includes PowerShell not being available or failing to launch.
        return _inconclusive("ExecutionFailed")

    if result.returncode != 0:
        return _inconclusive("ExecutionFailed")

    output = result.stdout.strip()
    if not output:
        return _inconclusive("EmptyOutput")

    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return _inconclusive("InvalidOutput")

    if not isinstance(payload, dict):
        return _inconclusive("InvalidOutput")
    
    status = payload.get("status")
    subject = payload.get("subject", "")
    status_message = payload.get("status_message", "")

    if not isinstance(status, str) or not status:
        return _inconclusive("MissingStatus")

    # Only Valid establishes a valid Authenticode signature.
    if status == "Valid":
        return {
            "signed": True,
            "publisher": subject or None,
            "checked": True,
            "status": status,
            "status_message": status_message,
        }

    # NotSigned is a conclusive unsigned result. Other statuses must not
    # be collapsed into NotSigned.
    if status == "NotSigned":
        return {
            "signed": False,
            "publisher": None,
            "checked": True,
            "status": status,
            "status_message": status_message,
        }

    # Preserve invalid or unsupported statuses for the risk layer to
    # interpret explicitly in a subsequent change.
    if status in {"HashMismatch", "NotTrusted"}:
        return {
            "signed": False,
            "publisher": subject or None,
            "checked": True,
            "status": status,
            "status_message": status_message,
        }

    result = _inconclusive(status)
    result["publisher"] = subject or None
    result["status_message"] = status_message
    return result


def is_signed(exe_path: str) -> bool:
    """Compatibility helper: True only for a confirmed valid signature."""
    result = check_signature(exe_path)
    return result["checked"] and result["signed"]


def batch_check(
    exe_paths: list[str],
    max_workers: int = 6,
) -> dict[str, dict]:
    """Check unique paths concurrently and retry inconclusive checks once."""
    if max_workers < 1:
        raise ValueError("max_workers must be at least 1")

    unique_paths = sorted(set(exe_paths))
    results: dict[str, dict] = {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers
    ) as pool:
        future_to_path = {
            pool.submit(check_signature, path): path
            for path in unique_paths
        }

        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            try:
                results[path] = future.result()
            except Exception:
                # One failed worker must not abort the complete batch.
                results[path] = _inconclusive("WorkerFailed")

    inconclusive_paths = [
        path for path, result in results.items()
        if not result["checked"]
    ]

    for path in inconclusive_paths:
        try:
            results[path] = check_signature(path, timeout=20)
        except Exception:
            results[path] = _inconclusive("RetryFailed")

    return results