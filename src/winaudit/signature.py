import re
import subprocess


def check_signature(exe_path: str) -> dict:
    """Checks whether a file is digitally signed, and if so, by whom.
    Returns a dict like {"signed": True, "publisher": "Microsoft Corporation"}
    or {"signed": False, "publisher": None}.
    """
    ps_command = (
        f"$sig = Get-AuthenticodeSignature -LiteralPath '{exe_path}'; "
        "if ($sig.Status -eq 'Valid') { $sig.SignerCertificate.Subject } "
        "else { 'NOT_SIGNED' }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {"signed": False, "publisher": None}

    output = result.stdout.strip()
    if not output or output == "NOT_SIGNED":
        return {"signed": False, "publisher": None}

    # The certificate subject looks like:
    # CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
    match = re.search(r"CN=([^,]+)", output)
    publisher = match.group(1).strip() if match else None
    return {"signed": True, "publisher": publisher}


def is_signed(exe_path: str) -> bool:
    """Simple True/False wrapper — this is what risk.assess() calls,
    since it only needs a yes/no answer, not the publisher name."""
    return check_signature(exe_path)["signed"]