import concurrent.futures
import re
import subprocess


def check_signature(exe_path: str, timeout: int = 15) -> dict:
    """Checks whether a file is digitally signed, and if so, by whom.
    Returns {"signed": bool, "publisher": str|None, "checked": bool}.
    "checked" is False when we couldn't get a conclusive answer (e.g. a
    timeout under load) -- this is NOT the same as a confirmed "unsigned"
    result, and callers should treat it differently.
    """
    ps_command = (
        f"$sig = Get-AuthenticodeSignature -LiteralPath '{exe_path}'; "
        "if ($sig.Status -eq 'Valid') { $sig.SignerCertificate.Subject } "
        "else { 'NOT_SIGNED' }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {"signed": False, "publisher": None, "checked": False}

    output = result.stdout.strip()
    if not output or output == "NOT_SIGNED":
        return {"signed": False, "publisher": None, "checked": True}

    # The certificate subject looks like:
    # CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
    match = re.search(r"CN=([^,]+)", output)
    publisher = match.group(1).strip() if match else None
    return {"signed": True, "publisher": publisher, "checked": True}


def is_signed(exe_path: str) -> bool:
    return check_signature(exe_path)["signed"]


def batch_check(exe_paths: list[str], max_workers: int = 6) -> dict[str, dict]:
    """Checks many files for valid signatures AND publisher identity at
    once. Deduplicates identical paths, checks the remaining unique paths
    in parallel (each check shells out to PowerShell and spends nearly all
    its time waiting on that process, not doing CPU work -- a good fit for
    a thread pool), then retries anything inconclusive ONE AT A TIME with
    more room to breathe -- a few stragglers running alone are far less
    likely to time out than 12 processes all competing at once.
    """
    unique_paths = sorted(set(exe_paths))
    results: dict[str, dict] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_path = {pool.submit(check_signature, path): path for path in unique_paths}
        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            try:
                results[path] = future.result()
            except Exception:
                results[path] = {"signed": False, "publisher": None, "checked": False}

    inconclusive = [path for path, r in results.items() if not r["checked"]]
    for path in inconclusive:
        results[path] = check_signature(path, timeout=20)

    return results