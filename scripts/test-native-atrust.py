#!/usr/bin/env python3
"""Run native aTrust packet I/O on disposable CI hosts (no VPN credentials)."""
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    repo = Path(__file__).resolve().parent.parent
    system = platform.system()
    if system not in {"Linux", "Windows", "Darwin"}:
        raise SystemExit("unsupported native TUN test platform")
    with tempfile.TemporaryDirectory(prefix="flexconnect-tun-") as directory:
        output = Path(directory)
        binary = output / ("atrust.test.exe" if system == "Windows" else "atrust.test")
        subprocess.run(["go", "test", "-c", "-o", str(binary), "./internal/vpn/atrust"], cwd=repo, check=True)
        if system == "Windows":
            shutil.copyfile(repo / "assets/windows/wintun.dll", output / "wintun.dll")
        command = [str(binary), "-test.run=^TestNativeATrustTUNFlows$", "-test.timeout=30s", "-test.v"]
        env = os.environ.copy()
        env["FLEXCONNECT_ATRUST_TUN_TEST"] = "1"
        if system == "Linux":
            command = ["sudo", "unshare", "--net", "env", "FLEXCONNECT_ATRUST_TUN_TEST=1", *command]
        elif system == "Darwin":
            command = ["sudo", "env", "FLEXCONNECT_ATRUST_TUN_TEST=1", *command]
        subprocess.run(command, cwd=repo, env=env, check=True)


if __name__ == "__main__":
    main()
