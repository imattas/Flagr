"""
Flagr CLI wrapper — handles version checking, self-update, and
launching the real flagr entry point.

When running as a PyInstaller binary, extracts the bundled flagr
package so Python can import it normally.
"""

import os
import sys
import shutil
import subprocess
import platform


REPO_URL = "https://github.com/imattas/Flagr"
REPO_RAW = "https://raw.githubusercontent.com/imattas/Flagr/main/VERSION"
BINARY_URL = "https://github.com/imattas/Flagr/releases/download/v{version}/flagr-{arch}"
INSTALL_DIR = "/opt/flagr"


def _get_version():
    """Read version from VERSION file."""
    search = [
        os.path.join(getattr(sys, "_MEIPASS", ""), "VERSION"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "VERSION"),
        os.path.join(INSTALL_DIR, "VERSION"),
    ]
    for vf in search:
        if os.path.exists(vf):
            with open(vf) as f:
                return f.read().strip()
    return "3.0"


def _get_arch():
    """Detect system architecture."""
    machine = platform.machine().lower()
    arch_map = {
        "x86_64": "x86_64", "amd64": "x86_64",
        "aarch64": "aarch64", "arm64": "aarch64",
        "armv7l": "armv7", "i686": "i686", "i386": "i686",
    }
    return arch_map.get(machine, machine)


def _find_install_path():
    """Find the best place to install the binary."""
    for d in ["/usr/local/bin", "/usr/bin", "/bin", os.path.expanduser("~/.local/bin")]:
        if os.path.isdir(d):
            return os.path.join(d, "flagr")
    local_bin = os.path.expanduser("~/.local/bin")
    os.makedirs(local_bin, exist_ok=True)
    return os.path.join(local_bin, "flagr")


def _fetch_remote_version():
    """Fetch latest VERSION from GitHub."""
    import re
    try:
        result = subprocess.run(
            ["curl", "-sL", "--max-time", "5", REPO_RAW],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            v = result.stdout.strip().splitlines()[0].strip()
            if re.match(r'^\d+\.\d+', v):
                return v
    except Exception:
        pass
    return None


def cmd_update():
    """Update Flagr to the latest version."""
    local = _get_version()
    print(f"Current version: {local}")
    print("Checking for updates...")

    remote = _fetch_remote_version()
    if remote is None:
        print("\033[1;31m[-]\033[0m Could not check remote version")
        return

    if remote == local:
        print(f"\033[1;32m[+]\033[0m Already up to date (v{local})")
        return

    arch = _get_arch()
    print(f"\033[1;33m[!]\033[0m Update available: v{local} → v{remote}")
    print(f"Downloading binary for {arch}...")

    urls_to_try = [
        BINARY_URL.format(version=remote, arch=arch),
        BINARY_URL.format(version=remote, arch="x86_64"),
    ]

    tmp_bin = "/tmp/flagr-update.tmp"
    downloaded = False

    for url in urls_to_try:
        r = subprocess.run(
            ["curl", "-sL", "--fail", "--max-time", "60", "-o", tmp_bin, url],
            capture_output=True, text=True
        )
        if r.returncode == 0 and os.path.exists(tmp_bin) and os.path.getsize(tmp_bin) > 1000:
            downloaded = True
            break

    if not downloaded:
        if os.path.exists(tmp_bin):
            os.remove(tmp_bin)
        print("\033[1;33m[!]\033[0m No binary for your platform, pulling source instead...")

        if os.path.exists(os.path.join(INSTALL_DIR, ".git")):
            r = subprocess.run(["sudo", "git", "-C", INSTALL_DIR, "pull"], capture_output=True, text=True)
            if r.returncode != 0:
                r = subprocess.run(["git", "-C", INSTALL_DIR, "pull"], capture_output=True, text=True)
            subprocess.run(["pip3", "install", "--break-system-packages", INSTALL_DIR],
                           capture_output=True)
            print("\033[1;32m[+]\033[0m Source updated + reinstalled via pip")
        else:
            print("\033[1;31m[-]\033[0m Reinstall:")
            print("  curl -fsSL https://raw.githubusercontent.com/imattas/Flagr/main/install.sh | sudo bash")
        return

    install_path = _find_install_path()
    os.chmod(tmp_bin, 0o755)

    installed = False
    if os.access(os.path.dirname(install_path), os.W_OK):
        try:
            shutil.copy2(tmp_bin, install_path)
            installed = True
        except Exception:
            pass

    if not installed:
        try:
            subprocess.run(["sudo", "cp", tmp_bin, install_path], check=True)
            installed = True
        except Exception:
            pass

    if not installed:
        local_bin = os.path.expanduser("~/.local/bin")
        os.makedirs(local_bin, exist_ok=True)
        install_path = os.path.join(local_bin, "flagr")
        shutil.copy2(tmp_bin, install_path)

    os.remove(tmp_bin)

    # Also pull source if repo exists
    if os.path.exists(os.path.join(INSTALL_DIR, ".git")):
        subprocess.run(["sudo", "git", "-C", INSTALL_DIR, "pull", "-q"],
                       capture_output=True)

    print(f"\033[1;32m[+]\033[0m Updated to v{remote}")
    print(f"    Installed to {install_path}")


def main():
    args = sys.argv[1:]

    # Handle wrapper subcommands before passing to real flagr
    if args and args[0] == "update":
        cmd_update()
        return

    if args and args[0] in ("--version", "version"):
        print(f"Flagr v{_get_version()}")
        return

    # Pass through to the real flagr entry point
    from flagr.__main__ import main as flagr_main
    flagr_main()


if __name__ == "__main__":
    main()
