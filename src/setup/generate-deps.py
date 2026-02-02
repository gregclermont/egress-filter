#!/usr/bin/env python3
"""Generate deps.sha256 manifest from package names.

Resolves latest versions for the current platform and computes SHA256 hashes.
Run on the target platform (e.g., Ubuntu 24.04 GitHub runner) to get correct versions.

Usage:
    ./generate-deps.py > deps.sha256
    ./generate-deps.py --check deps.sha256  # exits non-zero if manifest would change
"""

import argparse
import hashlib
import re
import subprocess
import sys
import urllib.request

# Packages to install via apt
APT_PACKAGES = [
    "libnfnetlink-dev",
    "libnetfilter-queue1",
    "libnetfilter-queue-dev",
]

# GitHub releases to fetch install scripts from
# Format: (owner, repo, asset_pattern)
GITHUB_INSTALL_SCRIPTS = [
    ("astral-sh", "uv", "install.sh"),
]


def get_apt_package_info(package: str) -> tuple[str, str]:
    """Get download URL and SHA256 for an apt package."""
    result = subprocess.run(
        ["apt-get", "download", "--print-uris", package],
        capture_output=True,
        text=True,
        check=True,
    )
    # Output format: 'URL' filename size SHA256:hash
    match = re.match(r"'([^']+)'\s+\S+\s+\d+\s+SHA256:(\w+)", result.stdout.strip())
    if not match:
        raise RuntimeError(f"Failed to parse apt output for {package}: {result.stdout}")

    url, sha256 = match.groups()
    # Convert http to https
    url = url.replace("http://", "https://")
    return url, sha256


def get_github_latest_release(owner: str, repo: str) -> str:
    """Get the latest release tag from GitHub."""
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
    with urllib.request.urlopen(req) as resp:
        import json
        data = json.load(resp)
        return data["tag_name"]


def fetch_and_hash(url: str) -> str:
    """Download a URL and return its SHA256 hash."""
    with urllib.request.urlopen(url) as resp:
        content = resp.read()
        return hashlib.sha256(content).hexdigest()


def generate_manifest() -> list[tuple[str, str, str]]:
    """Generate manifest entries. Returns list of (comment, sha256, url)."""
    entries = []

    # APT packages
    entries.append(("# System packages", "", ""))
    for package in APT_PACKAGES:
        url, sha256 = get_apt_package_info(package)
        entries.append(("", sha256, url))

    # GitHub install scripts
    entries.append(("", "", ""))
    entries.append(("# Installers", "", ""))
    for owner, repo, asset in GITHUB_INSTALL_SCRIPTS:
        version = get_github_latest_release(owner, repo)
        url = f"https://astral.sh/{repo}/{version}/install.sh"
        sha256 = fetch_and_hash(url)
        entries.append(("", sha256, url))

    return entries


def format_manifest(entries: list[tuple[str, str, str]]) -> str:
    """Format manifest entries as text."""
    lines = ["# Dependencies manifest with SHA256 verification", ""]
    for comment, sha256, url in entries:
        if comment:
            lines.append(comment)
        elif sha256 and url:
            lines.append(f"{sha256}  {url}")
        else:
            lines.append("")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        metavar="FILE",
        help="Check if FILE matches what would be generated (exit 1 if different)",
    )
    args = parser.parse_args()

    entries = generate_manifest()
    manifest = format_manifest(entries)

    if args.check:
        with open(args.check) as f:
            existing = f.read()
        if existing != manifest:
            print(f"Manifest {args.check} is out of date.", file=sys.stderr)
            print("Run ./generate-deps.py > deps.sha256 to update.", file=sys.stderr)
            print("\nDiff:", file=sys.stderr)
            import difflib
            diff = difflib.unified_diff(
                existing.splitlines(keepends=True),
                manifest.splitlines(keepends=True),
                fromfile=args.check,
                tofile="(generated)",
            )
            sys.stderr.writelines(diff)
            sys.exit(1)
        print(f"Manifest {args.check} is up to date.")
    else:
        print(manifest, end="")


if __name__ == "__main__":
    main()
