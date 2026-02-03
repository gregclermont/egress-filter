#!/usr/bin/env python3
"""Generate deps.sha256 manifest from package names.

Resolves latest versions for the current platform and computes SHA256 hashes.
Run on the target platform (e.g., Ubuntu 24.04 GitHub runner) to get correct versions.

Usage:
    python3 generate-deps.py > deps.sha256
"""

import hashlib
import re
import subprocess
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
    # Output format: 'URL' filename size HASH_TYPE:hash
    # URL can be direct (http://...) or mirror+file:/etc/apt/apt-mirrors.txt/pool/...
    line = result.stdout.strip()
    match = re.match(r"'([^']+)'\s+(\S+)\s+\d+\s+(\w+):(\w+)", line)
    if not match:
        raise RuntimeError(f"Failed to parse apt output for {package}: {line}")

    raw_url, filename, hash_type, hash_value = match.groups()

    # Handle mirror+file: URLs (used on GitHub runners)
    if raw_url.startswith("mirror+file:"):
        # Extract pool path: mirror+file:/etc/apt/apt-mirrors.txt/pool/main/...
        pool_match = re.search(r"(/pool/.+)$", raw_url)
        if not pool_match:
            raise RuntimeError(f"Cannot extract pool path from {raw_url}")
        pool_path = pool_match.group(1)
        url = f"https://archive.ubuntu.com/ubuntu{pool_path}"
    else:
        url = raw_url.replace("http://", "https://")

    # Always compute SHA256 ourselves (apt may provide SHA512)
    sha256 = fetch_and_hash(url)
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
    entries = generate_manifest()
    manifest = format_manifest(entries)
    print(manifest, end="")


if __name__ == "__main__":
    main()
