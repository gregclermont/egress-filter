"""Parse package registry URLs into Package URL (PURL) identifiers."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Version pattern shared across ecosystems
_VERSION_RE = r"[\w\.\-\+]+"

# npm: /@scope/name/-/name-version.tgz or /name/-/name-version.tgz
_NPM_RE = re.compile(
    rf"^https?://registry\.npmjs\.org/(?:(@[^/]+)/)?([^/]+)/-/\2-({_VERSION_RE})\.tgz$"
)

# PyPI sdist: /packages/.../name-version.tar.gz (or .zip)
_PYPI_SDIST_RE = re.compile(
    rf"^https?://files\.pythonhosted\.org/packages/[^#]+/([^/]+)-({_VERSION_RE})\.(tar\.gz|zip)$"
)

# PyPI wheel: /packages/.../name-version-pytag-abitag-plattag.whl
# Wheel filenames have 3+ hyphen-separated tags after version, so we extract
# the filename and split on hyphens to find where the version starts (first
# segment beginning with a digit).
_PYPI_WHEEL_PREFIX = "https://files.pythonhosted.org/packages/"

# Cargo: /api/v1/crates/name/version/download
_CARGO_RE = re.compile(
    rf"^https?://(?:crates\.io|static\.crates\.io)/api/v1/crates/([^/]+)/({_VERSION_RE})/download$"
)


def _normalize_pypi_name(name: str) -> str:
    """Normalize a PyPI package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True, slots=True)
class PackageRef:
    """A reference to a specific package version."""

    ecosystem: str
    name: str
    version: str

    @property
    def purl(self) -> str:
        return f"pkg:{self.ecosystem}/{self.name}@{self.version}"


def parse_registry_url(url: str) -> PackageRef | None:
    """Try to extract a package reference from a registry download URL.

    Returns None if the URL doesn't match any known registry pattern.
    """
    # npm
    m = _NPM_RE.match(url)
    if m:
        scope, name, version = m.group(1), m.group(2), m.group(3)
        full_name = f"{scope}/{name}" if scope else name
        return PackageRef("npm", full_name, version)

    # PyPI sdist
    m = _PYPI_SDIST_RE.match(url)
    if m:
        return PackageRef("pypi", _normalize_pypi_name(m.group(1)), m.group(2))

    # PyPI wheel
    if url.startswith(_PYPI_WHEEL_PREFIX) and url.endswith(".whl"):
        filename = url.rsplit("/", 1)[-1].removesuffix(".whl")
        parts = filename.split("-")
        # Find first part starting with a digit (the version)
        for i, part in enumerate(parts):
            if i > 0 and part and part[0].isdigit():
                name = "-".join(parts[:i])
                version = part
                return PackageRef("pypi", _normalize_pypi_name(name), version)

    # Cargo
    m = _CARGO_RE.match(url)
    if m:
        return PackageRef("cargo", m.group(1), m.group(2))

    return None
