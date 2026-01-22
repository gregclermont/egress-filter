"""
Parse package registry URLs into Package URLs (PURLs).

Supports:
- npm (registry.npmjs.org)
- PyPI (pypi.org, files.pythonhosted.org)

PURL spec: https://github.com/package-url/purl-spec
"""

import re
from dataclasses import dataclass
from urllib.parse import unquote


@dataclass
class PackageRef:
    """A parsed package reference."""
    ecosystem: str
    name: str
    version: str | None = None

    @property
    def purl(self) -> str:
        """Return the PURL string."""
        # Handle scoped npm packages: @scope/name -> %40scope/name
        name = self.name
        if name.startswith("@"):
            name = "%40" + name[1:]

        if self.version:
            return f"pkg:{self.ecosystem}/{name}@{self.version}"
        return f"pkg:{self.ecosystem}/{name}"


def parse_npm_url(url: str) -> PackageRef | None:
    """
    Parse npm registry URLs into PackageRef.

    Supported formats:
    - https://registry.npmjs.org/{package}
    - https://registry.npmjs.org/{package}/-/{package}-{version}.tgz
    - https://registry.npmjs.org/@{scope}/{package}/-/{package}-{version}.tgz
    """
    # Tarball URL with version: /{name}/-/{name}-{version}.tgz
    # Scoped: /@{scope}/{name}/-/{name}-{version}.tgz
    tarball_match = re.search(
        r'registry\.npmjs\.org/(@[^/]+/[^/]+|[^/@][^/]*)'
        r'/-/[^/]+-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)\.tgz',
        url
    )
    if tarball_match:
        name = unquote(tarball_match.group(1))
        version = tarball_match.group(2)
        return PackageRef(ecosystem="npm", name=name, version=version)

    # Metadata URL: /{name} or /@{scope}/{name}
    metadata_match = re.search(
        r'registry\.npmjs\.org/(@[^/]+/[^/]+|[^/@][^/]*)(?:/)?$',
        url
    )
    if metadata_match:
        name = unquote(metadata_match.group(1))
        return PackageRef(ecosystem="npm", name=name)

    return None


def parse_pypi_url(url: str) -> PackageRef | None:
    """
    Parse PyPI URLs into PackageRef.

    Supported formats:
    - https://pypi.org/simple/{package}/
    - https://files.pythonhosted.org/packages/.../package-version.tar.gz
    - https://files.pythonhosted.org/packages/.../package-version-py3-none-any.whl
    """
    # Simple index URL
    simple_match = re.search(r'pypi\.org/simple/([^/]+)', url)
    if simple_match:
        name = unquote(simple_match.group(1)).lower().replace("_", "-")
        return PackageRef(ecosystem="pypi", name=name)

    # Source distribution (.tar.gz)
    sdist_match = re.search(
        r'files\.pythonhosted\.org/packages/[^/]+/[^/]+/[^/]+/'
        r'([a-zA-Z0-9_-]+)-(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.]+)?)\.tar\.gz',
        url
    )
    if sdist_match:
        name = sdist_match.group(1).lower().replace("_", "-")
        version = sdist_match.group(2)
        return PackageRef(ecosystem="pypi", name=name, version=version)

    # Wheel (.whl): {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
    wheel_match = re.search(
        r'files\.pythonhosted\.org/packages/[^/]+/[^/]+/[^/]+/'
        r'([a-zA-Z0-9_-]+)-(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.]+)?)-',
        url
    )
    if wheel_match:
        name = wheel_match.group(1).lower().replace("_", "-")
        version = wheel_match.group(2)
        return PackageRef(ecosystem="pypi", name=name, version=version)

    return None


# Registry parsers in order of precedence
_PARSERS = [
    parse_npm_url,
    parse_pypi_url,
]


def parse_registry_url(url: str) -> PackageRef | None:
    """
    Parse a package registry URL into a PackageRef.

    Returns None if the URL doesn't match any known registry format.
    """
    for parser in _PARSERS:
        result = parser(url)
        if result:
            return result
    return None


if __name__ == "__main__":
    # Test cases
    test_urls = [
        # npm
        "https://registry.npmjs.org/is-odd",
        "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz",
        "https://registry.npmjs.org/@babel/core/-/core-7.23.0.tgz",
        "https://registry.npmjs.org/@types/node",
        # PyPI
        "https://pypi.org/simple/requests/",
        "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0.tar.gz",
        "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0-py3-none-any.whl",
        # Non-registry
        "https://example.com/foo",
    ]

    for url in test_urls:
        ref = parse_registry_url(url)
        if ref:
            print(f"{url}\n  -> {ref.purl}\n")
        else:
            print(f"{url}\n  -> (not a registry URL)\n")
