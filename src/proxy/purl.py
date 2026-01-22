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
    - https://registry.npmjs.org/{package}/-/{package}-{version}.tgz
    - https://registry.npmjs.org/@{scope}/{package}/-/{package}-{version}.tgz
    - https://registry.yarnpkg.com/... (same format as npmjs.org)

    Note: Metadata URLs (without version) return None since we need a version
    to query security APIs.
    """
    # Match both npmjs.org and yarnpkg.com registries
    # Tarball URL with version: /{name}/-/{name}-{version}.tgz
    # Scoped: /@{scope}/{name}/-/{name}-{version}.tgz
    # Version can include prerelease (-beta.1) and build metadata (+build.123)
    tarball_match = re.search(
        r'registry\.(?:npmjs\.org|yarnpkg\.com)/(@[^/]+/[^/]+|[^/@][^/]*)'
        r'/-/[^/]+-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?(?:\+[a-zA-Z0-9.-]+)?)\.tgz',
        url
    )
    if tarball_match:
        name = unquote(tarball_match.group(1))
        version = tarball_match.group(2)
        return PackageRef(ecosystem="npm", name=name, version=version)

    return None


def parse_pypi_url(url: str) -> PackageRef | None:
    """
    Parse PyPI URLs into PackageRef.

    Supported formats:
    - https://files.pythonhosted.org/packages/.../package-version.tar.gz
    - https://files.pythonhosted.org/packages/.../package-version-py3-none-any.whl
    - https://pypi.org/packages/source/.../package-version.tar.gz
    - Above formats with .metadata suffix

    Note: Simple index URLs (/simple/package/) return None since we need
    a version to query security APIs.

    PEP 440 versions: 1.0, 1.0.0, 1.0a1, 1.0b1, 1.0rc1, 1.0.post1, 1.0.dev1
    """
    # Strip .metadata suffix if present
    url = re.sub(r'\.(tar\.gz|whl)\.metadata$', r'.\1', url)

    # Version pattern: major.minor[.patch][prerelease][.postN][.devN]
    # Examples: 1.0, 1.0.0, 2.0.0b1, 2.0.0rc1, 2.0.0.post1, 2.0.0.dev1, 2.0.0a1
    version_pattern = r'(\d+\.\d+(?:\.\d+)?(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?)'

    # Source distribution (.tar.gz) from files.pythonhosted.org or pypi.org
    sdist_match = re.search(
        r'(?:files\.pythonhosted\.org/packages/[^/]+/[^/]+/[^/]+|pypi\.org/packages/source/[^/]/[^/]+)/'
        r'([a-zA-Z0-9_.-]+)-' + version_pattern + r'\.tar\.gz',
        url
    )
    if sdist_match:
        # Normalize: lowercase, replace _ with - (but preserve . in names like foo.bar)
        name = sdist_match.group(1).lower().replace("_", "-")
        version = sdist_match.group(2)
        return PackageRef(ecosystem="pypi", name=name, version=version)

    # Wheel (.whl): {name}-{version}-{python}-{abi}-{platform}.whl
    wheel_match = re.search(
        r'(?:files\.pythonhosted\.org/packages/[^/]+/[^/]+/[^/]+|pypi\.org/packages/source/[^/]/[^/]+)/'
        r'([a-zA-Z0-9_.-]+)-' + version_pattern + r'-[^/]+\.whl',
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
    # Test cases from Aikido safe-chain and our own
    test_cases = [
        # npm - regular packages
        ("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "pkg:npm/lodash@4.17.21"),
        ("https://registry.npmjs.org/express/-/express-4.18.2.tgz", "pkg:npm/express@4.18.2"),
        # npm - packages with hyphens
        ("https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-1.0.0.tgz", "pkg:npm/safe-chain-test@1.0.0"),
        ("https://registry.npmjs.org/web-vitals/-/web-vitals-3.5.0.tgz", "pkg:npm/web-vitals@3.5.0"),
        # npm - prerelease versions
        ("https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.1-security.tgz", "pkg:npm/safe-chain-test@0.0.1-security"),
        ("https://registry.npmjs.org/lodash/-/lodash-5.0.0-beta.1.tgz", "pkg:npm/lodash@5.0.0-beta.1"),
        ("https://registry.npmjs.org/react/-/react-18.3.0-canary-abc123.tgz", "pkg:npm/react@18.3.0-canary-abc123"),
        # npm - scoped packages
        ("https://registry.npmjs.org/@babel/core/-/core-7.21.4.tgz", "pkg:npm/%40babel/core@7.21.4"),
        ("https://registry.npmjs.org/@types/node/-/node-20.10.5.tgz", "pkg:npm/%40types/node@20.10.5"),
        ("https://registry.npmjs.org/@angular/common/-/common-17.0.8.tgz", "pkg:npm/%40angular/common@17.0.8"),
        # npm - scoped with hyphens
        ("https://registry.npmjs.org/@safe-chain/test-package/-/test-package-2.1.0.tgz", "pkg:npm/%40safe-chain/test-package@2.1.0"),
        ("https://registry.npmjs.org/@aws-sdk/client-s3/-/client-s3-3.465.0.tgz", "pkg:npm/%40aws-sdk/client-s3@3.465.0"),
        # npm - yarn registry
        ("https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz", "pkg:npm/lodash@4.17.21"),
        ("https://registry.yarnpkg.com/@babel/core/-/core-7.21.4.tgz", "pkg:npm/%40babel/core@7.21.4"),
        # npm - complex versions with build metadata
        ("https://registry.npmjs.org/pkg/-/pkg-1.0.0-rc.1+build.123.tgz", "pkg:npm/pkg@1.0.0-rc.1+build.123"),
        # npm - metadata URLs (should return None - no version)
        ("https://registry.npmjs.org/lodash", None),

        # PyPI - source distributions
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foobar-1.2.3.tar.gz", "pkg:pypi/foobar@1.2.3"),
        ("https://pypi.org/packages/source/f/foobar/foobar-1.2.3.tar.gz", "pkg:pypi/foobar@1.2.3"),
        ("https://pypi.org/packages/source/f/foo-bar/foo-bar-0.9.0.tar.gz", "pkg:pypi/foo-bar@0.9.0"),
        # PyPI - wheels
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foo_bar-2.0.0-py3-none-any.whl", "pkg:pypi/foo-bar@2.0.0"),
        ("https://pypi.org/packages/source/f/foo_bar/foo_bar-2.0.0-py3-none-any.whl", "pkg:pypi/foo-bar@2.0.0"),
        # PyPI - metadata files
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foo_bar-2.0.0-py3-none-any.whl.metadata", "pkg:pypi/foo-bar@2.0.0"),
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foo_bar-2.0.0.tar.gz.metadata", "pkg:pypi/foo-bar@2.0.0"),
        # PyPI - dots in package names
        ("https://pypi.org/packages/source/f/foo.bar/foo.bar-1.0.0.tar.gz", "pkg:pypi/foo.bar@1.0.0"),
        # PyPI - prerelease versions (PEP 440)
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foo_bar-2.0.0b1-py3-none-any.whl", "pkg:pypi/foo-bar@2.0.0b1"),
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foo_bar-2.0.0a1-py3-none-any.whl", "pkg:pypi/foo-bar@2.0.0a1"),
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foo_bar-2.0.0rc1-py3-none-any.whl", "pkg:pypi/foo-bar@2.0.0rc1"),
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foo_bar-2.0.0.post1.tar.gz", "pkg:pypi/foo-bar@2.0.0.post1"),
        ("https://files.pythonhosted.org/packages/xx/yy/zz/foo_bar-2.0.0.dev1.tar.gz", "pkg:pypi/foo-bar@2.0.0.dev1"),
        # PyPI - simple index (should return None - no version)
        ("https://pypi.org/simple/requests/", None),
        ("https://pypi.org/project/foobar/", None),

        # Non-registry URLs
        ("https://example.com/foo", None),
    ]

    passed = 0
    failed = 0
    for url, expected in test_cases:
        ref = parse_registry_url(url)
        actual = ref.purl if ref else None
        if actual == expected:
            passed += 1
            print(f"PASS: {url}")
        else:
            failed += 1
            print(f"FAIL: {url}")
            print(f"  expected: {expected}")
            print(f"  actual:   {actual}")

    print(f"\n{passed} passed, {failed} failed")
