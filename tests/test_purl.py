"""Tests for proxy.purl — registry URL → PURL parsing."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.purl import PackageRef, parse_registry_url


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url, expected", [
    # Unscoped package
    (
        "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
        PackageRef("npm", "express", "4.18.2"),
    ),
    # Scoped package
    (
        "https://registry.npmjs.org/@babel/core/-/core-7.23.0.tgz",
        PackageRef("npm", "@babel/core", "7.23.0"),
    ),
    # Pre-release version
    (
        "https://registry.npmjs.org/next/-/next-14.0.0-canary.1.tgz",
        PackageRef("npm", "next", "14.0.0-canary.1"),
    ),
])
def test_npm(url, expected):
    assert parse_registry_url(url) == expected


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url, expected", [
    # sdist tar.gz
    (
        "https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz",
        PackageRef("pypi", "requests", "2.31.0"),
    ),
    # sdist zip
    (
        "https://files.pythonhosted.org/packages/ab/cd/setuptools-69.0.0.zip",
        PackageRef("pypi", "setuptools", "69.0.0"),
    ),
    # wheel
    (
        "https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl",
        PackageRef("pypi", "requests", "2.31.0"),
    ),
    # PEP 503 normalization: underscores → hyphens
    (
        "https://files.pythonhosted.org/packages/ab/cd/my_cool_package-1.0.0.tar.gz",
        PackageRef("pypi", "my-cool-package", "1.0.0"),
    ),
    # PEP 503 normalization: dots → hyphens
    (
        "https://files.pythonhosted.org/packages/ab/cd/some.dotted.name-2.0.tar.gz",
        PackageRef("pypi", "some-dotted-name", "2.0"),
    ),
    # PEP 503 normalization: mixed separators
    (
        "https://files.pythonhosted.org/packages/ab/cd/Weird__Name..Thing-3.0.tar.gz",
        PackageRef("pypi", "weird-name-thing", "3.0"),
    ),
    # PEP 503 normalization in wheel filenames
    (
        "https://files.pythonhosted.org/packages/ab/cd/my_package-1.2.3-cp311-cp311-linux_x86_64.whl",
        PackageRef("pypi", "my-package", "1.2.3"),
    ),
    # Uppercase → lowercase
    (
        "https://files.pythonhosted.org/packages/ab/cd/Flask-2.3.0.tar.gz",
        PackageRef("pypi", "flask", "2.3.0"),
    ),
])
def test_pypi(url, expected):
    assert parse_registry_url(url) == expected


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url, expected", [
    # crates.io
    (
        "https://crates.io/api/v1/crates/serde/1.0.193/download",
        PackageRef("cargo", "serde", "1.0.193"),
    ),
    # static.crates.io (CDN)
    (
        "https://static.crates.io/api/v1/crates/tokio/1.34.0/download",
        PackageRef("cargo", "tokio", "1.34.0"),
    ),
    # Pre-release
    (
        "https://crates.io/api/v1/crates/my-crate/0.1.0-alpha.1/download",
        PackageRef("cargo", "my-crate", "0.1.0-alpha.1"),
    ),
])
def test_cargo(url, expected):
    assert parse_registry_url(url) == expected


# ---------------------------------------------------------------------------
# Non-matching URLs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://example.com/foo/bar",
    "https://registry.npmjs.org/@scope/pkg",  # metadata, not download
    "https://files.pythonhosted.org/packages/ab/cd/readme.txt",
    "https://github.com/owner/repo/archive/v1.0.tar.gz",
    "",
])
def test_no_match(url):
    assert parse_registry_url(url) is None


# ---------------------------------------------------------------------------
# PackageRef.purl
# ---------------------------------------------------------------------------

def test_purl_property():
    ref = PackageRef("npm", "@babel/core", "7.23.0")
    assert ref.purl == "pkg:npm/@babel/core@7.23.0"

def test_purl_property_pypi():
    ref = PackageRef("pypi", "requests", "2.31.0")
    assert ref.purl == "pkg:pypi/requests@2.31.0"
