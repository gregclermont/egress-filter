"""Tests for runc_wrapper (src/runc_wrapper.py)."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from runc_wrapper import inject_ca_cert, parse_runc_args


# ---------------------------------------------------------------------------
# parse_runc_args
# ---------------------------------------------------------------------------

class TestParseRuncArgs:
    def test_create_with_bundle(self):
        cmd, bundle = parse_runc_args(["create", "--bundle", "/run/bundle"])
        assert cmd == "create"
        assert bundle == "/run/bundle"

    def test_run_with_bundle(self):
        cmd, bundle = parse_runc_args(["run", "--bundle", "/run/bundle"])
        assert cmd == "run"
        assert bundle == "/run/bundle"

    def test_bundle_equals_syntax(self):
        cmd, bundle = parse_runc_args(["create", "--bundle=/run/bundle"])
        assert cmd == "create"
        assert bundle == "/run/bundle"

    def test_short_flag(self):
        cmd, bundle = parse_runc_args(["create", "-b", "/run/bundle"])
        assert cmd == "create"
        assert bundle == "/run/bundle"

    def test_global_flags_before_subcommand(self):
        cmd, bundle = parse_runc_args([
            "--root", "/var/run/runc",
            "--log", "/tmp/runc.log",
            "create",
            "--bundle", "/run/bundle",
        ])
        assert cmd == "create"
        assert bundle == "/run/bundle"

    def test_boolean_flags(self):
        cmd, bundle = parse_runc_args([
            "--debug",
            "create",
            "--bundle", "/run/bundle",
            "--no-pivot",
        ])
        assert cmd == "create"
        assert bundle == "/run/bundle"

    def test_no_bundle(self):
        cmd, bundle = parse_runc_args(["list"])
        assert cmd == "list"
        assert bundle is None

    def test_no_subcommand(self):
        cmd, bundle = parse_runc_args(["--help"])
        assert cmd is None
        assert bundle is None

    def test_empty_args(self):
        cmd, bundle = parse_runc_args([])
        assert cmd is None
        assert bundle is None

    def test_delete_subcommand(self):
        cmd, bundle = parse_runc_args(["delete", "container-id"])
        assert cmd == "delete"
        assert bundle is None

    def test_container_id_not_confused_for_bundle(self):
        """Container ID after subcommand shouldn't be treated as bundle."""
        cmd, bundle = parse_runc_args(["create", "--bundle", "/b", "my-container"])
        assert cmd == "create"
        assert bundle == "/b"

    def test_console_socket_flag_skips_value(self):
        cmd, bundle = parse_runc_args([
            "create",
            "--console-socket", "/run/console.sock",
            "--bundle", "/run/bundle",
        ])
        assert cmd == "create"
        assert bundle == "/run/bundle"

    def test_pid_file_flag_skips_value(self):
        cmd, bundle = parse_runc_args([
            "create",
            "--pid-file", "/run/container.pid",
            "--bundle", "/run/bundle",
        ])
        assert cmd == "create"
        assert bundle == "/run/bundle"

    def test_preserve_fds_flag_skips_value(self):
        cmd, bundle = parse_runc_args([
            "run",
            "--preserve-fds", "2",
            "--bundle", "/run/bundle",
        ])
        assert cmd == "run"
        assert bundle == "/run/bundle"

    def test_log_format_equals_syntax(self):
        cmd, bundle = parse_runc_args([
            "--log-format=json",
            "create",
            "--bundle", "/run/bundle",
        ])
        assert cmd == "create"
        assert bundle == "/run/bundle"


# ---------------------------------------------------------------------------
# inject_ca_cert
# ---------------------------------------------------------------------------

FAKE_CERT = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n"


@pytest.fixture
def bundle_dir(tmp_path):
    """Create a minimal OCI bundle directory for testing."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "tmp").mkdir()

    config = {
        "root": {"path": "rootfs"},
        "process": {
            "env": ["PATH=/usr/bin:/bin", "HOME=/root"],
        },
    }
    (tmp_path / "config.json").write_text(json.dumps(config))

    return tmp_path


@pytest.fixture
def ca_cert_file(tmp_path):
    """Create a fake CA cert file and patch the module constant."""
    cert = tmp_path / "ca-cert.pem"
    cert.write_text(FAKE_CERT)
    with patch("runc_wrapper.CA_CERT_FILE", str(cert)):
        yield cert


def _get_mount(config, destination):
    """Helper: find a mount entry by destination path."""
    for m in config.get("mounts", []):
        if m["destination"] == destination:
            return m
    return None


class TestInjectCaCert:
    def test_bind_mounts_cert_into_container(self, bundle_dir, ca_cert_file):
        inject_ca_cert(str(bundle_dir))

        config = json.loads((bundle_dir / "config.json").read_text())
        mount = _get_mount(config, "/tmp/mitmproxy-ca-cert.pem")
        assert mount is not None
        assert mount["type"] == "bind"
        assert mount["source"] == str(ca_cert_file)
        assert "ro" in mount["options"]

    def test_does_not_modify_rootfs(self, bundle_dir, ca_cert_file):
        """Bind mount approach must never write into the rootfs."""
        rootfs = bundle_dir / "rootfs"
        before = set(rootfs.rglob("*"))

        inject_ca_cert(str(bundle_dir))

        after = set(rootfs.rglob("*"))
        assert before == after, f"Rootfs was modified: new files {after - before}"

    def test_creates_merged_debian_ca_bundle(self, bundle_dir, ca_cert_file):
        ca_dir = bundle_dir / "rootfs" / "etc" / "ssl" / "certs"
        ca_dir.mkdir(parents=True)
        bundle_file = ca_dir / "ca-certificates.crt"
        bundle_file.write_text("EXISTING CERTS\n")

        inject_ca_cert(str(bundle_dir))

        # Original rootfs file is untouched
        assert bundle_file.read_text() == "EXISTING CERTS\n"

        # Merged file created in bundle dir
        merged = bundle_dir / ".egress-ca-etc_ssl_certs_ca-certificates.crt"
        assert merged.exists()
        content = merged.read_text()
        assert "EXISTING CERTS" in content
        assert "FAKECERT" in content

        # Bind mount configured
        config = json.loads((bundle_dir / "config.json").read_text())
        mount = _get_mount(config, "/etc/ssl/certs/ca-certificates.crt")
        assert mount is not None
        assert mount["source"] == str(merged)
        assert "ro" in mount["options"]

    def test_creates_merged_rhel_ca_bundle(self, bundle_dir, ca_cert_file):
        ca_dir = bundle_dir / "rootfs" / "etc" / "pki" / "tls" / "certs"
        ca_dir.mkdir(parents=True)
        bundle_file = ca_dir / "ca-bundle.crt"
        bundle_file.write_text("EXISTING CERTS\n")

        inject_ca_cert(str(bundle_dir))

        # Original rootfs file is untouched
        assert bundle_file.read_text() == "EXISTING CERTS\n"

        # Merged file exists and has both contents
        merged = bundle_dir / ".egress-ca-etc_pki_tls_certs_ca-bundle.crt"
        content = merged.read_text()
        assert "EXISTING CERTS" in content
        assert "FAKECERT" in content

    def test_merged_bundle_permissions(self, bundle_dir, ca_cert_file):
        ca_dir = bundle_dir / "rootfs" / "etc" / "ssl" / "certs"
        ca_dir.mkdir(parents=True)
        (ca_dir / "ca-certificates.crt").write_text("EXISTING CERTS\n")

        inject_ca_cert(str(bundle_dir))

        merged = bundle_dir / ".egress-ca-etc_ssl_certs_ca-certificates.crt"
        assert oct(merged.stat().st_mode & 0o777) == oct(0o444)

    def test_env_vars_use_system_bundle_when_present(self, bundle_dir, ca_cert_file):
        """Replacing env vars point to system CA bundle path."""
        ca_dir = bundle_dir / "rootfs" / "etc" / "ssl" / "certs"
        ca_dir.mkdir(parents=True)
        (ca_dir / "ca-certificates.crt").write_text("EXISTING CERTS\n")

        inject_ca_cert(str(bundle_dir))

        config = json.loads((bundle_dir / "config.json").read_text())
        env = config["process"]["env"]

        assert "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" in env
        assert "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" in env
        assert "REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt" in env
        assert "AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt" in env
        assert "HEX_CACERTS_PATH=/etc/ssl/certs/ca-certificates.crt" in env

    def test_env_vars_fallback_without_system_bundle(self, bundle_dir, ca_cert_file):
        """Distroless images with no system CA bundle fall back to standalone cert."""
        inject_ca_cert(str(bundle_dir))

        config = json.loads((bundle_dir / "config.json").read_text())
        env = config["process"]["env"]

        assert "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" in env
        assert "SSL_CERT_FILE=/tmp/mitmproxy-ca-cert.pem" in env
        assert "REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" in env
        assert "AWS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" in env
        assert "HEX_CACERTS_PATH=/tmp/mitmproxy-ca-cert.pem" in env

    def test_preserves_existing_env(self, bundle_dir, ca_cert_file):
        inject_ca_cert(str(bundle_dir))

        config = json.loads((bundle_dir / "config.json").read_text())
        env = config["process"]["env"]

        assert "PATH=/usr/bin:/bin" in env
        assert "HOME=/root" in env

    def test_does_not_override_existing_env_vars(self, bundle_dir, ca_cert_file):
        # Pre-set NODE_EXTRA_CA_CERTS in the config
        config = json.loads((bundle_dir / "config.json").read_text())
        config["process"]["env"].append("NODE_EXTRA_CA_CERTS=/custom/cert.pem")
        (bundle_dir / "config.json").write_text(json.dumps(config))

        inject_ca_cert(str(bundle_dir))

        config = json.loads((bundle_dir / "config.json").read_text())
        env = config["process"]["env"]

        # Should keep the original, not add a duplicate
        node_entries = [e for e in env if e.startswith("NODE_EXTRA_CA_CERTS=")]
        assert len(node_entries) == 1
        assert node_entries[0] == "NODE_EXTRA_CA_CERTS=/custom/cert.pem"

    def test_warns_on_skipped_env_vars(self, bundle_dir, ca_cert_file, capsys):
        """Pre-set env vars produce a stderr warning with container context."""
        config = json.loads((bundle_dir / "config.json").read_text())
        config["process"]["env"].append("NODE_EXTRA_CA_CERTS=/custom/cert.pem")
        config["process"]["args"] = ["node", "app.js"]
        (bundle_dir / "config.json").write_text(json.dumps(config))

        with patch("runc_wrapper._lookup_container_image", return_value="node:18-alpine"):
            inject_ca_cert(str(bundle_dir))

        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "NODE_EXTRA_CA_CERTS" in err
        assert "image=node:18-alpine" in err
        assert "node" in err  # from process args

    def test_warns_falls_back_to_bundle_path(self, bundle_dir, ca_cert_file, capsys):
        """Warning falls back to bundle path when image lookup fails."""
        config = json.loads((bundle_dir / "config.json").read_text())
        config["process"]["env"].append("SSL_CERT_FILE=/custom/ca.pem")
        (bundle_dir / "config.json").write_text(json.dumps(config))

        with patch("runc_wrapper._lookup_container_image", return_value=None):
            inject_ca_cert(str(bundle_dir))

        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "SSL_CERT_FILE" in err
        assert f"bundle={bundle_dir}" in err

    def test_handles_absolute_rootfs_path(self, bundle_dir, ca_cert_file):
        rootfs = bundle_dir / "rootfs"
        config = json.loads((bundle_dir / "config.json").read_text())
        config["root"]["path"] = str(rootfs)
        (bundle_dir / "config.json").write_text(json.dumps(config))

        inject_ca_cert(str(bundle_dir))

        # Cert mount is present (no rootfs copy to check)
        config = json.loads((bundle_dir / "config.json").read_text())
        mount = _get_mount(config, "/tmp/mitmproxy-ca-cert.pem")
        assert mount is not None

    def test_no_ca_bundle_in_rootfs(self, bundle_dir, ca_cert_file):
        """Injection succeeds even if no system CA bundle exists (e.g., distroless)."""
        inject_ca_cert(str(bundle_dir))

        # Cert bind mount present
        config = json.loads((bundle_dir / "config.json").read_text())
        mount = _get_mount(config, "/tmp/mitmproxy-ca-cert.pem")
        assert mount is not None

        # Env vars are still injected
        env = config["process"]["env"]
        assert "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" in env

    def test_preserves_existing_mounts(self, bundle_dir, ca_cert_file):
        """Pre-existing mounts in config.json are preserved."""
        config = json.loads((bundle_dir / "config.json").read_text())
        config["mounts"] = [{"destination": "/dev", "type": "tmpfs", "source": "tmpfs"}]
        (bundle_dir / "config.json").write_text(json.dumps(config))

        inject_ca_cert(str(bundle_dir))

        config = json.loads((bundle_dir / "config.json").read_text())
        assert _get_mount(config, "/dev") is not None
        assert _get_mount(config, "/tmp/mitmproxy-ca-cert.pem") is not None

    def test_config_written_atomically(self, bundle_dir, ca_cert_file):
        """Config is written via rename, so no .tmp file should remain."""
        inject_ca_cert(str(bundle_dir))

        assert not (bundle_dir / "config.json.tmp").exists()
        assert (bundle_dir / "config.json").exists()

    def test_handles_missing_process_env(self, bundle_dir, ca_cert_file):
        """Config without process.env should still work."""
        config = {"root": {"path": "rootfs"}, "process": {}}
        (bundle_dir / "config.json").write_text(json.dumps(config))

        inject_ca_cert(str(bundle_dir))

        config = json.loads((bundle_dir / "config.json").read_text())
        assert "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" in config["process"]["env"]

    def test_multiple_ca_bundles(self, bundle_dir, ca_cert_file):
        """Alpine images may have both /etc/ssl/certs/ca-certificates.crt and /etc/ssl/cert.pem."""
        # Create two bundle paths
        ca_dir1 = bundle_dir / "rootfs" / "etc" / "ssl" / "certs"
        ca_dir1.mkdir(parents=True)
        (ca_dir1 / "ca-certificates.crt").write_text("DEBIAN CERTS\n")

        cert_pem = bundle_dir / "rootfs" / "etc" / "ssl" / "cert.pem"
        cert_pem.write_text("ALPINE CERTS\n")

        inject_ca_cert(str(bundle_dir))

        config = json.loads((bundle_dir / "config.json").read_text())

        # Both get bind mounts
        assert _get_mount(config, "/etc/ssl/certs/ca-certificates.crt") is not None
        assert _get_mount(config, "/etc/ssl/cert.pem") is not None

        # First found is used for env vars (Debian path comes first in CA_BUNDLE_PATHS)
        env = config["process"]["env"]
        assert "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" in env
