#!/usr/bin/python3
"""runc wrapper that injects mitmproxy CA cert into containers via bind mounts.

Intercepts runc create/run to inject the CA certificate, enabling
TLS MITM for container HTTPS traffic. Fails open: if injection
fails for any reason, runc is still executed normally.

Uses OCI bind mounts instead of rootfs modifications so that injected
certs never appear in container image layers (safe for docker build).

Standalone script — uses only Python stdlib (no venv required).
"""

import http.client
import json
import os
import re
import socket
import sys

REAL_RUNC = "/usr/bin/runc.real"
CA_CERT_FILE = "/tmp/mitmproxy-ca-cert.pem"
DOCKER_SOCKET = "/var/run/docker.sock"

# System CA bundle paths for different distros
CA_BUNDLE_PATHS = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL/CentOS/Fedora
    "/etc/ssl/cert.pem",  # Alpine alternative
]

# runc flags that consume the next argument (global + subcommand)
_VALUE_FLAGS = {
    "--root", "--log", "--log-format", "--criu",
    "--bundle", "-b",
    "--console-socket",
    "--pid-file",
    "--preserve-fds",
}


def _lookup_container_image(bundle_path):
    """Try to get the Docker image name for a container via the Docker API.

    Extracts the container ID from the bundle path (last component under
    .../moby/<id>) and queries the Docker socket. Returns None on any error.
    """
    try:
        container_id = os.path.basename(bundle_path)
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            return None
        conn = http.client.HTTPConnection("localhost")
        conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.sock.settimeout(2.0)
        conn.sock.connect(DOCKER_SOCKET)
        try:
            conn.request("GET", f"/containers/{container_id}/json")
            resp = conn.getresponse()
            if resp.status == 200:
                data = json.loads(resp.read())
                return data.get("Config", {}).get("Image")
        finally:
            conn.close()
    except Exception:
        return None


def parse_runc_args(args):
    """Parse runc arguments to find subcommand and --bundle path.

    Returns (subcommand, bundle_path).
    Either or both may be None if not found.
    """
    bundle = None
    cmd = None

    i = 0
    while i < len(args):
        arg = args[i]

        # --bundle=<path>
        if arg.startswith("--bundle="):
            bundle = arg.split("=", 1)[1]
        elif arg in ("--bundle", "-b") and i + 1 < len(args):
            bundle = args[i + 1]
            i += 1
        # Other --flag=value forms — skip
        elif arg.startswith("--") and "=" in arg:
            pass
        # Flags that consume the next argument
        elif arg in _VALUE_FLAGS and i + 1 < len(args):
            i += 1
        # Positional: first non-flag is the subcommand
        elif not arg.startswith("-") and cmd is None:
            cmd = arg

        i += 1

    return cmd, bundle


def inject_ca_cert(bundle_path):
    """Inject CA cert into container via OCI bind mounts and env vars.

    Uses bind mounts (not rootfs modifications) so that injected certs
    never appear in container image layers. This is safe for docker build.

    1. Bind-mounts the cert into /tmp/ in the container
    2. For each system CA bundle found in the rootfs, creates a merged
       copy on the host and bind-mounts it over the original
    3. Injects environment variables into config.json for runtimes
       that use env vars rather than the system store
    """
    config_path = os.path.join(bundle_path, "config.json")

    with open(config_path) as f:
        config = json.load(f)

    # Resolve rootfs path (can be relative to bundle dir)
    rootfs = config.get("root", {}).get("path", "rootfs")
    if not os.path.isabs(rootfs):
        rootfs = os.path.join(bundle_path, rootfs)

    # Read the CA cert content
    with open(CA_CERT_FILE) as f:
        ca_cert_content = f.read()

    mounts = config.setdefault("mounts", [])

    # Bind-mount the standalone cert into the container's /tmp/.
    # Read-only: container cannot tamper with the host cert file.
    mounts.append({
        "destination": "/tmp/mitmproxy-ca-cert.pem",
        "type": "bind",
        "source": os.path.abspath(CA_CERT_FILE),
        "options": ["bind", "ro"],
    })

    # For each system CA bundle that exists in the container, create a
    # merged copy (original + our cert) on the host and bind-mount it
    # over the in-container path. The merged files are placed in the
    # bundle directory, which the container runtime cleans up automatically.
    # Track the first bundle found — used for env vars below.
    system_ca_bundle = None
    for ca_path in CA_BUNDLE_PATHS:
        container_bundle = os.path.join(rootfs, ca_path.lstrip("/"))
        if os.path.isfile(container_bundle):
            # Read original bundle from rootfs (read-only, no modification)
            with open(container_bundle) as f:
                original = f.read()

            # Write merged bundle to host (in bundle dir, cleaned up by runtime)
            safe_name = ca_path.replace("/", "_").lstrip("_")
            merged_path = os.path.join(bundle_path, f".egress-ca-{safe_name}")
            with open(merged_path, "w") as f:
                f.write(original)
                if not original.endswith("\n"):
                    f.write("\n")
                f.write(ca_cert_content)
            os.chmod(merged_path, 0o444)

            # Bind-mount merged bundle over the container's original
            mounts.append({
                "destination": ca_path,
                "type": "bind",
                "source": os.path.abspath(merged_path),
                "options": ["bind", "ro"],
            })

            if system_ca_bundle is None:
                system_ca_bundle = ca_path

    # NODE_EXTRA_CA_CERTS is additive — point to standalone cert.
    # Others replace the default bundle — point to system bundle (which now
    # includes mitmproxy CA). Fall back to standalone cert for distroless images.
    ca_bundle = system_ca_bundle or "/tmp/mitmproxy-ca-cert.pem"
    env_additions = [
        "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem",
        f"SSL_CERT_FILE={ca_bundle}",
        f"REQUESTS_CA_BUNDLE={ca_bundle}",
        f"AWS_CA_BUNDLE={ca_bundle}",
        f"HEX_CACERTS_PATH={ca_bundle}",
    ]

    # Inject env vars, skipping any already set by the image/user.
    # Pre-set vars mean the container may not trust our CA cert, causing
    # HTTPS connections to fail (MITM TLS handshake rejected by client).
    process = config.setdefault("process", {})
    env = process.setdefault("env", [])
    existing_keys = {e.split("=", 1)[0] for e in env if "=" in e}

    skipped_keys = []
    for env_entry in env_additions:
        key = env_entry.split("=", 1)[0]
        if key not in existing_keys:
            env.append(env_entry)
        else:
            skipped_keys.append(key)

    if skipped_keys:
        image = _lookup_container_image(bundle_path)
        context = f"image={image}" if image else f"bundle={bundle_path}"
        process_args = process.get("args", [])
        print(
            f"runc-wrapper: WARNING: {', '.join(skipped_keys)} already set"
            f" in container config ({context}, cmd={process_args!r}),"
            " container HTTPS may fail TLS verification",
            file=sys.stderr,
        )

    # Write config atomically
    tmp_config = config_path + ".tmp"
    with open(tmp_config, "w") as f:
        json.dump(config, f, indent="\t")
    os.rename(tmp_config, config_path)


def main():
    args = sys.argv[1:]

    cmd, bundle = parse_runc_args(args)

    if cmd in ("create", "run"):
        try:
            inject_ca_cert(bundle or ".")
        except Exception as e:
            # Fail open: log the error but still exec runc
            print(f"runc-wrapper: CA injection failed: {e}", file=sys.stderr)

    os.execv(REAL_RUNC, [REAL_RUNC] + args)


if __name__ == "__main__":
    main()
