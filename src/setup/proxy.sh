#!/bin/bash
# Setup transparent proxy with BPF PID tracking (GitHub Actions only)
#
# Usage: proxy.sh install-deps|start|stop
#
# Must run as root.

set -e

[[ $EUID -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }

SCRIPT_DIR="$(dirname "$0")"
# Use EGRESS_FILTER_ROOT if set (from action), otherwise calculate from script location
REPO_ROOT="${EGRESS_FILTER_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

# Download files and verify SHA256 hashes
# Usage: fetch_verified <manifest_file> <output_dir>
fetch_verified() {
    local manifest="$1" output_dir="$2"
    local urls=()

    while read -r hash url; do
        [[ "$hash" =~ ^#.*$ || -z "$hash" ]] && continue
        local filename="${url##*/}"
        urls+=(-o "$output_dir/$filename" "$url")
    done < "$manifest"

    curl -fsSL --parallel --parallel-immediate "${urls[@]}"

    # Verify checksums
    while read -r hash url; do
        [[ "$hash" =~ ^#.*$ || -z "$hash" ]] && continue
        local filename="${url##*/}"
        echo "$hash  $output_dir/$filename"
    done < "$manifest" | sha256sum -c --quiet
}

install_deps() {
    # Check Ubuntu version
    source /etc/os-release
    if [[ "$VERSION_ID" != "24.04" ]]; then
        echo "::error::Expected Ubuntu 24.04, got $VERSION_ID"
        exit 1
    fi

    # Download and verify all dependencies
    fetch_verified "$SCRIPT_DIR/deps.sha256" /tmp

    # Install system packages
    dpkg -i /tmp/*.deb >/dev/null

    # Install uv if not present
    if ! command -v uv &>/dev/null; then
        UV_PRINT_QUIET=1 sh /tmp/install.sh
        export PATH="/root/.local/bin:$PATH"
    fi

    # Install Python dependencies
    cd "$REPO_ROOT"
    uv sync --quiet --extra proxy
}

PIDFILE="/tmp/proxy.pid"
SUPERVISOR_PIDFILE="/tmp/supervisor.pid"
SCOPE_NAME="egress-filter-proxy"

start_proxy() {
    cd "$REPO_ROOT"

    # Protect policy file from modification by workflow code.
    # File is created by pre.js (runner user) but proxy runs as root.
    # Without this, attacker could modify policy and crash proxy to reload it.
    if [ -n "$EGRESS_POLICY_FILE" ] && [ -f "$EGRESS_POLICY_FILE" ]; then
        chown root:root "$EGRESS_POLICY_FILE"
    fi

    # Cleanup iptables on failure to avoid breaking runner communication
    trap '"$SCRIPT_DIR"/iptables.sh cleanup' ERR

    # Block network namespace creation to prevent iptables bypass.
    #
    # Without this, an attacker could run:
    #   unshare --user --net bash -c "curl https://malicious.com"
    # The new network namespace has no iptables rules, completely bypassing our proxy.
    #
    # Setting unprivileged_userns_clone=0 blocks unprivileged users from creating
    # user namespaces (which are needed to create other namespaces without root).
    # This does NOT affect Docker (daemon runs as root with CAP_SYS_ADMIN).
    #
    # Combined with disabling sudo (planned), this blocks ALL netns creation:
    # - Unprivileged: blocked by this sysctl
    # - Privileged: requires sudo which will be disabled
    sysctl -w kernel.unprivileged_userns_clone=0 >/dev/null

    # Start supervisor in a systemd scope
    # The supervisor runs IN the scope so it keeps the cgroup alive when the
    # proxy is killed. This prevents iptables cgroup match rules from going stale.
    systemd-run --scope --unit="$SCOPE_NAME" "$SCRIPT_DIR/supervisor.sh" &
    local supervisor_pid=$!
    echo "$supervisor_pid" > "$SUPERVISOR_PIDFILE"

    # Wait for proxy to be listening (supervisor writes proxy PID to PIDFILE)
    local counter=0
    while ! ss -tln | grep -q ':8080 '; do
        sleep 0.1
        counter=$((counter+1))
        if ! kill -0 $supervisor_pid 2>/dev/null; then
            echo "Supervisor died! Output:"
            cat /tmp/proxy-stdout.log || true
            exit 1
        fi
        if [ $counter -gt 100 ]; then
            echo "Timeout waiting for proxy"
            exit 1
        fi
    done

    # Setup iptables
    "$SCRIPT_DIR"/iptables.sh setup

    # Wait for mitmproxy to generate its CA certificate (runs as root, so uses /root/.mitmproxy)
    local mitmproxy_dir="/root/.mitmproxy"
    local cert_file="$mitmproxy_dir/mitmproxy-ca-cert.pem"
    local cert_counter=0
    while [ ! -f "$cert_file" ]; do
        sleep 0.1
        cert_counter=$((cert_counter+1))
        if [ $cert_counter -gt 100 ]; then
            echo "Timeout waiting for mitmproxy CA certificate at $cert_file"
            ls -la "$mitmproxy_dir" 2>/dev/null || echo "Directory $mitmproxy_dir does not exist"
            exit 1
        fi
    done

    # Install mitmproxy certificate as system CA (direct append is much faster than update-ca-certificates)
    cat "$cert_file" >> /etc/ssl/certs/ca-certificates.crt

    # Set CA env vars for tools that don't use system store
    cp "$cert_file" /tmp/mitmproxy-ca-cert.pem
    chmod 644 /tmp/mitmproxy-ca-cert.pem

    # Set CA env vars for subsequent steps (wide CI tool support)
    # GITHUB_ENV is only available in GHA step context
    if [ -n "$GITHUB_ENV" ]; then
        echo "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
        echo "REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
        echo "AWS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
        echo "HEX_CACERTS_PATH=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
    fi

    # Sudo disable/restore is now handled by the Python proxy (control.py)
    # based on EGRESS_ALLOW_SUDO environment variable.
}

stop_proxy() {
    echo "=== stop_proxy ===" | tee -a /tmp/proxy.log

    # IMPORTANT: Clean iptables FIRST, before anything else.
    # Otherwise traffic is still redirected to port 8080 after proxy dies,
    # which breaks runner communication with GitHub (jobs appear stuck).
    "$SCRIPT_DIR"/iptables.sh cleanup 2>/dev/null || true

    # Signal supervisor to shut down (it forwards SIGTERM to proxy)
    if [ -f "$SUPERVISOR_PIDFILE" ]; then
        kill -TERM "$(cat "$SUPERVISOR_PIDFILE")" 2>/dev/null || true
        rm -f "$SUPERVISOR_PIDFILE"
    fi
    rm -f "$PIDFILE"

    # Scope stop force-kills anything remaining
    systemctl stop "$SCOPE_NAME.scope" 2>/dev/null || true

    echo "Proxy stopped" | tee -a /tmp/proxy.log
}

case "${1:-}" in
    install-deps)
        install_deps
        ;;
    start)
        start_proxy
        ;;
    stop)
        stop_proxy
        ;;
    *)
        echo "Usage: $0 install-deps|start|stop" >&2
        exit 1
        ;;
esac
