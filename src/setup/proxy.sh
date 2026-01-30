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

install_deps() {
    # Check Ubuntu version
    source /etc/os-release
    if [[ "$VERSION_ID" != "24.04" ]]; then
        echo "::error::Expected Ubuntu 24.04, got $VERSION_ID"
        exit 1
    fi

    # Install system dependencies (direct .deb download is faster than apt)
    local base=http://archive.ubuntu.com/ubuntu/pool
    curl -fsSL --parallel --parallel-immediate \
        -o /tmp/libnfnetlink-dev.deb "$base/main/libn/libnfnetlink/libnfnetlink-dev_1.0.2-2build1_amd64.deb" \
        -o /tmp/libnetfilter-queue1.deb "$base/universe/libn/libnetfilter-queue/libnetfilter-queue1_1.0.5-4build1_amd64.deb" \
        -o /tmp/libnetfilter-queue-dev.deb "$base/universe/libn/libnetfilter-queue/libnetfilter-queue-dev_1.0.5-4build1_amd64.deb"
    dpkg -i /tmp/libnfnetlink-dev.deb /tmp/libnetfilter-queue1.deb /tmp/libnetfilter-queue-dev.deb >/dev/null

    # Install uv if not present (uv installs to ~/.local/bin which is /root/.local/bin when running as root)
    if ! command -v uv &>/dev/null; then
        curl -LsSf https://astral.sh/uv/install.sh | UV_PRINT_QUIET=1 sh
        export PATH="/root/.local/bin:$PATH"
    fi

    # Install Python dependencies
    cd "$REPO_ROOT"
    uv sync --quiet
}

PIDFILE="/tmp/proxy.pid"
SCOPE_NAME="egress-filter-proxy"
SUDOERS_BACKUP="/tmp/sudoers-runner-backup"

start_proxy() {
    cd "$REPO_ROOT"

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

    # Start proxy in its own cgroup scope using systemd-run
    # This allows iptables to exclude proxy traffic by cgroup instead of UID,
    # enabling us to capture traffic from root processes (like docker --network=host)
    systemd-run --scope --unit="$SCOPE_NAME" \
        env PROXY_LOG_FILE=/tmp/proxy.log VERBOSE="${VERBOSE:-0}" PYTHONPATH="$REPO_ROOT/src" \
            EGRESS_POLICY_FILE="${EGRESS_POLICY_FILE:-}" EGRESS_AUDIT_MODE="${EGRESS_AUDIT_MODE:-0}" \
        "$REPO_ROOT"/.venv/bin/python -m proxy.main > /tmp/proxy-stdout.log 2>&1 &
    local proxy_pid=$!

    # Write pidfile for reliable shutdown
    echo "$proxy_pid" > "$PIDFILE"

    # Wait for proxy to be listening
    local counter=0
    while ! ss -tln | grep -q ':8080 '; do
        sleep 0.1
        counter=$((counter+1))
        if ! kill -0 $proxy_pid 2>/dev/null; then
            echo "Proxy process died! Output:"
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

    # Disable sudo for the runner user to prevent iptables bypass.
    #
    # Without this, an attacker could run:
    #   sudo iptables -F  # Flush all rules, bypass proxy completely
    #
    # We backup and empty the sudoers.d/runner file. The proxy (running as root)
    # restores it on shutdown via the authenticated control socket.
    #
    # This is done LAST so all setup is complete before we lose sudo.
    local sudoers_file="/etc/sudoers.d/runner"
    if [ -f "$sudoers_file" ]; then
        cp "$sudoers_file" "$SUDOERS_BACKUP"
        truncate -s 0 "$sudoers_file"
        echo "Sudo disabled for runner user"
    fi
}

stop_proxy() {
    echo "=== stop_proxy ===" | tee -a /tmp/proxy.log

    # IMPORTANT: Clean iptables FIRST, before anything else.
    # Otherwise traffic is still redirected to port 8080 after proxy dies,
    # which breaks runner communication with GitHub (jobs appear stuck).
    "$SCRIPT_DIR"/iptables.sh cleanup 2>/dev/null || true

    # Restore sudo for runner user (backup created in start_proxy)
    local sudoers_file="/etc/sudoers.d/runner"
    if [ -f "$SUDOERS_BACKUP" ]; then
        cp "$SUDOERS_BACKUP" "$sudoers_file"
        rm -f "$SUDOERS_BACKUP"
        echo "Sudo restored for runner user" | tee -a /tmp/proxy.log
    fi

    # Restore unprivileged user namespace creation (cleanup)
    sysctl -w kernel.unprivileged_userns_clone=1 >/dev/null 2>&1 || true

    # First try graceful shutdown via pidfile (allows cleanup before systemd kills the scope)
    if [ -f "$PIDFILE" ]; then
        local pid
        pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Sending SIGTERM to proxy (PID $pid)" | tee -a /tmp/proxy.log
            kill -TERM "$pid" 2>/dev/null || true

            # Wait for graceful shutdown (Python's SHUTDOWN_TIMEOUT is 3s)
            local i=0
            while kill -0 "$pid" 2>/dev/null && [ $i -lt 40 ]; do
                sleep 0.1
                i=$((i+1))
            done

            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                echo "Graceful shutdown failed, sending SIGKILL" | tee -a /tmp/proxy.log
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$PIDFILE"
    fi

    # Clean up the systemd scope if it's still running
    if systemctl is-active --quiet "$SCOPE_NAME.scope" 2>/dev/null; then
        echo "Stopping systemd scope $SCOPE_NAME.scope" | tee -a /tmp/proxy.log
        systemctl stop "$SCOPE_NAME.scope" 2>/dev/null || true
    fi

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
