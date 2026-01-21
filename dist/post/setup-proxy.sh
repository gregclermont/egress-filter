#!/bin/bash
# Setup transparent proxy with BPF PID tracking (GitHub Actions only)
#
# Usage: setup-proxy.sh install-deps|start|stop
#
# Must run as root.

set -e

[[ $EUID -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }

SCRIPT_DIR="$(dirname "$0")"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

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
    dpkg -i /tmp/libnfnetlink-dev.deb /tmp/libnetfilter-queue1.deb /tmp/libnetfilter-queue-dev.deb

    # Install uv if not present
    if ! command -v uv &>/dev/null; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
    fi

    # Install Python dependencies
    cd "$REPO_ROOT"
    uv sync
}

start_proxy() {
    cd "$REPO_ROOT"

    # Cleanup iptables on failure to avoid breaking runner communication
    trap '"$SCRIPT_DIR"/iptables.sh cleanup' ERR

    # Start unified proxy (exclude root's traffic via iptables to prevent loops)
    env PROXY_LOG_FILE=/tmp/proxy.log \
        "$REPO_ROOT"/.venv/bin/python unified_proxy.py > /tmp/proxy-stdout.log 2>&1 &
    local proxy_pid=$!

    # Wait for proxy to be listening
    local counter=0
    while ! ss -tln | grep -q ':8080 '; do
        sleep 1
        counter=$((counter+1))
        if ! kill -0 $proxy_pid 2>/dev/null; then
            echo "Proxy process died! Output:"
            cat /tmp/proxy-stdout.log || true
            exit 1
        fi
        if [ $counter -gt 10 ]; then
            echo "Timeout waiting for proxy"
            exit 1
        fi
    done

    # Setup iptables
    "$SCRIPT_DIR"/iptables.sh setup

    # Install mitmproxy certificate as system CA
    mkdir -p /usr/local/share/ca-certificates/extra
    openssl x509 -in /root/.mitmproxy/mitmproxy-ca-cert.pem -inform PEM -out /tmp/mitmproxy-ca-cert.crt 2>/dev/null
    cp /tmp/mitmproxy-ca-cert.crt /usr/local/share/ca-certificates/extra/mitmproxy-ca-cert.crt
    dpkg-reconfigure -p critical ca-certificates >/dev/null 2>&1
    update-ca-certificates >/dev/null 2>&1

    # Set CA env vars for tools that don't use system store
    cp /root/.mitmproxy/mitmproxy-ca-cert.pem /tmp/mitmproxy-ca-cert.pem
    chmod 644 /tmp/mitmproxy-ca-cert.pem

    # Set CA env vars for subsequent steps
    echo "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
    echo "REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
}

stop_proxy() {
    pkill -TERM -f "python unified_proxy.py" || true
    sleep 2
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
