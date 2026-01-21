#!/bin/bash
# Setup transparent proxy with BPF PID tracking (GitHub Actions only)
#
# Usage: setup-proxy.sh install-deps|start|stop
#
# Must run as root.

set -e

[[ $EUID -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }

SCRIPT_DIR="$(dirname "$0")"
# Use EGRESS_FILTER_ROOT if set (from action), otherwise calculate from script location
REPO_ROOT="${EGRESS_FILTER_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

timer() {
    echo "::group::⏱ $1"
    local start=$(date +%s.%N)
    shift
    "$@"
    local end=$(date +%s.%N)
    echo "::endgroup::"
    printf "⏱ %s: %.2fs\n" "$1" "$(echo "$end - $start" | bc)"
}

install_deps() {
    local total_start=$(date +%s.%N)

    # Check Ubuntu version
    source /etc/os-release
    if [[ "$VERSION_ID" != "24.04" ]]; then
        echo "::error::Expected Ubuntu 24.04, got $VERSION_ID"
        exit 1
    fi

    # Install system dependencies (direct .deb download is faster than apt)
    local start=$(date +%s.%N)
    local base=http://archive.ubuntu.com/ubuntu/pool
    curl -fsSL --parallel --parallel-immediate \
        -o /tmp/libnfnetlink-dev.deb "$base/main/libn/libnfnetlink/libnfnetlink-dev_1.0.2-2build1_amd64.deb" \
        -o /tmp/libnetfilter-queue1.deb "$base/universe/libn/libnetfilter-queue/libnetfilter-queue1_1.0.5-4build1_amd64.deb" \
        -o /tmp/libnetfilter-queue-dev.deb "$base/universe/libn/libnetfilter-queue/libnetfilter-queue-dev_1.0.5-4build1_amd64.deb"
    dpkg -i /tmp/libnfnetlink-dev.deb /tmp/libnetfilter-queue1.deb /tmp/libnetfilter-queue-dev.deb
    printf "⏱ system-deps: %.2fs\n" "$(echo "$(date +%s.%N) - $start" | bc)"

    # Install uv if not present
    start=$(date +%s.%N)
    if ! command -v uv &>/dev/null; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
        printf "⏱ uv-install: %.2fs\n" "$(echo "$(date +%s.%N) - $start" | bc)"
    else
        printf "⏱ uv-install: skipped (already installed)\n"
    fi

    # Install Python dependencies
    start=$(date +%s.%N)
    cd "$REPO_ROOT"
    uv sync
    printf "⏱ uv-sync: %.2fs\n" "$(echo "$(date +%s.%N) - $start" | bc)"

    printf "⏱ install_deps total: %.2fs\n" "$(echo "$(date +%s.%N) - $total_start" | bc)"
}

start_proxy() {
    local total_start=$(date +%s.%N)
    cd "$REPO_ROOT"

    # Cleanup iptables on failure to avoid breaking runner communication
    trap '"$SCRIPT_DIR"/iptables.sh cleanup' ERR

    # Start proxy (exclude root's traffic via iptables to prevent loops)
    local start=$(date +%s.%N)
    env PROXY_LOG_FILE=/tmp/proxy.log VERBOSE="${VERBOSE:-0}" \
        "$REPO_ROOT"/.venv/bin/python "$REPO_ROOT/src/proxy/main.py" > /tmp/proxy-stdout.log 2>&1 &
    local proxy_pid=$!

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
    printf "⏱ proxy-start: %.2fs\n" "$(echo "$(date +%s.%N) - $start" | bc)"

    # Setup iptables
    start=$(date +%s.%N)
    "$SCRIPT_DIR"/iptables.sh setup
    printf "⏱ iptables-setup: %.2fs\n" "$(echo "$(date +%s.%N) - $start" | bc)"

    # Wait for mitmproxy to generate its CA certificate
    start=$(date +%s.%N)
    local mitmproxy_dir="$HOME/.mitmproxy"
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
    printf "⏱ ca-cert-wait: %.2fs\n" "$(echo "$(date +%s.%N) - $start" | bc)"

    # Install mitmproxy certificate as system CA (direct append is much faster than update-ca-certificates)
    start=$(date +%s.%N)
    cat "$cert_file" >> /etc/ssl/certs/ca-certificates.crt
    printf "⏱ ca-cert-install: %.2fs\n" "$(echo "$(date +%s.%N) - $start" | bc)"

    # Set CA env vars for tools that don't use system store
    cp "$cert_file" /tmp/mitmproxy-ca-cert.pem
    chmod 644 /tmp/mitmproxy-ca-cert.pem

    # Set CA env vars for subsequent steps (wide CI tool support)
    echo "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
    echo "REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
    echo "AWS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
    echo "HEX_CACERTS_PATH=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"

    printf "⏱ start_proxy total: %.2fs\n" "$(echo "$(date +%s.%N) - $total_start" | bc)"
}

stop_proxy() {
    echo "=== stop_proxy ===" | tee -a /tmp/proxy.log

    # Send SIGTERM - Python handles graceful shutdown with 3s timeout
    pkill -TERM -f "python.*src/proxy/main" 2>/dev/null || true

    # Wait for graceful shutdown (Python's SHUTDOWN_TIMEOUT is 3s)
    local i=0
    while pgrep -f "python.*src/proxy/main" >/dev/null 2>&1 && [ $i -lt 40 ]; do
        sleep 0.1
        i=$((i+1))
    done

    # Force kill if still running
    if pgrep -f "python.*src/proxy/main" >/dev/null 2>&1; then
        echo "Graceful shutdown failed, sending SIGKILL" | tee -a /tmp/proxy.log
        pkill -KILL -f "python.*src/proxy/main" 2>/dev/null || true
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
