#!/bin/bash
# Setup transparent proxy with BPF PID tracking
#
# This script:
# 1. Starts unified_proxy.py (mitmproxy + nfqueue)
# 2. Configures iptables to redirect traffic through the proxy
# 3. Installs mitmproxy CA certificate system-wide
#
# Requirements:
# - Must run as root (for BPF and iptables)
# - unified_proxy.py must be in current directory
# - .venv with dependencies must exist

set -e

# Cleanup iptables on failure to avoid breaking runner communication
cleanup() {
    sudo iptables -t mangle -F 2>/dev/null || true
    sudo iptables -t nat -F 2>/dev/null || true
    sudo iptables -t filter -F 2>/dev/null || true
    sudo ip6tables -t nat -F 2>/dev/null || true
}
trap cleanup ERR

# Start unified proxy as root (needed for BPF), exclude root's traffic via iptables
sudo env PROXY_LOG_FILE=/tmp/proxy.log \
  "$(pwd)"/.venv/bin/python unified_proxy.py > /tmp/proxy-stdout.log 2>&1 &
PROXY_PID=$!

# Wait for proxy to be listening
counter=0
while ! sudo ss -tln | grep -q ':8080 '; do
    sleep 1
    counter=$((counter+1))
    if ! sudo kill -0 $PROXY_PID 2>/dev/null; then
        echo "Proxy process died! Output:"
        cat /tmp/proxy-stdout.log || true
        exit 1
    fi
    if [ $counter -gt 10 ]; then
        echo "Timeout waiting for proxy"
        exit 1
    fi
done

# Setup iptables - exclude root's traffic to prevent loops
sudo sysctl -qw net.ipv4.ip_forward=1
sudo sysctl -qw net.ipv6.conf.all.forwarding=1
sudo sysctl -qw net.ipv4.conf.all.send_redirects=0

# ===========================================
# Block direct proxy connections
# ===========================================
# Prevent apps from bypassing transparent redirect by connecting
# directly to the proxy ports. Without this, apps could connect to
# localhost:8080 or :8053 directly, and we'd lose visibility into
# the original destination they intended to reach.
# Mark in mangle (before nat), drop in filter.
sudo iptables -t mangle -A OUTPUT -p tcp -d 127.0.0.1 --dport 8080 -m owner ! --uid-owner 0 -j MARK --set-mark 1
sudo iptables -t mangle -A OUTPUT -p udp -d 127.0.0.1 --dport 8053 -m owner ! --uid-owner 0 -j MARK --set-mark 1
sudo iptables -A OUTPUT -m mark --mark 1 -j DROP

# ===========================================
# UDP: nfqueue for DNS detection + PID tracking
# ===========================================
# Flow:
#   All UDP → nfqueue (mangle, before NAT)
#                 ↓
#           haslayer(DNS)?
#            /        \
#          yes         no
#           ↓           ↓
#      mark=2        (just log)
#      cache 4-tuple
#           ↓
#      nat: mark=2 → REDIRECT :8053
#           ↓
#      mitmproxy
#
# Exclude systemd-resolve: it's the system DNS stub resolver that
# forwards queries to upstream DNS. Must reach network directly.
sudo iptables -t mangle -A OUTPUT -p udp -m owner --uid-owner systemd-resolve -j RETURN
# Exclude root (uid 0): mitmproxy runs as root. Without this exclusion,
# mitmproxy's own DNS queries would loop back through nfqueue → mitmproxy.
sudo iptables -t mangle -A OUTPUT -p udp -m owner --uid-owner 0 -j RETURN
# Everything else → nfqueue for inspection
sudo iptables -t mangle -A OUTPUT -p udp -j NFQUEUE --queue-num 1

# ===========================================
# TCP: transparent proxy (8080)
# ===========================================
# Exclude root: mitmproxy runs as root and makes outbound connections
# to upstream servers. Without this, infinite redirect loop.
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 0 -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 8080
# IPv6 (note: blocked by BPF, but keep rules for completeness)
sudo ip6tables -t nat -A OUTPUT -p tcp -m owner --uid-owner 0 -j RETURN
sudo ip6tables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 8080

# ===========================================
# DNS: redirect marked packets (8053)
# ===========================================
# nfqueue inspects UDP packets and sets mark=2 on DNS (by structure,
# not port - catches DNS on non-standard ports too)
sudo iptables -t nat -A OUTPUT -p udp -m mark --mark 2 -j REDIRECT --to-port 8053
sudo ip6tables -t nat -A OUTPUT -p udp -m mark --mark 2 -j REDIRECT --to-port 8053

# Install mitmproxy certificate as system CA
sudo mkdir -p /usr/local/share/ca-certificates/extra
sudo openssl x509 -in /root/.mitmproxy/mitmproxy-ca-cert.pem -inform PEM -out /tmp/mitmproxy-ca-cert.crt 2>/dev/null
sudo cp /tmp/mitmproxy-ca-cert.crt /usr/local/share/ca-certificates/extra/mitmproxy-ca-cert.crt
sudo dpkg-reconfigure -p critical ca-certificates >/dev/null 2>&1
sudo update-ca-certificates >/dev/null 2>&1

# Set CA env vars for tools that don't use system store (copy to readable location)
sudo cp /root/.mitmproxy/mitmproxy-ca-cert.pem /tmp/mitmproxy-ca-cert.pem
sudo chmod 644 /tmp/mitmproxy-ca-cert.pem

# Export env vars (for GitHub Actions, write to GITHUB_ENV)
if [ -n "${GITHUB_ENV:-}" ]; then
    echo "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
    echo "REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
else
    export NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem
    export REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem
fi
