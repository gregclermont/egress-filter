#!/bin/bash
# Cleanup iptables rules set by setup-proxy.sh
#
# Flushes all tables modified by the proxy setup.
# Safe to run multiple times.

sudo iptables -t mangle -F 2>/dev/null || true
sudo iptables -t nat -F 2>/dev/null || true
sudo iptables -t filter -F 2>/dev/null || true
sudo ip6tables -t nat -F 2>/dev/null || true

echo "iptables cleaned up"
