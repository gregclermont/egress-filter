#!/bin/bash
# Unified iptables configuration for transparent proxy
#
# Usage: iptables.sh setup|cleanup
#
# All rules are defined once in apply_rules(). This ensures setup and cleanup
# stay in sync - you can't add a rule without it being cleaned up.

set -e

apply_rules() {
    local action="$1"  # -A or -D
    local ignore_errors="${2:-false}"

    rule() {
        local table="$1"; shift
        if [[ "$ignore_errors" == "true" ]]; then
            iptables -t "$table" "$action" "$@" 2>/dev/null || true
        else
            iptables -t "$table" "$action" "$@"
        fi
    }

    # Block direct proxy connections (mark in mangle, drop in filter)
    # Prevents apps from bypassing transparent redirect by connecting
    # directly to localhost:8080 or :8053
    rule mangle OUTPUT -p tcp -d 127.0.0.1 --dport 8080 -m owner ! --uid-owner 0 -j MARK --set-mark 1
    rule mangle OUTPUT -p udp -d 127.0.0.1 --dport 8053 -m owner ! --uid-owner 0 -j MARK --set-mark 1
    rule filter OUTPUT -m mark --mark 1 -j DROP

    # UDP: nfqueue for DNS detection + PID tracking
    # Exclude systemd-resolve (system DNS stub) and root (mitmproxy)
    rule mangle OUTPUT -p udp -m owner --uid-owner systemd-resolve -j RETURN
    rule mangle OUTPUT -p udp -m owner --uid-owner 0 -j RETURN
    rule mangle OUTPUT -p udp -j NFQUEUE --queue-num 1

    # TCP: transparent proxy redirect to port 8080
    # Exclude root to prevent mitmproxy redirect loop
    rule nat OUTPUT -p tcp -m owner --uid-owner 0 -j RETURN
    rule nat OUTPUT -p tcp -j REDIRECT --to-port 8080

    # DNS: redirect packets marked by nfqueue (mark=2) to port 8053
    rule nat OUTPUT -p udp -m mark --mark 2 -j REDIRECT --to-port 8053

    # Note: No IPv6 rules needed because:
    #   1. IPv6 is blocked at the socket level by the BPF program
    #   2. GitHub-hosted runners don't have IPv6 enabled
}

setup() {
    # Enable forwarding
    sysctl -qw net.ipv4.ip_forward=1
    sysctl -qw net.ipv4.conf.all.send_redirects=0

    # Add all rules
    apply_rules -A false
}

cleanup() {
    # Delete rules (ignore errors - rules may not exist)
    apply_rules -D true

    # Flush tables as safety net (in case rules were partially added
    # or script was interrupted)
    iptables -t mangle -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t filter -F 2>/dev/null || true
}

case "${1:-}" in
    setup)
        setup
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Usage: $0 setup|cleanup" >&2
        exit 1
        ;;
esac
