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

    rule6() {
        local table="$1"; shift
        if [[ "$ignore_errors" == "true" ]]; then
            ip6tables -t "$table" "$action" "$@" 2>/dev/null || true
        else
            ip6tables -t "$table" "$action" "$@"
        fi
    }

    # Cgroup path for the proxy (set by proxy.sh using systemd-run)
    local proxy_cgroup="system.slice/egress-filter-proxy.scope"

    # Block direct proxy connections (mark in mangle, drop in filter)
    # Prevents apps from bypassing transparent redirect by connecting
    # directly to localhost:8080 or :8053
    # Exclude proxy's own cgroup from this rule
    rule mangle OUTPUT -p tcp -d 127.0.0.1 --dport 8080 -m cgroup ! --path "$proxy_cgroup" -j MARK --set-mark 1
    rule mangle OUTPUT -p udp -d 127.0.0.1 --dport 8053 -m cgroup ! --path "$proxy_cgroup" -j MARK --set-mark 1
    rule filter OUTPUT -m mark --mark 1 -j DROP

    # UDP: nfqueue for DNS detection + PID tracking
    # Fast-path: skip nfqueue if conntrack already marked (subsequent non-DNS packets)
    rule mangle OUTPUT -p udp -m connmark --mark 4/4 -j RETURN
    # Handle packets just processed by nfqueue (marked with repeat verdict)
    # DNS (mark=2): just skip re-queuing (no fast-path - every query goes through nfqueue)
    rule mangle OUTPUT -p udp -m mark --mark 2 -j RETURN
    # Non-DNS (mark=4): save to conntrack for fast-path, then return
    rule mangle OUTPUT -p udp -m mark --mark 4/4 -j CONNMARK --save-mark
    rule mangle OUTPUT -p udp -m mark --mark 4/4 -j RETURN
    # Exclude systemd-resolve (system DNS stub) and proxy cgroup
    if id -u systemd-resolve &>/dev/null; then
        rule mangle OUTPUT -p udp -m owner --uid-owner systemd-resolve -j RETURN
    fi
    rule mangle OUTPUT -p udp -m cgroup --path "$proxy_cgroup" -j RETURN
    rule mangle OUTPUT -p udp -j NFQUEUE --queue-num 1

    # TCP: transparent proxy redirect to port 8080
    # Exclude proxy cgroup to prevent redirect loop
    rule nat OUTPUT -p tcp -m cgroup --path "$proxy_cgroup" -j RETURN
    rule nat OUTPUT -p tcp -j REDIRECT --to-port 8080

    # DNS: redirect packets marked by nfqueue (bit 2 set, could be mark 2 or 6)
    rule nat OUTPUT -p udp -m mark --mark 2/2 -j REDIRECT --to-port 8053

    # Docker container traffic (bridge mode)
    # Intercept traffic from docker0 for PID tracking and proxying
    # REDIRECT works in PREROUTING because packet is already at host
    if ip link show docker0 &>/dev/null; then
        # TCP from containers: redirect to proxy
        rule nat PREROUTING -i docker0 -p tcp -j REDIRECT --to-port 8080
        # UDP from containers: fast-path check, handle marked packets, then nfqueue
        rule mangle PREROUTING -i docker0 -p udp -m connmark --mark 4/4 -j RETURN
        rule mangle PREROUTING -i docker0 -p udp -m mark --mark 2 -j RETURN
        rule mangle PREROUTING -i docker0 -p udp -m mark --mark 4/4 -j CONNMARK --save-mark
        rule mangle PREROUTING -i docker0 -p udp -m mark --mark 4/4 -j RETURN
        rule mangle PREROUTING -i docker0 -p udp -j NFQUEUE --queue-num 1
        # DNS from containers: redirect marked packets to mitmproxy
        rule nat PREROUTING -i docker0 -p udp -m mark --mark 2/2 -j REDIRECT --to-port 8053
    fi

    # Note: IPv6 blocking for containers is handled by BPF cgroup hooks (cgroup/connect6,
    # cgroup/sendmsg6). Cgroups are orthogonal to network namespaces, so the hooks fire
    # for all processes including bridge containers.
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
    ip6tables -t filter -F 2>/dev/null || true
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
