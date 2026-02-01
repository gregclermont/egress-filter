#!/bin/bash
# Proxy supervisor with automatic restart capability
#
# Restarts proxy once on unexpected termination.
# On second unexpected termination, cleans up iptables and exits.
#
# Exit codes:
#   0 - Clean shutdown (SIGTERM received)
#   1 - Proxy crashed twice, iptables cleaned up

set -e

SCRIPT_DIR="$(dirname "$0")"
REPO_ROOT="${EGRESS_FILTER_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PIDFILE="/tmp/proxy.pid"

# Supervisor state
RESTART_COUNT=0
MAX_RESTARTS=1
SIGTERM_RECEIVED=0
PROXY_PID=""

log() {
    echo "[supervisor] $1" >> /tmp/proxy-stdout.log
}

# Handle SIGTERM - forward to proxy, don't restart
handle_sigterm() {
    SIGTERM_RECEIVED=1
    log "Received SIGTERM, forwarding to proxy"
    if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill -TERM "$PROXY_PID" 2>/dev/null || true
    fi
}

# Get signal number from exit code (128 + signal)
exit_signal() {
    local code=$1
    if [[ $code -gt 128 ]]; then
        echo $((code - 128))
    else
        echo 0
    fi
}

# Start proxy and wait for it to be ready
start_proxy() {
    log "Starting proxy (attempt $((RESTART_COUNT + 1)))"
    echo "=== Proxy starting at $(date -Iseconds) ===" >> /tmp/proxy-stdout.log

    # Start proxy as direct child process
    # The proxy inherits our cgroup (the supervisor runs in the proxy scope).
    # This means when the proxy is killed, the supervisor keeps the cgroup alive,
    # preventing iptables cgroup match rules from becoming stale.
    env PROXY_LOG_FILE=/tmp/proxy.log VERBOSE="${VERBOSE:-0}" PYTHONPATH="$REPO_ROOT/src" \
        EGRESS_POLICY_FILE="${EGRESS_POLICY_FILE:-}" EGRESS_AUDIT_MODE="${EGRESS_AUDIT_MODE:-0}" \
        GITHUB_ACTION_REPOSITORY="${GITHUB_ACTION_REPOSITORY:-}" \
        GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}" \
        EGRESS_ALLOW_SUDO="${EGRESS_ALLOW_SUDO:-0}" \
        "$REPO_ROOT"/.venv/bin/python -m proxy.main >> /tmp/proxy-stdout.log 2>&1 &
    PROXY_PID=$!
    echo "$PROXY_PID" > "$PIDFILE"

    log "Proxy started with PID $PROXY_PID"

    # Wait for port 8080 to be listening
    local counter=0
    while ! ss -tln | grep -q ':8080 '; do
        sleep 0.1
        counter=$((counter + 1))
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            log "Proxy died during startup"
            return 1
        fi
        if [[ $counter -gt 100 ]]; then
            log "Timeout waiting for proxy to listen on port 8080"
            kill -TERM "$PROXY_PID" 2>/dev/null || true
            return 1
        fi
    done

    log "Proxy is listening on port 8080"
    return 0
}

# Cleanup resources before restart
# Note: We do NOT stop the systemd scope here because the supervisor runs in it.
# Keeping the scope alive preserves the kernel cgroup object, which keeps
# iptables cgroup match rules valid (they cache cgroup references).
cleanup_before_restart() {
    log "Cleaning up before restart..."

    # Kill any remaining proxy processes that might be holding BPF resources
    # This is important because BPF kprobes are reference-counted - if
    # the old process's file descriptors aren't fully closed, the new
    # kprobe attachment might conflict or fail silently
    pkill -9 -f "python.*proxy.main" 2>/dev/null || true

    # Flush conntrack entries to ensure clean state after restart
    # Without this, stale NAT entries can cause mitmproxy's outbound
    # connections to be incorrectly handled
    if command -v conntrack &>/dev/null; then
        log "Flushing conntrack entries..."
        # Flush UDP entries (DNS, nfqueue fast-path marks)
        conntrack -D -p udp 2>/dev/null || true
        # Flush TCP entries that might conflict with new proxy connections
        # Only flush entries related to proxy ports to avoid disrupting other services
        conntrack -D -p tcp --dport 8080 2>/dev/null || true
        conntrack -D -p tcp --sport 8080 2>/dev/null || true
        conntrack -D -p tcp --dport 8053 2>/dev/null || true
        conntrack -D -p tcp --sport 8053 2>/dev/null || true
    fi

    # Check for and remove any lingering BPF kprobe links
    # After SIGKILL, kprobe links might still be attached to udp_sendmsg
    # Use bpftool to force cleanup if available
    if command -v bpftool &>/dev/null; then
        log "Checking for lingering BPF kprobe links..."
        # List and detach any kprobe links on udp_sendmsg
        for link_id in $(bpftool link list 2>/dev/null | grep -B1 "kprobe.*udp_sendmsg" | grep "^[0-9]" | cut -d: -f1); do
            log "Detaching lingering kprobe link $link_id"
            bpftool link detach id "$link_id" 2>/dev/null || true
        done
    fi

    # Brief wait for kernel cleanup
    sleep 1
}

# Main supervisor loop
main() {
    trap 'handle_sigterm' SIGTERM SIGINT

    # Increase file descriptor limit for the supervisor and its children
    # This prevents "Too many open files" after restart when BPF/nfqueue
    # resources aren't fully released from the killed proxy
    ulimit -n 65536 2>/dev/null || log "Warning: could not increase ulimit"

    while true; do
        # Start proxy
        if ! start_proxy; then
            # Startup failure
            if [[ $RESTART_COUNT -lt $MAX_RESTARTS ]]; then
                RESTART_COUNT=$((RESTART_COUNT + 1))
                echo "::warning::Proxy failed to start, retrying (attempt $RESTART_COUNT)"
                log "Startup failed, retrying..."
                cleanup_before_restart
                continue
            else
                echo "::warning::Proxy failed to start twice, cleaning up iptables"
                log "Startup failed twice, cleaning up iptables and exiting"
                "$SCRIPT_DIR/iptables.sh" cleanup 2>/dev/null || true
                exit 1
            fi
        fi

        # Wait for proxy to exit (capture exit code without triggering set -e)
        local exit_code=0
        wait "$PROXY_PID" 2>/dev/null || exit_code=$?
        local sig=$(exit_signal "$exit_code")

        log "Proxy exited with code $exit_code (signal=$sig)"

        # Clean shutdown via SIGTERM?
        if [[ $SIGTERM_RECEIVED -eq 1 ]]; then
            log "Clean shutdown (SIGTERM received)"
            exit 0
        fi

        # Unexpected exit - check if we should restart
        if [[ $RESTART_COUNT -lt $MAX_RESTARTS ]]; then
            RESTART_COUNT=$((RESTART_COUNT + 1))
            if [[ $sig -gt 0 ]]; then
                log "Proxy crashed (signal $sig), restarting (attempt $RESTART_COUNT)"
            else
                log "Proxy crashed (exit $exit_code), restarting (attempt $RESTART_COUNT)"
            fi
            cleanup_before_restart
            continue
        fi

        # Max restarts reached - cleanup and exit
        if [[ $sig -gt 0 ]]; then
            echo "::warning::Proxy crashed twice (signal $sig), cleaning up iptables"
        else
            echo "::warning::Proxy crashed twice (exit $exit_code), cleaning up iptables"
        fi
        log "Max restarts reached, cleaning up iptables and exiting"
        "$SCRIPT_DIR/iptables.sh" cleanup 2>/dev/null || true
        exit 1
    done
}

main "$@"
