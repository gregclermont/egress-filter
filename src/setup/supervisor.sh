#!/bin/bash
# Minimal proxy supervisor with restart capability
#
# Restarts proxy once on unexpected termination.
# On second crash, cleans up iptables and exits.

set -e

SCRIPT_DIR="$(dirname "$0")"
REPO_ROOT="${EGRESS_FILTER_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
TEMP_DIR="${RUNNER_TEMP:-/tmp}"
PIDFILE="$TEMP_DIR/proxy.pid"

RESTART_COUNT=0
MAX_RESTARTS=1
CLEAN_SHUTDOWN=0
PROXY_PID=""

log() {
    echo "[supervisor] $1" >> "$TEMP_DIR/proxy-stdout.log"
}

handle_sigterm() {
    CLEAN_SHUTDOWN=1
    log "Received SIGTERM, forwarding to proxy"
    if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill -TERM "$PROXY_PID" 2>/dev/null || true
    fi
}

start_proxy() {
    log "Starting proxy (attempt $((RESTART_COUNT + 1)))"

    # Start proxy as child - inherits our cgroup
    env PROXY_LOG_FILE="$TEMP_DIR/proxy.log" VERBOSE="${VERBOSE:-0}" PYTHONPATH="$REPO_ROOT/src" \
        RUNNER_TEMP="$TEMP_DIR" \
        EGRESS_POLICY_FILE="${EGRESS_POLICY_FILE:-}" EGRESS_AUDIT_MODE="${EGRESS_AUDIT_MODE:-0}" \
        GITHUB_ACTION_REPOSITORY="${GITHUB_ACTION_REPOSITORY:-}" \
        GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}" \
        EGRESS_ALLOW_SUDO="${EGRESS_ALLOW_SUDO:-0}" \
        EGRESS_SOCKET_SECURITY="${EGRESS_SOCKET_SECURITY:-0}" \
        GITHUB_TOKEN="${GITHUB_TOKEN:-}" \
        ACTIONS_ID_TOKEN_REQUEST_URL="${ACTIONS_ID_TOKEN_REQUEST_URL:-}" \
        ACTIONS_ID_TOKEN_REQUEST_TOKEN="${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" \
        "$REPO_ROOT"/.venv/bin/python -m proxy.main >> "$TEMP_DIR/proxy-stdout.log" 2>&1 &
    PROXY_PID=$!
    echo "$PROXY_PID" > "$PIDFILE"
    log "Proxy started with PID $PROXY_PID"

    # Wait for port 8080
    local counter=0
    while ! ss -tln | grep -q ':8080 '; do
        sleep 0.1
        counter=$((counter + 1))
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            log "Proxy died during startup"
            return 1
        fi
        if [[ $counter -gt 100 ]]; then
            log "Timeout waiting for port 8080"
            kill -TERM "$PROXY_PID" 2>/dev/null || true
            return 1
        fi
    done
    log "Proxy ready"
    return 0
}

main() {
    trap 'handle_sigterm' SIGTERM SIGINT

    while true; do
        if ! start_proxy; then
            if [[ $RESTART_COUNT -lt $MAX_RESTARTS ]]; then
                RESTART_COUNT=$((RESTART_COUNT + 1))
                log "Startup failed, retrying..."
                continue
            else
                log "Startup failed twice, cleaning up"
                "$SCRIPT_DIR/iptables.sh" cleanup 2>/dev/null || true
                exit 1
            fi
        fi

        # Wait for proxy to exit
        wait "$PROXY_PID" 2>/dev/null || true

        if [[ $CLEAN_SHUTDOWN -eq 1 ]]; then
            log "Clean shutdown"
            exit 0
        fi

        # Unexpected exit
        if [[ $RESTART_COUNT -lt $MAX_RESTARTS ]]; then
            RESTART_COUNT=$((RESTART_COUNT + 1))
            log "Proxy crashed, restarting (attempt $RESTART_COUNT)"
            continue
        fi

        log "Max restarts reached, cleaning up"
        "$SCRIPT_DIR/iptables.sh" cleanup 2>/dev/null || true
        exit 1
    done
}

main "$@"
