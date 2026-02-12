#!/bin/bash
# Comprehensive PID tracking tests
# This script tests all protocol/destination combinations and reports results.
# Exits 0 if all tests match expected results, 1 if any unexpected results.
#
# Usage: [VERBOSE=1] ./test_pid_tracking.sh

set -u

CONNECTIONS_LOG="${CONNECTIONS_FILE:-${RUNNER_TEMP:-/tmp}/connections.jsonl}"
VERBOSE="${VERBOSE:-0}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Results tracking
declare -a TEST_NAMES
declare -a TEST_RESULTS
declare -a TEST_EXPECTED
declare -a TEST_DETAILS

log() {
    [[ "$VERBOSE" == "1" ]] && echo "$@"
}

# run_test: Execute a command and check if its PID appears in proxy logs
# Arguments:
#   $1 - Test name
#   $2 - Expected result (PASS, FAIL, SKIP)
#   $3... - Command to run
run_test() {
    local name="$1"
    local expected="$2"
    shift 2
    local cmd=("$@")
    local details=""

    log ""
    log "=== Test: $name ==="
    log "Command: ${cmd[*]}"
    log "Expected: $expected"

    # Mark log position before test
    local log_lines_before=0
    if [[ -f "$CONNECTIONS_LOG" ]]; then
        log_lines_before=$(wc -l < "$CONNECTIONS_LOG")
    fi

    # Run command in background, capture PID
    local pid
    "${cmd[@]}" &>/dev/null &
    pid=$!

    # Wait for it to complete (with timeout)
    local waited=0
    while kill -0 "$pid" 2>/dev/null && [[ $waited -lt 10 ]]; do
        sleep 1
        ((waited++))
    done

    # Kill if still running
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        log "Command timed out"
    else
        wait "$pid" 2>/dev/null || true
    fi

    log "PID was: $pid"

    # Give proxy a moment to log
    sleep 0.5

    # Check if PID appears in new log entries (JSONL format: "pid":1234)
    local result="FAIL"
    if [[ -f "$CONNECTIONS_LOG" ]]; then
        local new_lines
        new_lines=$(tail -n +$((log_lines_before + 1)) "$CONNECTIONS_LOG" 2>/dev/null || true)

        if echo "$new_lines" | grep -q "\"pid\":$pid[,}]"; then
            result="PASS"
            details=$(echo "$new_lines" | grep "\"pid\":$pid[,}]" | head -1)
            log -e "${GREEN}PASS${NC} - Found pid=$pid in logs"
            log "$details"
        else
            details="pid=$pid not found. Recent: $(echo "$new_lines" | tail -1)"
            log -e "${RED}FAIL${NC} - pid=$pid not found in logs"
            log "Recent log entries:"
            log "$new_lines" | tail -5
        fi
    else
        details="Log file not found: $CONNECTIONS_LOG"
        log -e "${RED}FAIL${NC} - $details"
    fi

    # Progress indicator in non-verbose mode
    if [[ "$VERBOSE" != "1" ]]; then
        if [[ "$result" == "$expected" ]]; then
            echo -n "."
        else
            echo -n "X"
        fi
    fi

    TEST_NAMES+=("$name")
    TEST_RESULTS+=("$result")
    TEST_EXPECTED+=("$expected")
    TEST_DETAILS+=("$details")
}

# skip_test: Mark a test as skipped
skip_test() {
    local name="$1"
    local reason="$2"

    log ""
    log "=== Test: $name ==="
    log -e "${YELLOW}SKIP${NC} - $reason"

    [[ "$VERBOSE" != "1" ]] && echo -n "s"

    TEST_NAMES+=("$name")
    TEST_RESULTS+=("SKIP")
    TEST_EXPECTED+=("SKIP")
    TEST_DETAILS+=("$reason")
}

# Header
if [[ "$VERBOSE" == "1" ]]; then
    echo "========================================"
    echo "PID Tracking Comprehensive Test Suite"
    echo "========================================"
    echo ""
    echo "Connections log: $CONNECTIONS_LOG"
    echo "Date: $(date)"
    echo ""
    if [[ ! -f "$CONNECTIONS_LOG" ]]; then
        echo "WARNING: Connections log file does not exist yet"
    fi
else
    echo -n "Running tests "
fi

# ============================================
# TCP Tests
# ============================================

log ""
log "### TCP Tests ###"

run_test "HTTP/IPv4 external" "PASS" \
    curl -s -o /dev/null -m 5 http://example.com/

run_test "HTTPS/IPv4 external" "PASS" \
    curl -s -o /dev/null -m 5 https://example.com/

run_test "TCP/raw external (SSH)" "PASS" \
    nc -z -w 5 github.com 22

run_test "HTTP via direct proxy (blocked)" "FAIL" \
    curl -s -o /dev/null -m 2 --proxy http://localhost:8080 http://example.com/

run_test "TCP to loopback (blocked)" "FAIL" \
    curl -s -o /dev/null -m 2 http://127.0.0.1:8080/

# ============================================
# DNS Tests
# ============================================

log ""
log "### DNS Tests ###"

run_test "DNS via loopback (127.0.0.53)" "PASS" \
    dig +short +time=2 +tries=1 @127.0.0.53 example.com

run_test "DNS to external (8.8.8.8)" "PASS" \
    dig +short +time=2 +tries=1 @8.8.8.8 example.com

run_test "DNS via system resolver" "PASS" \
    dig +short +time=2 +tries=1 example.com

# ============================================
# IPv6 Tests
# ============================================

log ""
log "### IPv6 Tests ###"

run_test "TCP/IPv6 native (blocked)" "FAIL" \
    nc -6 -z -w 2 2606:4700:4700::1111 80

EXAMPLE_IP=$(dig +short example.com A | head -1)
if [[ -n "$EXAMPLE_IP" ]]; then
    run_test "TCP via IPv4-mapped IPv6 (blocked)" "FAIL" \
        nc -z -w 5 "::ffff:$EXAMPLE_IP" 80
else
    skip_test "TCP via IPv4-mapped IPv6 (blocked)" "Could not resolve example.com"
fi

# ============================================
# UDP Tests (non-DNS)
# ============================================

log ""
log "### UDP Tests (non-DNS) ###"

# Unconnected UDP (sendto with destination in msg_name)
run_test "UDP to external (port 9999)" "PASS" \
    nc -u -z -w 2 8.8.8.8 9999

run_test "UDP to external (port 12345)" "PASS" \
    nc -u -z -w 2 8.8.8.8 12345

# UDP to loopback (non-DNS) - tests kprobe loopback path for non-53 ports
run_test "UDP to loopback (non-DNS)" "PASS" \
    python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'test', ('127.0.0.1', 19999))"

# Connected UDP socket - tests kprobe connected path (destination in socket, not msg_name)
run_test "UDP via connected socket" "PASS" \
    python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('8.8.8.8', 9999)); s.send(b'test')"

# UDP IPv6 (should be blocked by cgroup/sendmsg6)
run_test "UDP/IPv6 (blocked)" "FAIL" \
    python3 -c "import socket; s=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.sendto(b'test', ('2001:4860:4860::8888', 9999))"

# ============================================
# Edge Cases
# ============================================

log ""
log "### Edge Cases ###"

run_test "HTTP via Python requests" "PASS" \
    python3 -c "import urllib.request; urllib.request.urlopen('http://example.com', timeout=5)"

run_test "HTTPS via wget" "PASS" \
    wget -q -O /dev/null --timeout=5 https://example.com/

run_test "Multiple HTTP requests (curl)" "PASS" \
    curl -s -o /dev/null -m 5 http://example.com/ http://example.org/

# ============================================
# Summary
# ============================================

[[ "$VERBOSE" != "1" ]] && echo ""  # End progress line

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo ""

# Count results
total=${#TEST_NAMES[@]}
passed=0
failed=0
skipped=0
unexpected=0

printf "%-35s %-10s %-10s %-10s\n" "TEST" "RESULT" "EXPECTED" "STATUS"
printf "%-35s %-10s %-10s %-10s\n" "----" "------" "--------" "------"

for i in "${!TEST_NAMES[@]}"; do
    name="${TEST_NAMES[$i]}"
    result="${TEST_RESULTS[$i]}"
    expected="${TEST_EXPECTED[$i]}"
    details="${TEST_DETAILS[$i]}"

    status=""
    if [[ "$result" == "SKIP" ]]; then
        ((skipped++))
        status="-"
    elif [[ "$result" == "$expected" ]]; then
        status="OK"
        if [[ "$result" == "PASS" ]]; then
            ((passed++))
        else
            ((failed++))
        fi
    else
        # Unexpected result
        ((unexpected++))
        if [[ "$result" == "PASS" ]]; then
            status="FIXED?"
        else
            status="REGRESS?"
        fi
    fi

    printf "%-35s %-10s %-10s %-10s\n" "$name" "$result" "$expected" "$status"

    # Show details for unexpected results even in non-verbose mode
    if [[ "$status" == "REGRESS?" || "$status" == "FIXED?" ]]; then
        echo "  -> $details"
    fi
done

echo ""
echo "----------------------------------------"
echo "Total: $total | Passed: $passed | Failed: $failed | Skipped: $skipped | Unexpected: $unexpected"
echo "----------------------------------------"
echo ""

if [[ $unexpected -gt 0 ]]; then
    echo "ERROR: $unexpected test(s) had unexpected results"
    exit 1
fi

echo "All tests matched expected results"
exit 0
