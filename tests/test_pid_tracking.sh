#!/bin/bash
# Comprehensive PID tracking tests
# This script tests all protocol/destination combinations and reports results.
# It ALWAYS exits 0 - failures are expected and tracked for observability.

set -u

PROXY_LOG="${PROXY_LOG_FILE:-/tmp/proxy.log}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Results tracking
declare -a TEST_NAMES
declare -a TEST_RESULTS
declare -a TEST_EXPECTED

# run_test: Execute a command and check if its PID appears in proxy logs
# Arguments:
#   $1 - Test name
#   $2 - Expected result (PASS, FAIL, SKIP, or ? for unknown)
#   $3... - Command to run
run_test() {
    local name="$1"
    local expected="$2"
    shift 2
    local cmd=("$@")

    echo ""
    echo "=== Test: $name ==="
    echo "Command: ${cmd[*]}"
    echo "Expected: $expected"

    # Get the base command name (first word, without path)
    local base_cmd
    base_cmd=$(basename "${cmd[0]}")

    # Mark log position before test
    local log_lines_before=0
    if [[ -f "$PROXY_LOG" ]]; then
        log_lines_before=$(wc -l < "$PROXY_LOG")
    fi

    # Run command and capture its PID
    # Use a subshell to get exact PID of the command
    local pid
    local exit_code=0

    # Run command in background, capture PID
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
        echo "Command timed out"
    else
        wait "$pid" 2>/dev/null || exit_code=$?
    fi

    echo "PID was: $pid"

    # Give proxy a moment to log
    sleep 0.5

    # Check if PID appears in new log entries
    local result="FAIL"
    if [[ -f "$PROXY_LOG" ]]; then
        # Get new log lines since test started
        local new_lines
        new_lines=$(tail -n +$((log_lines_before + 1)) "$PROXY_LOG" 2>/dev/null || true)

        # Look for pid=<our-pid> in logs
        if echo "$new_lines" | grep -q "pid=$pid"; then
            result="PASS"
            echo -e "${GREEN}PASS${NC} - Found pid=$pid in logs"
            # Show the matching log line
            echo "$new_lines" | grep "pid=$pid" | head -3
        else
            echo -e "${RED}FAIL${NC} - pid=$pid not found in logs"
            # Show recent log lines for debugging
            echo "Recent log entries:"
            echo "$new_lines" | tail -5
        fi
    else
        echo -e "${RED}FAIL${NC} - Log file not found: $PROXY_LOG"
    fi

    # Track results
    TEST_NAMES+=("$name")
    TEST_RESULTS+=("$result")
    TEST_EXPECTED+=("$expected")
}

# skip_test: Mark a test as skipped
skip_test() {
    local name="$1"
    local reason="$2"

    echo ""
    echo "=== Test: $name ==="
    echo -e "${YELLOW}SKIP${NC} - $reason"

    TEST_NAMES+=("$name")
    TEST_RESULTS+=("SKIP")
    TEST_EXPECTED+=("SKIP")
}

# Check for IPv6 connectivity
has_ipv6() {
    # Check if we have a global IPv6 address
    ip -6 addr show scope global 2>/dev/null | grep -q inet6
}

echo "========================================"
echo "PID Tracking Comprehensive Test Suite"
echo "========================================"
echo ""
echo "Log file: $PROXY_LOG"
echo "Date: $(date)"
echo ""

# Ensure log file exists and is readable
if [[ ! -f "$PROXY_LOG" ]]; then
    echo "WARNING: Log file does not exist yet, some tests may fail"
fi

# ============================================
# TCP Tests
# ============================================

echo ""
echo "### TCP Tests ###"

# HTTP to external (port 80)
run_test "HTTP/IPv4 external" "PASS" \
    curl -s -o /dev/null -m 5 http://example.com/

# HTTPS to external (port 443)
run_test "HTTPS/IPv4 external" "PASS" \
    curl -s -o /dev/null -m 5 https://example.com/

# Raw TCP to external (SSH port)
run_test "TCP/raw external (SSH)" "PASS" \
    nc -z -w 5 github.com 22

# TCP via explicit proxy (not iptables redirect)
run_test "HTTP via direct proxy" "?" \
    curl -s -o /dev/null -m 5 --proxy http://localhost:8080 http://example.com/

# TCP to loopback - should FAIL (no kprobe for TCP loopback)
# We need a service listening on localhost for this
# Skip if nothing is listening on localhost:8080 besides our proxy
run_test "TCP to loopback (proxy)" "FAIL" \
    curl -s -o /dev/null -m 2 http://127.0.0.1:8080/

# ============================================
# DNS Tests
# ============================================

echo ""
echo "### DNS Tests ###"

# DNS via loopback (systemd-resolved)
run_test "DNS via loopback (127.0.0.53)" "PASS" \
    dig +short +time=2 +tries=1 @127.0.0.53 example.com

# DNS to external resolver
run_test "DNS to external (8.8.8.8)" "?" \
    dig +short +time=2 +tries=1 @8.8.8.8 example.com

# DNS using system resolver (should go through 127.0.0.53)
run_test "DNS via system resolver" "PASS" \
    dig +short +time=2 +tries=1 example.com

# ============================================
# IPv6 Tests
# ============================================

echo ""
echo "### IPv6 Tests ###"

if has_ipv6; then
    # Native IPv6
    run_test "HTTPS/IPv6 native" "?" \
        curl -s -o /dev/null -m 5 -6 https://ipv6.google.com/

    # IPv4-mapped IPv6 address
    # Get an IP for example.com and try connecting via ::ffff:x.x.x.x
    EXAMPLE_IP=$(dig +short example.com A | head -1)
    if [[ -n "$EXAMPLE_IP" ]]; then
        run_test "TCP via IPv4-mapped IPv6" "?" \
            nc -z -w 5 "::ffff:$EXAMPLE_IP" 80
    else
        skip_test "TCP via IPv4-mapped IPv6" "Could not resolve example.com"
    fi
else
    skip_test "HTTPS/IPv6 native" "No IPv6 connectivity"
    skip_test "TCP via IPv4-mapped IPv6" "No IPv6 connectivity"
fi

# ============================================
# UDP Tests (non-DNS)
# ============================================

echo ""
echo "### UDP Tests (non-DNS) ###"

# Non-DNS UDP to external - should FAIL (not redirected by iptables)
# We'll try to send a UDP packet to a random port
run_test "UDP non-DNS to external" "FAIL" \
    nc -u -z -w 2 8.8.8.8 9999

# ============================================
# Edge Cases
# ============================================

echo ""
echo "### Edge Cases ###"

# Python making HTTP request (different binary)
run_test "HTTP via Python requests" "PASS" \
    python3 -c "import urllib.request; urllib.request.urlopen('http://example.com', timeout=5)"

# wget (another HTTP client)
run_test "HTTPS via wget" "PASS" \
    wget -q -O /dev/null --timeout=5 https://example.com/

# Multiple sequential connections (same command)
run_test "Multiple HTTP requests (curl)" "PASS" \
    curl -s -o /dev/null -m 5 http://example.com/ http://example.org/

# ============================================
# Summary
# ============================================

echo ""
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
    elif [[ "$expected" == "?" ]]; then
        # Unknown expected - report actual result
        if [[ "$result" == "PASS" ]]; then
            ((passed++))
            status="(new)"
        else
            ((failed++))
            status="(new)"
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
done

echo ""
echo "----------------------------------------"
echo "Total: $total | Passed: $passed | Failed: $failed | Skipped: $skipped | Unexpected: $unexpected"
echo "----------------------------------------"
echo ""

if [[ $unexpected -gt 0 ]]; then
    echo "NOTE: $unexpected test(s) had unexpected results - may need investigation"
fi

# Always exit 0 - this is for observability, not CI gating
echo ""
echo "Test suite complete (exit 0 - failures are tracked, not fatal)"
exit 0
