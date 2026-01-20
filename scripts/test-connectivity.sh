#!/bin/bash
# Basic connectivity tests through the transparent proxy
#
# Verifies that HTTP, HTTPS, raw TCP, and DNS work through the proxy.
# These are sanity checks - for detailed PID tracking tests, see tests/test_pid_tracking.sh

set -e

echo "Testing HTTP..."
curl -v http://example.com 2>&1 | head -20

echo "Testing HTTPS..."
curl -v https://example.com 2>&1 | head -20

echo "Testing with wget..."
wget -O /dev/null https://httpbin.org/get

echo "Testing non-HTTP TCP (SSH to github.com)..."
echo "" | nc -v github.com 22 2>&1 | head -5 || true

echo "Testing DNS..."
dig +short example.com

echo "All connectivity tests passed!"
