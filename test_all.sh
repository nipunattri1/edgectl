#!/bin/bash
# Test script for xdp-firewall Go CLI
# Run with: ./test_all.sh

set -uo pipefail

echo "========================================"
echo "xdp-firewall Go CLI Test Suite"
echo "========================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

function test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
}

function test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
}

function test_info() {
    echo -e "${YELLOW}ℹ${NC}: $1"
}

# Build
echo ""
echo "--- Build ---"
if just build 2>&1 | tail -5; then
    test_pass "Build successful"
else
    test_fail "Build failed"
    exit 1
fi

# Unit tests
echo ""
echo "--- Unit Tests ---"
if go test -count=1 ./... 2>&1 | grep -E "(ok|FAIL|PASS)"; then
    test_pass "All unit tests pass"
else
    test_fail "Some unit tests failed"
fi

# CLI help
echo ""
echo "--- CLI Help Tests ---"
./build/edgewall --help >/dev/null && test_pass "Root --help works" || test_fail "Root --help failed"
./build/edgewall attach --help >/dev/null && test_pass "attach --help works" || test_fail "attach --help failed"
./build/edgewall detach --help >/dev/null && test_pass "detach --help works" || test_fail "detach --help failed"
./build/edgewall reload --help >/dev/null && test_pass "reload --help works" || test_fail "reload --help failed"
./build/edgewall list --help >/dev/null && test_pass "list --help works" || test_fail "list --help failed"
./build/edgewall block --help >/dev/null && test_pass "block --help works" || test_fail "block --help failed"
./build/edgewall unblock --help >/dev/null && test_pass "unblock --help works" || test_fail "unblock --help failed"

# Config validation tests (attach requires interface)
echo ""
echo "--- Config Validation Tests ---"
# Test attach requires interface
if ./build/edgewall --config config/edgectl.sample.yaml attach 2>&1 | grep -q "requires root"; then
    test_pass "attach requires root"
else
    test_fail "attach should require root"
fi

# Test attach fails without config
if ./build/edgewall attach 2>&1 | grep -q "interface.device is required"; then
    test_pass "attach requires interface.device when no config"
else
    test_fail "attach should require interface.device"
fi

# Test attach with config but no interface
cat > /tmp/test_no_interface.yaml << 'EOF'
interface:
  mode: "generic"
rules:
  block_proto: []
  default: "disallow"
ddos:
  enable: true
  syn_rate_limit: 100
  udp_rate_limit: 1000
conn_track:
  enable: true
  udp_timeout_ns: 30000000000
pin_dir: "/sys/fs/bpf/edgectl"
log_level: "info"
EOF

if ./build/edgewall --config /tmp/test_no_interface.yaml attach 2>&1 | grep -q "interface.device is required"; then
    test_pass "attach requires interface.device in config"
else
    test_fail "attach should require interface.device in config"
fi

# Test reload works without interface in config (loads from pinned state)
if ./build/edgewall --config /tmp/test_no_interface.yaml reload 2>&1 | grep -q "memlock\|pinned"; then
    test_pass "reload works without interface in config (loads from pinned state)"
else
    test_fail "reload should work without interface in config"
fi

# Test list works without interface in config
if ./build/edgewall --config /tmp/test_no_interface.yaml list 2>&1 | grep -q "memlock\|pinned"; then
    test_pass "list works without interface in config (loads from pinned state)"
else
    test_fail "list should work without interface in config"
fi

# Test block works without interface in config
if ./build/edgewall --config /tmp/test_no_interface.yaml block 192.168.1.1/32 2>&1 | grep -q "memlock\|pinned"; then
    test_pass "block works without interface in config (loads from pinned state)"
else
    test_fail "block should work without interface in config"
fi

# Test unblock works without interface in config
if ./build/edgewall --config /tmp/test_no_interface.yaml unblock 192.168.1.1/32 2>&1 | grep -q "memlock\|pinned"; then
    test_pass "unblock works without interface in config (loads from pinned state)"
else
    test_fail "unblock should work without interface in config"
fi

# Test with full config (with interface)
echo ""
echo "--- Config with Interface Tests ---"
if ./build/edgewall --config config/edgectl.sample.yaml attach 2>&1 | grep -q "requires root"; then
    test_pass "attach with interface config requires root"
else
    test_fail "attach with interface should require root"
fi

if ./build/edgewall --config config/edgectl.sample.yaml reload 2>&1 | grep -q "memlock\|pinned"; then
    test_pass "reload with interface config works"
else
    test_fail "reload with interface should work"
fi

# CIDR parsing tests
echo ""
echo "--- CIDR Parsing Tests ---"
# Test invalid CIDRs (should fail validation before BPF)
if ./build/edgewall --config config/edgectl.sample.yaml block 192.168.1.1/33 2>&1 | grep -q "invalid prefix"; then
    test_pass "block rejects /33 IPv4 prefix"
else
    test_fail "block should reject /33 IPv4 prefix"
fi

if ./build/edgewall --config config/edgectl.sample.yaml block 2001:db8::1/129 2>&1 | grep -q "invalid prefix"; then
    test_pass "block rejects /129 IPv6 prefix"
else
    test_fail "block should reject /129 IPv6 prefix"
fi

if ./build/edgewall --config config/edgectl.sample.yaml block 192.168.1.1/0 2>&1 | grep -q "blocks all"; then
    test_pass "block rejects /0 prefix"
else
    test_fail "block should reject /0 prefix"
fi

if ./build/edgewall --config config/edgectl.sample.yaml block 2001:db8::1/0 2>&1 | grep -q "blocks all"; then
    test_pass "block rejects IPv6 /0 prefix"
else
    test_fail "block should reject IPv6 /0 prefix"
fi

if ./build/edgewall --config config/edgectl.sample.yaml block invalid/24 2>&1 | grep -q "invalid IP"; then
    test_pass "block rejects invalid IP"
else
    test_fail "block should reject invalid IP"
fi

# Config validation tests
echo ""
echo "--- Config File Tests ---"
# Test missing config file
if ./build/edgewall --config /nonexistent/config.yaml attach 2>&1 | grep -q "read config"; then
    test_pass "Missing config file errors properly"
else
    test_fail "Missing config file should error"
fi

# Test invalid log level
if ./build/edgewall --log-level invalid attach 2>&1 | grep -q "invalid log level"; then
    test_pass "Invalid log level rejected"
else
    test_fail "Invalid log level should be rejected"
fi

# Version test
echo ""
echo "--- Version Test ---"
VERSION=$(./build/edgewall --version 2>&1)
if echo "$VERSION" | grep -q "edgectl version"; then
    test_pass "Version output: $VERSION"
else
    test_fail "Version command failed: $VERSION"
fi

# Clean test
echo ""
echo "--- Clean Test ---"
if just clean 2>&1 >/dev/null && [ ! -d "build" ]; then
    test_pass "Clean removes build directory"
else
    test_fail "Clean should remove build directory"
fi

# Rebuild after clean
echo ""
echo "--- Rebuild Test ---"
if just build 2>&1 | tail -1 | grep -q "edgewall"; then
    test_pass "Rebuild after clean works"
else
    test_fail "Rebuild after clean failed"
fi

# Summary
echo ""
echo "========================================"
echo "Test Summary: $PASS passed, $FAIL failed"
echo "========================================"

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi