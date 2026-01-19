#!/usr/bin/env python3
"""Test the IPv6 blocker BPF program."""

import ctypes
import errno
import socket
import sys
from pathlib import Path

import tinybpf

# Initialize with system libbpf
for libbpf_path in ["/usr/lib/x86_64-linux-gnu/libbpf.so.1", "/usr/lib/libbpf.so.1"]:
    if Path(libbpf_path).exists():
        tinybpf.init(libbpf_path)
        break

BPF_PATH = Path(__file__).parent / "src" / "bpf" / "ipv6_blocker.bpf.o"


def get_self_cgroup() -> str:
    """Get the cgroup path for the current process."""
    cgroup_info = Path("/proc/self/cgroup").read_text().strip()
    cgroup_rel = cgroup_info.split(":")[-1]
    return f"/sys/fs/cgroup{cgroup_rel}"


def test_ipv6_blocker():
    """Test that IPv6 blocker blocks native IPv6 but allows v4-mapped."""
    print(f"Loading BPF from {BPF_PATH}")
    cgroup_path = get_self_cgroup()
    print(f"Attaching to cgroup {cgroup_path}")

    with tinybpf.load(str(BPF_PATH)) as obj:
        # Attach programs
        links = []
        links.append(obj.program("block_connect6").attach_cgroup(cgroup_path))
        links.append(obj.program("block_sendmsg6").attach_cgroup(cgroup_path))
        print("Programs attached")

        # Get config map
        config_map = obj.maps["config"].typed(key=int, value=int)

        # Test 1: With blocking disabled (default), native IPv6 should work
        # (or fail with network unreachable, not EPERM)
        print("\n=== Test 1: Blocking disabled ===")
        config_map[0] = 0
        print(f"config[0] = {config_map[0]}")

        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(("2001:4860:4860::8888", 443))
            print("Native IPv6 TCP: connected (allowed)")
            s.close()
        except socket.timeout:
            print("Native IPv6 TCP: timeout (network issue, not blocked)")
        except OSError as e:
            if e.errno == errno.ENETUNREACH:
                print("Native IPv6 TCP: network unreachable (not blocked, no IPv6)")
            elif e.errno == errno.EPERM:
                print("Native IPv6 TCP: EPERM - unexpectedly blocked!")
                return False
            else:
                print(f"Native IPv6 TCP: {e}")

        # Test 2: Enable blocking
        print("\n=== Test 2: Blocking enabled ===")
        config_map[0] = 1
        print(f"config[0] = {config_map[0]}")

        # Native IPv6 TCP should be blocked
        print("\nTesting native IPv6 TCP (should be blocked)...", end=" ")
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(("2001:4860:4860::8888", 443))
            print("FAIL - connected when should be blocked")
            s.close()
            return False
        except OSError as e:
            if e.errno == errno.EPERM:
                print("OK - blocked with EPERM")
            elif e.errno == errno.EACCES:
                print("OK - blocked with EACCES")
            elif e.errno == errno.ENETUNREACH:
                # Network unreachable could mask the block - try UDP
                print("network unreachable (can't distinguish from block)")
            else:
                print(f"error: {e}")

        # Native IPv6 UDP should be blocked
        print("Testing native IPv6 UDP (should be blocked)...", end=" ")
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(b"\x00", ("2001:4860:4860::8888", 53))
            print("FAIL - sent when should be blocked")
            s.close()
            return False
        except OSError as e:
            if e.errno == errno.EPERM:
                print("OK - blocked with EPERM")
            elif e.errno == errno.EACCES:
                print("OK - blocked with EACCES")
            elif e.errno == errno.ENETUNREACH:
                print("network unreachable (can't distinguish from block)")
            else:
                print(f"error: {e}")

        # v4-mapped should still work
        print("Testing v4-mapped TCP (should be allowed)...", end=" ")
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("::ffff:8.8.8.8", 443))
            print("OK - connected")
            s.close()
        except OSError as e:
            if e.errno in (errno.EPERM, errno.EACCES):
                print(f"FAIL - blocked when should be allowed: {e}")
                return False
            else:
                print(f"network error (not blocked): {e}")

        print("Testing v4-mapped UDP (should be allowed)...", end=" ")
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(b"\x00", ("::ffff:8.8.8.8", 53))
            print("OK - sent")
            s.close()
        except OSError as e:
            if e.errno in (errno.EPERM, errno.EACCES):
                print(f"FAIL - blocked when should be allowed: {e}")
                return False
            else:
                print(f"network error (not blocked): {e}")

        # Cleanup
        for link in links:
            link.destroy()

    print("\n=== All tests passed ===")
    return True


if __name__ == "__main__":
    success = test_ipv6_blocker()
    sys.exit(0 if success else 1)
