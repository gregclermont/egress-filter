#!/usr/bin/env python3
"""
Test methods for blocking raw sockets on GHA runners.

Methods to test:
1. Drop CAP_NET_RAW capability
2. Seccomp filter to block socket() with SOCK_RAW
3. eBPF cgroup/sock_create hook (if available)

Run with: sudo python3 test_blocking_methods.py
"""

import ctypes
import json
import os
import socket
import subprocess
import sys

IPPROTO_RAW = 255
IPPROTO_TCP = 6
ETH_P_ALL = 0x0003

results = {}


def log(msg):
    print(f"[*] {msg}")


def log_result(test_name, success, details=None):
    results[test_name] = {"success": success, "details": details}
    status = "✓" if success else "✗"
    print(f"[{status}] {test_name}: {details or ''}")


def test_capsh_drop():
    """Test if we can drop CAP_NET_RAW using capsh."""
    log("Testing CAP_NET_RAW drop with capsh...")

    # Check if capsh is available
    try:
        result = subprocess.run(["which", "capsh"], capture_output=True)
        if result.returncode != 0:
            log_result("capsh available", False, "capsh not found")
            return False
    except Exception as e:
        log_result("capsh available", False, str(e))
        return False

    log_result("capsh available", True, "capsh found")

    # Try to run a command with CAP_NET_RAW dropped
    test_script = """
import socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 6)
    print("RAW_SOCKET_CREATED")
    sock.close()
except PermissionError:
    print("RAW_SOCKET_BLOCKED")
except Exception as e:
    print(f"ERROR: {e}")
"""

    try:
        # Drop CAP_NET_RAW and run test
        result = subprocess.run(
            ["capsh", "--drop=cap_net_raw", "--", "-c",
             f"python3 -c '{test_script}'"],
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr
        if "RAW_SOCKET_BLOCKED" in output:
            log_result("capsh drop CAP_NET_RAW", True, "Raw sockets blocked after dropping capability")
            return True
        elif "RAW_SOCKET_CREATED" in output:
            log_result("capsh drop CAP_NET_RAW", False, "Raw sockets still work after capsh drop!")
            return False
        else:
            log_result("capsh drop CAP_NET_RAW", False, f"Unexpected output: {output}")
            return False
    except Exception as e:
        log_result("capsh drop CAP_NET_RAW", False, str(e))
        return False


def test_prctl_no_new_privs():
    """Test PR_SET_NO_NEW_PRIVS which is needed for seccomp."""
    log("Testing PR_SET_NO_NEW_PRIVS...")

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_NO_NEW_PRIVS = 38

        # This should succeed
        result = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if result == 0:
            log_result("PR_SET_NO_NEW_PRIVS", True, "Can set NO_NEW_PRIVS (required for seccomp)")
            return True
        else:
            errno = ctypes.get_errno()
            log_result("PR_SET_NO_NEW_PRIVS", False, f"prctl failed with errno {errno}")
            return False
    except Exception as e:
        log_result("PR_SET_NO_NEW_PRIVS", False, str(e))
        return False


def test_seccomp_available():
    """Check if seccomp is available."""
    log("Checking seccomp availability...")

    try:
        # Check /proc/sys/kernel/seccomp/actions_avail
        with open("/proc/sys/kernel/seccomp/actions_avail", "r") as f:
            actions = f.read().strip()
            log_result("seccomp available", True, f"Actions: {actions}")
            return True
    except FileNotFoundError:
        # Try alternative check
        try:
            result = subprocess.run(["grep", "CONFIG_SECCOMP", "/boot/config-" + os.uname().release],
                                   capture_output=True, text=True)
            if "CONFIG_SECCOMP=y" in result.stdout:
                log_result("seccomp available", True, "CONFIG_SECCOMP=y in kernel config")
                return True
        except Exception:
            pass
        log_result("seccomp available", False, "Cannot determine seccomp availability")
        return False
    except Exception as e:
        log_result("seccomp available", False, str(e))
        return False


def test_seccomp_block_raw():
    """Test blocking raw sockets with seccomp using a helper program."""
    log("Testing seccomp blocking of raw sockets...")

    # We'll use a simple approach: check if seccomp-tools or similar is available
    # For a real implementation, we'd need to write BPF filter

    # First, check if we can install seccomp filters via Python
    try:
        import seccomp
        log_result("python-seccomp", True, "python-seccomp module available")
    except ImportError:
        log_result("python-seccomp", False, "python-seccomp not installed (pip install seccomp)")

    # Check if libseccomp is available
    try:
        result = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True)
        if "libseccomp" in result.stdout:
            log_result("libseccomp", True, "libseccomp found in system")
        else:
            log_result("libseccomp", False, "libseccomp not found")
    except Exception as e:
        log_result("libseccomp", False, str(e))


def check_bpf_lsm():
    """Check if BPF LSM is available."""
    log("Checking BPF LSM availability...")

    try:
        # Check if bpf LSM is in the active LSMs
        with open("/sys/kernel/security/lsm", "r") as f:
            lsms = f.read().strip()
            if "bpf" in lsms:
                log_result("BPF LSM", True, f"BPF in active LSMs: {lsms}")
                return True
            else:
                log_result("BPF LSM", False, f"BPF not in active LSMs: {lsms}")
                return False
    except FileNotFoundError:
        log_result("BPF LSM", False, "/sys/kernel/security/lsm not found")
        return False
    except Exception as e:
        log_result("BPF LSM", False, str(e))
        return False


def check_cgroup_bpf():
    """Check if cgroup BPF (for cgroup/sock_create) is available."""
    log("Checking cgroup BPF availability...")

    try:
        # Check if we can attach BPF to cgroups
        # This would require actually loading a BPF program
        result = subprocess.run(["bpftool", "cgroup", "list", "/sys/fs/cgroup"],
                               capture_output=True, text=True)
        if result.returncode == 0:
            log_result("cgroup BPF", True, f"bpftool cgroup works: {result.stdout[:100]}")
            return True
        else:
            log_result("cgroup BPF", False, f"bpftool failed: {result.stderr}")
            return False
    except FileNotFoundError:
        log_result("cgroup BPF", False, "bpftool not found")
        return False
    except Exception as e:
        log_result("cgroup BPF", False, str(e))
        return False


def test_setcap_binary():
    """Test if we can create a binary without CAP_NET_RAW."""
    log("Testing setcap on binaries...")

    try:
        # Check if setcap/getcap are available
        result = subprocess.run(["which", "setcap"], capture_output=True)
        if result.returncode != 0:
            log_result("setcap available", False, "setcap not found")
            return
        log_result("setcap available", True, "setcap found")

        result = subprocess.run(["getcap", "/bin/ping"], capture_output=True, text=True)
        log_result("ping capabilities", True, f"ping caps: {result.stdout.strip() or 'none'}")

    except Exception as e:
        log_result("setcap test", False, str(e))


def suggest_mitigations():
    """Print suggested mitigations based on test results."""
    print("\n" + "=" * 60)
    print("SUGGESTED MITIGATIONS")
    print("=" * 60)

    print("""
1. DROP CAP_NET_RAW AT PROCESS START
   - Use capsh: capsh --drop=cap_net_raw -- -c "your_command"
   - In systemd: CapabilityBoundingSet=~CAP_NET_RAW
   - In Docker: --cap-drop=NET_RAW

2. SECCOMP FILTER
   - Block socket() syscall when type includes SOCK_RAW
   - Block socket() with AF_PACKET family
   - Can be applied via:
     * systemd: SystemCallFilter=~socket (too broad)
     * Custom BPF filter (fine-grained)
     * Docker: --security-opt seccomp=profile.json

3. eBPF cgroup/sock_create HOOK
   - Attach BPF program to block raw socket creation
   - Can filter by socket type, family, protocol
   - Requires: kernel with cgroup BPF support

4. AppArmor/SELinux
   - Deny capability net_raw
   - More complex to configure

RECOMMENDED APPROACH FOR GHA:
   Since we control the runner environment:
   1. Drop CAP_NET_RAW for all user processes (systemd)
   2. As fallback, add seccomp filter
   3. Consider eBPF hook for fine-grained control
""")


def main():
    log("=" * 60)
    log("Raw Socket Blocking Methods Test")
    log("=" * 60)

    if os.geteuid() != 0:
        log("WARNING: Not running as root, some tests may fail")

    print()

    # Test various blocking methods
    test_capsh_drop()
    print()

    test_prctl_no_new_privs()
    print()

    test_seccomp_available()
    test_seccomp_block_raw()
    print()

    check_bpf_lsm()
    check_cgroup_bpf()
    print()

    test_setcap_binary()
    print()

    # Summary
    log("=" * 60)
    log("Summary")
    log("=" * 60)
    print(json.dumps(results, indent=2))

    # Suggestions
    suggest_mitigations()


if __name__ == "__main__":
    main()
