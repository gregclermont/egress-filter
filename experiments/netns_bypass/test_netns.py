#!/usr/bin/env python3
"""
Test network namespace bypass and blocking methods on GHA runners.

Tests:
1. Can we create network namespaces?
2. Can traffic from a netns bypass iptables?
3. What methods can block netns creation?

Run with: sudo python3 test_netns.py
"""

import ctypes
import json
import os
import subprocess
import sys

# Clone flags
CLONE_NEWNET = 0x40000000

results = {}


def log(msg):
    print(f"[*] {msg}")


def log_result(test_name, success, details=None):
    results[test_name] = {"success": success, "details": details}
    status = "✓" if success else "✗"
    print(f"[{status}] {test_name}: {details or ''}")


def check_capabilities():
    """Check relevant capabilities for netns creation."""
    log("Checking capabilities...")

    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("Cap"):
                    print(f"    {line.strip()}")
    except Exception as e:
        log(f"Failed to read capabilities: {e}")

    # Check CAP_SYS_ADMIN (bit 21)
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split()[1], 16)
                    CAP_SYS_ADMIN = 21
                    has_sys_admin = bool(cap_hex & (1 << CAP_SYS_ADMIN))
                    log_result("CAP_SYS_ADMIN", has_sys_admin, f"CapEff=0x{cap_hex:x}")
                    return has_sys_admin
    except Exception as e:
        log_result("CAP_SYS_ADMIN", False, str(e))
        return False


def test_unshare_command():
    """Test if unshare --net works."""
    log("Testing unshare --net command...")

    try:
        # Try to create a network namespace and run a command in it
        result = subprocess.run(
            ["unshare", "--net", "ip", "link", "show"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            # Check if we see only 'lo' (loopback) - sign of new netns
            if "eth" not in result.stdout and "lo" in result.stdout:
                log_result("unshare --net", True, "New netns created (only lo interface)")
                return True
            else:
                log_result("unshare --net", True, f"Command succeeded: {result.stdout[:100]}")
                return True
        else:
            log_result("unshare --net", False, f"Failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        log_result("unshare --net", False, "Timeout")
        return False
    except Exception as e:
        log_result("unshare --net", False, str(e))
        return False


def test_unshare_syscall():
    """Test unshare() syscall directly."""
    log("Testing unshare() syscall...")

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)

        # Try to unshare network namespace
        result = libc.unshare(CLONE_NEWNET)

        if result == 0:
            log_result("unshare() syscall", True, "Network namespace created")
            return True
        else:
            errno = ctypes.get_errno()
            log_result("unshare() syscall", False, f"Failed with errno {errno}")
            return False
    except Exception as e:
        log_result("unshare() syscall", False, str(e))
        return False


def test_netns_bypass():
    """Test if network traffic from a netns bypasses iptables."""
    log("Testing netns bypass of iptables...")

    try:
        # Create a script that runs in a new netns and tries to reach the internet
        # This requires setting up veth pairs which is complex
        # For now, just check if we can create a netns with network access

        script = """
        # In the new netns, we'd need to set up routing to reach outside
        # This is complex - for now just verify we're in a new netns
        ip link show
        echo "NETNS_TEST_OK"
        """

        result = subprocess.run(
            ["unshare", "--net", "bash", "-c", script],
            capture_output=True,
            text=True,
            timeout=5
        )

        if "NETNS_TEST_OK" in result.stdout:
            log_result("netns bypass test", True, "Can execute in new netns")
            print(f"    Output: {result.stdout}")
            return True
        else:
            log_result("netns bypass test", False, f"Failed: {result.stderr}")
            return False
    except Exception as e:
        log_result("netns bypass test", False, str(e))
        return False


def check_apparmor():
    """Check AppArmor status and capabilities."""
    log("Checking AppArmor...")

    try:
        # Check if AppArmor is enabled
        with open("/sys/kernel/security/apparmor/profiles", "r") as f:
            profiles = f.read()
            profile_count = len(profiles.strip().split("\n"))
            log_result("AppArmor enabled", True, f"{profile_count} profiles loaded")
    except FileNotFoundError:
        log_result("AppArmor enabled", False, "AppArmor not available")
        return
    except Exception as e:
        log_result("AppArmor enabled", False, str(e))
        return

    # Check current process's AppArmor profile
    try:
        with open("/proc/self/attr/current", "r") as f:
            current_profile = f.read().strip()
            log_result("Current AppArmor profile", True, current_profile)
    except Exception as e:
        log_result("Current AppArmor profile", False, str(e))

    # Check if we can load profiles
    try:
        result = subprocess.run(
            ["aa-status"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            log_result("aa-status", True, "AppArmor tools available")
            # Count enforced profiles
            for line in result.stdout.split("\n"):
                if "profiles are in enforce mode" in line:
                    print(f"    {line.strip()}")
        else:
            log_result("aa-status", False, result.stderr)
    except FileNotFoundError:
        log_result("aa-status", False, "aa-status not found")
    except Exception as e:
        log_result("aa-status", False, str(e))


def check_seccomp():
    """Check seccomp status."""
    log("Checking seccomp...")

    try:
        with open("/proc/sys/kernel/seccomp/actions_avail", "r") as f:
            actions = f.read().strip()
            log_result("seccomp available", True, f"Actions: {actions}")
    except FileNotFoundError:
        log_result("seccomp available", False, "seccomp not available")
    except Exception as e:
        log_result("seccomp available", False, str(e))

    # Check current process seccomp mode
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    mode = line.split()[1]
                    modes = {0: "disabled", 1: "strict", 2: "filter"}
                    log_result("Current seccomp mode", True, modes.get(int(mode), mode))
    except Exception as e:
        log_result("Current seccomp mode", False, str(e))


def test_seccomp_block_unshare():
    """Test if we can use seccomp to block unshare."""
    log("Testing seccomp blocking of unshare...")

    # We'll use a small C program or libseccomp if available
    try:
        import seccomp
        log_result("python-seccomp", True, "Module available")

        # Note: We can't easily test this without forking because
        # seccomp filters are irreversible
        log("Skipping actual seccomp test (would affect current process)")

    except ImportError:
        log_result("python-seccomp", False, "Not installed")

    # Check if libseccomp is available
    try:
        result = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True)
        if "libseccomp" in result.stdout:
            log_result("libseccomp", True, "Available in system")
        else:
            log_result("libseccomp", False, "Not found")
    except Exception as e:
        log_result("libseccomp", False, str(e))


def check_user_namespaces():
    """Check if user namespaces are enabled (affects unprivileged unshare)."""
    log("Checking user namespace settings...")

    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
            value = f.read().strip()
            enabled = value == "1"
            log_result("unprivileged_userns_clone", enabled, f"Value: {value}")
    except FileNotFoundError:
        log_result("unprivileged_userns_clone", True, "File not found (likely enabled)")
    except Exception as e:
        log_result("unprivileged_userns_clone", False, str(e))

    # Check max_user_namespaces
    try:
        with open("/proc/sys/user/max_user_namespaces", "r") as f:
            value = f.read().strip()
            log_result("max_user_namespaces", True, f"Value: {value}")
    except Exception as e:
        log_result("max_user_namespaces", False, str(e))


def test_bpf_hooks():
    """Check available BPF hooks for namespace monitoring."""
    log("Checking BPF capabilities for namespace monitoring...")

    # Check if we can attach to namespace-related kprobes
    kprobes_to_check = [
        "create_new_namespaces",
        "copy_net_ns",
        "unshare_nsproxy_namespaces",
    ]

    try:
        with open("/proc/kallsyms", "r") as f:
            symbols = f.read()

        for kprobe in kprobes_to_check:
            if kprobe in symbols:
                log_result(f"kprobe:{kprobe}", True, "Symbol available")
            else:
                log_result(f"kprobe:{kprobe}", False, "Symbol not found")
    except Exception as e:
        log(f"Failed to check kallsyms: {e}")

    # Check LSM BPF availability (we know it's not, but document it)
    try:
        with open("/sys/kernel/security/lsm", "r") as f:
            lsms = f.read().strip()
            has_bpf = "bpf" in lsms
            log_result("BPF LSM", has_bpf, f"Active LSMs: {lsms}")
    except Exception as e:
        log_result("BPF LSM", False, str(e))


def suggest_mitigations():
    """Print suggested mitigations based on findings."""
    print("\n" + "=" * 60)
    print("ANALYSIS & MITIGATIONS")
    print("=" * 60)

    print("""
NETWORK NAMESPACE BYPASS ANALYSIS:

The threat: An attacker creates a new network namespace where our
iptables rules don't exist, then sets up routing to bypass the proxy.

BLOCKING OPTIONS:

1. SECCOMP FILTER (per-process, inherited)
   - Block unshare() and clone() with CLONE_NEWNET flag
   - Problem: Must be set before user code runs
   - Problem: Our pre-hook exits before user steps
   - Possible: Wrapper script that sets seccomp then execs user command

2. APPARMOR PROFILE
   - Can deny CAP_SYS_ADMIN or specific operations
   - Can be loaded system-wide
   - Need to test if we can load profiles on GHA

3. SYSCTL: Disable user namespaces
   - Set kernel.unprivileged_userns_clone=0
   - Blocks unprivileged users from creating any namespaces
   - May break legitimate uses (containers, sandboxes)

4. CGROUP DEVICE CONTROLLER
   - Can restrict device access but not namespace creation

5. DISABLE SUDO (indirect)
   - Without sudo, regular users need CAP_SYS_ADMIN for CLONE_NEWNET
   - User namespaces can grant this, so need to disable those too

RECOMMENDED APPROACH:
   1. Disable unprivileged user namespaces (sysctl)
   2. Disable sudo (prevents privileged unshare)
   3. For defense in depth, consider AppArmor profile
""")


def main():
    log("=" * 60)
    log("Network Namespace Bypass Test")
    log("=" * 60)

    if os.geteuid() != 0:
        log("WARNING: Not running as root, some tests may fail")

    print()

    # Capability check
    check_capabilities()
    print()

    # User namespace settings
    check_user_namespaces()
    print()

    # Test unshare
    test_unshare_command()
    test_unshare_syscall()
    print()

    # Test bypass
    test_netns_bypass()
    print()

    # Check security mechanisms
    check_apparmor()
    print()

    check_seccomp()
    test_seccomp_block_unshare()
    print()

    # BPF options
    test_bpf_hooks()
    print()

    # Summary
    log("=" * 60)
    log("Summary")
    log("=" * 60)
    print(json.dumps(results, indent=2))

    # Mitigations
    suggest_mitigations()


if __name__ == "__main__":
    main()
