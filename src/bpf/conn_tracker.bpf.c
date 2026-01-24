// SPDX-License-Identifier: GPL-2.0
//
// conn_tracker.bpf.c - Track connections to PID mapping for egress firewall
//
// Provides 4-tuple→PID correlation for mitmproxy to attribute connections
// to processes. IPv4 only - all IPv6 is blocked to force apps through
// the transparent proxy (IPv6 would bypass iptables REDIRECT).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// ============================================
// Data structures
// ============================================

struct conn_key_v4 {
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  protocol;
    u8  pad[3];
} __attribute__((packed));

// ============================================
// Maps
// ============================================

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct conn_key_v4);
    __type(value, u32);
    __uint(max_entries, 65536);
} conn_to_pid_v4 SEC(".maps");

// ============================================
// IPv6 blocking
// ============================================
// Block ALL IPv6 connections (including IPv4-mapped ::ffff:x.x.x.x).
// This forces apps to use AF_INET sockets, which go through our
// transparent proxy via iptables REDIRECT.

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx) {
    return 0;  // Block
}

SEC("cgroup/sendmsg6")
int block_sendmsg6(struct bpf_sock_addr *ctx) {
    return 0;  // Block
}

// ============================================
// TCP: cgroup/connect4 (IPv4 only)
// ============================================
// We use cgroup/connect4 attached to the root cgroup (/sys/fs/cgroup).
// Root cgroup hooks catch ALL processes including containers.
//
// Unlike UDP (where src_port is 0 at connect time), TCP's source port
// is assigned during connect() before the cgroup hook fires.

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx) {
    // Only track TCP (UDP is handled by kprobe)
    if (ctx->protocol != IPPROTO_TCP)
        return 1;

    u16 src_port = ctx->sk->src_port;
    if (src_port == 0)
        return 1;

    struct conn_key_v4 key = {
        .dst_ip = ctx->user_ip4,
        .src_port = src_port,
        .dst_port = bpf_ntohl(ctx->user_port) >> 16,
        .protocol = IPPROTO_TCP,
    };
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);

    return 1;
}

// ============================================
// UDP: kprobe
// ============================================
// We use kprobe instead of cgroup hooks for UDP because:
//
// 1. cgroup/sendmsg4 doesn't work for connected UDP sockets.
//    When send() is called without a destination (connected socket),
//    user_ip4 is 0. We tried falling back to ctx->sk but it doesn't
//    contain the connected destination.
//
// 2. cgroup/connect4 can't help because at connect() time for UDP,
//    the socket isn't bound yet - src_port is 0. The ephemeral port
//    is only assigned when actually sending data.
//
// 3. Dual-hook approach (connect4 stores cookie->dest, sendmsg4 completes)
//    was tested but TCP tracking broke for host processes while Docker
//    containers still worked. Root cause unknown.
//
// The kprobe fires after the socket is bound and has access to both
// msg_name (for sendto) and socket state (for connected sockets).

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!sk)
        return 0;

    // Only track IPv4 (IPv6 is blocked by cgroup/sendmsg6)
    u16 family;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    u16 src_port;
    BPF_CORE_READ_INTO(&src_port, sk, __sk_common.skc_num);
    if (src_port == 0)
        return 0;

    u32 dst_ip = 0;
    u16 dst_port = 0;

    // Get destination from msg_name (unconnected) or socket (connected)
    struct sockaddr_in *sin = NULL;
    if (msg)
        BPF_CORE_READ_INTO(&sin, msg, msg_name);

    if (sin) {
        bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), &sin->sin_addr.s_addr);
        bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sin->sin_port);
    } else {
        BPF_CORE_READ_INTO(&dst_ip, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
    }

    if (dst_ip == 0)
        return 0;

    struct conn_key_v4 key = {
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = bpf_ntohs(dst_port),
        .protocol = IPPROTO_UDP,
    };
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
