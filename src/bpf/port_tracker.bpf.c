// SPDX-License-Identifier: GPL-2.0
//
// port_tracker.bpf.c - Track connections to PID mapping for egress firewall
//
// Provides 4-tuple→PID correlation for mitmproxy to attribute connections
// to processes. IPv4 only - all IPv6 is blocked to force apps through
// the transparent proxy (IPv6 would bypass iptables REDIRECT).
//

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
// TCP: sock_ops (IPv4 only)
// ============================================

SEC("sockops")
int handle_sockops(struct bpf_sock_ops *skops) {
    if (skops->family != AF_INET)
        return 1;
    if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
        return 1;

    u16 src_port = skops->local_port;
    if (src_port == 0)
        return 1;

    u16 dst_port = bpf_ntohs(skops->remote_port >> 16);

    struct conn_key_v4 key = {
        .dst_ip = skops->remote_ip4,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = IPPROTO_TCP,
    };
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
    return 1;
}

// ============================================
// UDP: kprobe (works for loopback too)
// ============================================

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!sk)
        return 0;

    u16 src_port;
    BPF_CORE_READ_INTO(&src_port, sk, __sk_common.skc_num);
    if (src_port == 0)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Try to get destination from msg_name first (unconnected sends)
    struct sockaddr *addr = NULL;
    if (msg)
        BPF_CORE_READ_INTO(&addr, msg, msg_name);

    if (addr) {
        // Unconnected UDP: destination is in msg_name
        u16 family;
        bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family);

        if (family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            u32 dst_ip;
            u16 dst_port;
            bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), &sin->sin_addr.s_addr);
            bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sin->sin_port);

            struct conn_key_v4 key = {
                .dst_ip = dst_ip,
                .src_port = src_port,
                .dst_port = bpf_ntohs(dst_port),
                .protocol = IPPROTO_UDP,
            };
            bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
        }
        // IPv6 ignored - blocked by cgroup/sendmsg6
    } else {
        // Connected UDP: destination is in the socket
        u16 family;
        BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

        if (family == AF_INET) {
            u32 dst_ip;
            u16 dst_port;
            BPF_CORE_READ_INTO(&dst_ip, sk, __sk_common.skc_daddr);
            BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);

            if (dst_ip == 0)
                return 0;

            struct conn_key_v4 key = {
                .dst_ip = dst_ip,
                .src_port = src_port,
                .dst_port = bpf_ntohs(dst_port),
                .protocol = IPPROTO_UDP,
            };
            bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
        }
        // IPv6 ignored - blocked by cgroup/sendmsg6
    }

    return 0;
}

// ============================================
// UDP: sendmsg4 (cgroup, for non-loopback)
// ============================================

SEC("cgroup/sendmsg4")
int handle_sendmsg4(struct bpf_sock_addr *ctx) {
    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    u16 src_port = sk->src_port;
    if (src_port == 0)
        return 1;

    struct conn_key_v4 key = {
        .dst_ip = ctx->user_ip4,
        .src_port = src_port,
        .dst_port = bpf_ntohs(ctx->user_port),
        .protocol = IPPROTO_UDP,
    };
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
