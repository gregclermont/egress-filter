// SPDX-License-Identifier: GPL-2.0
//
// port_tracker.bpf.c - Track connections to PID mapping for egress firewall
//
// Provides 4-tuple→pid correlation for mitmproxy to attribute connections
// to processes. TCP uses sock_ops, UDP uses sendmsg hooks.
//

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
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

struct conn_key_v6 {
    u32 dst_ip[4];
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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct conn_key_v6);
    __type(value, u32);
    __uint(max_entries, 16384);
} conn_to_pid_v6 SEC(".maps");

// ============================================
// Helpers
// ============================================

// Check if IPv6 address is v4-mapped (::ffff:x.x.x.x)
// Must access context fields directly to satisfy verifier
#define IS_V4_MAPPED(ip6_0, ip6_1, ip6_2) \
    ((ip6_0) == 0 && (ip6_1) == 0 && (ip6_2) == bpf_htonl(0x0000ffff))

// ============================================
// TCP: sock_ops (IPv4 + IPv6)
// ============================================

SEC("sockops")
int handle_sockops(struct bpf_sock_ops *skops) {
    u16 src_port = skops->local_port;
    if (src_port == 0)
        return 1;

    // remote_port has port in upper 16 bits, in network byte order
    u16 dst_port = bpf_ntohs(skops->remote_port >> 16);

    // ---- IPv4 ----
    if (skops->family == AF_INET) {
        if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
            return 1;

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

    // ---- IPv6 ----
    if (skops->family == AF_INET6) {
        if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
            return 1;

        // Check for v4-mapped address
        if (IS_V4_MAPPED(skops->remote_ip6[0], skops->remote_ip6[1], skops->remote_ip6[2])) {
            // Treat as IPv4
            struct conn_key_v4 key = {
                .dst_ip = skops->remote_ip6[3],
                .src_port = src_port,
                .dst_port = dst_port,
                .protocol = IPPROTO_TCP,
            };
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
            return 1;
        }

        // Native IPv6
        struct conn_key_v6 key = {
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = IPPROTO_TCP,
        };
        // Copy fields individually to satisfy verifier
        key.dst_ip[0] = skops->remote_ip6[0];
        key.dst_ip[1] = skops->remote_ip6[1];
        key.dst_ip[2] = skops->remote_ip6[2];
        key.dst_ip[3] = skops->remote_ip6[3];

        u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_map_update_elem(&conn_to_pid_v6, &key, &pid, BPF_ANY);
        return 1;
    }

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

    // Get source port from socket
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
            u16 dst_port_h = bpf_ntohs(dst_port);

            struct conn_key_v4 key = {
                .dst_ip = dst_ip,
                .src_port = src_port,
                .dst_port = dst_port_h,
                .protocol = IPPROTO_UDP,
            };
            bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
            u32 dst_ip6[4];
            u16 dst_port;
            bpf_probe_read_kernel(&dst_ip6, sizeof(dst_ip6), &sin6->sin6_addr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sin6->sin6_port);
            u16 dst_port_h = bpf_ntohs(dst_port);

            if (dst_ip6[0] == 0 && dst_ip6[1] == 0 && dst_ip6[2] == bpf_htonl(0x0000ffff)) {
                struct conn_key_v4 key = {
                    .dst_ip = dst_ip6[3],
                    .src_port = src_port,
                    .dst_port = dst_port_h,
                    .protocol = IPPROTO_UDP,
                };
                bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
            } else {
                struct conn_key_v6 key = {
                    .src_port = src_port,
                    .dst_port = dst_port_h,
                    .protocol = IPPROTO_UDP,
                };
                key.dst_ip[0] = dst_ip6[0];
                key.dst_ip[1] = dst_ip6[1];
                key.dst_ip[2] = dst_ip6[2];
                key.dst_ip[3] = dst_ip6[3];
                bpf_map_update_elem(&conn_to_pid_v6, &key, &pid, BPF_ANY);
            }
        }
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

            u16 dst_port_h = bpf_ntohs(dst_port);
            struct conn_key_v4 key = {
                .dst_ip = dst_ip,
                .src_port = src_port,
                .dst_port = dst_port_h,
                .protocol = IPPROTO_UDP,
            };
            bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
        } else if (family == AF_INET6) {
            u32 dst_ip6[4];
            u16 dst_port;
            BPF_CORE_READ_INTO(&dst_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);

            if (dst_ip6[0] == 0 && dst_ip6[1] == 0 && dst_ip6[2] == 0 && dst_ip6[3] == 0)
                return 0;

            u16 dst_port_h = bpf_ntohs(dst_port);
            if (dst_ip6[0] == 0 && dst_ip6[1] == 0 && dst_ip6[2] == bpf_htonl(0x0000ffff)) {
                struct conn_key_v4 key = {
                    .dst_ip = dst_ip6[3],
                    .src_port = src_port,
                    .dst_port = dst_port_h,
                    .protocol = IPPROTO_UDP,
                };
                bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
            } else {
                struct conn_key_v6 key = {
                    .src_port = src_port,
                    .dst_port = dst_port_h,
                    .protocol = IPPROTO_UDP,
                };
                key.dst_ip[0] = dst_ip6[0];
                key.dst_ip[1] = dst_ip6[1];
                key.dst_ip[2] = dst_ip6[2];
                key.dst_ip[3] = dst_ip6[3];
                bpf_map_update_elem(&conn_to_pid_v6, &key, &pid, BPF_ANY);
            }
        }
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

    u16 dst_port_h = bpf_ntohs(ctx->user_port);
    struct conn_key_v4 key = {
        .dst_ip = ctx->user_ip4,
        .src_port = src_port,
        .dst_port = dst_port_h,
        .protocol = IPPROTO_UDP,
    };
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
    return 1;
}

// ============================================
// UDP: sendmsg6
// ============================================

SEC("cgroup/sendmsg6")
int handle_sendmsg6(struct bpf_sock_addr *ctx) {
    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    u16 src_port = sk->src_port;
    if (src_port == 0)
        return 1;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 dst_port_h = bpf_ntohs(ctx->user_port);

    // Check for IPv4-mapped address
    if (IS_V4_MAPPED(ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2])) {
        struct conn_key_v4 key = {
            .dst_ip = ctx->user_ip6[3],
            .src_port = src_port,
            .dst_port = dst_port_h,
            .protocol = IPPROTO_UDP,
        };
        bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);
        return 1;
    }

    // Native IPv6
    struct conn_key_v6 key = {
        .src_port = src_port,
        .dst_port = dst_port_h,
        .protocol = IPPROTO_UDP,
    };
    // Copy fields individually to satisfy verifier
    key.dst_ip[0] = ctx->user_ip6[0];
    key.dst_ip[1] = ctx->user_ip6[1];
    key.dst_ip[2] = ctx->user_ip6[2];
    key.dst_ip[3] = ctx->user_ip6[3];
    bpf_map_update_elem(&conn_to_pid_v6, &key, &pid, BPF_ANY);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
