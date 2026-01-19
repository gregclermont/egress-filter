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

struct conn_info {
    u32 pid;
    u32 _pad;
    u64 timestamp_ns;
    char comm[16];
};

// ============================================
// Maps
// ============================================

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct conn_key_v4);
    __type(value, struct conn_info);
    __uint(max_entries, 65536);
} conn_to_pid_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct conn_key_v6);
    __type(value, struct conn_info);
    __uint(max_entries, 16384);
} conn_to_pid_v6 SEC(".maps");

// ============================================
// Helpers
// ============================================

static __always_inline void fill_conn_info(struct conn_info *info) {
    info->pid = bpf_get_current_pid_tgid() >> 32;
    info->timestamp_ns = bpf_ktime_get_ns();
    // Note: bpf_get_current_comm not available in sock_ops on some kernels
    // Userspace can look up comm via /proc/[pid]/comm
}

static __always_inline bool is_v4_mapped(u32 *ip6) {
    // ::ffff:x.x.x.x
    return ip6[0] == 0 &&
           ip6[1] == 0 &&
           ip6[2] == bpf_htonl(0x0000ffff);
}

// ============================================
// TCP: sock_ops (IPv4 + IPv6)
// ============================================

SEC("sockops")
int handle_sockops(struct bpf_sock_ops *skops) {
    u16 src_port = skops->local_port;
    if (src_port == 0)
        return 1;

    u16 dst_port = bpf_ntohl(skops->remote_port) >> 16;

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
        struct conn_info info = {};
        fill_conn_info(&info);
        bpf_map_update_elem(&conn_to_pid_v4, &key, &info, BPF_ANY);
        return 1;
    }

    // ---- IPv6 ----
    if (skops->family == AF_INET6) {
        if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
            return 1;

        // Check for v4-mapped address
        if (is_v4_mapped(skops->remote_ip6)) {
            // Treat as IPv4
            struct conn_key_v4 key = {
                .dst_ip = skops->remote_ip6[3],
                .src_port = src_port,
                .dst_port = dst_port,
                .protocol = IPPROTO_TCP,
            };
            struct conn_info info = {};
            fill_conn_info(&info);
            bpf_map_update_elem(&conn_to_pid_v4, &key, &info, BPF_ANY);
            return 1;
        }

        // Native IPv6
        struct conn_key_v6 key = {
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = IPPROTO_TCP,
        };
        __builtin_memcpy(key.dst_ip, skops->remote_ip6, 16);

        struct conn_info info = {};
        fill_conn_info(&info);
        bpf_map_update_elem(&conn_to_pid_v6, &key, &info, BPF_ANY);
        return 1;
    }

    return 1;
}

// ============================================
// UDP: sendmsg4
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

    struct conn_info info = {};
    fill_conn_info(&info);

    bpf_map_update_elem(&conn_to_pid_v4, &key, &info, BPF_ANY);
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

    struct conn_info info = {};
    fill_conn_info(&info);

    // Check for IPv4-mapped address
    if (is_v4_mapped(ctx->user_ip6)) {
        struct conn_key_v4 key = {
            .dst_ip = ctx->user_ip6[3],
            .src_port = src_port,
            .dst_port = bpf_ntohs(ctx->user_port),
            .protocol = IPPROTO_UDP,
        };
        bpf_map_update_elem(&conn_to_pid_v4, &key, &info, BPF_ANY);
        return 1;
    }

    // Native IPv6
    struct conn_key_v6 key = {
        .src_port = src_port,
        .dst_port = bpf_ntohs(ctx->user_port),
        .protocol = IPPROTO_UDP,
    };
    __builtin_memcpy(key.dst_ip, ctx->user_ip6, 16);
    bpf_map_update_elem(&conn_to_pid_v6, &key, &info, BPF_ANY);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
