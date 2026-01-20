// SPDX-License-Identifier: GPL-2.0
//
// ipv6_blocker.bpf.c - Block native IPv6 connections
//
// Security-focused: blocks native IPv6 to simplify threat analysis
// (IPv6 has less threat intel coverage). IPv4-mapped addresses are allowed.
//

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Check if IPv6 address is v4-mapped (::ffff:x.x.x.x)
#define IS_V4_MAPPED(ip6_0, ip6_1, ip6_2) \
    ((ip6_0) == 0 && (ip6_1) == 0 && (ip6_2) == bpf_htonl(0x0000ffff))

// ============================================
// TCP: connect6
// ============================================

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx) {
    // v4-mapped: allow
    if (IS_V4_MAPPED(ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2]))
        return 1;

    // Native IPv6: block
    return 0;
}

// ============================================
// UDP: sendmsg6
// ============================================

SEC("cgroup/sendmsg6")
int block_sendmsg6(struct bpf_sock_addr *ctx) {
    // v4-mapped: allow
    if (IS_V4_MAPPED(ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2]))
        return 1;

    // Native IPv6: block
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
