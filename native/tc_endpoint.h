#ifndef SB_TC_ENDPOINT_H
#define SB_TC_ENDPOINT_H

#define TCP_FLAG_ACK 0x10U

#define SB_TC_FLAG_ENDPOINT_ENABLED (1U << 31)
#define SB_TC_FLAG_ENDPOINT_READY (1U << 30)

struct sb_tc_endpoint_flow_value {
    __u64 socket_cookie;
    __u8 intercept;
    __u8 reserved[7];
};
_Static_assert(sizeof(struct sb_tc_endpoint_flow_value) == 16, "sb_tc_endpoint_flow_value ABI size");

MAP(tc_endpoint_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_endpoint_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_endpoint_port, struct sb_tc_port_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_endpoint_flow, struct sb_tc_assign_key, struct sb_tc_endpoint_flow_value, BPF_MAP_TYPE_LRU_HASH, 8192U);

INLINE bool endpoint_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow) {
    if ((control->flags & SB_TC_FLAG_ENDPOINT_ENABLED) == 0U) return false;
    struct sb_tc_port_key port_key = {.protocol = flow->protocol, .port = flow->destination_port};
    if (map_lookup(&tc_endpoint_port, &port_key) == 0) return false;
    if (flow->family == AF_INET_VALUE) {
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->destination_addr, 4U);
        return map_lookup(&tc_endpoint_ipv4, &key) != 0;
    }
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->destination_addr, 16U);
    return map_lookup(&tc_endpoint_ipv6, &key) != 0;
}

INLINE bool endpoint_intercepted(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, __u8 tcp_flags, __u64 socket_cookie) {
    __u8 intercept = (control->flags & SB_TC_FLAG_ENDPOINT_READY) == 0U ? 1U : 0U;
    if (flow->protocol != IPPROTO_TCP_VALUE) return intercept != 0U;
    struct sb_tc_endpoint_flow_value *pinned = map_lookup(&tc_endpoint_flow, flow);
    if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) != TCP_FLAG_SYN) {
        if (pinned != 0) return pinned->intercept != 0U;
        // Without a pinned entry, intercept only if the flow is already assigned to the listener.
        return map_lookup(&tc_assignment, flow) != 0;
    }
    if (pinned != 0 && socket_cookie != 0U && pinned->socket_cookie == socket_cookie) {
        return pinned->intercept != 0U;
    }
    struct sb_tc_endpoint_flow_value value = {.socket_cookie = socket_cookie, .intercept = intercept};
    map_update(&tc_endpoint_flow, flow, &value, BPF_ANY);
    return intercept != 0U;
}

#endif
