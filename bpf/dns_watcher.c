#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"

#define DNS_PORT 53

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} dns_ringbuf SEC(".maps");


SEC("xdp")
int capture_dns(xdp_md_t *ctx) {
    void *data_end = (void *)ctx->data_end;
    void *data = (void *)ctx->data;
    ETHERNET_HEADER *eth = data;
    IPV4_HEADER *ip;
    UDP_HEADER *udp;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    if (udp->srcPort != htons(DNS_PORT))
        return XDP_PASS;

    // Copy the DNS packet to the ring buffer
    int len = ctx->data_end - ctx->data;
    bpf_ringbuf_output(&dns_ringbuf, data, len, 0);

    return XDP_PASS;
}

