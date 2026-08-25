#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SYN_SECRET 0x7F3A9C42

//maps
struct ins {
    __u8  ttl;
    __u64 last_refill_ns;
    __u32 tokens;
};

struct config {
    __u32 rate_pps;
    __u32 burst_cap;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);      // source IP
    __type(value, struct ins);     // stored TTL,etc
} ddos SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg SEC(".maps");

static __always_inline __u32 compute_syn_cookie(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport, __u32 secret)
{
    __u32 hash = secret;
    hash ^= saddr;
    hash = (hash << 5) + (hash >> 27) + sport;   // rotate-left-5 + add
    hash ^= daddr;
    hash = (hash << 5) + (hash >> 27) + dport;
    hash ^= secret;
    return hash;
}

static __always_inline __u16 csum_fold(__u32 sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline __u16 ip_checksum(struct iphdr *ip)
{
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)ip;

    ip->check = 0;

    #pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
        sum += ptr[i];
    }

    return csum_fold(sum);
}

static __always_inline __u16 tcp_checksum(struct iphdr *ip, struct tcphdr *tcp)
{
    // pseudo-header
    __u32 pseudo_hdr[3];
    pseudo_hdr[0] = ip->saddr;
    pseudo_hdr[1] = ip->daddr;
    pseudo_hdr[2] = bpf_htonl((IPPROTO_TCP << 16) | sizeof(struct tcphdr));

    tcp->check = 0;

    __wsum csum = bpf_csum_diff((__be32 *)pseudo_hdr, sizeof(pseudo_hdr),
                                 (__be32 *)tcp, sizeof(struct tcphdr), 0);

    return csum_fold(csum);
}

SEC("xdp")
int ttl_prog(struct xdp_md *ctx)
{
    struct iphdr  *ip;
    struct ethhdr *eth;
    struct tcphdr *tcp;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    ip = (void *)eth + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return XDP_DROP;
    }

    tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp +1) > data_end){
        return XDP_DROP;
    }

    __u32 src_ip = ip->saddr;
    __u8  ttl    = ip->ttl;
    __u8  proto  = ip->protocol;

if (proto == IPPROTO_TCP) {
    if (!tcp->syn && !tcp->ack){
            return XDP_PASS;
    }

    if (tcp->syn && !tcp->ack) {
        __u32 cookie = compute_syn_cookie(ip->saddr, tcp->source, ip->daddr, tcp->dest, SYN_SECRET);
        __u32 incoming_seq = tcp->seq;

        //mac swap
        unsigned char tmp_mac[ETH_ALEN];
        __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

        //ip swap
        __u32 tmp = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp;

        //port swap
        __u16 tmp_port = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = tmp_port;

        //seq ass
        tcp->seq = bpf_htonl(cookie);

        tcp->ack_seq = bpf_htonl(bpf_ntohl(incoming_seq) + 1);
        tcp->ack = 1;

        tcp->doff = 5;
        ip->tot_len = bpf_htons((ip->ihl * 4) + sizeof(struct tcphdr));

        ip->check  = ip_checksum(ip);
        tcp->check = tcp_checksum(ip, tcp);
        return XDP_TX;
       }

    if (tcp->ack && !tcp->syn) {
          __u32 recomputed = compute_syn_cookie(ip->saddr, tcp->source, ip->daddr, tcp->dest, SYN_SECRET);
                if (bpf_ntohl(tcp->ack_seq) != recomputed + 1) {
                    return XDP_DROP;
                }
                return XDP_PASS;
      }
    if (tcp->syn && tcp->ack) {
        return XDP_DROP;
      }
}

if (ip->protocol == IPPROTO_UDP){
    __u32 cfg_key = 0;
    struct config *thing = bpf_map_lookup_elem(&cfg, &cfg_key);
    if(!thing){
       return XDP_PASS;
    }

    struct ins *t2 = bpf_map_lookup_elem(&ddos, &src_ip);
    struct ins *udp_entry = bpf_map_lookup_elem(&ddos, &src_ip);
    if (!udp_entry) {
        __u64 now = bpf_ktime_get_ns();
        struct ins new_entry = {
            .ttl           = ttl,
            .tokens        = thing->burst_cap - 1,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&ddos, &src_ip, &new_entry, BPF_ANY);
        return XDP_PASS;
    }
}

if (ip->protocol == IPPROTO_ICMP){
    return XDP_PASS;
}

struct ins *ips = bpf_map_lookup_elem(&ddos, &src_ip);
    if (!ips) {
        struct ins new_entry = { .ttl = ttl, .tokens = 0, .last_refill_ns = 0 };
        bpf_map_update_elem(&ddos, &src_ip, &new_entry, BPF_ANY);
        return XDP_PASS;
    }
    if (ips->ttl != ttl) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
