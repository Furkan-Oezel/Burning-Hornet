
//go:build ignore

// add XDP stuff and some bpf stuff (e.g. BPF_MAP_TYPE_ARRAY)
#include <linux/bpf.h>
// add bpf helper functions (e.g bpf_map_lookup_elem(), bpf_map_update_elem())
#include <bpf/bpf_helpers.h>
// add struct ethhdr
#include <linux/if_ether.h>
// add struct iphdr
#include <linux/ip.h>
// add functions for network byte order conversions (htonl(), htons(), ntohl(), ntohs())
#include <netinet/in.h>

#include <linux/tcp.h>

struct
{
    // declare pointer called 'type' that points to a int array of the size 'BPF_MAP_TYPE_ARRAY' (2)
    __uint(type, BPF_MAP_TYPE_ARRAY);
    // declare pointer called 'key' that is of the type '__u32'
    __type(key, __u32);
    // declare pointer called 'value' that is of the type '__u64'
    __type(value, __u64);
    // declare pointer called 'max_entries' that points to a int array of the size 1
    __uint(max_entries, 1);
} Map SEC(".maps");

SEC("xdp_prog")
// data of the member variables of the xdp_md struct are assigned by the NIC driver
int xdp_filter_ip_range(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    // e.g. if 0x000A + 0x0005 > 0x0009, then drop
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_DROP;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_DROP;

    __be32 src_ip = ip->saddr;
    __be32 dst_ip = ip->daddr;
    __be32 ip_range_start = htonl(0xC0A80101);
    __be32 ip_range_end = htonl(0xC0A801FF);

    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&Map, &key);
    // if (value)
    // {
    // *value = src_ip;
    // bpf_map_update_elem(&Map, &key, value, BPF_ANY);
    // }

        if (value)
        {
            *value = dst_ip;
            bpf_map_update_elem(&Map, &key, value, BPF_ANY);
            if(dst_ip == htonl(0xC0A8000A)){

            *value = 4;
            bpf_map_update_elem(&Map, &key, value, BPF_ANY);
            }
            return XDP_PASS;
        }

    //  struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    //  __u16 src_port = tcp->source;
    //  if ((void *)(tcp + 1) > data_end)
    //      return XDP_DROP;
    //  if (value)
    //  {
    //      *value = src_port;
    //      bpf_map_update_elem(&Map, &key, value, BPF_ANY);
    //  }

   // if (value)
   // {
   //     *value = eth->h_dest[5];
   // }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";