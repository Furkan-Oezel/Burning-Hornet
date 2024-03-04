
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
// add struct tcphdr
#include <linux/tcp.h>

/*=============================================*/
/*              *map config*                   */
/* type = array                                */
/* number of entries = 5                       */
/* 1. entry = ip source address                */
/* 2. entry = lower ip boundary (source)       */
/* 3. entry = upper ip boundary (source)       */
/* 4. entry = setting for firewall behaviour   */
/* 5. entry = number of received packets       */
/*=============================================*/
struct
{
    // declare pointer called 'type' that points to a int array of the size 'BPF_MAP_TYPE_ARRAY' (2)
    __uint(type, BPF_MAP_TYPE_ARRAY);
    // declare pointer called 'key' that is of the type '__u32'
    __type(key, __u32);
    // declare pointer called 'value' that is of the type '__u64'
    __type(value, __u64);
    // declare pointer called 'max_entries' that points to a int array of the size 3
    __uint(max_entries, 5);
} Map SEC(".maps");

SEC("xdp_prog")
// member variables of the xdp_md struct are assigned by the NIC driver
int xdp_filter_ip_range(struct xdp_md *ctx)
{
    // declare variables to interact with the map
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&Map, &key);
    // declare ip boundaries for source address
    __u64 lower_ip_boundary = 0;
    __u64 upper_ip_boundary = 0;
    // declare variable to configure the behaviour of the firewall
    __u64 config_number = 0;

    // set pointers to the beginning and to the end of the arriving packet
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // eth block is the beginning of the packet
    struct ethhdr *eth = data;
    // e.g. if 0x0006 + 8 > 0x0009, then drop
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return XDP_DROP;
    }

    // ip block starts after the eth block
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(*ip) > data_end)
    {
        return XDP_DROP;
    }
    __u32 src_ip = ip->saddr;
    __u64 dst_ip = ip->daddr;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    __be16 src_port = tcp->source;
    __be16 dst_port = tcp->dest;

    // retrieve lower ip boundary from map
    key = 1;
    value = bpf_map_lookup_elem(&Map, &key);
    if (value)
    {
        lower_ip_boundary = *value;
    }

    // retrieve upper ip boundary from map
    key = 2;
    value = bpf_map_lookup_elem(&Map, &key);
    if (value)
    {
        upper_ip_boundary = *value;
    }

    // retrieve firewall setting and write it into 'config_number'
    key = 3;
    value = bpf_map_lookup_elem(&Map, &key);
    if (value)
    {
        config_number = *value;
    }

    // implement firewall behaviour based on firewall setting
    switch (config_number)
    {
    case 1:
        if (src_ip >= lower_ip_boundary && src_ip <= upper_ip_boundary)
        {
            // store packet ip source address into the first entry of the map
            key = 0;
            value = bpf_map_lookup_elem(&Map, &key);
            if (value)
            {
                *value = src_ip;
            }
            if (value)
            {
                bpf_map_update_elem(&Map, &key, value, BPF_ANY);
            }

            // count accepted packets
            key = 4;
            value = bpf_map_lookup_elem(&Map, &key);
            if (value)
            {
                *value = *value + 1;
            }
            if (value)
            {
                bpf_map_update_elem(&Map, &key, value, BPF_ANY);
            }
            return XDP_PASS;
        }
        else
        {
            return XDP_DROP;
        }
        break;
    default:
        break;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";