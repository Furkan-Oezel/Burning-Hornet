
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

/*=============================================*/
/*              *map config*                   */
/* type = array                                */
/* number of entries = 3                       */
/* 1. entry = ip source address                */
/* 2. entry = ip destination addres            */
/* 3. entry = setting for firewall behaviour   */
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
    __uint(max_entries, 3);
} Map SEC(".maps");

SEC("xdp_prog")
// member variables of the xdp_md struct are assigned by the NIC driver
int xdp_filter_ip_range(struct xdp_md *ctx)
{
    // declare variables to interact with the map
    __u32 key;
    __u64 *value;
    // declare variable to configure wether the firewall should be filtering
    __u64 config_number;
    // declare boundaries for ip source address filtering
    __be32 ip_range_start = htonl(0xC0A8000A); // 192.168.0.10
    __be32 ip_range_end = htonl(0xC0A8000B);   // 192.168.0.11

    // set pointers to the beginning and to the end of the arriving packet
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // eth block is the beginning of the packet
    struct ethhdr *eth = data;
    // e.g. if 0x0006 + 8 > 0x0009, then drop
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_DROP;

    // ip block starts after the eth block
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_DROP;

    __be32 src_ip = ip->saddr;
    __be32 dst_ip = ip->daddr;

    // set first entry of the map to ip source address
    // set second entry of the map to ip destination address
    if (value)
    {
        key = 0;
        *value = src_ip;
        bpf_map_update_elem(&Map, &key, value, BPF_ANY);

        key = 1;
        *value = dst_ip;
        bpf_map_update_elem(&Map, &key, value, BPF_ANY);
    }

    // retrieve firewall setting and write it into 'config_number'
    if (value)
    {
        key = 2;
        value = bpf_map_lookup_elem(&Map, &key);
        config_number = *value;
    }

    // implement firewall behaviour based on firewall setting
    switch (config_number)
    {
    case 1:
        if (src_ip >= ip_range_start && src_ip <= ip_range_end)
        {
            // do something
            return XDP_PASS;
        }
        break;
    default:
        break;
    }

    // // convert 192.168.0.10 from host byte order (little-endian) to network byte order (big-endian)
    // if (dst_ip == htonl(0xC0A8000A))
    // {
    //     // do something
    // }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";