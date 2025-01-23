#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#define DEBUG 1
struct key_t {
    __u32 ip;
    __u16 port;
    __u16 padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 102400);
    __type(key, struct key_t);
    __type(value, __u32);
} seq_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 102400);
    __type(key, struct key_t);
    __type(value, __u32);
} flow_map SEC(".maps");

__always_inline __u16 csum_folder_helper(__u32 csum) {
    __u32 sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

SEC("classifier")
int egress_tc_prog(struct __sk_buff *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if((void*)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if(eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if((void*)(ip + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if(ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    if(DEBUG) bpf_printk("Egress: find TCP\n");

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if((void*)(tcp + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    struct key_t key = {
        .ip = ip->daddr,
        .port = tcp->dest,
        .padding = 0
    };

    __u32 *diff = bpf_map_lookup_elem(&flow_map, &key);
    __u32 csum = ~tcp->check;

    if(diff) {
        if(DEBUG) bpf_printk("Egress: find diff\n");

        __u32 new_seq = bpf_htonl(bpf_ntohl(tcp->seq) - *diff);
        csum = bpf_csum_diff(&tcp->seq, sizeof(tcp->seq), &new_seq, sizeof(new_seq), csum);
        tcp->seq = new_seq;
        if(tcp->rst) {
            if(DEBUG) bpf_printk("Egress: find RST\n");
            bpf_map_delete_elem(&flow_map, &key);
            bpf_map_delete_elem(&seq_map, &key);
        }
    }
    else {
        if(!tcp->syn || !tcp->ack) {
            return TC_ACT_OK;
        }

        __u32 *f_seq = bpf_map_lookup_elem(&seq_map, &key);
        if(!f_seq) {
            return TC_ACT_OK;
        }

        if(DEBUG) bpf_printk("Egress: find new flow\n");

        __u32 new_diff = bpf_ntohl(tcp->seq) - bpf_ntohl(*f_seq);
        bpf_map_update_elem(&flow_map, &key, &new_diff, BPF_ANY);

        if(DEBUG) bpf_printk("Egress: update diff: %d\n", new_diff);
    }
    
    tcp->check = csum_folder_helper(csum);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";