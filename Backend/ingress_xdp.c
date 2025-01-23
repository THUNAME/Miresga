#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
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

SEC("xdp")
int ingress_xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if((void*)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    if(eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if((void*)(ip + 1) > data_end) {
        return XDP_DROP;
    }

    if(ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if((void*)(tcp + 1) > data_end) {
        return XDP_DROP;
    }

    struct key_t key = {
        .ip = ip->saddr,
        .port = tcp->source,
        .padding = 0
    };

    __u32 *diff = bpf_map_lookup_elem(&flow_map, &key);
    __u32 csum = ~((__u32)tcp->check);
    __u32 new_ack = 0;
    __u8 *opt = (__u8*)(tcp + 1);

    if(diff) {
        if(DEBUG) bpf_printk("Ingress:find diff\n");
        new_ack = bpf_htonl(bpf_ntohl(tcp->ack_seq) + *diff);
        if(DEBUG) bpf_printk("Ingress: checksum: %u\n", tcp->check);
        csum = bpf_csum_diff(&tcp->ack_seq, sizeof(tcp->ack_seq), &new_ack, sizeof(new_ack), csum);
        tcp->ack_seq = new_ack;
        if(tcp->doff > 5) {
            if(DEBUG) bpf_printk("Ingress:find options\n");

            if((void*)(opt + 1) > data_end) {
                return XDP_DROP;
            }

            if(*opt == 1) {
                opt++;
            }

            else if(*opt != 5){
                goto out;
            }

            else {
                goto sack_out;
            }

            if((void*)(opt + 1) > data_end) {
                return XDP_DROP;
            }

            if(*opt == 1) {
                opt++;
            }
            else if(*opt != 5){
                goto out;
            }
            else {
                goto sack_out;
            }

            if((void*)(opt + 1) > data_end) {
                return XDP_DROP;
            }

            if(*opt != 5) {
                goto out;
            }
            else {
                goto sack_out;
            }
        }
        else {
            goto out;
        }

        if(tcp->rst) {
            if(DEBUG) bpf_printk("Ingress: find RST\n");
            bpf_map_delete_elem(&flow_map, &key);
            bpf_map_delete_elem(&seq_map, &key);
        }
        goto out;
    }
    else {
        if(!tcp->syn) {
            return XDP_PASS;
        }
        if(DEBUG) bpf_printk("Ingress: find new flow\n");

        bpf_map_update_elem(&seq_map, &key, &tcp->ack_seq, BPF_ANY);
        new_ack = 0;
        csum = bpf_csum_diff(&tcp->ack_seq, sizeof(tcp->ack_seq), &new_ack, sizeof(new_ack), csum);
        tcp->ack_seq = 0;
        goto out;
    }
sack_out: {
        if((void*)(opt + 2) > data_end) {
            return XDP_DROP;
        }

        __u8 len = *(opt + 1);
        __u32 *sack = (__u32*)(opt + 2);
        if(DEBUG) bpf_printk("Ingress: find SACK\n");

        // TODO: Maybe we can use loop here
        if(len >= 10) {
            if((void*)(sack + 2) > data_end) {
                return XDP_DROP;
            }
            new_ack = bpf_htonl(bpf_ntohl(*sack) + *diff);
            csum = bpf_csum_diff(sack, sizeof(*sack), &new_ack, sizeof(new_ack), csum);
            *sack = new_ack;
            sack++;
            new_ack = bpf_htonl(bpf_ntohl(*sack) + *diff);
            csum = bpf_csum_diff(sack, sizeof(*sack), &new_ack, sizeof(new_ack), csum);
            *sack = new_ack;
            sack++;
            len -= 8;
        }
        if(len >= 10) {
            if((void*)(sack + 2) > data_end) {
                return XDP_DROP;
            }
            new_ack = bpf_htonl(bpf_ntohl(*sack) + *diff);
            csum = bpf_csum_diff(sack, sizeof(*sack), &new_ack, sizeof(new_ack), csum);
            *sack = new_ack;
            sack++;
            new_ack = bpf_htonl(bpf_ntohl(*sack) + *diff);
            csum = bpf_csum_diff(sack, sizeof(*sack), &new_ack, sizeof(new_ack), csum);
            *sack = new_ack;
            sack++;
            len -= 8;
        }
        if(len >= 10) {
            if((void*)(sack + 2) > data_end) {
                return XDP_DROP;
            }
            new_ack = bpf_htonl(bpf_ntohl(*sack) + *diff);
            csum = bpf_csum_diff(sack, sizeof(*sack), &new_ack, sizeof(new_ack), csum);
            *sack = new_ack;
            sack++;
            new_ack = bpf_htonl(bpf_ntohl(*sack) + *diff);
            csum = bpf_csum_diff(sack, sizeof(*sack), &new_ack, sizeof(new_ack), csum);
            *sack = new_ack;
            sack++;
            len -= 8;
        }
        if(len >= 10) {
            if((void*)(sack + 2) > data_end) {
                return XDP_DROP;
            }
            new_ack = bpf_htonl(bpf_ntohl(*sack) + *diff);
            csum = bpf_csum_diff(sack, sizeof(*sack), &new_ack, sizeof(new_ack), csum);
            *sack = new_ack;
            sack++;
            new_ack = bpf_htonl(bpf_ntohl(*sack) + *diff);
            csum = bpf_csum_diff(sack, sizeof(*sack), &new_ack, sizeof(new_ack), csum);
            *sack = new_ack;
            sack++;
            len -= 8;
        }
        if(len != 2) {
            return XDP_DROP;
        }
    }
out:
    tcp->check = csum_folder_helper(csum);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";