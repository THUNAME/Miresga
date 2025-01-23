#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

#define XDP_FLAGS XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE

int main(int argc, char **argv) {
    const char *ingress_filename = "ingress_xdp.o", *egress_filename = "egress_tc.o";
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index for %s: %s\n", ifname, strerror(errno));
        return 1;
    }
    
    struct bpf_object *ingress_obj = bpf_object__open_file(ingress_filename, NULL);
    if (libbpf_get_error(ingress_obj)) {
        fprintf(stderr, "Failed to open ingress BPF object file: %s\n", strerror(errno));
        return 1;
    }

    if (bpf_object__load(ingress_obj)) {
        fprintf(stderr, "Failed to load ingress BPF object file: %s\n", strerror(errno));
        bpf_object__close(ingress_obj);
        return 1;
    }

    struct bpf_program *ingress_prog = bpf_object__find_program_by_title(ingress_obj, "xdp");
    if (!ingress_prog) {
        fprintf(stderr, "Failed to find ingress BPF program in object file\n");
        bpf_object__close(ingress_obj);
        return 1;
    }

    int ingress_prog_fd = bpf_program__fd(ingress_prog);
    if (ingress_prog_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for ingress BPF program\n");
        bpf_object__close(ingress_obj);
        return 1;
    }

    if (bpf_set_link_xdp_fd(ifindex, ingress_prog_fd, XDP_FLAGS) < 0) {
        fprintf(stderr, "Failed to attach ingress XDP program to interface %s: %s\n", ifname, strerror(errno));
        bpf_object__close(ingress_obj);
        return 1;
    }

    // Pin maps
    struct bpf_map *ingress_flow_map = bpf_object__find_map_by_name(ingress_obj, "flow_map");
    if(!ingress_flow_map) {
        fprintf(stderr, "Failed to find ingress BPF map in object file\n");
        bpf_object__close(ingress_obj);
        return 1;
    }

    if(bpf_map__pin(ingress_flow_map, "/sys/fs/bpf/flow_map") < 0) {
        fprintf(stderr, "Failed to pin ingress BPF map\n");
        bpf_object__close(ingress_obj);
        return 1;
    }

    struct bpf_map *ingress_seq_map = bpf_object__find_map_by_name(ingress_obj, "seq_map");
    if(!ingress_seq_map) {
        fprintf(stderr, "Failed to find seq BPF map in object file\n");
        bpf_object__close(ingress_obj);
        return 1;
    }

    if(bpf_map__pin(ingress_seq_map, "/sys/fs/bpf/seq_map") < 0) {
        fprintf(stderr, "Failed to pin ingress BPF map\n");
        bpf_object__close(ingress_obj);
        return 1;
    }

    printf("Successfully loaded and attached XDP program to interface %s\n", ifname);
    
    struct bpf_object *egress_obj = bpf_object__open_file("egress_tc.o", NULL);
    if (libbpf_get_error(egress_obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(errno));

        return 1;
    }

    struct bpf_map *egress_flow_map = bpf_object__find_map_by_name(egress_obj, "flow_map");
    if(!egress_flow_map) {
        fprintf(stderr, "Failed to find BPF map in object file\n");
        bpf_object__close(ingress_obj);
        bpf_object__close(egress_obj);
        return 1;
    }

    // Link the ingress flow map to the egress flow map
    int flow_map_fd = bpf_obj_get("/sys/fs/bpf/flow_map");
    if(flow_map_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for BPF map\n");
        bpf_object__close(ingress_obj);
        bpf_object__close(egress_obj);
        return 1;
    }
    
    if(bpf_map__reuse_fd(egress_flow_map, flow_map_fd))
    {
        fprintf(stderr, "Failed to reuse file descriptor for BPF map\n");
        bpf_object__close(ingress_obj);
        bpf_object__close(egress_obj);
        return 1;
    }
    
    struct bpf_map *egress_seq_map = bpf_object__find_map_by_name(egress_obj, "seq_map");
    if(!egress_seq_map) {
        fprintf(stderr, "Failed to find BPF map in object file\n");
        bpf_object__close(ingress_obj);
        bpf_object__close(egress_obj);
        return 1;
    }
    
    int seq_map_fd = bpf_obj_get("/sys/fs/bpf/seq_map");
    if(seq_map_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for BPF map\n");
        bpf_object__close(ingress_obj);
        bpf_object__close(egress_obj);
        return 1;
    }

    if(bpf_map__reuse_fd(egress_seq_map, seq_map_fd))
    {
        fprintf(stderr, "Failed to reuse file descriptor for BPF map\n");
        bpf_object__close(ingress_obj);
        bpf_object__close(egress_obj);
        return 1;
    }  
    if(bpf_object__load(egress_obj)) {
        fprintf(stderr, "Failed to load BPF object file: %s\n", strerror(errno));
        bpf_object__close(egress_obj);
        return 1;
    }

    struct bpf_program *egress_prog = bpf_object__find_program_by_title(egress_obj, "classifier");
    if(!egress_prog) {
        fprintf(stderr, "Failed to find BPF program in object file\n");
        bpf_object__close(egress_obj);
        return 1;
    }

    int egress_prog_fd = bpf_program__fd(egress_prog);
    if(egress_prog_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for BPF program\n");
        bpf_object__close(egress_obj);
        return 1;
    }

    struct bpf_tc_hook hook = {
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS
    };

    if(bpf_tc_hook_create(&hook) < 0) {
        fprintf(stderr, "Failed to create TC hook\n");
        return 1;
    }

    struct bpf_tc_opts opts = {
        .sz = sizeof(struct bpf_tc_opts),
        .prog_fd = egress_prog_fd,
        .flags = BPF_TC_F_REPLACE,
        .prog_id = 0,
        .priority = 1
    };

    if(bpf_tc_attach(&hook, &opts) < 0) {
        fprintf(stderr, "Failed to attach TC program to egress on interface %s: %s\n", ifname, strerror(errno));
        return 1;
    }

    printf("Successfully loaded and attached TC program to egress on interface %s\n", ifname);
    return 0;
}