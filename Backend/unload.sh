ip link set dev $1 xdp off
rm /sys/fs/bpf/flow_map
rm /sys/fs/bpf/seq_map
tc filter del dev $1 egress
tc qdisc del dev $1 clsact
