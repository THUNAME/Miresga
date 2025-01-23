.PHONY: all clean ingress egress loader
CC_XDP = clang
CC = gcc
BUILD_DIR = build

all: ingress egress loader

ingress: ingress_xdp.c
	@mkdir -p $(BUILD_DIR)
	$(CC_XDP) -O2 -g -target bpf -c ingress_xdp.c -o $(BUILD_DIR)/ingress_xdp.o

egress: egress_tc.c
	@mkdir -p $(BUILD_DIR)
	$(CC_XDP) -O2 -g -target bpf -c egress_tc.c -o $(BUILD_DIR)/egress_tc.o

loader: xdp_loader.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) xdp_loader.c -o $(BUILD_DIR)/xdp_loader -lbpf

clean:
	rm -rf $(BUILD_DIR)