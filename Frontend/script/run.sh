echo 1 | tee /sys/class/net/enp197s0f1np1/device/sriov_numvfs
echo 1 | tee /sys/class/net/enp173s0f0np0/device/sriov_numvfs
ip netns add frontend_1
ip netns add frontend_2
ip link set enp197s0f1np1 netns frontend_1
ip link set enp197s0f1v0  netns frontend_1
ip link set enp173s0f0np0 netns frontend_2
ip link set enp173s0f0v0  netns frontend_2
ip netns exec frontend_1 ifconfig enp197s0f1np1 up
ip netns exec frontend_2 ifconfig enp173s0f0np0 up
ip netns exec frontend_1 ifconfig enp197s0f1v0 up
ip netns exec frontend_2 ifconfig enp173s0f0v0 up
ip netns exec frontend_1 ifconfig enp197s0f1v0 10.0.1.252/24
ip netns exec frontend_2 ifconfig enp173s0f0v0 10.0.1.253/24
ip netns exec frontend_1 arp -s 10.0.1.254 00:02:00:00:03:00 -i enp197s0f1v0
ip netns exec frontend_2 arp -s 10.0.1.254 00:02:00:00:03:00 -i enp173s0f0v0
ip netns exec frontend_1 ip route add default via 10.0.1.1
ip netns exec frontend_2 ip route add default via 10.0.1.1
