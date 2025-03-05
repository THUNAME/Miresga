origin_iface=$1
new_iface="${origin_iface}np0v0"
echo 1 | tee /sys/class/net/${origin_iface}/device/sriov_numvfs
ifconfig ${new_iface} up
ifconfig ${new_iface} $2
arp -s $3 00:02:00:00:03:00 -i ${new_iface}
