import json

ingress_prefix = "SwitchIngress."
egress_prefix = "SwitchEgress."

with open("config.json", "r") as f:
    config = json.load(f)

arp_table_config = {}
arp_table_config["table_name"] = ingress_prefix + "arp_table"
arp_table_config["key_names"] = [
    {"name": "hdr.arp.opcode", "match_type": "exact"},
    {"name": "hdr.arp.target_proto_addr", "match_type": "exact"}
]
arp_table_config["actions"] = [{"action_name": ingress_prefix + "reply_arp", "data_names": ["arp_mac"]}]
arp_table_config["initial_entries"] = [
    {
        "keys": [
            {"name": "hdr.arp.opcode", "value": 1, "match_type": "exact"},
            {"name": "hdr.arp.target_proto_addr", "value": {"raw": config["client_gateway"], "type": "ipv4"}, "match_type": "exact"}
        ],
        "action_name": ingress_prefix + "reply_arp",
        "datas": [
            {"name": "arp_mac", "value": {"raw": config["client_gateway_mac"], "type": "mac"}}
        ]
    },
    {
        "keys": [
            {"name": "hdr.arp.opcode", "value": 1, "match_type": "exact"},
            {"name": "hdr.arp.target_proto_addr", "value": {"raw": config["backend_gateway"], "type": "ipv4"}, "match_type": "exact"}
        ],
        "action_name": ingress_prefix + "reply_arp",
        "datas": [
            {"name": "arp_mac", "value": {"raw": config["backend_gateway_mac"], "type": "mac"}}
        ]
    },
    {
        "keys": [
            {"name": "hdr.arp.opcode", "value": 2, "match_type": "exact"},
            {"name": "hdr.arp.target_proto_addr", "value": {"raw": config["frontend_gateway"], "type": "ipv4"}, "match_type": "exact"}
        ],
        "action_name": ingress_prefix + "reply_arp",
        "datas": [
            {"name": "arp_mac", "value": {"raw": config["frontend_gateway_mac"], "type": "mac"}}
        ]
    }
]

with open("config/arp_table.json", "w") as f:
    json.dump(arp_table_config, f, indent=4)

offload_connection_table_config = {}
offload_connection_table_config["table_name"] = ingress_prefix + "offload_connection_table"
offload_connection_table_config["key_names"] = [
    {"name": "ig_md.cip", "match_type": "exact"},
    {"name": "ig_md.cport", "match_type": "exact"}
]
offload_connection_table_config["actions"] = [{
    "action_name": ingress_prefix + "oft_hit",
    "data_names": ["d_index"]
}]
with open("config/offload_connection_table.json", "w") as f:
    json.dump(offload_connection_table_config, f, indent=4)

dip_lookup_table_config = {}
dip_lookup_table_config["table_name"] = ingress_prefix + "dip_lookup_table"
dip_lookup_table_config["key_names"] = [
    {"name": "hdr.ipv4.src_addr", "match_type": "exact"},
    {"name": "hdr.tcp.src_port", "match_type": "exact"}
]
dip_lookup_table_config["actions"] = [{
    "action_name": ingress_prefix + "dip_hit",
    "data_names": []
}]
dip_lookup_table_config["initial_entries"] = []
dest_to_egress_port_table_config = {}
dest_to_egress_port_table_config["table_name"] = ingress_prefix + "dest_to_egress_port_table"
dest_to_egress_port_table_config["key_names"] = [
    {"name": "hdr.ipv4.dst_addr", "match_type": "exact"}
]
dest_to_egress_port_table_config["actions"] = [{
    "action_name": ingress_prefix + "set_egress_port",
    "data_names": ["src_mac", "dst_mac", "dst_port"]
}]
dest_to_egress_port_table_config["initial_entries"] = []
d_index_to_egress_port_table_config = {}
d_index_to_egress_port_table_config["table_name"] = ingress_prefix + "d_index_to_egress_port_table"
d_index_to_egress_port_table_config["key_names"] = [
    {"name": "hdr.bridged.index", "match_type": "exact"}
]
d_index_to_egress_port_table_config["actions"] = [{
    "action_name": ingress_prefix + "set_egress_port",
    "data_names": ["src_mac", "dst_mac", "dst_port"]
}]
d_index_to_egress_port_table_config["initial_entries"] = []

d_index_to_ip_port_table_config = {}
d_index_to_ip_port_table_config["table_name"] = egress_prefix + "d_index_to_ip_port_table"
d_index_to_ip_port_table_config["key_names"] = [
    {"name": "eg_md.bridged.index", "match_type": "exact"}
]
d_index_to_ip_port_table_config["actions"] = [{
    "action_name": egress_prefix + "set_dst_ip_port",
    "data_names": ["dst_ip", "dst_port"]
}]
d_index_to_ip_port_table_config["initial_entries"] = []
for i in range(len(config["backend_servers_info"])):
    backend_ip = config["backend_servers_info"][i]["ip"]
    backend_mac = config["backend_servers_info"][i]["mac"]
    backend_port = config["backend_servers_info"][i]["port"]
    backend_egress_port = config["backend_servers_info"][i]["egress_port"]
    dip_lookup_table_config["initial_entries"].append(
        {
            "keys": [
                {"name": "hdr.ipv4.src_addr", "value": {"raw": backend_ip, "type": "ipv4"}, "match_type": "exact"},
                {"name": "hdr.tcp.src_port", "value": config["backend_servers_info"][i]["port"], "match_type": "exact"}
            ],
            "action_name": ingress_prefix + "dip_hit",
            "datas": []
        }
    )
    dest_to_egress_port_table_config["initial_entries"].append(
        {
            "keys": [
                {"name": "hdr.ipv4.dst_addr", "value": {"raw": backend_ip, "type": "ipv4"}, "match_type": "exact"}
            ],
            "action_name": ingress_prefix + "set_egress_port",
            "datas": [
                {"name": "src_mac", "value": {"raw": config["backend_gateway_mac"], "type": "mac"}},
                {"name": "dst_mac", "value": {"raw": backend_mac, "type": "mac"}},
                {"name": "dst_port", "value": backend_egress_port}
            ]
        }
    )
    d_index_to_egress_port_table_config["initial_entries"].append(
        {
            "keys": [
                {"name": "hdr.bridged.index", "value": i, "match_type": "exact"}
            ],
            "action_name": ingress_prefix + "set_egress_port",
            "datas": [
                {"name": "src_mac", "value": {"raw": config["backend_gateway_mac"], "type": "mac"}},
                {"name": "dst_mac", "value": {"raw": backend_mac, "type": "mac"}},
                {"name": "dst_port", "value": backend_egress_port}
            ]
        }
    )
    d_index_to_ip_port_table_config["initial_entries"].append(
        {
            "keys": [
                {"name": "eg_md.bridged.index", "value": i, "match_type": "exact"}
            ],
            "action_name": egress_prefix + "set_dst_ip_port",
            "datas": [
                {"name": "dst_ip", "value": {"raw": backend_ip, "type": "ipv4"}},
                {"name": "dst_port", "value": backend_port}
            ]
        }
    )

for i in range(len(config["client_servers_info"])):
    client_ip = config["client_servers_info"][i]["ip"]
    client_mac = config["client_servers_info"][i]["mac"]
    client_egress_port = config["client_servers_info"][i]["egress_port"]
    dest_to_egress_port_table_config["initial_entries"].append(
        {
            "keys": [
                {"name": "hdr.ipv4.dst_addr", "value": {"raw": client_ip, "type": "ipv4"}, "match_type": "exact"}
            ],
            "action_name": ingress_prefix + "set_egress_port",
            "datas": [
                {"name": "src_mac", "value": {"raw": config["client_gateway_mac"], "type": "mac"}},
                {"name": "dst_mac", "value": {"raw": client_mac, "type": "mac"}},
                {"name": "dst_port", "value": client_egress_port}
            ]
        }
    )

for i in range(len(config["frontend_servers_info"])):
    frontend_ip = config["frontend_servers_info"][i]["client_ip"]
    frontend_mac = config["frontend_servers_info"][i]["client_mac"]
    frontend_egress_port = config["frontend_servers_info"][i]["egress_port"]
    dest_to_egress_port_table_config["initial_entries"].append(
        {
            "keys": [
                {"name": "hdr.ipv4.dst_addr", "value": {"raw": frontend_ip, "type": "ipv4"}, "match_type": "exact"}
            ],
            "action_name": ingress_prefix + "set_egress_port",
            "datas": [
                {"name": "src_mac", "value": {"raw": config["frontend_gateway_mac"], "type": "mac"}},
                {"name": "dst_mac", "value": {"raw": frontend_mac, "type": "mac"}},
                {"name": "dst_port", "value": frontend_egress_port}
            ]
        }
    )
    
with open("config/dip_lookup_table.json", "w") as f:
    json.dump(dip_lookup_table_config, f, indent=4)
with open("config/dest_to_egress_port_table.json", "w") as f:
    json.dump(dest_to_egress_port_table_config, f, indent=4)
with open("config/d_index_to_egress_port_table.json", "w") as f:
    json.dump(d_index_to_egress_port_table_config, f, indent=4)
with open("config/d_index_to_ip_port_table.json", "w") as f:
    json.dump(d_index_to_ip_port_table_config, f, indent=4)

lb_index_to_egress_port_table_0_config = {}
lb_index_to_egress_port_table_0_config["table_name"] = ingress_prefix + "lb_index_to_egress_port_table_0"
lb_index_to_egress_port_table_0_config["key_names"] = [
    {"name": "ig_md.crc_hash_res", "match_type": "exact"}
]
lb_index_to_egress_port_table_0_config["actions"] = [{
    "action_name": ingress_prefix + "set_egress_port",
    "data_names": ["src_mac", "dst_mac", "dst_port"]
}]
lb_index_to_egress_port_table_1_config = {}
lb_index_to_egress_port_table_1_config["table_name"] = ingress_prefix + "lb_index_to_egress_port_table_1"
lb_index_to_egress_port_table_1_config["key_names"] = [
    {"name": "ig_md.crc_hash_res", "match_type": "exact"}
]
lb_index_to_egress_port_table_1_config["actions"] = [{
    "action_name": ingress_prefix + "set_egress_port",
    "data_names": ["src_mac", "dst_mac", "dst_port"]
}]
with open("config/lb_index_to_egress_port_table_0.json", "w") as f:
    json.dump(lb_index_to_egress_port_table_0_config, f, indent=4)
with open("config/lb_index_to_egress_port_table_1.json", "w") as f:
    json.dump(lb_index_to_egress_port_table_1_config, f, indent=4)

ports_info = config["ports"]
    
with open("config/ports.json", "w") as f:
    json.dump(ports_info, f, indent=4)