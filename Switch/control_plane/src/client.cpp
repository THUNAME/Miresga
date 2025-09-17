#include "client.h"

static auto logger = spdlog::stdout_color_mt("client");

uint64_t SwitchClient_t::_parse_value(const nlohmann::json& value_json) {
    if (value_json.is_number()) {
        return value_json.get<uint64_t>();
    } 
    std::string value_str = value_json["raw"];
    std::string type_str = value_json["type"];
    std::stringstream ss(value_str);
    uint64_t value = 0;
    if (type_str == "ipv4") {
        std::string byte_str;
        while(std::getline(ss, byte_str, '.')) {
            value = (value << 8) | std::stoi(byte_str);
        }
    } else if (type_str == "mac") {
        std::string byte_str;
        while(std::getline(ss, byte_str, ':')) {
            value = (value << 8) | std::stoi(byte_str, nullptr, 16);
        }
    } else {
        throw std::invalid_argument("Unsupported value type: " + type_str);
        SPDLOG_LOGGER_ERROR(logger, "Unsupported value type: {}", type_str);
    }
    return value;
}

std::vector<KeyInput_t> SwitchClient_t::_parse_keys(const nlohmann::json& key_json) {
    assert(key_json.is_array());
    std::vector<KeyInput_t> keys;
    for (auto& key_item: key_json) {
        std::string key_name = key_item["name"];
        std::string match_type_str = key_item["match_type"];
        // Convert match_type_str to lowercase
        std::transform(match_type_str.begin(), match_type_str.end(), match_type_str.begin(), 
                       [](unsigned char c){ return std::tolower(c); });
        if (match_type_str == "exact") {
            uint64_t value = _parse_value(key_item["value"]);
            keys.push_back(ExactKeyInput_t(key_name, value));
        } else if (match_type_str == "lpm") {
            uint64_t value = _parse_value(key_item["value"]);
            uint32_t prefix_len = key_item["prefix_len"];
            keys.push_back(LPMKeyInput_t(key_name, value, prefix_len));
        } else if (match_type_str == "ternary") {
            uint64_t value = _parse_value(key_item["value"]);
            uint64_t mask = key_item["mask"];
            keys.push_back(TernaryKeyInput_t(key_name, mask));
        } else if (match_type_str == "range") {
            uint64_t start = _parse_value(key_item["start"]);
            uint64_t end = _parse_value(key_item["end"]);
            keys.push_back(RangeKeyInput_t(key_name, start, end));
        } else {
            throw std::invalid_argument("Invalid match type: " + match_type_str);
            SPDLOG_LOGGER_ERROR(logger, "Invalid match type: {}", match_type_str);
        }
    }
    return keys;
}

TableInfo_t* SwitchClient_t::_init_table_from_config(std::string config) {
    std::ifstream ifs(config);
    nlohmann::json config_json;
    ifs >> config_json;
    std::string table_name = config_json["table_name"];
    SPDLOG_LOGGER_INFO(logger, "Init table {} from {}", table_name, config);
    std::vector<std::pair<std::string, bf_rt_key_field_type_t>> key_names;
    auto key_config = config_json["key_names"];
    assert(key_config.is_array());
    for (auto& key_item : key_config) {
        std::string key_name = key_item["name"];
        std::string match_type_str = key_item["match_type"];
        bf_rt_key_field_type_t match_type;
        if (match_type_str == "exact") {
            match_type = bf_rt_key_field_type_t::EXACT;
        } else if (match_type_str == "lpm") {
            match_type = bf_rt_key_field_type_t::LPM;
        } else if (match_type_str == "ternary") {
            match_type = bf_rt_key_field_type_t::TERNARY;
        } else if (match_type_str == "range") {
            match_type = bf_rt_key_field_type_t::RANGE;
        } else {
            SPDLOG_LOGGER_ERROR(logger, "Invalid match type: {}", match_type_str);
            throw std::invalid_argument("Invalid match type: " + match_type_str);
        }
        key_names.push_back({key_name, match_type});
    }
    std::unordered_map<std::string, std::vector<std::string>> action_name_to_data_names;
    auto action_config = config_json["actions"];
    assert(action_config.is_array());
    for (auto& action : action_config) {
        std::string action_name = action["action_name"];
        auto data_names = action["data_names"];
        assert(data_names.is_array());
        action_name_to_data_names[action_name] = std::vector<std::string>();
        for (auto& data_name : data_names) {
            action_name_to_data_names[action_name].push_back(data_name.get<std::string>());
        }
    }
    bool enable_batch = config_json.value("enable_batch", false);
    TableInfo_t* table = new TableInfo_t(table_name, key_names, action_name_to_data_names, enable_batch);
    if (config_json.contains("initial_entries")) {
        auto initial_entries = config_json["initial_entries"];
        assert(initial_entries.is_array());
        std::vector<std::vector<KeyInput_t>> key_field_values;
        std::vector<std::vector<DataInput_t>> data_field_values;
        std::string action_name;
        for (auto& entry : initial_entries) {
            key_field_values.push_back(_parse_keys(entry["keys"]));
            action_name = entry["action_name"];
            auto data_config = entry["datas"];
            assert(data_config.is_array());
            std::vector<DataInput_t> data_fields;
            for (auto& data_item : data_config) {
                std::string data_name = data_item["name"];
                uint64_t value = _parse_value(data_item["value"]);
                data_fields.push_back(DataInput_t(data_name, value));
            }
            data_field_values.push_back(data_fields);
        }
        table->add_entry(key_field_values, action_name, data_field_values);
    }
    return table;
}

void SwitchClient_t::_init_ports_from_config(std::string config_path) {
    std::ifstream ifs(config_path);
    nlohmann::json config_json;
    ifs >> config_json;
    ifs.close();
    assert(config_json.is_array());
    std::vector<PortInfo_t> port_info_list;
    for (auto& port_item : config_json) {
        std::string port_name = port_item["name"];
        bf_port_speed_t port_speed;
        uint32_t speed = port_item["speed"];
        if (speed == 100) {
            port_speed = bf_port_speed_t::BF_SPEED_100G;
        } else if (speed == 10) {
            port_speed = bf_port_speed_t::BF_SPEED_10G;
        } else if (speed == 1) {
            port_speed = bf_port_speed_t::BF_SPEED_1G;
        } else {
            SPDLOG_LOGGER_ERROR(logger, "Invalid port speed: {}", speed);
            throw std::invalid_argument("Invalid port speed: " + std::to_string(speed));
        }
        bf_fec_type_t fec_type;
        std::string fec_str = port_item["fec_type"];
        if (fec_str == "rs") {
            fec_type = bf_fec_type_t::BF_FEC_TYP_RS;
        } else if (fec_str == "fc") {
            fec_type = bf_fec_type_t::BF_FEC_TYP_FC;
        } else {
            SPDLOG_LOGGER_ERROR(logger, "Invalid fec type: {}, set None", fec_str);
            fec_type = bf_fec_type_t::BF_FEC_TYP_NONE;
        }
        PortInfo_t port_info = {port_name, port_speed, fec_type};
        port_info_list.push_back(port_info);
    }
    _switch_info->init_ports(port_info_list);
}

SwitchClient_t::SwitchClient_t(std::string config_dir) {
    _switch_info = SwitchInfo_t::get_instance();
    _init_ports_from_config(config_dir + "ports.json");
    _arp_table = _init_table_from_config(config_dir + "arp_table.json");
    _dip_lookup_table = _init_table_from_config(config_dir + "dip_lookup_table.json");
    _dest_to_egress_port_table = _init_table_from_config(config_dir + "dest_to_egress_port_table.json");
    _d_index_to_egress_port_table = _init_table_from_config(config_dir + "d_index_to_egress_port_table.json");
    _d_index_to_ip_port_table = _init_table_from_config(config_dir + "d_index_to_ip_port_table.json");
    _lb_index_to_egress_port_table_0 = _init_table_from_config(config_dir + "lb_index_to_egress_port_table_0.json");
    _lb_index_to_egress_port_table_1 = _init_table_from_config(config_dir + "lb_index_to_egress_port_table_1.json");
    _offload_connection_table = _init_table_from_config(config_dir + "offload_connection_table.json");
    _updating_flag_reg = new RegisterInfo_t("SwitchIngress.updating_flag_reg");
    _new_tb_idx_reg = new RegisterInfo_t("SwitchIngress.new_tb_idx_reg");
    _bloom_filter_reg_1 = new RegisterInfo_t("SwitchIngress.bloomfilter_1_reg");
    _bloom_filter_reg_2 = new RegisterInfo_t("SwitchIngress.bloomfilter_2_reg");
    _new_tb_idx = 0;
    _bloom_filter_reg_1->clear_reg();
    _bloom_filter_reg_2->clear_reg();
    _updating_flag_reg->clear_reg();
    _new_tb_idx_reg->clear_reg();
}

SwitchClient_t::~SwitchClient_t() {
    delete _arp_table;
    delete _dip_lookup_table;
    delete _dest_to_egress_port_table;
    delete _d_index_to_egress_port_table;
    delete _d_index_to_ip_port_table;
    delete _lb_index_to_egress_port_table_0;
    delete _lb_index_to_egress_port_table_1;
    delete _offload_connection_table;
    delete _updating_flag_reg;
    delete _new_tb_idx_reg;
    delete _bloom_filter_reg_1;
    delete _bloom_filter_reg_2;
}

void SwitchClient_t::init_client(std::string config_dir) {
    if (_instance == nullptr) {
        _instance = new SwitchClient_t(config_dir);
    }
}

SwitchClient_t* SwitchClient_t::get_instance() {
    if (_instance == nullptr) {
        throw std::runtime_error("SwitchClient_t has not been initialized");
    }
    return _instance;
}

void SwitchClient_t::add_offload_entries(std::vector<MiresgaOFTEntry_t> entries) {
    std::vector<std::vector<KeyInput_t>> key_field_values;
    std::vector<std::vector<DataInput_t>> data_field_values;
    std::string action_name = "SwitchIngress.oft_hit";
    for (const auto& entry : entries) {
        key_field_values.push_back({
            ExactKeyInput_t("ig_md.cip", entry.key.client_ip),
            ExactKeyInput_t("ig_md.cport", entry.key.client_port)
        });
        data_field_values.push_back({
            DataInput_t("d_index", entry.data.d_index)
        });
    }
    _offload_connection_table->add_entry(key_field_values, action_name, data_field_values);
}

void SwitchClient_t::del_offload_entries(std::vector<MiresgaOFTKey_t> keys) {
    std::vector<std::vector<KeyInput_t>> key_field_values;
    for (const auto& key : keys) {
        key_field_values.push_back({
            ExactKeyInput_t("ig_md.cip", key.client_ip),
            ExactKeyInput_t("ig_md.cport", key.client_port)
        });
    }
    _offload_connection_table->delete_entry(key_field_values);
}

void SwitchClient_t::start_updating(std::unordered_map<uint8_t, EgressPortEntry_t> new_crc_2_idx) {
    TableInfo_t* new_tb;
    if (_new_tb_idx == 1) {
        new_tb = _lb_index_to_egress_port_table_0;
    } else {
        new_tb = _lb_index_to_egress_port_table_1;
    }
    std::vector<std::vector<KeyInput_t>> key_field_values;
    std::vector<std::vector<DataInput_t>> data_field_values;
    std::string action_name = "SwitchIngress.set_egress_port";
    for (const auto& [crc, entry] : new_crc_2_idx) {
        key_field_values.push_back({
            ExactKeyInput_t("ig_md.crc_hash_res", crc)
        });
        data_field_values.push_back({
            DataInput_t("src_mac", entry.src_mac),
            DataInput_t("dst_mac", entry.dst_mac),
            DataInput_t("dst_port", entry.dst_port)
        });
    }
    new_tb->add_entry(key_field_values, action_name, data_field_values);
    _new_tb_idx = 1 - _new_tb_idx;
    _new_tb_idx_reg->write_reg(0, _new_tb_idx);
    _updating_flag_reg->write_reg(0, 1);
}

void SwitchClient_t::finish_updating() {
    _updating_flag_reg->write_reg(0, 0);
    _bloom_filter_reg_1->clear_reg();
    _bloom_filter_reg_2->clear_reg();
    if (_new_tb_idx == 0) {
        _lb_index_to_egress_port_table_1->clear_all_entry();
    } else {
        _lb_index_to_egress_port_table_0->clear_all_entry();
    }
}