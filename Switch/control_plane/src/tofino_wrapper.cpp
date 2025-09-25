#include "tofino_wrapper.h"

static auto logger = spdlog::stdout_color_mt("tofino_wrapper");

SwitchInfo_t::SwitchInfo_t(std::string prog_name) {
    SPDLOG_LOGGER_INFO(logger, "Initializing Switch with prog_name: {}", prog_name);
    _prog_name = prog_name;
    _dev_tgt = new bf_rt_target_t;
    _switchd_ctx = new bf_switchd_context_t;
    _dev_tgt->dev_id = 0;
    _dev_tgt->pipe_id = BF_DEV_PIPE_ALL;
    _switchd_ctx->install_dir = getenv("SDE_INSTALL");
    std::string conf_file = std::string(getenv("SDE_INSTALL")) + 
                           "/share/p4/targets/tofino/" + 
                           prog_name + ".conf";
    _switchd_ctx->conf_file = conf_file.data();
    _switchd_ctx->running_in_background = true;
    _switchd_ctx->dev_sts_thread = true;
    _switchd_ctx->dev_sts_port = 7777;
    _switchd_ctx->kernel_pkt = true;
    if (bf_switchd_lib_init(_switchd_ctx) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to init switchd with conf_file: {}", conf_file);
        throw std::runtime_error("Failed to init switchd");
    }
    if (bf_rt_info_get(_dev_tgt->dev_id, _prog_name.data(), &_bf_rt_info) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to get bf_rt_info for prog_name: {}", prog_name);
        throw std::runtime_error("Failed to get bf_rt_info");
    }
    if (bf_rt_session_create(&_session) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to create session");
        throw std::runtime_error("Failed to create session");
    }
}

SwitchInfo_t::~SwitchInfo_t() {
    bf_rt_session_destroy(_session);
    delete _dev_tgt;
    delete _switchd_ctx;
}

void SwitchInfo_t::init_switch(std::string prog_name) {
    if (_instance == nullptr) {
        SPDLOG_LOGGER_INFO(logger, "Creating SwitchInfo_t instance");
        _instance = new SwitchInfo_t(prog_name);
    }
}

SwitchInfo_t* SwitchInfo_t::get_instance() {
    if (_instance == nullptr) {
        SPDLOG_LOGGER_ERROR(logger, "SwitchInfo_t is not initialized");
        throw std::runtime_error("SwitchInfo_t is not initialized");
    }
    return _instance;
}

void SwitchInfo_t::init_ports(std::vector<PortInfo_t> port_info_list) {
    SPDLOG_LOGGER_INFO(logger, "Initializing ports");
    for (const auto& port_info : port_info_list) {
        bf_pal_front_port_handle_t port_hdl;
        if (bf_pm_port_str_to_hdl_get(_dev_tgt->dev_id, 
                                      port_info.port_name.data(), 
                                      &port_hdl) != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to get port handle for {}", port_info.port_name);
            throw std::runtime_error("Failed to get port handle for " + port_info.port_name);
        }
        if (bf_pm_port_add(_dev_tgt->dev_id, &port_hdl, 
                           port_info.port_speed, port_info.fec_type) != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to add port {}", port_info.port_name);
            throw std::runtime_error("Failed to add port " + port_info.port_name);
        }
        if (bf_pm_port_enable(_dev_tgt->dev_id, &port_hdl) != BF_SUCCESS) {
            throw std::runtime_error("Failed to enable port " + port_info.port_name);
        }
    }
}

const bf_rt_table_hdl* SwitchInfo_t::get_table_hdl(std::string table_name) {
    SPDLOG_LOGGER_DEBUG(logger, "Getting table handle for {}", table_name);
    const bf_rt_table_hdl* table_hdl = new bf_rt_table_hdl;
    if (bf_rt_table_from_name_get(_bf_rt_info, 
                                  table_name.data(), 
                                  &table_hdl) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to get table {}", table_name);
        throw std::runtime_error("Failed to get table " + table_name);
    }
    return table_hdl;
}

void SwitchInfo_t::add_batched_entry(const bf_rt_table_hdl* table_hdl,
                             std::vector<bf_rt_table_key_hdl*> key_hdls,
                             std::vector<bf_rt_table_data_hdl*> data_hdls,
                             size_t size) {
    SPDLOG_LOGGER_DEBUG(logger, "Adding batched entries, size: {}", size);
    bf_status_t status = bf_rt_begin_batch(_session);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to begin batch");
        throw std::runtime_error("Failed to begin batch");
    }
    for(int i = 0; i < size; i++) {
        status = bf_rt_table_entry_add(table_hdl, _session, _dev_tgt,
                                       key_hdls[i], data_hdls[i]);
        if (status != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to add entry, {}", bf_err_str(status));
            throw std::runtime_error("Failed to add entry");
        }
    }
    status = bf_rt_end_batch(_session, false);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to end batch");
        throw std::runtime_error("Failed to end batch");
    }
}

void SwitchInfo_t::delete_batched_entry(const bf_rt_table_hdl* table_hdl,
                                std::vector<bf_rt_table_key_hdl*> key_hdls,
                                size_t size) {
    SPDLOG_LOGGER_DEBUG(logger, "Deleting batched entries, size: {}", size);
    bf_status_t status = bf_rt_begin_batch(_session);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to begin batch");
        throw std::runtime_error("Failed to begin batch");
    }
    for (size_t i = 0; i < size; i++) {
        status = bf_rt_table_entry_del(table_hdl, _session, _dev_tgt,
                                       key_hdls[i]);
        if (status != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to delete entry");
            throw std::runtime_error("Failed to delete entry");
        }
    }
    status = bf_rt_end_batch(_session, false);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to end batch");
        throw std::runtime_error("Failed to end batch");
    }
}

void SwitchInfo_t::modify_batched_entry(const bf_rt_table_hdl* table_hdl,
                                std::vector<bf_rt_table_key_hdl*> key_hdls,
                                std::vector<bf_rt_table_data_hdl*> data_hdls,
                                size_t size) {
    SPDLOG_LOGGER_DEBUG(logger, "Modifying batched entries, size: {}", size);
    bf_status_t status = bf_rt_begin_batch(_session);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to begin batch");
        throw std::runtime_error("Failed to begin batch");
    }
    for (size_t i = 0; i < size; i++) {
        status = bf_rt_table_entry_mod(table_hdl, _session, _dev_tgt,
                                       key_hdls[i], data_hdls[i]);
        if (status != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to modify entry");
            throw std::runtime_error("Failed to modify entry");
        }
    }
    status = bf_rt_end_batch(_session, false);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to end batch");
        throw std::runtime_error("Failed to end batch");
    }
}

void SwitchInfo_t::add_entry(const bf_rt_table_hdl* table_hdl,
                      bf_rt_table_key_hdl* key_hdl,
                      bf_rt_table_data_hdl* data_hdl) {
    SPDLOG_LOGGER_DEBUG(logger, "Adding entry");
    bf_status_t status = bf_rt_table_entry_add(table_hdl, _session, _dev_tgt,
                                               key_hdl, data_hdl);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to add entry");
        throw std::runtime_error("Failed to add entry");
    }
    status = bf_rt_session_complete_operations(_session);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to complete operations");
        throw std::runtime_error("Failed to complete operations");
    }
}

void SwitchInfo_t::delete_entry(const bf_rt_table_hdl* table_hdl,
                         bf_rt_table_key_hdl* key_hdl) {
    SPDLOG_LOGGER_DEBUG(logger, "Deleting entry");
    bf_status_t status = bf_rt_table_entry_del(table_hdl, _session, _dev_tgt,
                                               key_hdl);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to delete entry");
        throw std::runtime_error("Failed to delete entry");
    }
    status = bf_rt_session_complete_operations(_session);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to complete operations");
        throw std::runtime_error("Failed to complete operations");
    }
}

void SwitchInfo_t::modify_entry(const bf_rt_table_hdl* table_hdl,
                         bf_rt_table_key_hdl* key_hdl,
                         bf_rt_table_data_hdl* data_hdl) {
    SPDLOG_LOGGER_DEBUG(logger, "Modifying entry");
    bf_status_t status = bf_rt_table_entry_mod(table_hdl, _session, _dev_tgt,
                                               key_hdl, data_hdl);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to modify entry");
        throw std::runtime_error("Failed to modify entry");
    }
    status = bf_rt_session_complete_operations(_session);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to complete operations");
        throw std::runtime_error("Failed to complete operations");
    }
}

void SwitchInfo_t::clear_table(const bf_rt_table_hdl* table_hdl) {
    SPDLOG_LOGGER_DEBUG(logger, "Clearing table");
    bf_status_t status = bf_rt_table_clear(table_hdl, _session, _dev_tgt);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to clear table");
        throw std::runtime_error("Failed to clear table");
    }
    status = bf_rt_session_complete_operations(_session);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to complete operations");
        throw std::runtime_error("Failed to complete operations");
    }
}

TableInfo_t::TableInfo_t(std::string table_name, std::vector<std::pair<std::string, bf_rt_key_field_type_t>> key_names, 
                         std::unordered_map<std::string, std::vector<std::string>> action_name_to_data_names,  bool enable_batch)
{
    SPDLOG_LOGGER_DEBUG(logger, "Initializing Table {}", table_name);
    _enable_batch = enable_batch;
    if (_enable_batch && action_name_to_data_names.size() > 1) { 
        SPDLOG_LOGGER_WARN(logger, "Batch mode only supports one action per table. Disabling batch mode.");
        _enable_batch = false;
    }
    _switch_info = SwitchInfo_t::get_instance();
    _table_hdl = _switch_info->get_table_hdl(table_name);
    bf_rt_id_t key_id, data_id, action_id;
    bf_rt_table_key_hdl* key_hdl;
    bf_rt_table_data_hdl* data_hdl;
    for (const auto& key_name : key_names) {
        if (bf_rt_key_field_id_get(_table_hdl, 
                                   key_name.first.data(), 
                                   &key_id) != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to get key field id for {}", key_name.first);
            throw std::runtime_error("Failed to get key field id for " + key_name.first);
        }
        _key_name_2_id_map[key_name.first] = std::make_pair(key_id, key_name.second);
    }
    for (const auto& [action_name, data_names] : action_name_to_data_names) {
        if (bf_rt_action_name_to_id(_table_hdl, 
                                    action_name.data(), 
                                    &action_id) != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to get action id for {}", action_name);
            throw std::runtime_error("Failed to get action id for " + action_name);
        }
        _action_name_2_id_map[action_name] = action_id;
        for (const auto& data_name : data_names) {
            if (bf_rt_data_field_id_with_action_get(_table_hdl,
                                                    data_name.c_str(),
                                                    action_id,
                                                    &data_id) != BF_SUCCESS) {
                SPDLOG_LOGGER_ERROR(logger, "Failed to get data id for {}", data_name);
                throw std::runtime_error("Failed to get data id for {}" + data_name);
            }
            _data_name_2_id_map[data_name] = data_id;
        }
    }
    for (size_t i = 0; i < MAX_BATCH_SIZE; i++) {
        if (bf_rt_table_key_allocate(_table_hdl, &key_hdl) != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to allocate key handle");
            throw std::runtime_error("Failed to allocate key handle");
        }
        _key_hdls.push_back(key_hdl);
        if (bf_rt_table_data_allocate(_table_hdl, &data_hdl) != BF_SUCCESS) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to allocate data handle");
            throw std::runtime_error("Failed to allocate data handle");
        }
        if (_enable_batch) {
            if (bf_rt_table_action_data_reset(_table_hdl, 
                                              _action_name_2_id_map.begin()->second, 
                                              &data_hdl) != BF_SUCCESS) {
                SPDLOG_LOGGER_ERROR(logger, "Failed to allocate action data handle");
                throw std::runtime_error("Failed to allocate action data handle");
            }
        }
        _data_hdls.push_back(data_hdl);
    }
}

TableInfo_t::~TableInfo_t() {
    SPDLOG_LOGGER_WARN(logger, "Deallocating table handles");
    for (auto key_hdl : _key_hdls) {
        bf_rt_table_key_deallocate(key_hdl);
    }
    for (auto data_hdl : _data_hdls) {
        bf_rt_table_data_deallocate(data_hdl);
    }
}

void TableInfo_t::add_entry(std::vector<std::vector<KeyInput_t>> key_field_values,
                            std::string action_name,
                            std::vector<std::vector<DataInput_t>> data_field_values) {
    SPDLOG_LOGGER_DEBUG(logger, "Adding entries");
    size_t remain_entry = key_field_values.size();
    size_t offset = 0;
    while (remain_entry > 0) {
        size_t batch_size = std::min(remain_entry, (size_t)MAX_BATCH_SIZE);
        for (size_t i = 0; i < batch_size; i++) {
            auto& key_hdl = _key_hdls[i];
            for (const auto& key_field_value : key_field_values[i + offset]) {
                bf_rt_id_t key_id = _key_name_2_id_map[key_field_value.name].first;
                bf_rt_key_field_type_t match_type = _key_name_2_id_map[key_field_value.name].second;
                uint64_t value = key_field_value.value;
                bf_status_t status;
                switch (match_type) {
                    case bf_rt_key_field_type_t::EXACT:
                        status = bf_rt_key_field_set_value(key_hdl, key_id, value);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set key field value for " + key_field_value.name);
                        }
                        break;
                    case bf_rt_key_field_type_t::LPM:
                        status = bf_rt_key_field_set_value_lpm(key_hdl, key_id, value, ((LPMKeyInput_t*)(&key_field_value))->prefix_len);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set LPM key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set LPM key field value for " + key_field_value.name);
                        }
                        break;
                    case bf_rt_key_field_type_t::TERNARY:
                        status = bf_rt_key_field_set_value_and_mask(key_hdl, key_id, value, ((TernaryKeyInput_t*)(&key_field_value))->mask);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set TERNARY key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set TERNARY key field value for " + key_field_value.name);
                        }
                        break;
                    case bf_rt_key_field_type_t::RANGE:
                        status = bf_rt_key_field_set_value_range(key_hdl, key_id, ((RangeKeyInput_t*)(&key_field_value))->start, 
                                                                 ((RangeKeyInput_t*)(&key_field_value))->end);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set RANGE key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set RANGE key field value for " + key_field_value.name);
                        }
                        break;
                    default:
                        SPDLOG_LOGGER_ERROR(logger, "Unsupported key match type");
                        throw std::runtime_error("Unsupported key match type");
                }
            }
            auto& data_hdl = _data_hdls[i];
            if (!_enable_batch) {
                if (bf_rt_table_action_data_reset(_table_hdl,
                                                  _action_name_2_id_map[action_name], 
                                                  &data_hdl) != BF_SUCCESS) {
                    SPDLOG_LOGGER_ERROR(logger, "Failed to allocate action data handle");
                    throw std::runtime_error("Failed to allocate action data handle");
                }
            }
            for (const auto& data_field_value : data_field_values[i + offset]) {
                bf_rt_id_t data_id = _data_name_2_id_map[data_field_value.name];
                uint64_t value = data_field_value.value;
                bf_status_t status = bf_rt_data_field_set_value(data_hdl, data_id, value);
                if (status != BF_SUCCESS) {
                    SPDLOG_LOGGER_ERROR(logger, "Failed to set data field value for {}", data_field_value.name);
                    throw std::runtime_error("Failed to set data field value for " + data_field_value.name);
                }
            }
        }
        _switch_info->add_batched_entry(_table_hdl, _key_hdls, _data_hdls, batch_size);
        remain_entry -= batch_size;
        offset += batch_size;
        SPDLOG_LOGGER_DEBUG(logger, "Remaining entries: {}", remain_entry);
    }
}

void TableInfo_t::delete_entry(std::vector<std::vector<KeyInput_t>> key_field_values) {
    SPDLOG_LOGGER_DEBUG(logger, "Deleting entries");
    size_t remain_entry = key_field_values.size();
    size_t offset = 0;
    while (remain_entry > 0) {
        size_t batch_size = std::min(remain_entry, (size_t)MAX_BATCH_SIZE);
        for (size_t i = 0; i < batch_size; i++) {
            auto& key_hdl = _key_hdls[i];
            for (const auto& key_field_value : key_field_values[i + offset]) {
                bf_rt_id_t key_id = _key_name_2_id_map[key_field_value.name].first;
                bf_rt_key_field_type_t match_type = _key_name_2_id_map[key_field_value.name].second;
                uint64_t value = key_field_value.value;
                bf_status_t status;
                switch (match_type) {
                    case bf_rt_key_field_type_t::EXACT:
                        status = bf_rt_key_field_set_value(key_hdl, key_id, value);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set key field value for " + key_field_value.name);
                        }
                        break;
                    case bf_rt_key_field_type_t::LPM:
                        status = bf_rt_key_field_set_value_lpm(key_hdl, key_id, value, ((LPMKeyInput_t*)(&key_field_value))->prefix_len);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set LPM key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set LPM key field value for " + key_field_value.name);
                        }
                        break;
                    case bf_rt_key_field_type_t::TERNARY:
                        status = bf_rt_key_field_set_value_and_mask(key_hdl, key_id, value, ((TernaryKeyInput_t*)(&key_field_value))->mask);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set TERNARY key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set TERNARY key field value for " + key_field_value.name);
                        }
                        break;
                    case bf_rt_key_field_type_t::RANGE:
                        status = bf_rt_key_field_set_value_range(key_hdl, key_id, ((RangeKeyInput_t*)(&key_field_value))->start, 
                                                                 ((RangeKeyInput_t*)(&key_field_value))->end);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set RANGE key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set RANGE key field value for " + key_field_value.name);
                        }
                        break;
                    default:
                        SPDLOG_LOGGER_ERROR(logger, "Unsupported key match type");
                        throw std::runtime_error("Unsupported key match type");
                }
            }
        }
        _switch_info->delete_batched_entry(_table_hdl, _key_hdls, batch_size);
        remain_entry -= batch_size;
        offset += batch_size;
        SPDLOG_LOGGER_DEBUG(logger, "Remaining entries: {}", remain_entry);
    }
}

void TableInfo_t::modify_entry(std::vector<std::vector<KeyInput_t>> key_field_values,
                               std::string action_name,
                               std::vector<std::vector<DataInput_t>> data_field_values){
    SPDLOG_LOGGER_DEBUG(logger, "Modifying entries");
    size_t remain_entry = key_field_values.size();
    while (remain_entry > 0) {
        size_t batch_size = std::min(remain_entry, (size_t)MAX_BATCH_SIZE);
        for (size_t i = 0; i < batch_size; i++) {
            auto& key_hdl = _key_hdls[i];
            for (const auto& key_field_value : key_field_values[i]) {
                bf_rt_id_t key_id = _key_name_2_id_map[key_field_value.name].first;
                bf_rt_key_field_type_t match_type = _key_name_2_id_map[key_field_value.name].second;
                uint64_t value = key_field_value.value;
                bf_status_t status;
                switch (match_type) {
                    case bf_rt_key_field_type_t::EXACT:
                        status = bf_rt_key_field_set_value(key_hdl, key_id, value);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set key field value for " + key_field_value.name);
                        }
                        break;
                    case LPM:
                        status = bf_rt_key_field_set_value_lpm(key_hdl, key_id, value, ((LPMKeyInput_t*)(&key_field_value))->prefix_len);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set LPM key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set LPM key field value for " + key_field_value.name);
                        }
                        break;
                    case TERNARY:
                        status = bf_rt_key_field_set_value_and_mask(key_hdl, key_id, value, ((TernaryKeyInput_t*)(&key_field_value))->mask);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set TERNARY key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set TERNARY key field value for " + key_field_value.name);
                        }
                        break;
                    case RANGE:
                        status = bf_rt_key_field_set_value_range(key_hdl, key_id, ((RangeKeyInput_t*)(&key_field_value))->start, 
                                                                 ((RangeKeyInput_t*)(&key_field_value))->end);
                        if (status != BF_SUCCESS) {
                            SPDLOG_LOGGER_ERROR(logger, "Failed to set RANGE key field value for {}", key_field_value.name);
                            throw std::runtime_error("Failed to set RANGE key field value for " + key_field_value.name);
                        }
                        break;
                    default:
                        SPDLOG_LOGGER_ERROR(logger, "Unsupported key match type");
                        throw std::runtime_error("Unsupported key match type");
                }
            }
            auto& data_hdl = _data_hdls[i];
            if (!_enable_batch) {
                if (bf_rt_table_action_data_reset(_table_hdl,
                                                  _action_name_2_id_map[action_name], 
                                                  &data_hdl) != BF_SUCCESS) {
                    throw std::runtime_error("Failed to allocate action data handle");
                }
            }
            for (const auto& data_field_value : data_field_values[i]) {
                bf_rt_id_t data_id = _data_name_2_id_map[data_field_value.name];
                uint64_t value = data_field_value.value;
                bf_status_t status = bf_rt_data_field_set_value(data_hdl, data_id, value);
                if (status != BF_SUCCESS) {
                    throw std::runtime_error("Failed to set data field value for " + data_field_value.name);
                }
            }
        }
        _switch_info->modify_batched_entry(_table_hdl, _key_hdls, _data_hdls, batch_size);
        remain_entry -= batch_size;
        SPDLOG_LOGGER_DEBUG(logger, "Remaining entries: {}", remain_entry);
    }
}

void TableInfo_t::clear_all_entry() {
    SPDLOG_LOGGER_DEBUG(logger, "Clearing all entries");
    _switch_info->clear_table(_table_hdl);
}

RegisterInfo_t::RegisterInfo_t(std::string register_name) {
    SPDLOG_LOGGER_DEBUG(logger, "Initializing Register {}", register_name);
    _switch_info = SwitchInfo_t::get_instance();
    _reg_hdl = _switch_info->get_table_hdl(register_name);
    if (bf_rt_table_key_allocate(_reg_hdl, &_key_hdl) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to allocate register key handle");
        throw std::runtime_error("Failed to allocate register key handle");
    }
    if (bf_rt_table_data_allocate(_reg_hdl, &_data_hdl) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to allocate register data handle");
        throw std::runtime_error("Failed to allocate register data handle");
    }
    if (bf_rt_key_field_id_get(_reg_hdl, "$REGISTER_INDEX", &_index_id) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to get register index field id");
        throw std::runtime_error("Failed to get register index field id");
    }
    std::string data_field_name = register_name + ".f1";
    if (bf_rt_data_field_id_get(_reg_hdl, data_field_name.c_str(), &_data_id) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to get register data field id");
        throw std::runtime_error("Failed to get register data field id");
    }
    if (bf_rt_table_data_allocate(_reg_hdl, &_data_hdl) != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to allocate register data handle");
        throw std::runtime_error("Failed to allocate register data handle");
    }
}

RegisterInfo_t::~RegisterInfo_t() {
    SPDLOG_LOGGER_WARN(logger, "Deallocating register handles");
    bf_rt_table_key_deallocate(_key_hdl);
    bf_rt_table_data_deallocate(_data_hdl);
}

void RegisterInfo_t::write_reg(uint64_t index, uint64_t data) {
    bf_status_t status;
    SPDLOG_LOGGER_DEBUG(logger, "Writing register");
    status = bf_rt_key_field_set_value(_key_hdl, _index_id, index);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to set register index");
        throw std::runtime_error("Failed to set register index");
    }
    status = bf_rt_data_field_set_value(_data_hdl, _data_id, data);
    if (status != BF_SUCCESS) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to set register data");
        throw std::runtime_error("Failed to set register data");
    }
    _switch_info->add_entry(_reg_hdl, _key_hdl, _data_hdl);
}

void RegisterInfo_t::clear_reg() {
    SPDLOG_LOGGER_DEBUG(logger, "Clearing register");
    _switch_info->clear_table(_reg_hdl);
}