#ifndef CONTROLLER_CONNECTOR_H_
#define CONTROLLER_CONNECTOR_H_

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "spdlog/spdlog.h"
#include "miresga_utils.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <unistd.h>
#include <stdexcept>
#include <arpa/inet.h>
#include <linux/socket.h>

class ControllerConnector
{
public:
    int socket;

    ControllerConnector(char* controller_ip, uint16_t controller_port);
    ~ControllerConnector();

    MiresgaStatus_t send_message(char* msg, size_t msg_size);
    MiresgaStatus_t recv_message(char* buffer, size_t buffer_size, size_t& recv_size);
};

#endif