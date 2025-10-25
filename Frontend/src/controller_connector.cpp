#include "controller_connector.h"

static auto logger = spdlog::stdout_color_mt("ControllerConnector");

ControllerConnector::ControllerConnector(char* controller_ip, uint16_t controller_port)
{
    SPDLOG_LOGGER_INFO(logger, "Connecting to controller at {}:{}", controller_ip, controller_port);
    socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to create socket");
        throw std::runtime_error("Failed to create socket");
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(controller_port);
    inet_pton(AF_INET, controller_ip, &server_addr.sin_addr);

    if (connect(socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to connect to controller at {}:{}", controller_ip, controller_port);
        ::close(socket);
        throw std::runtime_error("Failed to connect to controller");
    }

    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to get socket flags");
        ::close(socket);
        throw std::runtime_error("Failed to get socket flags");
    }
    if (fcntl(socket, F_SETFL, flags| O_NONBLOCK) == -1) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to set socket to non-blocking");
        ::close(socket);
        throw std::runtime_error("Failed to set socket to non-blocking");
    }
}

ControllerConnector::~ControllerConnector()
{
    if (socket >= 0) {
        ::close(socket);
    }
}

__attribute__((always_inline)) MiresgaStatus_t ControllerConnector::send_message(char* msg, size_t msg_size)
{
    ssize_t sent_size = send(socket, msg, msg_size, 0);
    return (sent_size != msg_size) ? MiresgaStatus_t::INTERNAL_ERROR : MiresgaStatus_t::OK;
}

__attribute__((always_inline)) MiresgaStatus_t ControllerConnector::recv_message(char* buffer, size_t buffer_size, size_t& recv_size)
{
    ssize_t received = recv(socket, buffer, buffer_size, 0);
    recv_size = static_cast<size_t>(received);
    return (received < 0) ? MiresgaStatus_t::INTERNAL_ERROR : MiresgaStatus_t::OK;
}