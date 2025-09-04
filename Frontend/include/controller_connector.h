#ifndef CONTROLLER_CONNECTOR_H_
#define CONTROLLER_CONNECTOR_H_

#include "miresga_utils.h"
#include <linux/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>

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