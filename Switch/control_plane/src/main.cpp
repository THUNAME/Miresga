#include "controller.h"
#include "client.h"
#include <iostream>

#define CONFIG_PATH "../config.json"

int main(int argc, char* argv[]) {
    std::string config_path = CONFIG_PATH;
    if (argc > 1) {
        config_path = argv[1];
    }
    SwitchClient_t::init_client();
    FrontendController_t::init_frontend_controller(config_path);
    FrontendController_t* controller = FrontendController_t::get_instance();
    controller->start();
    std::string input_str;
    while(true) {
        std::cin >> input_str;
        if (input_str == "quit") {
            controller->stop();
            break;
        }
    }
}