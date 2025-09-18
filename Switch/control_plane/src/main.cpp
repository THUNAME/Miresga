#include "controller.h"
#include "client.h"
#include <iostream>

#define PROG_NAME "MiresgaSwitchDataPlane"
#define CONFIG_PATH "../config.json"

auto logger = spdlog::stdout_color_mt("main");

int main(int argc, char* argv[]) {
    std::string config_path = CONFIG_PATH;
    if (argc > 1) {
        config_path = argv[1];
    }
    #if DEBUG == 1
    spdlog::set_level(spdlog::level::debug);
    #else
    spdlog::set_level(spdlog::level::info);
    #endif
    SwitchInfo_t::init_switch(PROG_NAME);
    SwitchClient_t::init_client();
    FrontendController_t::init_frontend_controller(config_path);
    FrontendController_t* controller = FrontendController_t::get_instance();
    controller->start();
    SPDLOG_LOGGER_INFO(logger, "Initialized all components.");
    std::string input_str;
    while(true) {
        std::cin >> input_str;
        if (input_str == "quit") {
            controller->stop();
            break;
        }
    }
}