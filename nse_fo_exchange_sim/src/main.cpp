#include "nse_fo_exchange_sim/config.h"
#include "nse_fo_exchange_sim/simulator.h"

#include <atomic>
#include <csignal>
#include <chrono>
#include <iostream>
#include <thread>

namespace {

std::atomic<bool> g_running {true};

void handleSignal(int) {
  g_running = false;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3 || std::string(argv[1]) != "--config") {
    std::cerr << "Usage: " << argv[0] << " --config <path>\n";
    return 1;
  }

  try {
    const auto config = nse_fo_exchange_sim::Config::loadFromFile(argv[2]);
    nse_fo_exchange_sim::SimulatorApp app(config);

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    app.start();
    std::cout << "NSE FO exchange simulator listening on TLS gateway port "
              << app.gatewayPort() << " and session port " << app.sessionPort() << '\n';

    while (g_running.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    app.stop();
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "Simulator startup failed: " << ex.what() << '\n';
    return 1;
  }
}
