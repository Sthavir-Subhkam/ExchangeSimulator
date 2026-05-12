#pragma once

#include <cstdint>

#include "nse_fo_exchange_sim/config.h"

namespace nse_fo_exchange_sim {

class SimulatorApp {
public:
  explicit SimulatorApp(Config config);
  ~SimulatorApp();

  void start();
  void stop();

  uint16_t gatewayPort() const;
  uint16_t sessionPort() const;

private:
  class Impl;
  Impl* impl_;
};

}  // namespace nse_fo_exchange_sim
