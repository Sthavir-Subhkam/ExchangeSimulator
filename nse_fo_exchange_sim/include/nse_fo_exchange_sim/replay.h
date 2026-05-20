#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace nse_fo_exchange_sim {

struct ReplayDestination {
  std::string host;
  uint16_t port = 0;
};

enum class ReplayPacingMode {
  kNone,
  kCaptured,
};

struct ReplayOptions {
  std::string input_dir;
  std::vector<std::string> input_files;
  std::string token_filter_file;
  std::vector<uint32_t> tokens;
  std::string simulator_config_path;
  std::optional<ReplayDestination> default_destination;
  std::unordered_map<uint16_t, ReplayDestination> stream_destinations;
  std::string outgoing_interface_ip;
  ReplayPacingMode pacing = ReplayPacingMode::kNone;
  double speed = 1.0;
  uint64_t max_records = 0;
  bool loop = false;

  static ReplayOptions parseCommandLine(int argc, char** argv);
};

class MulticastReplayApp {
public:
  explicit MulticastReplayApp(ReplayOptions options);
  ~MulticastReplayApp();

  void run();

private:
  class Impl;
  Impl* impl_;
};

}  // namespace nse_fo_exchange_sim
