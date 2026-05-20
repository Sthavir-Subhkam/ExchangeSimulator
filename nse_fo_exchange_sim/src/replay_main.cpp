#include "nse_fo_exchange_sim/replay.h"

#include <iostream>
#include <string>

namespace {

void printUsage(const char* program) {
  std::cerr
      << "Usage: " << program << " --input-dir <path> [options]\n"
      << "       " << program << " --input-file <path> [--input-file <path> ...] [options]\n"
      << '\n'
      << "Required:\n"
      << "  --input-dir <path>           Directory containing tokenwise .dat or .dat.gz files\n"
      << "  or\n"
      << "  --input-file <path>          Explicit replay file, may be repeated\n"
      << '\n'
      << "Routing:\n"
      << "  --dest <host:port>           Default UDP destination for all streams\n"
      << "  --stream-dest <id=host:port> Stream-specific UDP destination, repeat as needed\n"
      << "  --sim-config <path>          Reuse simulator config token file and, when it has exactly\n"
      << "                               one market_data_stream, its UDP destination\n"
      << "  --out-interface <ip>         Outgoing multicast interface IPv4 address\n"
      << '\n'
      << "Selection:\n"
      << "  --token-file <path>          Token filter file, typically the same one as the simulator\n"
      << "  --tokens <csv>               Inline token list, for example 100519,100521\n"
      << '\n'
      << "Replay control:\n"
      << "  --pace none|captured         Replay as fast as possible or using captured timing\n"
      << "  --speed <multiplier>         Timing multiplier for --pace captured, default 1.0\n"
      << "  --max-records <n>            Stop after sending n packets\n"
      << "  --loop                       Restart from the beginning after finishing\n"
      << "  --help                       Show this help text\n";
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--help") {
    printUsage(argv[0]);
    return 0;
  }

  try {
    const auto options = nse_fo_exchange_sim::ReplayOptions::parseCommandLine(argc, argv);
    nse_fo_exchange_sim::MulticastReplayApp app(options);
    app.run();
    return 0;
  } catch (const std::exception& ex) {
    if (std::string(ex.what()) != "help") {
      std::cerr << "Replay startup failed: " << ex.what() << '\n';
    }
    printUsage(argv[0]);
    return 1;
  }
}
