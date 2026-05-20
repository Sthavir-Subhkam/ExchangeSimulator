#include "nse_fo_exchange_sim/replay.h"

#include "nse_fo_exchange_sim/config.h"
#include "nse_fo_exchange_sim/protocol.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <unordered_set>

namespace nse_fo_exchange_sim {
namespace {

using protocol::TbtOrderMessage;
using protocol::TbtStreamHeader;
using protocol::TbtTradeMessage;

constexpr std::size_t kCaptureRecordSize = 64;
constexpr std::size_t kCapturePrefixSize = 16;
constexpr std::size_t kCapturePayloadOffset = kCapturePrefixSize;
constexpr std::size_t kCaptureMaxPayloadSize = kCaptureRecordSize - kCapturePrefixSize;

std::string trim(std::string value) {
  auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
  return value;
}

bool endsWith(const std::string& value, const std::string& suffix) {
  return value.size() >= suffix.size() &&
         value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::string> split(const std::string& value, char delimiter) {
  std::vector<std::string> parts;
  std::stringstream input(value);
  std::string part;
  while (std::getline(input, part, delimiter)) {
    parts.push_back(part);
  }
  return parts;
}

ReplayDestination parseDestination(const std::string& value) {
  const std::string trimmed = trim(value);
  const std::size_t colon_pos = trimmed.rfind(':');
  if (colon_pos == std::string::npos) {
    throw std::runtime_error("Invalid destination, expected host:port: " + value);
  }

  ReplayDestination destination;
  destination.host = trim(trimmed.substr(0, colon_pos));
  if (destination.host.empty()) {
    throw std::runtime_error("Missing host in destination: " + value);
  }
  destination.port = static_cast<uint16_t>(std::stoul(trim(trimmed.substr(colon_pos + 1))));
  if (destination.port == 0) {
    throw std::runtime_error("Invalid port in destination: " + value);
  }
  return destination;
}

std::pair<uint16_t, ReplayDestination> parseStreamDestination(const std::string& value) {
  const std::size_t equal_pos = value.find('=');
  if (equal_pos == std::string::npos) {
    throw std::runtime_error("Invalid stream destination, expected stream=host:port: " + value);
  }
  const uint16_t stream_id = static_cast<uint16_t>(std::stoul(trim(value.substr(0, equal_pos))));
  return {stream_id, parseDestination(value.substr(equal_pos + 1))};
}

std::vector<uint32_t> parseTokenList(const std::string& value) {
  std::vector<uint32_t> tokens;
  for (const auto& part : split(value, ',')) {
    const std::string item = trim(part);
    if (item.empty()) {
      continue;
    }
    tokens.push_back(static_cast<uint32_t>(std::stoul(item)));
  }
  return tokens;
}

std::vector<uint32_t> loadTokenFilterFile(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("Unable to open token filter file: " + path);
  }

  std::vector<uint32_t> tokens;
  std::string line;
  while (std::getline(input, line)) {
    const std::size_t comment_pos = line.find('#');
    if (comment_pos != std::string::npos) {
      line.erase(comment_pos);
    }
    line = trim(line);
    if (line.empty()) {
      continue;
    }
    tokens.push_back(static_cast<uint32_t>(std::stoul(line)));
  }
  return tokens;
}

template <typename T>
T loadLittleEndian(const uint8_t* data) {
  static_assert(std::is_unsigned<T>::value, "loadLittleEndian expects unsigned integer");
  T value = 0;
  for (std::size_t index = 0; index < sizeof(T); ++index) {
    value |= static_cast<T>(data[index]) << (index * 8);
  }
  return value;
}

struct CaptureRecord {
  std::array<uint8_t, kCaptureRecordSize> raw {};
  uint64_t capture_seconds = 0;
  uint64_t capture_nanos = 0;
  uint64_t capture_time_ns = 0;
  uint16_t packet_size = 0;
  uint16_t stream_id = 0;
  uint32_t sequence_no = 0;
  uint8_t message_type = 0;
  uint32_t token = 0;
};

class CaptureRecordReader {
public:
  explicit CaptureRecordReader(std::string path)
      : path_(std::move(path)),
        gzip_(endsWith(path_, ".gz")) {
    if (gzip_) {
      gzip_file_ = gzopen(path_.c_str(), "rb");
      if (gzip_file_ == nullptr) {
        throw std::runtime_error("Unable to open gzip capture file: " + path_);
      }
    } else {
      input_.open(path_, std::ios::binary);
      if (!input_) {
        throw std::runtime_error("Unable to open capture file: " + path_);
      }
    }
  }

  ~CaptureRecordReader() {
    if (gzip_file_ != nullptr) {
      gzclose(gzip_file_);
    }
  }

  const std::string& path() const {
    return path_;
  }

  bool readNext(CaptureRecord* record) {
    std::array<uint8_t, kCaptureRecordSize> bytes {};
    if (!readExact(bytes.data(), bytes.size())) {
      return false;
    }

    ++record_index_;
    record->raw = bytes;
    record->capture_seconds = loadLittleEndian<uint64_t>(bytes.data());
    record->capture_nanos = loadLittleEndian<uint64_t>(bytes.data() + sizeof(uint64_t));
    record->packet_size = loadLittleEndian<uint16_t>(bytes.data() + kCapturePayloadOffset);
    record->stream_id = loadLittleEndian<uint16_t>(bytes.data() + kCapturePayloadOffset + 2);
    record->sequence_no = loadLittleEndian<uint32_t>(bytes.data() + kCapturePayloadOffset + 4);
    record->message_type = bytes[kCapturePayloadOffset + 8];

    if (record->packet_size < sizeof(TbtStreamHeader) || record->packet_size > kCaptureMaxPayloadSize) {
      throw std::runtime_error("Invalid packet size " + std::to_string(record->packet_size) +
                               " in " + path_ + " record " + std::to_string(record_index_));
    }
    if (record->capture_nanos >= 1000000000ULL) {
      throw std::runtime_error("Invalid nanosecond timestamp in " + path_ + " record " +
                               std::to_string(record_index_));
    }

    record->capture_time_ns =
        record->capture_seconds * 1000000000ULL + record->capture_nanos;

    if (record->message_type == 'T') {
      if (record->packet_size < sizeof(TbtTradeMessage)) {
        throw std::runtime_error("Short trade packet in " + path_ + " record " +
                                 std::to_string(record_index_));
      }
      TbtTradeMessage message {};
      std::memcpy(&message, bytes.data() + kCapturePayloadOffset, sizeof(message));
      record->token = message.token;
    } else {
      if (record->packet_size < sizeof(TbtOrderMessage)) {
        throw std::runtime_error("Short order packet in " + path_ + " record " +
                                 std::to_string(record_index_));
      }
      TbtOrderMessage message {};
      std::memcpy(&message, bytes.data() + kCapturePayloadOffset, sizeof(message));
      record->token = message.token;
    }

    return true;
  }

private:
  bool readExact(uint8_t* buffer, std::size_t size) {
    if (gzip_) {
      std::size_t total = 0;
      while (total < size) {
        const int rc = gzread(gzip_file_, buffer + total, static_cast<unsigned int>(size - total));
        if (rc == 0) {
          if (total == 0) {
            return false;
          }
          throw std::runtime_error("Truncated gzip capture file: " + path_);
        }
        if (rc < 0) {
          int error_number = Z_OK;
          const char* error_text = gzerror(gzip_file_, &error_number);
          throw std::runtime_error("gzread failed for " + path_ + ": " +
                                   std::string(error_text == nullptr ? "unknown error" : error_text));
        }
        total += static_cast<std::size_t>(rc);
      }
      return true;
    }

    input_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(size));
    if (input_.gcount() == 0 && input_.eof()) {
      return false;
    }
    if (input_.gcount() != static_cast<std::streamsize>(size)) {
      throw std::runtime_error("Truncated capture file: " + path_);
    }
    return true;
  }

  std::string path_;
  bool gzip_ = false;
  std::ifstream input_;
  gzFile gzip_file_ = nullptr;
  uint64_t record_index_ = 0;
};

struct RoutedDestination {
  ReplayDestination destination;
  sockaddr_in address {};
};

class UdpReplaySender {
public:
  UdpReplaySender(std::optional<ReplayDestination> default_destination,
                  const std::unordered_map<uint16_t, ReplayDestination>& stream_destinations,
                  std::string outgoing_interface_ip)
      : default_destination_(std::move(default_destination)),
        outgoing_interface_ip_(std::move(outgoing_interface_ip)) {
    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
      throw std::runtime_error("socket() failed for replay sender");
    }

    const int multicast_loop = 1;
    const int multicast_ttl = 1;
    setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_LOOP, &multicast_loop, sizeof(multicast_loop));
    setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_TTL, &multicast_ttl, sizeof(multicast_ttl));

    if (!outgoing_interface_ip_.empty()) {
      in_addr interface_addr {};
      if (inet_pton(AF_INET, outgoing_interface_ip_.c_str(), &interface_addr) != 1) {
        throw std::runtime_error("Invalid outgoing interface IP: " + outgoing_interface_ip_);
      }
      if (setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_IF,
                     &interface_addr, sizeof(interface_addr)) != 0) {
        throw std::runtime_error("Failed to configure IP_MULTICAST_IF for " + outgoing_interface_ip_);
      }
    }

    if (default_destination_.has_value()) {
      routed_default_ = buildRoutedDestination(*default_destination_);
    }
    for (const auto& entry : stream_destinations) {
      routed_stream_destinations_.emplace(entry.first, buildRoutedDestination(entry.second));
    }
  }

  ~UdpReplaySender() {
    if (socket_fd_ >= 0) {
      close(socket_fd_);
    }
  }

  void send(const CaptureRecord& record) {
    const RoutedDestination* routed = nullptr;
    const auto stream_it = routed_stream_destinations_.find(record.stream_id);
    if (stream_it != routed_stream_destinations_.end()) {
      routed = &stream_it->second;
    } else if (routed_default_.has_value()) {
      routed = &*routed_default_;
    }

    if (routed == nullptr) {
      throw std::runtime_error("No UDP destination configured for capture stream_id " +
                               std::to_string(record.stream_id));
    }

    const ssize_t rc = sendto(socket_fd_, record.raw.data() + kCapturePayloadOffset,
                              record.packet_size, 0,
                              reinterpret_cast<const sockaddr*>(&routed->address),
                              sizeof(routed->address));
    if (rc != static_cast<ssize_t>(record.packet_size)) {
      throw std::runtime_error("sendto() failed while replaying capture data");
    }
  }

private:
  static RoutedDestination buildRoutedDestination(const ReplayDestination& destination) {
    RoutedDestination routed;
    routed.destination = destination;
    routed.address.sin_family = AF_INET;
    routed.address.sin_port = htons(destination.port);
    if (inet_pton(AF_INET, destination.host.c_str(), &routed.address.sin_addr) != 1) {
      throw std::runtime_error("Replay destination host must be an IPv4 address: " + destination.host);
    }
    return routed;
  }

  int socket_fd_ = -1;
  std::optional<ReplayDestination> default_destination_;
  std::optional<RoutedDestination> routed_default_;
  std::unordered_map<uint16_t, RoutedDestination> routed_stream_destinations_;
  std::string outgoing_interface_ip_;
};

struct ReplayCursor {
  CaptureRecord record;
  std::size_t reader_index = 0;
};

struct ReplayCursorCompare {
  bool operator()(const ReplayCursor& lhs, const ReplayCursor& rhs) const {
    if (lhs.record.capture_time_ns != rhs.record.capture_time_ns) {
      return lhs.record.capture_time_ns > rhs.record.capture_time_ns;
    }
    if (lhs.record.stream_id != rhs.record.stream_id) {
      return lhs.record.stream_id > rhs.record.stream_id;
    }
    if (lhs.record.sequence_no != rhs.record.sequence_no) {
      return lhs.record.sequence_no > rhs.record.sequence_no;
    }
    return lhs.reader_index > rhs.reader_index;
  }
};

struct ResolvedReplayOptions {
  std::vector<std::string> input_files;
  std::optional<ReplayDestination> default_destination;
  std::unordered_map<uint16_t, ReplayDestination> stream_destinations;
  std::string outgoing_interface_ip;
  ReplayPacingMode pacing = ReplayPacingMode::kNone;
  double speed = 1.0;
  uint64_t max_records = 0;
  bool loop = false;
};

std::optional<uint32_t> parseTokenFromFilename(const std::filesystem::path& path) {
  const std::string filename = path.filename().string();
  const std::size_t underscore_pos = filename.find('_');
  if (underscore_pos == std::string::npos) {
    return std::nullopt;
  }

  const std::string token_text = filename.substr(0, underscore_pos);
  if (token_text.empty() || !std::all_of(token_text.begin(), token_text.end(),
                                         [](unsigned char ch) { return std::isdigit(ch); })) {
    return std::nullopt;
  }
  return static_cast<uint32_t>(std::stoul(token_text));
}

std::vector<std::string> collectInputFiles(const ReplayOptions& options,
                                           const std::optional<Config>& simulator_config) {
  std::unordered_set<uint32_t> selected_tokens(options.tokens.begin(), options.tokens.end());
  if (!options.token_filter_file.empty()) {
    for (uint32_t token : loadTokenFilterFile(options.token_filter_file)) {
      selected_tokens.insert(token);
    }
  } else if (simulator_config.has_value() && !simulator_config->token_filter_file.empty()) {
    for (uint32_t token : loadTokenFilterFile(simulator_config->token_filter_file)) {
      selected_tokens.insert(token);
    }
  }

  std::vector<std::string> files = options.input_files;
  if (!options.input_dir.empty()) {
    std::vector<std::filesystem::path> discovered;
    for (const auto& entry : std::filesystem::directory_iterator(options.input_dir)) {
      if (!entry.is_regular_file()) {
        continue;
      }

      const auto& path = entry.path();
      const std::string filename = path.filename().string();
      if (!endsWith(filename, ".dat") && !endsWith(filename, ".dat.gz")) {
        continue;
      }

      if (!selected_tokens.empty()) {
        const auto token = parseTokenFromFilename(path);
        if (!token.has_value() || selected_tokens.find(*token) == selected_tokens.end()) {
          continue;
        }
      }
      discovered.push_back(path);
    }
    std::sort(discovered.begin(), discovered.end());
    for (const auto& path : discovered) {
      files.push_back(path.string());
    }
  }

  std::sort(files.begin(), files.end());
  files.erase(std::unique(files.begin(), files.end()), files.end());
  if (files.empty()) {
    throw std::runtime_error("No replay input files selected");
  }
  return files;
}

ResolvedReplayOptions resolveOptions(const ReplayOptions& options) {
  std::optional<Config> simulator_config;
  if (!options.simulator_config_path.empty()) {
    simulator_config = Config::loadFromFile(options.simulator_config_path);
  }

  ResolvedReplayOptions resolved;
  resolved.input_files = collectInputFiles(options, simulator_config);
  resolved.default_destination = options.default_destination;
  resolved.stream_destinations = options.stream_destinations;
  resolved.outgoing_interface_ip = options.outgoing_interface_ip;
  resolved.pacing = options.pacing;
  resolved.speed = options.speed;
  resolved.max_records = options.max_records;
  resolved.loop = options.loop;

  if (!resolved.default_destination.has_value() && resolved.stream_destinations.empty() &&
      simulator_config.has_value()) {
    if (simulator_config->market_data_streams.size() == 1) {
      const auto& endpoint = simulator_config->market_data_streams.front();
      resolved.default_destination = ReplayDestination {endpoint.host, endpoint.port};
    }
  }

  if (!resolved.default_destination.has_value() && resolved.stream_destinations.empty()) {
    throw std::runtime_error("Replay destination missing. Use --dest, --stream-dest, or --sim-config "
                             "with exactly one market_data_stream");
  }
  if (resolved.pacing == ReplayPacingMode::kCaptured && resolved.speed <= 0.0) {
    throw std::runtime_error("--speed must be greater than zero when --pace captured is used");
  }
  return resolved;
}

std::string describeDestination(const ReplayDestination& destination) {
  return destination.host + ":" + std::to_string(destination.port);
}

}  // namespace

ReplayOptions ReplayOptions::parseCommandLine(int argc, char** argv) {
  ReplayOptions options;

  for (int index = 1; index < argc; ++index) {
    const std::string arg = argv[index];
    auto requireValue = [&](const std::string& name) -> std::string {
      if (index + 1 >= argc) {
        throw std::runtime_error("Missing value for " + name);
      }
      return argv[++index];
    };

    if (arg == "--input-dir") {
      options.input_dir = requireValue(arg);
    } else if (arg == "--input-file") {
      options.input_files.push_back(requireValue(arg));
    } else if (arg == "--token-file") {
      options.token_filter_file = requireValue(arg);
    } else if (arg == "--tokens") {
      const auto parsed = parseTokenList(requireValue(arg));
      options.tokens.insert(options.tokens.end(), parsed.begin(), parsed.end());
    } else if (arg == "--sim-config") {
      options.simulator_config_path = requireValue(arg);
    } else if (arg == "--dest") {
      options.default_destination = parseDestination(requireValue(arg));
    } else if (arg == "--stream-dest") {
      auto parsed = parseStreamDestination(requireValue(arg));
      options.stream_destinations[parsed.first] = std::move(parsed.second);
    } else if (arg == "--out-interface") {
      options.outgoing_interface_ip = requireValue(arg);
    } else if (arg == "--pace") {
      const std::string mode = requireValue(arg);
      if (mode == "none") {
        options.pacing = ReplayPacingMode::kNone;
      } else if (mode == "captured") {
        options.pacing = ReplayPacingMode::kCaptured;
      } else {
        throw std::runtime_error("Unknown pacing mode: " + mode);
      }
    } else if (arg == "--speed") {
      options.speed = std::stod(requireValue(arg));
    } else if (arg == "--max-records") {
      options.max_records = std::stoull(requireValue(arg));
    } else if (arg == "--loop") {
      options.loop = true;
    } else if (arg == "--help") {
      throw std::runtime_error("help");
    } else {
      throw std::runtime_error("Unknown argument: " + arg);
    }
  }

  if (options.input_dir.empty() && options.input_files.empty()) {
    throw std::runtime_error("Replay input missing. Use --input-dir or --input-file");
  }
  return options;
}

class MulticastReplayApp::Impl {
public:
  explicit Impl(ReplayOptions options)
      : options_(std::move(options)) {}

  void run() {
    const ResolvedReplayOptions resolved = resolveOptions(options_);

    std::cerr << "Replay selected " << resolved.input_files.size() << " capture files";
    if (resolved.default_destination.has_value()) {
      std::cerr << " to " << describeDestination(*resolved.default_destination);
    }
    if (!resolved.stream_destinations.empty()) {
      std::cerr << " with " << resolved.stream_destinations.size() << " stream-specific route(s)";
    }
    if (resolved.pacing == ReplayPacingMode::kCaptured) {
      std::cerr << " using captured pacing x" << resolved.speed;
    } else {
      std::cerr << " with no pacing";
    }
    std::cerr << '\n';

    uint64_t total_sent = 0;
    do {
      total_sent += replayOnePass(resolved, total_sent);
      if (resolved.max_records != 0 && total_sent >= resolved.max_records) {
        break;
      }
    } while (resolved.loop);

    std::cerr << "Replay complete. Sent " << total_sent << " packet(s)\n";
  }

private:
  uint64_t replayOnePass(const ResolvedReplayOptions& resolved, uint64_t already_sent) const {
    UdpReplaySender sender(resolved.default_destination, resolved.stream_destinations,
                           resolved.outgoing_interface_ip);

    std::vector<std::unique_ptr<CaptureRecordReader>> readers;
    readers.reserve(resolved.input_files.size());
    for (const auto& path : resolved.input_files) {
      readers.push_back(std::make_unique<CaptureRecordReader>(path));
    }

    std::priority_queue<ReplayCursor, std::vector<ReplayCursor>, ReplayCursorCompare> queue;
    for (std::size_t index = 0; index < readers.size(); ++index) {
      CaptureRecord record;
      if (readers[index]->readNext(&record)) {
        queue.push(ReplayCursor {record, index});
      }
    }

    std::optional<uint64_t> first_capture_time_ns;
    std::optional<std::chrono::steady_clock::time_point> first_wall_time;
    uint64_t sent = 0;

    while (!queue.empty()) {
      if (resolved.max_records != 0 && already_sent + sent >= resolved.max_records) {
        break;
      }

      ReplayCursor cursor = queue.top();
      queue.pop();

      if (resolved.pacing == ReplayPacingMode::kCaptured) {
        if (!first_capture_time_ns.has_value()) {
          first_capture_time_ns = cursor.record.capture_time_ns;
          first_wall_time = std::chrono::steady_clock::now();
        } else {
          const uint64_t delta_ns = cursor.record.capture_time_ns - *first_capture_time_ns;
          const auto scaled_delta = static_cast<uint64_t>(
              std::llround(static_cast<long double>(delta_ns) / resolved.speed));
          std::this_thread::sleep_until(*first_wall_time + std::chrono::nanoseconds(scaled_delta));
        }
      }

      sender.send(cursor.record);
      ++sent;

      CaptureRecord next_record;
      if (readers[cursor.reader_index]->readNext(&next_record)) {
        queue.push(ReplayCursor {next_record, cursor.reader_index});
      }
    }

    return sent;
  }

  ReplayOptions options_;
};

MulticastReplayApp::MulticastReplayApp(ReplayOptions options)
    : impl_(new Impl(std::move(options))) {}

MulticastReplayApp::~MulticastReplayApp() {
  delete impl_;
}

void MulticastReplayApp::run() {
  impl_->run();
}

}  // namespace nse_fo_exchange_sim
