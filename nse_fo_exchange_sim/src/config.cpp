#include "nse_fo_exchange_sim/config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace nse_fo_exchange_sim {
namespace {

std::string trim(std::string value) {
  auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
  return value;
}

}  // namespace

Config Config::loadFromFile(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("Unable to open config file: " + path);
  }

  Config config;
  std::string line;
  std::size_t line_no = 0;

  while (std::getline(input, line)) {
    ++line_no;
    const auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos) {
      line.erase(comment_pos);
    }
    line = trim(line);
    if (line.empty()) {
      continue;
    }

    const auto equal_pos = line.find('=');
    if (equal_pos == std::string::npos) {
      throw std::runtime_error("Invalid config line " + std::to_string(line_no) + ": " + line);
    }

    const std::string key = trim(line.substr(0, equal_pos));
    const std::string value = trim(line.substr(equal_pos + 1));

    if (key == "listen_host") {
      config.listen_host = value;
    } else if (key == "gr_tls_port") {
      config.gr_tls_port = static_cast<uint16_t>(std::stoul(value));
    } else if (key == "session_port") {
      config.session_port = static_cast<uint16_t>(std::stoul(value));
    } else if (key == "tls_cert_pem") {
      config.tls_cert_pem = value;
    } else if (key == "tls_key_pem") {
      config.tls_key_pem = value;
    } else if (key == "box_id") {
      config.box_id = static_cast<uint16_t>(std::stoul(value));
    } else if (key == "default_stream_no") {
      config.default_stream_no = static_cast<uint8_t>(std::stoul(value));
    } else if (key == "exchange_order_number_start") {
      config.exchange_order_number_start = std::stoull(value);
    } else if (key == "fill_number_start") {
      config.fill_number_start = static_cast<uint32_t>(std::stoul(value));
    } else if (key == "fill_delay_us") {
      config.fill_delay_us = std::stoull(value);
    } else {
      throw std::runtime_error("Unknown config key: " + key);
    }
  }

  if (config.tls_cert_pem.empty()) {
    throw std::runtime_error("tls_cert_pem is required");
  }
  if (config.tls_key_pem.empty()) {
    throw std::runtime_error("tls_key_pem is required");
  }

  return config;
}

}  // namespace nse_fo_exchange_sim
