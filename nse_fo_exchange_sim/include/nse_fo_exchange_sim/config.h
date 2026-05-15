#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace nse_fo_exchange_sim {

struct MarketDataEndpoint {
  std::string host;
  uint16_t port = 0;
  std::string interface_ip = "0.0.0.0";
};

struct Config {
  std::string listen_host = "127.0.0.1";
  uint16_t gr_tls_port = 24443;
  uint16_t session_port = 25000;
  std::string tls_cert_pem;
  std::string tls_key_pem;
  uint16_t box_id = 1;
  uint8_t default_stream_no = 1;
  uint64_t exchange_order_number_start = 1000000;
  uint32_t fill_number_start = 1;
  uint64_t fill_delay_us = 0;
  std::string token_filter_file;
  std::size_t max_book_contracts = 1024;
  std::vector<MarketDataEndpoint> market_data_streams;

  static Config loadFromFile(const std::string& path);
};

}  // namespace nse_fo_exchange_sim
