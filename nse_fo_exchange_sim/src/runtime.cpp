#include "nse_fo_exchange_sim/simulator.h"

#include "nse_fo_exchange_sim/crypto.h"
#include "nse_fo_exchange_sim/protocol.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <iostream>
namespace nse_fo_exchange_sim {
namespace {

using namespace protocol;

constexpr std::size_t kMaxSessionPayload = 2048;
constexpr std::size_t kMaxMarketDataPayload = 2048;
constexpr uint16_t kErrorUnsupportedOrder = 1;
constexpr uint16_t kErrorUnknownOrder = 2;
constexpr uint16_t kErrorNoLiquidity = 3;
constexpr uint16_t kErrorUnsupportedToken = 4;

uint64_t nowNanos() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

uint32_t nowSeconds32() {
  return static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string trim(std::string value) {
  auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
  return value;
}

bool isMulticastIpv4(const std::string& host) {
  in_addr addr {};
  if (inet_pton(AF_INET, host.c_str(), &addr) != 1) {
    return false;
  }
  const uint32_t host_order = ntohl(addr.s_addr);
  const uint8_t first_octet = static_cast<uint8_t>((host_order >> 24) & 0xFF);
  return first_octet >= 224 && first_octet <= 239;
}

uint64_t doubleBits(double value) {
  uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

bool isTbtBuySide(uint8_t order_type) {
  return (order_type & 1U) == 0;
}

int createListenSocket(const std::string& host, uint16_t port, uint16_t* bound_port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    throw std::runtime_error("socket() failed");
  }

  int reuse = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
    close(fd);
    throw std::runtime_error("setsockopt(SO_REUSEADDR) failed");
  }

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    close(fd);
    throw std::runtime_error("inet_pton failed for host: " + host);
  }

  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd);
    throw std::runtime_error("bind() failed");
  }

  if (listen(fd, 32) != 0) {
    close(fd);
    throw std::runtime_error("listen() failed");
  }

  sockaddr_in bound_addr {};
  socklen_t len = sizeof(bound_addr);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound_addr), &len) != 0) {
    close(fd);
    throw std::runtime_error("getsockname() failed");
  }

  *bound_port = ntohs(bound_addr.sin_port);
  return fd;
}

int createMarketDataSocket(const MarketDataEndpoint& endpoint) {
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    throw std::runtime_error("socket(AF_INET, SOCK_DGRAM) failed");
  }

  int reuse = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
    close(fd);
    throw std::runtime_error("setsockopt(SO_REUSEADDR) failed for market data");
  }

  timeval timeout {};
  timeout.tv_usec = 200000;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
    close(fd);
    throw std::runtime_error("setsockopt(SO_RCVTIMEO) failed for market data");
  }

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(endpoint.port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd);
    throw std::runtime_error("bind() failed for market data port " + std::to_string(endpoint.port));
  }

  if (isMulticastIpv4(endpoint.host)) {
    ip_mreq membership {};
    if (inet_pton(AF_INET, endpoint.host.c_str(), &membership.imr_multiaddr) != 1) {
      close(fd);
      throw std::runtime_error("inet_pton failed for multicast group: " + endpoint.host);
    }
    if (endpoint.interface_ip.empty() || endpoint.interface_ip == "0.0.0.0") {
      membership.imr_interface.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, endpoint.interface_ip.c_str(), &membership.imr_interface) != 1) {
      close(fd);
      throw std::runtime_error("inet_pton failed for multicast interface: " + endpoint.interface_ip);
    }
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &membership, sizeof(membership)) != 0) {
      close(fd);
      throw std::runtime_error("IP_ADD_MEMBERSHIP failed for market data stream");
    }
  }

  return fd;
}

std::string peerIpAddress(int fd) {
  if (fd < 0) {
    return "";
  }

  sockaddr_in addr {};
  socklen_t addr_len = sizeof(addr);
  if (getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &addr_len) != 0) {
    return "";
  }

  char ip_buffer[INET_ADDRSTRLEN] {};
  if (inet_ntop(AF_INET, &addr.sin_addr, ip_buffer, sizeof(ip_buffer)) == nullptr) {
    return "";
  }
  return std::string(ip_buffer);
}

std::string ipv4Address(const sockaddr_in& addr) {
  char ip_buffer[INET_ADDRSTRLEN] {};
  if (inet_ntop(AF_INET, &addr.sin_addr, ip_buffer, sizeof(ip_buffer)) == nullptr) {
    return "";
  }
  return std::string(ip_buffer);
}

void logTbtOrderMessage(const TbtOrderMessage& message,
                        const sockaddr_in& peer_addr,
                        std::size_t packet_size) {
  std::cout << "[tbt feed] contract_token=" << message.token
            << " packet=order"
            << " type=" << static_cast<char>(message.header.message_type)
            << " stream_id=" << message.header.stream_id
            << " seq_no=" << message.header.seq_no
            << " order_id_bits=" << doubleBits(message.order_id)
            << " price=" << message.price
            << " quantity=" << message.quantity
            << " source=" << ipv4Address(peer_addr) << ':' << ntohs(peer_addr.sin_port)
            << " bytes=" << packet_size << std::endl;
}

void logTbtTradeMessage(const TbtTradeMessage& message,
                        const sockaddr_in& peer_addr,
                        std::size_t packet_size) {
  std::cout << "[tbt feed] contract_token=" << message.token
            << " packet=trade"
            << " type=" << static_cast<char>(message.header.message_type)
            << " stream_id=" << message.header.stream_id
            << " seq_no=" << message.header.seq_no
            << " buy_order_id_bits=" << doubleBits(message.buy_order_id)
            << " sell_order_id_bits=" << doubleBits(message.sell_order_id)
            << " trade_price=" << message.trade_price
            << " trade_quantity=" << message.trade_quantity
            << " source=" << ipv4Address(peer_addr) << ':' << ntohs(peer_addr.sin_port)
            << " bytes=" << packet_size << std::endl;
}

void readFully(int fd, void* buffer, std::size_t size) {
  auto* out = static_cast<uint8_t*>(buffer);
  std::size_t read_total = 0;
  while (read_total < size) {
    const ssize_t rc = recv(fd, out + read_total, size - read_total, 0);
    if (rc <= 0) {
      throw std::runtime_error("socket read failed");
    }
    read_total += static_cast<std::size_t>(rc);
  }
}

void writeFully(int fd, const void* buffer, std::size_t size) {
  const auto* in = static_cast<const uint8_t*>(buffer);
  std::size_t written_total = 0;
  while (written_total < size) {
    const ssize_t rc = send(fd, in + written_total, size - written_total, 0);
    if (rc <= 0) {
      throw std::runtime_error("socket write failed");
    }
    written_total += static_cast<std::size_t>(rc);
  }
}

void sslReadFully(SSL* ssl, void* buffer, std::size_t size) {
  auto* out = static_cast<uint8_t*>(buffer);
  std::size_t read_total = 0;
  while (read_total < size) {
    const int rc = SSL_read(ssl, out + read_total, static_cast<int>(size - read_total));
    if (rc <= 0) {
      throw std::runtime_error("SSL_read failed");
    }
    read_total += static_cast<std::size_t>(rc);
  }
}

void sslWriteFully(SSL* ssl, const void* buffer, std::size_t size) {
  const auto* in = static_cast<const uint8_t*>(buffer);
  std::size_t written_total = 0;
  while (written_total < size) {
    const int rc = SSL_write(ssl, in + written_total, static_cast<int>(size - written_total));
    if (rc <= 0) {
      throw std::runtime_error("SSL_write failed");
    }
    written_total += static_cast<std::size_t>(rc);
  }
}

void initializeTlsContext(SSL_CTX* ctx, const Config& config) {
  auto currentOpenSslError = []() {
    const unsigned long error_code = ERR_get_error();
    if (error_code == 0) {
      return std::string("unknown OpenSSL error");
    }
    char buffer[256] {};
    ERR_error_string_n(error_code, buffer, sizeof(buffer));
    return std::string(buffer);
  };

  SSL_CTX_set_security_level(ctx, 0);

  if (SSL_CTX_use_certificate_file(ctx, config.tls_cert_pem.c_str(), SSL_FILETYPE_PEM) <= 0) {
    throw std::runtime_error("SSL_CTX_use_certificate_file failed for " + config.tls_cert_pem +
                             ": " + currentOpenSslError());
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, config.tls_key_pem.c_str(), SSL_FILETYPE_PEM) <= 0) {
    throw std::runtime_error("SSL_CTX_use_PrivateKey_file failed for " + config.tls_key_pem +
                             ": " + currentOpenSslError());
  }
  if (!SSL_CTX_check_private_key(ctx)) {
    throw std::runtime_error("TLS private key does not match certificate");
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
}

bool digestMatches(const uint8_t* digest, const std::vector<uint8_t>& payload) {
  const auto expected = Md5Digest::compute(payload.data(), payload.size());
  return std::memcmp(digest, expected.data(), expected.size()) == 0;
}

struct SessionTicket {
  std::string peer_ip;
  uint16_t box_id = 0;
  uint64_t session_key = 0;
  std::array<uint8_t, 32> crypto_key {};
  std::array<uint8_t, 16> crypto_iv {};
};

class PendingTicketStore {
public:
  void add(SessionTicket ticket) {
    std::lock_guard<std::mutex> lock(mutex_);
    tickets_.push_back(std::move(ticket));
  }

  std::optional<SessionTicket> claimForPeer(const std::string& peer_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(tickets_.begin(), tickets_.end(),
                           [&](const SessionTicket& ticket) { return ticket.peer_ip == peer_ip; });
    if (it == tickets_.end()) {
      return std::nullopt;
    }
    SessionTicket ticket = *it;
    tickets_.erase(it);
    return ticket;
  }

private:
  std::mutex mutex_;
  std::deque<SessionTicket> tickets_;
};

class SessionConnection;

struct OrderSnapshot {
  uint32_t user_id = 0;
  uint32_t token = 0;
  ContractDescTr contract_description {};
  std::array<uint8_t, 10> account_number {};
  uint16_t book_type = 0;
  uint16_t side = 0;
  uint32_t disclosed_volume = 0;
  uint32_t disclosed_volume_remaining = 0;
  uint32_t total_volume_remaining = 0;
  uint32_t volume = 0;
  uint32_t volume_filled_today = 0;
  uint32_t price = 0;
  uint32_t good_till_date = 0;
  uint8_t order_flags1 = 0;
  uint8_t order_flags2 = 0;
  uint16_t branch_id = 0;
  uint32_t trader_id = 0;
  std::array<uint8_t, 5> broker_id {};
  uint8_t open_close = ' ';
  std::array<uint8_t, 12> settlor {};
  uint16_t pro_client_indicator = 0;
  uint8_t additional_flags = 0;
  uint32_t filler = 0;
  double nnf_field_wire = 0.0;
  std::array<uint8_t, 10> pan {};
  uint32_t algo_id = 0;
  uint16_t unique_id = 0;
  uint64_t exchange_order_number = 0;
  uint64_t last_activity_reference = 0;
  uint32_t fill_number = 0;
  uint64_t event_nanos = 0;
  uint32_t event_seconds = 0;
  uint32_t entry_date_time = 0;
  uint32_t last_modified = 0;
  bool ioc = false;
  uint64_t session_id = 0;
  std::weak_ptr<SessionConnection> session;
};

struct EngineEvent {
  std::weak_ptr<SessionConnection> session;
  OrderSnapshot order;
  uint16_t txn_code = 0;
  uint16_t error_code = 0;
  uint32_t fill_quantity = 0;
  uint32_t fill_price = 0;
};

struct TopOfBookMatch {
  uint32_t price = 0;
  uint32_t quantity = 0;
};

struct PriceLevelState {
  uint64_t quantity = 0;
  uint32_t order_count = 0;
};

struct MarketOrderState {
  bool is_buy = false;
  uint32_t price = 0;
  uint32_t quantity = 0;
};

class ExternalBook {
public:
  void onNew(uint64_t order_id, bool is_buy, uint32_t price, uint32_t quantity) {
    auto existing = orders_.find(order_id);
    if (existing != orders_.end()) {
      onModify(order_id, is_buy, price, quantity);
      return;
    }

    if (is_buy) {
      addLevel(bids_, price, quantity);
    } else {
      addLevel(asks_, price, quantity);
    }
    orders_[order_id] = MarketOrderState {is_buy, price, quantity};
  }

  void onModify(uint64_t order_id, bool is_buy, uint32_t price, uint32_t quantity) {
    auto existing = orders_.find(order_id);
    if (existing != orders_.end()) {
      if (existing->second.is_buy) {
        removeLevel(bids_, existing->second.price, existing->second.quantity, true);
      } else {
        removeLevel(asks_, existing->second.price, existing->second.quantity, true);
      }
      orders_.erase(existing);
    }
    onNew(order_id, is_buy, price, quantity);
  }

  void onCancel(uint64_t order_id, bool is_buy, uint32_t price, uint32_t quantity) {
    if (!removeKnown(order_id, quantity)) {
      if (is_buy) {
        removeLevel(bids_, price, quantity, false);
      } else {
        removeLevel(asks_, price, quantity, false);
      }
    }
  }

  void onTrade(uint64_t buy_order_id, uint64_t sell_order_id, uint32_t trade_price, uint32_t trade_quantity) {
    if (!removeKnown(buy_order_id, trade_quantity)) {
      removeLevel(bids_, trade_price, trade_quantity, false);
    }
    if (!removeKnown(sell_order_id, trade_quantity)) {
      removeLevel(asks_, trade_price, trade_quantity, false);
    }
  }

  bool bestBid(uint32_t* price, uint32_t* quantity) const {
    if (bids_.empty()) {
      return false;
    }
    *price = bids_.begin()->first;
    *quantity = static_cast<uint32_t>(bids_.begin()->second.quantity);
    return true;
  }

  bool bestAsk(uint32_t* price, uint32_t* quantity) const {
    if (asks_.empty()) {
      return false;
    }
    *price = asks_.begin()->first;
    *quantity = static_cast<uint32_t>(asks_.begin()->second.quantity);
    return true;
  }

private:
  template <typename Map>
  static void addLevel(Map& side, uint32_t price, uint32_t quantity) {
    auto& level = side[price];
    level.quantity += quantity;
    level.order_count += 1;
  }

  template <typename Map>
  static void removeLevel(Map& side, uint32_t price, uint32_t quantity, bool decrement_order_count) {
    auto it = side.find(price);
    if (it == side.end()) {
      return;
    }

    if (it->second.quantity <= quantity) {
      side.erase(it);
      return;
    }

    it->second.quantity -= quantity;
    if (decrement_order_count && it->second.order_count > 0) {
      --it->second.order_count;
    }
    if (it->second.quantity == 0 || it->second.order_count == 0) {
      side.erase(it);
    }
  }

  bool removeKnown(uint64_t order_id, uint32_t quantity) {
    auto it = orders_.find(order_id);
    if (it == orders_.end()) {
      return false;
    }

    const uint32_t remove_qty =
        (quantity == 0 || quantity >= it->second.quantity) ? it->second.quantity : quantity;
    const bool remove_order_count = remove_qty >= it->second.quantity;
    if (it->second.is_buy) {
      removeLevel(bids_, it->second.price, remove_qty, remove_order_count);
    } else {
      removeLevel(asks_, it->second.price, remove_qty, remove_order_count);
    }
    if (remove_order_count) {
      orders_.erase(it);
    } else {
      it->second.quantity -= remove_qty;
    }
    return true;
  }

  std::map<uint32_t, PriceLevelState, std::greater<uint32_t>> bids_;
  std::map<uint32_t, PriceLevelState> asks_;
  std::unordered_map<uint64_t, MarketOrderState> orders_;
};

class MatchingEngine {
public:
  explicit MatchingEngine(const Config& config)
      : config_(config),
        next_exchange_order_number_(config.exchange_order_number_start),
        next_fill_number_(config.fill_number_start),
        next_last_activity_reference_(1) {
    loadTokenFilter();
  }

  bool marketDataEnabled() const {
    return !config_.market_data_streams.empty();
  }

  std::vector<EngineEvent> onNewOrder(const OrderEntryRequestPayload& request,
                                      uint64_t session_id,
                                      const std::weak_ptr<SessionConnection>& session) {
    OrderSnapshot snapshot = buildSnapshotFromEntryRequest(request, session_id, session);
    if (!isValidNewOrder(snapshot, request)) {
      stampOrder(snapshot, true);
      return {makeOrderEvent(snapshot, kTxnOrderErrorTrimmed, kErrorUnsupportedOrder)};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (marketDataEnabled()) {
      if (!canTrackTokenLocked(snapshot.token)) {
        stampOrder(snapshot, true);
        return {makeOrderEvent(snapshot, kTxnOrderErrorTrimmed, kErrorUnsupportedToken)};
      }
      static_cast<void>(ensureBookLocked(snapshot.token));
    }

    snapshot.exchange_order_number = next_exchange_order_number_.fetch_add(1);
    snapshot.last_activity_reference = next_last_activity_reference_.fetch_add(1);
    stampOrder(snapshot, true);

    if (!marketDataEnabled()) {
      std::vector<EngineEvent> events;
      events.push_back(makeOrderEvent(snapshot, kTxnOrderConfirmationTrimmed, 0));

      OrderSnapshot fill_snapshot = snapshot;
      fill_snapshot.last_activity_reference = next_last_activity_reference_.fetch_add(1);
      fill_snapshot.fill_number = next_fill_number_.fetch_add(1);
      applyFillToSnapshot(fill_snapshot, fill_snapshot.total_volume_remaining);
      stampOrder(fill_snapshot, false);
      events.push_back(
          makeTradeEvent(fill_snapshot, fill_snapshot.price, fill_snapshot.volume_filled_today));
      return events;
    }

    if (snapshot.ioc) {
      std::vector<EngineEvent> events;
      events.push_back(makeOrderEvent(snapshot, kTxnOrderConfirmationTrimmed, 0));
      const auto top = matchTopLocked(snapshot);
      if (!top.has_value()) {
        appendEvents(events, cancelUnfilledOrderLocked(snapshot));
        return events;
      }

      const uint32_t fill_quantity = std::min(snapshot.total_volume_remaining, top->quantity);
      if (fill_quantity > 0) {
        OrderSnapshot fill_snapshot = snapshot;
        fill_snapshot.last_activity_reference = next_last_activity_reference_.fetch_add(1);
        fill_snapshot.fill_number = next_fill_number_.fetch_add(1);
        applyFillToSnapshot(fill_snapshot, fill_quantity);
        stampOrder(fill_snapshot, false);
        events.push_back(makeTradeEvent(fill_snapshot, top->price, fill_quantity));
        if (fill_snapshot.total_volume_remaining > 0) {
          appendEvents(events, cancelUnfilledOrderLocked(fill_snapshot));
        }
        return events;
      }

      appendEvents(events, cancelUnfilledOrderLocked(snapshot));
      return events;
    }

    storeOpenOrderLocked(snapshot);
    std::vector<EngineEvent> events;
    events.push_back(makeOrderEvent(snapshot, kTxnOrderConfirmationTrimmed, 0));

    const auto top = matchTopLocked(snapshot);
    if (top.has_value()) {
      appendEvents(events,
                   fillOpenOrderLocked(snapshot.exchange_order_number, top->price, top->quantity));
    }
    return events;
  }

  std::vector<EngineEvent> onModifyOrder(const OrderUpdateRequestPayload& request,
                                         uint64_t session_id,
                                         const std::weak_ptr<SessionConnection>& session) {
    OrderSnapshot request_snapshot = buildSnapshotFromUpdateRequest(request, session_id, session);
    request_snapshot.exchange_order_number = decodeExchangeOrderNumber(request.order_number);

    if (!isValidModifyRequest(request_snapshot, request)) {
      stampOrder(request_snapshot, false);
      return {makeOrderEvent(request_snapshot, kTxnOrderModificationErrorTrimmed, kErrorUnsupportedOrder)};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = open_orders_.find(request_snapshot.exchange_order_number);
    if (it == open_orders_.end() || it->second.session_id != session_id) {
      stampOrder(request_snapshot, false);
      return {makeOrderEvent(request_snapshot, kTxnOrderModificationErrorTrimmed, kErrorUnknownOrder)};
    }

    OrderSnapshot& live = it->second;
    if (live.token != request_snapshot.token || live.side != request_snapshot.side ||
        live.book_type != request_snapshot.book_type || live.ioc) {
      stampOrder(request_snapshot, false);
      return {makeOrderEvent(request_snapshot, kTxnOrderModificationErrorTrimmed, kErrorUnsupportedOrder)};
    }

    live.contract_description = request_snapshot.contract_description;
    live.account_number = request_snapshot.account_number;
    live.disclosed_volume = request_snapshot.disclosed_volume;
    live.disclosed_volume_remaining =
        request_snapshot.disclosed_volume_remaining == 0 && request_snapshot.disclosed_volume > 0
            ? request_snapshot.disclosed_volume
            : std::min(request_snapshot.disclosed_volume_remaining, request_snapshot.disclosed_volume);
    live.total_volume_remaining =
        request_snapshot.total_volume_remaining == 0 && request_snapshot.volume > 0
            ? request_snapshot.volume
            : std::min(request_snapshot.total_volume_remaining, request_snapshot.volume);
    live.volume = request_snapshot.volume;
    live.volume_filled_today = request_snapshot.volume_filled_today;
    live.price = request_snapshot.price;
    live.good_till_date = request_snapshot.good_till_date;
    live.order_flags1 = request_snapshot.order_flags1;
    live.order_flags2 = request_snapshot.order_flags2;
    live.branch_id = request_snapshot.branch_id;
    live.trader_id = request_snapshot.trader_id;
    live.broker_id = request_snapshot.broker_id;
    live.open_close = request_snapshot.open_close;
    live.settlor = request_snapshot.settlor;
    live.pro_client_indicator = request_snapshot.pro_client_indicator;
    live.additional_flags = request_snapshot.additional_flags;
    live.filler = request_snapshot.filler;
    live.nnf_field_wire = request_snapshot.nnf_field_wire;
    live.pan = request_snapshot.pan;
    live.algo_id = request_snapshot.algo_id;
    live.unique_id = request_snapshot.unique_id;
    live.last_activity_reference = next_last_activity_reference_.fetch_add(1);
    stampOrder(live, false);

    std::vector<EngineEvent> events;
    events.push_back(makeOrderEvent(live, kTxnOrderModificationConfirmationTrimmed, 0));

    const auto top = matchTopLocked(live);
    if (top.has_value()) {
      appendEvents(events, fillOpenOrderLocked(live.exchange_order_number, top->price, top->quantity));
    }
    return events;
  }

  std::vector<EngineEvent> onCancelOrder(const OrderUpdateRequestPayload& request,
                                         uint64_t session_id,
                                         const std::weak_ptr<SessionConnection>& session) {
    OrderSnapshot request_snapshot = buildSnapshotFromUpdateRequest(request, session_id, session);
    request_snapshot.exchange_order_number = decodeExchangeOrderNumber(request.order_number);

    if (!isValidCancelRequest(request_snapshot, request)) {
      stampOrder(request_snapshot, false);
      return {makeOrderEvent(request_snapshot, kTxnOrderCancellationErrorTrimmed, kErrorUnsupportedOrder)};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = open_orders_.find(request_snapshot.exchange_order_number);
    if (it == open_orders_.end() || it->second.session_id != session_id) {
      stampOrder(request_snapshot, false);
      return {makeOrderEvent(request_snapshot, kTxnOrderCancellationErrorTrimmed, kErrorUnknownOrder)};
    }

    OrderSnapshot cancelled = it->second;
    cancelled.last_activity_reference = next_last_activity_reference_.fetch_add(1);
    cancelled.disclosed_volume_remaining = 0;
    cancelled.total_volume_remaining = 0;
    stampOrder(cancelled, false);
    eraseOpenOrderLocked(cancelled);
    return {makeOrderEvent(cancelled, kTxnOrderCancellationConfirmationTrimmed, 0)};
  }

  std::vector<EngineEvent> onTbtOrderMessage(const TbtOrderMessage& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    ExternalBook* book = ensureBookLocked(message.token);
    if (book == nullptr) {
      return {};
    }

    const uint64_t order_id = doubleBits(message.order_id);
    const bool is_buy = isTbtBuySide(message.order_type);
    switch (message.header.message_type) {
      case 'N':
        book->onNew(order_id, is_buy, message.price, message.quantity);
        break;
      case 'M':
        book->onModify(order_id, is_buy, message.price, message.quantity);
        break;
      case 'X':
        book->onCancel(order_id, is_buy, message.price, message.quantity);
        break;
      default:
        return {};
    }
    return maybeFillRestingOrdersLocked(message.token);
  }

  std::vector<EngineEvent> onTbtTradeMessage(const TbtTradeMessage& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    ExternalBook* book = ensureBookLocked(message.token);
    if (book == nullptr) {
      return {};
    }

    book->onTrade(doubleBits(message.buy_order_id), doubleBits(message.sell_order_id),
                  message.trade_price, message.trade_quantity);
    return maybeFillRestingOrdersLocked(message.token);
  }

  void onSessionClosed(uint64_t session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto session_it = open_order_ids_by_session_.find(session_id);
    if (session_it == open_order_ids_by_session_.end()) {
      return;
    }

    std::vector<uint64_t> order_ids(session_it->second.begin(), session_it->second.end());
    for (uint64_t order_id : order_ids) {
      const auto order_it = open_orders_.find(order_id);
      if (order_it != open_orders_.end()) {
        eraseOpenOrderLocked(order_it->second);
      }
    }
  }

private:
  static uint64_t decodeExchangeOrderNumber(double wire_order_number) {
    return static_cast<uint64_t>(wireToHostDouble(wire_order_number));
  }

  static void appendEvents(std::vector<EngineEvent>& target, const std::vector<EngineEvent>& source) {
    target.insert(target.end(), source.begin(), source.end());
  }

  void loadTokenFilter() {
    if (config_.token_filter_file.empty()) {
      return;
    }

    std::ifstream input(config_.token_filter_file);
    if (!input) {
      throw std::runtime_error("Unable to open token_filter_file: " + config_.token_filter_file);
    }

    std::string line;
    while (std::getline(input, line)) {
      const auto comment_pos = line.find('#');
      if (comment_pos != std::string::npos) {
        line.erase(comment_pos);
      }
      line = trim(line);
      if (line.empty()) {
        continue;
      }
      allowed_tokens_.insert(static_cast<uint32_t>(std::stoul(line)));
    }
  }

  static void stampOrder(OrderSnapshot& order, bool set_entry_time) {
    order.event_seconds = nowSeconds32();
    order.event_nanos = nowNanos();
    if (set_entry_time || order.entry_date_time == 0) {
      order.entry_date_time = order.event_seconds;
    }
    order.last_modified = order.event_seconds;
  }

  static OrderSnapshot buildSnapshotFromEntryRequest(const OrderEntryRequestPayload& request,
                                                     uint64_t session_id,
                                                     const std::weak_ptr<SessionConnection>& session) {
    OrderSnapshot snapshot;
    snapshot.user_id = byteswap(request.user_id);
    snapshot.token = byteswap(request.token_no);
    snapshot.contract_description = request.contract_description;
    std::memcpy(snapshot.account_number.data(), request.account_number, snapshot.account_number.size());
    snapshot.book_type = byteswap(request.book_type);
    snapshot.side = byteswap(request.buy_sell_indicator);
    snapshot.disclosed_volume = byteswap(request.disclosed_volume);
    snapshot.disclosed_volume_remaining = snapshot.disclosed_volume;
    snapshot.total_volume_remaining = byteswap(request.volume);
    snapshot.volume = byteswap(request.volume);
    snapshot.price = byteswap(request.price);
    snapshot.good_till_date = byteswap(request.good_till_date);
    snapshot.order_flags1 = request.order_flags1;
    snapshot.order_flags2 = request.order_flags2;
    snapshot.branch_id = byteswap(request.branch_id);
    snapshot.trader_id = byteswap(request.trader_id);
    std::memcpy(snapshot.broker_id.data(), request.broker_id, snapshot.broker_id.size());
    snapshot.open_close = request.open_close;
    std::memcpy(snapshot.settlor.data(), request.settlor, snapshot.settlor.size());
    snapshot.pro_client_indicator = byteswap(request.pro_client_indicator);
    snapshot.additional_flags = request.additional_flags;
    snapshot.filler = byteswap(request.filler);
    snapshot.nnf_field_wire = request.nnf_field;
    std::memcpy(snapshot.pan.data(), request.pan, snapshot.pan.size());
    snapshot.algo_id = byteswap(request.algo_id);
    snapshot.unique_id = byteswap(request.unique_id);
    snapshot.ioc = request.order_flags1 == kOrderFlagsIoc;
    snapshot.session_id = session_id;
    snapshot.session = session;
    return snapshot;
  }

  static OrderSnapshot buildSnapshotFromUpdateRequest(const OrderUpdateRequestPayload& request,
                                                      uint64_t session_id,
                                                      const std::weak_ptr<SessionConnection>& session) {
    OrderSnapshot snapshot;
    snapshot.user_id = byteswap(request.user_id);
    snapshot.token = byteswap(request.token_no);
    snapshot.contract_description = request.contract_description;
    std::memcpy(snapshot.account_number.data(), request.account_number, snapshot.account_number.size());
    snapshot.book_type = byteswap(request.book_type);
    snapshot.side = byteswap(request.buy_sell_indicator);
    snapshot.disclosed_volume = byteswap(request.disclosed_volume);
    snapshot.disclosed_volume_remaining = byteswap(request.disclosed_volume_remaining);
    snapshot.total_volume_remaining = byteswap(request.total_volume_remaining);
    snapshot.volume = byteswap(request.volume);
    snapshot.volume_filled_today = byteswap(request.volume_filled_today);
    snapshot.price = byteswap(request.price);
    snapshot.good_till_date = byteswap(request.good_till_date);
    snapshot.entry_date_time = byteswap(request.entry_date_time);
    snapshot.last_modified = byteswap(request.last_modified);
    snapshot.order_flags1 = request.order_flags1;
    snapshot.order_flags2 = request.order_flags2;
    snapshot.branch_id = byteswap(request.branch_id);
    snapshot.trader_id = byteswap(request.trader_id);
    std::memcpy(snapshot.broker_id.data(), request.broker_id, snapshot.broker_id.size());
    snapshot.open_close = request.open_close;
    std::memcpy(snapshot.settlor.data(), request.settlor, snapshot.settlor.size());
    snapshot.pro_client_indicator = byteswap(request.pro_client_indicator);
    snapshot.additional_flags = request.additional_flags;
    snapshot.filler = byteswap(request.filler);
    snapshot.nnf_field_wire = request.nnf_field;
    std::memcpy(snapshot.pan.data(), request.pan, snapshot.pan.size());
    snapshot.algo_id = byteswap(request.algo_id);
    snapshot.unique_id = byteswap(request.unique_id);
    snapshot.last_activity_reference = byteswap(request.last_activity_reference);
    snapshot.session_id = session_id;
    snapshot.session = session;
    return snapshot;
  }

  static bool isValidSide(uint16_t side) {
    return side == 1 || side == 2;
  }

  static bool isValidNewOrder(const OrderSnapshot& snapshot, const OrderEntryRequestPayload& request) {
    const uint16_t transaction_code = byteswap(request.transaction_code);
    const bool supported_flags =
        (request.order_flags1 == kOrderFlagsDay && request.order_flags2 == 0) ||
        (request.order_flags1 == kOrderFlagsIoc && request.order_flags2 == 0);
    return transaction_code == kTxnOrderEntryTrimmed && snapshot.book_type == 1 &&
           supported_flags && snapshot.open_close == 'O' && snapshot.volume > 0 &&
           snapshot.price > 0 && isValidSide(snapshot.side);
  }

  static bool isValidModifyRequest(const OrderSnapshot& snapshot, const OrderUpdateRequestPayload& request) {
    const uint16_t transaction_code = byteswap(request.transaction_code);
    return transaction_code == kTxnOrderModificationTrimmed && snapshot.book_type == 1 &&
           snapshot.order_flags1 == kOrderFlagsDay && snapshot.order_flags2 == 0x10 &&
           snapshot.open_close == 'O' && snapshot.volume > 0 && snapshot.price > 0 &&
           snapshot.exchange_order_number != 0 && isValidSide(snapshot.side);
  }

  static bool isValidCancelRequest(const OrderSnapshot& snapshot, const OrderUpdateRequestPayload& request) {
    const uint16_t transaction_code = byteswap(request.transaction_code);
    return transaction_code == kTxnOrderCancellationTrimmed && snapshot.book_type == 1 &&
           snapshot.order_flags1 == kOrderFlagsDay && snapshot.order_flags2 == 0 &&
           snapshot.open_close == 'O' && snapshot.exchange_order_number != 0 &&
           isValidSide(snapshot.side);
  }

  static void applyFillToSnapshot(OrderSnapshot& order, uint32_t fill_quantity) {
    const uint32_t applied_fill = std::min(fill_quantity, order.total_volume_remaining);
    order.volume_filled_today += applied_fill;
    order.total_volume_remaining -= applied_fill;
    order.disclosed_volume_remaining =
        applied_fill >= order.disclosed_volume_remaining ? 0 : order.disclosed_volume_remaining - applied_fill;
  }

  bool canTrackTokenLocked(uint32_t token) const {
    if (!marketDataEnabled()) {
      return true;
    }
    if (allowed_tokens_.find(token) == allowed_tokens_.end()) {
      return false;
    }
    return books_.find(token) != books_.end() || books_.size() < config_.max_book_contracts;
  }

  ExternalBook* ensureBookLocked(uint32_t token) {
    if (!marketDataEnabled()) {
      return nullptr;
    }
    if (!canTrackTokenLocked(token)) {
      return nullptr;
    }
    return &books_.try_emplace(token).first->second;
  }

  void storeOpenOrderLocked(const OrderSnapshot& snapshot) {
    open_orders_[snapshot.exchange_order_number] = snapshot;
    open_order_ids_by_token_[snapshot.token].insert(snapshot.exchange_order_number);
    open_order_ids_by_session_[snapshot.session_id].insert(snapshot.exchange_order_number);
  }

  void eraseOpenOrderLocked(const OrderSnapshot& snapshot) {
    open_orders_.erase(snapshot.exchange_order_number);

    auto token_it = open_order_ids_by_token_.find(snapshot.token);
    if (token_it != open_order_ids_by_token_.end()) {
      token_it->second.erase(snapshot.exchange_order_number);
      if (token_it->second.empty()) {
        open_order_ids_by_token_.erase(token_it);
      }
    }

    auto session_it = open_order_ids_by_session_.find(snapshot.session_id);
    if (session_it != open_order_ids_by_session_.end()) {
      session_it->second.erase(snapshot.exchange_order_number);
      if (session_it->second.empty()) {
        open_order_ids_by_session_.erase(session_it);
      }
    }
  }

  std::optional<TopOfBookMatch> matchTopLocked(const OrderSnapshot& snapshot) const {
    if (!marketDataEnabled()) {
      return TopOfBookMatch {snapshot.price,
                             snapshot.total_volume_remaining > 0 ? snapshot.total_volume_remaining
                                                                 : snapshot.volume};
    }

    const auto book_it = books_.find(snapshot.token);
    if (book_it == books_.end()) {
      return std::nullopt;
    }

    uint32_t top_price = 0;
    uint32_t top_qty = 0;
    if (snapshot.side == 1) {
      if (book_it->second.bestAsk(&top_price, &top_qty) && top_qty > 0 && top_price <= snapshot.price) {
        return TopOfBookMatch {top_price, top_qty};
      }
    } else if (snapshot.side == 2) {
      if (book_it->second.bestBid(&top_price, &top_qty) && top_qty > 0 && top_price >= snapshot.price) {
        return TopOfBookMatch {top_price, top_qty};
      }
    }
    return std::nullopt;
  }

  EngineEvent makeOrderEvent(const OrderSnapshot& order, uint16_t txn_code, uint16_t error_code) const {
    EngineEvent event;
    event.session = order.session;
    event.order = order;
    event.txn_code = txn_code;
    event.error_code = error_code;
    return event;
  }

  EngineEvent makeTradeEvent(const OrderSnapshot& order, uint32_t fill_price, uint32_t fill_quantity) const {
    EngineEvent event;
    event.session = order.session;
    event.order = order;
    event.txn_code = kTxnTradeConfirmationTrimmed;
    event.fill_price = fill_price;
    event.fill_quantity = fill_quantity;
    return event;
  }

  std::vector<EngineEvent> cancelUnfilledOrderLocked(const OrderSnapshot& order) {
    OrderSnapshot cancelled = order;
    cancelled.last_activity_reference = next_last_activity_reference_.fetch_add(1);
    cancelled.disclosed_volume_remaining = 0;
    cancelled.total_volume_remaining = 0;
    stampOrder(cancelled, false);
    return {makeOrderEvent(cancelled, kTxnOrderCancellationConfirmationTrimmed, 0)};
  }

  std::vector<EngineEvent> fillOpenOrderLocked(uint64_t exchange_order_number,
                                               uint32_t fill_price,
                                               uint32_t available_quantity) {
    auto it = open_orders_.find(exchange_order_number);
    if (it == open_orders_.end()) {
      return {};
    }
    if (it->second.session.expired()) {
      eraseOpenOrderLocked(it->second);
      return {};
    }

    OrderSnapshot filled = it->second;
    const uint32_t fill_quantity = std::min(available_quantity, filled.total_volume_remaining);
    if (fill_quantity == 0) {
      return {};
    }

    filled.last_activity_reference = next_last_activity_reference_.fetch_add(1);
    filled.fill_number = next_fill_number_.fetch_add(1);
    applyFillToSnapshot(filled, fill_quantity);
    stampOrder(filled, false);
    if (filled.total_volume_remaining == 0) {
      eraseOpenOrderLocked(it->second);
    } else {
      it->second = filled;
    }
    return {makeTradeEvent(filled, fill_price, fill_quantity)};
  }

  std::vector<EngineEvent> maybeFillRestingOrdersLocked(uint32_t token) {
    std::vector<EngineEvent> events;
    const auto token_it = open_order_ids_by_token_.find(token);
    if (token_it == open_order_ids_by_token_.end()) {
      return events;
    }

    const auto book_it = books_.find(token);
    if (book_it == books_.end()) {
      return events;
    }

    uint32_t best_bid_price = 0;
    uint32_t best_bid_qty = 0;
    uint32_t best_ask_price = 0;
    uint32_t best_ask_qty = 0;
    const bool have_bid = book_it->second.bestBid(&best_bid_price, &best_bid_qty) && best_bid_qty > 0;
    const bool have_ask = book_it->second.bestAsk(&best_ask_price, &best_ask_qty) && best_ask_qty > 0;

    struct FillRequest {
      uint64_t order_id = 0;
      uint32_t fill_price = 0;
      uint32_t fill_quantity = 0;
    };

    std::vector<FillRequest> fillable;
    std::vector<OrderSnapshot> stale_orders;
    for (uint64_t order_id : token_it->second) {
      const auto order_it = open_orders_.find(order_id);
      if (order_it == open_orders_.end()) {
        continue;
      }

      const OrderSnapshot& order = order_it->second;
      if (order.session.expired()) {
        stale_orders.push_back(order);
        continue;
      }

      if (order.side == 1) {
        if (have_ask && best_ask_price <= order.price && best_ask_qty > 0) {
          const uint32_t fill_quantity = std::min(order.total_volume_remaining, best_ask_qty);
          if (fill_quantity > 0) {
            fillable.push_back(FillRequest {order_id, best_ask_price, fill_quantity});
            best_ask_qty -= fill_quantity;
          }
        }
      } else if (order.side == 2) {
        if (have_bid && best_bid_price >= order.price && best_bid_qty > 0) {
          const uint32_t fill_quantity = std::min(order.total_volume_remaining, best_bid_qty);
          if (fill_quantity > 0) {
            fillable.push_back(FillRequest {order_id, best_bid_price, fill_quantity});
            best_bid_qty -= fill_quantity;
          }
        }
      }
    }

    for (const auto& stale : stale_orders) {
      eraseOpenOrderLocked(stale);
    }

    for (const auto& fill : fillable) {
      appendEvents(events, fillOpenOrderLocked(fill.order_id, fill.fill_price, fill.fill_quantity));
    }
    return events;
  }

  Config config_;
  std::unordered_set<uint32_t> allowed_tokens_;
  std::unordered_map<uint32_t, ExternalBook> books_;
  std::unordered_map<uint64_t, OrderSnapshot> open_orders_;
  std::unordered_map<uint32_t, std::set<uint64_t>> open_order_ids_by_token_;
  std::unordered_map<uint64_t, std::set<uint64_t>> open_order_ids_by_session_;
  std::mutex mutex_;
  std::atomic<uint64_t> next_exchange_order_number_;
  std::atomic<uint32_t> next_fill_number_;
  std::atomic<uint64_t> next_last_activity_reference_;
};

class SessionConnection : public std::enable_shared_from_this<SessionConnection> {
public:
  SessionConnection(int fd,
                    Config config,
                    SessionTicket ticket,
                    MatchingEngine& engine,
                    uint64_t session_id)
      : fd_(fd),
        config_(std::move(config)),
        ticket_(std::move(ticket)),
        engine_(engine),
        session_id_(session_id) {}

  ~SessionConnection() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  void run() {
    try {
      for (;;) {
        DirectExCtclHeader header {};
        readFully(fd_, &header, sizeof(header));
        const uint16_t wire_length = byteswap(header.length);
        if (wire_length < sizeof(header) || wire_length > kMaxSessionPayload + sizeof(header)) {
          throw std::runtime_error("invalid session packet length");
        }

        std::vector<uint8_t> payload(wire_length - sizeof(header));
        readFully(fd_, payload.data(), payload.size());
        if (encryption_enabled_) {
          inbound_crypto_.xorData(payload.data(), payload.size());
        }
        if (!digestMatches(header.md5_checksum, payload)) {
          throw std::runtime_error("bad session MD5");
        }

        handlePayload(payload);
      }
    } catch (...) {
      closed_.store(true);
      engine_.onSessionClosed(session_id_);
    }
  }

  void dispatchEvent(const EngineEvent& event) {
    if (closed_.load()) {
      return;
    }
    if (event.txn_code == kTxnTradeConfirmationTrimmed && config_.fill_delay_us > 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(config_.fill_delay_us));
    }

    std::lock_guard<std::mutex> lock(write_mutex_);
    if (closed_.load()) {
      return;
    }

    try {
      if (event.txn_code == kTxnTradeConfirmationTrimmed) {
        sendTradeResponse(event.order, event.fill_quantity, event.fill_price);
      } else {
        sendOrderResponse(event.order, event.txn_code, event.error_code);
      }
    } catch (...) {
      closed_.store(true);
      engine_.onSessionClosed(session_id_);
    }
  }

private:
  enum class Phase {
    kAwaitSecureBoxRegistration,
    kAwaitBoxSignOn,
    kAwaitLogin,
    kReady
  };

  void sendPayload(const void* payload, std::size_t size) {
    auto bytes = std::vector<uint8_t>(static_cast<const uint8_t*>(payload),
                                      static_cast<const uint8_t*>(payload) + size);
    const auto digest = Md5Digest::compute(bytes.data(), bytes.size());
    if (encryption_enabled_) {
      outbound_crypto_.xorData(bytes.data(), bytes.size());
    }

    DirectExCtclHeader header {};
    header.length = byteswap<uint16_t>(static_cast<uint16_t>(sizeof(header) + bytes.size()));
    header.sequence_number = byteswap(++sequence_number_);
    std::memcpy(header.md5_checksum, digest.data(), digest.size());
    writeFully(fd_, &header, sizeof(header));
    writeFully(fd_, bytes.data(), bytes.size());
  }

  void sendSecureBoxRegistrationResponse(uint32_t trader_id) {
    SecureBoxRegistrationResponsePayload response {};
    initializeMessageHeader(response.header, kTxnSecureBoxRegistrationResponse, trader_id,
                            sizeof(response));
    sendPayload(&response, sizeof(response));
    inbound_crypto_.initialize(ticket_.crypto_key.data(), ticket_.crypto_iv.data());
    outbound_crypto_.initialize(ticket_.crypto_key.data(), ticket_.crypto_iv.data());
    encryption_enabled_ = true;
    phase_ = Phase::kAwaitBoxSignOn;
  }

  void sendBoxSignOnResponse(uint32_t trader_id) {
    BoxSignOnResponsePayload response {};
    initializeMessageHeader(response.header, kTxnBoxSignOnRequestOut, trader_id, sizeof(response));
    response.box_id = byteswap(ticket_.box_id);
    sendPayload(&response, sizeof(response));
    phase_ = Phase::kAwaitLogin;
  }

  void sendLogonResponse(const SignOnInPayload& request) {
    SignOnOutPayload response {};
    initializeMessageHeader(response.header, kTxnLogonResponse, byteswap(request.header.trader_id),
                            sizeof(response));
    response.user_id = request.user_id;
    std::memcpy(response.password, request.password, sizeof(response.password));
    std::memcpy(response.new_password, request.new_password, sizeof(response.new_password));
    std::memcpy(response.trader_name, request.trader_name, sizeof(response.trader_name));
    response.last_password_change_date = byteswap<uint32_t>(nowSeconds32());
    std::memcpy(response.broker_id, request.broker_id, sizeof(response.broker_id));
    response.branch_id = request.branch_id;
    response.version_number = request.version_number;
    response.end_time = byteswap<uint32_t>(nowSeconds32());
    response.sequence_number = hostToWireDouble(0.0);
    std::memcpy(response.ws_class_name, request.ws_class_name, sizeof(response.ws_class_name));
    response.broker_status = ' ';
    response.show_index = 'T';
    response.clearing_status = ' ';
    copyTrailingSpaces(response.broker_name, "SIMULATOR");
    sendPayload(&response, sizeof(response));
    phase_ = Phase::kReady;
  }

  void sendSystemInfoResponse(uint32_t trader_id) {
    SystemInfoResponsePayload response {};
    initializeMessageHeader(response.header, kTxnSystemInfoResponse, trader_id, sizeof(response));
    response.header.alpha_char[0] = static_cast<uint8_t>(config_.default_stream_no);
    response.board_lot_quantity = byteswap<uint32_t>(1);
    response.tick_size = byteswap<uint32_t>(5);
    response.disclosed_quantity_percent_allowed = byteswap<uint16_t>(100);
    sendPayload(&response, sizeof(response));
  }

  void sendSimpleHeaderResponse(uint16_t txn_code, uint32_t trader_id) {
    MessageHeader response {};
    initializeMessageHeader(response, txn_code, trader_id, sizeof(response));
    sendPayload(&response, sizeof(response));
  }

  void sendOrderResponse(const OrderSnapshot& order, uint16_t txn_code, uint16_t error_code) {
    OrderConfirmationPayload response {};
    response.transaction_code = byteswap(txn_code);
    response.log_time = byteswap(order.event_seconds);
    response.user_id = byteswap(order.user_id);
    response.error_code = byteswap(error_code);
    response.time_stamp1 = byteswap(order.event_nanos);
    response.time_stamp2 = static_cast<uint8_t>(config_.default_stream_no);
    response.modified_cancelled_by = 'T';
    response.reason_code = 0;
    response.token_no = byteswap(order.token);
    response.contract_description = order.contract_description;
    response.close_out_flag = ' ';
    response.order_number = hostToWireDouble(static_cast<double>(order.exchange_order_number));
    std::memcpy(response.account_number, order.account_number.data(), order.account_number.size());
    response.book_type = byteswap(order.book_type);
    response.buy_sell_indicator = byteswap(order.side);
    response.disclosed_volume = byteswap(order.disclosed_volume);
    response.disclosed_volume_remaining = byteswap(error_code == 0 ? order.disclosed_volume_remaining : 0U);
    response.total_volume_remaining = byteswap(error_code == 0 ? order.total_volume_remaining : 0U);
    response.volume = byteswap(order.volume);
    response.volume_filled_today = byteswap(order.volume_filled_today);
    response.price = byteswap(order.price);
    response.good_till_date = byteswap(order.good_till_date);
    response.entry_date_time = byteswap(order.entry_date_time);
    response.last_modified = byteswap(order.last_modified);
    response.order_flags1 = order.order_flags1;
    response.order_flags2 = order.order_flags2;
    response.branch_id = byteswap(order.branch_id);
    response.trader_id = byteswap(order.trader_id);
    std::memcpy(response.broker_id, order.broker_id.data(), order.broker_id.size());
    response.open_close = order.open_close;
    std::memcpy(response.settlor, order.settlor.data(), order.settlor.size());
    response.pro_client_indicator = byteswap(order.pro_client_indicator);
    response.additional_flags = order.additional_flags;
    response.filler = byteswap(order.filler);
    response.nnf_field = order.nnf_field_wire;
    response.time_stamp3 = byteswap(order.event_nanos);
    std::memcpy(response.pan, order.pan.data(), order.pan.size());
    response.algo_id = byteswap(order.algo_id);
    response.unique_id = byteswap(order.unique_id);
    response.last_activity_reference = byteswap(order.last_activity_reference);
    sendPayload(&response, sizeof(response));
  }

  void sendTradeResponse(const OrderSnapshot& order, uint32_t fill_quantity, uint32_t fill_price) {
    TradeConfirmationPayload response {};
    response.transaction_code = byteswap(kTxnTradeConfirmationTrimmed);
    response.log_time = byteswap(order.event_seconds);
    response.trader_id = byteswap(order.user_id);
    response.time_stamp = byteswap(order.event_nanos);
    response.time_stamp1 = byteswap(order.event_nanos);
    response.time_stamp2[7] = static_cast<uint8_t>(config_.default_stream_no);
    response.response_order_number = hostToWireDouble(static_cast<double>(order.exchange_order_number));
    std::memcpy(response.broker_id, order.broker_id.data(), order.broker_id.size());
    std::memcpy(response.account_number, order.account_number.data(), order.account_number.size());
    response.buy_sell_indicator = byteswap(order.side);
    response.original_volume = byteswap(order.volume);
    response.disclosed_volume = byteswap(order.disclosed_volume);
    response.remaining_volume = byteswap(order.total_volume_remaining);
    response.disclosed_volume_remaining = byteswap(order.disclosed_volume_remaining);
    response.price = byteswap(order.price);
    response.order_flags1 = order.order_flags1;
    response.order_flags2 = order.order_flags2;
    response.good_till_date = byteswap(order.good_till_date);
    response.fill_number = byteswap(order.fill_number);
    response.fill_quantity = byteswap(fill_quantity);
    response.fill_price = byteswap(fill_price);
    response.volume_filled_today = byteswap(order.volume_filled_today);
    response.activity_type[0] = 'T';
    response.activity_type[1] = 'R';
    response.activity_time = byteswap(order.event_seconds);
    response.token = byteswap(order.token);
    response.contract_description = order.contract_description;
    response.open_close = order.open_close;
    response.book_type = static_cast<uint8_t>(order.book_type);
    std::memcpy(response.participant, order.settlor.data(),
                std::min(sizeof(response.participant), order.settlor.size()));
    response.additional_flags = order.additional_flags;
    std::memcpy(response.pan, order.pan.data(), order.pan.size());
    response.algo_id = byteswap(order.algo_id);
    response.last_activity_reference = byteswap(order.last_activity_reference);
    sendPayload(&response, sizeof(response));
  }

  void dispatchEvents(const std::vector<EngineEvent>& events) {
    for (const auto& event : events) {
      dispatchEvent(event);
    }
  }

  void handlePayload(const std::vector<uint8_t>& payload) {
    if (payload.size() < sizeof(uint16_t)) {
      throw std::runtime_error("payload too small");
    }
    const uint16_t txn_code = byteswap(*reinterpret_cast<const uint16_t*>(payload.data()));

    switch (phase_) {
      case Phase::kAwaitSecureBoxRegistration:
        handleSecureBoxRegistration(txn_code, payload);
        return;
      case Phase::kAwaitBoxSignOn:
        handleBoxSignOn(txn_code, payload);
        return;
      case Phase::kAwaitLogin:
        handleLogin(txn_code, payload);
        return;
      case Phase::kReady:
        handleReadyPayload(txn_code, payload);
        return;
    }
  }

  void handleSecureBoxRegistration(uint16_t txn_code, const std::vector<uint8_t>& payload) {
    if (txn_code != kTxnSecureBoxRegistrationRequest ||
        payload.size() != sizeof(SecureBoxRegistrationRequestPayload)) {
      throw std::runtime_error("unexpected secure box registration payload");
    }

    const auto& request = *reinterpret_cast<const SecureBoxRegistrationRequestPayload*>(payload.data());
    if (byteswap(request.box_id) != ticket_.box_id) {
      throw std::runtime_error("unexpected secure box registration box id");
    }
    sendSecureBoxRegistrationResponse(byteswap(request.header.trader_id));
  }

  void handleBoxSignOn(uint16_t txn_code, const std::vector<uint8_t>& payload) {
    if (txn_code != kTxnBoxSignOnRequestIn || payload.size() != sizeof(BoxSignOnRequestPayload)) {
      throw std::runtime_error("unexpected box sign on payload");
    }

    const auto& request = *reinterpret_cast<const BoxSignOnRequestPayload*>(payload.data());
    if (byteswap(request.box_id) != ticket_.box_id ||
        byteswap(request.session_key) != ticket_.session_key) {
      throw std::runtime_error("box sign on validation failed");
    }
    sendBoxSignOnResponse(byteswap(request.header.trader_id));
  }

  void handleLogin(uint16_t txn_code, const std::vector<uint8_t>& payload) {
    if (txn_code != kTxnLogonRequest || payload.size() != sizeof(SignOnInPayload)) {
      throw std::runtime_error("unexpected logon payload");
    }

    const auto& request = *reinterpret_cast<const SignOnInPayload*>(payload.data());
    logged_in_user_id_ = byteswap(request.user_id);
    sendLogonResponse(request);
  }

  void handleReadyPayload(uint16_t txn_code, const std::vector<uint8_t>& payload) {
    switch (txn_code) {
      case kTxnSystemInfoRequest: {
        if (payload.size() != sizeof(SystemInfoRequestPayload)) {
          throw std::runtime_error("bad system info request size");
        }
        sendSystemInfoResponse(logged_in_user_id_);
        return;
      }
      case kTxnUpdateLocalDatabase: {
        if (payload.size() != sizeof(UpdateLocalDatabaseRequestPayload)) {
          throw std::runtime_error("bad update local db size");
        }
        sendSimpleHeaderResponse(kTxnUpdateLocalDatabaseTrailer, logged_in_user_id_);
        return;
      }
      case kTxnMessageDownloadRequest: {
        if (payload.size() != sizeof(MessageDownloadRequestPayload)) {
          throw std::runtime_error("bad message download request size");
        }
        sendSimpleHeaderResponse(kTxnMessageDownloadTrailer, logged_in_user_id_);
        return;
      }
      case kTxnHeartbeat:
        return;
      case kTxnOrderEntryTrimmed: {
        if (payload.size() != sizeof(OrderEntryRequestPayload)) {
          throw std::runtime_error("bad order request size");
        }
        const auto& request = *reinterpret_cast<const OrderEntryRequestPayload*>(payload.data());
        dispatchEvents(engine_.onNewOrder(request, session_id_, shared_from_this()));
        return;
      }
      case kTxnOrderModificationTrimmed: {
        if (payload.size() != sizeof(OrderUpdateRequestPayload)) {
          throw std::runtime_error("bad order modification request size");
        }
        const auto& request = *reinterpret_cast<const OrderUpdateRequestPayload*>(payload.data());
        dispatchEvents(engine_.onModifyOrder(request, session_id_, shared_from_this()));
        return;
      }
      case kTxnOrderCancellationTrimmed: {
        if (payload.size() != sizeof(OrderUpdateRequestPayload)) {
          throw std::runtime_error("bad order cancellation request size");
        }
        const auto& request = *reinterpret_cast<const OrderUpdateRequestPayload*>(payload.data());
        dispatchEvents(engine_.onCancelOrder(request, session_id_, shared_from_this()));
        return;
      }
      default:
        throw std::runtime_error("unsupported transaction code");
    }
  }

  int fd_ = -1;
  Config config_;
  SessionTicket ticket_;
  MatchingEngine& engine_;
  CtrCryptoStream inbound_crypto_;
  CtrCryptoStream outbound_crypto_;
  bool encryption_enabled_ = false;
  Phase phase_ = Phase::kAwaitSecureBoxRegistration;
  uint32_t sequence_number_ = 0;
  uint32_t logged_in_user_id_ = 0;
  uint64_t session_id_ = 0;
  std::atomic<bool> closed_ {false};
  std::mutex write_mutex_;
};

void dispatchEngineEvents(const std::vector<EngineEvent>& events) {
  for (const auto& event : events) {
    if (const auto session = event.session.lock()) {
      session->dispatchEvent(event);
    }
  }
}

}  // namespace

class SimulatorApp::Impl {
public:
  explicit Impl(Config config)
      : config_(std::move(config)),
        engine_(config_) {}

  ~Impl() {
    stop();
  }

  void start() {
    if (running_) {
      return;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    gateway_ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    if (gateway_ssl_ctx_ == nullptr) {
      throw std::runtime_error("SSL_CTX_new failed");
    }
    initializeTlsContext(gateway_ssl_ctx_, config_);

    gateway_listen_fd_ = createListenSocket(config_.listen_host, config_.gr_tls_port, &gateway_port_);
    session_listen_fd_ = createListenSocket(config_.listen_host, config_.session_port, &session_port_);
    for (const auto& endpoint : config_.market_data_streams) {
      market_data_fds_.push_back(createMarketDataSocket(endpoint));
    }

    running_ = true;
    gateway_thread_ = std::thread([this] { gatewayLoop(); });
    session_thread_ = std::thread([this] { sessionLoop(); });
    for (std::size_t i = 0; i < market_data_fds_.size(); ++i) {
      market_data_threads_.emplace_back([this, i] { marketDataLoop(market_data_fds_[i]); });
    }
  }

  void stop() {
    if (!running_) {
      cleanup();
      return;
    }

    running_ = false;
    if (gateway_listen_fd_ >= 0) {
      shutdown(gateway_listen_fd_, SHUT_RDWR);
      close(gateway_listen_fd_);
      gateway_listen_fd_ = -1;
    }
    if (session_listen_fd_ >= 0) {
      shutdown(session_listen_fd_, SHUT_RDWR);
      close(session_listen_fd_);
      session_listen_fd_ = -1;
    }
    for (int& fd : market_data_fds_) {
      if (fd >= 0) {
        close(fd);
        fd = -1;
      }
    }

    if (gateway_thread_.joinable()) {
      gateway_thread_.join();
    }
    if (session_thread_.joinable()) {
      session_thread_.join();
    }
    for (auto& thread : market_data_threads_) {
      if (thread.joinable()) {
        thread.join();
      }
    }
    market_data_threads_.clear();

    std::vector<std::thread> workers;
    {
      std::lock_guard<std::mutex> lock(worker_mutex_);
      workers.swap(session_workers_);
    }
    for (auto& worker : workers) {
      if (worker.joinable()) {
        worker.join();
      }
    }

    cleanup();
  }

  uint16_t gatewayPort() const {
    return gateway_port_;
  }

  uint16_t sessionPort() const {
    return session_port_;
  }

private:
  void cleanup() {
    if (gateway_ssl_ctx_ != nullptr) {
      SSL_CTX_free(gateway_ssl_ctx_);
      gateway_ssl_ctx_ = nullptr;
    }
  }

  void gatewayLoop() {
    while (running_) {
      const int client_fd = accept(gateway_listen_fd_, nullptr, nullptr);
      if (client_fd < 0) {
        if (!running_) {
          return;
        }
        continue;
      }

      try {
        handleGatewayClient(client_fd);
      } catch (...) {
      }
      close(client_fd);
    }
  }

  void handleGatewayClient(int client_fd) {
    SSL* ssl = SSL_new(gateway_ssl_ctx_);
    if (ssl == nullptr) {
      throw std::runtime_error("SSL_new failed");
    }
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) {
      SSL_free(ssl);
      throw std::runtime_error("SSL_accept failed");
    }

    DirectExCtclHeader ctcl_header {};
    sslReadFully(ssl, &ctcl_header, sizeof(ctcl_header));
    if (byteswap(ctcl_header.length) != sizeof(GatewayRouterRequest)) {
      SSL_free(ssl);
      throw std::runtime_error("unexpected gateway request length");
    }

    GatewayRouterRequest request {};
    request.ctcl_header = ctcl_header;
    sslReadFully(ssl, reinterpret_cast<uint8_t*>(&request) + sizeof(ctcl_header),
                 sizeof(request) - sizeof(ctcl_header));
    const auto digest = Md5Digest::compute(
        reinterpret_cast<const uint8_t*>(&request.header), sizeof(request) - sizeof(request.ctcl_header));
    if (std::memcmp(request.ctcl_header.md5_checksum, digest.data(), digest.size()) != 0) {
      SSL_free(ssl);
      throw std::runtime_error("gateway request MD5 mismatch");
    }
    if (byteswap(request.header.transaction_code) != kTxnGatewayRouterRequest) {
      SSL_free(ssl);
      throw std::runtime_error("unexpected gateway request txn code");
    }

    SessionTicket ticket;
    ticket.peer_ip = peerIpAddress(client_fd);
    ticket.box_id = config_.box_id;
    ticket.session_key = next_session_key_.fetch_add(1);
    if (RAND_bytes(ticket.crypto_key.data(), static_cast<int>(ticket.crypto_key.size())) != 1 ||
        RAND_bytes(ticket.crypto_iv.data(), static_cast<int>(ticket.crypto_iv.size())) != 1) {
      SSL_free(ssl);
      throw std::runtime_error("RAND_bytes failed");
    }
    tickets_.add(ticket);

    GatewayRouterResponse response {};
    response.ctcl_header.length = byteswap<uint16_t>(sizeof(response));
    response.ctcl_header.sequence_number = byteswap<uint32_t>(1);
    initializeMessageHeader(response.header, kTxnGatewayRouterResponse, byteswap(request.header.trader_id),
                            sizeof(response) - sizeof(response.ctcl_header));
    response.box_id = byteswap(ticket.box_id);
    std::memcpy(response.broker_id, request.broker_id, sizeof(response.broker_id));
    copyCString(response.ip, config_.listen_host);
    response.port = byteswap<uint32_t>(session_port_);
    response.session_key = byteswap<uint64_t>(ticket.session_key);
    std::memcpy(response.cryptographic_key, ticket.crypto_key.data(), ticket.crypto_key.size());
    std::memcpy(response.cryptographic_iv, ticket.crypto_iv.data(), ticket.crypto_iv.size());
    const auto response_digest = Md5Digest::compute(
        reinterpret_cast<const uint8_t*>(&response.header),
        sizeof(response) - sizeof(response.ctcl_header));
    std::memcpy(response.ctcl_header.md5_checksum, response_digest.data(), response_digest.size());

    sslWriteFully(ssl, &response, sizeof(response));
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  void sessionLoop() {
    while (running_) {
      const int client_fd = accept(session_listen_fd_, nullptr, nullptr);
      if (client_fd < 0) {
        if (!running_) {
          return;
        }
        continue;
      }

      auto ticket = tickets_.claimForPeer(peerIpAddress(client_fd));
      if (!ticket.has_value()) {
        close(client_fd);
        continue;
      }

      const uint64_t session_id = next_connection_id_.fetch_add(1);
      std::lock_guard<std::mutex> lock(worker_mutex_);
      session_workers_.emplace_back([this, client_fd, ticket = std::move(*ticket), session_id]() mutable {
        auto connection =
            std::make_shared<SessionConnection>(client_fd, config_, std::move(ticket), engine_, session_id);
        connection->run();
      });
    }
  }

  void marketDataLoop(int socket_fd) {
    std::array<uint8_t, kMaxMarketDataPayload> buffer {};
    while (running_) {
      sockaddr_in peer_addr {};
      socklen_t peer_len = sizeof(peer_addr);
      const ssize_t rc =
          recvfrom(socket_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer_addr), &peer_len);
      if (rc < 0) {
        if (!running_) {
          return;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
          continue;
        }
        continue;
      }
      const std::size_t packet_size = static_cast<std::size_t>(rc);
      if (packet_size < sizeof(TbtStreamHeader)) {
        continue;
      }

      const auto* header = reinterpret_cast<const TbtStreamHeader*>(buffer.data());
      switch (header->message_type) {
        case 'N':
        case 'M':
        case 'X': {
          if (packet_size < sizeof(TbtOrderMessage)) {
            continue;
          }
          TbtOrderMessage message {};
          std::memcpy(&message, buffer.data(), sizeof(message));
          logTbtOrderMessage(message, peer_addr, packet_size);
          dispatchEngineEvents(engine_.onTbtOrderMessage(message));
          break;
        }
        case 'T': {
          if (packet_size < sizeof(TbtTradeMessage)) {
            continue;
          }
          TbtTradeMessage message {};
          std::memcpy(&message, buffer.data(), sizeof(message));
          logTbtTradeMessage(message, peer_addr, packet_size);
          dispatchEngineEvents(engine_.onTbtTradeMessage(message));
          break;
        }
        default:
          break;
      }
    }
  }

  Config config_;
  MatchingEngine engine_;
  PendingTicketStore tickets_;
  std::atomic<uint64_t> next_session_key_ {1};
  std::atomic<uint64_t> next_connection_id_ {1};
  std::atomic<bool> running_ {false};
  uint16_t gateway_port_ = 0;
  uint16_t session_port_ = 0;
  int gateway_listen_fd_ = -1;
  int session_listen_fd_ = -1;
  std::vector<int> market_data_fds_;
  SSL_CTX* gateway_ssl_ctx_ = nullptr;
  std::thread gateway_thread_;
  std::thread session_thread_;
  std::vector<std::thread> market_data_threads_;
  std::mutex worker_mutex_;
  std::vector<std::thread> session_workers_;
};

SimulatorApp::SimulatorApp(Config config)
    : impl_(new Impl(std::move(config))) {}

SimulatorApp::~SimulatorApp() {
  delete impl_;
}

void SimulatorApp::start() {
  impl_->start();
}

void SimulatorApp::stop() {
  impl_->stop();
}

uint16_t SimulatorApp::gatewayPort() const {
  return impl_->gatewayPort();
}

uint16_t SimulatorApp::sessionPort() const {
  return impl_->sessionPort();
}

}  // namespace nse_fo_exchange_sim
