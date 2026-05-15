// NOTE:
// The live simulator implementation moved to `src/runtime.cpp` when market-data-driven
// book building, resting order management, and modify/cancel handling were added.
// This file is no longer compiled by CMake and is kept only as a historical reference.

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
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace nse_fo_exchange_sim {
namespace {

using namespace protocol;

constexpr std::size_t kMaxSessionPayload = 1024;
std::string currentOpenSslError() {
  const unsigned long error_code = ERR_get_error();
  if (error_code == 0) {
    return std::string("unknown OpenSSL error");
  }

  char buffer[256] {};
  ERR_error_string_n(error_code, buffer, sizeof(buffer));
  return std::string(buffer);
}

std::string formatErrnoError(const char* operation, int error_number) {
  std::ostringstream stream;
  stream << operation << " failed: errno=" << error_number << " (" << std::strerror(error_number)
         << ")";
  return stream.str();
}

std::string formatSslIoError(const char* operation, SSL* ssl, int rc) {
  const int ssl_error = SSL_get_error(ssl, rc);
  std::ostringstream stream;
  stream << operation << " failed";
  switch (ssl_error) {
    case SSL_ERROR_ZERO_RETURN:
      stream << ": peer closed TLS connection";
      return stream.str();
    case SSL_ERROR_SYSCALL:
      if (rc == 0) {
        stream << ": peer closed TLS connection";
        return stream.str();
      }
      if (errno != 0) {
        return formatErrnoError(operation, errno);
      }
      stream << ": SSL_ERROR_SYSCALL";
      return stream.str();
    default:
      stream << ": ssl_error=" << ssl_error << " (" << currentOpenSslError() << ")";
      return stream.str();
  }
}

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

std::string hexString(const uint8_t* data, std::size_t size) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < size; ++i) {
    if (i != 0) {
      stream << ' ';
    }
    stream << std::setw(2) << static_cast<unsigned int>(data[i]);
  }
  return stream.str();
}

std::optional<uint16_t> decodeTxnCode(const uint8_t* payload, std::size_t size) {
  if (size < sizeof(uint16_t)) {
    return std::nullopt;
  }

  uint16_t wire_txn_code = 0;
  std::memcpy(&wire_txn_code, payload, sizeof(wire_txn_code));
  return byteswap(wire_txn_code);
}

const char* txnName(uint16_t txn_code) {
  switch (txn_code) {
    case kTxnHeartbeat:
      return "Heartbeat";
    case kTxnGatewayRouterRequest:
      return "GatewayRouterRequest";
    case kTxnGatewayRouterResponse:
      return "GatewayRouterResponse";
    case kTxnBoxSignOnRequestIn:
      return "BoxSignOnRequestIn";
    case kTxnBoxSignOnRequestOut:
      return "BoxSignOnRequestOut";
    case kTxnSecureBoxRegistrationRequest:
      return "SecureBoxRegistrationRequest";
    case kTxnSecureBoxRegistrationResponse:
      return "SecureBoxRegistrationResponse";
    case kTxnLogonRequest:
      return "LogonRequest";
    case kTxnLogonResponse:
      return "LogonResponse";
    case kTxnSystemInfoRequest:
      return "SystemInfoRequest";
    case kTxnSystemInfoResponse:
      return "SystemInfoResponse";
    case kTxnUpdateLocalDatabase:
      return "UpdateLocalDatabase";
    case kTxnUpdateLocalDatabaseTrailer:
      return "UpdateLocalDatabaseTrailer";
    case kTxnMessageDownloadRequest:
      return "MessageDownloadRequest";
    case kTxnMessageDownloadTrailer:
      return "MessageDownloadTrailer";
    case kTxnPriceVolModification:
      return "PriceVolModification";
    case kTxnOrderEntryTrimmed:
      return "OrderEntryTrimmed";
    case kTxnOrderConfirmationTrimmed:
      return "OrderConfirmationTrimmed";
    case kTxnOrderErrorTrimmed:
      return "OrderErrorTrimmed";
    case kTxnOrderModificationRequestTrimmed:
      return "OrderModificationRequestTrimmed";
    case kTxnOrderModificationConfirmationTrimmed:
      return "OrderModificationConfirmationTrimmed";
    case kTxnOrderModificationErrorTrimmed:
      return "OrderModificationErrorTrimmed";
    case kTxnOrderCancellationRequestTrimmed:
      return "OrderCancellationRequestTrimmed";
    case kTxnOrderCancellationConfirmationTrimmed:
      return "OrderCancellationConfirmationTrimmed";
    case kTxnOrderCancellationErrorTrimmed:
      return "OrderCancellationErrorTrimmed";
    case kTxnTradeConfirmationTrimmed:
      return "TradeConfirmationTrimmed";
    default:
      return "Unknown";
  }
}

std::string packetSummary(const char* scope,
                          const std::string& peer_ip,
                          const char* direction,
                          const char* view,
                          const char* phase,
                          const DirectExCtclHeader& header,
                          const uint8_t* payload,
                          std::size_t payload_size,
                          bool ctr_encrypted) {
  std::ostringstream stream;
  stream << "[" << scope << ' ' << direction;
  if (view != nullptr && view[0] != '\0') {
    stream << ' ' << view;
  }
  stream << "] peer=" << peer_ip;
  if (phase != nullptr && phase[0] != '\0') {
    stream << " phase=" << phase;
  }
  stream << " seq=" << byteswap(header.sequence_number)
         << " wire_length=" << byteswap(header.length)
         << " payload_size=" << payload_size
         << " ctr_encrypted=" << (ctr_encrypted ? "yes" : "no");
  if (const auto txn_code = decodeTxnCode(payload, payload_size); txn_code.has_value()) {
    stream << " txn=" << *txn_code << " (" << txnName(*txn_code) << ")";
  }
  stream << " md5=" << hexString(header.md5_checksum, sizeof(header.md5_checksum))
         << " payload_hex=" << hexString(payload, payload_size);
  return stream.str();
}

int createListenSocket(const std::string& host, uint16_t port, uint16_t* bound_port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    throw std::runtime_error(formatErrnoError("socket()", errno));
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

std::string peerIpAddress(int fd) {
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

void readFully(int fd, void* buffer, std::size_t size) {
  auto* out = static_cast<uint8_t*>(buffer);
  std::size_t read_total = 0;
  while (read_total < size) {
    const ssize_t rc = recv(fd, out + read_total, size - read_total, 0);
    if (rc == 0) {
      throw std::runtime_error("socket read failed: peer closed connection");
    }
    if (rc < 0) {
      throw std::runtime_error(formatErrnoError("socket read", errno));
    }
    read_total += static_cast<std::size_t>(rc);
  }
}

void writeFully(int fd, const void* buffer, std::size_t size) {
  const auto* in = static_cast<const uint8_t*>(buffer);
  std::size_t written_total = 0;
  while (written_total < size) {
    const ssize_t rc = send(fd, in + written_total, size - written_total, 0);
    if (rc == 0) {
      throw std::runtime_error("socket write failed: peer closed connection");
    }
    if (rc < 0) {
      throw std::runtime_error(formatErrnoError("socket write", errno));
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
      throw std::runtime_error(formatSslIoError("SSL_read", ssl, rc));
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
      throw std::runtime_error(formatSslIoError("SSL_write", ssl, rc));
    }
    written_total += static_cast<std::size_t>(rc);
  }
}

void initializeTlsContext(SSL_CTX* ctx, const Config& config) {
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

struct OrderSnapshot {
  OrderEntryRequestPayload request {};
  uint32_t user_id = 0;
  uint32_t token = 0;
  uint16_t book_type = 0;
  uint16_t side = 0;
  uint32_t disclosed_volume = 0;
  uint32_t volume = 0;
  uint32_t price = 0;
  uint32_t client_order_id = 0;
  uint16_t branch_id = 0;
  uint16_t unique_id = 0;
  uint32_t algo_id = 0;
  uint64_t exchange_order_number = 0;
  uint32_t fill_number = 0;
  uint64_t last_activity_reference = 0;
  uint64_t event_nanos = 0;
  uint32_t event_seconds = 0;
};

class FillEngine {
public:
  explicit FillEngine(const Config& config)
      : next_exchange_order_number_(config.exchange_order_number_start),
        next_fill_number_(config.fill_number_start),
        next_last_activity_reference_(1) {}

  std::optional<OrderSnapshot> acceptLimitOrder(const OrderEntryRequestPayload& request) {
    const uint16_t transaction_code = byteswap(request.transaction_code);
    const uint16_t book_type = byteswap(request.book_type);
    const uint16_t side = byteswap(request.buy_sell_indicator);
    const uint32_t disclosed_volume = byteswap(request.disclosed_volume);
    const uint32_t volume = byteswap(request.volume);
    const uint32_t price = byteswap(request.price);
    const bool supported_order_flags1 = request.order_flags1 == 0x8 || request.order_flags1 == 0x2;

    if (transaction_code != kTxnOrderEntryTrimmed || book_type != 1 || !supported_order_flags1 ||
        request.order_flags2 != 0 || request.open_close != 'O' ||
        volume == 0 || price == 0 || (side != 1 && side != 2)) {
      std::cout << "Rejecting order entry request due to unsupported parameters: "
                << "transaction_code=" << (transaction_code != kTxnOrderEntryTrimmed)
                << ", book_type=" << (book_type != 1)
                << ", order_flags1=" << (!supported_order_flags1)
                << ", order_flags2=" << (request.order_flags2 != 0)
                << ", open_close=" << (request.open_close != 'O')
                << ", volume=" << (volume == 0)
                << ", price=" << (price == 0)
                << ", side=" << (side != 1 && side != 2)
                << std::endl;
      return std::nullopt;
    }

    OrderSnapshot snapshot;
    snapshot.request = request;
    snapshot.user_id = byteswap(request.user_id);
    snapshot.token = byteswap(request.token_no);
    snapshot.book_type = book_type;
    snapshot.side = side;
    snapshot.disclosed_volume = disclosed_volume;
    snapshot.volume = volume;
    snapshot.price = price;
    snapshot.client_order_id = byteswap(request.filler);
    snapshot.branch_id = byteswap(request.branch_id);
    snapshot.unique_id = byteswap(request.unique_id);
    snapshot.algo_id = byteswap(request.algo_id);
    snapshot.exchange_order_number = next_exchange_order_number_.fetch_add(1);
    snapshot.fill_number = next_fill_number_.fetch_add(1);
    snapshot.last_activity_reference = next_last_activity_reference_.fetch_add(1);
    snapshot.event_nanos = nowNanos();
    snapshot.event_seconds = nowSeconds32();
    return snapshot;
  }

private:
  std::atomic<uint64_t> next_exchange_order_number_;
  std::atomic<uint32_t> next_fill_number_;
  std::atomic<uint64_t> next_last_activity_reference_;
};

class SessionConnection {
public:
  SessionConnection(int fd,
                    Config config,
                    SessionTicket ticket,
                    FillEngine& engine)
      : fd_(fd),
        config_(std::move(config)),
        ticket_(std::move(ticket)),
        engine_(engine) {}

  ~SessionConnection() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  void run() {
    std::cout << "[session connect] peer=" << ticket_.peer_ip << " box_id=" << ticket_.box_id
              << " session_key=" << ticket_.session_key << std::endl;
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
          logPacket("recv", "wire", header, payload, true);
          inbound_crypto_.xorData(payload.data(), payload.size());
          logPacket("recv", "plain", header, payload, false);
        } else {
          logPacket("recv", "wire", header, payload, false);
        }

        const auto expected_digest = Md5Digest::compute(payload.data(), payload.size());
        if (std::memcmp(header.md5_checksum, expected_digest.data(), expected_digest.size()) != 0) {
          throw std::runtime_error("bad session MD5: expected=" +
                                   hexString(header.md5_checksum, sizeof(header.md5_checksum)) +
                                   " actual=" +
                                   hexString(expected_digest.data(), expected_digest.size()));
        }

        handlePayload(payload);
      }
    } catch (const std::exception& ex) {
      logDisconnect(ex.what());
    } catch (...) {
      logDisconnect("unknown exception");
    }
  }

private:
  enum class Phase {
    kAwaitSecureBoxRegistration,
    kAwaitBoxSignOn,
    kAwaitLogin,
    kReady
  };

  struct TrackedOrderState {
    ContractDescTr contract_description {};
    std::array<uint8_t, 10> account_number {};
    std::array<uint8_t, 5> broker_id {};
    std::array<uint8_t, 12> settlor {};
    std::array<uint8_t, 10> pan {};
    uint32_t user_id = 0;
    uint32_t trader_id = 0;
    uint32_t token = 0;
    uint16_t book_type = 0;
    uint16_t side = 0;
    uint32_t disclosed_volume = 0;
    uint32_t disclosed_volume_remaining = 0;
    uint32_t total_volume = 0;
    uint32_t total_volume_remaining = 0;
    uint32_t volume_filled_today = 0;
    uint32_t price = 0;
    uint32_t good_till_date = 0;
    uint32_t entry_date_time = 0;
    uint32_t last_modified = 0;
    uint8_t order_flags1 = 0;
    uint8_t order_flags2 = 0;
    uint16_t branch_id = 0;
    uint8_t open_close = ' ';
    uint16_t pro_client_indicator = 0;
    uint8_t additional_flags = 0;
    uint32_t filler = 0;
    double nnf_field = 0.0;
    uint32_t algo_id = 0;
    uint16_t unique_id = 0;
    uint64_t exchange_order_number = 0;
    uint64_t last_activity_reference = 0;
    uint64_t event_nanos = 0;
    uint32_t event_seconds = 0;
  };

  const char* phaseName() const {
    switch (phase_) {
      case Phase::kAwaitSecureBoxRegistration:
        return "AwaitSecureBoxRegistration";
      case Phase::kAwaitBoxSignOn:
        return "AwaitBoxSignOn";
      case Phase::kAwaitLogin:
        return "AwaitLogin";
      case Phase::kReady:
        return "Ready";
    }
    return "Unknown";
  }

  uint64_t exchangeOrderNumberFromWire(double wire_order_number) const {
    return static_cast<uint64_t>(wireToHostDouble(wire_order_number));
  }

  void touchTrackedOrder(TrackedOrderState& order, std::optional<uint64_t> request_last_activity_reference) {
    order.event_nanos = nowNanos();
    order.event_seconds = nowSeconds32();
    order.last_modified = order.event_seconds;
    if (order.entry_date_time == 0) {
      order.entry_date_time = order.event_seconds;
    }
    order.last_activity_reference =
        std::max(order.last_activity_reference, request_last_activity_reference.value_or(0)) + 1;
  }

  TrackedOrderState makeTrackedOrderState(const OrderSnapshot& order) const {
    TrackedOrderState state;
    std::memcpy(&state.contract_description, &order.request.contract_description,
                sizeof(state.contract_description));
    std::memcpy(state.account_number.data(), order.request.account_number, state.account_number.size());
    std::memcpy(state.broker_id.data(), order.request.broker_id, state.broker_id.size());
    std::memcpy(state.settlor.data(), order.request.settlor, state.settlor.size());
    std::memcpy(state.pan.data(), order.request.pan, state.pan.size());
    state.user_id = order.user_id;
    state.trader_id = byteswap(order.request.trader_id);
    state.token = order.token;
    state.book_type = order.book_type;
    state.side = order.side;
    state.disclosed_volume = order.disclosed_volume;
    state.disclosed_volume_remaining = order.disclosed_volume;
    state.total_volume = order.volume;
    state.total_volume_remaining = order.volume;
    state.volume_filled_today = 0;
    state.price = order.price;
    state.good_till_date = byteswap(order.request.good_till_date);
    state.entry_date_time = order.event_seconds;
    state.last_modified = order.event_seconds;
    state.order_flags1 = order.request.order_flags1;
    state.order_flags2 = order.request.order_flags2;
    state.branch_id = order.branch_id;
    state.open_close = order.request.open_close;
    state.pro_client_indicator = byteswap(order.request.pro_client_indicator);
    state.additional_flags = order.request.additional_flags;
    state.filler = order.client_order_id;
    state.nnf_field = wireToHostDouble(order.request.nnf_field);
    state.algo_id = order.algo_id;
    state.unique_id = order.unique_id;
    state.exchange_order_number = order.exchange_order_number;
    state.last_activity_reference = order.last_activity_reference;
    state.event_nanos = order.event_nanos;
    state.event_seconds = order.event_seconds;
    return state;
  }

  TrackedOrderState makeTrackedOrderState(const OrderModifyCancelRequestPayload& request) const {
    TrackedOrderState state;
    std::memcpy(&state.contract_description, &request.contract_description,
                sizeof(state.contract_description));
    std::memcpy(state.account_number.data(), request.account_number, state.account_number.size());
    std::memcpy(state.broker_id.data(), request.broker_id, state.broker_id.size());
    std::memcpy(state.settlor.data(), request.settlor, state.settlor.size());
    std::memcpy(state.pan.data(), request.pan, state.pan.size());
    state.user_id = byteswap(request.user_id);
    state.trader_id = byteswap(request.trader_id);
    state.token = byteswap(request.token_no);
    state.book_type = byteswap(request.book_type);
    state.side = byteswap(request.buy_sell_indicator);
    state.disclosed_volume = byteswap(request.disclosed_volume);
    state.disclosed_volume_remaining = byteswap(request.disclosed_volume_remaining);
    state.total_volume_remaining = byteswap(request.total_volume_remaining);
    state.volume_filled_today = byteswap(request.volume_filled_today);
    state.total_volume = state.total_volume_remaining + state.volume_filled_today;
    state.price = byteswap(request.price);
    state.good_till_date = byteswap(request.good_till_date);
    state.entry_date_time = byteswap(request.entry_date_time);
    state.last_modified = byteswap(request.last_modified);
    state.order_flags1 = request.order_flags1;
    state.order_flags2 = request.order_flags2;
    state.branch_id = byteswap(request.branch_id);
    state.open_close = request.open_close;
    state.pro_client_indicator = byteswap(request.pro_client_indicator);
    state.additional_flags = request.additional_flags;
    state.filler = byteswap(request.filler);
    state.nnf_field = wireToHostDouble(request.nnf_field);
    state.algo_id = byteswap(request.algo_id);
    state.unique_id = byteswap(request.unique_id);
    state.exchange_order_number = exchangeOrderNumberFromWire(request.order_number);
    state.last_activity_reference = byteswap(request.last_activity_reference);
    return state;
  }

  TrackedOrderState makeTrackedOrderState(const PriceVolumeModificationRequestPayload& request,
                                          uint64_t exchange_order_number) const {
    TrackedOrderState state;
    state.user_id = byteswap(request.header.trader_id);
    state.trader_id = byteswap(request.trader_id);
    state.token = byteswap(request.token_no);
    state.side = byteswap(request.buy_sell);
    state.total_volume = byteswap(request.volume);
    state.total_volume_remaining = state.total_volume;
    state.disclosed_volume = state.total_volume;
    state.disclosed_volume_remaining = state.total_volume_remaining;
    state.price = byteswap(request.price);
    state.last_modified = byteswap(request.last_modified);
    state.filler = byteswap(request.filler);
    state.exchange_order_number = exchange_order_number;
    state.last_activity_reference = byteswap(request.last_activity_reference);
    return state;
  }

  TrackedOrderState* findTrackedOrder(uint64_t exchange_order_number, uint32_t filler) {
    if (exchange_order_number != 0) {
      auto it = tracked_orders_.find(exchange_order_number);
      if (it != tracked_orders_.end()) {
        return &it->second;
      }
    }

    if (filler == 0) {
      return nullptr;
    }

    auto it = std::find_if(tracked_orders_.begin(), tracked_orders_.end(),
                           [&](const auto& entry) { return entry.second.filler == filler; });
    return (it == tracked_orders_.end()) ? nullptr : &it->second;
  }

  void rememberAcceptedOrder(const OrderSnapshot& order) {
    tracked_orders_[order.exchange_order_number] = makeTrackedOrderState(order);
  }

  void markOrderFilled(uint64_t exchange_order_number) {
    auto* tracked_order = findTrackedOrder(exchange_order_number, 0);
    if (tracked_order == nullptr) {
      return;
    }

    tracked_order->volume_filled_today = tracked_order->total_volume;
    tracked_order->total_volume_remaining = 0;
    tracked_order->disclosed_volume_remaining = 0;
  }

  bool hasEmittedFill(const TrackedOrderState& order) const {
    return order.total_volume > 0 && order.total_volume_remaining == 0 &&
           order.volume_filled_today >= order.total_volume;
  }

  void sendFilledModificationError(TrackedOrderState& order,
                                   std::optional<uint64_t> request_last_activity_reference) {
    touchTrackedOrder(order, request_last_activity_reference);
    sendTrackedOrderResponse(order, kTxnOrderModificationErrorTrimmed, kErrorOrderAlreadyFilled,
                             order.total_volume_remaining);
  }

  void applyTrimmedModification(TrackedOrderState& order, const OrderModifyCancelRequestPayload& request) {
    std::memcpy(&order.contract_description, &request.contract_description,
                sizeof(order.contract_description));
    std::memcpy(order.account_number.data(), request.account_number, order.account_number.size());
    std::memcpy(order.broker_id.data(), request.broker_id, order.broker_id.size());
    std::memcpy(order.settlor.data(), request.settlor, order.settlor.size());
    std::memcpy(order.pan.data(), request.pan, order.pan.size());
    order.user_id = byteswap(request.user_id);
    order.trader_id = byteswap(request.trader_id);
    order.token = byteswap(request.token_no);
    order.book_type = byteswap(request.book_type);
    order.side = byteswap(request.buy_sell_indicator);
    order.disclosed_volume = byteswap(request.disclosed_volume);
    order.disclosed_volume_remaining = byteswap(request.disclosed_volume_remaining);
    order.total_volume_remaining = byteswap(request.total_volume_remaining);
    order.volume_filled_today = byteswap(request.volume_filled_today);
    order.total_volume = order.total_volume_remaining + order.volume_filled_today;
    order.price = byteswap(request.price);
    order.good_till_date = byteswap(request.good_till_date);
    order.entry_date_time = byteswap(request.entry_date_time);
    order.order_flags1 = request.order_flags1;
    order.order_flags2 = request.order_flags2;
    order.branch_id = byteswap(request.branch_id);
    order.open_close = request.open_close;
    order.pro_client_indicator = byteswap(request.pro_client_indicator);
    order.additional_flags = request.additional_flags;
    order.filler = byteswap(request.filler);
    order.nnf_field = wireToHostDouble(request.nnf_field);
    order.algo_id = byteswap(request.algo_id);
    order.unique_id = byteswap(request.unique_id);
    order.exchange_order_number = exchangeOrderNumberFromWire(request.order_number);
    touchTrackedOrder(order, byteswap(request.last_activity_reference));
  }

  void applyTrimmedCancellation(TrackedOrderState& order, const OrderModifyCancelRequestPayload& request) {
    applyTrimmedModification(order, request);
    order.disclosed_volume_remaining = 0;
    order.total_volume_remaining = 0;
  }

  void applyPriceVolumeModification(TrackedOrderState& order,
                                    const PriceVolumeModificationRequestPayload& request) {
    order.user_id = byteswap(request.header.trader_id);
    order.trader_id = byteswap(request.trader_id);
    order.token = byteswap(request.token_no);
    order.side = byteswap(request.buy_sell);
    order.price = byteswap(request.price);
    order.filler = byteswap(request.filler);
    order.total_volume = byteswap(request.volume);
    order.volume_filled_today = std::min(order.volume_filled_today, order.total_volume);
    order.total_volume_remaining = order.total_volume - order.volume_filled_today;
    order.disclosed_volume = order.total_volume;
    order.disclosed_volume_remaining = order.total_volume_remaining;
    order.exchange_order_number = exchangeOrderNumberFromWire(request.order_number);
    touchTrackedOrder(order, byteswap(request.last_activity_reference));
  }

  void logPacket(const char* direction,
                 const char* view,
                 const DirectExCtclHeader& header,
                 const std::vector<uint8_t>& payload,
                 bool ctr_encrypted) const {
    std::cout << packetSummary("session", ticket_.peer_ip, direction, view, phaseName(), header,
                               payload.data(), payload.size(), ctr_encrypted)
              << std::endl;
  }

  void logDisconnect(const std::string& reason) const {
    std::cout << "[session disconnect] peer=" << ticket_.peer_ip << " phase=" << phaseName()
              << " last_sequence_sent=" << sequence_number_
              << " logged_in_user_id=" << logged_in_user_id_ << " reason=" << reason << std::endl;
  }

  void sendPayload(const void* payload, std::size_t size) {
    std::vector<uint8_t> bytes(static_cast<const uint8_t*>(payload),
                               static_cast<const uint8_t*>(payload) + size);
    const auto digest = Md5Digest::compute(bytes.data(), bytes.size());

    DirectExCtclHeader header {};
    header.length = byteswap<uint16_t>(static_cast<uint16_t>(sizeof(header) + bytes.size()));
    header.sequence_number = byteswap(++sequence_number_);
    std::memcpy(header.md5_checksum, digest.data(), digest.size());

    if (encryption_enabled_) {
      logPacket("send", "plain", header, bytes, false);
      outbound_crypto_.xorData(bytes.data(), bytes.size());
      logPacket("send", "wire", header, bytes, true);
    } else {
      logPacket("send", "wire", header, bytes, false);
    }

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
    response.token_no = order.request.token_no;
    std::memcpy(&response.contract_description, &order.request.contract_description,
                sizeof(response.contract_description));
    response.close_out_flag = ' ';
    response.order_number = hostToWireDouble(static_cast<double>(order.exchange_order_number));
    std::memcpy(response.account_number, order.request.account_number, sizeof(response.account_number));
    response.book_type = order.request.book_type;
    response.buy_sell_indicator = order.request.buy_sell_indicator;
    response.disclosed_volume = order.request.disclosed_volume;
    response.disclosed_volume_remaining =
        (txn_code == kTxnOrderErrorTrimmed) ? 0 : order.request.disclosed_volume;
    response.total_volume_remaining = (txn_code == kTxnOrderErrorTrimmed) ? 0 : order.request.volume;
    response.volume = order.request.volume;
    response.volume_filled_today = 0;
    response.price = order.request.price;
    response.good_till_date = order.request.good_till_date;
    response.entry_date_time = byteswap(order.event_seconds);
    response.last_modified = byteswap(order.event_seconds);
    response.order_flags1 = order.request.order_flags1;
    response.order_flags2 = order.request.order_flags2;
    response.branch_id = order.request.branch_id;
    response.trader_id = order.request.trader_id;
    std::memcpy(response.broker_id, order.request.broker_id, sizeof(response.broker_id));
    response.open_close = order.request.open_close;
    std::memcpy(response.settlor, order.request.settlor, sizeof(response.settlor));
    response.pro_client_indicator = order.request.pro_client_indicator;
    response.additional_flags = order.request.additional_flags;
    response.filler = order.request.filler;
    response.nnf_field = order.request.nnf_field;
    response.time_stamp3 = byteswap(order.event_nanos);
    std::memcpy(response.pan, order.request.pan, sizeof(response.pan));
    response.algo_id = order.request.algo_id;
    response.unique_id = order.request.unique_id;
    response.last_activity_reference = byteswap(order.last_activity_reference);
    sendPayload(&response, sizeof(response));
  }

  void sendTrackedOrderResponse(const TrackedOrderState& order,
                                uint16_t txn_code,
                                uint16_t error_code,
                                uint32_t response_volume) {
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
    std::memcpy(&response.contract_description, &order.contract_description,
                sizeof(response.contract_description));
    response.close_out_flag = ' ';
    response.order_number = hostToWireDouble(static_cast<double>(order.exchange_order_number));
    std::memcpy(response.account_number, order.account_number.data(), sizeof(response.account_number));
    response.book_type = byteswap(order.book_type);
    response.buy_sell_indicator = byteswap(order.side);
    response.disclosed_volume = byteswap(order.disclosed_volume);
    response.disclosed_volume_remaining = byteswap(order.disclosed_volume_remaining);
    response.total_volume_remaining = byteswap(order.total_volume_remaining);
    response.volume = byteswap(response_volume);
    response.volume_filled_today = byteswap(order.volume_filled_today);
    response.price = byteswap(order.price);
    response.good_till_date = byteswap(order.good_till_date);
    response.entry_date_time = byteswap(order.entry_date_time);
    response.last_modified = byteswap(order.last_modified);
    response.order_flags1 = order.order_flags1;
    response.order_flags2 = order.order_flags2;
    response.branch_id = byteswap(order.branch_id);
    response.trader_id = byteswap(order.trader_id);
    std::memcpy(response.broker_id, order.broker_id.data(), sizeof(response.broker_id));
    response.open_close = order.open_close;
    std::memcpy(response.settlor, order.settlor.data(), sizeof(response.settlor));
    response.pro_client_indicator = byteswap(order.pro_client_indicator);
    response.additional_flags = order.additional_flags;
    response.filler = byteswap(order.filler);
    response.nnf_field = hostToWireDouble(order.nnf_field);
    response.time_stamp3 = byteswap(order.event_nanos);
    std::memcpy(response.pan, order.pan.data(), sizeof(response.pan));
    response.algo_id = byteswap(order.algo_id);
    response.unique_id = byteswap(order.unique_id);
    response.last_activity_reference = byteswap(order.last_activity_reference);
    sendPayload(&response, sizeof(response));
  }

  void sendTradeResponse(const OrderSnapshot& order) {
    TradeConfirmationPayload response {};
    response.transaction_code = byteswap(kTxnTradeConfirmationTrimmed);
    response.log_time = byteswap(order.event_seconds);
    response.trader_id = byteswap(order.user_id);
    response.time_stamp = byteswap(order.event_nanos);
    response.time_stamp1 = byteswap(order.event_nanos);
    response.time_stamp2[7] = static_cast<uint8_t>(config_.default_stream_no);
    response.response_order_number = hostToWireDouble(static_cast<double>(order.exchange_order_number));
    std::memcpy(response.broker_id, order.request.broker_id, sizeof(response.broker_id));
    std::memcpy(response.account_number, order.request.account_number, sizeof(response.account_number));
    response.buy_sell_indicator = order.request.buy_sell_indicator;
    response.original_volume = order.request.volume;
    response.disclosed_volume = order.request.disclosed_volume;
    response.remaining_volume = 0;
    response.disclosed_volume_remaining = 0;
    response.price = order.request.price;
    response.order_flags1 = order.request.order_flags1;
    response.order_flags2 = order.request.order_flags2;
    response.good_till_date = order.request.good_till_date;
    response.fill_number = byteswap(order.fill_number);
    response.fill_quantity = order.request.volume;
    response.fill_price = order.request.price;
    response.volume_filled_today = order.request.volume;
    response.activity_type[0] = 'T';
    response.activity_type[1] = 'R';
    response.activity_time = byteswap(order.event_seconds);
    response.token = order.request.token_no;
    std::memcpy(&response.contract_description, &order.request.contract_description,
                sizeof(response.contract_description));
    response.open_close = order.request.open_close;
    response.book_type = static_cast<uint8_t>(order.book_type);
    std::memcpy(response.participant, order.request.settlor,
                std::min(sizeof(response.participant), sizeof(order.request.settlor)));
    response.additional_flags = order.request.additional_flags;
    std::memcpy(response.pan, order.request.pan, sizeof(response.pan));
    response.algo_id = order.request.algo_id;
    response.last_activity_reference = byteswap(order.last_activity_reference);
    sendPayload(&response, sizeof(response));
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
    std::cout << "Received secure box registration request" << std::endl;
    if (txn_code != kTxnSecureBoxRegistrationRequest ||
        payload.size() != sizeof(SecureBoxRegistrationRequestPayload)) {
      throw std::runtime_error("unexpected secure box registration payload");
    }

    const auto& request = *reinterpret_cast<const SecureBoxRegistrationRequestPayload*>(payload.data());
    const uint16_t box_id = byteswap(request.box_id);
    if (box_id != ticket_.box_id) {
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

  void handlePriceVolumeModificationRequest(const std::vector<uint8_t>& payload) {
    if (payload.size() != sizeof(PriceVolumeModificationRequestPayload)) {
      throw std::runtime_error("bad price/volume modification request size");
    }

    const auto& request = *reinterpret_cast<const PriceVolumeModificationRequestPayload*>(payload.data());
    const uint64_t exchange_order_number = exchangeOrderNumberFromWire(request.order_number);
    auto* tracked_order = findTrackedOrder(exchange_order_number, byteswap(request.filler));
    if (tracked_order == nullptr) {
      TrackedOrderState fallback = makeTrackedOrderState(request, exchange_order_number);
      touchTrackedOrder(fallback, byteswap(request.last_activity_reference));
      sendTrackedOrderResponse(fallback, kTxnOrderModificationErrorTrimmed, kErrorUnknownOrder,
                               fallback.total_volume_remaining);
      return;
    }

    if (hasEmittedFill(*tracked_order)) {
      sendFilledModificationError(*tracked_order, byteswap(request.last_activity_reference));
      return;
    }

    applyPriceVolumeModification(*tracked_order, request);
    sendTrackedOrderResponse(*tracked_order, kTxnOrderModificationConfirmationTrimmed, 0,
                             tracked_order->total_volume_remaining);
  }

  void handleTrimmedModificationRequest(const std::vector<uint8_t>& payload) {
    if (payload.size() != sizeof(OrderModifyCancelRequestPayload)) {
      throw std::runtime_error("bad modification request size");
    }

    const auto& request = *reinterpret_cast<const OrderModifyCancelRequestPayload*>(payload.data());
    const uint64_t exchange_order_number = exchangeOrderNumberFromWire(request.order_number);
    auto* tracked_order = findTrackedOrder(exchange_order_number, byteswap(request.filler));
    if (tracked_order == nullptr) {
      TrackedOrderState fallback = makeTrackedOrderState(request);
      touchTrackedOrder(fallback, byteswap(request.last_activity_reference));
      sendTrackedOrderResponse(fallback, kTxnOrderModificationErrorTrimmed, kErrorUnknownOrder,
                               fallback.total_volume_remaining);
      return;
    }

    if (hasEmittedFill(*tracked_order)) {
      sendFilledModificationError(*tracked_order, byteswap(request.last_activity_reference));
      return;
    }

    applyTrimmedModification(*tracked_order, request);
    sendTrackedOrderResponse(*tracked_order, kTxnOrderModificationConfirmationTrimmed, 0,
                             tracked_order->total_volume_remaining);
  }

  void handleTrimmedCancellationRequest(const std::vector<uint8_t>& payload) {
    if (payload.size() != sizeof(OrderModifyCancelRequestPayload)) {
      throw std::runtime_error("bad cancellation request size");
    }

    const auto& request = *reinterpret_cast<const OrderModifyCancelRequestPayload*>(payload.data());
    const uint64_t exchange_order_number = exchangeOrderNumberFromWire(request.order_number);
    auto* tracked_order = findTrackedOrder(exchange_order_number, byteswap(request.filler));
    if (tracked_order == nullptr) {
      TrackedOrderState fallback = makeTrackedOrderState(request);
      touchTrackedOrder(fallback, byteswap(request.last_activity_reference));
      fallback.disclosed_volume_remaining = 0;
      fallback.total_volume_remaining = 0;
      sendTrackedOrderResponse(fallback, kTxnOrderCancellationErrorTrimmed, kErrorUnknownOrder, 0);
      return;
    }

    applyTrimmedCancellation(*tracked_order, request);
    sendTrackedOrderResponse(*tracked_order, kTxnOrderCancellationConfirmationTrimmed, 0, 0);
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
      case kTxnPriceVolModification:
        handlePriceVolumeModificationRequest(payload);
        return;
      case kTxnOrderModificationRequestTrimmed:
        handleTrimmedModificationRequest(payload);
        return;
      case kTxnOrderCancellationRequestTrimmed:
        handleTrimmedCancellationRequest(payload);
        return;
      case kTxnOrderEntryTrimmed: {
        if (payload.size() != sizeof(OrderEntryRequestPayload)) {
          throw std::runtime_error("bad order request size");
        }
        const auto& request = *reinterpret_cast<const OrderEntryRequestPayload*>(payload.data());
        const auto accepted_order = engine_.acceptLimitOrder(request);
        if (!accepted_order.has_value()) {
          OrderSnapshot snapshot;
          snapshot.request = request;
          snapshot.user_id = byteswap(request.user_id);
          snapshot.event_seconds = nowSeconds32();
          snapshot.event_nanos = nowNanos();
          snapshot.last_activity_reference = 0;
          sendOrderResponse(snapshot, kTxnOrderErrorTrimmed, kErrorUnsupportedOrder);
          return;
        }

        rememberAcceptedOrder(*accepted_order);
        sendOrderResponse(*accepted_order, kTxnOrderConfirmationTrimmed, 0);
        if (config_.fill_delay_us > 0) {
          std::this_thread::sleep_for(std::chrono::microseconds(config_.fill_delay_us));
        }
        sendTradeResponse(*accepted_order);
        markOrderFilled(accepted_order->exchange_order_number);
        return;
      }
      default:
        throw std::runtime_error("unsupported transaction code");
    }
  }

  int fd_ = -1;
  Config config_;
  SessionTicket ticket_;
  FillEngine& engine_;
  CtrCryptoStream inbound_crypto_;
  CtrCryptoStream outbound_crypto_;
  bool encryption_enabled_ = false;
  Phase phase_ = Phase::kAwaitSecureBoxRegistration;
  uint32_t sequence_number_ = 0;
  uint32_t logged_in_user_id_ = 0;
  std::map<uint64_t, TrackedOrderState> tracked_orders_;
};

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

    running_ = true;
    gateway_thread_ = std::thread([this] { gatewayLoop(); });
    session_thread_ = std::thread([this] { sessionLoop(); });
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

    if (gateway_thread_.joinable()) {
      gateway_thread_.join();
    }
    if (session_thread_.joinable()) {
      session_thread_.join();
    }

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

      const std::string peer_ip = peerIpAddress(client_fd);
      std::cout << "[gateway connect] peer=" << peer_ip << std::endl;
      try {
        handleGatewayClient(client_fd);
      } catch (const std::exception& ex) {
        std::cout << "[gateway disconnect] peer=" << peer_ip << " reason=" << ex.what() << std::endl;
      } catch (...) {
        std::cout << "[gateway disconnect] peer=" << peer_ip << " reason=unknown exception"
                  << std::endl;
      }
      close(client_fd);
    }
  }

  void handleGatewayClient(int client_fd) {
    const std::string peer_ip = peerIpAddress(client_fd);
    std::cout << "Starting TLS handshake with gateway client " << peer_ip << std::endl;
    SSL* ssl = SSL_new(gateway_ssl_ctx_);
    if (ssl == nullptr) {
      throw std::runtime_error("SSL_new failed");
    }
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) {
      SSL_free(ssl);
      throw std::runtime_error("SSL_accept failed");
    }
    std::cout << "Completed TLS handshake with gateway client " << peer_ip << std::endl;
    DirectExCtclHeader ctcl_header {};
    sslReadFully(ssl, &ctcl_header, sizeof(ctcl_header));
    const uint16_t wire_length = byteswap(ctcl_header.length);
    if (wire_length != sizeof(GatewayRouterRequest)) {
      SSL_free(ssl);
      throw std::runtime_error("unexpected gateway request length");
    }
    GatewayRouterRequest request {};
    request.ctcl_header = ctcl_header;
    sslReadFully(ssl, reinterpret_cast<uint8_t*>(&request) + sizeof(ctcl_header),
                 sizeof(request) - sizeof(ctcl_header));
    std::cout << packetSummary("gateway", peer_ip, "recv", "wire", nullptr, ctcl_header,
                               reinterpret_cast<const uint8_t*>(&request.header),
                               sizeof(request) - sizeof(request.ctcl_header), false)
              << std::endl;
    const auto digest = Md5Digest::compute(
        reinterpret_cast<const uint8_t*>(&request.header), sizeof(request) - sizeof(request.ctcl_header));
    if (std::memcmp(request.ctcl_header.md5_checksum, digest.data(), digest.size()) != 0) {
      SSL_free(ssl);
      throw std::runtime_error("gateway request MD5 mismatch: expected=" +
                               hexString(request.ctcl_header.md5_checksum,
                                         sizeof(request.ctcl_header.md5_checksum)) +
                               " actual=" + hexString(digest.data(), digest.size()));
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

    std::cout << "Prepared gateway response to " << peer_ip << " with session key "
              << ticket.session_key << " and port " << session_port_ << std::endl;
    std::cout << packetSummary("gateway", peer_ip, "send", "wire", nullptr, response.ctcl_header,
                               reinterpret_cast<const uint8_t*>(&response.header),
                               sizeof(response) - sizeof(response.ctcl_header), false)
              << std::endl;

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
      const std::string peer_ip = peerIpAddress(client_fd);
      std::cout << "[session accept] peer=" << peer_ip << std::endl;
      auto ticket = tickets_.claimForPeer(peer_ip);
      if (!ticket.has_value()) {
        std::cout << "[session disconnect] peer=" << peer_ip
                  << " reason=no pending gateway ticket for peer" << std::endl;
        close(client_fd);
        continue;
      }

      std::lock_guard<std::mutex> lock(worker_mutex_);
      session_workers_.emplace_back([this, client_fd, ticket = std::move(*ticket)]() mutable {
        SessionConnection connection(client_fd, config_, std::move(ticket), engine_);
        connection.run();
      });
    }
  }

  Config config_;
  FillEngine engine_;
  PendingTicketStore tickets_;
  std::atomic<uint64_t> next_session_key_ {1};
  std::atomic<bool> running_ {false};
  uint16_t gateway_port_ = 0;
  uint16_t session_port_ = 0;
  int gateway_listen_fd_ = -1;
  int session_listen_fd_ = -1;
  SSL_CTX* gateway_ssl_ctx_ = nullptr;
  std::thread gateway_thread_;
  std::thread session_thread_;
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
